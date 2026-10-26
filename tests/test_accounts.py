import asyncio
import json
import os
import shutil
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from ctf_agent.accounts import AccountManager, register_accounts
from ctf_agent.providers.codex import CodexAccount, ProviderError, isolated_environment, normalize_rate_limits, official_login_url
from ctf_agent.providers.runtime import CodexRuntime
from ctf_agent.providers.claude_runtime import ClaudeRuntime
from ctf_agent.providers.claude import ClaudeAccount, _login_url_from_output, normalize_claude_usage
from ctf_agent.providers.auth_file import MAX_AUTH_BYTES, validate_auth_file
from ctf_agent.providers.codex import provider_error


@pytest.fixture
def settings(tmp_path):
    return SimpleNamespace(database_path=tmp_path / "db" / "test.sqlite3", config_dir=tmp_path / "config", data_dir=tmp_path / "data")


def test_multiple_quota_buckets_keep_actual_window_lengths():
    result = normalize_rate_limits({"rateLimitsByLimitId": {
        "codex": {"primary": {"usedPercent": 23, "windowDurationMins": 300, "resetsAt": 2000},
                  "secondary": {"usedPercent": 72, "windowDurationMins": 10080, "resetsAt": 9000},
                  "rateLimitReachedType": "workspace_member_usage_limit_reached",
                  "credits": {"hasCredits": False, "unlimited": False},
                  "individualLimit": {"remainingPercent": 0, "resetsAt": 2500}},
        "model-specific": {"primary": {"usedPercent": 0, "windowDurationMins": 60, "resetsAt": 999}}
    }, "rateLimitResetCredits": {"availableCount": 2, "credits": [{"id": "must-not-leak"}]}}, now=1000)
    assert len(result["buckets"]) == 2
    first = result["buckets"][0]["windows"]
    assert [window["label"] for window in first] == ["5시간", "7일"]
    assert first[0]["remaining_seconds"] == 1000
    assert result["buckets"][1]["windows"][0]["remaining_seconds"] == 0
    assert result["buckets"][1]["windows"][0]["used_percent"] == 0
    assert result["limited"] and result["status"] == "available"
    assert result["buckets"][0]["limited"]
    assert result["buckets"][0]["reached_type"] == "workspace_member_usage_limit_reached"
    assert result["buckets"][0]["credits"] == {"has_credits": False, "unlimited": False}
    assert result["buckets"][0]["individual_limit"] == {
        "remaining_percent": 0, "resets_at": 2500, "remaining_seconds": 1500}
    assert result["reset_credits"] == {"available_count": 2}
    assert "must-not-leak" not in json.dumps(result)


def test_unknown_quota_is_not_zero_and_legacy_supported():
    assert normalize_rate_limits({})["status"] == "unavailable"
    quota = normalize_rate_limits({"rateLimits": {"primary": {"usedPercent": None, "windowDurationMins": 15}, "secondary": None}})
    window = quota["buckets"][0]["windows"][0]
    assert window["used_percent"] is None
    assert window["resets_at"] is None
    assert window["label"] == "15분"


def test_invalid_quota_numbers_are_unknown():
    quota = normalize_rate_limits({"rateLimits": {"primary": {"usedPercent": float("nan"), "windowDurationMins": -10, "resetsAt": True}}})
    assert quota["buckets"][0]["windows"][0]["used_percent"] is None
    assert quota["buckets"][0]["windows"][0]["window_minutes"] is None
    assert quota["buckets"][0]["windows"][0]["resets_at"] is None


def test_future_rate_limit_reason_is_bounded_but_still_marks_account_limited():
    quota = normalize_rate_limits({"rateLimits": {
        "primary": {"usedPercent": 20, "windowDurationMins": 300},
        "rateLimitReachedType": "future_backend_reason/private-value",
    }})
    assert quota["status"] == "available"
    assert quota["limited"] and quota["buckets"][0]["limited"]
    assert quota["buckets"][0]["reached_type"] == "rate_limit_reached"
    assert "private-value" not in json.dumps(quota)


def test_account_homes_and_credentials_are_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "host-secret")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "host-secret")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "host"))
    first = isolated_environment(tmp_path / "first")
    second = isolated_environment(tmp_path / "second")
    assert first["CODEX_HOME"] != second["CODEX_HOME"]
    assert first["HOME"] != second["HOME"]
    assert "OPENAI_API_KEY" not in first and "CLAUDE_CODE_OAUTH_TOKEN" not in first
    assert first["CODEX_HOME"].startswith(str(tmp_path / "first"))


@pytest.mark.parametrize("url", ["http://auth.openai.com/codex/device", "https://auth.openai.com.evil.example/codex/device", "https://name@auth.openai.com/device", "javascript:alert(1)"])
def test_login_urls_reject_nonofficial_destinations(url):
    with pytest.raises(ProviderError):
        official_login_url(url, "codex")


def test_provider_does_not_expose_execution_methods(tmp_path):
    adapter = CodexAccount(tmp_path, [])
    for method in ("turn/start", "thread/start", "command/exec", "process/start"):
        with pytest.raises(ProviderError) as error:
            asyncio.run(adapter.request(method))
        assert error.value.code == "unsupported"


def test_snapshot_redacts_tokens_and_keeps_identity(tmp_path):
    adapter = CodexAccount(tmp_path, [])
    async def request(method, params=None):
        if method == "account/read":
            return {"account": {"type": "chatgpt", "email": "owner@example.com", "planType": "plus", "accessToken": "never-return"}}
        return {"rateLimits": {"primary": {"usedPercent": 20, "windowDurationMins": 300}}}
    adapter.request = request
    result = asyncio.run(adapter.snapshot())
    assert "never-return" not in json.dumps(result)
    assert result["identity"]["email"] == "owner@example.com"


def test_snapshot_marks_cached_account_auth_required_when_quota_rejects_token(tmp_path):
    adapter = CodexAccount(tmp_path, [])

    async def request(method, params=None):
        if method == "account/read":
            return {
                "account": {
                    "type": "chatgpt",
                    "email": "owner@example.com",
                    "accessToken": "never-return",
                }
            }
        raise ProviderError(
            "Authentication required",
            "auth_required",
            stage="quota",
            category="auth",
            retryable=False,
        )

    adapter.request = request
    result = asyncio.run(adapter.snapshot())

    assert result["status"] == "auth_required"
    assert result["quota"]["status"] == "auth_required"
    assert result["error"] == result["quota"]["error"]
    assert result["error"]["category"] == "auth"
    assert "never-return" not in json.dumps(result)


def test_snapshot_keeps_authenticated_status_for_temporary_quota_error(tmp_path):
    adapter = CodexAccount(tmp_path, [])

    async def request(method, params=None):
        if method == "account/read":
            return {"account": {"type": "chatgpt", "email": "owner@example.com"}}
        raise ProviderError("Timed out", "timeout", stage="quota", category="temporary")

    adapter.request = request
    result = asyncio.run(adapter.snapshot())

    assert result["status"] == "authenticated"
    assert result["quota"]["status"] == "timeout"
    assert "error" not in result


def test_multiple_account_selection_is_persisted_per_provider(settings):
    manager = AccountManager(settings)
    first = manager.create("codex", "First")
    second = manager.create("codex", "Second")
    claude = manager.create("claude", "Claude")
    asyncio.run(manager.select(second["id"]))
    reopened = AccountManager(settings)
    assert not reopened.get(first["id"])["selected"]
    assert reopened.get(second["id"])["selected"]
    assert reopened.get(claude["id"])["selected"]
    assert reopened.adapter(first["id"]).home != reopened.adapter(second["id"]).home
    with pytest.raises(HTTPException):
        reopened.adapter("../host")


def test_concurrent_account_creation_enforces_owner_cap_without_sqlite_busy(settings):
    manager = AccountManager(settings)
    for index in range(49):
        manager.create("codex", f"Existing {index}")

    def create(index):
        try:
            return manager.create("codex", f"Concurrent {index}")["id"]
        except HTTPException as exc:
            return exc.status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(create, range(8)))

    assert sum(isinstance(result, str) for result in results) == 1
    assert results.count(409) == 7
    assert len(manager.listing()["accounts"]) == 50


def test_failed_refresh_preserves_old_quota_as_stale(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    adapter = manager.adapter(account["id"])
    async def good():
        return {"status": "authenticated", "identity": {"email": "owner@example.com"}, "quota": {"status": "available", "buckets": [{"id": "codex"}], "checked_at": 10}}
    adapter.snapshot = good
    asyncio.run(manager.refresh(account["id"]))
    async def fail():
        raise ProviderError("Connection failed", "timeout")
    adapter.snapshot = fail
    result = asyncio.run(manager.refresh(account["id"]))
    assert result["snapshot"]["status"] == "timeout"
    assert result["snapshot"]["quota"]["stale"]
    assert result["snapshot"]["quota"]["buckets"] == [{"id": "codex"}]
    assert result["snapshot"]["quota"]["checked_at"] == 10


def test_model_selection_validated_against_account_catalog(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    async def models():
        return {"status": "available", "models": [{"id": "test-model", "model": "test-model", "supportedReasoningEfforts": [{"reasoningEffort": "low"}]}]}
    manager.adapter(account["id"]).models = models
    with pytest.raises(HTTPException):
        asyncio.run(manager.update(account["id"], {"model": "invented"}))
    with pytest.raises(HTTPException):
        asyncio.run(manager.update(account["id"], {"model": "test-model", "reasoning_effort": "invented"}))
    result = asyncio.run(manager.update(account["id"], {"model": "test-model", "reasoning_effort": "low"}))
    assert result["model"] == "test-model" and result["reasoning_effort"] == "low"


def test_routes_require_auth_and_mutation_csrf(settings):
    app = FastAPI()
    async def auth(request: Request):
        if request.headers.get("authorization") != "Bearer test":
            raise HTTPException(401)
        if request.method not in ("GET", "HEAD") and request.headers.get("x-csrf-token") != "csrf":
            raise HTTPException(403)
        return {"id": "legacy", "role": "admin"}
    register_accounts(app, auth, settings)
    with TestClient(app) as client:
        assert client.get("/api/accounts").status_code == 401
        assert client.post("/api/accounts", json={"provider": "codex", "label": "a"}, headers={"authorization": "Bearer test"}).status_code == 403
        headers = {"authorization": "Bearer test", "x-csrf-token": "csrf"}
        response = client.post("/api/accounts", json={"provider": "codex", "label": "a"}, headers=headers)
        assert response.status_code == 201
        account = response.json()
        assert client.get(f"/api/accounts/{account['id']}/login").status_code == 401
        assert client.delete(f"/api/accounts/{account['id']}").status_code == 401
        assert client.post("/api/providers/codex/update", json={"version": "1.2.3"}).status_code == 401
        assert client.get("/api/providers/claude/runtime").status_code == 401
        assert client.post("/api/accounts", json={"provider": "codex", "label": "a", "command": "anything"}, headers=headers).status_code == 422
        assert client.delete(f"/api/accounts/{account['id']}", headers=headers).status_code == 200


@pytest.mark.parametrize("version", ["latest", "../../1.2.3", "1.2.3;echo", "1.2.3 --x", "https://example.com/package.tgz"])
def test_runtime_rejects_unpinned_or_injected_versions(tmp_path, version):
    runtime = CodexRuntime(tmp_path)
    with pytest.raises(ProviderError) as error:
        asyncio.run(runtime.update(version, None))
    assert error.value.code == "invalid_version"


def test_runtime_startup_removes_only_interrupted_install_state(tmp_path):
    stale = tmp_path / ("install-" + "a" * 32)
    stale.mkdir()
    (stale / "partial-package").write_bytes(b"partial")
    legacy_cache = tmp_path / "installer"
    legacy_cache.mkdir()
    (legacy_cache / "cache").write_bytes(b"cache")
    installed = tmp_path / "codex-1.2.3"
    installed.mkdir()
    similar = tmp_path / "install-not-a-stage"
    similar.mkdir()

    CodexRuntime(tmp_path)

    assert not stale.exists() and not legacy_cache.exists()
    assert installed.is_dir() and similar.is_dir()


def test_runtime_install_reserves_shared_volume_before_creating_stage(tmp_path, monkeypatch):
    class Budget:
        minimum_free_bytes = 0

        def __init__(self):
            self.calls = []

        def reconcile_kind(self, kind, expected):
            self.calls.append(("reconcile", kind, expected))

        def reserve(self, *args):
            self.calls.append(("reserve", *args))
            raise RuntimeError("synthetic capacity refusal")

        def release(self, key):
            self.calls.append(("release", key))

    budget = Budget()
    runtime = CodexRuntime(tmp_path, budget)
    monkeypatch.setattr(runtime, "version_command", lambda _version: [])

    asyncio.run(runtime._install("1.2.3", lambda: None))

    assert runtime.operation["status"] == "failed"
    assert [call[0] for call in budget.calls] == ["reconcile", "reserve", "release"]
    assert not list(tmp_path.glob("install-*"))


def test_runtime_install_releases_reservation_when_stage_cleanup_fails(tmp_path, monkeypatch):
    class Budget:
        minimum_free_bytes = 0

        def __init__(self):
            self.released = []

        def reconcile_kind(self, _kind, _expected):
            pass

        def reserve(self, *_args):
            pass

        def release(self, key):
            self.released.append(key)

    budget = Budget()
    runtime = CodexRuntime(tmp_path, budget)
    monkeypatch.setattr(runtime, "version_command", lambda _version: [])

    async def fail_spawn(*_args, **_kwargs):
        raise OSError("synthetic spawn failure")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_spawn)
    monkeypatch.setattr("ctf_agent.providers.runtime.shutil.rmtree", lambda _path: (_ for _ in ()).throw(OSError("busy")))

    asyncio.run(runtime._install("1.2.3", lambda: None))

    assert runtime.operation["status"] == "failed"
    assert len(list(tmp_path.glob("install-*"))) == 1
    assert len(budget.released) == 1 and budget.released[0].startswith("runtime:")


def test_runtime_status_probe_is_single_flight_cached_and_invalidated(tmp_path, monkeypatch):
    runtime = CodexRuntime(tmp_path)
    calls = []

    class Probe:
        def __init__(self):
            self.returncode = None

        async def communicate(self):
            await asyncio.sleep(0.05)
            self.returncode = 0
            return b"codex-cli 1.2.3\n", b""

    async def spawn(*_args, **_kwargs):
        calls.append("spawn")
        return Probe()

    async def run():
        monkeypatch.setattr(runtime, "command", lambda: ["synthetic-codex"])
        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        results = await asyncio.gather(*(runtime.status() for _ in range(40)))
        assert all(result["version"] == "1.2.3" for result in results)
        assert calls == ["spawn"]
        runtime.save({"selected": "1.2.3"})
        assert (await runtime.status())["selected"] == "1.2.3"
        assert calls == ["spawn", "spawn"]

    asyncio.run(run())


def test_failed_runtime_verification_preserves_selection(tmp_path, monkeypatch):
    runtime = CodexRuntime(tmp_path)
    runtime.save({"selected": "1.2.3", "previous": "1.2.2"})
    monkeypatch.setattr(runtime, "version_command", lambda version: ["fake", version])
    async def fail(_self):
        raise ProviderError("Invalid protocol")
    monkeypatch.setattr(CodexAccount, "start", fail)
    async def switched():
        pytest.fail("Failed version must never become selected")
    asyncio.run(runtime._install("1.2.4", switched))
    assert runtime.state()["selected"] == "1.2.3"
    assert runtime.operation["status"] == "failed"


def test_failed_runtime_switch_restores_previous_state(tmp_path, monkeypatch):
    runtime = CodexRuntime(tmp_path)
    previous = {"selected": "1.2.3", "previous": "1.2.2"}
    runtime.save(previous)
    monkeypatch.setattr(runtime, "version_command", lambda version: ["fake", version])
    async def verified(_command):
        return None
    monkeypatch.setattr(runtime, "verify", verified)
    async def fail_switch():
        raise OSError("Cannot close adapter")
    asyncio.run(runtime._install("1.2.4", fail_switch))
    assert runtime.state() == previous
    assert runtime.operation["status"] == "failed"


class FakeProcess:
    """A bounded in-memory auth process: no subprocess or network is started."""
    def __init__(self):
        self.returncode = None
        self.stdout = asyncio.StreamReader()
        self.exited = asyncio.Event()
        self.stdin = self
        self.writes = []

    def write(self, value):
        self.writes.append(value)

    async def drain(self):
        await asyncio.sleep(0)

    def terminate(self):
        self.returncode = 0
        self.stdout.feed_eof()
        self.exited.set()

    kill = terminate

    async def wait(self):
        await self.exited.wait()
        return self.returncode


def test_parameterless_app_server_requests_omit_params(tmp_path):
    async def run():
        adapter = CodexAccount(tmp_path, [])
        process = FakeProcess()
        adapter.process = process
        adapter.reader = asyncio.create_task(adapter._read(process))
        task = asyncio.create_task(adapter._request("account/rateLimits/read"))
        while not process.writes:
            await asyncio.sleep(0)
        request = json.loads(process.writes[0])
        assert request["method"] == "account/rateLimits/read"
        assert "params" not in request
        process.stdout.feed_data((json.dumps({"id": request["id"], "result": {"rateLimits": {}}}) + "\n").encode())
        assert await task == {"rateLimits": {}}
        await adapter.close()

    asyncio.run(run())


def ceremony():
    return {"loginId": "private-login-id", "userCode": "ABCD-1234",
            "verificationUrl": "https://auth.openai.com/codex/device"}


def test_early_codex_login_completion_notification_is_not_lost(tmp_path):
    async def run():
        adapter = CodexAccount(tmp_path, [])
        process = FakeProcess()
        adapter.process = process
        adapter.reader = asyncio.create_task(adapter._read(process))
        async def request(method, params=None):
            process.stdout.feed_data((json.dumps({"method": "account/login/completed", "params": {
                "loginId": "private-login-id", "success": True}}) + "\n").encode())
            await asyncio.sleep(0)
            return ceremony()
        adapter.request = request
        result = await adapter.start_login()
        assert result["status"] == "completed"
        assert "login_id" not in result and adapter.login_timer is None
        await adapter.close()
    asyncio.run(run())


def test_codex_login_expires_without_browser_polling_even_if_cancel_fails(tmp_path, monkeypatch):
    monkeypatch.setattr("ctf_agent.providers.codex.LOGIN_TIMEOUT_SECONDS", 0.01)
    async def run():
        adapter = CodexAccount(tmp_path, [])
        process = FakeProcess()
        adapter.process = process
        async def request(method, params=None):
            return ceremony()
        async def disconnected(method, params=None):
            raise ProviderError("Disconnected", "timeout")
        adapter.request, adapter._request = request, disconnected
        assert (await adapter.start_login())["status"] == "pending"
        await asyncio.wait_for(adapter.login_timer, 1)
        assert adapter.login["status"] == "expired"
        assert adapter.process is None and process.returncode == 0
    asyncio.run(run())


def test_codex_cancel_always_closes_process_and_clears_login_id(tmp_path):
    async def run():
        adapter = CodexAccount(tmp_path, [])
        process = FakeProcess()
        adapter.process = process
        adapter.login = {"status": "pending", "login_id": "private-login-id"}
        async def fail(method, params=None):
            raise ProviderError("Cannot contact CLI")
        adapter._request = fail
        assert await adapter.cancel_login() == {"status": "cancelled"}
        assert process.returncode == 0 and adapter.process is None
    asyncio.run(run())


def test_cancelled_codex_initialization_does_not_leak_process(tmp_path, monkeypatch):
    async def run():
        process = FakeProcess()
        async def spawn(*args, **kwargs):
            return process
        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        adapter = CodexAccount(tmp_path, ["test-only"])
        task = asyncio.create_task(adapter.start())
        while not process.writes:
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert process.returncode == 0 and adapter.process is None and not adapter.pending
    asyncio.run(run())


def test_failed_quota_only_refresh_retains_last_good_windows(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    adapter = manager.adapter(account["id"])
    async def good():
        return {"status": "authenticated", "identity": {"email": "owner@example.com"},
                "quota": {"status": "available", "buckets": [{"id": "codex", "windows": []}], "checked_at": 10}}
    adapter.snapshot = good
    asyncio.run(manager.refresh(account["id"]))
    async def fail_quota():
        return {"status": "authenticated", "identity": {"email": "owner@example.com"},
                "quota": {"status": "timeout", "message": "Request timed out", "buckets": [], "checked_at": 20}}
    adapter.snapshot = fail_quota
    result = asyncio.run(manager.refresh(account["id"]))["snapshot"]["quota"]
    assert result["buckets"] == [{"id": "codex", "windows": []}]
    assert result["stale"] and result["checked_at"] == 10 and result["status"] == "timeout"


def test_refresh_keeps_fresh_provider_limit_state_even_without_windows(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    adapter = manager.adapter(account["id"])

    async def old_snapshot():
        return {"status": "authenticated", "identity": {"email": "owner@example.com"},
                "quota": {"status": "available", "limited": False,
                          "buckets": [{"id": "codex", "windows": [{"used_percent": 20}]}],
                          "checked_at": 10}}

    adapter.snapshot = old_snapshot
    asyncio.run(manager.refresh(account["id"]))

    async def reached_snapshot():
        quota = normalize_rate_limits({"rateLimits": {
            "limitId": "codex",
            "rateLimitReachedType": "workspace_member_credits_depleted",
        }}, now=20)
        return {"status": "authenticated", "identity": {"email": "owner@example.com"}, "quota": quota}

    adapter.snapshot = reached_snapshot
    result = asyncio.run(manager.refresh(account["id"]))["snapshot"]["quota"]
    assert result["status"] == "available" and result["limited"]
    assert not result.get("stale") and result["checked_at"] == 20
    assert result["buckets"][0]["windows"] == []


def test_account_listing_preserves_pending_login_for_page_revisit(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    manager.adapter(account["id"]).login = {"status": "pending", "user_code": "ABCD-1234", "login_id": "private-login-id"}
    result = manager.listing()["accounts"][0]["login"]
    assert result == {"status": "pending", "user_code": "ABCD-1234"}


def test_logout_closes_adapter_and_clears_old_account_identity(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    adapter = manager.adapter(account["id"])
    calls = []
    async def cancel():
        calls.append("cancel")
    async def close():
        calls.append("close")
    async def request(method, params=None):
        calls.append(method)
        return {}
    adapter.cancel_login, adapter.close, adapter.request = cancel, close, request
    result = asyncio.run(manager.logout(account["id"]))
    assert calls == ["cancel", "account/logout", "close"]
    assert result["snapshot"]["status"] == "signed_out" and result["snapshot"]["identity"] is None
    assert account["id"] not in manager.adapters


def test_delete_account_removes_only_its_credentials_and_selects_remaining(settings):
    manager = AccountManager(settings)
    first, second = manager.create("codex", "First"), manager.create("codex", "Second")
    provider = manager.create("claude", "Claude")
    first_home, second_home = manager.home / first["id"], manager.home / second["id"]
    first_home.mkdir()
    second_home.mkdir()
    (first_home / "auth.json").write_text("synthetic first credentials")
    (second_home / "auth.json").write_text("synthetic second credentials")
    assert asyncio.run(manager.delete(first["id"])) == {"ok": True}
    assert not first_home.exists() and (second_home / "auth.json").exists()
    assert manager.get(second["id"])["selected"] and manager.get(provider["id"])["selected"]
    with pytest.raises(HTTPException):
        manager.get(first["id"])


def test_delete_rechecks_selection_after_concurrent_promotion(settings, monkeypatch):
    manager = AccountManager(settings)
    first = manager.create("codex", "First")
    second = manager.create("codex", "Second")
    second_home = manager.home / second["id"]
    second_home.mkdir()
    original_remove = shutil.rmtree

    def promote_during_filesystem_cleanup(path):
        with manager.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE provider_accounts SET selected=0 WHERE owner_user_id=? AND provider='codex'",
                (manager.legacy_owner_id,),
            )
            db.execute(
                "UPDATE provider_accounts SET selected=1 WHERE id=?",
                (second["id"],),
            )
        original_remove(path)

    monkeypatch.setattr("ctf_agent.accounts.shutil.rmtree", promote_during_filesystem_cleanup)
    assert asyncio.run(manager.delete(second["id"])) == {"ok": True}
    assert manager.home.is_dir()
    assert manager.get(first["id"])["selected"] is True


def test_delete_cleanup_failure_leaves_only_unreachable_retryable_tombstone(settings, monkeypatch):
    manager = AccountManager(settings)
    account = manager.create("codex", "Disposable")
    canonical = manager.home / account["id"]
    credential = canonical / "codex" / "auth.json"
    credential.parent.mkdir(parents=True)
    credential.write_bytes(b"synthetic credential")
    original_remove = shutil.rmtree

    def fail_cleanup(_path):
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr("ctf_agent.accounts.shutil.rmtree", fail_cleanup)
    assert asyncio.run(manager.delete(account["id"])) == {"ok": True}
    assert not canonical.exists()
    with pytest.raises(HTTPException) as error:
        manager.get(account["id"])
    assert error.value.status_code == 404
    tombstones = list(manager.home.glob(f".deleted-{account['id']}-*"))
    assert len(tombstones) == 1 and (tombstones[0] / "codex" / "auth.json").is_file()

    monkeypatch.setattr("ctf_agent.accounts.shutil.rmtree", original_remove)
    AccountManager(settings)
    assert not tombstones[0].exists()


def test_runtime_rollback_blocks_concurrent_update_and_second_rollback(tmp_path, monkeypatch):
    async def run():
        runtime = CodexRuntime(tmp_path)
        runtime.save({"selected": "1.2.3", "previous": "1.2.2"})
        monkeypatch.setattr(runtime, "version_command", lambda version: ["fake", version])
        started, finish = asyncio.Event(), asyncio.Event()
        async def verify(command):
            started.set()
            await finish.wait()
        async def noop():
            return None
        async def status():
            return runtime.state()
        monkeypatch.setattr(runtime, "verify", verify)
        monkeypatch.setattr(runtime, "status", status)
        rollback = asyncio.create_task(runtime.rollback(noop))
        await started.wait()
        with pytest.raises(ProviderError) as update_error:
            await runtime.update("1.2.4", noop)
        assert update_error.value.code == "busy"
        with pytest.raises(ProviderError) as rollback_error:
            await runtime.rollback(noop)
        assert rollback_error.value.code == "busy"
        finish.set()
        await rollback
        assert runtime.state()["selected"] == "1.2.2" and not runtime.busy
    asyncio.run(run())


def test_reinstall_selected_runtime_keeps_previous_rollback_version(tmp_path, monkeypatch):
    runtime = CodexRuntime(tmp_path)
    runtime.save({"selected": "1.2.3", "previous": "1.2.2"})
    monkeypatch.setattr(runtime, "version_command", lambda version: ["fake", version])
    async def verify(command):
        return None
    async def switched():
        return None
    monkeypatch.setattr(runtime, "verify", verify)
    asyncio.run(runtime._install("1.2.3", switched))
    assert runtime.state()["previous"] == "1.2.2"


def test_claude_cancel_stops_reader_and_process(tmp_path):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        process = FakeProcess()
        adapter.process = process
        adapter.login = {"status": "pending"}
        adapter.reader = asyncio.create_task(adapter._read_login(process))
        await asyncio.sleep(0)
        assert await adapter.cancel_login() == {"status": "cancelled"}
        assert process.returncode == 0 and adapter.process is None and adapter.reader is None
    asyncio.run(run())


def test_claude_login_url_extraction_accepts_official_terminal_links_only():
    official = "https://claude.com/cai/oauth/authorize?client_id=test&state=abc"
    assert _login_url_from_output("Open " + official[:30]) is None
    assert _login_url_from_output("Open " + official + "\n") == official
    assert _login_url_from_output("\x1b]8;;" + official + "\x1b\\Open link\x1b]8;;\x1b\\") == official
    assert _login_url_from_output("https://claude.ai.evil.example/oauth/authorize\n") is None
    assert _login_url_from_output("https://claude.com.evil.example/cai/oauth/authorize\n") is None


def test_claude_login_exposes_link_and_submits_browser_code(tmp_path, monkeypatch):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        process = FakeProcess()
        async def spawn(*arguments):
            assert arguments == ("login", "--claudeai")
            return process
        monkeypatch.setattr(adapter, "_spawn", spawn)
        assert (await adapter.start_login())["status"] == "pending"
        url = "https://claude.com/cai/oauth/authorize?client_id=test&state=abc"
        process.stdout.feed_data(("Open " + url + "\nPaste code here if prompted: ").encode())
        for _ in range(20):
            if adapter.login.get("verification_url") == url:
                break
            await asyncio.sleep(0)
        assert adapter.login["verification_url"] == url
        await adapter.submit_code("  browser-code#state  ")
        assert process.writes == [b"browser-code#state\n"]
        process.terminate()
        await adapter.reader
        assert adapter.login["status"] == "completed"
        assert "browser-code" not in str(adapter.login)
        await adapter.close()
    asyncio.run(run())


def test_claude_login_continues_after_browser_authentication(tmp_path, monkeypatch):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        process = FakeProcess()

        async def spawn(*arguments):
            return process

        monkeypatch.setattr(adapter, "_spawn", spawn)
        await adapter.start_login()
        process.stdout.feed_data(b"Login successful\nPress Enter to continue")
        for _ in range(20):
            if process.writes:
                break
            await asyncio.sleep(0)
        assert process.writes == [b"\n"]
        process.terminate()
        await adapter.reader
        assert adapter.login["status"] == "completed"
        await adapter.close()

    asyncio.run(run())


def test_claude_login_without_link_fails_promptly(tmp_path, monkeypatch):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        process = FakeProcess()

        async def spawn(*arguments):
            return process

        monkeypatch.setattr(adapter, "_spawn", spawn)
        monkeypatch.setattr("ctf_agent.providers.claude.CLAUDE_LINK_TIMEOUT_SECONDS", 0.01)
        await adapter.start_login()
        await adapter.reader
        assert adapter.login["status"] == "expired"
        assert "인증 링크" in adapter.login["message"]
        assert process.returncode == 0

    asyncio.run(run())


def test_claude_subscription_usage_uses_account_token_and_caches_snapshot(tmp_path, monkeypatch):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        credential = tmp_path / "claude" / ".credentials.json"
        credential.parent.mkdir()
        credential.write_text(json.dumps({"claudeAiOauth": {"accessToken": "private-token-for-test"}}))

        async def status(_name):
            return 0, b'{"loggedIn":true,"email":"member@example.com"}'

        adapter._auth_command = status
        requests = []
        original_client = httpx.AsyncClient

        def client(**_kwargs):
            def respond(request):
                requests.append(request)
                return httpx.Response(200, json={
                    "five_hour": {"utilization": 25.5, "resets_at": "2026-10-26T03:00:00Z"},
                    "seven_day": {"utilization": 40, "resets_at": "2026-11-01T03:00:00Z"},
                    "seven_day_opus": {"utilization": 71, "resets_at": "2026-11-01T03:00:00Z"},
                    "secret": "never-return",
                })
            return original_client(transport=httpx.MockTransport(respond))

        monkeypatch.setattr("ctf_agent.providers.claude.httpx.AsyncClient", client)
        first = await adapter.snapshot()
        second = await adapter.snapshot()
        assert first["status"] == "authenticated"
        assert first["quota"] == second["quota"]
        assert len(requests) == 1
        assert requests[0].url == "https://api.anthropic.com/api/oauth/usage"
        assert requests[0].headers["anthropic-beta"] == "oauth-2025-04-20"
        assert [window["used_percent"] for window in first["quota"]["buckets"][0]["windows"]] == [25.5, 40, 71]
        assert "private-token-for-test" not in json.dumps(first)
        assert "never-return" not in json.dumps(first)

    asyncio.run(run())


def test_claude_usage_rejects_missing_or_malformed_windows():
    assert normalize_claude_usage({"five_hour": {"utilization": "25"}})["status"] == "unavailable"
    assert normalize_claude_usage({"limits": [{"kind": "session", "percent": 12,
        "resets_at": "2026-10-26T03:00:00Z"}]})["buckets"][0]["windows"][0]["used_percent"] == 12


def test_claude_usage_rate_limit_is_cached_without_false_zero(tmp_path, monkeypatch):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        credential = tmp_path / "claude" / ".credentials.json"
        credential.parent.mkdir()
        credential.write_text(json.dumps({"claudeAiOauth": {"accessToken": "private-token-for-test"}}))
        calls = []
        original_client = httpx.AsyncClient

        def client(**_kwargs):
            def respond(request):
                calls.append(request)
                return httpx.Response(429, json={"error": "private diagnostic"})
            return original_client(transport=httpx.MockTransport(respond))

        monkeypatch.setattr("ctf_agent.providers.claude.httpx.AsyncClient", client)
        first = await adapter._usage()
        second = await adapter._usage()
        assert first == second and len(calls) == 1
        assert first["status"] == "rate_limited" and first["buckets"] == []
        assert "private diagnostic" not in json.dumps(first)

    asyncio.run(run())


def test_claude_code_pipe_failure_returns_safe_error_and_closes(tmp_path):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        process = FakeProcess()
        adapter.process = process
        adapter.login = {"status": "pending"}
        def fail_write(value):
            raise BrokenPipeError("Private CLI diagnostics")
        process.write = fail_write
        with pytest.raises(ProviderError) as error:
            await adapter.submit_code("user-provided-code")
        assert "Private CLI diagnostics" not in str(error.value)
        assert adapter.process is None and adapter.login["status"] == "failed"
    asyncio.run(run())


def test_quota_bucket_without_windows_is_unavailable():
    result = normalize_rate_limits({"rateLimits": {"limitId": "codex", "primary": None, "secondary": None}})
    assert result["status"] == "unavailable" and result["buckets"][0]["windows"] == []


def test_api_key_identity_does_not_request_subscription_quota(tmp_path):
    adapter = CodexAccount(tmp_path, [])
    async def request(method, params=None):
        assert method == "account/read"
        return {"account": {"type": "apiKey"}}
    adapter.request = request
    result = asyncio.run(adapter.snapshot())
    assert result["status"] == "authenticated" and result["quota"]["status"] == "unsupported"


def test_logout_error_still_releases_adapter(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Account")
    adapter = manager.adapter(account["id"])
    closed = []
    async def cancel():
        return None
    async def close():
        closed.append(True)
    async def fail(method, params=None):
        raise ProviderError("Logout failed")
    adapter.cancel_login, adapter.close, adapter.request = cancel, close, fail
    with pytest.raises(ProviderError):
        asyncio.run(manager.logout(account["id"]))
    assert closed and account["id"] not in manager.adapters


def test_cancelled_claude_status_command_closes_subprocess(tmp_path, monkeypatch):
    async def run():
        adapter = ClaudeAccount(tmp_path)
        process = FakeProcess()
        async def spawn(*args):
            return process
        monkeypatch.setattr(adapter, "_spawn", spawn)
        task = asyncio.create_task(adapter.snapshot())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert process.returncode == 0
    asyncio.run(run())


def test_existing_accounts_migrate_to_original_admin_without_touching_auth(settings):
    settings.database_path.parent.mkdir(parents=True)
    account_id = "a" * 32
    with sqlite3.connect(settings.database_path) as db:
        db.executescript("""
            CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO meta VALUES('legacy_owner_id','original-admin');
            CREATE TABLE provider_accounts(id TEXT PRIMARY KEY,provider TEXT NOT NULL,label TEXT NOT NULL,
                selected INTEGER NOT NULL DEFAULT 0,model TEXT,reasoning_effort TEXT,snapshot TEXT,checked_at REAL,created_at REAL NOT NULL);
            CREATE UNIQUE INDEX one_selected_account_per_provider ON provider_accounts(provider) WHERE selected=1;
        """)
        db.execute("INSERT INTO provider_accounts(id,provider,label,selected,created_at) VALUES(?,?,?,?,?)", (account_id, "codex", "Existing account", 1, 1))
    auth = settings.config_dir / "accounts" / account_id / "codex" / "auth.json"
    auth.parent.mkdir(parents=True)
    original = b'original account credentials remain unchanged'
    auth.write_bytes(original)
    for _ in range(2):
        manager = AccountManager(settings)
        assert manager.get(account_id, "original-admin")["selected"]
        assert manager.get(account_id, "original-admin")["label"] == "Existing account"
        assert auth.read_bytes() == original
        with pytest.raises(HTTPException):
            manager.get(account_id, "another-user")
        with pytest.raises(HTTPException):
            manager.get(account_id)
    second = manager.create("codex", "Second owner", "another-user")
    assert second["selected"] and manager.get(account_id, "original-admin")["selected"]


def test_user_scoped_account_routes_and_runtime_admin_gate(settings):
    app = FastAPI()
    async def auth(request: Request):
        return {"id": request.headers.get("x-test-user", "alice"), "role": "admin" if request.headers.get("x-test-user") == "admin" else "user"}
    manager = register_accounts(app, auth, settings)
    with TestClient(app) as client:
        alice = client.post("/api/accounts", json={"provider": "codex", "label": "Alice"}).json()
        bob = client.post("/api/accounts", json={"provider": "codex", "label": "Bob"}, headers={"x-test-user": "bob"}).json()
        assert alice["selected"] and bob["selected"]
        assert [item["id"] for item in client.get("/api/accounts").json()["accounts"]] == [alice["id"]]
        foreign = f"/api/accounts/{bob['id']}"
        for suffix in ("", "/login", "/models"):
            assert client.get(foreign + suffix).status_code == 404
        for suffix in ("/select", "/refresh", "/login", "/login/cancel", "/logout"):
            assert client.post(foreign + suffix).status_code == 404
        assert client.patch(foreign, json={"label": "Changed"}).status_code == 404
        assert client.delete(foreign).status_code == 404
        assert client.post(foreign + "/auth-file", files={"file": ("auth.json", b'{"OPENAI_API_KEY":"synthetic"}')}).status_code == 404
        assert client.get("/api/providers/codex/catalog").status_code == 403
        assert client.post("/api/providers/codex/update", json={"version": "1.2.3"}).status_code == 403
        assert client.post("/api/providers/codex/rollback").status_code == 403
        assert client.get("/api/providers/claude/runtime").json()["can_manage"] is False
        assert client.get("/api/providers/claude/runtime", headers={"x-test-user": "admin"}).json()["can_manage"] is True
        assert client.get("/api/providers/claude/catalog").status_code == 403
        assert client.post("/api/providers/claude/update", json={"version": "2.1.310"}).status_code == 403
        assert client.post("/api/providers/claude/rollback").status_code == 403
        async def catalog():
            return {"latest": "1.2.3"}
        manager.runtime.catalog = catalog
        manager.claude_runtime.catalog = catalog
        assert client.get("/api/providers/codex/catalog", headers={"x-test-user": "admin"}).status_code == 200
        assert client.get("/api/providers/claude/catalog", headers={"x-test-user": "admin"}).json()["latest"] == "1.2.3"
        async def start_claude_update(version, after_switch):
            assert version == "2.1.310"
            assert after_switch == manager.reset_claude
            return {"status": "installing", "version": version}
        manager.claude_runtime.update = start_claude_update
        response = client.post("/api/providers/claude/update", json={"version": "2.1.310"},
                               headers={"x-test-user": "admin"})
        assert response.status_code == 202
        assert response.json()["status"] == "installing"


def test_claude_login_waits_for_runtime_update(settings):
    manager = AccountManager(settings)
    account = manager.create("claude", "Claude", "owner")
    manager.claude_runtime.rolling_back = True
    try:
        with pytest.raises(ProviderError) as error:
            asyncio.run(manager.start_login(account["id"], "owner"))
        assert error.value.code == "busy"
    finally:
        manager.claude_runtime.rolling_back = False


def test_claude_runtime_checks_version_and_solver_cli_contract(tmp_path):
    runtime = ClaudeRuntime(tmp_path / "runtime")
    runtime._verifying_version = "2.1.310"
    fake = tmp_path / "fake_claude.py"
    options = ("--restricted --output-format --include-partial-messages --json-schema "
               "--session-id --resume --model --effort --allowedTools --disallowedTools "
               "--permission-mode --permission-prompts --disable-slash-commands --settings")
    fake.write_text("import sys\nprint('2.1.310' if '--version' in sys.argv else " + repr(options) + ")\n",
                    encoding="utf-8")
    asyncio.run(runtime.verify([sys.executable, str(fake)]))
    fake.write_text("import sys\nprint('2.1.310' if '--version' in sys.argv else '--model')\n",
                    encoding="utf-8")
    with pytest.raises(ProviderError):
        asyncio.run(runtime.verify([sys.executable, str(fake)]))


@pytest.mark.parametrize("raw", [b"", b"[]", b"{}", b"not-json", b'{"OPENAI_API_KEY":null}',
    b'{"OPENAI_API_KEY":"a","OPENAI_API_KEY":"b"}', b'{"OPENAI_API_KEY":NaN}',
    b'{"tokens":{"access_token":"a"}}', b'{"OPENAI_API_KEY":"a","unknown":1}',
    b"x" * (MAX_AUTH_BYTES + 1)], ids=["empty", "array", "missing", "syntax", "null-key", "duplicate", "nan", "incomplete-tokens", "unknown", "oversize"])
def test_auth_import_rejects_invalid_json_or_structure_without_echo(raw):
    with pytest.raises(ProviderError) as error:
        validate_auth_file(raw)
    assert error.value.code == "invalid_auth_file" and error.value.stage == "auth"


def test_auth_import_accepts_known_codex_cache_shapes():
    api = validate_auth_file(b'{"OPENAI_API_KEY":"synthetic-api-key"}')
    assert json.loads(api)["OPENAI_API_KEY"] == "synthetic-api-key"
    tokens = {"auth_mode": "chatgpt", "OPENAI_API_KEY": None, "tokens": {
        "access_token": "synthetic-access", "id_token": "synthetic-id", "refresh_token": "synthetic-refresh", "account_id": "synthetic-account"}}
    assert json.loads(validate_auth_file(json.dumps(tokens).encode())) == tokens


def import_adapter(manager, account_id, owner_id="alice", fail=False):
    adapter = manager.adapter(account_id, owner_id)
    events = []
    async def cancel():
        events.append("cancel")
    async def close():
        events.append("close")
    async def request(method, params=None):
        assert method == "account/read" and params == {"refreshToken": False}
        events.append("verify")
        if fail:
            raise ProviderError("Synthetic verification failure", "auth_required", stage="auth")
        return {"account": {"type": "apiKey"}}
    async def snapshot():
        return {"status": "authenticated", "identity": {"type": "apiKey"}, "quota": {"status": "unsupported", "buckets": []}}
    adapter.cancel_login, adapter.close, adapter.request, adapter.snapshot = cancel, close, request, snapshot
    return adapter, events


def test_auth_file_import_is_owned_private_atomic_and_preserves_other_account(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Alice", "alice")
    other = manager.create("codex", "Bob", "bob")
    untouched = manager.home / other["id"] / "codex" / "auth.json"
    untouched.parent.mkdir(parents=True)
    untouched.write_bytes(b"untouched existing credentials")
    adapter, events = import_adapter(manager, account["id"])
    raw = b'{"OPENAI_API_KEY":"synthetic-new-key"}'
    result = asyncio.run(manager.import_auth(account["id"], raw, "alice"))
    target = adapter.home / "codex" / "auth.json"
    assert json.loads(target.read_bytes()) == json.loads(raw)
    assert untouched.read_bytes() == b"untouched existing credentials"
    assert result["snapshot"]["status"] == "authenticated" and "synthetic-new-key" not in json.dumps(result)
    assert events.index("close") < events.index("verify") and events[-1] == "close"
    assert account["id"] not in manager.adapters and not list(target.parent.glob(".auth-*"))
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("existing", [True, False])
def test_failed_auth_verification_restores_previous_file_and_cleans_process(settings, existing):
    manager = AccountManager(settings)
    account = manager.create("codex", "Alice", "alice")
    adapter, events = import_adapter(manager, account["id"], fail=True)
    target = adapter.home / "codex" / "auth.json"
    target.parent.mkdir(parents=True)
    if existing:
        target.write_bytes(b"existing credentials must remain byte-for-byte")
    with pytest.raises(ProviderError):
        asyncio.run(manager.import_auth(account["id"], b'{"OPENAI_API_KEY":"synthetic-new"}', "alice"))
    assert (target.read_bytes() == b"existing credentials must remain byte-for-byte") if existing else not target.exists()
    assert not list(target.parent.glob(".auth-*")) and events[-1] == "close"
    assert account["id"] not in manager.adapters


def test_auth_import_is_blocked_during_update_and_for_claude(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Alice", "alice")
    manager.runtime.rolling_back = True
    with pytest.raises(ProviderError) as error:
        asyncio.run(manager.import_auth(account["id"], b'{"OPENAI_API_KEY":"synthetic"}', "alice"))
    assert error.value.code == "busy" and not (manager.home / account["id"]).exists()
    claude = manager.create("claude", "Claude", "alice")
    with pytest.raises(ProviderError) as error:
        asyncio.run(manager.import_auth(claude["id"], b'{"OPENAI_API_KEY":"synthetic"}', "alice"))
    assert error.value.code == "unsupported"


def test_fast_tier_requires_actual_model_catalog_and_applies_fixed_configuration(settings):
    manager = AccountManager(settings)
    account = manager.create("codex", "Alice", "alice")
    adapter = manager.adapter(account["id"], "alice")
    async def catalog():
        return {"status": "available", "models": [{"id": "listed-model", "model": "listed-model", "supportedReasoningEfforts": [{"reasoningEffort": "high"}], "serviceTiers": []}]}
    adapter.models = catalog
    with pytest.raises(HTTPException):
        asyncio.run(manager.update(account["id"], {"model": "listed-model", "reasoning_effort": "high", "service_tier": "fast"}, "alice"))
    async def fast_catalog():
        data = await catalog()
        data["models"][0]["serviceTiers"] = [{"id": "fast", "name": "Fast", "description": "Provided by account catalog"}]
        return data
    adapter.models = fast_catalog
    result = asyncio.run(manager.update(account["id"], {"model": "listed-model", "reasoning_effort": "high", "service_tier": "fast"}, "alice"))
    assert result["service_tier"] == "fast"
    args = manager.adapter(account["id"], "alice").configuration_arguments()
    assert 'model="listed-model"' in args and 'model_reasoning_effort="high"' in args
    assert 'service_tier="fast"' in args and "features.fast_mode=true" in args


def test_documented_fast_tier_fills_app_server_gap_only_for_chatgpt_gpt56(settings):
    manager = AccountManager(settings)
    chatgpt = manager.create("codex", "ChatGPT", "alice")
    adapter = manager.adapter(chatgpt["id"], "alice")

    async def catalog():
        return {"status": "available", "models": [
            {"id": "gpt-5.6-sol", "model": "gpt-5.6-sol", "supportedReasoningEfforts": [{"reasoningEffort": "high"}]},
            {"id": "gpt-daybreak-blue-latest", "model": "gpt-daybreak-blue-latest", "supportedReasoningEfforts": [{"reasoningEffort": "high"}]},
        ]}

    adapter.models = catalog
    with manager.connect() as db:
        db.execute("UPDATE provider_accounts SET snapshot=? WHERE id=?", (
            json.dumps({"status": "authenticated", "identity": {"type": "chatgpt"}}), chatgpt["id"]
        ))
    models = asyncio.run(manager.models(chatgpt["id"], "alice"))["models"]
    assert models[0]["serviceTiers"] == [{
        "id": "fast", "name": "1.5배 Fast",
        "description": "ChatGPT Fast 모드: 응답 속도 1.5배, Standard 대비 크레딧 2.5배 사용",
        "source": "official_documentation",
    }]
    assert models[1]["serviceTiers"] == []
    saved = asyncio.run(manager.update(chatgpt["id"], {
        "model": "gpt-5.6-sol", "reasoning_effort": "high", "service_tier": "fast"
    }, "alice"))
    assert saved["service_tier"] == "fast"

    api_key = manager.create("codex", "API", "bob")
    api_adapter = manager.adapter(api_key["id"], "bob")
    api_adapter.models = catalog
    with manager.connect() as db:
        db.execute("UPDATE provider_accounts SET snapshot=? WHERE id=?", (
            json.dumps({"status": "authenticated", "identity": {"type": "apiKey"}}), api_key["id"]
        ))
    assert asyncio.run(manager.models(api_key["id"], "bob"))["models"][0].get("serviceTiers") is None


@pytest.mark.parametrize("message,expected", [
    ("authentication failed", "auth"), ("rate_limit exceeded", "quota"),
    ("model_not_found", "model"), ("upstream unavailable", "temporary"), ("policy_violation TAC", "policy_security")])
def test_provider_errors_are_classified_without_raw_diagnostics(message, expected):
    result = provider_error({"message": message + " /private/auth.json secret-token-value", "code": -32000}, "model")
    assert result.category == expected and result.stage == "model"
    public = {"message": str(result), **result.public()}
    assert "secret-token-value" not in json.dumps(public) and "/private/" not in json.dumps(public)
    if expected == "policy_security":
        assert public["provider_code"] == "TAC" and not public["retryable"]


def test_parallel_account_refreshes_cap_provider_processes_and_close_them(settings):
    async def run():
        manager = AccountManager(settings)
        accounts = [manager.create("codex", f"Account {index}", "alice") for index in range(12)]
        release = asyncio.Event()
        four_started = asyncio.Event()
        state = {"active": 0, "maximum": 0, "started": 0}

        class Adapter:
            def __init__(self):
                self.login = {"status": "idle"}
                self.closed = 0

            async def snapshot(self):
                state["active"] += 1
                state["started"] += 1
                state["maximum"] = max(state["maximum"], state["active"])
                if state["active"] == 4:
                    four_started.set()
                await release.wait()
                state["active"] -= 1
                return {"status": "signed_out", "identity": None,
                        "quota": {"status": "unauthenticated", "buckets": []}}

            async def close(self):
                self.closed += 1

        adapters = {}
        for account in accounts:
            adapters[account["id"]] = Adapter()
            manager.adapters[account["id"]] = adapters[account["id"]]

        tasks = [asyncio.create_task(manager.refresh(account["id"], "alice")) for account in accounts]
        await asyncio.wait_for(four_started.wait(), 1)
        await asyncio.sleep(0.02)
        assert state["started"] == state["maximum"] == 4
        release.set()
        await asyncio.gather(*tasks)
        assert state["maximum"] == 4
        assert all(adapter.closed == 1 for adapter in adapters.values())

    asyncio.run(run())


def test_second_account_login_is_rejected_while_another_is_pending(settings):
    app = FastAPI()

    async def auth():
        return {"id": "alice", "role": "user"}

    manager = register_accounts(app, auth, settings)
    first = manager.create("codex", "First", "alice")
    second = manager.create("codex", "Second", "alice")
    manager.adapter(first["id"], "alice").login = {
        "status": "pending", "login_id": "private-id", "user_code": "SAFE-CODE"
    }
    called = []

    async def must_not_start():
        called.append(True)
        return {"status": "pending"}

    manager.adapter(second["id"], "alice").start_login = must_not_start
    with TestClient(app) as client:
        response = client.post(f"/api/accounts/{second['id']}/login")
        assert response.status_code == 409 and response.json()["code"] == "busy"
    assert called == []


def test_pending_login_limit_allows_second_user_but_caps_instance_at_two(settings):
    manager = AccountManager(settings)
    alice = manager.create("codex", "Alice", "alice")
    bob = manager.create("codex", "Bob", "bob")
    carol = manager.create("codex", "Carol", "carol")
    manager.adapter(alice["id"], "alice").login = {"status": "pending"}
    manager.require_login_slot(bob["id"], "bob")
    manager.adapter(bob["id"], "bob").login = {"status": "pending"}
    with pytest.raises(ProviderError) as error:
        manager.require_login_slot(carol["id"], "carol")
    assert error.value.code == "busy" and error.value.stage == "auth"


def test_auth_file_rollback_when_snapshot_database_save_fails(settings):
    from ctf_agent.providers.auth_file import install_auth_file
    manager = AccountManager(settings)
    account = manager.create("codex", "Alice", "alice")
    adapter, events = import_adapter(manager, account["id"])
    target = adapter.home / "codex" / "auth.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"original credentials")
    def failed_save(snapshot):
        raise sqlite3.OperationalError("simulated database failure")
    with pytest.raises(sqlite3.Error):
        asyncio.run(install_auth_file(adapter, validate_auth_file(b'{"OPENAI_API_KEY":"synthetic-new"}'), manager.home, failed_save))
    assert target.read_bytes() == b"original credentials" and not list(target.parent.glob(".auth-*"))
    assert events[-1] == "close"


def test_auth_import_holds_lifecycle_and_owned_account_lock(settings):
    async def run():
        manager = AccountManager(settings)
        account = manager.create("codex", "Alice", "alice")
        adapter, _events = import_adapter(manager, account["id"])
        async def verify(method, params=None):
            assert manager.lifecycle_lock.locked() and manager.lock(account["id"]).locked()
            return {"account": {"type": "apiKey"}}
        adapter.request = verify
        await manager.import_auth(account["id"], b'{"OPENAI_API_KEY":"synthetic"}', "alice")
        assert not manager.lifecycle_lock.locked() and not manager.lock(account["id"]).locked()
    asyncio.run(run())


def test_login_completion_policy_error_keeps_safe_provider_identifier(tmp_path):
    async def run():
        adapter = CodexAccount(tmp_path, [])
        process = FakeProcess()
        adapter.process = process
        adapter.reader = asyncio.create_task(adapter._read(process))
        adapter.login = {"status": "pending", "login_id": "private-login-id"}
        process.stdout.feed_data((json.dumps({"method": "account/login/completed", "params": {
            "loginId": "private-login-id", "success": False,
            "error": "CVP policy_violation private-token /private/auth.json"}}) + "\n").encode())
        await asyncio.sleep(0)
        assert adapter.login["error"]["provider_code"] == "CVP"
        assert adapter.login["error"]["stage"] == "auth" and not adapter.login["error"]["retryable"]
        assert "private-token" not in json.dumps(adapter.login) and "/private/" not in json.dumps(adapter.login)
        await adapter.close()
    asyncio.run(run())
def test_claude_catalog_exposes_aliases_and_documented_model_ids(tmp_path):
    catalog = asyncio.run(ClaudeAccount(tmp_path / "claude").models())
    assert catalog["status"] == "available"
    assert [item["id"] for item in catalog["models"]] == [
        "default", "claude-opus-5-5", "claude-fable-5-1", "claude-sonnet-5-5",
        "claude-haiku-5-5", "claude-haiku-4-5-20251001", "claude-sonnet-5",
        "claude-opus-5", "claude-fable-5", "claude-opus-4-8", "claude-opus-4-7",
        "claude-opus-4-6", "claude-sonnet-4-6", "best", "fable", "opus", "sonnet", "haiku"
    ]
    assert {
        effort["reasoningEffort"]
        for model in catalog["models"]
        for effort in model["supportedReasoningEfforts"]
    } == {"low", "medium", "high", "xhigh", "max"}
    assert all(model["serviceTiers"] == [] for model in catalog["models"])
