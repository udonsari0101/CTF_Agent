"""Account routes share the real application session, CSRF and response protections."""

import asyncio
import json
import threading
import uuid

from fastapi.testclient import TestClient
import pytest

from ctf_agent.db import Settings
from ctf_agent.main import create_app
from ctf_agent.providers.codex import ProviderError
from ctf_agent.solver_exchange import ExchangeError


def test_accounts_integrate_with_application_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "integration-test-password")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/api/accounts").status_code == 401
        login = client.post("/api/auth/login", json={"password": "integration-test-password"})
        assert login.status_code == 200
        csrf = login.json()["csrf_token"]
        assert client.post("/api/accounts", json={"provider": "codex", "label": "Personal"}).status_code == 403
        client.headers["X-CSRF-Token"] = csrf
        response = client.post("/api/accounts", json={"provider": "codex", "label": "Personal"})
        assert response.status_code == 201
        account = response.json()
        assert account["selected"] is True
        assert response.headers["cache-control"] == "no-store"
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert client.get("/api/accounts").json()["accounts"][0]["id"] == account["id"]
        assert client.get(f"/api/accounts/{account['id']}/login").json()["status"] == "idle"
        # Cross-origin mutations are refused even with the live administrator session and CSRF value.
        assert client.post(f"/api/accounts/{account['id']}/select", headers={"Origin": "https://other.example"}).status_code == 403
        assert client.get("/assets/accounts.js").status_code == 200
        assert client.get("/assets/accounts.css").status_code == 200
        assert client.post("/api/auth/logout").status_code == 200
        assert client.get("/api/accounts").status_code == 401


def test_codex_login_returns_only_public_ceremony_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "integration-test-password")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    app = create_app(settings)
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"password": "integration-test-password"})
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        account = client.post("/api/accounts", json={"provider": "codex", "label": "Personal"}).json()
        adapter = app.state.accounts.adapter(account["id"], account["owner_user_id"])
        async def response(method, params=None):
            return {"type": "chatgptDeviceCode", "verificationUrl": "https://auth.openai.com/codex/device",
                    "userCode": "TEST-1234", "loginId": "ceremony-id", "accessToken": "must-never-leave-server"}
        adapter.request = response
        ceremony = client.post(f"/api/accounts/{account['id']}/login")
        assert ceremony.status_code == 200
        assert ceremony.json()["user_code"] == "TEST-1234"
        assert "must-never-leave-server" not in ceremony.text
        status = client.get(f"/api/accounts/{account['id']}/login")
        assert "login_id" not in status.json()
        async def fail():
            raise ProviderError("Codex 요청에 실패했습니다.", "provider_error")
        adapter.start_login = fail
        failure = client.post(f"/api/accounts/{account['id']}/login")
        assert failure.status_code == 503
        assert failure.json()["code"] == "provider_error"


def test_account_auth_lifecycle_is_blocked_while_that_account_has_an_open_solver_job(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "integration-test-password")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    app = create_app(settings)
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"password": "integration-test-password"})
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        account = client.post("/api/accounts", json={"provider": "codex", "label": "Busy"}).json()
        calls = []

        def open_account(owner_id, account_id, *, connection=None):
            calls.append((owner_id, account_id))
            return True

        monkeypatch.setattr(app.state.solver_jobs, "has_open_account", open_account)
        routes = [
            client.post(f"/api/accounts/{account['id']}/login"),
            client.post(f"/api/accounts/{account['id']}/logout"),
            client.post(
                f"/api/accounts/{account['id']}/auth-file",
                files={"file": ("auth.json", b'{"OPENAI_API_KEY":"synthetic-key"}')},
            ),
            client.delete(f"/api/accounts/{account['id']}"),
        ]
        assert all(response.status_code == 409 and response.json()["code"] == "busy" for response in routes)
        assert len(calls) == 4
        assert client.get(f"/api/accounts/{account['id']}").status_code == 200


def test_logout_and_solver_enqueue_share_a_deterministic_cross_process_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "integration-test-password")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    app = create_app(settings)
    manager = app.state.accounts
    with app.state.connect() as db:
        owner = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone()[0]
    account = manager.create("codex", "Race boundary", owner)
    workspace_id, challenge_id = uuid.uuid4().hex, uuid.uuid4().hex
    stamp = "2026-09-09T00:00:00+00:00"
    with app.state.connect() as db:
        db.execute(
            "UPDATE provider_accounts SET model='gpt-5.6-sol',reasoning_effort='high',snapshot=? WHERE id=?",
            (json.dumps({"status": "authenticated"}), account["id"]),
        )
        db.execute(
            "INSERT INTO workspaces(id,name,description,created_at,updated_at,owner_user_id) VALUES(?,?,?,?,?,?)",
            (workspace_id, "Race", "", stamp, stamp, owner),
        )
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,description,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (challenge_id, workspace_id, "Challenge", "", stamp, stamp),
        )

    adapter = manager.adapter(account["id"], owner)
    entered, finish = threading.Event(), threading.Event()

    async def cancel_login():
        return {"status": "cancelled"}

    async def logout_request(method, params=None):
        assert method == "account/logout"
        entered.set()
        while not finish.is_set():
            await asyncio.sleep(0.01)
        return {}

    async def close():
        return None

    adapter.cancel_login = cancel_login
    adapter.request = logout_request
    adapter.close = close
    result = {}

    def logout():
        result["value"] = asyncio.run(manager.logout(account["id"], owner))

    thread = threading.Thread(target=logout)
    thread.start()
    assert entered.wait(3)
    with pytest.raises(ExchangeError) as error:
        app.state.solver_jobs.enqueue(owner, workspace_id, challenge_id)
    assert error.value.code == "account_busy"
    with app.state.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM solver_jobs").fetchone()[0] == 0
        assert db.execute(
            "SELECT account_id FROM account_lifecycle_blocks WHERE owner_user_id=?", (owner,)
        ).fetchone()[0] == account["id"]
    finish.set()
    thread.join(3)
    assert not thread.is_alive()
    assert result["value"]["snapshot"]["status"] == "signed_out"
    with app.state.connect() as db:
        assert not db.execute(
            "SELECT 1 FROM account_lifecycle_blocks WHERE owner_user_id=?", (owner,)
        ).fetchone()


def test_pending_login_blocks_solver_until_the_ceremony_is_cancelled(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "integration-test-password")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    app = create_app(settings)
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"password": "integration-test-password"})
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        account = client.post("/api/accounts", json={"provider": "codex", "label": "Pending"}).json()
        owner = account["owner_user_id"]
        workspace = client.post("/api/workspaces", json={"name": "Pending race"}).json()
        challenge = client.post(
            f"/api/workspaces/{workspace['id']}/challenges", json={"name": "Challenge"}
        ).json()
        with app.state.connect() as db:
            db.execute(
                "UPDATE provider_accounts SET model='gpt-5.6-sol',reasoning_effort='high',snapshot=? WHERE id=?",
                (json.dumps({"status": "authenticated"}), account["id"]),
            )
        adapter = app.state.accounts.adapter(account["id"], owner)

        async def start_pending():
            adapter.login = {"status": "pending", "user_code": "TEST-CODE"}
            return adapter.login

        async def cancel_pending():
            adapter.login = {"status": "cancelled"}
            return adapter.login

        async def close():
            return None

        adapter.start_login = start_pending
        adapter.cancel_login = cancel_pending
        adapter.close = close
        assert client.post(f"/api/accounts/{account['id']}/login").json()["status"] == "pending"
        with pytest.raises(ExchangeError) as error:
            app.state.solver_jobs.enqueue(owner, workspace["id"], challenge["id"])
        assert error.value.code == "account_busy"
        assert client.post(f"/api/accounts/{account['id']}/login/cancel").status_code == 200
        queued = app.state.solver_jobs.enqueue(owner, workspace["id"], challenge["id"])
        assert queued["status"] == "queued"
