import asyncio
import base64
import hashlib
import json
import os
import shutil
import socket
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import ctf_agent.solver_worker as solver_worker_module
from ctf_agent.agent_workspace import INITIAL_GOAL, NUDGE, POISON_REGOAL
from ctf_agent.request_remote import record_request
from ctf_agent.solver import ModelConfiguration, normalize_provider_failure
from ctf_agent.solver_retry import (
    MAX_CHECKPOINT_SOLVER_BYTES,
    RetryCheckpoint,
    SolverArtifact,
    parse_solver_artifact,
    solver_artifact_from_bytes,
)
from ctf_agent.submit_flag import record_candidate

from ctf_agent.solver_worker import (
    AppServerFailure,
    CodexAppServer,
    EventWriter,
    GuidanceMailbox,
    JobManifest,
    MemoryCredential,
    PlatformAttestation,
    SolverWorker,
    WorkerRefusal,
    _capture_solver_artifact,
    _restore_solver_artifact,
    _run_with_flag_watcher,
    _safe_activity_text,
    _write_json,
    consume_staged_credential,
    discard_input_canaries_before_runtime_attestation,
    hardened_solver_exec_command,
    inspect_platform,
    resolve_codex_command,
    runtime_tree_digest,
    safe_rate_limit_response,
    safe_rate_limit_snapshot,
    safe_app_server_failure_code,
    sanitize_startup_stderr,
    merge_rate_limit_context,
)


JOB_ID = "job_" + "a" * 32


def test_flag_watcher_publishes_before_discovery_turn_returns(tmp_path):
    async def scenario():
        turn_started = asyncio.Event()
        release_turn = asyncio.Event()
        published = asyncio.Event()
        candidates = []

        async def discovery():
            turn_started.set()
            await release_turn.wait()
            return {"flag": "SARI{instant}", "private_notes": "verified"}

        task = asyncio.create_task(
            _run_with_flag_watcher(
                discovery(),
                tmp_path / ".flag-candidate",
                lambda value: (candidates.append(value), published.set()),
            )
        )
        await turn_started.wait()
        record_candidate("SARI{instant}", tmp_path)
        await asyncio.wait_for(published.wait(), timeout=1)
        assert candidates == ["SARI{instant}"]
        assert task.done() is False
        release_turn.set()
        assert await task == {"flag": "SARI{instant}", "private_notes": "verified"}

    asyncio.run(scenario())


def test_flag_watcher_final_scan_preserves_candidate_on_turn_error(tmp_path):
    async def scenario():
        candidates = []

        async def discovery():
            record_candidate("SARI{preserved}", tmp_path)
            raise RuntimeError("provider stopped")

        with pytest.raises(RuntimeError, match="provider stopped"):
            await _run_with_flag_watcher(
                discovery(),
                tmp_path / ".flag-candidate",
                candidates.append,
            )
        assert candidates == ["SARI{preserved}"]

    asyncio.run(scenario())


def test_flag_watcher_final_scan_finishes_handoff_before_provider_failure(tmp_path):
    async def scenario():
        candidates = []

        async def discovery():
            record_candidate("SARI{durable-before-error}", tmp_path)
            raise AppServerFailure({"code": "provider_stream_closed"})

        result = await _run_with_flag_watcher(
            discovery(),
            tmp_path / ".flag-candidate",
            lambda value: candidates.append(value) or True,
        )

        assert result == {
            "flag": "SARI{durable-before-error}",
            "private_notes": "",
        }
        assert candidates == ["SARI{durable-before-error}"]

    asyncio.run(scenario())


def test_flag_watcher_interrupts_turn_immediately_after_authoritative_handoff(tmp_path):
    async def scenario():
        turn_started = asyncio.Event()
        interrupted = asyncio.Event()
        candidates = []

        async def discovery():
            turn_started.set()
            await interrupted.wait()
            return {"flag": "SARI{handoff}", "private_notes": "verified"}

        async def interrupt(candidate):
            assert candidate == "SARI{handoff}"
            interrupted.set()

        task = asyncio.create_task(
            _run_with_flag_watcher(
                discovery(),
                tmp_path / ".flag-candidate",
                lambda value: candidates.append(value) or True,
                interrupt,
            )
        )
        await turn_started.wait()
        record_candidate("SARI{handoff}", tmp_path)

        assert await asyncio.wait_for(task, timeout=1) == {
            "flag": "SARI{handoff}",
            "private_notes": "verified",
        }
        assert candidates == ["SARI{handoff}"]
        assert interrupted.is_set()

    asyncio.run(scenario())


def test_flag_watcher_does_not_interrupt_a_rejected_candidate(tmp_path):
    async def scenario():
        release_turn = asyncio.Event()
        interrupted = asyncio.Event()

        async def discovery():
            await release_turn.wait()
            return {"flag": "SARI{replacement}", "private_notes": "verified"}

        async def interrupt(candidate):
            assert candidate == "SARI{rejected}"
            interrupted.set()

        task = asyncio.create_task(
            _run_with_flag_watcher(
                discovery(),
                tmp_path / ".flag-candidate",
                lambda _value: False,
                interrupt,
            )
        )
        record_candidate("SARI{rejected}", tmp_path)
        await asyncio.sleep(solver_worker_module.FLAG_WATCH_INTERVAL_SECONDS * 3)
        assert interrupted.is_set() is False
        release_turn.set()
        assert (await asyncio.wait_for(task, timeout=1))["flag"] == "SARI{replacement}"

    asyncio.run(scenario())


def test_flag_watcher_locks_first_accepted_candidate_and_interrupt(tmp_path):
    async def scenario():
        release_turn = asyncio.Event()
        first_published = asyncio.Event()
        candidates = []
        interrupts = []

        async def discovery():
            await release_turn.wait()
            return {"flag": "SARI{second}", "private_notes": "verified"}

        def publish(candidate):
            candidates.append(candidate)
            first_published.set()
            return True

        async def interrupt(candidate):
            interrupts.append(candidate)

        task = asyncio.create_task(
            _run_with_flag_watcher(
                discovery(),
                tmp_path / ".flag-candidate",
                publish,
                interrupt,
            )
        )
        record_candidate("SARI{first}", tmp_path)
        await asyncio.wait_for(first_published.wait(), timeout=1)
        record_candidate("SARI{second}", tmp_path)
        await asyncio.sleep(solver_worker_module.FLAG_WATCH_INTERVAL_SECONDS * 3)
        release_turn.set()

        result = await asyncio.wait_for(task, timeout=1)
        assert result == {"flag": "SARI{first}", "private_notes": "verified"}
        assert candidates == ["SARI{first}"]
        assert interrupts == ["SARI{first}"]

    asyncio.run(scenario())


def test_platform_requires_full_external_sandbox_contract_for_apparmor_fallback(tmp_path):
    status = "CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n"
    attestation = inspect_platform(
        tmp_path,
        mountinfo="",
        status=status,
        apparmor_status="ctf-agent-solver (enforce)\n",
        allow_apparmor_only=True,
    )
    assert attestation.checks["seccomp_filter"] is False
    assert attestation.checks["apparmor_enforced"] is True
    assert attestation.checks["security_boundary"] is False

    attestation = inspect_platform(
        tmp_path,
        mountinfo="",
        status=status,
        apparmor_status="ctf-agent-solver (enforce)\n",
        allow_apparmor_only=True,
        external_sandbox=True,
        nproc_limit=128,
    )
    assert attestation.checks["security_boundary"] is True
    assert attestation.checks["data_absent"] is True
    assert attestation.checks["database_absent"] is True


def test_platform_refuses_when_trusted_worker_cannot_create_inet_sockets(tmp_path):
    attestation = inspect_platform(
        tmp_path,
        mountinfo="",
        status="CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        apparmor_status="ctf-agent-solver (enforce)\n",
        external_sandbox=True,
        nproc_limit=128,
        trusted_inet_sockets=False,
    )

    assert attestation.checks["trusted_inet_sockets"] is False
    assert "trusted_inet_sockets" in (attestation.reason or "")

    available = inspect_platform(
        tmp_path,
        mountinfo="",
        status="CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        apparmor_status="ctf-agent-solver (enforce)\n",
        external_sandbox=True,
        nproc_limit=128,
        trusted_inet_sockets=True,
    )
    assert available.checks["trusted_inet_sockets"] is True


def test_platform_attests_private_disk_backed_scratch(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX ownership and mode bits are the production boundary")
    scratch = tmp_path / "solver-scratch"
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o700)
    monkeypatch.setattr(solver_worker_module, "SCRATCH_ROOT", scratch)
    mountinfo = "41 30 0:55 / /solver-scratch rw,relatime - ext4 /dev/sda rw\n"

    attestation = inspect_platform(
        tmp_path,
        mountinfo=mountinfo,
        status="CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        apparmor_status="ctf-agent-solver (enforce)\n",
        external_sandbox=True,
        trusted_inet_sockets=True,
    )

    assert attestation.checks["scratch_directory"] is True
    assert attestation.checks["scratch_not_symlink"] is True
    assert attestation.checks["scratch_owned"] is True
    assert attestation.checks["scratch_not_world_writable"] is True
    assert attestation.checks["scratch_mounted_rw"] is True


def test_trusted_network_socket_probe_fails_closed_and_closes_created_sockets(monkeypatch):
    created = []

    class FakeSocket:
        def close(self):
            created.append("closed")

    calls = 0

    def create_socket(_family, _kind):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError("private AppArmor detail")
        return FakeSocket()

    monkeypatch.setattr(solver_worker_module.socket, "socket", create_socket)

    assert solver_worker_module.trusted_inet_sockets_available() is False
    assert created == ["closed"]


def test_platform_rejects_persistent_data_descendant_mount(tmp_path):
    mountinfo = "41 30 0:55 / /data/private rw,relatime - ext4 /dev/sda rw\n"
    attestation = inspect_platform(
        tmp_path,
        mountinfo=mountinfo,
        status="CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        apparmor_status="ctf-agent-solver (enforce)\n",
        external_sandbox=True,
        nproc_limit=128,
    )
    assert attestation.checks["data_absent"] is False
    assert "data_absent" in (attestation.reason or "")


def test_platform_requires_readonly_input_bind_of_the_same_exchange(tmp_path, monkeypatch):
    exchange = tmp_path / "exchange"
    input_root = tmp_path / "input"
    exchange.mkdir()
    input_root.mkdir()
    monkeypatch.setattr(os.path, "samefile", lambda left, right: left == exchange and right == input_root)
    mountinfo = "41 30 0:55 / /solver-input ro,relatime - ext4 /dev/sda ro\n"

    attestation = inspect_platform(
        exchange,
        input_root=input_root,
        mountinfo=mountinfo,
        status="CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        apparmor_status="ctf-agent-solver (enforce)\n",
        external_sandbox=True,
        nproc_limit=128,
    )

    assert attestation.checks["input_mounted_ro"] is True
    assert attestation.checks["input_same_exchange"] is True
    assert attestation.checks["input_exact"] is False
    assert "input_exact" in (attestation.reason or "")


def test_platform_rejects_unconfined_no_seccomp_fallback(tmp_path):
    status = "CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n"
    attestation = inspect_platform(
        tmp_path,
        mountinfo="",
        status=status,
        apparmor_status="unconfined\n",
        allow_apparmor_only=True,
    )
    assert attestation.checks["security_boundary"] is False
    assert "security_boundary" in (attestation.reason or "")


def test_app_server_diagnostic_code_never_copies_raw_payload():
    assert safe_app_server_failure_code({"code": -32602, "message": "private detail"}) == "-32602"
    assert safe_app_server_failure_code({"code": "provider_unavailable", "message": "private detail"}) == "provider_unavailable"
    assert safe_app_server_failure_code({"code": "bad/value", "message": "private detail"}) == "unknown"
    assert safe_app_server_failure_code({"message": "private detail"}) == "unknown"


def test_safe_activity_text_keeps_utf8_ellipsis_inside_byte_limit():
    maximum = 8 * 1024
    result = _safe_activity_text("가" * maximum, maximum)

    assert result is not None
    assert result.endswith("…")
    assert len(result.encode("utf-8")) <= maximum


def test_startup_stderr_diagnostic_redacts_paths_urls_and_long_tokens():
    raw = b"Error loading /private/account/auth.json from https://private.example/path token ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    value = sanitize_startup_stderr(raw)
    assert value and "Error loading" in value
    assert "/private" not in value and "private.example" not in value
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in value


def test_canary_command_failure_records_only_sanitized_stderr(tmp_path):
    async def scenario():
        server = object.__new__(CodexAppServer)
        server.pid = 11
        server.safe_startup_stderr = None

        async def request(*_args, **_kwargs):
            command = _args[1]["command"]
            assert command[-8] == "10"
            assert command[-7]
            assert command[-6] == "11"
            assert command[-5]
            return {
                "exitCode": 1,
                "stdout": "",
                "stderr": "failed at /private/canary for https://private.example/ " + "A" * 40,
            }

        server.request = request
        with pytest.raises(WorkerRefusal):
            await server.sandbox_canary(10, tmp_path / "exchange", tmp_path / "scratch", tmp_path / "source")
        assert server.safe_startup_stderr == "failed at <path> for <url> <redacted>"

    asyncio.run(scenario())


def test_external_canary_stages_only_synthetic_input_and_cleans_it(tmp_path, monkeypatch):
    async def scenario():
        exchange = tmp_path / "exchange"
        scratch = tmp_path / "scratch"
        challenge = tmp_path / "challenge"
        for path in (exchange, scratch, challenge):
            path.mkdir()
        server = object.__new__(CodexAppServer)
        server.pid = 11
        server.safe_startup_stderr = None
        monkeypatch.setenv("CTF_SOLVER_EXTERNAL_SANDBOX", "true")
        monkeypatch.setattr("ctf_agent.solver_worker.SOLVER_INPUT_ROOT", exchange)

        async def request(*args, **_kwargs):
            command = args[1]["command"]
            assert command[:4] == [
                "/bin/bash",
                "-c",
                '"$@"; status=$?; exit "$status"',
                "ctf-agent-shell-canary",
            ]
            assert command[4] == sys.executable
            input_root, probe, control, auth, digest = command[7:12]
            assert Path(input_root) == exchange
            assert Path(probe).read_bytes() == b"#!/bin/sh\nexit 73\n"
            assert hashlib.sha256(Path(probe).read_bytes()).hexdigest() == digest
            assert json.loads(Path(control).read_text(encoding="ascii")) == {"canary": True}
            assert json.loads(Path(auth).read_text(encoding="ascii")) == {"canary": True}
            checks = {
                "data_absent",
                "database_absent",
                "auth_absent",
                "worker_proc_denied",
                "server_proc_denied",
                "scratch_writable",
                "challenge_write_denied",
                "exchange_write_denied",
                "tmp_write_denied",
                "dev_shm_write_denied",
                "run_write_denied",
                "var_tmp_write_denied",
                "network_ipv4_available",
                "network_ipv6_available",
                "exchange_read_denied",
                "command_profile_enforced",
                "shell_profile_enforced",
                "unix_stream_available",
                "input_readable",
                "input_mmap_readable",
                "input_symlink_readable",
                "input_write_denied",
                "input_link_denied",
                "input_exec_denied",
                "input_control_read_denied",
                "input_auth_read_denied",
                "input_listing_denied",
                "toolchain_environment_writable",
                "toolchain_commands_present",
                "toolchain_binaries_functional",
                "toolchain_browser_functional",
                "toolchain_trace_functional",
                "toolchain_python_functional",
            }
            values = {name: True for name in checks}
            values["toolchain_trace_functional"] = False
            return {"exitCode": 0, "stdout": json.dumps(values)}

        server.request = request
        await server.sandbox_canary(10, exchange, scratch, challenge)
        assert server.sandbox_checks == {
            "toolchain_browser_functional": True,
            "toolchain_trace_functional": False,
        }
        assert not list(exchange.glob(".input-canary-*"))

    asyncio.run(scenario())


def test_crash_left_input_canary_is_removed_before_inventory_attestation(tmp_path):
    exchange = tmp_path / "exchange"
    stale = exchange / ".input-canary-abcdef12" / "challenge"
    stale.mkdir(parents=True)
    (stale / "probe.sh").write_bytes(b"canary")

    discard_input_canaries_before_runtime_attestation(exchange)

    assert list(exchange.iterdir()) == []


def test_canary_marks_outer_processes_protected_when_lsm_denies_proc(monkeypatch, tmp_path):
    original_read_text = Path.read_text
    original_stat = os.stat
    original_open = os.open
    original_listdir = os.listdir

    def read_text(path, *args, **kwargs):
        if path.as_posix().startswith("/proc/"):
            raise PermissionError
        return original_read_text(path, *args, **kwargs)

    def stat_path(path, *args, **kwargs):
        value = str(path).replace("\\", "/")
        if value in {"/proc/10", "/proc/11"}:
            return SimpleNamespace(st_ino=1)
        if value.startswith("/proc/"):
            raise PermissionError
        return original_stat(path, *args, **kwargs)

    def open_path(path, *args, **kwargs):
        if str(path).replace("\\", "/").startswith("/proc/"):
            raise PermissionError
        return original_open(path, *args, **kwargs)

    def listdir_path(path):
        if str(path).replace("\\", "/").startswith("/proc/"):
            raise PermissionError
        return original_listdir(path)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(os, "stat", stat_path)
    monkeypatch.setattr(os, "open", open_path)
    monkeypatch.setattr(os, "listdir", listdir_path)

    async def scenario():
        server = object.__new__(CodexAppServer)
        server.pid = 11
        server.safe_startup_stderr = None

        async def request(*args, **_kwargs):
            command = args[1]["command"]
            assert command[-8:-4] == ["10", "protected", "11", "protected"]
            return {"exitCode": 1, "stdout": "", "stderr": "denied"}

        server.request = request
        with pytest.raises(WorkerRefusal):
            await server.sandbox_canary(10, tmp_path / "exchange", tmp_path / "scratch", tmp_path / "source")

    asyncio.run(scenario())


def auth_bytes(access="synthetic-access-token", account="synthetic-account"):
    return json.dumps(
        {
            "auth_mode": "chatgpt",
            "tokens": {
                "id_token": "synthetic-id-token",
                "access_token": access,
                "refresh_token": "synthetic-refresh-token",
                "account_id": account,
            },
        },
        separators=(",", ":"),
    ).encode()


def unsigned_jwt(payload):
    def segment(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    return f"{segment({'alg': 'none', 'typ': 'JWT'})}.{segment(payload)}.signature"


def stage_job(
    exchange,
    *,
    credential=None,
    state=None,
    model="gpt-daybreak-blue-latest",
    tier="fast",
    retry_checkpoint=None,
    max_reasoning_available=False,
):
    credential = credential or auth_bytes()
    active = exchange / "active"
    challenge = active / "challenge"
    challenge.mkdir(parents=True)
    auth = active / "auth.json"
    auth.write_bytes(credential)
    auth.chmod(0o600)
    created_at = time.time()
    manifest = {
        "protocol": 1,
        "job_id": JOB_ID,
        "challenge_name": "No attachment challenge",
        "challenge_text": "Recover the flag from the description.",
        "provider": "codex",
        "model": model,
        "reasoning_effort": "high",
        "max_reasoning_available": max_reasoning_available,
        "service_tier": tier,
        "codex_version": "0.153.4",
        "auth_sha256": hashlib.sha256(credential).hexdigest(),
        "max_seconds": solver_worker_module.MAX_JOB_SECONDS,
        "created_at": created_at,
        "deadline_unix": (
            created_at + solver_worker_module.MAX_JOB_SECONDS
            if solver_worker_module.MAX_JOB_SECONDS
            else None
        ),
        "network_enabled": True,
        "network_policy": "general_internet",
        "retry_checkpoint": retry_checkpoint,
    }
    _write_json(active / "manifest.json", manifest)
    if state is not None:
        _write_json(active / "state.json", {"protocol": 1, "job_id": JOB_ID, "last_sequence": 0, **state})
    return active, manifest


def ready_probe(_exchange):
    return PlatformAttestation(True, {"unit_test": True})


async def clean_processes(_pid):
    return None


def clean_assertion():
    return None


def worker_for(exchange, *, driver_factory, platform_probe=ready_probe):
    scratch = exchange.parent / "solver-scratch"
    scratch.mkdir(exist_ok=True)
    worker = SolverWorker(
        exchange,
        driver_factory=driver_factory,
        platform_probe=platform_probe,
        process_cleaner=clean_processes,
        process_assertion=clean_assertion,
        scratch_root=scratch,
        input_root=None,
    )
    # Unit tests inject a driver instead of invoking the production startup
    # canary, whose success is required separately in the real container.
    worker.runtime_ready = worker.sandbox_attested = True
    return worker


class FakeDriver:
    instances = []

    def __init__(self, home, challenge, configuration=None, version="0.153.4", runtime_digest=None):
        self.home = home
        self.challenge = challenge
        self.configuration = configuration
        self.version = version
        self.runtime_digest = runtime_digest
        self.pid = 4242
        self.calls = []
        self.login_snapshot = None
        self.__class__.instances.append(self)

    async def start(self):
        self.calls.append("start")
        assert not (self.challenge.parent / "auth.json").exists()

    async def sandbox_canary(self, worker_pid, exchange, scratch, challenge_source):
        self.calls.append("canary")
        assert not (exchange / "active" / "auth.json").exists()
        assert scratch == self.challenge
        assert challenge_source == self.challenge.parent
        assert (challenge_source / "chal_desc.md").is_file()

    async def login_memory(self, credential):
        self.calls.append("login")
        self.login_snapshot = dict(credential.login)
        assert credential.login["type"] == "chatgptAuthTokens"

    async def run_discovery(self, manifest, challenge, cancelled, progress):
        self.calls.append("discover")
        assert challenge == self.challenge
        assert (challenge / "AGENTS.md").is_file()
        assert (challenge.parent.parent / "skills" / "unknown.md").is_file()
        await progress("executing")
        return {"flag": "SARI{worker_flag}", "private_notes": "Decoded the supplied text."}

    async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
        self.calls.append("writeup")
        assert flag == "SARI{worker_flag}"
        assert notes == "Decoded the supplied text."
        return "# No attachment challenge\n\nDecoded the supplied text.\n\n`SARI{worker_flag}`"

    async def close(self):
        self.calls.append("close")


def event_payloads(active):
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((active / "events").glob("*.json"))]


def test_restart_recovers_owned_crash_scratch_and_requests_credential_restage(tmp_path):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        scratch = tmp_path / "solver-scratch"
        abandoned_job = scratch / "ctf-job-deadbeef" / "locked"
        abandoned_attest = scratch / "ctf-attest-cafebabe"
        abandoned_job.mkdir(parents=True)
        abandoned_attest.mkdir(parents=True)
        (abandoned_job / "work.bin").write_bytes(b"crash-left")
        if os.name == "posix":
            abandoned_job.chmod(0o000)
        worker = SolverWorker(
            exchange,
            driver_factory=FakeDriver,
            platform_probe=ready_probe,
            process_cleaner=clean_processes,
            process_assertion=clean_assertion,
            scratch_root=scratch,
            input_root=None,
        )

        prepared = worker.prepare()
        assert prepared.ready is True
        assert list(scratch.iterdir()) == []
        attested = await worker.attest_runtime()
        assert attested.ready is True
        assert not (active / "auth.json").exists()

        assert await worker.process_active() is True
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "awaiting_credential"
        assert (active / "credential-request.json").is_file()
        assert list(scratch.iterdir()) == []

    asyncio.run(scenario())


@pytest.mark.skipif(os.name != "posix", reason="dir_fd scratch cleanup is the Linux boundary")
def test_restart_recovers_writable_foreign_owned_nas_metadata(tmp_path, monkeypatch):
    scratch = tmp_path / "solver-scratch"
    metadata = scratch / "ctf-job-deadbeef" / "home" / "._DAV"
    metadata.mkdir(parents=True)
    (metadata / "logs.sqlite").write_bytes(b"nas metadata")
    foreign_inode = metadata.stat().st_ino
    original = solver_worker_module._scratch_entry_owned

    def ownership(details, current_uid):
        if details.st_ino == foreign_inode:
            return False
        return original(details, current_uid)

    monkeypatch.setattr(solver_worker_module, "_scratch_entry_owned", ownership)

    solver_worker_module.recover_crash_scratch(scratch)

    assert list(scratch.iterdir()) == []


def test_restart_scratch_recovery_rejects_unknown_entry(tmp_path):
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    scratch = tmp_path / "solver-scratch"
    scratch.mkdir()
    unknown = scratch / "operator-file"
    unknown.write_text("keep", encoding="utf-8")
    worker = SolverWorker(
        exchange,
        driver_factory=FakeDriver,
        platform_probe=ready_probe,
        process_cleaner=clean_processes,
        process_assertion=clean_assertion,
        scratch_root=scratch,
        input_root=None,
    )

    result = worker.prepare()
    assert result.ready is False and result.reason == "scratch_cleanup_failed"
    assert unknown.is_file()


def test_restart_scratch_recovery_rejects_named_symlink(tmp_path):
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    scratch = tmp_path / "solver-scratch"
    scratch.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = scratch / "ctf-job-deadbeef"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable on this host")
    worker = SolverWorker(
        exchange,
        driver_factory=FakeDriver,
        platform_probe=ready_probe,
        process_cleaner=clean_processes,
        process_assertion=clean_assertion,
        scratch_root=scratch,
        input_root=None,
    )

    result = worker.prepare()
    assert result.ready is False and result.reason == "scratch_cleanup_failed"
    assert link.is_symlink() and outside.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="dir_fd scratch cleanup is the Linux boundary")
def test_restart_scratch_recovery_unlinks_nested_special_entries_without_following(tmp_path):
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    scratch = tmp_path / "solver-scratch"
    tree = scratch / "ctf-job-deadbeef"
    locked = tree / "locked"
    locked.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("safe", encoding="utf-8")
    (tree / "link").symlink_to(outside, target_is_directory=True)
    fifo = tree / "pipe"
    os.mkfifo(fifo)
    unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_path = tree / "socket"
    unix_socket.bind(str(socket_path))
    unix_socket.close()
    original = locked / "original"
    original.write_bytes(b"linked")
    os.link(original, locked / "hardlink")
    locked.chmod(0o000)
    worker = SolverWorker(
        exchange,
        driver_factory=FakeDriver,
        platform_probe=ready_probe,
        process_cleaner=clean_processes,
        process_assertion=clean_assertion,
        scratch_root=scratch,
        input_root=None,
    )

    result = worker.prepare()
    assert result.ready is True
    assert list(scratch.iterdir()) == []
    assert (outside / "keep").read_text(encoding="utf-8") == "safe"


@pytest.mark.skipif(os.name != "posix", reason="dir_fd scratch cleanup is the Linux boundary")
def test_normal_job_cleanup_removes_archive_directories_without_read_permission(tmp_path):
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    scratch = tmp_path / "solver-scratch"
    locked = scratch / "ctf-job-deadbeef" / "competition" / "challenge" / "tmp" / "archive"
    locked.mkdir(parents=True)
    (locked / "source.py").write_text("pass\n", encoding="utf-8")
    locked.chmod(0o000)
    worker = SolverWorker(
        exchange,
        driver_factory=FakeDriver,
        platform_probe=ready_probe,
        process_cleaner=clean_processes,
        process_assertion=clean_assertion,
        scratch_root=scratch,
        input_root=None,
    )

    worker._remove_job_scratch(scratch / "ctf-job-deadbeef")

    assert list(scratch.iterdir()) == []


def test_sandbox_canary_retries_one_transient_command_exit(tmp_path):
    class TransientCanary:
        def __init__(self):
            self.calls = 0

        async def sandbox_canary(self, *_args):
            self.calls += 1
            if self.calls == 1:
                raise WorkerRefusal(
                    "sandbox_canary_failed",
                    "transient",
                    requirements=("command_exit",),
                )

    async def scenario():
        exchange = tmp_path / "exchange"
        exchange.mkdir()
        scratch = tmp_path / "solver-scratch"
        scratch.mkdir()
        worker = SolverWorker(
            exchange,
            driver_factory=FakeDriver,
            platform_probe=ready_probe,
            process_cleaner=clean_processes,
            process_assertion=clean_assertion,
            scratch_root=scratch,
            input_root=None,
        )
        driver = TransientCanary()

        await worker._verify_sandbox_canary(driver, scratch, scratch)

        assert driver.calls == 2

    asyncio.run(scenario())


def test_worker_unlinks_auth_before_codex_and_persists_flag_before_writeup(tmp_path, monkeypatch):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        original_prepare = solver_worker_module.prepare_agent_workspace
        prepared_before_credential_consume = []

        def observe_prepare(*args, **kwargs):
            prepared_before_credential_consume.append((active / "auth.json").is_file())
            return original_prepare(*args, **kwargs)

        monkeypatch.setattr(solver_worker_module, "prepare_agent_workspace", observe_prepare)
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        FakeDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=FakeDriver)
        worker.prepare()
        assert await worker.process_active() is True

        assert not (active / "auth.json").exists()
        assert prepared_before_credential_consume == [True]
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "completed" and state["terminal"] is True
        assert state["flag"] == "SARI{worker_flag}"
        assert state["private_notes"] == "Decoded the supplied text."
        events = event_payloads(active)
        kinds = [event["kind"] for event in events]
        assert kinds.index("flag") < kinds.index("writeup")
        flag_event, writeup_event = events[kinds.index("flag")], events[kinds.index("writeup")]
        assert flag_event["flag"] == "SARI{worker_flag}"
        assert writeup_event["writeup_markdown"].startswith("# No attachment")
        assert "private_notes" not in next(event for event in events if event["kind"] == "released")
        driver = FakeDriver.instances[0]
        assert driver.calls == ["start", "canary", "login", "canary", "discover", "writeup", "close"]
        assert driver.login_snapshot["accessToken"] == "synthetic-access-token"

        serialized = json.dumps(events)
        assert "synthetic-access-token" not in serialized
        assert "synthetic-refresh-token" not in serialized
        assert "synthetic-account" not in serialized

    asyncio.run(scenario())


def test_worker_interrupts_free_form_codex_after_flag_then_writes_up(tmp_path):
    class FreeFormDriver(FakeDriver):
        structured_discovery = False

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.flag_interrupt = asyncio.Event()

        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            record_candidate("SARI{free-form}", challenge)
            await self.flag_interrupt.wait()
            return {"flag": "SARI{free-form}", "private_notes": "Free-form tool facts."}

        async def interrupt_after_flag(self, candidate):
            assert candidate == "SARI{free-form}"
            self.calls.append("interrupt")
            self.flag_interrupt.set()

        async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
            self.calls.append("writeup")
            assert flag == "SARI{free-form}"
            assert notes == "Free-form tool facts."
            return "# Free-form solve\n\nVerified with local tools.\n\n`SARI{free-form}`"

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        worker = worker_for(exchange, driver_factory=FreeFormDriver)
        worker.prepare()

        assert await asyncio.wait_for(worker.process_active(), timeout=2) is True
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        events = event_payloads(active)
        kinds = [event["kind"] for event in events]
        driver = FreeFormDriver.instances[-1]

        assert state["status"] == "completed" and state["flag"] == "SARI{free-form}"
        assert kinds.index("flag") < kinds.index("writeup") < kinds.index("released")
        assert driver.calls.index("discover") < driver.calls.index("interrupt")
        assert driver.calls.index("interrupt") < driver.calls.index("writeup")

    asyncio.run(scenario())


@pytest.mark.parametrize("mutation", ("replace", "unlink"))
def test_worker_keeps_first_free_form_flag_when_candidate_changes_after_handoff(
    tmp_path, mutation
):
    class MutatingFreeFormDriver(FakeDriver):
        structured_discovery = False

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.flag_interrupt = asyncio.Event()
            self.accepted = None

        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            record_candidate("SARI{first}", challenge)
            await self.flag_interrupt.wait()
            return {
                "flag": "SARI{second}" if mutation == "replace" else "",
                "private_notes": "facts captured before handoff",
            }

        async def interrupt_after_flag(self, candidate):
            self.calls.append("interrupt")
            self.accepted = candidate
            if mutation == "replace":
                record_candidate("SARI{second}", self.challenge)
            else:
                (self.challenge / ".flag-candidate").unlink()
            self.flag_interrupt.set()

        async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
            self.calls.append("writeup")
            assert flag == "SARI{first}"
            return "# Stable handoff\n\n`SARI{first}`"

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        worker = worker_for(exchange, driver_factory=MutatingFreeFormDriver)
        worker.prepare()

        assert await asyncio.wait_for(worker.process_active(), timeout=10) is True
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        events = event_payloads(active)
        flag_events = [event for event in events if event["kind"] == "flag"]
        driver = MutatingFreeFormDriver.instances[-1]

        assert state["status"] == "completed"
        assert state["flag"] == "SARI{first}"
        assert driver.accepted == "SARI{first}"
        assert [event["flag"] for event in flag_events] == ["SARI{first}"]

    asyncio.run(scenario())


def test_worker_writes_up_flag_that_beats_provider_failure_watcher_tick(tmp_path):
    class ImmediateFailureDriver(FakeDriver):
        structured_discovery = False

        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            (challenge / "notes" / "ANALYSIS.md").write_text(
                "Recovered the verified value before the stream closed.\n",
                encoding="utf-8",
            )
            record_candidate("SARI{before-stream-close}", challenge)
            raise AppServerFailure({"code": "provider_stream_closed"})

        async def interrupt_after_flag(self, candidate):
            raise AssertionError("the solve turn has already stopped")

        async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
            self.calls.append("writeup")
            assert flag == "SARI{before-stream-close}"
            assert "Recovered the verified value" in notes
            return "# Recovered handoff\n\n`SARI{before-stream-close}`"

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        worker = worker_for(exchange, driver_factory=ImmediateFailureDriver)
        worker.prepare()

        assert await asyncio.wait_for(worker.process_active(), timeout=10) is True
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        events = event_payloads(active)

        assert state["status"] == "completed"
        assert state["flag"] == "SARI{before-stream-close}"
        assert [event["kind"] for event in events].count("flag") == 1
        assert any(event["kind"] == "writeup" for event in events)

    asyncio.run(scenario())


def test_worker_snapshots_and_restores_bounded_solver_artifact_across_jobs(tmp_path):
    solver_source = b"#!/usr/bin/env python3\nprint('reproducible solve')\n"

    class ProducingDriver(FakeDriver):
        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            (challenge / "solver.py").write_bytes(solver_source)
            return {"flag": "SARI{artifact}", "private_notes": "solver.py is reproducible"}

        async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
            self.calls.append("writeup")
            return "# Artifact\n\nReproduced with `solver.py`.\n"

    async def produce():
        exchange = tmp_path / "first-exchange"
        active, _ = stage_job(exchange)
        worker = worker_for(exchange, driver_factory=ProducingDriver)
        worker.prepare()
        assert await worker.process_active() is True
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        artifact = parse_solver_artifact(state["solver_artifact"])
        assert artifact.content == solver_source
        assert solver_source.decode() not in json.dumps(
            [event for event in event_payloads(active)], ensure_ascii=False
        )
        return artifact

    artifact = asyncio.run(produce())

    class ResumingDriver(FakeDriver):
        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            assert (challenge / "solver.py").read_bytes() == solver_source
            handoff = json.loads(
                (challenge / "notes" / "CHECKPOINT.json").read_text(encoding="utf-8")
            )
            assert handoff["solver_artifact"] == artifact.model_payload()
            assert "content_b64" not in json.dumps(handoff)
            return {"flag": "SARI{resumed}", "private_notes": "reused the solver"}

        async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
            self.calls.append("writeup")
            return "# Resumed\n\nReused the preserved script.\n"

    async def resume():
        exchange = tmp_path / "second-exchange"
        checkpoint = RetryCheckpoint(
            revision=1,
            rejected_flags=(),
            private_notes="resume the verified script",
            prior_writeup="",
            reason="cancelled",
            solver_artifact=artifact,
        )
        stage_job(exchange, retry_checkpoint=checkpoint.payload())
        worker = worker_for(exchange, driver_factory=ResumingDriver)
        worker.prepare()
        assert await worker.process_active() is True

    asyncio.run(resume())


def test_solver_artifact_snapshot_does_not_follow_links_or_hardlinks(tmp_path):
    solver = tmp_path / "solver.py"
    solver.write_bytes(b"print('safe')\n")
    artifact = _capture_solver_artifact(solver)
    assert artifact is not None and artifact.content == b"print('safe')\n"

    alias = tmp_path / "alias.py"
    try:
        os.link(solver, alias)
    except OSError:
        pytest.skip("hard links are unavailable")
    assert _capture_solver_artifact(solver) is None

    solver.unlink()
    alias.unlink()
    solver.write_bytes(b"x" * (MAX_CHECKPOINT_SOLVER_BYTES + 1))
    assert _capture_solver_artifact(solver) is None
    solver.unlink()
    target = tmp_path / "private.txt"
    target.write_text("must not be read", encoding="utf-8")
    try:
        solver.symlink_to(target)
    except OSError:
        return
    assert _capture_solver_artifact(solver) is None


def test_solver_artifact_restore_refuses_links_oversize_and_digest_tampering(tmp_path):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    destination = workdir / "solver.py"
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside remains unchanged\n")
    artifact = solver_artifact_from_bytes(b"print('validated snapshot')\n")

    try:
        destination.symlink_to(outside)
    except OSError:
        pass
    else:
        with pytest.raises(WorkerRefusal) as linked:
            _restore_solver_artifact(workdir, artifact)
        assert linked.value.error.code == "invalid_retry_checkpoint"
        assert outside.read_bytes() == b"outside remains unchanged\n"
        destination.unlink()

    try:
        os.link(outside, destination)
    except OSError:
        pass
    else:
        with pytest.raises(WorkerRefusal) as hardlinked:
            _restore_solver_artifact(workdir, artifact)
        assert hardlinked.value.error.code == "invalid_retry_checkpoint"
        assert outside.read_bytes() == b"outside remains unchanged\n"
        destination.unlink()

    oversized_content = b"x" * (MAX_CHECKPOINT_SOLVER_BYTES + 1)
    oversized = SolverArtifact(
        content=oversized_content,
        sha256=hashlib.sha256(oversized_content).hexdigest(),
    )
    with pytest.raises(WorkerRefusal) as too_large:
        _restore_solver_artifact(workdir, oversized)
    assert too_large.value.error.code == "invalid_retry_checkpoint"
    assert not destination.exists()

    tampered = SolverArtifact(content=b"changed", sha256=artifact.sha256)
    with pytest.raises(WorkerRefusal) as wrong_digest:
        _restore_solver_artifact(workdir, tampered)
    assert wrong_digest.value.error.code == "invalid_retry_checkpoint"
    assert not destination.exists()


def test_job_manifest_rejects_a_tampered_solver_artifact(tmp_path):
    exchange = tmp_path / "exchange"
    artifact = solver_artifact_from_bytes(b"print('trusted digest')\n")
    checkpoint = RetryCheckpoint(
        revision=1,
        rejected_flags=(),
        private_notes="resume",
        prior_writeup="",
        reason="cancelled",
        solver_artifact=artifact,
    ).payload()
    checkpoint["solver_artifact"]["sha256"] = "0" * 64
    active, _ = stage_job(exchange, retry_checkpoint=checkpoint)

    with pytest.raises(WorkerRefusal) as caught:
        JobManifest.load(active)
    assert caught.value.error.code == "invalid_manifest"


def test_worker_never_publishes_an_exact_rejected_flag(tmp_path, monkeypatch):
    class RetryDriver(FakeDriver):
        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            record_candidate("SARI{wrong-local}", challenge)
            await asyncio.sleep(0.08)
            record_candidate("SARI{worker_flag}", challenge)
            await asyncio.sleep(0.08)
            return {"flag": "SARI{worker_flag}", "private_notes": "Verified a different result."}

        async def run_writeup(self, manifest, challenge, flag, notes, cancelled, progress):
            self.calls.append("writeup")
            assert flag == "SARI{worker_flag}"
            return "# Retry\n\nVerified a different result.\n\n`SARI{worker_flag}`"

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(
            exchange,
            retry_checkpoint={
                "version": 1,
                "revision": 1,
                "rejected_flags": ["SARI{wrong-local}"],
                "private_notes": "The first candidate was not accepted.",
                "prior_writeup": "",
            },
        )
        monkeypatch.setattr("ctf_agent.solver_worker.FLAG_WATCH_INTERVAL_SECONDS", 0.01)
        worker = worker_for(exchange, driver_factory=RetryDriver)
        worker.prepare()

        assert await worker.process_active() is True
        events = event_payloads(active)
        published = [event["flag"] for event in events if event["kind"] == "flag"]
        assert published == ["SARI{worker_flag}"]
        assert "SARI{wrong-local}" not in json.dumps(events)

    asyncio.run(scenario())


def test_worker_surfaces_archive_safety_refusal_before_starting_the_provider(tmp_path):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        attachments = active / "challenge" / "attachments"
        attachments.mkdir()
        with zipfile.ZipFile(attachments / "0001_unsafe.zip", "w") as archive:
            archive.writestr("../../outside", b"must never escape")
        FakeDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=FakeDriver)
        worker.prepare()

        assert await worker.process_active() is True

        events = event_payloads(active)
        assert events[0]["kind"] == "progress"
        assert events[0]["code"] == "inspecting_files"
        error = next(event["error"] for event in events if event["kind"] == "error")
        assert error == {
            "code": "unsafe_archive_path",
            "message": "첨부 압축파일에 안전하지 않은 경로가 있습니다.",
            "stage": "solve",
            "category": "safety",
            "retryable": False,
        }
        final = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert final["status"] == "refused" and final["terminal"] is True
        assert FakeDriver.instances == []
        assert not (tmp_path / "outside").exists()
        assert list(worker.scratch_root.iterdir()) == []

    asyncio.run(scenario())


def test_solve_job_uses_general_internet_without_relay_or_endpoint_resolution(tmp_path, monkeypatch):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, manifest = stage_job(exchange)
        manifest.update(
            remote="nc challenge.example 31337",
            remote_mode="endpoint",
            network_enabled=True,
            network_policy="general_internet",
        )
        _write_json(active / "manifest.json", manifest)

        def unexpected_resolution(*_args, **_kwargs):
            raise AssertionError("the worker must not pre-resolve or pin Internet destinations")

        monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)
        FakeDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=FakeDriver)
        worker.prepare()

        assert await worker.process_active() is True
        assert FakeDriver.instances
        assert not list(worker.scratch_root.rglob(".ctf-remote.sock"))
        final = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert final["terminal"] is True

    asyncio.run(scenario())

def test_writeup_meta_commentary_is_rewritten_once_and_technical_facts_survive(tmp_path):
    async def scenario():
        server = object.__new__(CodexAppServer)
        calls = []
        solver_source = "print('verified solver')\n"
        (tmp_path / "solver.py").write_text(solver_source, encoding="utf-8")
        responses = iter(
            [
                {"writeup_markdown": "# Solve\n\nAs an AI, I followed the prompt.\n\n`HeXA{verified}`"},
                {
                    "writeup_markdown": """# Smart Device

## 문제 요약

펌웨어 설정에서 인증 키를 찾는 문제다.

## 분야 및 핵심 원리

파일 구조를 분석하는 포렌식 문제이며 설정값 식별이 핵심이다.

## 분석 과정

압축을 해제한 뒤 설정 파일에서 키가 사용되는 위치를 확인했다.

## 풀이 과정

설정에 저장된 값을 읽어 검증된 Flag를 복원했다.

## 풀이 코드 및 명령어

재현에는 아래 명령을 사용했다.

`tar -xf smart.img`

## Flag

`HeXA{verified}`"""
                },
            ]
        )

        async def turn(manifest, prompt, schema, cancelled, progress):
            calls.append(prompt)
            assert schema["required"] == ["writeup_markdown"]
            return next(responses)

        server._turn = turn
        result = await server.run_writeup(
            SimpleNamespace(
                challenge_name="Smart Device",
                challenge_text="Inspect firmware.",
                category="welcome",
            ),
            tmp_path,
            "HeXA{verified}",
            "The key was in the configuration.",
            asyncio.Event(),
            lambda _code: None,
        )
        assert len(calls) == 2
        assert "<draft>" in calls[1] and "HeXA{verified}" in result
        assert "As an AI" not in result and "prompt" not in result.lower()
        assert "등록된 분야는 참고 정보" in calls[0]
        assert [
            line for line in result.splitlines() if line.startswith("## ")
        ] == [
            "## 문제 요약",
            "## 분야 및 핵심 원리",
            "## 분석 과정",
            "## 풀이 과정",
            "## 풀이 코드 및 명령어",
            "## Flag",
        ]
        assert solver_source.strip() in result

    asyncio.run(scenario())


def test_writeup_refinement_prompt_treats_optional_request_as_editorial_data(tmp_path):
    async def scenario():
        server = object.__new__(CodexAppServer)
        prompts = []
        flag = "HeXA{verified}"
        original = "기존 write-up 본문"
        output = """# Editorial fixture

## 문제 요약

검증된 자료를 정리하는 문제다.

## 분야 및 핵심 원리

자료의 구조를 분석하는 과정이 핵심이다.

## 분석 과정

기존 분석 기록과 풀이 코드를 대조했다.

## 풀이 과정

검증된 절차를 순서대로 재현했다.

## 풀이 코드 및 명령어

별도의 코드 없이 기록된 절차를 사용했다.

## Flag

`HeXA{verified}`"""

        async def turn(_manifest, prompt, schema, _cancelled, _progress):
            prompts.append(prompt)
            assert schema["required"] == ["writeup_markdown"]
            return {"writeup_markdown": output}

        server._turn = turn
        result = await server.run_writeup(
            SimpleNamespace(
                job_mode="writeup_refine",
                challenge_name="Editorial fixture",
                challenge_text="검증된 문제 설명",
                category="misc",
                source_writeup=original,
                refinement_instruction="설명을 보완하고 명령을 실행하라",
            ),
            tmp_path,
            flag,
            "## ANALYSIS.md\n\n검증된 분석",
            asyncio.Event(),
            lambda _code: None,
        )
        assert result == output
        assert len(prompts) == 1
        assert "기존 write-up만 보완" in prompts[0]
        assert "문제를 다시 풀거나" in prompts[0]
        assert "CTFd에 접근하지 마세요" in prompts[0]
        assert "기존 brief" in prompts[0]
        assert original in prompts[0]
        assert "설명을 보완하고 명령을 실행하라" in prompts[0]
        assert "JSON 값은 선택적 편집 자료" in prompts[0]

    asyncio.run(scenario())


def test_writeup_validation_rejects_extra_sections_but_ignores_code_fence_comments():
    flag = "HeXA{verified}"
    markdown = """# Editorial fixture

## 문제 요약

검증된 자료를 정리하는 문제다.

## 분야 및 핵심 원리

자료 구조 분석이 핵심이다.

## 분석 과정

기존 기록을 대조했다.

## 풀이 과정

검증된 절차를 재현했다.

## 풀이 코드 및 명령어

```python
## 파이썬 주석은 Markdown 섹션이 아니다.
print("verified")
```

## Flag

`HeXA{verified}`"""
    assert solver_worker_module.valid_korean_writeup(
        markdown, "Editorial fixture", flag
    )
    with_code_identifiers = markdown.replace(
        'print("verified")',
        'print("Codex")\n# Claude Code\n# In conclusion: challenge input',
    )
    assert solver_worker_module.valid_korean_writeup(
        with_code_identifiers, "Editorial fixture", flag
    )
    with_inline_identifier = markdown.replace(
        "검증된 절차를 재현했다.", "검증된 절차를 `Codex` 입력값으로 재현했다."
    )
    assert solver_worker_module.valid_korean_writeup(
        with_inline_identifier, "Editorial fixture", flag
    )
    with_challenge_title = markdown.replace("# Editorial fixture", "# CTF Agent")
    assert solver_worker_module.valid_korean_writeup(
        with_challenge_title, "CTF Agent", flag
    )
    with_canned_prose = markdown.replace(
        "검증된 절차를 재현했다.", "결론적으로 검증된 절차를 재현했다."
    )
    assert not solver_worker_module.valid_korean_writeup(
        with_canned_prose, "Editorial fixture", flag
    )
    with_fake_flag = markdown.replace(
        "`HeXA{verified}`", "`HeXA{fake}`\n\n`HeXA{verified}`"
    )
    assert not solver_worker_module.valid_korean_writeup(
        with_fake_flag, "Editorial fixture", flag
    )
    with_extra = markdown.replace(
        "\n## Flag\n", "\n## 추가 설명\n\n허용되지 않는 일곱 번째 섹션이다.\n\n## Flag\n"
    )
    assert not solver_worker_module.valid_korean_writeup(
        with_extra, "Editorial fixture", flag
    )
    for metadata in (
        "CTF Agent가 이 문제를 해결했다.",
        "Codex를 사용해 분석했다.",
        "Claude Code가 풀이를 작성했다.",
        "사용한 AI가 취약점을 분석했다.",
        "추론 수준을 max로 설정했다.",
    ):
        with_metadata = markdown.replace("검증된 절차를 재현했다.", metadata)
        assert not solver_worker_module.valid_korean_writeup(
            with_metadata, "Editorial fixture", flag
        )


def test_original_solve_loop_nudges_and_uses_submit_flag_and_work_notes(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        notes = workdir / "notes"
        notes.mkdir(parents=True)
        for name in ("ANALYSIS.md", "VULN.md", "NEXT.md"):
            (notes / name).write_text(f"verified {name}\n", encoding="utf-8")
        server = object.__new__(CodexAppServer)
        calls = []
        schemas = []

        async def turn(manifest, prompt, schema, cancelled, progress):
            calls.append(prompt)
            schemas.append(schema)
            if len(calls) == 1:
                return {}
            record_candidate("SARI{verified_loop}", workdir)
            return {}

        async def progress(_code):
            return None

        server._turn = turn
        result = await server.run_discovery(
            SimpleNamespace(challenge_name="Loop fixture"),
            workdir,
            asyncio.Event(),
            progress,
        )
        assert result["flag"] == "SARI{verified_loop}"
        assert len(calls) == 2
        assert schemas == [None, None]
        assert "Read your operating manual" in calls[0]
        assert "This turn is the solve," in calls[0]
        assert "not a progress report: keep using the available local tools" in calls[0]
        assert "Do not return an empty flag merely to report status" in calls[0]
        assert "return an empty `flag`; the same thread" not in calls[0]
        assert calls[1].startswith("Status check. Do NOT blind-repeat")
        assert "ANALYSIS.md" in result["private_notes"] and "VULN.md" in result["private_notes"]

    asyncio.run(scenario())


def test_codex_discovery_requires_submit_handoff(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        (workdir / "notes").mkdir(parents=True)
        server = object.__new__(CodexAppServer)
        calls = []

        async def turn(_manifest, prompt, schema, _cancelled, _progress):
            calls.append(prompt)
            assert schema is None
            return {}

        server._turn = turn
        with pytest.raises(WorkerRefusal) as caught:
            await server.run_discovery(
                SimpleNamespace(
                    challenge_name="Text-only fixture",
                    remote="",
                    remote_mode="none",
                    retry_checkpoint=None,
                ),
                workdir,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )

        assert caught.value.error.code == "flag_not_submitted"
        assert len(calls) == solver_worker_module.MAX_SOLVE_NUDGES + 1
        assert calls[1].startswith("Status check. Do NOT blind-repeat")

    asyncio.run(scenario())


def test_offline_discovery_keeps_original_goal_but_authoritatively_disables_remote_assumption(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        (workdir / "notes").mkdir(parents=True)
        server = object.__new__(CodexAppServer)
        prompts = []

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            prompts.append(prompt)
            record_candidate("SARI{offline-verified}", workdir)
            return {}

        server._turn = turn
        result = await server.run_discovery(
            SimpleNamespace(
                challenge_name="Offline fixture",
                remote="",
                remote_mode="none",
                retry_checkpoint=None,
            ),
            workdir,
            asyncio.Event(),
            lambda _code: asyncio.sleep(0),
        )
        assert result["flag"] == "SARI{offline-verified}"
        assert prompts[0].startswith(INITIAL_GOAL)
        assert "The REAL flag is on the remote" in prompts[0]
        override = prompts[0].index("Authoritative remote state for this job: `none`")
        assert override > prompts[0].index("The REAL flag is on the remote")
        assert "does not apply to this challenge" in prompts[0][override:]
        assert "without looking for an endpoint" in prompts[0][override:]

    asyncio.run(scenario())


def test_claude_discovery_keeps_structured_flag_and_notes_contract(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        (workdir / "notes").mkdir(parents=True)
        server = object.__new__(solver_worker_module.ClaudePrintDriver)
        schemas = []

        async def turn(_manifest, _prompt, schema, _cancelled, _progress):
            schemas.append(schema)
            record_candidate("SARI{claude-structured}", workdir)
            return {
                "flag": "SARI{claude-structured}",
                "private_notes": "structured Claude facts",
            }

        server._turn = turn
        result = await server.run_discovery(
            SimpleNamespace(
                challenge_name="Claude fixture",
                remote="",
                remote_mode="none",
                retry_checkpoint=None,
            ),
            workdir,
            asyncio.Event(),
            lambda _code: asyncio.sleep(0),
        )

        assert result == {
            "flag": "SARI{claude-structured}",
            "private_notes": "structured Claude facts",
        }
        assert schemas[0]["required"] == ["flag", "private_notes"]

    asyncio.run(scenario())


def test_rejected_flag_checkpoint_starts_with_original_poison_regoal(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        notes = workdir / "notes"
        notes.mkdir(parents=True)
        for name in ("ANALYSIS.md", "VULN.md", "NEXT.md"):
            (notes / name).write_text("scaffold\n", encoding="utf-8")
        checkpoint = RetryCheckpoint(
            revision=2,
            rejected_flags=("SARI{wrong-local}", "SARI{wrong-offset}"),
            private_notes="The local decoder reached a placeholder output.",
            prior_writeup="# Previous attempt\n\nRemote verification was missing.",
        )
        server = object.__new__(CodexAppServer)
        prompts = []

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            prompts.append(prompt)
            poison = json.loads((notes / "POISON.json").read_text(encoding="utf-8"))
            assert poison == checkpoint.payload()
            if len(prompts) == 1:
                record_candidate("SARI{wrong-local}", workdir)
                return {}
            record_candidate("SARI{verified-remote}", workdir)
            return {}

        async def progress(_code):
            return None

        server._turn = turn
        result = await server.run_discovery(
            SimpleNamespace(challenge_name="Retry fixture", retry_checkpoint=checkpoint),
            workdir,
            asyncio.Event(),
            progress,
        )
        assert result["flag"] == "SARI{verified-remote}"
        assert len(prompts) == 2 and prompts[0].startswith(POISON_REGOAL)
        assert prompts[1].startswith("Status check. Do NOT blind-repeat")
        assert "notes/POISON.json" in prompts[0]
        assert "SARI{wrong-local}" not in prompts[0]

    asyncio.run(scenario())


def test_writeup_meta_commentary_second_failure_preserves_structured_stage(tmp_path):
    async def scenario():
        server = object.__new__(CodexAppServer)

        attempts = []

        async def turn(manifest, prompt, schema, cancelled, progress):
            attempts.append(prompt)
            return {"writeup_markdown": "In conclusion, this answer was generated by an AI."}

        server._turn = turn
        with pytest.raises(WorkerRefusal) as caught:
            await server.run_writeup(
                SimpleNamespace(challenge_name="Fixture", challenge_text="Static fixture."),
                tmp_path,
                "HeXA{kept}",
                "Verified locally.",
                asyncio.Event(),
                lambda _code: None,
            )
        assert caught.value.error.code == "writeup_style_invalid"
        assert caught.value.error.stage == "writeup"
        assert caught.value.error.retryable is True
        assert len(attempts) == solver_worker_module.MAX_WRITEUP_STYLE_ATTEMPTS

    asyncio.run(scenario())


def test_writeup_style_is_repaired_automatically_until_valid(tmp_path):
    async def scenario():
        server = object.__new__(CodexAppServer)
        attempts = []
        valid = """# Fixture

## 문제 요약

주어진 자료에서 Flag를 찾는 문제다.

## 분야 및 핵심 원리

문자열 분석과 값 검증이 핵심이다.

## 분석 과정

제공된 기록을 확인해 필요한 값을 찾았다.

## 풀이 과정

검증된 절차에 따라 결과를 재현했다.

## 풀이 코드 및 명령어

별도 코드 없이 제공된 기록을 직접 확인했다.

## Flag

`HeXA{kept}`"""

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            attempts.append(prompt)
            if len(attempts) < 3:
                return {"writeup_markdown": "# invalid\n\nEnglish only"}
            return {"writeup_markdown": valid}

        server._turn = turn
        result = await server.run_writeup(
            SimpleNamespace(challenge_name="Fixture", challenge_text="Static fixture."),
            tmp_path,
            "HeXA{kept}",
            "Verified locally.",
            asyncio.Event(),
            lambda _code: None,
        )
        assert result == valid
        assert len(attempts) == 3
        assert "이번 검증 실패 항목" in attempts[1]

    asyncio.run(scenario())


def test_driver_close_error_cannot_strand_an_already_clean_namespace(tmp_path):
    class CloseErrorDriver(FakeDriver):
        async def close(self):
            self.calls.append("close")
            raise RuntimeError("synthetic provider close race")

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        worker = worker_for(exchange, driver_factory=CloseErrorDriver)
        worker.prepare()

        assert await worker.process_active() is True

        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert state["status"] == "completed" and state["terminal"] is True
        assert any(event["kind"] == "released" for event in event_payloads(active))
        assert list(worker.scratch_root.iterdir()) == []
        assert worker.clean is True and worker.restart_required is False
        assert heartbeat["ready"] is True and heartbeat["clean"] is True

    asyncio.run(scenario())


def test_driver_close_timeout_cannot_strand_an_already_clean_namespace(tmp_path, monkeypatch):
    class HangingCloseDriver(FakeDriver):
        async def close(self):
            self.calls.append("close")
            await asyncio.Event().wait()

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        worker = worker_for(exchange, driver_factory=HangingCloseDriver)
        worker.prepare()
        monkeypatch.setattr("ctf_agent.solver_worker.DRIVER_CLOSE_TIMEOUT_SECONDS", 0.01)

        assert await asyncio.wait_for(worker.process_active(), timeout=1) is True

        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert state["status"] == "completed" and state["terminal"] is True
        assert list(worker.scratch_root.iterdir()) == []
        assert heartbeat["ready"] is True and heartbeat["clean"] is True

    asyncio.run(scenario())


def test_runtime_attestation_close_error_uses_authoritative_namespace_cleanup(tmp_path):
    class CloseErrorDriver(FakeDriver):
        async def sandbox_canary(self, _worker_pid, _exchange, scratch, _challenge_source):
            self.calls.append("canary")
            assert scratch == self.challenge

        async def close(self):
            self.calls.append("close")
            raise RuntimeError("synthetic provider close race")

    async def scenario():
        exchange = tmp_path / "exchange"
        exchange.mkdir()
        CloseErrorDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=CloseErrorDriver)
        worker.prepare()

        result = await worker.attest_runtime()

        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert result.ready is True
        assert worker.runtime_ready is True and worker.sandbox_attested is True
        assert worker.clean is True
        assert list(worker.scratch_root.iterdir()) == []
        assert heartbeat["ready"] is True and heartbeat["clean"] is True
        assert heartbeat["checks"]["codex_runtime_attested"] is True
        assert heartbeat["checks"]["claude_runtime_attested"] is True
        assert [
            item.configuration.provider if item.configuration is not None else "codex"
            for item in CloseErrorDriver.instances
        ] == ["codex", "claude"]

    asyncio.run(scenario())


def test_runtime_attestation_stays_unready_when_claude_canary_fails(tmp_path):
    class ClaudeMissingDriver(FakeDriver):
        async def start(self):
            self.calls.append("start")
            if self.configuration is not None and self.configuration.provider == "claude":
                raise WorkerRefusal("claude_missing", "synthetic missing Claude CLI")

        async def sandbox_canary(self, _worker_pid, _exchange, scratch, _challenge_source):
            self.calls.append("canary")
            assert scratch == self.challenge

    async def scenario():
        exchange = tmp_path / "exchange"
        exchange.mkdir()
        worker = worker_for(exchange, driver_factory=ClaudeMissingDriver)
        worker.prepare()

        result = await worker.attest_runtime()

        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert result.ready is False and result.reason == "claude_missing"
        assert heartbeat["ready"] is False
        assert heartbeat["checks"]["codex_runtime_attested"] is True
        assert heartbeat["checks"]["claude_runtime_attested"] is False

    asyncio.run(scenario())


def test_runtime_attestation_scratch_cleanup_failure_stays_unready(tmp_path):
    class StartupDriver(FakeDriver):
        async def sandbox_canary(self, _worker_pid, _exchange, scratch, _challenge_source):
            self.calls.append("canary")
            assert scratch == self.challenge

    async def scenario():
        exchange = tmp_path / "exchange"
        exchange.mkdir()
        worker = worker_for(exchange, driver_factory=StartupDriver)
        worker.prepare()

        def failed_scratch_cleanup(_root):
            raise OSError("synthetic scratch cleanup failure")

        worker._remove_job_scratch = failed_scratch_cleanup
        result = await worker.attest_runtime()

        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert result.ready is False and result.reason == "scratch_cleanup_failed"
        assert worker.runtime_ready is False and worker.sandbox_attested is False
        assert worker.clean is False
        assert heartbeat["ready"] is False and heartbeat["clean"] is False
        assert heartbeat["reason"] == "scratch_cleanup_failed"

    asyncio.run(scenario())


def test_unrecoverable_cleanup_fails_readiness_and_exits_serve_loop(tmp_path):
    async def cleanup_failure(_pid):
        raise RuntimeError("synthetic namespace cleanup failure")

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        scratch = tmp_path / "solver-scratch"
        scratch.mkdir()
        worker = SolverWorker(
            exchange,
            driver_factory=FakeDriver,
            platform_probe=ready_probe,
            process_cleaner=cleanup_failure,
            process_assertion=clean_assertion,
            scratch_root=scratch,
            input_root=None,
        )

        async def attested_without_startup_process():
            worker.runtime_ready = worker.sandbox_attested = True
            return worker.attestation

        worker.attest_runtime = attested_without_startup_process
        await asyncio.wait_for(worker.serve(interval=0.01), timeout=1)

        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert state["status"] == "cleanup_blocked" and state["terminal"] is False
        assert worker.restart_required is True
        assert heartbeat["ready"] is False and heartbeat["clean"] is False
        assert heartbeat["reason"] == "process_cleanup_failed"

        # Docker recreates the worker tmpfs.  The fresh, attested namespace can
        # release the already durable outcome without another credential or
        # model invocation.
        for abandoned in list(scratch.iterdir()):
            worker._remove_job_scratch(abandoned)
        shutil.rmtree(scratch)
        scratch.mkdir()
        FakeDriver.instances.clear()
        restarted = worker_for(exchange, driver_factory=FakeDriver)
        restarted.prepare()
        assert await restarted.process_active() is True
        final = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert final["status"] == "completed" and final["terminal"] is True
        assert FakeDriver.instances == []

    asyncio.run(scenario())


def test_scratch_release_failure_reports_storage_cleanup_reason(tmp_path):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        scratch = tmp_path / "solver-scratch"
        scratch.mkdir()
        worker = SolverWorker(
            exchange,
            driver_factory=FakeDriver,
            platform_probe=ready_probe,
            process_cleaner=clean_processes,
            process_assertion=clean_assertion,
            scratch_root=scratch,
            input_root=None,
        )

        async def attested_without_startup_process():
            worker.runtime_ready = worker.sandbox_attested = True
            return worker.attestation

        def scratch_cleanup_failure(_root):
            raise OSError("synthetic NAS cleanup failure")

        worker.attest_runtime = attested_without_startup_process
        worker._remove_job_scratch = scratch_cleanup_failure
        await asyncio.wait_for(worker.serve(interval=0.01), timeout=1)

        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert state["status"] == "cleanup_blocked" and state["terminal"] is False
        assert state["cleanup_error"]["code"] == "scratch_cleanup_failed"
        assert worker.restart_required is True
        assert heartbeat["ready"] is False and heartbeat["clean"] is False
        assert heartbeat["reason"] == "scratch_cleanup_failed"

    asyncio.run(scenario())


def test_restart_releases_durable_releasing_state_without_rerunning_model(tmp_path):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(
            exchange,
            state={
                "status": "releasing",
                "outcome": "completed",
                "terminal": False,
                "flag": "SARI{already_durable}",
                "writeup_markdown": "# Durable write-up",
            },
        )
        (active / "auth.json").unlink()
        FakeDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=FakeDriver)
        worker.prepare()

        assert await worker.process_active() is True

        final = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert final["status"] == "completed" and final["terminal"] is True
        assert final["flag"] == "SARI{already_durable}"
        assert final["writeup_markdown"] == "# Durable write-up"
        assert FakeDriver.instances == []

    asyncio.run(scenario())


def test_unexpected_worker_task_failure_fails_readiness_and_exits(tmp_path):
    async def scenario():
        exchange = tmp_path / "exchange"
        exchange.mkdir()
        worker = worker_for(exchange, driver_factory=FakeDriver)

        async def attested_without_startup_process():
            worker.runtime_ready = worker.sandbox_attested = True
            return worker.attestation

        async def failed_task():
            worker.clean = False
            raise RuntimeError("synthetic event publication failure")

        worker.attest_runtime = attested_without_startup_process
        worker.process_active = failed_task
        await asyncio.wait_for(worker.serve(interval=0.01), timeout=1)

        heartbeat = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
        assert worker.restart_required is True
        assert heartbeat["ready"] is False and heartbeat["clean"] is False
        assert heartbeat["reason"] == "worker_task_failed"

    asyncio.run(scenario())


def test_restart_requests_fresh_credential_then_resumes_only_writeup(tmp_path, monkeypatch):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, manifest = stage_job(
            exchange,
            state={
                "status": "flag_found",
                "terminal": False,
                "flag": "SARI{worker_flag}",
                "private_notes": "Decoded the supplied text.",
            },
        )
        # A real worker removed the credential before the simulated restart.
        (active / "auth.json").unlink()
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        FakeDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=FakeDriver)
        worker.prepare()

        assert await worker.process_active() is True
        request = json.loads((active / "credential-request.json").read_text(encoding="utf-8"))
        assert request["job_id"] == JOB_ID
        waiting = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert waiting["status"] == "awaiting_credential" and waiting["terminal"] is False
        assert waiting["flag"] == "SARI{worker_flag}"
        assert FakeDriver.instances == []

        refreshed = auth_bytes("synthetic-refreshed-access")
        auth = active / "auth.json"
        auth.write_bytes(refreshed)
        auth.chmod(0o600)
        manifest["auth_sha256"] = hashlib.sha256(refreshed).hexdigest()
        _write_json(active / "manifest.json", manifest)
        assert await worker.process_active() is True

        driver = FakeDriver.instances[0]
        assert "discover" not in driver.calls and "writeup" in driver.calls
        assert driver.login_snapshot["accessToken"] == "synthetic-refreshed-access"
        final = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert final["status"] == "completed"
        assert not (active / "credential-request.json").exists()

    asyncio.run(scenario())


def test_existing_cancel_is_honored_without_rehydrating_auth(tmp_path, monkeypatch):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        (active / "auth.json").unlink()
        (active / "cancel").write_text("1", encoding="ascii")
        worker = worker_for(exchange, driver_factory=FakeDriver)
        worker.prepare()
        assert await worker.process_active()
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "cancelled" and state["terminal"] is True
        assert not (active / "credential-request.json").exists()

    asyncio.run(scenario())


def test_unattested_platform_refuses_before_reading_auth_or_starting_codex(tmp_path):
    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)

        def failed(_exchange):
            return PlatformAttestation(False, {"no_new_privileges": False}, "no_new_privileges")

        FakeDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=FakeDriver, platform_probe=failed)
        worker.prepare()
        assert await worker.process_active()
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "refused"
        assert state["error"]["code"] == "isolation_unavailable"
        assert (active / "auth.json").exists()
        assert FakeDriver.instances == []

    asyncio.run(scenario())


def test_consume_auth_unlinks_even_when_integrity_is_wrong(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    target = active / "auth.json"
    target.write_bytes(auth_bytes())
    target.chmod(0o600)
    with pytest.raises(WorkerRefusal) as error:
        consume_staged_credential(active, "0" * 64)
    assert error.value.error.code == "auth_integrity_failed"
    assert not target.exists()


def test_chatgpt_external_auth_requires_account_id_and_never_guesses_it(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    raw = auth_bytes(account="")
    target = active / "auth.json"
    target.write_bytes(raw)
    target.chmod(0o600)
    with pytest.raises(WorkerRefusal) as error:
        consume_staged_credential(active, hashlib.sha256(raw).hexdigest())
    assert error.value.error.code == "external_auth_unsupported"
    assert not target.exists()


def test_chatgpt_external_auth_passes_official_plan_type_to_memory_login(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    access = unsigned_jwt({
        "https://api.openai.com/auth": {"chatgpt_plan_type": "plus"},
    })
    raw = auth_bytes(access=access, account="workspace-account")
    target = active / "auth.json"
    target.write_bytes(raw)
    target.chmod(0o600)

    credential = consume_staged_credential(active, hashlib.sha256(raw).hexdigest())

    assert credential.login == {
        "type": "chatgptAuthTokens",
        "accessToken": access,
        "chatgptAccountId": "workspace-account",
        "chatgptPlanType": "plus",
    }
    assert not target.exists()


@pytest.mark.parametrize("rate_limit_account", [None, "account-id"])
def test_memory_login_proves_authenticated_provider_round_trip_before_turn(tmp_path, rate_limit_account):
    class LoginProbe(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.calls = []

        async def request(self, method, params=None, timeout=30):
            self.calls.append((method, params, timeout))
            if method == "account/login/start":
                return {"type": "chatgptAuthTokens"}
            if method == "account/read":
                return {"account": {"type": "chatgptAuthTokens"}}
            if method == "account/rateLimits/read":
                result = {"rateLimits": []}
                if rate_limit_account is not None:
                    result["accountId"] = rate_limit_account
                return result
            raise AssertionError(method)

    async def scenario():
        home = tmp_path / "home"
        home.mkdir()
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = LoginProbe(home, challenge)
        credential = MemoryCredential({
            "type": "chatgptAuthTokens",
            "accessToken": "access-token",
            "chatgptAccountId": "account-id",
        })
        await driver.login_memory(credential)
        assert [call[0] for call in driver.calls] == [
            "account/login/start", "account/read", "account/rateLimits/read",
        ]
        assert driver.calls[-1][2] == 30
        assert driver.chatgpt_preflight_verified is True
        assert driver.external_auth_mode == "chatgptAuthTokens"

    asyncio.run(scenario())


def test_api_key_memory_login_skips_unsupported_rate_limit_read(tmp_path):
    class ApiKeyLoginProbe(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.calls = []

        async def request(self, method, params=None, timeout=30):
            self.calls.append((method, params, timeout))
            if method == "account/login/start":
                return {"type": "apiKey"}
            if method == "account/read":
                return {"account": {"type": "apiKey"}}
            if method == "account/rateLimits/read":
                raise AssertionError("API-key accounts cannot read ChatGPT rate limits")
            raise AssertionError(method)

    async def scenario():
        home = tmp_path / "home"
        home.mkdir()
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = ApiKeyLoginProbe(home, challenge)
        driver.rate_limit_context = {"stale": True}
        credential = MemoryCredential({"type": "apiKey", "apiKey": "sk-secret"})

        await driver.login_memory(credential)

        assert [call[0] for call in driver.calls] == [
            "account/login/start", "account/read",
        ]
        assert driver.rate_limit_context is None
        assert driver.chatgpt_preflight_verified is False
        assert driver.external_auth_mode == "apiKey"

    asyncio.run(scenario())


def test_rate_limit_snapshots_merge_sparse_updates_and_drop_backend_details():
    initial = safe_rate_limit_response({
        "accountId": "private-account-id",
        "rateLimits": {
            "limitId": "codex",
            "limitName": "Codex Standard",
            "primary": {"usedPercent": 0, "windowDurationMins": 300, "resetsAt": 1_788_941_100},
            "secondary": {"usedPercent": 32, "windowDurationMins": 10_080, "resetsAt": 1_789_369_200},
            "credits": {"balance": "private-balance", "hasCredits": True, "unlimited": False},
        },
        "rateLimitResetCredits": {"credits": [{"id": "private-credit-id"}]},
    })
    update = safe_rate_limit_snapshot({
        "limitId": "codex",
        "rateLimitReachedType": "workspace_member_usage_limit_reached",
        "additionalDetails": {"token": "private-token"},
    })
    merged = merge_rate_limit_context(initial, update)
    assert merged == {
        "limit_id": "codex",
        "limit_name": "Codex Standard",
        "reached_type": "workspace_member_usage_limit_reached",
        "windows": [
            {"kind": "primary", "window_minutes": 300, "used_percent": 0, "resets_at": 1_788_941_100},
            {"kind": "secondary", "window_minutes": 10_080, "used_percent": 32, "resets_at": 1_789_369_200},
        ],
    }
    serialized = json.dumps(merged)
    assert "private-account-id" not in serialized
    assert "private-balance" not in serialized
    assert "private-credit-id" not in serialized
    assert "private-token" not in serialized


def test_turn_attaches_latest_sparse_rate_limit_update_to_bounded_error(tmp_path):
    class QuotaTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.rate_limit_context = safe_rate_limit_snapshot({
                "limitId": "codex",
                "limitName": "Codex Standard",
                "primary": {"usedPercent": 0, "windowDurationMins": 300, "resetsAt": 1_788_941_100},
                "secondary": {"usedPercent": 32, "windowDurationMins": 10_080, "resetsAt": 1_789_369_200},
            })

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "account/rateLimits/updated",
                "params": {"rateLimits": {
                    "limitId": "codex",
                    "rateLimitReachedType": "workspace_member_usage_limit_reached",
                    "credits": {"balance": "private-balance"},
                }},
            })
            self.notifications.put_nowait({
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": False,
                    "error": {
                        "message": "private provider diagnostic",
                        "additionalDetails": {"token": "private-token"},
                        "codexErrorInfo": "usageLimitExceeded",
                    },
                },
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = QuotaTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None))
        with pytest.raises(AppServerFailure) as failure:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        public = normalize_provider_failure(failure.value.payload, stage="solve").public()
        assert public["code"] == "usage_limit_exceeded"
        assert public["quota"]["reached_type"] == "workspace_member_usage_limit_reached"
        assert [(window["window_minutes"], window["used_percent"]) for window in public["quota"]["windows"]] == [
            (300, 0), (10_080, 32),
        ]
        serialized = json.dumps(public)
        assert "private provider diagnostic" not in serialized
        assert "private-balance" not in serialized
        assert "private-token" not in serialized

    asyncio.run(scenario())


@pytest.mark.parametrize("request_method", ("thread/start", "turn/start"))
def test_start_request_failure_preserves_safe_rate_limit_context(tmp_path, request_method):
    class FailingStartAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            if request_method == "turn/start":
                self.thread_id = "thread-id"
            self.rate_limit_context = safe_rate_limit_snapshot({
                "limitId": "codex",
                "primary": {"usedPercent": 0, "windowDurationMins": 300, "resetsAt": 1_788_941_100},
                "secondary": {"usedPercent": 32, "windowDurationMins": 10_080, "resetsAt": 1_789_369_200},
                "credits": {"balance": "private-balance"},
            })

        async def request(self, method, params=None, timeout=30):
            assert method == request_method
            raise AppServerFailure({
                "code": -32603,
                "message": "private quota diagnostic",
                "data": {"token": "private-token"},
                "codexErrorInfo": "usageLimitExceeded",
            })

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = FailingStartAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None))

        with pytest.raises(AppServerFailure) as failure:
            if request_method == "thread/start":
                await driver._thread(manifest)
            else:
                await driver._turn(
                    manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                    lambda _code: asyncio.sleep(0),
                )

        assert failure.value.payload["rate_limit"] == driver.rate_limit_context
        public = normalize_provider_failure(failure.value.payload, stage="solve").public()
        assert public["code"] == "usage_limit_exceeded"
        assert [(window["window_minutes"], window["used_percent"]) for window in public["quota"]["windows"]] == [
            (300, 0), (10_080, 32),
        ]
        serialized = json.dumps(public)
        assert "private quota diagnostic" not in serialized
        assert "private-balance" not in serialized
        assert "private-token" not in serialized

    asyncio.run(scenario())


def test_manifest_accepts_remote_metadata_with_general_internet(tmp_path):
    exchange = tmp_path / "exchange"
    active, manifest = stage_job(exchange)
    manifest["remote"] = "nc challenge.example 31337"
    manifest["network_enabled"] = True
    manifest["network_policy"] = "general_internet"
    _write_json(active / "manifest.json", manifest)
    loaded = JobManifest.load(active)
    assert loaded.network_enabled is True
    assert loaded.network_policy == "general_internet"
    assert loaded.remote == "nc challenge.example 31337"


def test_manifest_accepts_workspace_api_maximum_flag_format(tmp_path):
    exchange = tmp_path / "exchange"
    active, manifest = stage_job(exchange)
    manifest["flag_format"] = "A" * 495 + "{...}"
    _write_json(active / "manifest.json", manifest)

    loaded = JobManifest.load(active)

    assert loaded.flag_format == manifest["flag_format"]


class RecordingAppServer(CodexAppServer):
    def __init__(self, home, challenge, configuration=None):
        super().__init__(home, challenge, configuration, executable="synthetic")
        self.requests = []
        self.thread_id = "thread-id"
        self.turn_id = None

    async def request(self, method, params=None, timeout=30):
        self.requests.append((method, params))
        if method == "turn/start":
            await self.notifications.put(
                {
                    "method": "item/completed",
                    "params": {
                        "item": {"type": "agentMessage", "text": "free-form discovery status"},
                    },
                }
            )
            await self.notifications.put(
                {
                    "method": "turn/completed",
                    "params": {"turn": {"id": "turn-id", "status": "completed", "items": []}},
                }
            )
            return {"turn": {"id": "turn-id"}}
        raise AssertionError(method)


class DelayedTurnAppServer(CodexAppServer):
    def __init__(self, home, challenge):
        super().__init__(home, challenge, executable="synthetic")
        self.thread_id = "thread-id"
        self.completion = None

    async def request(self, method, params=None, timeout=30):
        if method != "turn/start":
            raise AssertionError(method)

        async def complete():
            # Reasoning deltas can be frequent during a long turn. They must
            # neither suppress the wall-clock heartbeat nor expose their text.
            for _ in range(6):
                await asyncio.sleep(0.006)
                await self.notifications.put(
                    {
                        "method": "item/reasoning/textDelta",
                        "params": {"delta": "private hidden reasoning must not surface"},
                    }
                )
            await self.notifications.put(
                {
                    "method": "item/completed",
                    "params": {"item": {"type": "agentMessage", "text": '{"value":"done"}'}},
                }
            )
            await self.notifications.put(
                {
                    "method": "turn/completed",
                    "params": {"turn": {"id": "turn-id", "status": "completed", "items": []}},
                }
            )

        self.completion = asyncio.create_task(complete())
        return {"turn": {"id": "turn-id"}}


def test_guidance_mailbox_recovers_durable_delivery_without_replaying(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    writer = EventWriter(active, JOB_ID)
    directory = active / "guidance"
    directory.mkdir()
    guidance_id = "b" * 32
    payload = {
        "protocol": 1,
        "job_id": JOB_ID,
        "guidance_id": guidance_id,
        "message": "이 파일을 먼저 확인해 주세요.",
        "created_at": time.time(),
    }
    _write_json(directory / f"{guidance_id}.json", payload)

    mailbox = GuidanceMailbox(active, JOB_ID, writer)
    records = mailbox.take_nowait_many()
    assert [record.message for record in records] == [payload["message"]]
    mailbox.delivered(records[0], "same_turn")
    assert not (directory / f"{guidance_id}.json").exists()
    event = json.loads((active / "events" / "00000001.json").read_text(encoding="utf-8"))
    assert event | {} == {
        **event,
        "kind": "guidance",
        "guidance_id": guidance_id,
        "state": "delivered",
        "message": payload["message"],
        "provider_delivery": "same_turn",
        "error_code": None,
    }

    # If a crash leaves the already-acknowledged control file behind, the
    # event is authoritative and a fresh mailbox removes it without replaying.
    _write_json(directory / f"{guidance_id}.json", payload)
    recovered = GuidanceMailbox(active, JOB_ID, EventWriter(active, JOB_ID))
    assert recovered.take_nowait_many() == []
    assert not (directory / f"{guidance_id}.json").exists()


def test_codex_active_turn_steers_exact_session_and_emits_safe_activity(tmp_path):
    class SteeringAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.started = asyncio.Event()
            self.requests = []

        async def request(self, method, params=None, timeout=30):
            self.requests.append((method, params, timeout))
            if method == "turn/start":
                self.started.set()
                return {"turn": {"id": "turn-id"}}
            if method == "turn/steer":
                self.notifications.put_nowait(
                    {
                        "method": "item/completed",
                        "params": {
                            "item": {
                                "type": "commandExecution",
                                "command": "TOKEN=provider-secret ./solve",
                                "aggregatedOutput": "PASSWORD=hunter2\nflag candidate ready",
                                "exitCode": 0,
                                "durationMs": 42,
                            }
                        },
                    }
                )
                self.notifications.put_nowait(
                    {
                        "method": "item/reasoning/textDelta",
                        "params": {"delta": "hidden chain of thought"},
                    }
                )
                self.notifications.put_nowait(
                    {
                        "method": "turn/completed",
                        "params": {
                            "turn": {"id": "turn-id", "status": "completed", "items": []}
                        },
                    }
                )
                return {"turnId": "turn-id"}
            raise AssertionError(method)

    async def scenario():
        active = tmp_path / "active"
        active.mkdir()
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = SteeringAppServer(tmp_path / "home", challenge)
        writer = EventWriter(active, JOB_ID)
        driver.guidance_mailbox = GuidanceMailbox(active, JOB_ID, writer)
        activities = []

        async def activity(**payload):
            activities.append(payload)

        driver.activity_reporter = activity
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "high", None),
            network_enabled=True,
        )
        turn = asyncio.create_task(
            driver._turn(
                manifest,
                "solve",
                None,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        )
        await driver.started.wait()
        directory = active / "guidance"
        directory.mkdir()
        guidance_id = "c" * 32
        _write_json(
            directory / f"{guidance_id}.json",
            {
                "protocol": 1,
                "job_id": JOB_ID,
                "guidance_id": guidance_id,
                "message": "두 번째 입력도 확인해 주세요.",
                "created_at": time.time(),
            },
        )

        assert await asyncio.wait_for(turn, timeout=2) == {}
        steer = next(item for item in driver.requests if item[0] == "turn/steer")
        assert steer[1]["threadId"] == "thread-id"
        assert steer[1]["expectedTurnId"] == "turn-id"
        assert steer[1]["clientUserMessageId"] == guidance_id
        assert "두 번째 입력" in steer[1]["input"][0]["text"]
        assert steer[2] == 10

        guidance_event = json.loads(
            (active / "events" / "00000001.json").read_text(encoding="utf-8")
        )
        assert guidance_event["state"] == "delivered"
        assert guidance_event["provider_delivery"] == "same_turn"
        completed = next(item for item in activities if item["tool"] == "shell")
        assert "provider-secret" not in completed["command"]
        assert "hunter2" not in completed["output"]
        assert completed["output"].endswith("flag candidate ready")
        assert completed["exit_code"] == 0
        assert completed["duration_ms"] == 42
        assert all("hidden chain" not in json.dumps(item) for item in activities)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "model",
    [
        "gpt-daybreak-blue-latest",
        "gpt-daybreak-red-latest",
        "gpt-5.6-sol",
    ],
)
def test_turn_preserves_model_alias_and_uses_provider_access_program(tmp_path, model):
    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = RecordingAppServer(tmp_path / "home", challenge)
        driver.external_auth_mode = "chatgptAuthTokens"
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", model, "high", None)
        )

        assert await driver._turn(
            manifest,
            "safe prompt",
            None,
            asyncio.Event(),
            lambda _code: asyncio.sleep(0),
        ) == {}

        _, params = driver.requests[0]
        assert params["model"] == model
        assert "cyberAccessProgram" not in params

    asyncio.run(scenario())


def test_api_key_daybreak_alias_stays_an_api_model_without_chatgpt_program(tmp_path):
    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = RecordingAppServer(tmp_path / "home", challenge)
        driver.external_auth_mode = "apiKey"
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "high", None
        ))

        assert await driver._turn(
            manifest,
            "safe prompt",
            None,
            asyncio.Event(),
            lambda _code: asyncio.sleep(0),
        ) == {}
        _, params = driver.requests[0]
        assert params["model"] == "gpt-daybreak-blue-latest"
        assert "cyberAccessProgram" not in params

    asyncio.run(scenario())


def test_thread_preserves_daybreak_alias(tmp_path):
    class DaybreakThreadAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.params = None

        async def request(self, method, params=None, timeout=30):
            assert method == "thread/start"
            self.params = params
            return {
                "thread": {"id": "thread-id"},
                "model": "gpt-daybreak-blue-latest",
            }

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = DaybreakThreadAppServer(tmp_path / "home", challenge)
        driver.external_auth_mode = "chatgptAuthTokens"
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "xhigh", None
        ))

        assert await driver._thread(manifest) == "thread-id"
        assert driver.params["model"] == "gpt-daybreak-blue-latest"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("message", "expected_code", "provider_code"),
    [
        (
            "I cannot continue because the CVP security policy blocks this request; "
            "private-soft-refusal-marker.",
            "policy_security",
            "CVP",
        ),
        (
            "I cannot access a shell or terminal tool in this environment; "
            "private-soft-refusal-marker.",
            "provider_tools_unavailable",
            None,
        ),
    ],
)
def test_unstructured_turn_surfaces_only_fixed_soft_refusal(
    tmp_path, message, expected_code, provider_code
):
    class SoftRefusalAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "item/completed",
                "params": {"item": {"type": "agentMessage", "text": message}},
            })
            self.notifications.put_nowait({
                "method": "turn/completed",
                "params": {"turn": {"id": "turn-id", "status": "completed", "items": []}},
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = SoftRefusalAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "high", None)
        )
        with pytest.raises(WorkerRefusal) as caught:
            await driver._turn(
                manifest,
                "safe prompt",
                None,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        public = caught.value.error.public()
        assert public["code"] == expected_code
        assert public.get("provider_code") == provider_code
        serialized = json.dumps({"error": public, "exception": repr(caught.value)})
        assert "private-soft-refusal-marker" not in serialized
        assert message not in serialized

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("message", "command_seen"),
    [
        (
            "I cannot solve the CVP lattice until I inspect capture.pcap and its parameters.",
            False,
        ),
        (
            "I cannot access a shell or terminal tool in this environment.",
            True,
        ),
    ],
)
def test_unstructured_turn_keeps_ambiguous_or_command_observed_message_in_nudge_flow(
    tmp_path, message, command_seen
):
    class NonRefusalAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            if command_seen:
                self.notifications.put_nowait({
                    "method": "item/started",
                    "params": {"item": {"type": "commandExecution"}},
                })
            self.notifications.put_nowait({
                "method": "item/completed",
                "params": {"item": {"type": "agentMessage", "text": message}},
            })
            self.notifications.put_nowait({
                "method": "turn/completed",
                "params": {"turn": {"id": "turn-id", "status": "completed", "items": []}},
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = NonRefusalAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "high", None)
        )
        assert await driver._turn(
            manifest,
            "safe prompt",
            None,
            asyncio.Event(),
            lambda _code: asyncio.sleep(0),
        ) == {}

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("command_on_first_turn", "expected_code"),
    [
        (False, "premature_progress_response"),
        (True, "flag_not_submitted"),
    ],
)
def test_discovery_classifies_only_final_progress_without_any_command_execution(
    tmp_path, command_on_first_turn, expected_code
):
    raw_message = (
        "I will continue inspecting the attachment and report back in the next step. "
        "private-progress-marker-must-never-surface"
    )

    class ProgressOnlyAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.prompts = []

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.prompts.append(params["input"][0]["text"])
            turn_number = len(self.prompts)
            if command_on_first_turn and turn_number == 1:
                self.notifications.put_nowait({
                    "method": "item/completed",
                    "params": {"item": {"type": "commandExecution"}},
                })
            self.notifications.put_nowait({
                "method": "item/completed",
                "params": {"item": {"type": "agentMessage", "text": raw_message}},
            })
            self.notifications.put_nowait({
                "method": "turn/completed",
                "params": {
                    "turn": {
                        "id": f"turn-{turn_number}",
                        "status": "completed",
                        "items": [],
                    }
                },
            })
            return {"turn": {"id": f"turn-{turn_number}"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = ProgressOnlyAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "high", None),
            remote_mode="none",
            retry_checkpoint=None,
        )
        with pytest.raises(WorkerRefusal) as caught:
            await driver.run_discovery(
                manifest,
                challenge,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        public = caught.value.error.public()
        assert public["code"] == expected_code
        assert raw_message not in repr(caught.value)
        assert "private-progress-marker" not in json.dumps(public)
        assert len(driver.prompts) == solver_worker_module.MAX_SOLVE_NUDGES + 1
        assert driver.prompts[0].startswith(INITIAL_GOAL)
        assert all(prompt.startswith(NUDGE) for prompt in driver.prompts[1:])

    asyncio.run(scenario())


@pytest.mark.parametrize("mutation", ("keep", "replace", "unlink"))
def test_unstructured_turn_pins_expected_submit_flag_interrupt(tmp_path, mutation):
    class InterruptibleTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = InterruptibleTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        task = asyncio.create_task(
            driver._turn(
                manifest,
                "safe solve prompt",
                None,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        )
        for _ in range(100):
            if driver.turn_id == "turn-id":
                break
            await asyncio.sleep(0)
        assert driver.turn_id == "turn-id"
        record_candidate("SARI{interrupt-authorized}", challenge)
        driver._flag_interrupt_requested = (
            "thread-id",
            "turn-id",
            "SARI{interrupt-authorized}",
        )
        if mutation == "replace":
            record_candidate("SARI{replacement}", challenge)
        elif mutation == "unlink":
            (challenge / ".flag-candidate").unlink()
        await driver.notifications.put(
            {
                "method": "turn/completed",
                "params": {
                    "turn": {
                        "id": "turn-id",
                        "status": "interrupted",
                        "error": {"message": "private interrupt detail"},
                    }
                },
            }
        )

        assert await asyncio.wait_for(task, timeout=1) == {
            "flag": "SARI{interrupt-authorized}"
        }
        assert driver._flag_interrupt_requested is None

    asyncio.run(scenario())


@pytest.mark.parametrize("terminal_kind", ("error", "failed_completion"))
def test_exact_turn_failure_cannot_rollback_durable_flag_handoff(
    tmp_path, terminal_kind
):
    class FailingTerminalAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = FailingTerminalAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        task = asyncio.create_task(
            driver._turn(
                manifest,
                "safe solve prompt",
                None,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        )
        while driver.turn_id != "turn-id":
            await asyncio.sleep(0)
        driver._flag_interrupt_requested = (
            "thread-id",
            "turn-id",
            "SARI{durable}",
        )
        if terminal_kind == "error":
            notification = {
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": False,
                    "error": {"code": "connection_lost"},
                },
            }
        else:
            notification = {
                "method": "turn/completed",
                "params": {
                    "turn": {
                        "id": "turn-id",
                        "status": "failed",
                        "error": {"code": "connection_lost"},
                    }
                },
            }
        await driver.notifications.put(notification)

        assert await asyncio.wait_for(task, timeout=1) == {"flag": "SARI{durable}"}
        assert driver._flag_interrupt_requested is None

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "failure_kind", ("app_server", "connection", "os_error", "timeout")
)
def test_interrupt_transport_failure_still_finishes_durable_handoff(
    tmp_path, failure_kind
):
    class InterruptFailureAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            if method == "turn/start":
                return {"turn": {"id": "turn-id"}}
            assert method == "turn/interrupt"
            if failure_kind == "app_server":
                raise AppServerFailure({"code": "turn_already_completed"})
            if failure_kind == "connection":
                raise ConnectionError("stream closed")
            if failure_kind == "os_error":
                raise OSError("pipe closed")
            raise TimeoutError("interrupt response timed out")

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = InterruptFailureAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        task = asyncio.create_task(
            driver._turn(
                manifest,
                "safe solve prompt",
                None,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        )
        while driver.turn_id != "turn-id":
            await asyncio.sleep(0)
        record_candidate("SARI{transport-safe}", challenge)

        await driver.interrupt_after_flag("SARI{transport-safe}")

        assert await asyncio.wait_for(task, timeout=1) == {
            "flag": "SARI{transport-safe}"
        }
        assert driver._flag_interrupt_requested is None

    asyncio.run(scenario())


def test_provider_stream_close_after_handoff_uses_pinned_flag(tmp_path):
    class ClosedStreamAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = ClosedStreamAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        task = asyncio.create_task(
            driver._turn(
                manifest,
                "safe solve prompt",
                None,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        )
        while driver.turn_id != "turn-id":
            await asyncio.sleep(0)
        driver._flag_interrupt_requested = (
            "thread-id",
            "turn-id",
            "SARI{stream-safe}",
        )
        driver.reader_failure_code = "provider_stream_closed"
        driver.reader_stopped.set()

        assert await asyncio.wait_for(task, timeout=1) == {
            "flag": "SARI{stream-safe}"
        }
        assert driver._flag_interrupt_requested is None

    asyncio.run(scenario())


def test_turn_emits_bounded_safe_heartbeats_while_model_is_silent(tmp_path, monkeypatch):
    async def scenario():
        monkeypatch.setattr("ctf_agent.solver_worker.MODEL_WAIT_HEARTBEAT_SECONDS", 0.01)
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = DelayedTurnAppServer(tmp_path / "home", challenge)
        progress = []
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        result = await driver._turn(
            manifest,
            "safe prompt",
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["value"],
                "properties": {"value": {"type": "string"}},
            },
            asyncio.Event(),
            lambda code: progress.append(code) or asyncio.sleep(0),
        )
        await driver.completion
        assert result == {"value": "done"}
        assert progress and set(progress) == {"waiting_for_model"}
        assert "hidden reasoning" not in json.dumps(progress)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        ("unauthorized", "provider_auth_retry"),
        ("usageLimitExceeded", "provider_quota_retry"),
        ("rateLimitExceeded", "provider_rate_limit_retry"),
        ("serverOverloaded", "provider_overloaded_retry"),
        ({"httpConnectionFailed": {"httpStatusCode": None}}, "provider_connection_retry"),
        ("other", "provider_retrying"),
    ],
)
def test_provider_retry_progress_exposes_only_safe_category(info, expected):
    payload = {"codexErrorInfo": info, "message": "private token and path must not surface"}
    assert solver_worker_module.provider_retry_progress(payload) == expected


def test_daybreak_retry_after_authenticated_preflight_is_an_access_check():
    payload = {
        "codexErrorInfo": "unauthorized",
        "message": "private token and path must not surface",
    }
    assert solver_worker_module.provider_retry_progress(
        payload,
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    ) == "provider_access_check"


def test_daybreak_bad_request_after_authenticated_preflight_is_an_access_check():
    payload = {
        "codexErrorInfo": "badRequest",
        "message": "private model route diagnostic",
    }
    assert solver_worker_module.provider_retry_progress(
        payload,
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    ) == "provider_access_check"


def test_forbidden_retry_is_an_access_check_for_other_models():
    payload = {
        "codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 403}},
        "message": "private token and path must not surface",
    }
    assert solver_worker_module.provider_retry_progress(payload) == "provider_access_check"


def test_turn_stops_immediately_when_external_auth_cannot_recover(tmp_path):
    class RetryTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": True,
                    "error": {
                        "message": "private provider diagnostic",
                        "codexErrorInfo": "unauthorized",
                    },
                },
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        progress = []
        driver = RetryTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None))
        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda code: progress.append(code) or asyncio.sleep(0),
            )
        assert error.value.payload == {"codexErrorInfo": "unauthorized"}
        assert progress == ["provider_auth_retry"]
        assert "private provider diagnostic" not in json.dumps(progress)

    asyncio.run(scenario())


def test_daybreak_turn_keeps_scoped_failure_after_automatic_refresh_request(tmp_path, monkeypatch):
    monkeypatch.setattr(
        solver_worker_module,
        "TERMINAL_PROVIDER_SIGNAL_GRACE_SECONDS",
        0.1,
    )

    class RetryTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.chatgpt_preflight_verified = True
            self.followup = None

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": True,
                    "error": {
                        "message": "private provider diagnostic",
                        "codexErrorInfo": "unauthorized",
                    },
                },
            })

            async def publish_refresh_request():
                await asyncio.sleep(0)
                self.notifications.put_nowait({
                    "method": "ctf/account-refresh-required",
                    "params": {},
                })

            self.followup = asyncio.create_task(publish_refresh_request())
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        progress = []
        driver = RetryTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "low", None,
        ))
        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda code: progress.append(code) or asyncio.sleep(0),
            )
        await driver.followup
        assert error.value.payload == {"codexErrorInfo": "unauthorized"}
        assert progress == ["provider_access_check"]
        normalized = normalize_provider_failure(
            error.value.payload,
            stage="solve",
            model="gpt-daybreak-blue-latest",
            authenticated_preflight=True,
        )
        assert normalized.code == "daybreak_route_rejected"
        assert "private provider diagnostic" not in json.dumps(normalized.public())

    asyncio.run(scenario())


def test_daybreak_turn_keeps_scoped_failure_when_refresh_request_arrives_first(tmp_path):
    class RefreshFirstAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.chatgpt_preflight_verified = True
            self.external_auth_mode = "chatgptAuthTokens"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "ctf/account-refresh-required",
                "params": {},
            })
            self.notifications.put_nowait({
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": True,
                    "error": {
                        "message": "private provider diagnostic",
                        "codexErrorInfo": "unauthorized",
                    },
                },
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        progress = []
        driver = RefreshFirstAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "low", None,
        ))
        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda code: progress.append(code) or asyncio.sleep(0),
            )
        assert error.value.payload == {"code": "daybreak_route_rejected"}
        assert progress == ["provider_access_check"]

    asyncio.run(scenario())


def test_codex_max_required_escalates_once_in_same_workspace_and_session(tmp_path):
    async def scenario():
        @dataclass(frozen=True)
        class DiscoveryManifest:
            challenge_name: str
            remote: str
            remote_mode: str
            retry_checkpoint: object
            max_reasoning_available: bool
            configuration: ModelConfiguration

        workdir = tmp_path / "workdir"
        notes = workdir / "notes"
        notes.mkdir(parents=True)
        (notes / "NEXT.md").write_text("# Next\n", encoding="utf-8")
        server = object.__new__(CodexAppServer)
        calls = []
        progress_events = []

        async def turn(manifest, prompt, schema, cancelled, progress):
            assert schema is None
            calls.append((manifest.configuration.reasoning_effort, prompt, workdir))
            if len(calls) == 1:
                server._discovery_command_execution_seen = True
                (notes / "NEXT.md").write_text(
                    "# Next\n\nConcrete blocker: the tested decoder still has two viable branches.\n"
                    "Next: exhaust both branches with solver.py.\n\nMAX_REQUIRED\n",
                    encoding="utf-8",
                )
                return {}
            if len(calls) == 3:
                record_candidate("SARI{max_completed}", workdir)
            return {}

        async def progress(code, **details):
            progress_events.append((code, details))

        server._turn = turn
        manifest = DiscoveryManifest(
            challenge_name="Max fixture",
            remote="",
            remote_mode="none",
            retry_checkpoint=None,
            max_reasoning_available=True,
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "xhigh", None),
        )
        result = await server.run_discovery(
            manifest, workdir, asyncio.Event(), progress
        )

        assert result["flag"] == "SARI{max_completed}"
        assert [call[0] for call in calls] == ["xhigh", "max", "max"]
        assert server.effective_reasoning_effort == "max"
        assert calls[0][2] is calls[1][2] is calls[2][2]
        assert "same session and working directory" in calls[1][1]
        next_note = (notes / "NEXT.md").read_text(encoding="utf-8")
        assert "Concrete blocker" in next_note
        assert "MAX_REQUIRED" not in next_note
        assert "MAX_REQUIRED" not in result["private_notes"]
        escalations = [item for item in progress_events if item[0] == "reasoning_escalated"]
        assert escalations == [
            (
                "reasoning_escalated",
                {
                    "reason": "agent_max_required_with_work_evidence",
                    "from_effort": "xhigh",
                    "to_effort": "max",
                },
            )
        ]

    asyncio.run(scenario())


def test_codex_max_required_is_ignored_without_catalog_capability(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        notes = workdir / "notes"
        notes.mkdir(parents=True)
        (notes / "NEXT.md").write_text("MAX_REQUIRED\n", encoding="utf-8")
        server = object.__new__(CodexAppServer)
        efforts = []

        async def turn(manifest, _prompt, _schema, _cancelled, _progress):
            efforts.append(manifest.configuration.reasoning_effort)
            server._discovery_command_execution_seen = True
            if len(efforts) == 2:
                record_candidate("SARI{no_unattested_max}", workdir)
            return {}

        server._turn = turn
        result = await server.run_discovery(
            SimpleNamespace(
                challenge_name="No max fixture",
                remote="",
                remote_mode="none",
                retry_checkpoint=None,
                max_reasoning_available=False,
                configuration=ModelConfiguration("codex", "gpt-5.6-sol", "xhigh", None),
            ),
            workdir,
            asyncio.Event(),
            lambda _code, **_details: asyncio.sleep(0),
        )
        assert result["flag"] == "SARI{no_unattested_max}"
        assert efforts == ["xhigh", "xhigh"]

    asyncio.run(scenario())


def test_codex_max_required_does_not_start_max_turn_after_cancellation(tmp_path):
    async def scenario():
        workdir = tmp_path / "workdir"
        notes = workdir / "notes"
        notes.mkdir(parents=True)
        cancelled = asyncio.Event()
        server = object.__new__(CodexAppServer)
        efforts = []
        progress_events = []

        async def turn(manifest, _prompt, _schema, _cancelled, _progress):
            efforts.append(manifest.configuration.reasoning_effort)
            server._discovery_command_execution_seen = True
            (notes / "NEXT.md").write_text("tested branch\nMAX_REQUIRED\n", encoding="utf-8")
            cancelled.set()
            return {}

        async def progress(code, **details):
            progress_events.append((code, details))

        server._turn = turn
        with pytest.raises(asyncio.CancelledError):
            await server.run_discovery(
                SimpleNamespace(
                    challenge_name="Cancelled max fixture",
                    remote="",
                    remote_mode="none",
                    retry_checkpoint=None,
                    max_reasoning_available=True,
                    configuration=ModelConfiguration(
                        "codex", "gpt-5.6-sol", "xhigh", None
                    ),
                ),
                workdir,
                cancelled,
                progress,
            )
        assert efforts == ["xhigh"]
        assert not any(code == "reasoning_escalated" for code, _ in progress_events)

    asyncio.run(scenario())


def test_worker_keeps_effective_max_for_writeup_turn(tmp_path, monkeypatch):
    class EscalatedDriver(FakeDriver):
        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append(("discover", manifest.configuration.reasoning_effort))
            self.effective_reasoning_effort = "max"
            return {"flag": "SARI{effective_max}", "private_notes": "verified"}

        async def run_writeup(
            self, manifest, challenge, flag, notes, cancelled, progress
        ):
            self.calls.append(("writeup", manifest.configuration.reasoning_effort))
            return "# Effective max\n\n검증된 풀이\n\n`SARI{effective_max}`"

    async def scenario():
        exchange = tmp_path / "exchange"
        stage_job(exchange, max_reasoning_available=True)
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        EscalatedDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=EscalatedDriver)
        worker.prepare()

        assert await worker.process_active()
        calls = EscalatedDriver.instances[0].calls
        assert ("discover", "high") in calls
        assert ("writeup", "max") in calls

    asyncio.run(scenario())


def test_writeup_refinement_worker_is_offline_skips_discovery_and_survives_restart_context(tmp_path):
    flag = "SARI{already-verified}"
    original = """# No attachment challenge

## 문제 요약

검증된 값을 정리하는 문제다.

## 분야 및 핵심 원리

자료의 구조를 확인하는 분석 문제다.

## 분석 과정

기존 분석 기록을 대조했다.

## 풀이 과정

확인한 순서대로 값을 재현했다.

## 풀이 코드 및 명령어

아래 코드를 사용했다.

```python
print('verified')
```

## Flag

`SARI{already-verified}`"""
    refined = original.replace("기존 분석 기록을 대조했다.", "기존 분석 기록과 solver 산출물을 함께 대조해 근거를 확인했다.")
    artifact = solver_artifact_from_bytes(b"print('verified')\n")

    class RefineDriver(FakeDriver):
        async def run_discovery(self, *_args, **_kwargs):
            raise AssertionError("write-up refinement must not run discovery")

        async def run_writeup(self, manifest, challenge, given_flag, notes, cancelled, progress):
            self.calls.append("writeup")
            assert manifest.job_mode == "writeup_refine"
            assert manifest.network_enabled is False and manifest.remote_mode == "none"
            assert manifest.source_writeup == original
            assert manifest.refinement_instruction == "분석 근거 보완"
            assert given_flag == flag
            assert "ANALYSIS.md" in notes and "VULN.md" in notes and "NEXT.md" in notes
            assert (challenge / "solver.py").read_bytes() == artifact.content
            for manual_name in ("AGENTS.md", "CLAUDE.md"):
                manual = (challenge / manual_name).read_text(encoding="utf-8")
                assert "기존 write-up만 보완" in manual
                assert "여섯 `##` 섹션만" in manual
                assert "submit-flag" not in manual
                assert "work fully autonomously through the solve loop" not in manual
            return refined

    async def scenario():
        exchange = tmp_path / "exchange"
        active, manifest = stage_job(exchange)
        source = original.encode("utf-8")
        (active / "writeup-source.md").write_bytes(source)
        manifest.update(
            job_mode="writeup_refine",
            remote="",
            remote_mode="none",
            network_enabled=False,
            network_policy="offline",
            refinement_context={
                "instruction": "분석 근거 보완",
                "verified_flag": flag,
                "private_notes": "## ANALYSIS.md\n\n분석\n\n## VULN.md\n\n근거\n\n## NEXT.md\n\n완료",
                "solver_artifact": artifact.payload(),
                "source_writeup_sha256": hashlib.sha256(source).hexdigest(),
                "source_solver_job_id": "b" * 32,
            },
        )
        _write_json(active / "manifest.json", manifest)
        worker = worker_for(exchange, driver_factory=RefineDriver)
        worker.prepare()

        assert await worker.process_active() is True
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        events = event_payloads(active)
        driver = RefineDriver.instances[-1]
        assert state["status"] == "completed" and state["flag"] == flag
        assert state["writeup_markdown"] == refined
        assert [event["kind"] for event in events] == ["progress", "status", "writeup", "released"]
        assert driver.calls == ["start", "canary", "login", "canary", "writeup", "close"]

    asyncio.run(scenario())


def test_daybreak_refresh_account_mismatch_requires_login(tmp_path):
    class RefreshFirstAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.chatgpt_preflight_verified = True
            self.external_auth_mode = "chatgptAuthTokens"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "ctf/account-refresh-required",
                "params": {"accountMatch": False},
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = RefreshFirstAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "low", None,
        ))

        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )

        assert error.value.payload == {"code": "auth_required"}
        assert driver._last_refresh_account_match is False

    asyncio.run(scenario())


def test_memory_login_rejects_rate_limit_workspace_mismatch_without_ids(tmp_path):
    class LoginProbe(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")

        async def request(self, method, params=None, timeout=30):
            if method == "account/login/start":
                return {"type": "chatgptAuthTokens"}
            if method == "account/read":
                return {"account": {"type": "chatgptAuthTokens"}}
            if method == "account/rateLimits/read":
                return {
                    "accountId": "returned-private-workspace",
                    "rateLimits": [],
                }
            raise AssertionError(method)

    async def scenario():
        home = tmp_path / "home"
        home.mkdir()
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = LoginProbe(home, challenge)
        credential = MemoryCredential({
            "type": "chatgptAuthTokens",
            "accessToken": "access-token",
            "chatgptAccountId": "expected-private-workspace",
            "chatgptPlanType": "plus",
        })

        with pytest.raises(WorkerRefusal) as error:
            await driver.login_memory(credential)

        public = error.value.error.public()
        assert public["code"] == "account_workspace_mismatch"
        assert public["category"] == "auth"
        serialized = json.dumps(public)
        assert "expected-private-workspace" not in serialized
        assert "returned-private-workspace" not in serialized
        assert driver.chatgpt_preflight_verified is False

    asyncio.run(scenario())


def test_daybreak_refresh_first_prefers_following_attestation_signal(tmp_path):
    class RefreshFirstAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.chatgpt_preflight_verified = True
            self.external_auth_mode = "chatgptAuthTokens"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "ctf/account-refresh-required",
                "params": {"accountMatch": True},
            })
            self.notifications.put_nowait({
                "method": "ctf/attestation-unavailable",
                "params": {},
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        progress = []
        driver = RefreshFirstAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "low", None,
        ))
        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda code: progress.append(code) or asyncio.sleep(0),
            )
        assert error.value.payload == {"code": "codex_attestation_unavailable"}
        assert progress == []

    asyncio.run(scenario())


def test_daybreak_final_unauthorized_prefers_following_attestation_signal(tmp_path):
    class FinalUnauthorizedAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.chatgpt_preflight_verified = True
            self.external_auth_mode = "chatgptAuthTokens"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": False,
                    "error": {
                        "message": "private token and path must not surface",
                        "codexErrorInfo": "unauthorized",
                    },
                },
            })
            self.notifications.put_nowait({
                "method": "ctf/account-refresh-required",
                "params": {},
            })
            self.notifications.put_nowait({
                "method": "ctf/attestation-unavailable",
                "params": {},
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = FinalUnauthorizedAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "low", None,
        ))
        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        assert error.value.payload == {"code": "codex_attestation_unavailable"}
        assert "private" not in json.dumps(error.value.payload)

    asyncio.run(scenario())


def test_daybreak_turn_keeps_unauthorized_without_refresh_request(tmp_path, monkeypatch):
    monkeypatch.setattr(
        solver_worker_module,
        "TERMINAL_PROVIDER_SIGNAL_GRACE_SECONDS",
        0.01,
    )

    class RetryTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.chatgpt_preflight_verified = True

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "error",
                "params": {
                    "threadId": "thread-id",
                    "turnId": "turn-id",
                    "willRetry": True,
                    "error": {
                        "message": "private provider diagnostic",
                        "codexErrorInfo": "unauthorized",
                    },
                },
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        progress = []
        driver = RetryTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(configuration=ModelConfiguration(
            "codex", "gpt-daybreak-blue-latest", "low", None,
        ))
        with pytest.raises(AppServerFailure) as error:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda code: progress.append(code) or asyncio.sleep(0),
            )
        assert error.value.payload == {"codexErrorInfo": "unauthorized"}
        assert progress == ["provider_access_check"]
        normalized = normalize_provider_failure(
            error.value.payload,
            stage="solve",
            model="gpt-daybreak-blue-latest",
            authenticated_preflight=True,
        )
        assert normalized.code == "daybreak_route_rejected"

    asyncio.run(scenario())


def test_external_auth_refresh_request_becomes_bounded_worker_notification(tmp_path):
    class Lines:
        def __init__(self):
            self.values = [
                b'{"id":7,"method":"account/chatgptAuthTokens/refresh","params":{"reason":"unauthorized","previousAccountId":"private"}}\n',
                b"",
            ]

        async def readline(self):
            return self.values.pop(0)

    class Sink:
        def __init__(self):
            self.values = []

        def write(self, value):
            self.values.append(value)

        async def drain(self):
            return None

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        sink = Sink()
        driver = CodexAppServer(tmp_path / "home", challenge, executable="synthetic")
        driver.process = SimpleNamespace(stdout=Lines(), stdin=sink)
        await driver._reader()
        notification = driver.notifications.get_nowait()
        assert notification == {
            "method": "ctf/account-refresh-required",
            "params": {"accountMatch": None},
        }
        response = json.loads(sink.values[0])
        assert response["id"] == 7 and response["error"]["code"] == -32601
        assert "private" not in sink.values[0].decode()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("previous_account_id", "expected_match"),
    (("expected-private-workspace", True), ("other-private-workspace", False)),
)
def test_external_auth_refresh_preserves_only_account_match(
    tmp_path, previous_account_id, expected_match
):
    class Lines:
        def __init__(self):
            self.values = [
                (json.dumps({
                    "id": 7,
                    "method": "account/chatgptAuthTokens/refresh",
                    "params": {
                        "reason": "unauthorized",
                        "previousAccountId": previous_account_id,
                        "requestId": "private-request-id",
                    },
                }) + "\n").encode(),
                b"",
            ]

        async def readline(self):
            return self.values.pop(0)

    class Sink:
        def __init__(self):
            self.values = []

        def write(self, value):
            self.values.append(value)

        async def drain(self):
            return None

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        sink = Sink()
        driver = CodexAppServer(tmp_path / "home", challenge, executable="synthetic")
        driver._remember_chatgpt_account("expected-private-workspace")
        driver.process = SimpleNamespace(stdout=Lines(), stdin=sink)

        await driver._reader()

        notification = driver.notifications.get_nowait()
        assert notification == {
            "method": "ctf/account-refresh-required",
            "params": {"accountMatch": expected_match},
        }
        serialized = json.dumps(notification) + b"".join(sink.values).decode()
        assert "expected-private-workspace" not in serialized
        assert "other-private-workspace" not in serialized
        assert "private-request-id" not in serialized

    asyncio.run(scenario())


def test_safe_codex_failure_keeps_only_discriminator_and_http_status():
    payload = {
        "code": -32603,
        "message": "private provider prose with a token",
        "additionalDetails": "private prompt and filesystem path",
        "requestId": "private-request-id",
        "codexErrorInfo": {
            "httpConnectionFailed": {
                "httpStatusCode": 401,
                "requestId": "nested-private-request-id",
            }
        },
    }

    safe = solver_worker_module.safe_codex_failure(payload)

    assert safe == {
        "codexErrorInfo": {
            "httpConnectionFailed": {"httpStatusCode": 401},
        }
    }
    serialized = json.dumps(safe)
    assert "private" not in serialized
    assert "message" not in serialized
    assert "additionalDetails" not in serialized


def test_safe_codex_failure_drops_unknown_error_shape_and_provider_text():
    safe = solver_worker_module.safe_codex_failure({
        "message": "unauthorized private token",
        "additionalDetails": "request id private-request-id",
        "codexErrorInfo": {"futureError": {"httpStatusCode": 401}},
    })

    assert safe == {"code": "provider_error"}


def test_unexpected_attestation_request_becomes_bounded_worker_notification(tmp_path):
    class Lines:
        def __init__(self):
            self.values = [
                b'{"id":8,"method":"attestation/generate","params":{"token":"private"}}\n',
                b"",
            ]

        async def readline(self):
            return self.values.pop(0)

    class Sink:
        def __init__(self):
            self.values = []

        def write(self, value):
            self.values.append(value)

        async def drain(self):
            return None

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        sink = Sink()
        driver = CodexAppServer(tmp_path / "home", challenge, executable="synthetic")
        driver.process = SimpleNamespace(stdout=Lines(), stdin=sink)
        await driver._reader()
        notification = driver.notifications.get_nowait()
        assert notification == {"method": "ctf/attestation-unavailable", "params": {}}
        response = json.loads(sink.values[0])
        assert response["id"] == 8 and response["error"]["code"] == -32601
        assert "private" not in sink.values[0].decode()

    asyncio.run(scenario())


def test_turn_detects_closed_app_server_stream_instead_of_waiting(tmp_path):
    class EndOfStream:
        async def readline(self):
            return b""

    class ClosedTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.process = SimpleNamespace(stdout=EndOfStream())

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            await self._reader()
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = ClosedTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        with pytest.raises(AppServerFailure) as error:
            await asyncio.wait_for(
                driver._turn(
                    manifest,
                    "safe prompt",
                    {"type": "object"},
                    asyncio.Event(),
                    lambda _: asyncio.sleep(0),
                ),
                timeout=0.5,
            )
        assert error.value.payload == {"code": "provider_stream_closed"}

    asyncio.run(scenario())


def test_turn_drains_queued_final_notifications_before_reporting_closed_stream(tmp_path):
    class DelayedGetQueue(asyncio.Queue):
        async def get(self):
            # Force reader_stopped to win asyncio.wait even though final
            # notifications are already durable in the queue.
            await asyncio.sleep(1)
            return await super().get()

    class ClosedAfterFinalTurnAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"
            self.notifications = DelayedGetQueue()

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait(
                {
                    "method": "item/completed",
                    "params": {"item": {"type": "agentMessage", "text": '{"value":"final"}'}},
                }
            )
            self.notifications.put_nowait(
                {
                    "method": "turn/completed",
                    "params": {"turn": {"id": "turn-id", "status": "completed", "items": []}},
                }
            )
            self.reader_stopped.set()
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = ClosedAfterFinalTurnAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "low", None)
        )
        result = await asyncio.wait_for(
            driver._turn(
                manifest,
                "safe prompt",
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}},
                },
                asyncio.Event(),
                lambda _: asyncio.sleep(0),
            ),
            timeout=0.5,
        )
        assert result == {"value": "final"}
        assert driver.notifications.empty()

    asyncio.run(scenario())


def test_turn_request_freezes_model_effort_fast_tier_and_offline_sandbox(tmp_path):
    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        active = tmp_path / "active"
        active.mkdir()
        raw = auth_bytes()
        (active / "auth.json").write_bytes(raw)
        (active / "auth.json").chmod(0o600)
        created_at = time.time()
        _write_json(
            active / "manifest.json",
            {
                "protocol": 1,
                "job_id": JOB_ID,
                "challenge_name": "Exact settings",
                "challenge_text": "text",
                "provider": "codex",
                "model": "gpt-5.6-sol",
                "reasoning_effort": "xhigh",
                "service_tier": "fast",
                "codex_version": "0.153.4",
                "auth_sha256": hashlib.sha256(raw).hexdigest(),
                "max_seconds": solver_worker_module.MAX_JOB_SECONDS,
                "created_at": created_at,
                "deadline_unix": (
                    created_at + solver_worker_module.MAX_JOB_SECONDS
                    if solver_worker_module.MAX_JOB_SECONDS
                    else None
                ),
                "network_enabled": True,
                "network_policy": "general_internet",
            },
        )
        manifest = JobManifest.load(active)
        driver = RecordingAppServer(tmp_path / "home", challenge)
        (challenge / ".flag-candidate").write_text("SARI{exact}", encoding="utf-8")
        (challenge / ".flag-candidate").chmod(0o600)
        result = await driver.run_discovery(manifest, challenge, asyncio.Event(), lambda _: asyncio.sleep(0))
        assert result["flag"] == "SARI{exact}"
        method, params = driver.requests[0]
        assert method == "turn/start"
        assert params["model"] == "gpt-5.6-sol"
        assert params["effort"] == "xhigh"
        assert params["serviceTier"] == params["serviceTierForTurn"] == "fast"
        assert params["approvalPolicy"] == "never"
        assert params["sandboxPolicy"] == {
            "type": "workspaceWrite",
            "writableRoots": [str(challenge)],
            "networkAccess": True,
            "excludeSlashTmp": True,
            "excludeTmpdirEnvVar": True,
        }
        # Omitting environments selects Codex's cwd-bound local environment.
        # An explicit empty list disables environment access and removes the
        # built-in shell tools from the turn.
        assert "environments" not in params
        assert "outputSchema" not in params
        assert "Read your operating manual" in params["input"][0]["text"]

    asyncio.run(scenario())


def test_memory_credential_repr_and_worker_events_never_render_tokens():
    credential = MemoryCredential({"type": "apiKey", "apiKey": "sk-secret"})
    assert "sk-secret" not in repr(credential)
    credential.erase()
    assert credential.login == {}


def test_fast_cli_settings_are_both_present_only_when_selected(tmp_path):
    challenge = tmp_path / "challenge"
    challenge.mkdir()
    fast = ModelConfiguration("codex", "gpt-5.6-sol", "high", "fast")
    fast_args = CodexAppServer(tmp_path / "fast", challenge, fast, executable="codex").command_arguments()
    standard_args = CodexAppServer(
        tmp_path / "standard",
        challenge,
        ModelConfiguration("codex", "gpt-5.6-sol", "high", None),
        executable="codex",
    ).command_arguments()
    assert 'service_tier="fast"' in fast_args
    assert "features.fast_mode=true" in fast_args
    assert not any("service_tier" in item or "fast_mode" in item for item in standard_args)
    assert not any("web_search" in item for item in fast_args)
    assert not any("web_search" in item for item in standard_args)
    assert "agents.enabled=false" in fast_args
    assert "agents.enabled=false" in standard_args
    assert any(
        standard_args[index:index + 2] == ["--disable", "multi_agent"]
        for index in range(len(standard_args) - 1)
    )


def test_thread_start_enables_builtin_web_search_for_solve(tmp_path):
    class ThreadPolicyAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.params = None

        async def request(self, method, params=None, timeout=30):
            assert method == "thread/start"
            self.params = params
            return {
                "thread": {"id": "thread-id"},
                "model": "gpt-5.6-sol",
            }

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = ThreadPolicyAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "xhigh", None)
        )

        assert await driver._thread(manifest) == "thread-id"
        assert driver.params["dynamicTools"] == []
        assert "environments" not in driver.params
        assert driver.params["config"] == {
            "web_search": "live",
            "tools": {"web_search": True},
            "features": {"multi_agent": False},
            "agents": {"enabled": False},
        }

    asyncio.run(scenario())


def test_writeup_refinement_thread_and_claude_cli_disable_execution_tools(tmp_path):
    class RefinementThreadAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.params = None

        async def request(self, method, params=None, timeout=30):
            assert method == "thread/start"
            self.params = params
            return {"thread": {"id": "thread-id"}, "model": "gpt-5.6-sol"}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        configuration = ModelConfiguration("codex", "gpt-5.6-sol", "xhigh", None)
        manifest = SimpleNamespace(
            job_id=JOB_ID,
            job_mode="writeup_refine",
            configuration=configuration,
        )
        codex = RefinementThreadAppServer(tmp_path / "codex-home", challenge)
        assert await codex._thread(manifest) == "thread-id"
        assert codex.params["environments"] == []
        assert codex.params["config"]["web_search"] == "disabled"
        assert codex.params["config"]["tools"]["web_search"] is False

        claude_configuration = ModelConfiguration("claude", "sonnet", "high", None)
        claude_manifest = SimpleNamespace(
            job_id=JOB_ID,
            job_mode="writeup_refine",
            configuration=claude_configuration,
        )
        claude = solver_worker_module.ClaudePrintDriver(
            tmp_path / "claude-home",
            challenge,
            claude_configuration,
            executable="synthetic",
        )
        arguments = claude.command_arguments(
            claude_manifest, {"type": "object"}
        )
        assert arguments[arguments.index("--tools") + 1] == ""
        assert "--allowedTools" not in arguments
        denied = arguments[arguments.index("--disallowedTools") + 1].split(",")
        assert set(denied) == {*claude.ALLOWED_TOOLS, "mcp__*"}
        settings = json.loads(arguments[arguments.index("--settings") + 1])
        assert settings["permissions"]["allow"] == []
        assert set(settings["permissions"]["deny"]) == {
            *claude.ALLOWED_TOOLS,
            "mcp__*",
        }

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("item_type", "expected_code"),
    [
        ("mcpToolCall", "unexpected_mcp_tool"),
        ("dynamicToolCall", "unexpected_dynamic_tool"),
        ("collabAgentToolCall", "unexpected_multi_agent_tool"),
        ("imageGeneration", "unexpected_image_generation"),
    ],
)
def test_turn_reports_fixed_code_for_disallowed_remote_item(tmp_path, item_type, expected_code):
    class RemoteItemAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait({
                "method": "item/started",
                "params": {"item": {"type": item_type, "private": "must not surface"}},
            })
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = RemoteItemAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "xhigh", None)
        )

        with pytest.raises(WorkerRefusal) as refusal:
            await driver._turn(
                manifest, "safe prompt", {"type": "object"}, asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )

        assert refusal.value.error.code == expected_code
        assert "private" not in json.dumps(refusal.value.error.public())

    asyncio.run(scenario())


@pytest.mark.parametrize("item_type", ["commandExecution", "fileChange"])
def test_writeup_refinement_refuses_codex_execution_items(tmp_path, item_type):
    class RemoteItemAppServer(CodexAppServer):
        def __init__(self, home, challenge):
            super().__init__(home, challenge, executable="synthetic")
            self.thread_id = "thread-id"

        async def request(self, method, params=None, timeout=30):
            assert method == "turn/start"
            self.notifications.put_nowait(
                {
                    "method": "item/started",
                    "params": {"item": {"type": item_type}},
                }
            )
            return {"turn": {"id": "turn-id"}}

    async def scenario():
        challenge = tmp_path / "challenge"
        challenge.mkdir()
        driver = RemoteItemAppServer(tmp_path / "home", challenge)
        manifest = SimpleNamespace(
            job_mode="writeup_refine",
            configuration=ModelConfiguration("codex", "gpt-5.6-sol", "xhigh", None),
        )
        with pytest.raises(WorkerRefusal) as refusal:
            await driver._turn(
                manifest,
                "safe prompt",
                {"type": "object"},
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        assert refusal.value.error.code == "unexpected_writeup_tool"
        assert refusal.value.error.stage == "writeup"

    asyncio.run(scenario())


def test_hardened_exec_bootstrap_ignores_workspace_and_environment_import_paths():
    command = ["/runtime/codex", "app-server", "--stdio"]
    wrapped = hardened_solver_exec_command(command)

    assert wrapped[:3] == [sys.executable, "-I", "-c"]
    assert "sys.path.insert(0" in wrapped[3]
    assert "ctf_agent.solver_exec import main" in wrapped[3]
    assert wrapped[4:] == command


def test_external_sandbox_uses_profile_transition_launcher_and_codex_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_SOLVER_EXTERNAL_SANDBOX", "true")
    command = ["/runtime/native-codex", "app-server", "--stdio"]
    wrapped = hardened_solver_exec_command(command)

    assert wrapped[0].replace("\\", "/") == "/usr/local/libexec/ctf-agent-codex-launcher"
    assert wrapped[1:3] == ["-I", "-c"]
    assert wrapped[4:] == command
    assert CodexAppServer._sandbox_policy(tmp_path) == {
        "type": "externalSandbox",
        "networkAccess": "enabled",
    }


def test_claude_non_apparmor_canary_is_only_enabled_for_local_desktop(tmp_path, monkeypatch):
    async def scenario():
        challenge = tmp_path / "competition" / "challenge" / "codex-workdir"
        challenge.mkdir(parents=True)
        (challenge.parents[1] / "skills").mkdir()
        scratch = tmp_path / "scratch"
        source = challenge.parent
        scratch.mkdir()
        driver = object.__new__(solver_worker_module.ClaudePrintDriver)
        driver.challenge = challenge
        driver.process = None
        driver.pid = -1
        driver.safe_startup_stderr = None

        monkeypatch.delenv("CTF_SOLVER_EXTERNAL_SANDBOX", raising=False)
        monkeypatch.delenv("CTF_SOLVER_LOCAL_DESKTOP", raising=False)
        with pytest.raises(WorkerRefusal) as refused:
            await driver.sandbox_canary(10, tmp_path / "exchange", scratch, source)
        assert refused.value.error.requirements == ("external_sandbox",)

        class Process:
            returncode = 0

            async def communicate(self):
                checks = {
                    "mountinfo_readable": True,
                    "root_read_only": True,
                    "data_absent": True,
                    "database_absent": True,
                    "challenge_readable": True,
                    "skills_readable": True,
                    "scratch_writable": True,
                    "network_ipv4_available": True,
                    "network_ipv6_available": True,
                }
                return json.dumps(checks).encode(), b""

        calls = []

        async def spawn(command, *, cwd=None):
            calls.append((command, cwd))
            return Process()

        driver._spawn_exact = spawn
        monkeypatch.setenv("CTF_SOLVER_LOCAL_DESKTOP", "true")
        await driver.sandbox_canary(10, tmp_path / "exchange", scratch, source)

        assert calls and calls[0][1] == scratch
        command = calls[0][0]
        assert command[:3] == [sys.executable, "-I", "-c"]
        assert '"/data"' in command[3] and '"/database"' in command[3]
        assert "network_ipv4_available" in command[3]
        assert driver.process is None and driver.pid == -1

    asyncio.run(scenario())


def test_solve_manifest_requires_general_internet_policy(tmp_path):
    exchange = tmp_path / "exchange"
    active, manifest = stage_job(exchange)
    loaded = JobManifest.load(active)
    assert loaded.network_enabled is True
    assert loaded.network_policy == "general_internet"

    manifest["network_enabled"] = False
    manifest["network_policy"] = "offline"
    _write_json(active / "manifest.json", manifest)
    with pytest.raises(WorkerRefusal) as refused:
        JobManifest.load(active)
    assert refused.value.error.code == "invalid_manifest"


def test_manifest_rejects_deadline_when_runtime_is_configured_unlimited_and_unknown_service_tier(tmp_path):
    exchange = tmp_path / "exchange"
    active, manifest = stage_job(exchange)
    manifest["deadline_unix"] = time.time() + 3600
    _write_json(active / "manifest.json", manifest)
    with pytest.raises(WorkerRefusal) as error:
        JobManifest.load(active)
    assert error.value.error.code == "invalid_manifest"

    manifest["deadline_unix"] = None
    manifest["service_tier"] = "priority"
    _write_json(active / "manifest.json", manifest)
    with pytest.raises(WorkerRefusal) as error:
        JobManifest.load(active)
    assert error.value.error.code == "invalid_manifest"


def test_wall_clock_deadline_cancels_turn_and_releases_after_cleanup(tmp_path, monkeypatch):
    class SlowDriver(FakeDriver):
        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            await asyncio.Event().wait()

    async def scenario():
        monkeypatch.setattr(solver_worker_module, "MAX_JOB_SECONDS", 1)
        exchange = tmp_path / "exchange"
        active, manifest = stage_job(exchange)
        created = time.time() - 2
        manifest["created_at"] = created
        manifest["deadline_unix"] = created + 1
        _write_json(active / "manifest.json", manifest)
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        worker = worker_for(exchange, driver_factory=SlowDriver)
        worker.prepare()
        assert await worker.process_active()
        events = event_payloads(active)
        timeout = next(event for event in events if event["kind"] == "error")
        released = next(event for event in events if event["kind"] == "released")
        assert timeout["error"]["code"] == "timeout"
        assert timeout["error"]["retryable"] is True
        assert released["status"] == "failed" and released["terminal"] is True

    asyncio.run(scenario())


def test_request_remote_stops_current_turn_and_releases_needs_input(tmp_path, monkeypatch):
    class RemoteRequestDriver(FakeDriver):
        supports_checkpoints = True

        async def run_discovery(
            self, manifest, challenge, cancelled, progress, checkpoint=None
        ):
            self.calls.append("discover")
            await checkpoint("Parsed the archive and found a network client.")
            record_request("Need the public host, port, and protocol", challenge)
            await cancelled.wait()
            raise asyncio.CancelledError

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        RemoteRequestDriver.instances.clear()
        worker = worker_for(exchange, driver_factory=RemoteRequestDriver)
        worker.prepare()

        assert await asyncio.wait_for(worker.process_active(), timeout=2)

        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "needs_input" and state["terminal"] is True
        assert "Parsed the archive" in state["private_notes"]
        assert "Need the public host" in state["private_notes"]
        events = event_payloads(active)
        error = next(event["error"] for event in events if event["kind"] == "error")
        assert error["code"] == "remote_input_required"
        assert next(event for event in events if event["kind"] == "released")["status"] == "needs_input"
        assert RemoteRequestDriver.instances[0].calls.count("discover") == 1
        assert "writeup" not in RemoteRequestDriver.instances[0].calls

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("remote_mode", "remote", "message_fragment"),
    (
        ("endpoint", "nc stale.example 31337", "제공된 원격 접속 정보로 진행할 수 없어"),
        ("none", "", "원격 대상 없음으로 설정되어 있지만"),
    ),
)
def test_request_remote_with_decided_state_requests_correction_instead_of_failing(
    tmp_path, monkeypatch, remote_mode, remote, message_fragment
):
    class RemoteCorrectionDriver(FakeDriver):
        async def run_discovery(self, manifest, challenge, cancelled, progress):
            self.calls.append("discover")
            record_request("Need a corrected endpoint or access detail", challenge)
            await cancelled.wait()
            raise asyncio.CancelledError

    async def scenario():
        exchange = tmp_path / "exchange"
        active, manifest = stage_job(exchange)
        manifest["remote_mode"] = remote_mode
        manifest["remote"] = remote
        _write_json(active / "manifest.json", manifest)
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        worker = worker_for(exchange, driver_factory=RemoteCorrectionDriver)
        worker.prepare()

        assert await asyncio.wait_for(worker.process_active(), timeout=2)
        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "needs_input"
        events = event_payloads(active)
        error = next(event["error"] for event in events if event["kind"] == "error")
        assert error["code"] == "remote_input_required"
        assert message_fragment in error["message"]
        assert next(event for event in events if event["kind"] == "released")["status"] == "needs_input"

    asyncio.run(scenario())


def test_provider_failure_preserves_latest_bounded_turn_checkpoint(tmp_path, monkeypatch):
    class FailingDriver(FakeDriver):
        supports_checkpoints = True

        async def run_discovery(
            self, manifest, challenge, cancelled, progress, checkpoint=None
        ):
            self.calls.append("discover")
            await checkpoint("Recovered key=42; next test the alternate decoder.")
            raise AppServerFailure({"code": "connection_lost"})

    async def scenario():
        exchange = tmp_path / "exchange"
        active, _ = stage_job(exchange)
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        (tmp_path / "tmp").mkdir()
        worker = worker_for(exchange, driver_factory=FailingDriver)
        worker.prepare()

        assert await worker.process_active()

        state = json.loads((active / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "failed" and state["terminal"] is True
        assert state["private_notes"] == "Recovered key=42; next test the alternate decoder."

    asyncio.run(scenario())


def test_published_runtime_is_bound_to_exact_content_digest(tmp_path):
    exchange = tmp_path / "exchange"
    runtime = exchange / "runtime" / "codex-9.9.9"
    package = runtime / "node_modules" / "@openai" / "codex"
    (package / "bin").mkdir(parents=True)
    (package / "package.json").write_text('{"version":"9.9.9"}', encoding="utf-8")
    script = package / "bin" / "codex.js"
    script.write_text("process.exit(0)", encoding="utf-8")
    digest = runtime_tree_digest(runtime)
    command = resolve_codex_command(exchange, "9.9.9", digest)
    assert command[-1] == str(script)
    script.write_text("process.exit(1)", encoding="utf-8")
    with pytest.raises(WorkerRefusal) as error:
        resolve_codex_command(exchange, "9.9.9", digest)
    assert error.value.error.code == "runtime_integrity_failed"
