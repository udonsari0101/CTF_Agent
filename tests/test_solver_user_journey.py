"""Deterministic user-journey coverage for solver completion semantics."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import unquote

from fastapi.testclient import TestClient

from ctf_agent.db import Settings, connect
from ctf_agent.main import create_app
from ctf_agent.solver_service import SolverService
from ctf_agent.writeups import merge_generated_writeup


PASSWORD = "solver-journey-password"


def _write_worker_ready(exchange: Path) -> None:
    checks = {
        "linux": True,
        "non_root": True,
        "exchange_exact": True,
        "data_absent": True,
        "database_absent": True,
        "root_read_only": True,
        "exchange_mounted_rw": True,
        "runtime_mounted_ro": True,
        "input_exact": True,
        "input_mounted_ro": True,
        "input_same_exchange": True,
        "scratch_exact": True,
        "scratch_directory": True,
        "scratch_not_symlink": True,
        "scratch_owned": True,
        "scratch_not_world_writable": True,
        "scratch_mounted_rw": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "seccomp_filter": True,
        "trusted_inet_sockets": True,
        "security_boundary": True,
        "private_pid_namespace": True,
    }
    (exchange / "worker.json").write_text(
        json.dumps(
            {
                "protocol": 1,
                "ready": True,
                "clean": True,
                "sandbox_canary": True,
                "instance_id": "deterministic-worker-instance",
                "pid": 1,
                "checks": checks,
                "checked_at": time.time(),
            }
        ),
        encoding="utf-8",
    )


def _write_event(active: Path, sequence: int, kind: str, **values) -> None:
    manifest = json.loads((active / "manifest.json").read_text(encoding="utf-8"))
    event = {
        "protocol": 1,
        "job_id": manifest["job_id"],
        "sequence": sequence,
        "kind": kind,
        "created_at": time.time(),
        **values,
    }
    events = active / "events"
    events.mkdir(exist_ok=True)
    (events / f"{sequence:08d}.json").write_text(
        json.dumps(event, ensure_ascii=False), encoding="utf-8"
    )


def _create_challenge(client: TestClient, workspace_id: str, name: str) -> dict:
    response = client.post(
        f"/api/workspaces/{workspace_id}/challenges",
        json={"name": name, "description": "A deterministic fixture."},
    )
    assert response.status_code == 201
    return response.json()


def _tick_until(coordinator, predicate, *, timeout: float = 3.0) -> None:
    """Drive the asynchronous slot pool until the observable state commits."""

    deadline = time.monotonic() + timeout
    while True:
        coordinator.tick()
        if predicate():
            return
        if time.monotonic() >= deadline:
            raise AssertionError("solver pool did not reach the expected state")
        time.sleep(0.01)


def test_fake_solver_events_cover_flag_writeup_manual_and_quota_paths(
    tmp_path, monkeypatch
):
    """Exercise the user-visible lifecycle without a provider or the network."""

    async def skip_background_service(_service):
        return None

    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("CTF_SOLVER_EXCHANGE_WEB", raising=False)
    monkeypatch.setattr(SolverService, "start", skip_background_service)
    monkeypatch.setattr(SolverService, "stop", skip_background_service)

    settings = Settings(
        tmp_path / "data",
        tmp_path / "database",
        tmp_path / "config",
        tmp_path / "logs",
    )
    app = create_app(settings)

    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"password": PASSWORD})
        assert login.status_code == 200
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        owner = login.json()["user"]["id"]

        workspace_response = client.post(
            "/api/workspaces", json={"name": "Solver lifecycle"}
        )
        assert workspace_response.status_code == 201
        workspace = workspace_response.json()

        account_id = "a" * 32
        with connect(settings) as db:
            db.execute(
                """INSERT INTO provider_accounts(
                       id,provider,label,selected,model,reasoning_effort,
                       snapshot,checked_at,created_at,owner_user_id,service_tier
                   ) VALUES(?,'codex','Fixture Codex',1,'gpt-5.6-sol','high',?,?,?,?,NULL)""",
                (
                    account_id,
                    json.dumps({"status": "authenticated"}),
                    time.time(),
                    time.time(),
                    owner,
                ),
            )
        account_home = app.state.solver.coordinator.accounts_dir / account_id / "codex"
        account_home.mkdir(parents=True)
        (account_home / "auth.json").write_text(
            json.dumps(
                {
                    "auth_mode": "chatgpt",
                    "tokens": {
                        "id_token": "fixture-id",
                        "access_token": "fixture-access",
                        "refresh_token": "fixture-refresh",
                        "account_id": "fixture-account",
                    },
                }
            ),
            encoding="utf-8",
        )
        (account_home / "auth.json").chmod(0o600)

        coordinator = app.state.solver.coordinator
        _write_worker_ready(coordinator.exchange)
        observed_hooks: list[tuple[str, str]] = []

        def flag_hook(_owner, _workspace, challenge_id, flag, job_id):
            assert job_id == queued["id"]
            with connect(settings) as db:
                challenge = db.execute(
                    "SELECT flag,status FROM challenges WHERE id=?", (challenge_id,)
                ).fetchone()
                writeup = db.execute(
                    "SELECT 1 FROM challenge_writeups WHERE challenge_id=?",
                    (challenge_id,),
                ).fetchone()
            assert tuple(challenge) == (flag, "flag_found")
            assert writeup is None
            observed_hooks.append(("flag", flag))
            return True

        def writeup_hook(_owner, _workspace, challenge_id, markdown, job_id):
            assert job_id == queued["id"]
            with connect(settings) as db:
                result = db.execute(
                    """SELECT c.status,c.completion_source,c.notes,w.markdown
                       FROM challenges c
                       JOIN challenge_writeups w ON w.challenge_id=c.id
                       WHERE c.id=?""",
                    (challenge_id,),
                ).fetchone()
            assert tuple(result) == (
                "solved",
                "agent",
                merge_generated_writeup("# analyst notes\n", markdown),
                markdown,
            )
            observed_hooks.append(("writeup", markdown))
            return True

        app.state.telegram_flag_found = flag_hook
        app.state.telegram_writeup_ready = writeup_hook
        app.state.ctfd_auto_submit_flag = lambda *_args: True

        solved = _create_challenge(client, workspace["id"], "한글 / Agent: 1")
        solved_route = (
            f"/api/workspaces/{workspace['id']}/challenges/{solved['id']}"
        )
        assert client.put(
            solved_route + "/notes", json={"content": "# analyst notes\n"}
        ).status_code == 200

        queued = coordinator.enqueue(owner, workspace["id"], solved["id"])
        assert queued["status"] == "queued"
        assert client.get(solved_route).json()["status"] == "running"

        _tick_until(
            coordinator,
            lambda: (coordinator.exchange / "active" / "manifest.json").is_file(),
        )
        assert client.get(solved_route).json()["status"] == "running"
        active = coordinator.exchange / "active"
        (active / "auth.json").unlink()

        _write_event(active, 1, "status", status="running", terminal=False)
        _tick_until(
            coordinator,
            lambda: coordinator.get(queued["id"], owner)["status"] == "running",
        )
        assert coordinator.get(queued["id"], owner)["status"] == "running"

        flag = "SARI{committed_before_writeup}"
        _write_event(active, 2, "flag", flag=flag)
        _tick_until(
            coordinator,
            lambda: client.get(solved_route).json().get("flag") == flag
            and observed_hooks == [("flag", flag)],
        )
        flag_visible = client.get(solved_route).json()
        assert flag_visible["status"] == "flag_found"
        assert flag_visible["flag"] == flag
        assert flag_visible["has_writeup"] is False
        assert client.get(solved_route + "/writeup").status_code == 404
        assert observed_hooks == [("flag", flag)]

        generated = "# Agent result\n\nThe deterministic fixture was solved.\n"
        _write_event(
            active,
            3,
            "writeup",
            flag=flag,
            writeup_markdown=generated,
            terminal=False,
        )
        _tick_until(
            coordinator,
            lambda: client.get(solved_route).json().get("status") == "solved"
            and observed_hooks == [("flag", flag), ("writeup", generated)],
        )
        agent_complete = client.get(solved_route).json()
        assert agent_complete["status"] == "solved"
        assert agent_complete["completion_source"] == "agent"
        merged_notes = merge_generated_writeup("# analyst notes\n", generated)
        assert agent_complete["notes"] == merged_notes
        assert agent_complete["writeup_markdown"] == generated
        assert observed_hooks == [("flag", flag), ("writeup", generated)]

        _write_event(
            active,
            4,
            "released",
            status="completed",
            flag=flag,
            writeup_markdown=generated,
            terminal=True,
        )
        _tick_until(
            coordinator,
            lambda: coordinator.get(queued["id"], owner)["status"] == "completed",
        )
        assert coordinator.get(queued["id"], owner)["status"] == "completed"

        notes_download = client.get(solved_route + "/notes/download")
        writeup_download = client.get(solved_route + "/writeup/download")
        assert notes_download.text == merged_notes
        assert writeup_download.text == generated
        assert "한글 _ Agent_ 1-notes.md" in unquote(
            notes_download.headers["content-disposition"]
        )
        assert "한글 _ Agent_ 1-writeup.md" in unquote(
            writeup_download.headers["content-disposition"]
        )

        manual = _create_challenge(client, workspace["id"], "Manual only")
        manual_route = (
            f"/api/workspaces/{workspace['id']}/challenges/{manual['id']}"
        )
        manual_result = client.post(manual_route + "/complete")
        assert manual_result.status_code == 200
        assert manual_result.json()["completion_source"] == "manual"
        assert manual_result.json()["has_writeup"] is False
        assert client.get(manual_route + "/writeup").status_code == 404
        assert client.get(manual_route + "/writeup/download").status_code == 404
        with connect(settings) as db:
            assert db.execute(
                "SELECT 1 FROM challenge_writeups WHERE challenge_id=?", (manual["id"],)
            ).fetchone() is None

        quota_challenge = _create_challenge(
            client, workspace["id"], "Flag survives provider quota"
        )
        quota_route = (
            f"/api/workspaces/{workspace['id']}/challenges/{quota_challenge['id']}"
        )
        quota_job = coordinator.enqueue(
            owner, workspace["id"], quota_challenge["id"]
        )
        assert quota_job["status"] == "queued"
        _tick_until(
            coordinator,
            lambda: (coordinator.exchange / "active" / "manifest.json").is_file(),
        )
        quota_active = coordinator.exchange / "active"
        (quota_active / "auth.json").unlink()
        quota_flag = "SARI{durable_even_when_quota_stops_writeup}"
        _write_event(
            quota_active, 1, "status", status="running", terminal=False
        )
        _write_event(quota_active, 2, "flag", flag=quota_flag)
        _tick_until(
            coordinator,
            lambda: client.get(quota_route).json().get("flag") == quota_flag,
        )

        quota_error = {
            "code": "usage_limit_exceeded",
            "message": "The selected account reached its usage limit.",
            "stage": "solve",
            "category": "quota",
            "retryable": True,
            "quota": {
                "limit_id": "codex",
                "limit_name": "Codex Standard",
                "reached_type": "workspace_member_usage_limit_reached",
                "windows": [
                    {
                        "kind": "primary",
                        "window_minutes": 300,
                        "used_percent": 100,
                        "resets_at": 1_788_941_100,
                    }
                ],
            },
        }
        _write_event(
            quota_active,
            3,
            "error",
            error=quota_error,
            flag=quota_flag,
            terminal=False,
        )
        _write_event(
            quota_active,
            4,
            "released",
            status="failed",
            error=quota_error,
            flag=quota_flag,
            terminal=True,
        )
        _tick_until(
            coordinator,
            lambda: coordinator.get(quota_job["id"], owner)["status"] == "failed",
        )

        failed_job = coordinator.get(quota_job["id"], owner)
        assert failed_job["status"] == "failed"
        assert failed_job["flag"] == quota_flag
        assert failed_job["error"] == quota_error
        durable_flag = client.get(quota_route).json()
        assert durable_flag["status"] == "flag_found"
        assert durable_flag["flag"] == quota_flag
        assert durable_flag["completion_source"] is None
        assert durable_flag["has_writeup"] is False
        assert client.get(quota_route + "/writeup").status_code == 404
