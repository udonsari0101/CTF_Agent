"""Verify challenge solve-time sorting uses the same continuation clock as cards."""

from __future__ import annotations

import sys
import tempfile
import uuid
from pathlib import Path

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.main import create_app


with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
    root = Path(directory)
    app = create_app(Settings(
        root / "data", root / "db", root / "config", root / "logs",
        storage_min_free_bytes=0, auth_mode="nologin",
    ))
    with TestClient(app) as browser:
        browser.headers["x-csrf-token"] = browser.get("/api/auth/state").json()["csrf_token"]
        response = browser.post("/api/workspaces", json={"name": "sort clock"})
        assert response.status_code == 201, response.text
        workspace = response.json()["id"]
        challenges = {}
        for name in ("manual", "slow", "unstarted", "fast"):
            response = browser.post(
                f"/api/workspaces/{workspace}/challenges",
                json={"name": name, "remote_mode": "none"},
            )
            assert response.status_code == 201, response.text
            challenges[name] = response.json()["id"]

        coordinator = app.state.solver_jobs.primary
        with coordinator._connect() as db:
            owner = db.execute(
                "SELECT owner_user_id FROM workspaces WHERE id=?", (workspace,)
            ).fetchone()[0]
            for name, duration in (("slow", 85), ("fast", 12)):
                challenge = challenges[name]
                db.execute(
                    """INSERT INTO solver_jobs(
                           id,owner_user_id,workspace_id,challenge_id,account_id,
                           provider,model,reasoning_effort,status,created_at,
                           updated_at,released_at)
                       VALUES(?,?,?,?,?,'codex','offline-test','low','completed',
                              100,?,?)""",
                    (uuid.uuid4().hex, owner, workspace, challenge,
                     uuid.uuid4().hex, 100 + duration, 100 + duration),
                )
                db.execute("UPDATE challenges SET status='solved' WHERE id=?", (challenge,))
            db.execute(
                "UPDATE challenges SET status='solved' WHERE id=?",
                (challenges["manual"],),
            )

        response = browser.get(
            f"/api/workspaces/{workspace}/challenges", params={"sort": "solve_time_asc"}
        )
        assert response.status_code == 200, response.text
        rows = response.json()["challenges"]
        assert [row["name"] for row in rows[:2]] == ["fast", "slow"]
        assert {row["name"] for row in rows[2:]} == {"unstarted", "manual"}
        assert [row["latest_solver"]["elapsed_seconds"] for row in rows[:2]] == [12, 85]
        response = browser.get(
            f"/api/workspaces/{workspace}/challenges", params={"sort": "solve_time_desc"}
        )
        assert response.status_code == 200, response.text
        rows = response.json()["challenges"]
        assert [row["name"] for row in rows[:2]] == ["slow", "fast"]
        assert {row["name"] for row in rows[2:]} == {"unstarted", "manual"}
        assert browser.get(
            f"/api/workspaces/{workspace}/challenges", params={"sort": "bogus"}
        ).status_code == 400

print("solve-time ordering: completed agent runs first; unmeasured last")
