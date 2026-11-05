"""Offline checks for durable, owner-scoped solver milestone timings."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "ctf_agent").is_dir():
    ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

from local_test_client import TestClient

from ctf_agent.db import Settings
from ctf_agent.main import create_app
from ctf_agent.solver_exchange import ExchangeError, SolverExchangeCoordinator
from ctf_agent.solver_worker import EXCHANGE_PROTOCOL


class SolverTimingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        self.app = create_app(self.settings)
        self.coordinator = self.app.state.solver_jobs.primary
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        csrf = self.client.get("/api/auth/state").json()["csrf_token"]
        self.client.headers.update({"x-csrf-token": csrf})
        response = self.client.post("/api/workspaces", json={"name": "timing"})
        self.assertEqual(response.status_code, 201, response.text)
        self.workspace_id = response.json()["id"]
        response = self.client.post(
            f"/api/workspaces/{self.workspace_id}/challenges",
            json={"name": "offline", "category": "web", "description": "timing test",
                  "remote_mode": "none"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.challenge_id = response.json()["id"]
        with self.coordinator._connect() as db:
            self.owner_id = db.execute(
                "SELECT owner_user_id FROM workspaces WHERE id=?", (self.workspace_id,)
            ).fetchone()[0]
        self.job_id = uuid.uuid4().hex
        with self.coordinator._connect() as db:
            db.execute(
                """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                   model,reasoning_effort,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','offline-test','low','queued',100,100)""",
                (self.job_id, self.owner_id, self.workspace_id,
                 self.challenge_id, uuid.uuid4().hex),
            )

    def event(self, kind: str, sequence: int, **details: object) -> None:
        with self.coordinator._connect() as db:
            job = dict(db.execute("SELECT * FROM solver_jobs WHERE id=?", (self.job_id,)).fetchone())
        self.coordinator._commit_event(job, {
            "protocol": EXCHANGE_PROTOCOL, "job_id": self.job_id,
            "sequence": sequence, "kind": kind, "created_at": 100.0,
            **details,
        })

    def test_observed_stages_and_owner_scope(self) -> None:
        values = iter((110.0, 120.0, 126.0, 150.0, 180.0))
        self.coordinator.clock = lambda: next(values)
        claimed = self.coordinator._claim_next("offline-worker")
        self.assertIsNotNone(claimed)
        with self.coordinator._connect() as db:
            db.execute("UPDATE solver_jobs SET staged_at=116 WHERE id=?", (self.job_id,))
        self.event("status", 1, status="running")
        self.event(
            "activity_evidence", 2, activity_id="a" * 32, correlatable=True,
            phase="started", tool="shell", agent_id="root", command_bytes=1,
            output_bytes=0, command_truncated=False, output_truncated=False,
        )
        self.event("flag", 3, flag="test{timing}")
        self.event("writeup", 4, flag="test{timing}", writeup_markdown="# offline\n\nTest write-up")
        observed = self.coordinator.get(self.job_id, self.owner_id)["timing"]
        self.assertEqual(observed["source"], "coordinator_observed")
        self.assertEqual(observed["queue_seconds"], 10.0)
        self.assertEqual(observed["staging_seconds"], 6.0)
        self.assertEqual(observed["preparation_seconds"], 4.0)
        self.assertEqual(observed["first_activity_wait_seconds"], 6.0)
        self.assertEqual(observed["time_to_flag_seconds"], 30.0)
        self.assertEqual(observed["flag_to_writeup_seconds"], 30.0)
        with self.assertRaises(ExchangeError) as denied:
            self.coordinator.get(self.job_id, uuid.uuid4().hex)
        self.assertEqual(denied.exception.code, "job_not_found")

    def test_missing_old_milestones_are_not_inferred(self) -> None:
        observed = self.coordinator.get(self.job_id, self.owner_id)["timing"]
        self.assertIsNone(observed["queue_seconds"])
        self.assertIsNone(observed["first_activity_wait_seconds"])
        self.assertIsNone(observed["flag_to_writeup_seconds"])

    def test_additive_schema_migration(self) -> None:
        with self.coordinator._connect() as db:
            for field in ("claimed_at", "staged_at", "running_at", "first_activity_at", "flag_at", "writeup_at"):
                db.execute(f"ALTER TABLE solver_jobs DROP COLUMN {field}")
        migrated = SolverExchangeCoordinator(
            self.coordinator.database_path,
            self.coordinator.data_dir,
            self.coordinator.accounts_dir,
            self.coordinator.exchange,
            enforce_host_ownership=False,
        )
        observed = migrated.get(self.job_id, self.owner_id)["timing"]
        self.assertEqual(observed["queued_at"], 100.0)
        self.assertIsNone(observed["claimed_at"])
        self.assertIsNone(observed["flag_at"])


if __name__ == "__main__":
    unittest.main()
