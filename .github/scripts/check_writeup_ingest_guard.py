"""Offline regression checks for coordinator write-up publication boundaries.

Run from the repository root:
    python .github/scripts/check_writeup_ingest_guard.py
No model, network, Telegram or CTFd connection is used.
"""

from __future__ import annotations

import gc
import hashlib
import json
import sys
import tempfile
import unittest
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.db import Settings, connect, initialize
from ctf_agent.solver_exchange import (
    EXCHANGE_PROTOCOL, SolverExchangeCoordinator, _public_job, _validate_event,
)
from ctf_agent.writeups import merge_generated_writeup


FLAG = "test{offline-writeup-guard}"
UNSAFE = "# Challenge\n\n```python\nprint('solved')\nsubmit-flag " + FLAG + "\n```\n"
SAFE = "# Challenge\n\n```python\nprint('solved')\n```\n"


class IngestGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.settings = Settings(root / "data", root / "db", root / "config", root / "logs")
        initialize(self.settings)
        self.flags: list[str] = []
        self.writeups: list[str] = []
        self.coordinator = SolverExchangeCoordinator(
            self.settings.database_path,
            self.settings.data_dir,
            root / "accounts",
            root / "exchange",
            on_flag_committed=lambda owner, workspace, challenge, flag, job: self.flags.append(flag),
            on_writeup_committed=lambda owner, workspace, challenge, markdown, job: self.writeups.append(markdown),
        )
        self.counter = 0

    def tearDown(self) -> None:
        self.coordinator = None
        gc.collect()

    def make_job(self, *, mode: str = "solve", source: str | None = None) -> tuple[str, str, str]:
        self.counter += 1
        suffix = f"{self.counter:032x}"
        workspace_id, challenge_id, job_id = suffix, f"{self.counter + 100:032x}", f"{self.counter + 200:032x}"
        with self.db() as db:
            db.execute(
                "INSERT INTO workspaces(id,name,created_at,updated_at) VALUES(?,?,?,?)",
                (workspace_id, "Offline", "2026-01-01", "2026-01-01"),
            )
            db.execute(
                """INSERT INTO challenges(id,workspace_id,name,description,status,flag,notes,
                   completion_source,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    challenge_id, workspace_id, "Challenge", "offline test",
                    "solved" if mode == "writeup_refine" else "pending",
                    FLAG if mode == "writeup_refine" else None,
                    merge_generated_writeup("operator note", source, None) if source else "operator note",
                    "agent" if mode == "writeup_refine" else None,
                    "2026-01-01", "2026-01-01",
                ),
            )
            if source:
                db.execute(
                    "INSERT INTO challenge_writeups(challenge_id,markdown,created_at,updated_at) VALUES(?,?,?,?)",
                    (challenge_id, source, "2026-01-01", "2026-01-01"),
                )
            db.execute(
                """INSERT INTO solver_jobs(id,job_mode,owner_user_id,workspace_id,challenge_id,
                   account_id,provider,model,reasoning_effort,status,flag,source_writeup_sha256,
                   created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, mode, "a" * 32, workspace_id, challenge_id,
                    "b" * 32, "codex", "test-model", "low", "running",
                    FLAG if mode == "writeup_refine" else None,
                    hashlib.sha256(source.encode()).hexdigest() if source else None,
                    1.0, 1.0,
                ),
            )
        return workspace_id, challenge_id, job_id

    @contextmanager
    def db(self):
        connection = connect(self.settings)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def commit(self, job_id: str, event: dict):
        with self.db() as db:
            job = dict(db.execute(
                "SELECT id,workspace_id,challenge_id FROM solver_jobs WHERE id=?", (job_id,)
            ).fetchone())
        self.coordinator._commit_event(job, _validate_event(event, job_id, event["sequence"]))

    @staticmethod
    def event(job_id: str, sequence: int, kind: str, **kwargs):
        return {
            "protocol": EXCHANGE_PROTOCOL,
            "job_id": job_id,
            "sequence": sequence,
            "kind": kind,
            "created_at": float(sequence),
            **kwargs,
        }

    def row(self, table: str, column: str, value: str):
        with self.db() as db:
            return db.execute(f"SELECT * FROM {table} WHERE {column}=?", (value,)).fetchone()

    def test_unsafe_writeup_event_preserves_flag_and_fails_on_release(self):
        _, challenge_id, job_id = self.make_job()
        self.commit(job_id, self.event(job_id, 1, "flag", flag=FLAG))
        self.commit(
            job_id, self.event(job_id, 2, "writeup", flag=FLAG, writeup_markdown=UNSAFE),
        )
        job = self.row("solver_jobs", "id", job_id)
        self.assertEqual(job["flag"], FLAG)
        self.assertIsNone(job["writeup_markdown"])
        self.assertEqual(self.row("challenges", "id", challenge_id)["status"], "flag_found")
        self.assertIsNone(self.row("challenge_writeups", "challenge_id", challenge_id))
        with self.db() as db:
            stored = json.loads(db.execute(
                "SELECT event_json FROM solver_job_events WHERE job_id=? AND sequence=2", (job_id,)
            ).fetchone()[0])
        self.assertEqual(stored["kind"], "error")
        self.assertNotIn("writeup_markdown", stored)
        self.assertTrue(stored["error"]["retryable"])
        # A second candidate from the same cancelled attempt cannot publish
        # after the first candidate failed the publication boundary.
        self.commit(
            job_id, self.event(job_id, 3, "writeup", flag=FLAG, writeup_markdown=SAFE),
        )
        self.assertIsNone(self.row("challenge_writeups", "challenge_id", challenge_id))
        self.commit(
            job_id,
            self.event(job_id, 4, "released", status="completed", flag=FLAG,
                       writeup_markdown=UNSAFE, terminal=True),
        )
        self.assertEqual(self.row("solver_jobs", "id", job_id)["status"], "failed")
        self.assertEqual(self.row("challenges", "id", challenge_id)["flag"], FLAG)
        self.assertTrue(self.coordinator._deliver_pending_hooks(job_id))
        self.assertEqual(self.flags, [FLAG])
        self.assertEqual(self.writeups, [])

    def test_release_only_unsafe_markdown_is_not_persisted(self):
        _, challenge_id, job_id = self.make_job()
        self.commit(job_id, self.event(job_id, 1, "flag", flag=FLAG))
        self.commit(
            job_id,
            self.event(job_id, 2, "released", status="completed", flag=FLAG,
                       writeup_markdown=UNSAFE, terminal=True),
        )
        with self.db() as db:
            stored = json.loads(db.execute(
                "SELECT event_json FROM solver_job_events WHERE job_id=? AND sequence=2", (job_id,)
            ).fetchone()[0])
        self.assertNotIn("writeup_markdown", stored)
        self.assertEqual(stored["status"], "failed")
        self.assertEqual(self.row("solver_jobs", "id", job_id)["status"], "failed")
        self.assertEqual(self.row("challenges", "id", challenge_id)["status"], "flag_found")

    def test_safe_writeup_still_publishes(self):
        _, challenge_id, job_id = self.make_job()
        self.commit(job_id, self.event(job_id, 1, "flag", flag=FLAG))
        self.commit(
            job_id, self.event(job_id, 2, "writeup", flag=FLAG, writeup_markdown=SAFE),
        )
        self.assertEqual(self.row("challenge_writeups", "challenge_id", challenge_id)["markdown"], SAFE)
        self.coordinator._deliver_pending_hooks(job_id)
        self.assertEqual(self.writeups, [SAFE])

    def test_refinement_cannot_replace_safe_writeup(self):
        _, challenge_id, job_id = self.make_job(mode="writeup_refine", source=SAFE)
        self.commit(
            job_id, self.event(job_id, 1, "writeup", flag=FLAG, writeup_markdown=UNSAFE),
        )
        self.assertEqual(self.row("challenge_writeups", "challenge_id", challenge_id)["markdown"], SAFE)
        self.assertIsNone(self.row("solver_jobs", "id", job_id)["writeup_markdown"])
        self.assertEqual(self.writeups, [])

    def test_legacy_pending_notification_is_quarantined(self):
        _, challenge_id, job_id = self.make_job(mode="writeup_refine", source=UNSAFE)
        with self.db() as db:
            db.execute(
                """UPDATE solver_jobs SET job_mode='solve',status='completed',released_ingested=1,
                   writeup_markdown=?,flag_hooked=1,writeup_hooked=0 WHERE id=?""",
                (UNSAFE, job_id),
            )
        self.assertTrue(self.coordinator._deliver_pending_hooks(job_id))
        self.assertEqual(self.writeups, [])
        self.assertEqual(self.row("challenge_writeups", "challenge_id", challenge_id)["markdown"], UNSAFE)
        challenge = self.row("challenges", "id", challenge_id)
        self.assertEqual(challenge["status"], "solved")
        self.assertEqual(challenge["flag"], FLAG)
        self.assertIn("submit-flag", challenge["notes"])
        job = self.row("solver_jobs", "id", job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIsNone(job["writeup_markdown"])
        self.assertEqual(json.loads(job["error_json"])["code"], "writeup_publication_unsafe")

    def test_legacy_quarantine_does_not_depend_on_flag_notification(self):
        _, challenge_id, job_id = self.make_job(mode="writeup_refine", source=UNSAFE)
        with self.db() as db:
            db.execute(
                """UPDATE solver_jobs SET job_mode='solve',status='completed',released_ingested=1,
                   writeup_markdown=?,flag_hooked=0,writeup_hooked=0 WHERE id=?""",
                (UNSAFE, job_id),
            )
        self.coordinator.on_flag_committed = lambda *args: False
        self.assertTrue(self.coordinator._deliver_pending_hooks(job_id))
        self.assertEqual(self.row("challenge_writeups", "challenge_id", challenge_id)["markdown"], UNSAFE)
        self.assertEqual(self.row("challenges", "id", challenge_id)["flag"], FLAG)
        self.assertEqual(self.writeups, [])

    def test_legacy_quarantine_keeps_newer_safe_writeup(self):
        _, challenge_id, job_id = self.make_job(mode="writeup_refine", source=SAFE)
        with self.db() as db:
            db.execute(
                """UPDATE solver_jobs SET job_mode='solve',status='completed',released_ingested=1,
                   writeup_markdown=?,flag_hooked=1,writeup_hooked=0 WHERE id=?""",
                (UNSAFE, job_id),
            )
        self.assertTrue(self.coordinator._deliver_pending_hooks(job_id))
        self.assertEqual(self.row("challenge_writeups", "challenge_id", challenge_id)["markdown"], SAFE)
        self.assertEqual(self.row("challenges", "id", challenge_id)["status"], "solved")

    def test_public_job_hides_unsafe_legacy_markdown(self):
        _, _, job_id = self.make_job()
        row = defaultdict(lambda: None, dict(self.row("solver_jobs", "id", job_id)))
        row["status"] = "completed"
        row["released_ingested"] = 1
        row["writeup_markdown"] = UNSAFE
        visible = _public_job(
            row,
            [{"kind": "writeup", "writeup_markdown": UNSAFE},
             {"kind": "released", "writeup_markdown": UNSAFE}],
            None,
        )
        self.assertIsNone(visible["writeup_markdown"])
        self.assertTrue(all("writeup_markdown" not in event for event in visible["events"]))


if __name__ == "__main__":
    unittest.main()
