"""Offline regression checks for provider activity provenance and public paging."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_exchange import (  # noqa: E402
    EXCHANGE_PROTOCOL,
    SCHEMA,
    ExchangeError,
    SolverExchangeCoordinator,
    _validate_event,
)
from ctf_agent.solver_worker import (  # noqa: E402
    CodexAppServer,
    EventWriter,
    MAX_LIVE_ACTIVITY_EVENTS,
    MAX_LIVE_OUTPUT_BYTES,
    _provider_activity_id,
)

JOB_ID = "a" * 32
OWNER_ID = "owner-1"


def make_driver(*, reporter=None, evidence=None, activity_count=0):
    driver = object.__new__(CodexAppServer)
    driver.activity_reporter = reporter
    driver.evidence_reporter = evidence
    driver.activity_events = activity_count
    driver._next_activity_sample_at = None
    driver.agent_nodes = {}
    driver._current_event_agent_id = "root"
    return driver


def make_coordinator(db_path):
    coordinator = object.__new__(SolverExchangeCoordinator)
    coordinator.database_path = db_path
    coordinator.clock = time.time
    return coordinator


def create_job_db(db_path):
    with contextlib.closing(sqlite3.connect(db_path)) as db, db:
        db.execute(
            "CREATE TABLE challenges(id TEXT,workspace_id TEXT,name TEXT,status TEXT,"
            "completion_source TEXT,flag TEXT,notes TEXT)"
        )
        db.executescript(SCHEMA)
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,status) "
            "VALUES('challenge-1','workspace-1','test','running')"
        )
        db.execute(
            """INSERT INTO solver_jobs(
                 id,owner_user_id,workspace_id,challenge_id,account_id,
                 provider,model,reasoning_effort,status,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (JOB_ID, OWNER_ID, "workspace-1", "challenge-1", "account-1",
             "codex", "model", "high", "running", 1, 1),
        )


class ActivityProvenanceTests(unittest.TestCase):
    def test_provider_identity_is_stable_opaque_and_scoped(self):
        original = _provider_activity_id("codex", "thread-A", "item-1")
        self.assertRegex(original, r"^[0-9a-f]{32}$")
        self.assertEqual(original, _provider_activity_id("codex", "thread-A", "item-1"))
        self.assertNotIn("thread", original)
        self.assertNotEqual(original, _provider_activity_id("codex", "thread-A", "item-2"))
        self.assertNotEqual(original, _provider_activity_id("codex", "thread-B", "item-1"))
        self.assertNotEqual(original, _provider_activity_id("claude", "thread-A", "item-1"))
        self.assertIsNone(_provider_activity_id("codex", "thread-A", None))

    def test_tool_evidence_survives_live_log_cap_and_is_append_only(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            base = Path(temp)
            writer = EventWriter(base, JOB_ID)
            live = []

            async def evidence(**details):
                writer.emit("activity_evidence", **details)

            async def activity(**details):
                live.append(details)

            driver = make_driver(
                reporter=activity, evidence=evidence,
                activity_count=MAX_LIVE_ACTIVITY_EVENTS,
            )
            activity_id = _provider_activity_id("codex", "thread-1", "command-1")
            output = "x" * (MAX_LIVE_OUTPUT_BYTES + 9)

            async def run():
                await driver._report_activity(
                    "started", "shell", "Command started", command="echo x",
                    activity_id=activity_id,
                )
                await driver._report_activity(
                    "completed", "shell", "Command completed", output=output,
                    exit_code=0, activity_id=activity_id,
                )

            asyncio.run(run())
            self.assertEqual(live, [])
            records = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((base / "events").glob("*.json"))
            ]
            self.assertEqual([item["phase"] for item in records], ["started", "completed"])
            self.assertEqual({item["activity_id"] for item in records}, {activity_id})
            self.assertTrue(all(item["correlatable"] for item in records))
            self.assertEqual(records[1]["output_bytes"], len(output))
            self.assertTrue(records[1]["output_truncated"])
            self.assertFalse(any("output" in item or "command" in item for item in records))
            for sequence, event in enumerate(records, 1):
                self.assertEqual(_validate_event(event, JOB_ID, sequence), event)

            db_path = base / "ledger.sqlite3"
            create_job_db(db_path)
            coordinator = make_coordinator(db_path)
            job = {"id": JOB_ID, "workspace_id": "workspace-1", "challenge_id": "challenge-1"}
            for event in records:
                coordinator._commit_event(job, event)
            coordinator._commit_event(job, records[0])  # replay is idempotent
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                stored = db.execute(
                    "SELECT sequence,kind,event_json FROM solver_job_events ORDER BY sequence"
                ).fetchall()
                self.assertEqual([(row[0], row[1]) for row in stored],
                                 [(1, "activity_evidence"), (2, "activity_evidence")])
                self.assertFalse(any(output[:100] in row[2] for row in stored))

    def test_public_pages_skip_private_rows_without_spending_limit(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            base = Path(temp)
            writer = EventWriter(base, JOB_ID)
            db_path = base / "ledger.sqlite3"
            create_job_db(db_path)
            coordinator = make_coordinator(db_path)
            job = {"id": JOB_ID, "workspace_id": "workspace-1", "challenge_id": "challenge-1"}
            activity_id = "f" * 32
            for index in range(6):
                event = writer.emit(
                    "activity_evidence", activity_id=activity_id,
                    correlatable=True,
                    phase="started" if index % 2 == 0 else "completed",
                    tool="shell", command_bytes=4, output_bytes=0,
                    command_truncated=False, output_truncated=False,
                )
                coordinator._commit_event(job, event)
            for label in ("first", "second", "third"):
                coordinator._commit_event(job, writer.emit(
                    "activity", phase="completed", tool="analysis", summary=label,
                ))

            page1 = coordinator.get(JOB_ID, OWNER_ID, after=0, limit=2)
            self.assertEqual([event["summary"] for event in page1["events"]],
                             ["first", "second"])
            self.assertEqual(page1["event_cursor"], 8)
            page2 = coordinator.get(JOB_ID, OWNER_ID, after=page1["event_cursor"], limit=2)
            self.assertEqual([event["summary"] for event in page2["events"]], ["third"])
            self.assertEqual(page2["event_cursor"], 9)
            self.assertEqual(
                coordinator.get(JOB_ID, OWNER_ID, after=page2["event_cursor"], limit=2)["events"],
                [],
            )
            with self.assertRaises(ExchangeError):
                coordinator.get(JOB_ID, "different-owner", after=0, limit=2)
            self.assertEqual(page1["account_id"], "account-1")

    def test_missing_provider_id_is_recorded_without_false_pairing(self):
        evidence = []

        async def record(**details):
            evidence.append(details)

        driver = make_driver(evidence=record, activity_count=MAX_LIVE_ACTIVITY_EVENTS)

        async def run():
            await driver._report_activity("started", "shell", "Started", command="echo test")
            await driver._report_activity("completed", "shell", "Completed", output="test")

        asyncio.run(run())
        self.assertEqual(len(evidence), 2)
        self.assertNotEqual(evidence[0]["activity_id"], evidence[1]["activity_id"])
        self.assertTrue(all(item["correlatable"] is False for item in evidence))

    def test_live_activity_shows_truncation_when_sampled_in(self):
        seen = []

        async def record(**details):
            seen.append(details)

        driver = make_driver(reporter=record)
        activity_id = _provider_activity_id("claude", "session", "tool-1")
        asyncio.run(driver._report_activity(
            "completed", "shell", "Done", output="y" * (MAX_LIVE_OUTPUT_BYTES + 1),
            activity_id=activity_id,
        ))
        self.assertEqual(seen[0]["activity_id"], activity_id)
        self.assertTrue(seen[0]["output_truncated"])
        self.assertLessEqual(len(seen[0]["output"].encode("utf-8")), MAX_LIVE_OUTPUT_BYTES)

    def test_evidence_schema_rejects_leaks_and_invalid_metadata(self):
        valid = {
            "protocol": EXCHANGE_PROTOCOL, "job_id": JOB_ID, "sequence": 1,
            "kind": "activity_evidence", "created_at": 1.0,
            "activity_id": "a" * 32, "correlatable": True,
            "phase": "started", "tool": "shell", "command_bytes": 3,
            "output_bytes": 0, "command_truncated": False,
            "output_truncated": False,
        }
        self.assertEqual(_validate_event(valid, JOB_ID, 1), valid)
        for changed in (
            {"activity_id": "raw-provider-tool-id"}, {"command": "secret"},
            {"command_bytes": -1}, {"output_truncated": 1}, {"correlatable": 1},
        ):
            with self.subTest(changed=changed), self.assertRaises(ExchangeError):
                _validate_event({**valid, **changed}, JOB_ID, 1)


if __name__ == "__main__":
    unittest.main()
