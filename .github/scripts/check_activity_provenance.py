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
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_exchange import (  # noqa: E402
    EXCHANGE_PROTOCOL,
    SCHEMA,
    ExchangeError,
    SolverExchangeCoordinator,
    _normalize_legacy_attachment_activity,
    _validate_event,
)
from ctf_agent.solver_worker import (  # noqa: E402
    ClaudePrintDriver,
    CodexAppServer,
    EventWriter,
    MAX_LIVE_ACTIVITY_EVENTS,
    MAX_LIVE_OUTPUT_BYTES,
    _provider_activity_id,
    _watch_live_attachments,
)
from ctf_agent.solve_repeat import SolveRepeatObserver  # noqa: E402

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
            "CREATE TABLE challenges(id TEXT,workspace_id TEXT,name TEXT,canonical_name TEXT,status TEXT,"
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
    def test_repeated_root_shell_result_is_a_private_next_turn_hint(self):
        driver = make_driver(activity_count=MAX_LIVE_ACTIVITY_EVENTS)
        driver._solve_repeat_observer = SolveRepeatObserver()
        driver.agent_nodes["child"] = {}

        async def run():
            for index in range(3):
                key = f"child-{index}"
                await driver._report_activity(
                    "started", "shell", "Started", command="ls", agent_id="child",
                    activity_id=key,
                )
                await driver._report_activity(
                    "completed", "shell", "Done", output="same", agent_id="child",
                    activity_id=key,
                )
            for index in range(3):
                key = f"root-{index}"
                await driver._report_activity(
                    "started", "shell", "Started", command="ls", activity_id=key,
                )
                await driver._report_activity(
                    "completed", "shell", "Done", output="same", activity_id=key,
                )

        asyncio.run(run())
        self.assertTrue(driver._solve_repeat_observer.take_hint())
        self.assertFalse(driver._solve_repeat_observer.take_hint())

    def test_changed_shell_results_and_unpaired_completions_do_not_hint(self):
        observer = SolveRepeatObserver()
        for index in range(4):
            key = str(index)
            observer.started(key, "curl https://example.test/status")
            observer.completed(key, f"state={index}", 0)
        observer.completed("orphan", "state=0", 0)
        self.assertFalse(observer.take_hint())

    def test_repeated_result_only_compares_matching_command_and_output(self):
        observer = SolveRepeatObserver()
        for index, command in enumerate(("ls a", "ls b", "ls a")):
            key = str(index)
            observer.started(key, command)
            observer.completed(key, "same", 0)
        self.assertFalse(observer.take_hint())
        observer.started("last", "ls a")
        observer.completed("last", "same", 0)
        self.assertTrue(observer.take_hint())

    def test_legacy_live_attachment_events_are_narrowly_recovered(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            active = Path(temp)
            writer = EventWriter(active, JOB_ID)
            writer.emit(
                "activity", phase="attachment_added",
                summary="1 new attachment(s) available in attachments/",
            )
            writer.emit(
                "activity", phase="attachment_sync_failed",
                summary="private diagnostic\x00" + "x" * 800,
            )
            db_path = active / "ledger.sqlite3"
            create_job_db(db_path)
            coordinator = make_coordinator(db_path)
            coordinator.deliver_global_hooks = False
            job = {"id": JOB_ID, "workspace_id": "workspace-1", "challenge_id": "challenge-1", "last_event_sequence": 0}
            self.assertTrue(coordinator._ingest_events(job, active))
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                self.assertIsNone(db.execute(
                    "SELECT first_activity_at FROM solver_jobs WHERE id=?", (JOB_ID,)
                ).fetchone()[0])
            writer.emit("activity", phase="completed", tool="analysis", summary="next event")
            job["last_event_sequence"] = 2
            self.assertTrue(coordinator._ingest_events(job, active))
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                events = [json.loads(row[0]) for row in db.execute(
                    "SELECT event_json FROM solver_job_events ORDER BY sequence"
                )]
                self.assertIsNotNone(db.execute(
                    "SELECT first_activity_at FROM solver_jobs WHERE id=?", (JOB_ID,)
                ).fetchone()[0])
            self.assertEqual([event["phase"] for event in events], ["completed"] * 3)
            self.assertEqual([event["tool"] for event in events], ["file", "file", "analysis"])
            self.assertEqual([event.get("exit_code") for event in events], [0, 1, None])
            self.assertEqual(events[1]["summary"], "Attachment sync failed; retrying.")
            self.assertEqual(
                [event.get("source") for event in events],
                ["worker_attachment", "worker_attachment", None],
            )
            self.assertNotIn("private diagnostic", json.dumps(events))

        legacy = {
            "protocol": EXCHANGE_PROTOCOL, "job_id": JOB_ID, "sequence": 1,
            "kind": "activity", "created_at": 1.0, "phase": "attachment_added",
            "summary": "1 new attachment(s) available in attachments/",
        }
        for changed in (
            {"summary": "unexpected attachment"},
            {"tool": "shell"},
            {"command": "untrusted extra field"},
            {"phase": "other_legacy_phase"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ExchangeError):
                _validate_event(
                    _normalize_legacy_attachment_activity({**legacy, **changed}), JOB_ID, 1
                )

    def test_live_attachment_events_do_not_block_following_worker_events(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            active = Path(temp)
            source = active / "incoming"
            destination = active / "scratch" / "attachments"
            source.mkdir()
            destination.parent.mkdir()
            (source / "live-test_fixture.bin").write_bytes(b"fixture")
            writer = EventWriter(active, JOB_ID)

            async def collect_one_event(expected_sequence):
                watcher = asyncio.create_task(
                    _watch_live_attachments(source, destination, None, writer)
                )
                try:
                    async def wait_for_event():
                        while writer.sequence < expected_sequence:
                            if watcher.done():
                                await watcher
                            await asyncio.sleep(0.01)
                    await asyncio.wait_for(wait_for_event(), timeout=2)
                finally:
                    watcher.cancel()
                    await asyncio.gather(watcher, return_exceptions=True)

            asyncio.run(collect_one_event(1))
            self.assertEqual((destination / "live-test_fixture.bin").read_bytes(), b"fixture")
            with patch(
                "ctf_agent.solver_worker._install_live_attachments",
                side_effect=ValueError("temporary attachment error\x00" + "x" * 800),
            ):
                asyncio.run(collect_one_event(2))
            records = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((active / "events").glob("*.json"))
            ]
            self.assertEqual([event["tool"] for event in records[:2]], ["file", "file"])
            self.assertEqual([event["phase"] for event in records[:2]], ["completed", "completed"])
            self.assertEqual([event["exit_code"] for event in records[:2]], [0, 1])
            self.assertEqual([event["source"] for event in records[:2]], ["worker_attachment"] * 2)
            self.assertLessEqual(len(records[1]["summary"].encode("utf-8")), 400)
            self.assertNotIn("\x00", records[1]["summary"])

            db_path = active / "ledger.sqlite3"
            create_job_db(db_path)
            coordinator = make_coordinator(db_path)
            coordinator.deliver_global_hooks = False
            job = {"id": JOB_ID, "workspace_id": "workspace-1", "challenge_id": "challenge-1", "last_event_sequence": 0}
            self.assertTrue(coordinator._ingest_events(job, active))
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                self.assertEqual(
                    db.execute("SELECT last_event_sequence FROM solver_jobs WHERE id=?", (JOB_ID,)).fetchone()[0],
                    2,
                )
                self.assertIsNone(db.execute(
                    "SELECT first_activity_at FROM solver_jobs WHERE id=?", (JOB_ID,)
                ).fetchone()[0])

    def test_provider_file_activity_still_sets_first_activity(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            db_path = Path(temp) / "ledger.sqlite3"
            create_job_db(db_path)
            coordinator = make_coordinator(db_path)
            coordinator.deliver_global_hooks = False
            worker = {
                "protocol": EXCHANGE_PROTOCOL, "job_id": JOB_ID, "sequence": 1,
                "kind": "activity", "created_at": 1.0, "phase": "completed",
                "tool": "file", "summary": "1 new attachment(s) available in attachments/",
                "exit_code": 0, "source": "worker_attachment",
            }
            provider = {
                "protocol": EXCHANGE_PROTOCOL, "job_id": JOB_ID, "sequence": 2,
                "kind": "activity", "created_at": 2.0, "phase": "completed",
                "tool": "file", "summary": "Read challenge source",
                "exit_code": 0,
            }
            job = {"id": JOB_ID, "workspace_id": "workspace-1", "challenge_id": "challenge-1"}
            coordinator._commit_event(job, _validate_event(worker, JOB_ID, 1))
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                self.assertIsNone(db.execute(
                    "SELECT first_activity_at FROM solver_jobs WHERE id=?", (JOB_ID,)
                ).fetchone()[0])
            coordinator._commit_event(job, _validate_event(provider, JOB_ID, 2))
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                self.assertIsNotNone(db.execute(
                    "SELECT first_activity_at FROM solver_jobs WHERE id=?", (JOB_ID,)
                ).fetchone()[0])
            for changed in (
                {"summary": "Read challenge source"},
                {"tool": "shell"},
                {"command": "cat challenge.txt"},
                {"exit_code": 2},
            ):
                with self.subTest(changed=changed), self.assertRaises(ExchangeError):
                    _validate_event({**worker, **changed}, JOB_ID, 1)

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

    def test_timing_observers_fire_once_without_changing_sampled_activity(self):
        live = []
        timings = []

        async def record(**details):
            live.append(details)

        driver = make_driver(reporter=record, activity_count=MAX_LIVE_ACTIVITY_EVENTS)
        driver.first_model_text_reporter = lambda: timings.append("model")
        driver.first_tool_result_reporter = lambda: timings.append("tool")
        driver._note_first_model_text("  ")
        driver._note_first_model_text("child", root=False)
        self.assertEqual(timings, [])
        driver._note_first_model_text("root response")
        driver._note_first_model_text("another response")

        async def run():
            await driver._report_activity(
                "completed", "shell", "Unpaired", output="ignored",
                activity_id="orphan",
            )
            await driver._report_activity(
                "started", "shell", "Started", activity_id="root-tool",
            )
            await driver._report_activity(
                "started", "web_search", "Search started", activity_id="root-search",
            )
            await driver._report_activity(
                "completed", "web_search", "Search completed", activity_id="root-search",
            )
            driver.agent_nodes["child"] = {}
            await driver._report_activity(
                "completed", "shell", "Child result", output="ignored",
                agent_id="child", activity_id="root-tool",
            )
            await driver._report_activity(
                "completed", "shell", "Done", output="secret",
                activity_id="root-tool",
            )
            await driver._report_activity(
                "completed", "shell", "Done again", activity_id="root-tool",
            )

        asyncio.run(run())
        self.assertEqual(timings, ["model", "tool"])
        self.assertEqual(live, [])

    def test_codex_notification_path_observes_only_root_paired_result(self):
        timings = []

        async def run():
            driver = CodexAppServer(Path("."), Path("."), command_prefix=["codex"])
            driver.first_model_text_reporter = lambda: timings.append("model")
            driver.first_tool_result_reporter = lambda: timings.append("tool")
            driver.thread_agents["child-thread"] = "child"
            driver.agent_nodes["child"] = {}

            async def thread(_manifest):
                return "root-thread"

            async def request(method, _params):
                self.assertEqual(method, "turn/start")
                return {"turn": {"id": "turn-1"}}

            async def progress(_code):
                pass

            driver._thread = thread
            driver.request = request
            driver._sandbox_parameters = lambda *_args, **_kwargs: {}
            for method, source, item in (
                ("item/started", "child-thread", {"id": "child-tool", "type": "commandExecution", "command": "echo child"}),
                ("item/completed", "child-thread", {"id": "child-tool", "type": "commandExecution", "aggregatedOutput": "child output"}),
                ("item/completed", "root-thread", {"id": "orphan", "type": "commandExecution", "aggregatedOutput": "orphan output"}),
                ("item/started", "root-thread", {"id": "root-search", "type": "webSearch", "query": "fixture"}),
                ("item/completed", "root-thread", {"id": "root-search", "type": "webSearch", "query": "fixture"}),
                ("item/completed", "root-thread", {"id": "root-text", "type": "agentMessage", "text": "root response"}),
                ("item/started", "root-thread", {"id": "root-tool", "type": "commandExecution", "command": "echo root"}),
                ("item/completed", "root-thread", {"id": "root-tool", "type": "commandExecution", "aggregatedOutput": "root output"}),
            ):
                driver.notifications.put_nowait({
                    "method": method,
                    "params": {"threadId": source, "item": item},
                })
            driver.notifications.put_nowait({
                "method": "turn/completed",
                "params": {"threadId": "root-thread", "turn": {"id": "turn-1", "status": "completed"}},
            })
            manifest = SimpleNamespace(
                configuration=SimpleNamespace(
                    model="gpt-6-sol", reasoning_effort="medium", service_tier=None,
                ),
                job_mode="solve", network_enabled=True,
            )
            self.assertEqual(
                await driver._turn(manifest, "fixture prompt", None, asyncio.Event(), progress),
                {},
            )

        asyncio.run(run())
        self.assertEqual(timings, ["model", "tool"])

    def test_claude_stream_path_observes_only_root_paired_result(self):
        timings = []

        async def run():
            configuration = SimpleNamespace(
                model="claude-sonnet-4-6", reasoning_effort="high", ultracode=False,
            )
            driver = ClaudePrintDriver(
                Path("."), Path("."), configuration, command_prefix=["claude"],
            )
            driver.session_id = "session-root"
            driver.tool_agents["parent-agent-tool"] = "child"
            driver.agent_nodes["child"] = {"parent_id": "root", "label": "child"}
            driver.first_model_text_reporter = lambda: timings.append("model")
            driver.first_tool_result_reporter = lambda: timings.append("tool")
            manifest = SimpleNamespace(
                configuration=configuration,
                job_mode="solve",
            )
            events = [
                {
                    "type": "system", "subtype": "init", "session_id": "session-root",
                    "model": manifest.configuration.model, "effort": "high",
                    "claude_code_version": driver.expected_version,
                    "permissionMode": "dontAsk", "slash_commands": [],
                    "tools": [*driver.ALLOWED_TOOLS, "StructuredOutput"], "mcp_servers": [],
                },
                {
                    "type": "assistant", "session_id": "session-root",
                    "parent_tool_use_id": "parent-agent-tool",
                    "message": {"content": [{"type": "tool_use", "id": "child-tool",
                                            "name": "Bash", "input": {"command": "echo child"}}]},
                },
                {
                    "type": "user", "session_id": "session-root",
                    "parent_tool_use_id": "parent-agent-tool",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "child-tool",
                                            "content": "child output"}]},
                },
                {
                    "type": "user", "session_id": "session-root",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "orphan",
                                            "content": "orphan output"}]},
                },
                {
                    "type": "assistant", "session_id": "session-root",
                    "message": {"content": [{"type": "tool_use", "id": "root-read",
                                            "name": "Read", "input": {}}]},
                },
                {
                    "type": "user", "session_id": "session-root",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "root-read",
                                            "content": ""}]},
                },
                {
                    "type": "assistant", "session_id": "session-root",
                    "message": {"content": [{"type": "text", "text": "root response"}]},
                },
                {
                    "type": "assistant", "session_id": "session-root",
                    "message": {"content": [{"type": "tool_use", "id": "root-tool",
                                            "name": "Bash", "input": {"command": "echo root"}}]},
                },
                {
                    "type": "user", "session_id": "session-root",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "root-tool",
                                            "content": "root output"}]},
                },
                {
                    "type": "result", "session_id": "session-root", "subtype": "success",
                    "is_error": False, "result": "",
                    "structured_output": {"flag": "test{fixture}", "private_notes": ""},
                },
            ]
            reader = asyncio.StreamReader()
            for event in events:
                reader.feed_data((json.dumps(event) + "\n").encode("utf-8"))
            reader.feed_eof()

            class FakeProcess:
                stdout = reader
                returncode = 0

                async def wait(self):
                    return self.returncode

            async def progress(_code):
                pass

            self.assertEqual(
                (await driver._read_stream(FakeProcess(), manifest, progress))["flag"],
                "test{fixture}",
            )

        asyncio.run(run())
        self.assertEqual(timings, ["model", "tool"])

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
