"""Provider context observations stay separate from account and billing usage."""

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

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.solver_exchange import (  # noqa: E402
    ExchangeError,
    SCHEMA,
    SolverExchangeCoordinator,
    _validate_event,
)
from ctf_agent.solver_worker import (  # noqa: E402
    EventWriter,
    MAX_LIVE_CONTEXT_EVENTS,
    _claude_context_sample,
    _claude_context_windows,
    _codex_context_sample,
    _emit_context_usage,
)


JOB_ID = "a" * 32


def make_coordinator(path: Path) -> SolverExchangeCoordinator:
    coordinator = object.__new__(SolverExchangeCoordinator)
    coordinator.database_path = path
    coordinator.clock = time.time
    return coordinator


def create_db(path: Path) -> None:
    with contextlib.closing(sqlite3.connect(path)) as db, db:
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
            (JOB_ID, "owner-1", "workspace-1", "challenge-1", "account-1",
             "codex", "model", "high", "running", 1, 1),
        )


class ContextUsageTests(unittest.TestCase):
    def test_codex_uses_last_response_and_actual_window(self):
        payload = {
            "tokenUsage": {
                "total": {"totalTokens": 1_200_000},
                "last": {"totalTokens": 52_000},
                "modelContextWindow": 200_000,
            },
            "rateLimits": {"primary": {"usedPercent": 80}},
        }
        self.assertEqual(_codex_context_sample(payload), (52_000, 200_000))
        for token_usage in (
            {"total": {"totalTokens": 52_000}, "modelContextWindow": 200_000},
            {"last": {"totalTokens": 52_000}, "modelContextWindow": None},
            {"last": {"totalTokens": 201_000}, "modelContextWindow": 200_000},
            {"last": {"totalTokens": True}, "modelContextWindow": 200_000},
        ):
            self.assertIsNone(_codex_context_sample({"tokenUsage": token_usage}))

    def test_claude_uses_latest_request_not_cumulative_model_usage(self):
        sample = _claude_context_sample({
            "model": "claude-opus-5",
            "usage": {
                "input_tokens": 1_000,
                "cache_creation_input_tokens": 2_000,
                "cache_read_input_tokens": 37_000,
                "output_tokens": 600,
            },
        })
        self.assertEqual(sample, ("claude-opus-5", 40_000))
        self.assertEqual(_claude_context_windows({
            "modelUsage": {
                "claude-opus-5": {"inputTokens": 900_000, "contextWindow": 200_000},
            },
        }), {"claude-opus-5": 200_000})
        self.assertIsNone(_claude_context_sample({"model": "x", "usage": {"input_tokens": -1}}))
        self.assertIsNone(_claude_context_sample({"model": "x", "usage": {}}))
        self.assertIsNone(_claude_context_sample({
            "model": "x", "usage": {"input_tokens": 900_000_000,
                                    "cache_read_input_tokens": 900_000_000},
        }))
        self.assertEqual(_claude_context_windows({"modelUsage": {"x": {"contextWindow": None}}}), {})

    def test_duplicate_observations_and_compaction_clear_values(self):
        class Driver:
            context_events = 0
            context_snapshots = {}
            context_last_emit_at = {}
            context_budget_closed = False
            agent_nodes = {}

        driver = Driver()
        events = []

        async def reporter(**payload):
            events.append(payload)

        driver.context_reporter = reporter

        async def run():
            await _emit_context_usage(driver, "root", "available", "codex_last_response", 10, 100)
            await _emit_context_usage(driver, "root", "available", "codex_last_response", 10, 100)
            await _emit_context_usage(driver, "root", "compacting", "codex_last_response")
            await _emit_context_usage(driver, "root", "awaiting_usage", "codex_last_response")
            await _emit_context_usage(driver, "missing-child", "available", "codex_last_response", 1, 100)
            await _emit_context_usage(driver, "root", "available", "codex_last_response", 5, 100,
                                      observed_at=123.5)

        asyncio.run(run())
        self.assertEqual([item["state"] for item in events],
                         ["available", "compacting", "awaiting_usage", "available"])
        self.assertEqual((events[2]["used_tokens"], events[2]["window_tokens"]), (None, None))
        self.assertEqual(events[-1]["used_tokens"], 5)
        self.assertTrue(all(isinstance(item["observed_at"], float) for item in events))
        self.assertEqual(events[-1]["observed_at"], 123.5)

        driver.agent_nodes = {"codex_child": {"status": "running"}}
        driver.context_snapshots["codex_child"] = (
            "available", "codex_last_response", 50, 100,
        )
        driver.context_events = MAX_LIVE_CONTEXT_EVENTS
        asyncio.run(_emit_context_usage(
            driver, "root", "available", "codex_last_response", 60, 100,
        ))
        self.assertEqual([item["agent_id"] for item in events[-2:]], ["root", "codex_child"])
        self.assertTrue(all(item["state"] == "unavailable" for item in events[-2:]))
        self.assertTrue(all(item["used_tokens"] is None for item in events[-2:]))
        prior_count = len(events)
        asyncio.run(_emit_context_usage(
            driver, "root", "available", "codex_last_response", 70, 100,
        ))
        self.assertEqual(len(events), prior_count)

    def test_exchange_is_owner_scoped_and_preserves_per_agent_snapshots(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            base = Path(temp)
            path = base / "ledger.sqlite3"
            create_db(path)
            coordinator = make_coordinator(path)
            job = {"id": JOB_ID, "workspace_id": "workspace-1", "challenge_id": "challenge-1"}
            writer = EventWriter(base, JOB_ID)
            unknown = coordinator.get(JOB_ID, "owner-1")["context_usage"][0]
            self.assertEqual(unknown["state"], "unavailable")
            self.assertIsNone(unknown["percent"])
            self.assertIsNone(unknown["observed_at"])

            def commit(kind: str, **payload):
                event = writer.emit(kind, **payload)
                _validate_event(event, JOB_ID, event["sequence"])
                coordinator._commit_event(job, event)
                return event

            commit("context_usage", agent_id="root", state="available",
                   source="codex_last_response", used_tokens=50_000,
                   window_tokens=200_000, observed_at=time.time())
            commit("agent", agent_id="codex_child", parent_id="root",
                   label="Child", status="running", provider="codex")
            commit("context_usage", agent_id="codex_child", state="available",
                   source="codex_last_response", used_tokens=20_000,
                   window_tokens=100_000, observed_at=time.time())
            page = coordinator.get(JOB_ID, "owner-1")
            self.assertEqual([(item["agent_id"], item["percent"]) for item in page["context_usage"]],
                             [("root", 25.0), ("codex_child", 20.0)])
            with self.assertRaises(ExchangeError):
                coordinator.get(JOB_ID, "other-owner")

            commit("context_usage", agent_id="root", state="awaiting_usage",
                   source="codex_last_response", used_tokens=None,
                   window_tokens=None, observed_at=time.time())
            root = coordinator.get(JOB_ID, "owner-1")["context_usage"][0]
            self.assertEqual(root["state"], "awaiting_usage")
            self.assertIsNone(root["percent"])
            self.assertIsNone(root["used_tokens"])
            self.assertEqual(coordinator.get(JOB_ID, "owner-1")["context_usage"][1]["percent"], 20.0)

    def test_invalid_context_events_are_rejected(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            writer = EventWriter(Path(temp), JOB_ID)
            valid = writer.emit("context_usage", agent_id="root", state="available",
                                source="codex_last_response", used_tokens=20,
                                window_tokens=100, observed_at=time.time())
            self.assertEqual(_validate_event(valid, JOB_ID, 1), valid)
            for invalid in (
                {"used_tokens": True}, {"window_tokens": 0}, {"used_tokens": 200},
                {"source": "account_quota"}, {"observed_at": float("nan")},
                {"state": "awaiting_usage"}, {"agent_id": "raw/provider/id"},
            ):
                with self.subTest(invalid=invalid), self.assertRaises(ExchangeError):
                    _validate_event({**valid, **invalid}, JOB_ID, 1)


if __name__ == "__main__":
    unittest.main()
