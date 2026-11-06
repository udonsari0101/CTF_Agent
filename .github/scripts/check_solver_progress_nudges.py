"""Offline regression for bounded, evidence-gated solve continuation."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent import solver_worker as worker  # noqa: E402
from ctf_agent.solver import ModelConfiguration  # noqa: E402


class ProgressNudgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.challenge = Path(self.temporary.name)
        (self.challenge / "notes").mkdir()
        self.driver = object.__new__(worker.CodexAppServer)
        self.driver.structured_discovery = False
        self.manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-6-sol", "high"),
            remote_mode="none",
            remote="",
            retry_checkpoint=None,
            max_reasoning_available=False,
            ultra_escalation_mode="off",
        )
        self.progress_codes: list[str] = []

    async def _progress(self, code: str, **_details: object) -> None:
        self.progress_codes.append(code)

    def _run(self, turn, *, nudges: int = 1, extra: int = 2) -> tuple[dict[str, str] | None, str | None]:
        self.driver._turn = turn
        with (
            patch.object(worker, "MAX_SOLVE_NUDGES", nudges),
            patch.object(worker, "MAX_PROGRESS_NUDGES", extra),
        ):
            try:
                result = asyncio.run(self.driver.run_discovery(
                    self.manifest, self.challenge, asyncio.Event(), self._progress,
                ))
            except worker.WorkerRefusal as exc:
                return None, exc.error.code
        return result, None

    def test_fresh_tool_result_and_notes_allow_one_extra_turn(self) -> None:
        calls = 0

        async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.driver._solve_tool_count += 1
                (self.challenge / "notes" / "ANALYSIS.md").write_text(
                    "The local parser returned a new, reproducible value.", encoding="utf-8",
                )
            return {"flag": "CTF{verified}"} if calls == 3 else {}

        result, error = self._run(turn)
        self.assertIsNone(error)
        self.assertEqual(result["flag"], "CTF{verified}")
        self.assertEqual(calls, 3)

    def test_no_extra_turn_for_model_only_or_unrecorded_tool_work(self) -> None:
        for activity in ("none", "notes_only", "tool_only"):
            with self.subTest(activity=activity):
                (self.challenge / "notes" / "ANALYSIS.md").unlink(missing_ok=True)
                calls = 0

                async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
                    nonlocal calls
                    calls += 1
                    if calls == 2 and activity == "notes_only":
                        (self.challenge / "notes" / "ANALYSIS.md").write_text(
                            "A new observation", encoding="utf-8",
                        )
                    if calls == 2 and activity == "tool_only":
                        self.driver._solve_tool_count += 1
                    return {}

                result, error = self._run(turn)
                self.assertIsNone(result)
                self.assertEqual(error, "flag_not_submitted")
                self.assertEqual(calls, 2)

    def test_repeated_progress_stops_at_finite_extra_cap(self) -> None:
        calls = 0

        async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
            nonlocal calls
            calls += 1
            self.driver._solve_tool_count += 1
            (self.challenge / "notes" / "ANALYSIS.md").write_text(
                f"Experiment {calls}: new observed result.", encoding="utf-8",
            )
            return {}

        result, error = self._run(turn)
        self.assertIsNone(result)
        self.assertEqual(error, "flag_not_submitted")
        self.assertEqual(calls, 4)  # initial + one ordinary + two progress nudges

    def test_explicit_unlimited_setting_keeps_existing_behavior(self) -> None:
        calls = 0

        async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
            nonlocal calls
            calls += 1
            return {"flag": "CTF{verified}"} if calls == 5 else {}

        result, error = self._run(turn, nudges=0)
        self.assertIsNone(error)
        self.assertEqual(result["flag"], "CTF{verified}")
        self.assertEqual(calls, 5)

    def test_turn_count_alone_does_not_authorize_max_reasoning(self) -> None:
        self.manifest.max_reasoning_available = True
        (self.challenge / "notes" / "NEXT.md").write_text(
            "Need to inspect the available material.\nMAX_REQUIRED\n", encoding="utf-8",
        )
        calls = 0

        async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
            nonlocal calls
            calls += 1
            return {}

        result, error = self._run(turn)
        self.assertIsNone(result)
        self.assertEqual(error, "flag_not_submitted")
        self.assertEqual(calls, 2)
        self.assertNotIn("reasoning_escalated", self.progress_codes)
        self.assertIn("MAX_REQUIRED", (self.challenge / "notes" / "NEXT.md").read_text())

    def test_completed_tool_still_allows_documented_max_request(self) -> None:
        @dataclass(frozen=True)
        class Manifest:
            configuration: ModelConfiguration
            remote_mode: str = "none"
            remote: str = ""
            retry_checkpoint: object = None
            max_reasoning_available: bool = True
            ultra_escalation_mode: str = "off"

        self.manifest = Manifest(ModelConfiguration("codex", "gpt-6-sol", "high"))
        efforts: list[str] = []

        async def turn(manifest, _prompt, _schema, _cancelled, _progress):
            efforts.append(manifest.configuration.reasoning_effort)
            if len(efforts) == 1:
                self.driver._solve_tool_count += 1
                (self.challenge / "notes" / "NEXT.md").write_text(
                    "The parser returned a reproducible mismatch; next test a wider search.\n"
                    "MAX_REQUIRED\n", encoding="utf-8",
                )
                return {}
            return {"flag": "CTF{verified}"}

        result, error = self._run(turn)
        self.assertIsNone(error)
        self.assertEqual(result["flag"], "CTF{verified}")
        self.assertEqual(efforts, ["high", "max"])
        self.assertEqual(self.progress_codes.count("reasoning_escalated"), 1)
        self.assertNotIn("MAX_REQUIRED", (self.challenge / "notes" / "NEXT.md").read_text())

    def test_claude_counts_only_paired_root_tool_results(self) -> None:
        async def run() -> int:
            configuration = SimpleNamespace(
                model="claude-sonnet-4-6", reasoning_effort="high", ultracode=False,
            )
            driver = worker.ClaudePrintDriver(
                self.challenge, self.challenge, configuration, command_prefix=["claude"],
            )
            driver.session_id = "root-session"
            manifest = SimpleNamespace(configuration=configuration, job_mode="solve")
            events = [
                {
                    "type": "system", "subtype": "init", "session_id": "root-session",
                    "model": configuration.model, "effort": "high",
                    "claude_code_version": driver.expected_version,
                    "permissionMode": "dontAsk", "slash_commands": [],
                    "tools": [*driver.ALLOWED_TOOLS, "StructuredOutput"], "mcp_servers": [],
                },
                {
                    "type": "user", "session_id": "root-session",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "orphan"}]},
                },
                {
                    "type": "assistant", "session_id": "root-session",
                    "message": {"content": [{"type": "tool_use", "id": "read-1",
                                            "name": "Read", "input": {}}]},
                },
                {
                    "type": "user", "session_id": "root-session",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "read-1",
                                            "content": "observed data"}]},
                },
                {
                    "type": "result", "session_id": "root-session", "subtype": "success",
                    "is_error": False, "result": "",
                    "structured_output": {"flag": "", "private_notes": ""},
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

            await driver._read_stream(FakeProcess(), manifest, self._progress)
            return driver._solve_tool_count

        self.assertEqual(asyncio.run(run()), 1)


if __name__ == "__main__":
    unittest.main()
