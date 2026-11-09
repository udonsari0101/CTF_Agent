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
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent import solver_worker as worker  # noqa: E402
from ctf_agent.solver import ModelConfiguration  # noqa: E402
from ctf_agent.request_remote import record_request  # noqa: E402


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

    def test_ultra_limits_concurrent_children_without_disabling_delegation(self) -> None:
        self.driver.command_prefix = ["codex"]
        self.driver.configuration = ModelConfiguration("codex", "gpt-6-sol", "ultra")
        with (
            patch.object(worker, "CODEX_ULTRA_MAX_SUBAGENTS", 2),
            patch.object(self.driver, "_uses_local_permissions", return_value=False),
        ):
            arguments = self.driver.command_arguments()
        self.assertIn("agents.max_concurrent_threads_per_session=2", arguments)
        self.assertEqual(arguments[arguments.index("multi_agent") - 1], "--enable")

        self.driver.configuration = ModelConfiguration("codex", "gpt-6-sol", "xhigh")
        with patch.object(self.driver, "_uses_local_permissions", return_value=False):
            arguments = self.driver.command_arguments()
        self.assertNotIn("agents.max_concurrent_threads_per_session=2", arguments)
        self.assertEqual(arguments[arguments.index("multi_agent") - 1], "--disable")

    def test_ultra_thread_start_uses_the_same_child_limit_as_launch(self) -> None:
        self.driver.thread_id = None
        self.driver.resume_thread_id = None
        self.driver.challenge = self.challenge
        self.driver.rate_limit_context = None
        self.manifest.configuration = ModelConfiguration("codex", "gpt-6-sol", "ultra")
        request = AsyncMock(return_value={"thread": {"id": "new-thread"}})
        with (
            patch.object(worker, "CODEX_ULTRA_MAX_SUBAGENTS", 2),
            patch.object(self.driver, "_provider_model", return_value="gpt-6-sol"),
            patch.object(self.driver, "_sandbox_parameters", return_value={}),
        ):
            self.driver.request = request
            self.assertEqual(asyncio.run(self.driver._thread(self.manifest)), "new-thread")
        params = request.await_args.args[1]
        self.assertEqual(params["config"]["agents"], {
            "enabled": True,
            "max_concurrent_threads_per_session": 2,
        })

    def test_offline_remote_request_gets_one_same_session_review(self) -> None:
        self.manifest.remote_mode = "none"
        self.driver.thread_id = "existing-thread"
        self.driver.remote_request_reviewed = asyncio.Event()
        prompts: list[str] = []

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            prompts.append(prompt)
            if len(prompts) == 1:
                record_request("A local emulator lacks a device.", self.challenge)
                return {}
            self.assertTrue(self.driver.remote_request_reviewed.is_set())
            self.assertFalse((self.challenge / ".remote-request").exists())
            return {"flag": "CTF{verified}"}

        result, error = self._run(turn, nudges=0)
        self.assertIsNone(error)
        self.assertEqual(result["flag"], "CTF{verified}")
        self.assertEqual(len(prompts), 2)
        self.assertIn("provisional", prompts[1])

    def test_second_offline_remote_request_stops_the_watcher(self) -> None:
        async def scenario() -> tuple[bool, bool, str]:
            requested, cancelled, reviewed = asyncio.Event(), asyncio.Event(), asyncio.Event()
            result: dict[str, object] = {}
            request_path = self.challenge / ".remote-request"
            watcher = asyncio.create_task(worker._watch_remote_request(
                request_path, requested, cancelled, result, reviewed,
            ))
            try:
                record_request("First unverified request", self.challenge)
                await asyncio.sleep(0.06)
                self.assertFalse(requested.is_set())
                request_path.unlink()
                reviewed.set()
                record_request("Verified missing endpoint", self.challenge)
                await asyncio.wait_for(requested.wait(), 1)
                await watcher
                return requested.is_set(), cancelled.is_set(), result["note"]
            finally:
                watcher.cancel()

        self.assertEqual(
            asyncio.run(scenario()),
            (True, True, "Verified missing endpoint"),
        )

    def test_offline_remote_confirmation_reaches_terminal_handoff(self) -> None:
        async def scenario() -> tuple[int, str]:
            self.manifest.remote_mode = "none"
            self.driver.remote_request_reviewed = asyncio.Event()
            requested, cancelled = asyncio.Event(), asyncio.Event()
            result: dict[str, object] = {}
            watcher = asyncio.create_task(worker._watch_remote_request(
                self.challenge / ".remote-request",
                requested, cancelled, result, self.driver.remote_request_reviewed,
            ))
            calls = 0

            async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
                nonlocal calls
                calls += 1
                record_request(f"Missing endpoint check {calls}", self.challenge)
                if calls == 1:
                    return {}
                await cancelled.wait()
                raise asyncio.CancelledError

            self.driver._turn = turn
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(self.driver.run_discovery(
                        self.manifest, self.challenge, cancelled, self._progress,
                    ), 2)
                self.assertTrue(requested.is_set())
                return calls, result["note"]
            finally:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)

        self.assertEqual(asyncio.run(scenario()), (2, "Missing endpoint check 2"))

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

    def test_transient_provider_failure_resumes_once_in_same_thread(self) -> None:
        self.driver.thread_id = "existing-thread"
        prompts: list[str] = []

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            prompts.append(prompt)
            if len(prompts) == 1:
                self.driver._solve_tool_count += 1
                raise worker.AppServerFailure({"code": "provider_error"})
            return {"flag": "CTF{verified}"}

        result, error = self._run(turn, nudges=0)
        self.assertIsNone(error)
        self.assertEqual(result["flag"], "CTF{verified}")
        self.assertEqual(len(prompts), 2)
        self.assertIn("existing session", prompts[1])
        self.assertEqual(self.progress_codes.count("provider_retrying"), 1)

    def test_verified_handoff_survives_failed_final_turn(self) -> None:
        self.driver.thread_id = "existing-thread"
        calls = 0

        async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
            nonlocal calls
            calls += 1
            candidate_path = self.challenge / ".flag-candidate"
            candidate_path.write_text("CTF{verified}", encoding="utf-8")
            candidate_path.chmod(0o600)
            (self.challenge / "notes" / "ANALYSIS.md").write_text(
                "The candidate was checked against the supplied artifact.", encoding="utf-8",
            )
            raise worker.AppServerFailure({"code": "provider_error"})

        result, error = self._run(turn, nudges=0)
        self.assertIsNone(error)
        self.assertEqual(result["flag"], "CTF{verified}")
        self.assertIn("supplied artifact", result["private_notes"])
        self.assertEqual(calls, 1)

    def test_transient_resume_is_bounded_and_requires_work(self) -> None:
        self.driver.thread_id = "existing-thread"
        for has_work in (False, True):
            with self.subTest(has_work=has_work):
                calls = 0

                async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
                    nonlocal calls
                    calls += 1
                    if has_work:
                        self.driver._solve_tool_count += 1
                    raise worker.AppServerFailure({"code": "provider_error"})

                self.driver._turn = turn
                with patch.object(worker, "MAX_SOLVE_NUDGES", 0):
                    with self.assertRaises(worker.AppServerFailure):
                        asyncio.run(self.driver.run_discovery(
                            self.manifest, self.challenge, asyncio.Event(), self._progress,
                        ))
                self.assertEqual(calls, 2 if has_work else 1)

    def test_quota_and_auth_failures_never_auto_resume(self) -> None:
        self.driver.thread_id = "existing-thread"
        for payload in (
            {"codexErrorInfo": "usageLimitExceeded"},
            {"code": "auth_required"},
            {"codexErrorInfo": "cyberPolicy"},
            {"code": "provider_error", "retryable": False},
        ):
            with self.subTest(payload=payload):
                calls = 0

                async def turn(_manifest, _prompt, _schema, _cancelled, _progress):
                    nonlocal calls
                    calls += 1
                    self.driver._solve_tool_count += 1
                    raise worker.AppServerFailure(payload)

                self.driver._turn = turn
                with patch.object(worker, "MAX_SOLVE_NUDGES", 0):
                    with self.assertRaises(worker.AppServerFailure):
                        asyncio.run(self.driver.run_discovery(
                            self.manifest, self.challenge, asyncio.Event(), self._progress,
                        ))
                self.assertEqual(calls, 1)

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
