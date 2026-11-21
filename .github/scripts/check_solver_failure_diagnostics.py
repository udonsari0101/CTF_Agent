"""Check bounded diagnostics for interrupted provider and startup canary paths."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver import normalize_provider_failure  # noqa: E402
from ctf_agent.solver_exchange import EXCHANGE_PROTOCOL, ExchangeError, _validate_event  # noqa: E402
from ctf_agent.solver_worker import (  # noqa: E402
    AppServerFailure,
    CodexAppServer,
    PlatformAttestation,
    SolverWorker,
    failure_with_rate_limit,
    safe_provider_failure_diagnostic,
)


class SolverFailureDiagnosticTests(unittest.TestCase):
    def test_exec_create_failures_stop_one_turn_without_leaking_output(self) -> None:
        async def scenario(items: list[dict]) -> tuple[dict | None, dict | None, int, int]:
            driver = CodexAppServer(Path("/tmp/codex-home"), Path("/tmp/challenge"))
            evidence: list[dict] = []

            async def record_evidence(**entry):
                evidence.append(entry)

            driver.evidence_reporter = record_evidence

            async def thread(_manifest):
                return "root-thread"

            async def request(method, _params):
                self.assertEqual(method, "turn/start")
                return {"turn": {"id": "turn-1"}}

            async def progress(_code):
                return None

            driver._thread = thread
            driver.request = request
            driver._sandbox_parameters = lambda *_args, **_kwargs: {}
            for item in items:
                driver.notifications.put_nowait({
                    "method": "item/completed",
                    "params": {"threadId": "root-thread", "item": item},
                })
            driver.notifications.put_nowait({
                "method": "turn/completed",
                "params": {
                    "threadId": "root-thread",
                    "turn": {"id": "turn-1", "status": "completed"},
                },
            })
            manifest = SimpleNamespace(
                configuration=SimpleNamespace(
                    model="gpt-6-sol", reasoning_effort="high", service_tier=None,
                ),
                job_mode="solve", network_enabled=True,
            )
            try:
                result = await driver._turn(
                    manifest, "fixture prompt", None, asyncio.Event(), progress,
                )
            except AppServerFailure as exc:
                return None, exc.payload, driver._solve_tool_count, len(evidence)
            return result, None, driver._solve_tool_count, len(evidence)

        launcher_error = "Failed to create unified exec process: No such file or directory (os error 2)"

        def command(identifier, output, exit_code):
            return {
                "id": identifier, "type": "commandExecution",
                "command": "printf fixture", "aggregatedOutput": output,
                "exitCode": exit_code,
            }

        result, failure, tools, evidence = asyncio.run(scenario([
            command("a", launcher_error, -1),
            command("b", launcher_error, -1),
            command("c", launcher_error, -1),
        ]))
        self.assertIsNone(result)
        self.assertEqual(failure, {"code": "codex_exec_unavailable", "retryable": False})
        self.assertEqual(tools, 0)
        self.assertEqual(evidence, 3)
        public = normalize_provider_failure(failure, stage="solve").public()
        self.assertEqual(public["code"], "codex_exec_unavailable")
        self.assertFalse(public["retryable"])
        self.assertNotIn("No such file", json.dumps(public))

        # The command itself can fail to find a file, and may print the same
        # phrase. Neither case indicates an app-server exec launcher failure.
        result, failure, tools, evidence = asyncio.run(scenario([
            command("a", launcher_error, 127),
            command("b", "cat: missing: No such file or directory", -1),
            command("c", launcher_error, -1),
        ]))
        self.assertEqual(result, {})
        self.assertIsNone(failure)
        self.assertEqual(tools, 2)
        self.assertEqual(evidence, 3)

        # Distinct consecutive failures are required; a working command
        # resets the streak, and duplicate notifications do not inflate it.
        result, failure, tools, evidence = asyncio.run(scenario([
            command("a", launcher_error, -1),
            command("a", launcher_error, -1),
            command("b", launcher_error, -1),
            command("ok", "ready", 0),
            command("c", launcher_error, -1),
            command("d", launcher_error, -1),
        ]))
        self.assertEqual(result, {})
        self.assertIsNone(failure)
        self.assertEqual(tools, 1)
        self.assertEqual(evidence, 6)

    def test_nonretryable_unknown_provider_error_stays_nonretryable(self) -> None:
        payload = failure_with_rate_limit(
            {"code": "provider_error", "retryable": False, "message": "secret"},
            None,
        )
        self.assertEqual(payload, {"code": "provider_error", "retryable": False})
        error = normalize_provider_failure(payload, stage="solve")
        self.assertFalse(error.retryable)
        self.assertNotIn("secret", json.dumps(error.public()))

    def test_provider_diagnostic_keeps_only_fixed_non_secret_fields(self) -> None:
        payload = {
            "codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 503}},
            "message": "secret-provider-text",
        }
        driver = SimpleNamespace(
            provider_failure_phase="turn_stream",
            provider_retry_events=2,
            same_session_retry_attempted=True,
            process=SimpleNamespace(returncode=1),
        )
        diagnostic = safe_provider_failure_diagnostic(payload, driver)
        error = replace(
            normalize_provider_failure(payload, stage="solve"),
            diagnostic=diagnostic,
        ).public()
        self.assertEqual(error["diagnostic"], {
            "phase": "turn_stream",
            "kind": "httpConnectionFailed",
            "http_status": 503,
            "retry_events": 2,
            "same_session_retry": True,
            "cli_exit_code": 1,
        })
        self.assertNotIn("secret-provider-text", json.dumps(error))
        event = {
            "protocol": EXCHANGE_PROTOCOL,
            "job_id": "a" * 32,
            "sequence": 1,
            "kind": "error",
            "created_at": time.time(),
            "error": error,
            "terminal": False,
        }
        self.assertEqual(_validate_event(event, "a" * 32, 1), event)
        event["error"]["diagnostic"]["message"] = "secret-provider-text"
        with self.assertRaises(ExchangeError):
            _validate_event(event, "a" * 32, 1)
        event["error"]["diagnostic"] = {"kind": []}
        with self.assertRaises(ExchangeError):
            _validate_event(event, "a" * 32, 1)

    def test_unanswered_request_records_reader_end(self) -> None:
        async def scenario() -> dict:
            driver = CodexAppServer(Path("/tmp/codex-home"), Path("/tmp/challenge"))
            stream = asyncio.StreamReader()
            stream.feed_eof()
            driver.process = SimpleNamespace(stdout=stream)
            future = asyncio.get_running_loop().create_future()
            driver.pending[1] = future
            await driver._reader()
            with self.assertRaises(AppServerFailure) as raised:
                await future
            return raised.exception.payload

        payload = asyncio.run(scenario())
        self.assertEqual(payload, {"code": "provider_stream_closed"})
        normalized = normalize_provider_failure(payload, stage="solve")
        self.assertEqual(normalized.code, "provider_stream_closed")
        self.assertTrue(normalized.retryable)

    def test_exited_app_server_is_not_labeled_provider_overload(self) -> None:
        async def scenario() -> dict:
            driver = CodexAppServer(Path("/tmp/codex-home"), Path("/tmp/challenge"))
            driver.process = SimpleNamespace(returncode=1)
            with self.assertRaises(AppServerFailure) as raised:
                await driver.request("turn/start")
            return raised.exception.payload

        self.assertEqual(asyncio.run(scenario()), {"code": "provider_stream_closed"})

    def test_unexpected_canary_exception_is_classified_without_message(self) -> None:
        async def clean(_pid: int | None) -> None:
            return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exchange, scratch = root / "exchange", root / "scratch"
            exchange.mkdir()
            scratch.mkdir()
            worker = SolverWorker(
                exchange=exchange, scratch_root=scratch,
                process_cleaner=clean, process_assertion=lambda: None,
            )
            worker.attestation = PlatformAttestation(True, {})
            with patch(
                "ctf_agent.solver_worker.prepare_agent_workspace",
                side_effect=FileNotFoundError("secret-path-should-not-appear"),
            ):
                result = asyncio.run(worker.attest_runtime())
            status = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
            self.assertFalse(result.ready)
            self.assertEqual(status["reason"], "sandbox_canary_failed")
            self.assertEqual(status["diagnostic"], "canary:workspace:FileNotFoundError")
            self.assertNotIn("secret-path", json.dumps(status))


if __name__ == "__main__":
    unittest.main()
