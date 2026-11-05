"""Check bounded diagnostics for interrupted provider and startup canary paths."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver import normalize_provider_failure  # noqa: E402
from ctf_agent.solver_worker import (  # noqa: E402
    AppServerFailure,
    CodexAppServer,
    PlatformAttestation,
    SolverWorker,
)


class SolverFailureDiagnosticTests(unittest.TestCase):
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
