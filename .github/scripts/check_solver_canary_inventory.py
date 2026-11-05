"""Regression checks for atomic worker status updates during sandbox canaries."""

from __future__ import annotations

import asyncio
import ast
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_worker import (  # noqa: E402
    CodexAppServer,
    SolverWorker,
    WorkerRefusal,
    assert_runtime_exchange_inventory,
)


def command_canary_inventory_safe(exchange: Path) -> bool:
    """Exercise the exact embedded command-sandbox inventory expression."""

    method = ast.parse("class _:\n" + inspect.getsource(CodexAppServer.sandbox_canary))
    script = next(
        node.value.value
        for node in ast.walk(method)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "script" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )
    start = script.index("try:\n    exchange_names=os.listdir(exchange)")
    end = script.index("try:\n    profile=open", start)
    namespace = {"os": os, "exchange": str(exchange), "result": {}}
    exec(script[start:end], namespace)  # noqa: S102 - embedded, pinned canary code
    return namespace["result"]["exchange_inventory_safe"]


class SolverCanaryInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.exchange = Path(self.temp.name) / "exchange"
        self.exchange.mkdir()
        self.active = self.exchange / "active"
        self.active.mkdir()
        self.worker = SolverWorker(exchange=self.exchange)

    def test_heartbeat_status_temp_stays_inside_active_during_canary(self) -> None:
        observed = []
        real_replace = os.replace
        worker = self.worker

        def inspect_replace(source: Path, destination: Path) -> None:
            source = Path(source)
            destination = Path(destination)
            observed.append(source)
            self.assertEqual(source.parent, self.active)
            self.assertEqual(destination, self.exchange / "worker.json")
            self.assertTrue(source.is_file())
            self.assertEqual(
                {entry.name for entry in self.exchange.iterdir()},
                {"active"},
            )
            # The strict startup gate must pass at the exact instant the
            # heartbeat's temporary status file exists.
            assert_runtime_exchange_inventory(self.exchange)
            self.assertTrue(command_canary_inventory_safe(self.exchange))
            real_replace(source, destination)

        class Canary:
            async def sandbox_canary(self, *_args) -> None:
                worker._publish_worker()

        with patch("ctf_agent.solver_worker.os.replace", side_effect=inspect_replace):
            asyncio.run(self.worker._verify_sandbox_canary(Canary(), self.active, self.active))
        self.assertEqual(len(observed), 1)
        self.assertFalse(self.worker._canary_in_progress)
        self.assertEqual({entry.name for entry in self.exchange.iterdir()}, {"active", "worker.json"})
        self.assertEqual(json.loads((self.exchange / "worker.json").read_text())["sandbox_canary"], False)

    def test_normal_status_publication_remains_atomic(self) -> None:
        observed = []
        real_replace = os.replace

        def inspect_replace(source: Path, destination: Path) -> None:
            observed.append(Path(source))
            self.assertEqual(Path(source).parent, self.exchange)
            real_replace(source, destination)

        with patch("ctf_agent.solver_worker.os.replace", side_effect=inspect_replace):
            self.worker._publish_worker()
        self.assertEqual(len(observed), 1)
        self.assertEqual({entry.name for entry in self.exchange.iterdir()}, {"active", "worker.json"})

    def test_unknown_top_level_artifact_is_rejected_without_retry(self) -> None:
        (self.exchange / "unexpected-staged-file").write_text("untrusted", encoding="utf-8")
        self.assertFalse(command_canary_inventory_safe(self.exchange))
        calls = 0
        exchange = self.exchange

        class Canary:
            async def sandbox_canary(self, *_args) -> None:
                nonlocal calls
                calls += 1
                assert_runtime_exchange_inventory(exchange)

        with self.assertRaises(WorkerRefusal) as raised:
            asyncio.run(self.worker._verify_sandbox_canary(Canary(), self.active, self.active))
        self.assertEqual(raised.exception.error.code, "invalid_exchange_inventory")
        self.assertEqual(calls, 1)
        self.assertFalse(self.worker._canary_in_progress)

    def test_missing_active_during_canary_fails_closed(self) -> None:
        self.active.rmdir()
        self.worker._canary_in_progress = True
        with self.assertRaises(WorkerRefusal) as raised:
            self.worker._publish_worker()
        self.assertEqual(raised.exception.error.code, "invalid_exchange_inventory")
        self.assertFalse((self.exchange / "worker.json").exists())

    def test_inventory_failure_cannot_pass_on_second_attempt(self) -> None:
        calls = 0

        class Canary:
            async def sandbox_canary(self, *_args) -> None:
                nonlocal calls
                calls += 1
                raise WorkerRefusal(
                    "sandbox_canary_failed", "unexpected top-level artifact",
                    requirements=("exchange_inventory_safe",),
                )

        with self.assertRaises(WorkerRefusal) as raised:
            asyncio.run(self.worker._verify_sandbox_canary(Canary(), self.active, self.active))
        self.assertEqual(raised.exception.error.requirements, ("exchange_inventory_safe",))
        self.assertEqual(calls, 1)
        self.assertFalse(self.worker._canary_in_progress)


if __name__ == "__main__":
    unittest.main()
