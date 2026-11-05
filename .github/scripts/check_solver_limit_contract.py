"""The web and isolated worker must agree before claiming a timed job."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_exchange import ExchangeError, SolverExchangeCoordinator  # noqa: E402
from ctf_agent.solver_worker import PlatformAttestation, SolverWorker  # noqa: E402


class SolverLimitContractTests(unittest.TestCase):
    def test_compose_passes_one_limit_to_web_and_every_worker(self) -> None:
        env = dict(os.environ)
        env["CTF_SOLVER_MAX_SECONDS"] = "1800"
        result = subprocess.run(
            ["docker", "compose", "--profile", "*", "-f", "compose.local.yaml", "config", "--format", "json"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=True,
        )
        services = json.loads(result.stdout)["services"]
        for name in ("web", "solver", *(f"solver-{i}" for i in range(2, 7))):
            with self.subTest(service=name):
                self.assertEqual(services[name]["environment"]["CTF_SOLVER_MAX_SECONDS"], "1800")

    def test_worker_publishes_limit_and_coordinator_rejects_mismatch(self) -> None:
        worker = object.__new__(SolverWorker)
        worker.attestation = PlatformAttestation(True, {})
        worker.provider_runtime_checks = {}
        worker.runtime_ready = worker.sandbox_attested = worker.clean = True
        worker.restart_required = False
        worker.instance_id = "worker-instance-123456789012"
        worker.restart_reason = worker.startup_diagnostic = None
        worker.exchange = ROOT
        published = []
        with patch("ctf_agent.solver_worker.MAX_JOB_SECONDS", 1800), patch(
            "ctf_agent.solver_worker._write_json", side_effect=lambda _path, value, **_kw: published.append(value)
        ):
            worker._publish_worker()
        self.assertEqual(published[0]["max_job_seconds"], 1800)

        coordinator = object.__new__(SolverExchangeCoordinator)
        coordinator.exchange = ROOT
        coordinator.clock = time.time
        coordinator.worker_max_age = 30
        with patch("ctf_agent.solver_exchange._read_json_file", return_value=published[0]), patch(
            "ctf_agent.solver_exchange.MAX_JOB_SECONDS", 0
        ):
            with self.assertRaises(ExchangeError) as context:
                coordinator._worker_status(require_clean=True)
        self.assertEqual(context.exception.code, "solver_limit_mismatch")
        self.assertTrue(context.exception.retryable)

    def test_legacy_or_malformed_worker_limit_is_not_accepted(self) -> None:
        coordinator = object.__new__(SolverExchangeCoordinator)
        coordinator.exchange = ROOT
        for value in ({}, {"max_job_seconds": True}, {"max_job_seconds": "0"}):
            with self.subTest(value=value), patch(
                "ctf_agent.solver_exchange._read_json_file", return_value=value
            ):
                with self.assertRaises(ExchangeError) as context:
                    coordinator._worker_status(require_clean=False)
                self.assertEqual(context.exception.code, "solver_limit_mismatch")


if __name__ == "__main__":
    unittest.main()
