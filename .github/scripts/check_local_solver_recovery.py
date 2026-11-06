"""A failed local worker recovers without bypassing the database mount gate."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_worker import (  # noqa: E402
    EXCHANGE_PROTOCOL,
    EventWriter,
    JobManifest,
    PlatformAttestation,
    SolverWorker,
    main as worker_main,
)


def load_local_compose():
    path = ROOT / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_recovery_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LocalSolverRecoveryTests(unittest.TestCase):
    def test_local_policies_recover_worker_without_auto_starting_database_stack(self):
        local_compose = load_local_compose()
        for requested, expected in (("no", "on-failure:3"), ("unless-stopped", "unless-stopped")):
            with self.subTest(requested=requested):
                policy = local_compose.local_solver_restart_policy(requested)
                self.assertEqual(policy, expected)
                environment = dict(os.environ)
                environment.update(
                    CTF_LOCAL_RESTART_POLICY=requested,
                    CTF_LOCAL_SOLVER_RESTART_POLICY=policy,
                )
                result = subprocess.run(
                    ["docker", "compose", "-f", "compose.local.yaml", "--profile", "*", "config", "--format", "json"],
                    cwd=ROOT, env=environment, capture_output=True, text=True, check=True,
                )
                services = json.loads(result.stdout)["services"]
                for name in ("solver", *(f"solver-{index}" for index in range(2, 7))):
                    self.assertEqual(services[name]["restart"], expected)
                self.assertEqual(services["web"]["restart"], requested)
                self.assertEqual(services["solver-autoscaler"]["restart"], requested)
        for invalid in ("always", "on-failure", ""):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                local_compose.local_solver_restart_policy(invalid)

    def test_unexpected_worker_return_fails_and_operator_stop_succeeds(self):
        class ReturnedWorker:
            def __init__(self, stopped: bool):
                self.stopping = stopped

            async def serve(self):
                return None

        for stopped, expected in ((False, 1), (True, 0)):
            with self.subTest(stopped=stopped), patch(
                "ctf_agent.solver_worker.SolverWorker", return_value=ReturnedWorker(stopped)
            ):
                self.assertEqual(worker_main(), expected)


class WorkerFailureStatusTests(unittest.IsolatedAsyncioTestCase):
    async def test_worker_task_failure_publishes_bounded_type_only(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = SolverWorker(exchange=Path(directory))

            def prepare():
                worker.attestation = PlatformAttestation(True, {})
                return worker.attestation

            async def attest():
                worker.runtime_ready = True
                worker.sandbox_attested = True
                return worker.attestation

            async def broken_task():
                raise RuntimeError("secret-from-provider-output")

            worker.prepare = prepare
            worker.attest_runtime = attest
            worker.process_active = broken_task
            await worker.serve(interval=0.001)

            status_text = (Path(directory) / "worker.json").read_text(encoding="utf-8")
            status = json.loads(status_text)
            self.assertTrue(worker.restart_required)
            self.assertFalse(worker.stopping)
            self.assertEqual(status["reason"], "worker_task_failed")
            self.assertEqual(status["diagnostic"], "worker_task:RuntimeError")
            self.assertNotIn("secret-from-provider-output", status_text)

    async def test_retired_released_job_does_not_restart_clean_worker(self):
        for outcome in ("completed", "failed", "flag_found", "cancelled", "needs_input", "refused"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                exchange, scratch = root / "exchange", root / "scratch"
                active = exchange / "active"
                active.mkdir(parents=True)
                scratch.mkdir()
                job_id = "a" * 32
                (active / "state.json").write_text(json.dumps({
                    "protocol": EXCHANGE_PROTOCOL,
                    "job_id": job_id,
                    "status": outcome,
                    "terminal": True,
                }), encoding="utf-8")

                async def clean(_pid):
                    return None

                worker = SolverWorker(
                    exchange=exchange, scratch_root=scratch,
                    process_cleaner=clean, process_assertion=lambda: None,
                )
                worker.attestation = PlatformAttestation(True, {})
                worker.runtime_ready = worker.sandbox_attested = True
                manifest = SimpleNamespace(
                    job_id=job_id, job_mode="solve", resume_flag=False,
                    deadline_unix=None, configuration=SimpleNamespace(model="test-model"),
                    challenge_name="test challenge",
                )
                with patch("ctf_agent.solver_worker.JobManifest.load", return_value=manifest):
                    # Release an already durable terminal outcome in this PID.
                    self.assertTrue(await worker.process_active())
                    self.assertEqual(worker.last_released_job_id, job_id)
                    self.assertTrue(worker.clean)

                    def retire_during_next_poll(*_args):
                        active.rename(root / "retired-audit")
                        raise FileNotFoundError("coordinator retired active")

                    with patch("ctf_agent.solver_worker.GuidanceMailbox", side_effect=retire_during_next_poll):
                        self.assertFalse(await worker.process_active())

                status = json.loads((exchange / "worker.json").read_text(encoding="utf-8"))
                self.assertTrue(worker.clean)
                self.assertFalse(worker.restart_required)
                self.assertTrue(status["ready"])
                self.assertTrue(status["clean"])
                self.assertFalse(active.exists())
                recorded = [
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in (root / "retired-audit" / "events").glob("*.json")
                ]
                self.assertEqual([event["kind"] for event in recorded], ["released"])

    async def test_retirement_during_manifest_load_never_writes_a_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exchange, scratch = root / "exchange", root / "scratch"
            active = exchange / "active"
            active.mkdir(parents=True)
            scratch.mkdir()
            worker = SolverWorker(exchange=exchange, scratch_root=scratch)
            worker.attestation = PlatformAttestation(True, {})
            worker.runtime_ready = worker.sandbox_attested = worker.clean = True
            original_load = JobManifest.load

            def retire_before_manifest_read(path):
                shutil.rmtree(path)
                return original_load(path)

            with patch.object(JobManifest, "load", side_effect=retire_before_manifest_read):
                self.assertTrue(await worker.process_active())
            self.assertTrue(worker.clean)
            self.assertFalse(worker.restart_required)
            self.assertFalse(active.exists())
            self.assertFalse((exchange / "events").exists())

    async def test_missing_other_job_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exchange, scratch = root / "exchange", root / "scratch"
            active = exchange / "active"
            active.mkdir(parents=True)
            scratch.mkdir()
            worker = SolverWorker(exchange=exchange, scratch_root=scratch, process_assertion=lambda: None)
            worker.last_released_job_id = "a" * 32
            manifest = SimpleNamespace(
                job_id="b" * 32, job_mode="solve", resume_flag=False,
                deadline_unix=None, configuration=SimpleNamespace(model="test-model"),
                challenge_name="test challenge",
            )

            def retire_during_new_job(*_args):
                shutil.rmtree(active)
                raise FileNotFoundError("a different active job disappeared")

            with patch("ctf_agent.solver_worker.JobManifest.load", return_value=manifest), patch(
                "ctf_agent.solver_worker.GuidanceMailbox", side_effect=retire_during_new_job
            ):
                with self.assertRaises(FileNotFoundError):
                    await worker.process_active()

    async def test_missing_active_after_workspace_start_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exchange, scratch = root / "exchange", root / "scratch"
            active = exchange / "active"
            (active / "challenge").mkdir(parents=True)
            scratch.mkdir()
            job_id = "a" * 32

            async def clean(_pid):
                return None

            worker = SolverWorker(
                exchange=exchange, scratch_root=scratch,
                process_cleaner=clean, process_assertion=lambda: None,
            )
            worker.attestation = PlatformAttestation(True, {})
            worker.runtime_ready = worker.sandbox_attested = True
            worker.last_released_job_id = job_id
            manifest = SimpleNamespace(
                job_id=job_id, job_mode="solve", resume_flag=False,
                deadline_unix=None, configuration=SimpleNamespace(model="test-model"),
                challenge_name="test challenge",
            )
            original_emit = EventWriter.emit

            def retire_after_workspace_start(writer, kind, **payload):
                if kind == "progress" and payload.get("code") == "inspecting_files":
                    shutil.rmtree(active)
                    raise FileNotFoundError("active disappeared during a new execution")
                return original_emit(writer, kind, **payload)

            with patch("ctf_agent.solver_worker.JobManifest.load", return_value=manifest), patch.object(
                EventWriter, "emit", retire_after_workspace_start
            ):
                with self.assertRaises(FileNotFoundError):
                    await worker.process_active()


if __name__ == "__main__":
    unittest.main()
