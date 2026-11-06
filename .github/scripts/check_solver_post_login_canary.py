"""No-model regression for the post-login Codex canary profile."""

from __future__ import annotations

import asyncio
import ast
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_worker import (  # noqa: E402
    ClaudePrintDriver,
    CodexAppServer,
    PlatformAttestation,
    REQUIRED_CODEX_VERSION,
    SolverWorker,
    WorkerRefusal,
    _post_login_canary_profile,
    _record_startup_timing,
)


BASE_BOUNDARIES = {
    "data_absent", "database_absent", "auth_absent",
    "worker_proc_denied", "server_proc_denied", "scratch_writable",
    "challenge_write_denied", "exchange_write_denied", "tmp_write_denied",
    "dev_shm_write_denied", "run_write_denied", "var_tmp_write_denied",
    "network_ipv4_available", "network_ipv6_available",
}
EXTERNAL_BOUNDARIES = {
    "exchange_read_denied", "command_profile_enforced", "unix_stream_available",
    "input_readable", "input_mmap_readable", "input_symlink_readable",
    "input_write_denied", "input_link_denied", "input_exec_denied",
    "input_control_read_denied", "input_auth_read_denied",
    "input_api_key_read_denied", "input_listing_denied", "shell_profile_enforced",
}
FUNCTIONAL = {
    "toolchain_environment_writable", "toolchain_commands_present",
    "toolchain_binaries_functional", "toolchain_browser_functional",
    "toolchain_python_functional",
}


class PostLoginCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.exchange = root / "exchange"
        self.scratch = root / "scratch"
        self.challenge = root / "source"
        for path in (self.exchange, self.scratch, self.challenge):
            path.mkdir()
        self.driver = object.__new__(CodexAppServer)
        self.driver.pid = os.getpid()
        self.driver.safe_startup_stderr = None
        self.driver.sandbox_checks = {}
        self.driver._full_canary_verified = False
        self.driver._full_canary_context = None
        self.driver.startup_timing_reporter = None
        self.policy_marker = True
        self.driver._sandbox_parameters = lambda *_args, **_kwargs: {
            "sandbox_marker": self.policy_marker
        }
        self.checks: dict[str, bool] = {}
        self.requests: list[dict] = []

        async def request(method: str, params: dict, *, timeout: int) -> dict:
            self.assertEqual(method, "command/exec")
            self.assertEqual(timeout, 25)
            self.requests.append(params)
            return {"exitCode": 0, "stdout": json.dumps(self.checks)}

        self.driver.request = request

    def run_canary(self, *, external: bool, profile: str) -> None:
        with patch.dict(os.environ, {"CTF_SOLVER_EXTERNAL_SANDBOX": str(external).lower()}):
            asyncio.run(self.driver.sandbox_canary(
                os.getpid(), self.exchange, self.scratch, self.challenge,
                profile=profile,
            ))

    def full_checks(self, *, external: bool) -> dict[str, bool]:
        names = BASE_BOUNDARIES | FUNCTIONAL | {"toolchain_trace_functional"}
        names |= EXTERNAL_BOUNDARIES if external else {"exchange_inventory_safe"}
        return {name: True for name in names}

    def test_profile_is_on_by_default_and_codex_only(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                _post_login_canary_profile(self.driver), "post_login_isolation_only"
            )
        with patch.dict(os.environ, {"CTF_SOLVER_POST_LOGIN_ISOLATION_ONLY": "false"}):
            self.assertEqual(_post_login_canary_profile(self.driver), "full")
        with patch.dict(os.environ, {"CTF_SOLVER_POST_LOGIN_ISOLATION_ONLY": "true"}):
            self.assertEqual(
                _post_login_canary_profile(self.driver), "post_login_isolation_only"
            )
            self.assertEqual(_post_login_canary_profile(object()), "full")
            self.assertEqual(
                _post_login_canary_profile(object.__new__(ClaudePrintDriver)), "full"
            )

    def test_claude_still_runs_the_full_post_login_probe_when_flag_is_on(self) -> None:
        driver = object.__new__(ClaudePrintDriver)
        calls = []

        async def probe(*args):
            calls.append(args)

        driver.sandbox_canary = probe
        worker = SolverWorker(exchange=self.exchange)
        with patch.dict(os.environ, {"CTF_SOLVER_POST_LOGIN_ISOLATION_ONLY": "true"}):
            profile = _post_login_canary_profile(driver)
            asyncio.run(worker._verify_sandbox_canary(
                driver, self.scratch, self.challenge, profile=profile,
            ))
        self.assertEqual(profile, "full")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0]), 4)

    def test_isolation_refuses_without_prior_full_check(self) -> None:
        self.checks = self.full_checks(external=True)
        with self.assertRaises(WorkerRefusal) as raised:
            self.run_canary(external=True, profile="post_login_isolation_only")
        self.assertEqual(raised.exception.error.requirements, ("pre_login_full_canary",))
        self.assertEqual(self.requests, [])

    def test_isolation_refuses_after_command_policy_or_process_change(self) -> None:
        self.checks = self.full_checks(external=True)
        self.run_canary(external=True, profile="full")
        calls = len(self.requests)
        self.policy_marker = False
        with self.assertRaises(WorkerRefusal) as raised:
            self.run_canary(external=True, profile="post_login_isolation_only")
        self.assertEqual(raised.exception.error.requirements, ("pre_login_full_canary",))
        self.assertEqual(len(self.requests), calls)
        self.policy_marker = True
        self.driver.pid += 1
        with self.assertRaises(WorkerRefusal):
            self.run_canary(external=True, profile="post_login_isolation_only")
        self.assertEqual(len(self.requests), calls)

    def test_failed_full_check_clears_older_attestation(self) -> None:
        self.checks = self.full_checks(external=True)
        self.run_canary(external=True, profile="full")
        self.checks["network_ipv4_available"] = False
        with self.assertRaises(WorkerRefusal):
            self.run_canary(external=True, profile="full")
        self.assertFalse(self.driver._full_canary_verified)
        self.assertIsNone(self.driver._full_canary_context)
        with self.assertRaises(WorkerRefusal) as raised:
            self.run_canary(external=True, profile="post_login_isolation_only")
        self.assertEqual(raised.exception.error.requirements, ("pre_login_full_canary",))

    def test_new_provider_start_clears_attestation(self) -> None:
        self.checks = self.full_checks(external=True)
        self.run_canary(external=True, profile="full")
        self.driver.executable = ""
        with self.assertRaises(WorkerRefusal) as raised:
            asyncio.run(self.driver.start())
        self.assertEqual(raised.exception.error.code, "codex_missing")
        self.assertFalse(self.driver._full_canary_verified)
        self.assertIsNone(self.driver._full_canary_context)

    def test_each_boundary_remains_required_in_both_sandbox_modes(self) -> None:
        for external in (False, True):
            with self.subTest(external=external):
                self.driver._full_canary_verified = False
                self.checks = self.full_checks(external=external)
                self.run_canary(external=external, profile="full")
                self.assertTrue(self.driver._full_canary_verified)
                boundaries = BASE_BOUNDARIES | (
                    EXTERNAL_BOUNDARIES if external else {"exchange_inventory_safe"}
                )
                for name in sorted(boundaries):
                    with self.subTest(external=external, boundary=name):
                        self.checks = self.full_checks(external=external)
                        self.checks[name] = False
                        with self.assertRaises(WorkerRefusal) as raised:
                            self.run_canary(
                                external=external, profile="post_login_isolation_only"
                            )
                        self.assertIn(name, raised.exception.error.requirements)

    def test_only_functional_checks_are_omitted_after_login(self) -> None:
        for external in (False, True):
            with self.subTest(external=external):
                self.driver._full_canary_verified = False
                self.checks = self.full_checks(external=external)
                self.run_canary(external=external, profile="full")
                self.assertEqual(self.driver.sandbox_checks, {
                    "toolchain_browser_functional": True,
                    "toolchain_trace_functional": True,
                })
                self.checks = self.full_checks(external=external)
                for name in FUNCTIONAL | {"toolchain_trace_functional"}:
                    self.checks.pop(name)
                self.run_canary(external=external, profile="post_login_isolation_only")
                self.assertEqual(self.driver.sandbox_checks, {
                    "toolchain_browser_functional": True,
                    "toolchain_trace_functional": True,
                })
                full_command = self.requests[-2]["command"]
                isolation_command = self.requests[-1]["command"]
                full_script = full_command[
                    max(index for index, value in enumerate(full_command) if value == "-c") + 1
                ]
                isolation_script = isolation_command[
                    max(index for index, value in enumerate(isolation_command) if value == "-c") + 1
                ]
                self.assertEqual(full_script, isolation_script)
                self.assertEqual(full_command[-1], "full")
                self.assertEqual(isolation_command[-1], "post_login_isolation_only")
                self.assertEqual(self.requests[-1]["sandbox_marker"], True)
                guard = next(
                    node for node in ast.parse(full_script).body
                    if isinstance(node, ast.If)
                    and isinstance(node.test, ast.Compare)
                    and isinstance(node.test.left, ast.Name)
                    and node.test.left.id == "canary_profile"
                )
                self.assertIn("sys.exit(0)", ast.unparse(guard))
                self.assertLess(
                    full_script.index("result[\"network_ipv6_available\"]="),
                    full_script.index('if canary_profile in ("post_login_isolation_only","ready_toolchain_isolation_only"):'),
                )
                self.assertLess(
                    full_script.index('if canary_profile in ("post_login_isolation_only","ready_toolchain_isolation_only"):'),
                    full_script.index("tool_root=os.path.join(scratch"),
                )

    def test_full_external_check_still_requires_functional_tools(self) -> None:
        for name in sorted(FUNCTIONAL):
            with self.subTest(functional=name):
                self.checks = self.full_checks(external=True)
                self.checks[name] = False
                with self.assertRaises(WorkerRefusal) as raised:
                    self.run_canary(external=True, profile="full")
                self.assertIn(name, raised.exception.error.requirements)
                self.assertFalse(self.driver._full_canary_verified)

    def test_ready_toolchain_profile_rechecks_boundaries_and_preserves_capabilities(self) -> None:
        cached = {
            "toolchain_browser_functional": True,
            "toolchain_trace_functional": False,
        }
        self.driver._ready_toolchain_checks = cached
        self.checks = self.full_checks(external=True)
        for name in FUNCTIONAL | {"toolchain_trace_functional"}:
            self.checks.pop(name)
        self.run_canary(external=True, profile="ready_toolchain_isolation_only")
        self.assertEqual(self.driver.sandbox_checks, cached)
        self.assertIsNone(self.driver._ready_toolchain_checks)
        self.run_canary(external=True, profile="post_login_isolation_only")
        self.assertEqual(self.requests[-2]["command"][-1], "ready_toolchain_isolation_only")
        self.assertEqual(self.requests[-1]["command"][-1], "post_login_isolation_only")

        for name in sorted(BASE_BOUNDARIES | EXTERNAL_BOUNDARIES):
            with self.subTest(boundary=name):
                self.driver._ready_toolchain_checks = cached
                self.driver._full_canary_verified = False
                self.checks = self.full_checks(external=True)
                self.checks[name] = False
                with self.assertRaises(WorkerRefusal) as raised:
                    self.run_canary(external=True, profile="ready_toolchain_isolation_only")
                self.assertIn(name, raised.exception.error.requirements)
                self.assertFalse(self.driver._full_canary_verified)

        self.driver._ready_toolchain_checks = cached
        with self.assertRaises(WorkerRefusal) as raised:
            self.run_canary(external=False, profile="ready_toolchain_isolation_only")
        self.assertEqual(raised.exception.error.requirements, ("ready_toolchain_attestation",))

    def test_ready_toolchain_reuse_guard_requires_opt_in_and_same_pinned_worker(self) -> None:
        worker = SolverWorker(exchange=self.exchange)
        worker.attestation = PlatformAttestation(True, {}, None)
        worker.runtime_ready = worker.sandbox_attested = worker.clean = True
        worker.provider_runtime_checks["codex_runtime_attested"] = True
        self.driver.command_prefix = ["/image/codex"]
        self.driver.command_arguments = lambda: ["/image/codex", "app-server"]
        self.driver.expected_version = REQUIRED_CODEX_VERSION
        self.driver.challenge = self.scratch
        self.driver._sandbox_parameters = lambda *_args, **_kwargs: {
            "sandboxPolicy": {"type": "externalSandbox", "networkAccess": "enabled"},
        }
        worker._ready_codex_toolchain = (
            os.getpid(), worker.instance_id, tuple(self.driver.command_prefix),
            tuple(self.driver.command_arguments()), REQUIRED_CODEX_VERSION, True, False,
        )
        def candidate():
            return worker._ready_toolchain_reuse_candidate(
                self.driver, REQUIRED_CODEX_VERSION, None, clean_before_job=True,
            )
        with patch.dict(os.environ, {"CTF_SOLVER_EXTERNAL_SANDBOX": "true"}):
            with patch.dict(os.environ, {"CTF_SOLVER_REUSE_READY_TOOLCHAIN_CANARY": "false"}):
                self.assertIsNone(candidate())
            with patch.dict(os.environ, {"CTF_SOLVER_REUSE_READY_TOOLCHAIN_CANARY": "true"}):
                self.assertEqual(candidate(), {
                    "toolchain_browser_functional": True,
                    "toolchain_trace_functional": False,
                })
                self.assertIsNone(worker._ready_toolchain_reuse_candidate(
                    self.driver, "0.0.1", None, clean_before_job=True,
                ))
                self.assertIsNone(worker._ready_toolchain_reuse_candidate(
                    self.driver, REQUIRED_CODEX_VERSION, "a" * 64, clean_before_job=True,
                ))
                self.assertIsNone(worker._ready_toolchain_reuse_candidate(
                    self.driver, REQUIRED_CODEX_VERSION, None, clean_before_job=False,
                ))
                self.driver.command_prefix = ["/different/codex"]
                self.assertIsNone(candidate())
                self.driver.command_prefix = ["/image/codex"]
                self.driver.command_arguments = lambda: ["/image/codex", "--enable", "multi_agent"]
                self.assertIsNone(candidate())
                self.driver.command_arguments = lambda: ["/image/codex", "app-server"]
                worker.instance_id = "restarted-worker"
                self.assertIsNone(candidate())
                worker.instance_id = worker._ready_codex_toolchain[1]
                worker.runtime_ready = False
                self.assertIsNone(candidate())
                worker.runtime_ready = True
                worker.restart_required = True
                self.assertIsNone(candidate())

    def test_process_active_uses_ready_profile_after_marking_job_unclean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exchange, scratch_root = root / "exchange", root / "scratch"
            (exchange / "active" / "challenge").mkdir(parents=True)
            scratch_root.mkdir()
            worker = SolverWorker(
                exchange=exchange, scratch_root=scratch_root,
                input_root=None, process_assertion=lambda: None,
            )
            worker.attestation = PlatformAttestation(True, {}, None)
            worker.runtime_ready = worker.sandbox_attested = worker.clean = True
            worker.provider_runtime_checks["codex_runtime_attested"] = True
            driver = object.__new__(CodexAppServer)
            driver.command_prefix = ["/image/codex"]
            driver.command_arguments = lambda: ["/image/codex", "app-server"]
            driver.expected_version = REQUIRED_CODEX_VERSION
            driver.challenge = scratch_root
            driver._sandbox_parameters = lambda *_args, **_kwargs: {
                "sandboxPolicy": {"type": "externalSandbox", "networkAccess": "enabled"},
            }
            async def no_op():
                return None
            driver.start = no_op
            driver.close = no_op
            worker._ready_codex_toolchain = (
                os.getpid(), worker.instance_id, tuple(driver.command_prefix),
                tuple(driver.command_arguments()), REQUIRED_CODEX_VERSION, True, False,
            )
            manifest = SimpleNamespace(
                job_id="a" * 32, job_mode="solve", deadline_unix=None,
                configuration=SimpleNamespace(provider="codex", model="test-model"),
                resume_flag=None, retry_checkpoint=None,
                challenge_name="test", challenge_text="test", related_context=None,
                category="unknown", flag_format=None, remote=None,
                remote_mode="none", network_enabled=False,
                auth_sha256="", auth_kind="oauth", credential_file="auth.json",
                codex_version=REQUIRED_CODEX_VERSION, codex_runtime_sha256=None,
            )
            observed = []
            async def probe(_driver, _scratch, _source, *, profile):
                observed.append((profile, worker.clean, driver._ready_toolchain_checks))
                raise SystemExit(19)
            worker._verify_sandbox_canary = probe
            def make_workspace(job_root, *_args, **_kwargs):
                workdir = job_root / "work"
                workdir.mkdir()
                return SimpleNamespace(workdir=workdir, brief=workdir / "brief")
            def make_driver(_home, challenge, *_args, **_kwargs):
                driver.challenge = challenge
                return driver
            worker._new_driver = make_driver
            credential = SimpleNamespace(
                login={"type": "chatgptAuthTokens"}, erase=lambda: None,
            )
            with patch.dict(os.environ, {
                "CTF_SOLVER_EXTERNAL_SANDBOX": "true",
                "CTF_SOLVER_REUSE_READY_TOOLCHAIN_CANARY": "true",
            }), patch("ctf_agent.solver_worker.JobManifest.load", return_value=manifest), patch(
                "ctf_agent.solver_worker._validate_challenge_tree"
            ), patch("ctf_agent.solver_worker.prepare_agent_workspace", side_effect=make_workspace), patch(
                "ctf_agent.solver_worker.workspace_baseline", return_value={}
            ), patch("ctf_agent.solver_worker.consume_staged_credential", return_value=credential):
                with self.assertRaises(SystemExit):
                    asyncio.run(worker.process_active())
            self.assertEqual(observed, [(
                "ready_toolchain_isolation_only", False,
                {"toolchain_browser_functional": True, "toolchain_trace_functional": False},
            )])

    def test_full_canary_reports_only_valid_stage_durations(self) -> None:
        reported = []
        self.driver.startup_timing_reporter = lambda phase, started, duration: (
            reported.append((phase, started, duration))
        )
        self.checks = self.full_checks(external=True)
        self.checks.update({
            "canary_native_ms": 17,
            "canary_browser_ms": 23,
            "canary_strace_ms": 7,
            "canary_python_ms": 99,
            "canary_account_ms": 12,
        })
        self.run_canary(external=True, profile="full")
        self.assertEqual(reported, [
            ("canary_native", None, 17),
            ("canary_browser", None, 23),
            ("canary_strace", None, 7),
            ("canary_python", None, 99),
        ])
        self.run_canary(external=True, profile="post_login_isolation_only")
        self.assertEqual(len(reported), 4)

        reported.clear()
        self.checks.update({
            "canary_native_ms": True,
            "canary_browser_ms": "23",
            "canary_strace_ms": -1,
            "canary_python_ms": 120_001,
        })
        self.checks["toolchain_python_functional"] = False
        with self.assertRaises(WorkerRefusal) as raised:
            self.run_canary(external=True, profile="full")
        self.assertIn("toolchain_python_functional", raised.exception.error.requirements)
        self.assertEqual(reported, [])

    def test_stage_timing_log_is_allowlisted_and_anonymous(self) -> None:
        output = io.StringIO()
        with patch.object(sys, "stderr", output):
            _record_startup_timing("canary_native", None, "random-run-key", duration_ms=37)
            _record_startup_timing("canary_account", None, "random-run-key", duration_ms=12)
            _record_startup_timing("canary_python", None, "random-run-key", duration_ms=True)
            _record_startup_timing("canary_python", None, "random-run-key", duration_ms=-1)
        self.assertEqual(json.loads(output.getvalue()), {
            "event": "solver_startup_timing",
            "run": "random-run-key",
            "phase": "canary_native",
            "duration_ms": 37,
        })


if __name__ == "__main__":
    unittest.main()
