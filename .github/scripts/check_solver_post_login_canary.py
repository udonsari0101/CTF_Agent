"""No-model regression for the post-login Codex canary profile."""

from __future__ import annotations

import asyncio
import ast
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
    ClaudePrintDriver,
    CodexAppServer,
    SolverWorker,
    WorkerRefusal,
    _post_login_canary_profile,
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
                    full_script.index("if canary_profile == \"post_login_isolation_only\":"),
                )
                self.assertLess(
                    full_script.index("if canary_profile == \"post_login_isolation_only\":"),
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


if __name__ == "__main__":
    unittest.main()
