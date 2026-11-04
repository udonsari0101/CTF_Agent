"""Offline fault injection for data-volume storage accounting diagnostics."""

from __future__ import annotations

import errno
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing, nullcontext
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.storage_budget import (  # noqa: E402
    StorageBudget, StorageBudgetError, storage_http_status, storage_io_http_response,
)
from ctf_agent.solver_exchange import (  # noqa: E402
    SolverExchangeCoordinator, _stage_budget_error, _stage_io_error,
)


class StorageBudgetDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "budget.sqlite3"
        self.data = root / "data"

        def connect():
            db = sqlite3.connect(self.database)
            db.row_factory = sqlite3.Row
            return db

        self.budget = StorageBudget(self.data, connect, minimum_free_bytes=200)

    def assert_error(self, expected_code, action):
        with self.assertRaises(StorageBudgetError) as caught:
            action()
        error = caught.exception
        self.assertEqual(error.code, expected_code)
        self.assertIsInstance(error.diagnostics, dict)
        self.assertNotIn(str(self.data), json.dumps(error.diagnostics))
        self.assertNotIn(str(self.database), json.dumps(error.diagnostics))
        return error

    def reserve(self, key="one", amount=100, owner="owner"):
        self.budget.reserve(key, "upload", owner, "workspace", None, amount)

    def test_low_space_uses_one_sample_and_preserves_existing_reservation(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve()
        original = self.data / "original.bin"
        original.write_bytes(b"original")
        with patch.object(self.budget, "_free", return_value=1000) as free:
            error = self.assert_error("insufficient_space", lambda: self.reserve("two", 800))
        free.assert_called_once_with()
        self.assertEqual(error.diagnostics["free_bytes"], 1000)
        self.assertEqual(error.diagnostics["reserved_bytes"], 100)
        self.assertEqual(error.diagnostics["requested_bytes"], 800)
        self.assertEqual(error.diagnostics["projected_reserved_bytes"], 900)
        self.assertEqual(error.diagnostics["minimum_free_bytes"], 200)
        self.assertIsInstance(error.diagnostics["mount_device"], int)
        self.assertIsInstance(error.diagnostics["observed_at_ns"], int)
        self.assertEqual([row["reservation_key"] for row in self.budget.snapshot()], ["one"])
        self.assertEqual(original.read_bytes(), b"original")

    def test_replacing_reservation_counts_only_projected_total(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve(amount=100)
        with patch.object(self.budget, "_free", return_value=1000) as free:
            error = self.assert_error("insufficient_space", lambda: self.reserve(amount=900))
        free.assert_called_once_with()
        self.assertEqual(error.diagnostics["reserved_bytes"], 100)
        self.assertEqual(error.diagnostics["projected_reserved_bytes"], 900)
        self.assertEqual(self.budget.snapshot()[0]["remaining_bytes"], 100)

    def test_free_check_failure_is_not_reported_as_insufficient_space(self):
        with patch("ctf_agent.storage_budget.shutil.disk_usage",
                   side_effect=OSError(errno.EIO, "probe failed")) as usage:
            error = self.assert_error("free_check_failed", self.reserve)
        usage.assert_called_once_with(self.data)
        self.assertEqual(error.diagnostics["errno"], errno.EIO)
        self.assertEqual(error.diagnostics["requested_bytes"], 100)
        self.assertNotIn("free_bytes", error.diagnostics)
        self.assertFalse(self.budget.snapshot())

    def test_lock_failure_has_its_own_code_and_errno(self):
        with patch("ctf_agent.storage_budget.os.open",
                   side_effect=PermissionError(errno.EACCES, "denied")):
            error = self.assert_error("lock_unavailable", self.reserve)
        self.assertEqual(error.diagnostics["errno"], errno.EACCES)
        self.assertFalse(self.budget.snapshot())

    def test_scope_and_missing_reservation_are_distinct(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve()
        mismatch = self.assert_error(
            "reservation_mismatch", lambda: self.reserve(owner="different")
        )
        self.assertEqual(mismatch.diagnostics["requested_bytes"], 100)
        missing = self.assert_error(
            "reservation_missing",
            lambda: self.budget.commit_reserved_write("missing", 1, lambda: None),
        )
        self.assertEqual(missing.diagnostics["requested_bytes"], 1)

    def test_writer_enospc_keeps_reservation_and_original(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve()
        original = self.data / "original.bin"
        original.write_bytes(b"original")

        def fail():
            raise OSError(errno.ENOSPC, "disk full")

        with patch.object(self.budget, "_free", return_value=1000) as free:
            error = self.assert_error(
                "write_enospc", lambda: self.budget.commit_reserved_write("one", 100, fail)
            )
        free.assert_called_once_with()
        self.assertEqual(error.diagnostics["errno"], errno.ENOSPC)
        self.assertEqual(error.diagnostics["free_bytes"], 1000)
        self.assertEqual(self.budget.snapshot()[0]["remaining_bytes"], 100)
        self.assertEqual(original.read_bytes(), b"original")
        self.budget.release("one")
        self.assertFalse(self.budget.snapshot())

    def test_permission_and_other_writer_failures_are_distinct(self):
        for err, code in ((errno.EACCES, "write_permission"),
                          (errno.EIO, "write_failed")):
            with self.subTest(errno=err):
                with patch.object(self.budget, "_free", return_value=1000):
                    error = self.assert_error(
                        code,
                        lambda err=err: self.budget.write_unreserved(
                            20, lambda: (_ for _ in ()).throw(OSError(err, "write error"))
                        ),
                    )
                self.assertEqual(error.diagnostics["errno"], err)
                self.assertEqual(error.diagnostics["projected_reserved_bytes"], 20)
                self.assertFalse(self.budget.snapshot())

    def test_commit_detects_reservation_changed_after_durable_write(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve()

        def writer():
            with closing(sqlite3.connect(self.database)) as db:
                with db:
                    db.execute("DELETE FROM storage_reservations WHERE reservation_key='one'")

        with patch.object(self.budget, "_free", return_value=1000):
            error = self.assert_error(
                "reservation_changed",
                lambda: self.budget.commit_reserved_write("one", 100, writer),
            )
        self.assertEqual(error.diagnostics["requested_bytes"], 100)
        self.assertFalse(self.budget.snapshot())

    def test_commit_detects_metadata_state_changed_without_releasing_reservation(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve()
        checks = []

        def precheck(_connection):
            checks.append(True)
            return len(checks) == 1

        with patch.object(self.budget, "_free", return_value=1000):
            error = self.assert_error(
                "state_changed",
                lambda: self.budget.commit_reserved_write(
                    "one", 100, lambda: None, precheck=precheck,
                ),
            )
        self.assertEqual(error.diagnostics["requested_bytes"], 100)
        self.assertEqual(self.budget.snapshot()[0]["remaining_bytes"], 100)

    def test_failed_cleanup_does_not_release_reservation(self):
        with patch.object(self.budget, "_free", return_value=1000):
            self.reserve()
        with self.assertRaises(OSError):
            self.budget.release("one", cleanup=lambda: (_ for _ in ()).throw(OSError("busy")))
        self.assertEqual(self.budget.snapshot()[0]["remaining_bytes"], 100)

    def test_api_and_solver_only_call_actual_capacity_failure_insufficient(self):
        expected = {
            "insufficient_space": (507, "insufficient_solver_storage"),
            "write_enospc": (507, "solver_storage_write_enospc"),
            "lock_unavailable": (503, "solver_storage_lock_unavailable"),
            "free_check_failed": (503, "solver_storage_probe_failed"),
            "write_permission": (503, "solver_storage_permission"),
            "reservation_missing": (409, "solver_storage_reservation_invalid"),
            "state_changed": (409, "solver_storage_state_changed"),
        }
        for code, (http_status, solver_code) in expected.items():
            with self.subTest(code=code):
                error = StorageBudgetError("synthetic", code=code)
                self.assertEqual(storage_http_status(error), http_status)
                self.assertEqual(_stage_budget_error(error).code, solver_code)

    def test_os_error_and_sqlite_full_have_separate_public_codes(self):
        self.assertEqual(storage_io_http_response(OSError(errno.ENOSPC, "full"))[0], 507)
        self.assertEqual(storage_io_http_response(OSError(errno.EACCES, "denied"))[0], 503)
        self.assertEqual(storage_io_http_response(OSError(errno.EIO, "io"))[0], 503)
        self.assertEqual(_stage_io_error(OSError(errno.ENOSPC, "full")).code, "solver_storage_write_enospc")
        self.assertEqual(_stage_io_error(OSError(errno.EACCES, "denied")).code, "solver_storage_permission")
        sqlite_full = sqlite3.OperationalError("database or disk is full")
        sqlite_full.sqlite_errorname = "SQLITE_FULL"
        self.assertEqual(_stage_io_error(sqlite_full).code, "solver_database_full")

    def test_existing_slot_stage_failure_is_not_reported_as_success(self):
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("CREATE TABLE users (id TEXT PRIMARY KEY, active INTEGER)")
            db.execute("INSERT INTO users VALUES ('owner',1)")
            coordinator = object.__new__(SolverExchangeCoordinator)
            coordinator._connect = lambda: nullcontext(db)
            coordinator._worker_status = lambda **_kw: {"instance_id": "worker"}
            coordinator._stage_initial = lambda *_args: (_ for _ in ()).throw(
                OSError(errno.ENOSPC, "simulated write failure")
            )
            coordinator.data_dir = self.data
            coordinator.database_path = self.database
            coordinator.last_block = None
            job = {"id": "job", "owner_user_id": "owner", "cancel_requested": 0,
                   "released_ingested": 0, "status": "staging"}
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING"):
                result = coordinator._tick_slot(job, self.data / "absent-stage")
            self.assertFalse(result)
            self.assertEqual(coordinator.last_block["code"], "solver_storage_write_enospc")


if __name__ == "__main__":
    unittest.main()
