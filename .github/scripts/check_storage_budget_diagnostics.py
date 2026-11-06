"""Offline fault injection for data-volume storage accounting diagnostics."""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.storage_budget import (  # noqa: E402
    StorageBudget, StorageBudgetError, storage_http_status, storage_io_http_response,
)
from ctf_agent.solver_exchange import (  # noqa: E402
    EXCHANGE_PROTOCOL, ExchangeError, SCHEMA as SOLVER_SCHEMA, SolverExchangeCoordinator,
    _stage_budget_error, _stage_io_error,
    _log_stage_storage_failure,
    _write_json_file, _write_live_attachment_chunk,
    _publish_live_attachment_no_replace, _LIVE_ATTACHMENT_CHUNK_BYTES,
)
from ctf_agent.solver_worker import _install_live_attachments  # noqa: E402


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

    def test_parallel_staging_writes_keep_reservations_consistent(self):
        original = self.data / "existing.bin"
        original.write_bytes(b"preserved")
        start = threading.Barrier(8)

        def stage(index):
            key = f"solver:{index}"
            path = self.data / f"stage-{index}.bin"
            start.wait(timeout=10)
            self.budget.reserve(key, "solver", "owner", "workspace", str(index), 1024 * 1024)

            def write():
                with path.open("xb") as output:
                    output.write(bytes([index]) * (1024 * 1024))
                    output.flush()
                    os.fsync(output.fileno())

            self.budget.commit_reserved_write(key, 1024 * 1024, write)
            return path.stat().st_size

        with ThreadPoolExecutor(max_workers=8) as pool:
            sizes = list(pool.map(stage, range(8)))
        self.assertEqual(sizes, [1024 * 1024] * 8)
        self.assertEqual(original.read_bytes(), b"preserved")
        self.assertFalse(self.budget.snapshot())

    def test_new_slot_keeps_other_claimed_stage_auth_and_live_copy_reservations(self):
        jobs = {
            "a" * 32: "staging",
            "b" * 32: "running",
            "c" * 32: "cleanup_blocked",
            "d" * 32: "failed",
        }
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.executescript(SOLVER_SCHEMA)
                for index, (job_id, status) in enumerate(jobs.items()):
                    db.execute(
                        """INSERT INTO solver_jobs
                           (id,owner_user_id,workspace_id,challenge_id,account_id,
                            provider,model,reasoning_effort,status,created_at,updated_at)
                           VALUES (?,?,?,?,?,'codex','test-model','low',?,1,1)""",
                        (job_id, "owner", "workspace", f"challenge-{index}", "account", status),
                    )
                    if status != "failed":
                        db.execute("INSERT INTO solver_slots VALUES (?,?)", (f"slot-{index}", job_id))

        stage_key = "solver:" + "a" * 32
        live_key = "solver-live:" + "b" * 32 + ":" + "e" * 32
        auth_key = "solver-auth:" + "b" * 32
        cleanup_key = "solver:" + "c" * 32
        orphan_key = "solver:" + "d" * 32
        for index, key in enumerate((stage_key, live_key, cleanup_key, orphan_key)):
            self.budget.reserve(key, "solver", "owner", "workspace", f"challenge-{index}", 10)
        self.budget.reserve(auth_key, "solver", "owner", "workspace", "challenge-1", 10)
        other_runtime = "solver-runtime:other-slot:0.166.0:" + "f" * 32
        own_runtime = "solver-runtime:new-slot:0.166.0:" + "e" * 32
        legacy_runtime = "solver-runtime:0.166.0:" + "d" * 32
        for key in (other_runtime, own_runtime, legacy_runtime):
            self.budget.reserve(key, "solver_runtime", "system", "runtime", "0.166.0", 10)

        original_reconcile = self.budget.reconcile_kind

        def assert_locked_snapshot(kind, expected):
            if kind in {"solver", "solver_runtime"}:
                self.assertTrue(callable(expected))
            return original_reconcile(kind, expected)

        with patch.object(self.budget, "reconcile_kind", side_effect=assert_locked_snapshot):
            SolverExchangeCoordinator(
                self.database, self.data, self.data / "accounts",
                self.data / "solver-exchange" / "slots" / "new-slot",
                storage_budget=self.budget, slot_id="new-slot",
                enforce_host_ownership=False,
            )
        self.assertEqual(
            {row["reservation_key"] for row in self.budget.snapshot(kind="solver")},
            {stage_key, auth_key, live_key, cleanup_key},
        )
        self.assertEqual(
            {row["reservation_key"] for row in self.budget.snapshot(kind="solver_runtime")},
            {other_runtime, legacy_runtime},
        )
        self.budget.commit_reserved_write(stage_key, 10, lambda: None)
        self.budget.commit_reserved_write(auth_key, 10, lambda: None)
        self.budget.consume_durable_reserved_write(live_key, 10)
        self.budget.release(cleanup_key)
        self.budget.release(other_runtime)
        self.budget.release(legacy_runtime)
        self.assertFalse(self.budget.snapshot(kind="solver"))
        self.assertFalse(self.budget.snapshot(kind="solver_runtime"))

    def test_published_active_job_reclaims_crash_left_stage_and_auth_reservations(self):
        job_id = "a" * 32
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.executescript(SOLVER_SCHEMA)
                db.execute("CREATE TABLE users (id TEXT PRIMARY KEY, active INTEGER)")
                db.execute("INSERT INTO users VALUES ('owner',1)")
                db.execute(
                    """INSERT INTO solver_jobs
                       (id,owner_user_id,workspace_id,challenge_id,account_id,
                        provider,model,reasoning_effort,status,created_at,updated_at)
                       VALUES (?,?,?,?,?,'codex','test-model','low','running',1,1)""",
                    (job_id, "owner", "workspace", "challenge", "account"),
                )
                db.execute("INSERT INTO solver_slots VALUES ('slot-1',?)", (job_id,))

        exchange = self.data / "solver-exchange" / "slots" / "slot-1"
        active = exchange / "active"
        active.mkdir(parents=True)
        stage_key = "solver:" + job_id
        auth_key = "solver-auth:" + job_id
        self.budget.reserve(stage_key, "solver", "owner", "workspace", "challenge", 700)
        self.budget.reserve(auth_key, "solver", "owner", "workspace", "challenge", 100)
        with patch.object(self.budget, "_free", return_value=900):
            self.assert_error("insufficient_space", lambda: self.reserve("next", 1))

        # An incomplete or mismatched active tree must retain its conservative
        # accounting; only the complete tree for this exact claimed job may
        # release a crash-left reservation.
        SolverExchangeCoordinator(
            self.database, self.data, self.data / "accounts", exchange,
            storage_budget=self.budget, slot_id="slot-1", enforce_host_ownership=False,
        )
        self.assertEqual(
            {row["reservation_key"] for row in self.budget.snapshot(kind="solver")},
            {stage_key, auth_key},
        )

        _write_json_file(active / "manifest.json", {"protocol": EXCHANGE_PROTOCOL, "job_id": "b" * 32})
        SolverExchangeCoordinator(
            self.database, self.data, self.data / "accounts", exchange,
            storage_budget=self.budget, slot_id="slot-1", enforce_host_ownership=False,
        )
        self.assertEqual(
            {row["reservation_key"] for row in self.budget.snapshot(kind="solver")},
            {stage_key, auth_key},
        )

        _write_json_file(active / "manifest.json", {"protocol": EXCHANGE_PROTOCOL, "job_id": job_id})
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE solver_jobs SET status='cleanup_blocked' WHERE id=?", (job_id,))
        SolverExchangeCoordinator(
            self.database, self.data, self.data / "accounts", exchange,
            storage_budget=self.budget, slot_id="slot-1", enforce_host_ownership=False,
        )
        self.assertEqual(
            {row["reservation_key"] for row in self.budget.snapshot(kind="solver")},
            {stage_key, auth_key},
        )
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE solver_jobs SET status='running' WHERE id=?", (job_id,))
        SolverExchangeCoordinator(
            self.database, self.data, self.data / "accounts", exchange,
            storage_budget=self.budget, slot_id="slot-1", enforce_host_ownership=False,
        )

        self.assertFalse(self.budget.snapshot(kind="solver"))
        with patch.object(self.budget, "_free", return_value=900):
            self.reserve("next", 1)
        self.budget.release("next")

    def test_post_publication_accounting_failure_does_not_fail_runnable_job(self):
        exchange = self.data / "solver-exchange" / "slots" / "slot-1"
        coordinator = SolverExchangeCoordinator(
            self.database, self.data, self.data / "accounts", exchange,
            storage_budget=self.budget, slot_id="slot-1", enforce_host_ownership=False,
        )
        job_id = "a" * 32
        with coordinator._connect() as db:
            db.execute(
                """INSERT INTO solver_jobs
                   (id,owner_user_id,workspace_id,challenge_id,account_id,
                    provider,model,reasoning_effort,status,created_at,updated_at)
                   VALUES (?,?,?,?,?,'codex','gpt-6-sol','low','staging',1,1)""",
                (job_id, "owner", "workspace", "challenge", "account"),
            )
            db.execute("INSERT INTO solver_slots VALUES ('slot-1',?)", (job_id,))
            job = dict(db.execute("SELECT * FROM solver_jobs WHERE id=?", (job_id,)).fetchone())
        auth = self.data / "auth.json"
        auth.write_bytes(b"{}")
        auth.chmod(0o600)
        coordinator._auth_source = lambda _job: auth
        coordinator._continuation_for_stage = lambda _job: None
        coordinator._copy_attachments = lambda *_args: None
        coordinator._is_cancelled = lambda _job_id: False
        coordinator._stage_records = lambda _job: (
            {"name": "test", "description": "test", "remote_mode": "none"}, []
        )

        def copy_auth(_job, destination, *, expected_size):
            self.assertEqual(expected_size, 2)
            with destination.open("xb") as output:
                output.write(b"{}")
                output.flush()
                os.fsync(output.fileno())
            return "a" * 64

        coordinator._copy_auth = copy_auth
        original_release = self.budget.release
        reservation = "solver:" + job_id

        def transient_release(key, *args, **kwargs):
            if key == reservation and (exchange / "active").exists():
                raise StorageBudgetError("transient lock failure", code="lock_unavailable")
            return original_release(key, *args, **kwargs)

        with patch.object(self.budget, "release", side_effect=transient_release):
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING"):
                coordinator._stage_initial(job, "worker")
        self.assertTrue((exchange / "active" / "manifest.json").is_file())
        self.assertEqual(
            {row["reservation_key"] for row in self.budget.snapshot(kind="solver")},
            {reservation},
        )
        self.assertEqual(coordinator._published_stage_reservations, {reservation})
        coordinator._fail_staging(job_id, "failed", {"code": "synthetic_post_publish_error"})
        with coordinator._connect() as db:
            self.assertEqual(db.execute("SELECT job_id FROM solver_slots WHERE slot_id='slot-1'").fetchone()[0], job_id)
            self.assertEqual(db.execute("SELECT status FROM solver_jobs WHERE id=?", (job_id,)).fetchone()[0], "staging")

        coordinator._retry_published_stage_reservations()
        self.assertFalse(coordinator._published_stage_reservations)
        self.assertFalse(self.budget.snapshot(kind="solver"))

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

    def test_durable_chunk_consumption_is_exact_and_short(self):
        self.reserve(amount=100)
        self.budget.consume_durable_reserved_write("one", 40)
        self.assertEqual(self.budget.snapshot()[0]["remaining_bytes"], 60)
        error = self.assert_error(
            "reservation_missing",
            lambda: self.budget.consume_durable_reserved_write("one", 61),
        )
        self.assertEqual(error.diagnostics["requested_bytes"], 61)
        self.assertEqual(self.budget.snapshot()[0]["remaining_bytes"], 60)
        self.budget.consume_durable_reserved_write("one", 60)
        self.assertFalse(self.budget.snapshot())

    def test_unacknowledged_durable_bytes_conservatively_reduce_headroom(self):
        # The 40-byte write is already durable but has not yet had its short
        # reservation-decrement transaction. This can briefly reject a new
        # request near the floor; it must never admit an unsafe one.
        with patch.object(self.budget, "_free", return_value=301):
            self.reserve(amount=100)
        with patch.object(self.budget, "_free", return_value=261):
            self.assert_error(
                "insufficient_space",
                lambda: self.budget.reserve("next", "solver", "owner", "workspace", None, 1),
            )
        self.budget.consume_durable_reserved_write("one", 40)
        with patch.object(self.budget, "_free", return_value=261):
            self.budget.reserve("next", "solver", "owner", "workspace", None, 1)
        self.budget.release("next")
        self.budget.release("one")

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

    def test_stage_log_keeps_raw_error_codes_without_paths_or_exception_text(self):
        secret = "private-source-path-and-secret-value"
        source = self.data / secret
        source.mkdir()
        filesystem_error = OSError(errno.ENOSPC, f"{secret}: injected write failure")
        with self.assertLogs("ctf_agent.solver_exchange", level="WARNING") as captured:
            _log_stage_storage_failure(filesystem_error, self.data, self.database)
        entry = captured.output[0]
        self.assertIn(f"'errno': {errno.ENOSPC}", entry)
        self.assertNotIn(secret, entry)
        self.assertNotIn(str(source), entry)
        self.assertNotIn(str(self.database), entry)

        sqlite_error = sqlite3.OperationalError(f"{secret}: database busy")
        sqlite_error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        sqlite_error.sqlite_errorname = "SQLITE_BUSY"
        with self.assertLogs("ctf_agent.solver_exchange", level="WARNING") as captured:
            _log_stage_storage_failure(sqlite_error, self.data, self.database)
        entry = captured.output[0]
        self.assertIn(f"'sqlite_errorcode': {sqlite3.SQLITE_BUSY}", entry)
        self.assertIn("'sqlite_errorname': 'SQLITE_BUSY'", entry)
        self.assertNotIn(secret, entry)
        self.assertNotIn(str(self.database), entry)

        sqlite_error.sqlite_errorname = "SQLITE_BUSY\n" + secret
        with self.assertLogs("ctf_agent.solver_exchange", level="WARNING") as captured:
            _log_stage_storage_failure(sqlite_error, self.data, self.database)
        self.assertNotIn(secret, captured.output[0])
        self.assertNotIn("sqlite_errorname", captured.output[0])

    def test_stage_log_records_inode_headroom_without_file_paths(self):
        # shutil.disk_usage also calls os.statvfs on Linux. Mock its byte
        # probe separately so this inode-only fixture does not replace the
        # unrelated statvfs fields required by disk_usage.
        with patch(
            "ctf_agent.solver_exchange.shutil.disk_usage",
            return_value=SimpleNamespace(free=4096, total=8192),
        ), patch(
            "ctf_agent.solver_exchange.os.statvfs", create=True,
            return_value=SimpleNamespace(f_favail=0, f_files=1234),
        ):
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING") as captured:
                _log_stage_storage_failure(OSError(errno.ENOSPC, "private path"), self.data, self.database)
        entry = captured.output[0]
        self.assertIn("'free_inodes': 0", entry)
        self.assertIn("'total_inodes': 1234", entry)
        self.assertNotIn(str(self.data), entry)
        self.assertNotIn(str(self.database), entry)
        self.assertNotIn("private path", entry)

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

    def _live_attachment_fixture(self):
        owner = "a" * 32
        workspace = "b" * 32
        challenge = "c" * 32
        attachment = "d" * 32
        source = (self.data / "workspaces" / workspace / "challenges" /
                  challenge / "attachments" / attachment)
        source.parent.mkdir(parents=True)
        source.write_bytes(b"saved attachment contents")
        active = self.data / "solver-exchange" / "active"
        (active / "challenge" / "attachments").mkdir(parents=True)
        index = active / "attachment-index.json"
        index.write_text('{"ids": []}', encoding="utf-8")
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute(
                    "CREATE TABLE attachments (id TEXT,workspace_id TEXT,challenge_id TEXT,"
                    "original_name TEXT,stored_name TEXT,size INTEGER,created_at TEXT)"
                )
                db.execute(
                    "INSERT INTO attachments VALUES (?,?,?,?,?,?,?)",
                    (attachment, workspace, challenge, "proof.bin", attachment,
                     source.stat().st_size, "2026-11-05T00:00:00Z"),
                )

        @contextmanager
        def connect():
            db = sqlite3.connect(self.database)
            db.row_factory = sqlite3.Row
            try:
                yield db
            finally:
                db.close()

        coordinator = object.__new__(SolverExchangeCoordinator)
        coordinator.data_dir = self.data
        coordinator.database_path = self.database
        coordinator.storage_budget = self.budget
        coordinator.stop_requested = threading.Event()
        coordinator._is_cancelled = lambda _job_id: False
        coordinator._connect = connect
        job = {"id": "job", "owner_user_id": owner,
               "workspace_id": workspace, "challenge_id": challenge}
        target = active / "challenge" / "attachments" / f"live-{attachment}_proof.bin"
        return coordinator, job, active, source, target, index

    def test_live_attachment_partial_enospc_cleans_up_and_retries(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()

        def fail_after_partial(_source, destination, **_kwargs):
            destination.write_bytes(b"partial")
            raise OSError(errno.ENOSPC, "simulated write failure")

        with patch("ctf_agent.solver_exchange._copy_regular_file_reserved_chunks", side_effect=fail_after_partial):
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING"):
                with self.assertRaises(ExchangeError) as caught:
                    coordinator._sync_live_attachments(job, active)
        self.assertEqual(caught.exception.code, "solver_storage_write_enospc")
        self.assertFalse(target.exists())
        self.assertFalse((target.parent / ("." + target.name + ".partial")).exists())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})
        self.assertEqual(source.read_bytes(), b"saved attachment contents")
        self.assertFalse(self.budget.snapshot())

        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": ["d" * 32]})
        self.assertFalse(coordinator._sync_live_attachments(job, active))

    def test_live_attachment_recovers_leftover_partial_after_restart(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        partial = target.parent / ("." + target.name + ".partial")
        partial.write_bytes(b"interrupted copy")
        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertFalse(partial.exists())
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": ["d" * 32]})

    def test_live_attachment_drain_leaves_job_retryable(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        coordinator.stop_requested.set()
        self.assertFalse(coordinator._sync_live_attachments(job, active))
        self.assertFalse(target.exists())
        self.assertFalse((target.parent / ("." + target.name + ".partial")).exists())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})
        coordinator.stop_requested.clear()
        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_live_attachment_index_failure_rechecks_existing_content(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()

        def fail_index(path, payload):
            if path == index:
                raise OSError(errno.EIO, "simulated index failure")
            return _write_json_file(path, payload)

        with patch("ctf_agent.solver_exchange._write_json_file", side_effect=fail_index):
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING"):
                with self.assertRaises(ExchangeError) as caught:
                    coordinator._sync_live_attachments(job, active)
        self.assertEqual(caught.exception.code, "stage_storage_failed")
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})

        changed = b"X" * source.stat().st_size
        target.write_bytes(changed)
        with self.assertRaises(ExchangeError) as caught:
            coordinator._sync_live_attachments(job, active)
        self.assertEqual(caught.exception.code, "invalid_attachment_path")
        self.assertEqual(target.read_bytes(), changed)
        self.assertEqual(source.read_bytes(), b"saved attachment contents")
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})

        target.write_bytes(source.read_bytes())
        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": ["d" * 32]})

    def _grow_live_attachment(self, source, size):
        source.write_bytes(b"A" * size)
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE attachments SET size=?", (size,))

    def test_live_attachment_second_chunk_failure_releases_reservation(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        self._grow_live_attachment(source, _LIVE_ATTACHMENT_CHUNK_BYTES * 2 + 17)
        original_write = _write_live_attachment_chunk
        calls = 0

        def fail_second(destination_fd, chunk):
            nonlocal calls
            calls += 1
            if calls == 2:
                original_write(destination_fd, chunk)
                raise OSError(errno.ENOSPC, "simulated second chunk fsync failure")
            return original_write(destination_fd, chunk)

        with patch("ctf_agent.solver_exchange._write_live_attachment_chunk", side_effect=fail_second):
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING"):
                with self.assertRaises(ExchangeError) as caught:
                    coordinator._sync_live_attachments(job, active)
        self.assertEqual(caught.exception.code, "solver_storage_write_enospc")
        self.assertEqual(calls, 2)
        self.assertFalse(target.exists())
        self.assertFalse((target.parent / ("." + target.name + ".partial")).exists())
        self.assertFalse(self.budget.snapshot())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})
        self.assertEqual(source.stat().st_size, _LIVE_ATTACHMENT_CHUNK_BYTES * 2 + 17)
        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertFalse(self.budget.snapshot())

    def test_live_attachment_releases_global_lock_between_chunks(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        self._grow_live_attachment(source, _LIVE_ATTACHMENT_CHUNK_BYTES * 2 + 17)
        original_consume = self.budget.consume_durable_reserved_write
        first_committed = threading.Event()
        continue_copy = threading.Event()
        calls = 0

        def pause_between_chunks(key, amount):
            nonlocal calls
            result = original_consume(key, amount)
            calls += 1
            if calls == 1:
                first_committed.set()
                if not continue_copy.wait(timeout=10):
                    raise TimeoutError("test did not resume the copy")
            return result

        with patch.object(self.budget, "consume_durable_reserved_write", side_effect=pause_between_chunks):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(coordinator._sync_live_attachments, job, active)
                self.assertTrue(first_committed.wait(timeout=10))
                try:
                    start = time.monotonic()
                    self.budget.reserve("unrelated", "solver", "other", "workspace", None, 1)
                    elapsed = time.monotonic() - start
                    self.assertLess(elapsed, 5)
                    self.assertFalse(future.done())
                finally:
                    continue_copy.set()
                self.assertTrue(future.result(timeout=30))
        self.budget.release("unrelated")
        self.assertEqual(calls, 3)
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": ["d" * 32]})
        self.assertFalse(self.budget.snapshot())

    def test_live_attachment_slow_write_does_not_hold_global_lock(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        self._grow_live_attachment(source, _LIVE_ATTACHMENT_CHUNK_BYTES + 17)
        entered_write = threading.Event()
        resume_write = threading.Event()

        def paused_write(destination_fd, chunk):
            entered_write.set()
            if not resume_write.wait(timeout=10):
                raise TimeoutError("test did not resume the write")
            return _write_live_attachment_chunk(destination_fd, chunk)

        with patch("ctf_agent.solver_exchange._write_live_attachment_chunk", side_effect=paused_write):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(coordinator._sync_live_attachments, job, active)
                self.assertTrue(entered_write.wait(timeout=10))
                try:
                    started = time.monotonic()
                    self.budget.reserve("unrelated", "solver", "other", "workspace", None, 1)
                    self.assertLess(time.monotonic() - started, 5)
                    self.assertFalse(future.done())
                finally:
                    resume_write.set()
                self.assertTrue(future.result(timeout=30))
        self.budget.release("unrelated")
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": ["d" * 32]})
        self.assertFalse(self.budget.snapshot())

    def test_live_attachment_reservation_removed_during_copy_cleans_partial(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        original_consume = self.budget.consume_durable_reserved_write

        def remove_before_ack(key, amount):
            self.budget.release(key)
            original_consume(key, amount)

        with patch.object(self.budget, "consume_durable_reserved_write", side_effect=remove_before_ack):
            with self.assertLogs("ctf_agent.solver_exchange", level="WARNING"):
                with self.assertRaises(ExchangeError) as caught:
                    coordinator._sync_live_attachments(job, active)
        self.assertEqual(caught.exception.code, "solver_storage_reservation_invalid")
        self.assertFalse(target.exists())
        self.assertFalse((target.parent / ("." + target.name + ".partial")).exists())
        self.assertFalse(self.budget.snapshot())
        self.assertEqual(source.read_bytes(), b"saved attachment contents")
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})
        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_live_attachment_publish_never_overwrites_racing_target(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        original_publish = _publish_live_attachment_no_replace

        def race_target_creation(partial, destination, **kwargs):
            self.assertEqual(destination, target)
            target.write_bytes(b"created by another writer")
            return original_publish(partial, destination, **kwargs)

        with patch("ctf_agent.solver_exchange._publish_live_attachment_no_replace", side_effect=race_target_creation):
            with self.assertRaises(ExchangeError) as caught:
                coordinator._sync_live_attachments(job, active)
        self.assertEqual(caught.exception.code, "invalid_attachment_path")
        self.assertEqual(target.read_bytes(), b"created by another writer")
        self.assertEqual(source.read_bytes(), b"saved attachment contents")
        self.assertFalse((target.parent / ("." + target.name + ".partial")).exists())
        self.assertFalse(self.budget.snapshot())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": []})
        target.unlink()
        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_live_attachment_recovers_interrupted_hardlink_publication(self):
        coordinator, job, active, source, target, index = self._live_attachment_fixture()
        partial = target.parent / ("." + target.name + ".partial")
        partial.write_bytes(source.read_bytes())
        os.link(partial, target)
        self.assertEqual(partial.stat().st_nlink, 2)

        # On a fallback filesystem, a worker poll in the tiny link/unlink
        # window sees nlink=2 and retries on its next 0.5-second poll.
        worker_destination = self.data / "worker-visible-attachments"
        with self.assertRaisesRegex(ValueError, "regular file"):
            _install_live_attachments(target.parent, worker_destination, None)

        self.assertTrue(coordinator._sync_live_attachments(job, active))
        self.assertFalse(partial.exists())
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(_install_live_attachments(target.parent, worker_destination, None), 1)
        self.assertEqual((worker_destination / target.name).read_bytes(), source.read_bytes())
        self.assertEqual(json.loads(index.read_text(encoding="utf-8")), {"ids": ["d" * 32]})


if __name__ == "__main__":
    unittest.main()
