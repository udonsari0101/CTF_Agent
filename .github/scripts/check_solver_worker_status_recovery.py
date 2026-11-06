from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent import solver_autoscaler, solver_exchange, solver_worker as worker


ORPHAN = ".worker.json.1.1793942308964284383.tmp"


class WorkerStatusRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.exchange = self.root / "exchange"
        self.exchange.mkdir()
        (self.exchange / "runtime").mkdir()
        (self.exchange / "active").mkdir()
        (self.exchange / "active" / "job-marker").write_text("keep")
        (self.exchange / "worker.json").write_text("{}")
        (self.exchange / "worker.lock").touch()

    def test_exact_orphan_recovers_without_touching_active_job(self) -> None:
        orphan = self.exchange / ORPHAN
        orphan.write_text("partial status")
        orphan.chmod(0o644)
        worker.recover_crash_worker_status(self.exchange)
        self.assertFalse(orphan.exists())
        self.assertEqual((self.exchange / "active" / "job-marker").read_text(), "keep")
        self.assertTrue((self.exchange / "worker.json").exists())
        worker.assert_runtime_exchange_inventory(self.exchange)

    def test_unknown_prefix_stays_blocked_by_inventory(self) -> None:
        unknown = self.exchange / ".worker.json.extra.tmp"
        unknown.write_text("keep")
        worker.recover_crash_worker_status(self.exchange)
        self.assertTrue(unknown.exists())
        with self.assertRaises(worker.WorkerRefusal):
            worker.assert_runtime_exchange_inventory(self.exchange)

    def test_exact_name_symlink_is_rejected_without_following(self) -> None:
        target = self.root / "target"
        target.write_text("keep")
        link = self.exchange / ORPHAN
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        with self.assertRaises(worker.WorkerRefusal):
            worker.recover_crash_worker_status(self.exchange)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(), "keep")

    def test_oversized_status_temp_is_rejected(self) -> None:
        orphan = self.exchange / ORPHAN
        orphan.write_bytes(b"x" * (128 * 1024 + 1))
        with self.assertRaises(worker.WorkerRefusal):
            worker.recover_crash_worker_status(self.exchange)
        self.assertTrue(orphan.exists())

    def test_other_owner_status_temp_is_rejected(self) -> None:
        orphan = self.exchange / ORPHAN
        orphan.write_text("keep")
        if not hasattr(worker.os, "geteuid"):
            self.skipTest("owner identity unavailable on this platform")
        fake_uid = os.stat(orphan).st_uid + 1
        with mock.patch.object(worker.os, "geteuid", return_value=fake_uid):
            with self.assertRaises(worker.WorkerRefusal):
                worker.recover_crash_worker_status(self.exchange)
        self.assertTrue(orphan.exists())

    def test_hardlinked_status_temp_is_rejected(self) -> None:
        target = self.root / "target"
        target.write_text("keep")
        orphan = self.exchange / ORPHAN
        os.link(target, orphan)
        with self.assertRaises(worker.WorkerRefusal):
            worker.recover_crash_worker_status(self.exchange)
        self.assertEqual(target.read_text(), "keep")

    def test_world_writable_status_temp_is_rejected(self) -> None:
        if os.name != "posix":
            self.skipTest("Windows does not expose POSIX write permissions")
        orphan = self.exchange / ORPHAN
        orphan.write_text("keep")
        orphan.chmod(0o666)
        if not (stat.S_IMODE(orphan.stat().st_mode) & 0o022):
            self.skipTest("host filesystem did not retain writable mode")
        with self.assertRaises(worker.WorkerRefusal):
            worker.recover_crash_worker_status(self.exchange)

    def test_atomic_write_exception_does_not_leave_new_temp(self) -> None:
        target = self.exchange / "worker.json"
        with mock.patch.object(worker.os, "replace", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                worker._write_json(target, {"status": "ready"}, mode=0o644)
        self.assertEqual(list(self.exchange.glob(".worker.json.*.tmp")), [])
        self.assertEqual(target.read_text(), "{}")

    def test_exclusive_create_failure_does_not_remove_preexisting_temp(self) -> None:
        target = self.exchange / "worker.json"
        existing = self.exchange / ".worker.json.123.1793942308964284383.tmp"
        existing.write_text("keep")
        with mock.patch.object(worker.os, "getpid", return_value=123), mock.patch.object(
            worker.time, "time_ns", return_value=1793942308964284383
        ):
            with self.assertRaises(FileExistsError):
                worker._write_json(target, {"status": "ready"}, mode=0o644)
        self.assertEqual(existing.read_text(), "keep")

    def test_prepare_recovers_before_publishing_worker_status(self) -> None:
        orphan = self.exchange / ORPHAN
        orphan.write_text("partial status")
        scratch = self.root / "scratch"
        scratch.mkdir()
        instance = worker.SolverWorker(
            self.exchange,
            platform_probe=lambda _: worker.PlatformAttestation(True, {}),
            process_assertion=lambda: None,
            scratch_root=scratch,
        )
        with mock.patch.object(worker, "harden_current_process"):
            outcome = instance.prepare()
        self.assertTrue(outcome.ready)
        self.assertFalse(orphan.exists())
        self.assertTrue((self.exchange / "worker.json").exists())

    def test_prepare_does_not_recover_before_clean_namespace_proof(self) -> None:
        orphan = self.exchange / ORPHAN
        orphan.write_text("partial status")
        scratch = self.root / "scratch"
        scratch.mkdir()

        def occupied() -> None:
            raise worker.WorkerRefusal("residual_processes", "occupied")

        instance = worker.SolverWorker(
            self.exchange,
            platform_probe=lambda _: worker.PlatformAttestation(True, {}),
            process_assertion=occupied,
            scratch_root=scratch,
        )
        with mock.patch.object(worker, "harden_current_process"):
            outcome = instance.prepare()
        self.assertFalse(outcome.ready)
        self.assertTrue(orphan.exists())

    def test_recovery_releases_draining_slot_without_weakening_idle_check(self) -> None:
        storage = self.root / "storage"
        slots = storage / "solver-exchange" / "slots"
        slot2 = slots / "solver-2"
        slot2.mkdir(parents=True)
        (slot2 / "runtime").mkdir()
        (slot2 / "worker.json").write_text("{}")
        (slot2 / "worker.lock").touch()
        scratch = storage / "solver-scratch" / "solver-2"
        scratch.mkdir(parents=True)
        orphan = slot2 / ORPHAN
        orphan.write_text("partial status")
        db = storage / "db-does-not-exist.sqlite3"
        self.assertEqual(
            solver_exchange.SolverCoordinatorPool._protected_slot_indices(db, storage, slots),
            {1, 2},
        )
        self.assertFalse(solver_autoscaler._slot_is_idle(storage, 2))
        worker.recover_crash_worker_status(slot2)
        self.assertEqual(
            solver_exchange.SolverCoordinatorPool._protected_slot_indices(db, storage, slots),
            {1},
        )
        self.assertTrue(solver_autoscaler._slot_is_idle(storage, 2))


if __name__ == "__main__":
    unittest.main()
