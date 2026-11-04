"""Offline owner-scoped resumable bundle-upload regression checks."""

from __future__ import annotations

import gc
import hashlib
import sys
import tempfile
import threading
import unittest
import warnings
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings, connect, initialize  # noqa: E402
from ctf_agent.transfer_uploads import (  # noqa: E402
    TransferUploadError, TransferUploadManager,
)


class BundleUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ctf-bundle-upload-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.settings = Settings(
            data_dir=root / "data", db_dir=root / "db", config_dir=root / "config",
            log_dir=root / "logs", storage_min_free_bytes=0,
        )
        initialize(self.settings)
        self.manager = TransferUploadManager(self.settings)
        with closing(connect(self.settings)) as db:
            self.owner = db.execute(
                "SELECT value FROM meta WHERE key='legacy_owner_id'"
            ).fetchone()[0]

    def tearDown(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            gc.collect()

    def test_resume_finalize_and_import_slot(self):
        payload = b"abcdef"
        digest = hashlib.sha256(payload).hexdigest()
        created = self.manager.create(self.owner, len(payload), digest)
        upload_id = created["upload_id"]
        self.assertEqual((created["offset"], created["status"]), (0, "uploading"))
        self.manager.append(self.owner, upload_id, 0, b"abc")
        replay = self.manager.append(self.owner, upload_id, 0, b"abc")
        self.assertEqual(replay["offset"], 3)
        with self.assertRaisesRegex(TransferUploadError, "differs"):
            self.manager.append(self.owner, upload_id, 0, b"BAD")
        self.manager.append(self.owner, upload_id, 3, b"def")
        ready = self.manager.finalize(self.owner, upload_id)
        self.assertEqual((ready["offset"], ready["status"], ready["sha256"]),
                         (6, "ready", digest))
        self.assertEqual(self.manager.finalize(self.owner, upload_id), ready)
        with self.assertRaisesRegex(RuntimeError, "retry"):
            with self.manager.import_slot(self.owner, upload_id) as path:
                self.assertEqual(path.read_bytes(), payload)
                raise RuntimeError("retry")
        self.assertEqual(self.manager.status(self.owner, upload_id)["status"], "ready")
        with self.manager.import_slot(self.owner, upload_id) as path:
            self.assertEqual(path.read_bytes(), payload)
        self.assertEqual(self.manager.status(self.owner, upload_id)["status"], "consumed")
        with self.assertRaises(TransferUploadError):
            self.manager.ready_path(self.owner, upload_id)

    def test_owner_scope_limits_and_disk_floor(self):
        first = self.manager.create(self.owner, 0)["upload_id"]
        second = self.manager.create(self.owner, 0)["upload_id"]
        with self.assertRaisesRegex(TransferUploadError, "Too many"):
            self.manager.create(self.owner, 0)
        with self.assertRaises(TransferUploadError):
            self.manager.status("0" * 32, first)
        with self.assertRaises(TransferUploadError):
            self.manager.create(self.owner, 2**63 - 1)
        self.manager.cancel(self.owner, second)
        self.assertEqual(self.manager.status(self.owner, second)["status"], "cancelled")
        third = self.manager.create(self.owner, 0)["upload_id"]
        self.assertNotEqual(third, first)

    def test_crash_tail_truncation_and_digest_mismatch(self):
        created = self.manager.create(self.owner, 4, hashlib.sha256(b"good").hexdigest())
        upload_id = created["upload_id"]
        stage = self.manager._stage(self.owner, upload_id)
        stage.write_bytes(b"orphan crash tail")
        self.manager.append(self.owner, upload_id, 0, b"bad!")
        self.assertEqual(stage.read_bytes(), b"bad!")
        with self.assertRaisesRegex(TransferUploadError, "SHA-256"):
            self.manager.finalize(self.owner, upload_id)
        self.assertEqual(self.manager.status(self.owner, upload_id)["status"], "uploading")

    def test_concurrent_import_is_refused(self):
        upload_id = self.manager.create(self.owner, 0)["upload_id"]
        self.manager.finalize(self.owner, upload_id)
        entered = threading.Event()
        release = threading.Event()
        errors: list[str] = []

        def first_import():
            try:
                with self.manager.import_slot(self.owner, upload_id):
                    entered.set()
                    release.wait(5)
            except Exception as exc:
                errors.append(str(exc))

        worker = threading.Thread(target=first_import)
        worker.start()
        self.assertTrue(entered.wait(5))
        try:
            with self.assertRaisesRegex(TransferUploadError, "in progress"):
                with self.manager.import_slot(self.owner, upload_id):
                    pass
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(errors)
        self.assertEqual(self.manager.status(self.owner, upload_id)["status"], "consumed")

    def test_stale_cleanup_removes_only_owned_stage(self):
        first = self.manager.create(self.owner, 3)["upload_id"]
        second = self.manager.create(self.owner, 1)["upload_id"]
        stage = self.manager._stage(self.owner, first)
        with closing(connect(self.settings)) as db, db:
            db.execute("UPDATE transfer_upload_sessions SET updated_at=1 WHERE id=?",
                       (first,))
        self.assertEqual(self.manager.cleanup_stale(older_than_seconds=1), 1)
        self.assertEqual(self.manager.status(self.owner, first)["status"], "expired")
        self.assertFalse(stage.exists())
        self.assertEqual(self.manager.status(self.owner, second)["status"], "uploading")


if __name__ == "__main__":
    unittest.main()
