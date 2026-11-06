"""Regression checks for pre-uploaded workspace files and multi-GB chunk semantics."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.main import create_app


class StagedFileApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.temporary.name)
        self.settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        self.app = create_app(self.settings)
        self.browser = TestClient(self.app)
        self.browser.__enter__()
        csrf = self.browser.get("/api/auth/state").json()["csrf_token"]
        self.browser.headers.update({"x-csrf-token": csrf})
        created = self.browser.post("/api/workspaces", json={"name": "Final"})
        self.assertEqual(created.status_code, 201, created.text)
        self.workspace = created.json()["id"]
        other = self.browser.post("/api/workspaces", json={"name": "Other"})
        self.assertEqual(other.status_code, 201, other.text)
        self.other = other.json()["id"]

    def tearDown(self):
        self.browser.__exit__(None, None, None)
        self.temporary.cleanup()

    def challenge(self, name: str, workspace: str | None = None) -> str:
        where = workspace or self.workspace
        created = self.browser.post(
            f"/api/workspaces/{where}/challenges", json={"name": name},
        )
        self.assertEqual(created.status_code, 201, created.text)
        return created.json()["id"]

    def test_resumable_staging_multi_challenge_and_independent_delete(self):
        one = self.challenge("first")
        two = self.challenge("second")
        foreign = self.challenge("foreign", self.other)
        payload = b"A" * (8 * 1024 * 1024) + b"tail"
        digest = hashlib.sha256(payload).hexdigest()
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={
            "name": "fileSystem.qcow2.7z", "size": len(payload),
            "sha256": digest,
        })
        self.assertEqual(created.status_code, 201, created.text)
        file_id = created.json()["id"]
        file_url = f"{base}/{file_id}"
        first = self.browser.put(
            file_url + "/chunks?offset=0", content=payload[:-4],
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["offset"], len(payload) - 4)
        replay = self.browser.put(
            file_url + "/chunks?offset=0", content=payload[:-4],
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        manifest = self.browser.get(file_url + "/chunks")
        self.assertEqual(manifest.status_code, 200, manifest.text)
        self.assertEqual(manifest.json()["chunks"][0]["size"], len(payload) - 4)
        last = self.browser.put(
            file_url + f"/chunks?offset={len(payload) - 4}", content=payload[-4:],
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(last.status_code, 200, last.text)
        final = self.browser.post(file_url + "/finalize")
        self.assertEqual(final.status_code, 200, final.text)
        self.assertEqual(final.json()["sha256"], digest)
        self.assertEqual(final.json()["status"], "ready")
        self.assertEqual(final.json()["storage_path"],
                         f"workspaces/{self.workspace}/.staged/{file_id}.ready")
        self.assertEqual(self.browser.post(file_url + "/finalize").status_code, 200)
        self.assertEqual(self.browser.get(file_url + "/content").content, payload)

        wrong = self.browser.post(
            f"/api/workspaces/{self.other}/challenges/{foreign}/staged-files/{file_id}/attach"
        )
        self.assertEqual(wrong.status_code, 404, wrong.text)
        linked = []
        for challenge in (one, two):
            url = f"/api/workspaces/{self.workspace}/challenges/{challenge}/staged-files/{file_id}/attach"
            attached = self.browser.post(url)
            self.assertEqual(attached.status_code, 200, attached.text)
            self.assertEqual(self.browser.post(url).json()["id"], attached.json()["id"])
            linked.append((challenge, attached.json()["id"]))
        listing = self.browser.get(base).json()["files"]
        self.assertEqual(listing[0]["linked_count"], 2)
        ready_path = self.app.state.staged_files.path(
            {"id": file_id, "workspace_id": self.workspace}, "ready"
        )
        for challenge, attachment_id in linked:
            destination = self.app.state.storage_layout.legacy_attachment_path(
                self.workspace, challenge, attachment_id,
            )
            self.assertTrue(os.path.samefile(ready_path, destination))
        removed = self.browser.delete(file_url)
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertEqual(self.browser.get(file_url).status_code, 404)
        for challenge, attachment_id in linked:
            response = self.browser.get(
                f"/api/workspaces/{self.workspace}/challenges/{challenge}/attachments/{attachment_id}"
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.content, payload)

    def test_restart_and_sha_mismatch(self):
        base = f"/api/workspaces/{self.workspace}/staged-files"
        body = b"some staged data"
        created = self.browser.post(base, json={
            "name": "early.bin", "size": len(body),
            "sha256": hashlib.sha256(b"different").hexdigest(),
        })
        self.assertEqual(created.status_code, 201, created.text)
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        sent = self.browser.put(
            endpoint + "/chunks?offset=0", content=body,
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(sent.status_code, 200, sent.text)
        self.assertEqual(self.browser.post(endpoint + "/finalize").status_code, 409)
        self.assertEqual(self.browser.get(endpoint).json()["status"], "uploading")
        second_app = create_app(self.settings)
        with TestClient(second_app) as second_browser:
            second_browser.headers.update({
                "x-csrf-token": second_browser.get("/api/auth/state").json()["csrf_token"]
            })
            self.assertEqual(second_browser.get(endpoint).json()["offset"], len(body))
            self.assertEqual(second_browser.delete(endpoint).status_code, 200)
            self.assertEqual(second_browser.get(endpoint).status_code, 404)

    def test_cancelled_reconcile_does_not_block_workspace_deletion(self):
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "partial.bin", "size": 5})
        self.assertEqual(created.status_code, 201, created.text)
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        sent = self.browser.put(
            endpoint + "/chunks?offset=0", content=b"ab",
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(sent.status_code, 200, sent.text)
        part = self.app.state.staged_files.path(
            {"id": file_id, "workspace_id": self.workspace}, "part"
        )
        part.unlink()
        restarted = create_app(self.settings)
        with restarted.state.connect() as db:
            status = db.execute(
                "SELECT status FROM workspace_staged_files WHERE id=?", (file_id,)
            ).fetchone()[0]
        self.assertEqual(status, "cancelled")
        deleted = self.browser.delete(f"/api/workspaces/{self.workspace}")
        self.assertEqual(deleted.status_code, 200, deleted.text)
        with restarted.state.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM workspace_staged_files WHERE workspace_id=?",
                (self.workspace,),
            ).fetchone()[0], 0)

    def test_copy_mode_and_missing_ready_file(self):
        challenge = self.challenge("copy")
        body = b"independent bytes"
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "sample.bin", "size": len(body)})
        self.assertEqual(created.status_code, 201, created.text)
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        sent = self.browser.put(
            endpoint + "/chunks?offset=0", content=body,
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(sent.status_code, 200, sent.text)
        self.assertEqual(self.browser.post(endpoint + "/finalize").status_code, 200)
        ready = self.app.state.staged_files.path(
            {"id": file_id, "workspace_id": self.workspace}, "ready"
        )
        missing = ready.with_name("temporary-missing")
        ready.rename(missing)
        restarted = create_app(self.settings)
        with TestClient(restarted) as browser:
            browser.headers.update({
                "x-csrf-token": browser.get("/api/auth/state").json()["csrf_token"]
            })
            self.assertFalse(browser.get(endpoint).json()["file_available"])
            self.assertEqual(browser.post(
                f"/api/workspaces/{self.workspace}/challenges/{challenge}/staged-files/{file_id}/attach"
            ).status_code, 409)
        missing.rename(ready)
        attached = self.browser.post(
            f"/api/workspaces/{self.workspace}/challenges/{challenge}/staged-files/{file_id}/attach?mode=copy"
        )
        self.assertEqual(attached.status_code, 200, attached.text)
        self.assertEqual(attached.json()["storage_mode"], "copy")
        canonical = self.app.state.storage_layout.legacy_attachment_path(
            self.workspace, challenge, attached.json()["id"],
        )
        self.assertFalse(os.path.samefile(ready, canonical))
        self.assertEqual(self.browser.delete(endpoint).status_code, 200)
        self.assertEqual(canonical.read_bytes(), body)

    def test_very_large_declared_size_keeps_chunked_upload(self):
        base = f"/api/workspaces/{self.workspace}/staged-files"
        declared_size = 20 * 1024**3 + 123
        created = self.browser.post(base, json={
            "name": "disk.qcow2.7z", "size": declared_size,
        })
        self.assertEqual(created.status_code, 201, created.text)
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        piece = b"Z" * (8 * 1024 * 1024)
        sent = self.browser.put(
            endpoint + "/chunks?offset=0", content=piece,
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(sent.status_code, 200, sent.text)
        self.assertEqual(sent.json()["size"], declared_size)
        self.assertEqual(sent.json()["offset"], len(piece))
        self.assertEqual(len(self.browser.get(endpoint + "/chunks").json()["chunks"]), 1)
        self.assertEqual(self.browser.delete(endpoint).status_code, 200)

    def test_attach_during_solver_uses_live_attachment_watcher(self):
        challenge = self.challenge("running")
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "late.bin", "size": 4})
        self.assertEqual(created.status_code, 201, created.text)
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        self.assertEqual(self.browser.put(
            endpoint + "/chunks?offset=0", content=b"late",
            headers={"content-type": "application/octet-stream"},
        ).status_code, 200)
        self.assertEqual(self.browser.post(endpoint + "/finalize").status_code, 200)
        original = self.app.state.solver_jobs.has_open_challenge
        self.app.state.solver_jobs.has_open_challenge = lambda *_args, **_kwargs: True
        try:
            attached = self.browser.post(
                f"/api/workspaces/{self.workspace}/challenges/{challenge}/staged-files/{file_id}/attach"
            )
        finally:
            self.app.state.solver_jobs.has_open_challenge = original
        self.assertEqual(attached.status_code, 200, attached.text)
        downloaded = self.browser.get(
            f"/api/workspaces/{self.workspace}/challenges/{challenge}/attachments/{attached.json()['id']}"
        )
        self.assertEqual(downloaded.content, b"late")

    def test_unchanged_file_attach_skips_rehash_but_change_is_rejected(self):
        first = self.challenge("first")
        second = self.challenge("second")
        third = self.challenge("third")
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "cached.bin", "size": 4})
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        self.assertEqual(self.browser.put(
            endpoint + "/chunks?offset=0", content=b"data",
            headers={"content-type": "application/octet-stream"},
        ).status_code, 200)
        self.assertEqual(self.browser.post(endpoint + "/finalize").status_code, 200)
        manager = self.app.state.staged_files
        with patch.object(manager, "hash_stable_file", side_effect=AssertionError("unexpected rehash")):
            self.assertEqual(self.browser.post(
                f"/api/workspaces/{self.workspace}/challenges/{first}/staged-files/{file_id}/attach"
            ).status_code, 200)
            self.assertEqual(self.browser.post(
                f"/api/workspaces/{self.workspace}/challenges/{second}/staged-files/{file_id}/attach"
            ).status_code, 200)
        source = manager.path({"id": file_id, "workspace_id": self.workspace}, "ready")
        old = source.stat().st_mtime_ns
        os.utime(source, ns=(old + 1_000_000_000, old + 1_000_000_000))
        self.assertEqual(self.browser.post(
            f"/api/workspaces/{self.workspace}/challenges/{third}/staged-files/{file_id}/attach"
        ).status_code, 200)
        with source.open("r+b") as handle:
            handle.write(b"evil")
        os.utime(source, ns=(old + 2_000_000_000, old + 2_000_000_000))
        fourth = self.challenge("fourth")
        self.assertEqual(self.browser.post(
            f"/api/workspaces/{self.workspace}/challenges/{fourth}/staged-files/{file_id}/attach"
        ).status_code, 409)

    def test_async_finalize_status_and_restart_recovery(self):
        from ctf_agent import staged_files

        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "async.bin", "size": 5})
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        self.assertEqual(self.browser.put(
            endpoint + "/chunks?offset=0", content=b"async",
            headers={"content-type": "application/octet-stream"},
        ).status_code, 200)
        entered, release = threading.Event(), threading.Event()
        manager = self.app.state.staged_files
        original = manager.hash_stable_file

        def slow_hash(path, size):
            entered.set()
            self.assertTrue(release.wait(10))
            return original(path, size)

        with patch.object(staged_files, "ASYNC_VERIFY_BYTES", 1), patch.object(
            manager, "hash_stable_file", side_effect=slow_hash,
        ):
            started = self.browser.post(endpoint + "/finalize")
            self.assertEqual(started.status_code, 202, started.text)
            self.assertTrue(entered.wait(5))
            self.assertEqual(self.browser.get(endpoint).json()["status"], "verifying")
            self.assertEqual(self.browser.delete(endpoint).status_code, 409)
            release.set()
            for _ in range(100):
                status = self.browser.get(endpoint).json()
                if status["status"] == "ready":
                    break
                time.sleep(0.05)
            self.assertEqual(status["status"], "ready", status)

        interrupted = self.browser.post(base, json={"name": "interrupted.bin", "size": 9})
        interrupted_id = interrupted.json()["id"]
        with self.app.state.connect() as db:
            db.execute(
                "UPDATE workspace_staged_files SET verifying=1 WHERE id=?",
                (interrupted_id,),
            )
        restarted = create_app(self.settings)
        with TestClient(restarted) as other:
            result = other.get(f"{base}/{interrupted_id}").json()
            self.assertEqual(result["status"], "uploading", result)
            self.assertIn("interrupted", result["verification_error"])

    def test_cleanup_rechecks_expiry_and_process_lock(self):
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "old.bin", "size": 12})
        file_id = created.json()["id"]
        manager = self.app.state.staged_files
        other = create_app(self.settings).state.staged_files
        old = int(time.time()) - 9 * 86400
        with self.app.state.connect() as db:
            db.execute(
                "UPDATE workspace_staged_files SET updated_at=? WHERE id=?", (old, file_id)
            )
        process_lock = manager.app.state.uploads.process_workspace_lock(self.workspace)
        self.assertTrue(process_lock.try_acquire())
        try:
            other.cleanup()
            self.assertEqual(self.browser.get(f"{base}/{file_id}").status_code, 200)
            with self.app.state.connect() as db:
                db.execute(
                    "UPDATE workspace_staged_files SET updated_at=? WHERE id=?",
                    (int(time.time()), file_id),
                )
        finally:
            process_lock.release()
        other.cleanup()
        self.assertEqual(self.browser.get(f"{base}/{file_id}").status_code, 200)
        with self.app.state.connect() as db:
            db.execute(
                "UPDATE workspace_staged_files SET updated_at=? WHERE id=?", (old, file_id)
            )
        other.cleanup()
        self.assertEqual(self.browser.get(f"{base}/{file_id}").status_code, 404)

    def test_missing_workspace_storage_does_not_break_startup(self):
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "missing.bin", "size": 12})
        file_id = created.json()["id"]
        storage = self.app.state.storage_layout.legacy_workspace_path(self.workspace)
        shutil.rmtree(storage)
        restarted = create_app(self.settings)
        with TestClient(restarted) as other:
            self.assertEqual(other.get(f"{base}/{file_id}").status_code, 200)

    def test_copy_crash_gap_reclaims_orphan_and_reservation(self):
        challenge = self.challenge("orphan copy")
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "staged.bin", "size": 4})
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        self.assertEqual(self.browser.put(
            endpoint + "/chunks?offset=0", content=b"data",
            headers={"content-type": "application/octet-stream"},
        ).status_code, 200)
        self.assertEqual(self.browser.post(endpoint + "/finalize").status_code, 200)
        manager = self.app.state.staged_files
        destination = self.app.state.storage_layout.legacy_attachment_path(
            self.workspace, challenge, manager.attachment_id(file_id, challenge),
            create_parent=True,
        )
        destination.write_bytes(b"data")
        reservation = manager.copy_reservation(file_id, challenge)
        manager.budget.reserve(
            reservation, "staged-copy", self.browser.get("/api/auth/state").json()["user"]["id"],
            self.workspace, challenge, 4,
        )
        restarted = create_app(self.settings)
        self.assertFalse(destination.exists())
        self.assertFalse(restarted.state.storage_budget.snapshot(kind="staged-copy"))
        self.assertEqual(self.browser.post(
            f"/api/workspaces/{self.workspace}/challenges/{challenge}/staged-files/{file_id}/attach?mode=copy"
        ).status_code, 200)

    def test_attachment_directory_sync_and_copy_retry_release(self):
        first = self.challenge("linked")
        second = self.challenge("copied")
        base = f"/api/workspaces/{self.workspace}/staged-files"
        created = self.browser.post(base, json={"name": "durable.bin", "size": 4})
        file_id = created.json()["id"]
        endpoint = f"{base}/{file_id}"
        self.assertEqual(self.browser.put(
            endpoint + "/chunks?offset=0", content=b"data",
            headers={"content-type": "application/octet-stream"},
        ).status_code, 200)
        self.assertEqual(self.browser.post(endpoint + "/finalize").status_code, 200)
        manager = self.app.state.staged_files
        user = self.browser.get("/api/auth/state").json()["user"]
        linked_path = self.app.state.storage_layout.legacy_attachment_path(
            self.workspace, first, manager.attachment_id(file_id, first),
            create_parent=True,
        )
        with patch.object(manager, "sync_directory", wraps=manager.sync_directory) as sync:
            manager.attach(self.workspace, first, file_id, user, "link")
            sync.assert_called_once_with(linked_path.parent)

        copied_path = self.app.state.storage_layout.legacy_attachment_path(
            self.workspace, second, manager.attachment_id(file_id, second),
            create_parent=True,
        )
        with patch.object(manager, "sync_directory", side_effect=OSError("fsync failed")):
            with self.assertRaises(HTTPException) as failure:
                manager.attach(self.workspace, second, file_id, user, "copy")
        self.assertEqual(failure.exception.status_code, 503)
        self.assertTrue(copied_path.exists())
        self.assertTrue(manager.budget.snapshot(kind="staged-copy"))
        resumed = manager.attach(self.workspace, second, file_id, user, "copy")
        self.assertEqual(resumed["storage_mode"], "copy")
        self.assertFalse(manager.budget.snapshot(kind="staged-copy"))


if __name__ == "__main__":
    unittest.main()
