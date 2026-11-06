"""CTFd imports may reuse only a verified staged file from the same workspace."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.ctfd import CTFdClient, published_attachment_sha256
from ctf_agent.db import Settings
from ctf_agent.main import create_app


SOURCE = "https://ctf.example"
PAYLOAD = b"pre-uploaded challenge attachment\n" * 100
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FakeClient:
    def __init__(self, payload=PAYLOAD):
        self.url = SOURCE
        self.payload = payload
        self.file_count = 0
        self.limits = SimpleNamespace(files=10, file_bytes=1024 * 1024)
        self.downloads = 0
        self.cancel_event = None

    def download_to(self, url, partial, *, progress=None, **_kwargs):
        self.downloads += 1
        self.file_count += 1
        partial.write_bytes(self.payload)
        if progress:
            progress(len(self.payload), len(self.payload), "")
        return {"bytes": len(self.payload), "total": len(self.payload),
                "validator": "", "sha256": hashlib.sha256(self.payload).hexdigest()}

    def clear_credentials(self):
        pass


class StagedReuseTest(unittest.TestCase):
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
        self.workspace = self.new_workspace("Staging")
        self.other = self.new_workspace("Other")
        with self.app.state.connect() as db:
            self.owner = db.execute(
                "SELECT owner_user_id FROM workspaces WHERE id=?", (self.workspace,)
            ).fetchone()[0]

    def tearDown(self):
        self.browser.__exit__(None, None, None)
        self.temporary.cleanup()

    def new_workspace(self, name):
        result = self.browser.post("/api/workspaces", json={"name": name})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()["id"]

    def stage(self, workspace=None, payload=PAYLOAD):
        workspace = workspace or self.workspace
        digest = hashlib.sha256(payload).hexdigest()
        base = f"/api/workspaces/{workspace}/staged-files"
        result = self.browser.post(base, json={
            "name": "fileSystem.qcow2.7z", "size": len(payload), "sha256": digest,
        })
        self.assertEqual(result.status_code, 201, result.text)
        file_id = result.json()["id"]
        result = self.browser.put(
            f"{base}/{file_id}/chunks?offset=0", content=payload,
            headers={"content-type": "application/octet-stream"},
        )
        self.assertEqual(result.status_code, 200, result.text)
        result = self.browser.post(f"{base}/{file_id}/finalize")
        self.assertEqual(result.status_code, 200, result.text)
        return self.app.state.staged_files.path(
            {"id": file_id, "workspace_id": workspace}, "ready"
        )

    def run_import(self, *, workspace=None, published="", mode="import",
                   target=None, payload=PAYLOAD, remote_id=7):
        workspace = workspace or self.workspace
        job_id = uuid4().hex
        jobs = self.app.state.ctfd_jobs
        with jobs.db() as db:
            db.execute(
                """INSERT INTO ctfd_jobs
                   (id,owner_user_id,workspace_id,source_url,auth_type,
                    mode,target_challenge_id,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (job_id, self.owner, workspace, SOURCE, "token", mode,
                 target, "queued", "now", "now"),
            )
        source = {"url": SOURCE + "/files/fileSystem.qcow2.7z",
                  "name": "fileSystem.qcow2.7z"}
        if published:
            source["published_sha256"] = published
        remote = {"id": remote_id, "name": "Forensics", "category": "misc",
                  "description": "file", "remote": "", "files": [source]}
        client = FakeClient(payload)
        jobs._run_leased(
            job_id, workspace, self.owner, client,
            {"errors": [], "challenges": [remote]}, None, threading.Event(),
        )
        job = jobs.get(workspace, {"id": self.owner}, job_id)
        with jobs.db() as db:
            row = db.execute(
                "SELECT * FROM ctfd_job_files WHERE job_id=?", (job_id,)
            ).fetchone()
            mapping = db.execute(
                "SELECT challenge_id FROM ctfd_job_challenges WHERE job_id=?",
                (job_id,),
            ).fetchone()
            provenance = db.execute(
                "SELECT * FROM ctfd_managed_attachments WHERE attachment_id=?",
                (row["id"],),
            ).fetchone() if row else None
        return client, job, row, mapping, provenance

    def test_single_file_published_hash_is_explicit(self):
        self.assertEqual(published_attachment_sha256("SHA-256: " + DIGEST, 1), DIGEST)
        self.assertEqual(published_attachment_sha256("SHA-256: " + DIGEST, 2), "")
        self.assertEqual(published_attachment_sha256("hash " + DIGEST, 1), "")
        self.assertEqual(published_attachment_sha256(
            "SHA-256: " + DIGEST + "\nSHA-256: " + DIGEST, 1
        ), "")

    def test_preview_exposes_only_unambiguous_published_digest(self):
        client = CTFdClient(SOURCE)
        client.authenticate = lambda: None
        client._json = lambda url: (
            [{"id": 7, "name": "Forensics", "type": "standard"}]
            if url.endswith("/api/v1/challenges") else
            {"id": 7, "name": "Forensics", "type": "standard",
             "description": "SHA-256: " + DIGEST,
             "files": ["/files/fileSystem.qcow2.7z"]}
        )
        preview = client.preview()
        self.assertEqual(preview["challenges"][0]["files"][0]["published_sha256"], DIGEST)

    def test_published_hash_skips_remote_download_and_keeps_ctfd_provenance(self):
        staged = self.stage()
        client, job, row, mapping, provenance = self.run_import(published=DIGEST)
        self.assertEqual(client.downloads, 0)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["reused_without_download"], 1)
        self.assertEqual(job["downloaded_bytes"], 0)
        self.assertEqual(row["reuse_mode"], "published_hash")
        self.assertEqual(provenance["sha256"], DIGEST)
        destination = self.app.state.ctfd_jobs.path(
            self.workspace, "challenges", mapping["challenge_id"],
            "attachments", row["id"],
        )
        self.assertTrue(os.path.samefile(staged, destination))

    def test_missing_hash_downloads_then_reuses_same_workspace_file(self):
        staged = self.stage()
        client, job, row, mapping, provenance = self.run_import()
        self.assertEqual(client.downloads, 1)
        self.assertEqual(job["downloaded_then_reused"], 1)
        self.assertEqual(job["downloaded_bytes"], len(PAYLOAD))
        self.assertEqual(row["reuse_mode"], "after_download")
        self.assertIsNotNone(provenance)
        destination = self.app.state.ctfd_jobs.path(
            self.workspace, "challenges", mapping["challenge_id"],
            "attachments", row["id"],
        )
        self.assertTrue(os.path.samefile(staged, destination))

    def test_other_workspace_and_changed_staged_file_are_not_reused(self):
        self.stage(self.other)
        client, job, row, _mapping, _provenance = self.run_import(published=DIGEST)
        self.assertEqual(client.downloads, 1)
        self.assertEqual(row["reuse_mode"], "")

        staged = self.stage()
        staged.chmod(0o640)
        staged.write_bytes(b"X" * len(PAYLOAD))
        client, job, row, _mapping, _provenance = self.run_import(
            published=DIGEST, payload=PAYLOAD, remote_id=8,
        )
        self.assertEqual(client.downloads, 1)
        self.assertEqual(row["reuse_mode"], "")

    def test_refresh_downloads_and_keeps_independent_generation(self):
        staged = self.stage()
        _client, job, _row, mapping, _provenance = self.run_import(published=DIGEST)
        self.assertEqual(job["status"], "completed")
        client, job, row, _mapping, provenance = self.run_import(
            published=DIGEST, mode="refresh", target=mapping["challenge_id"],
        )
        self.assertEqual(client.downloads, 1)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(row["reuse_mode"], "")
        destination = self.app.state.ctfd_jobs.path(
            self.workspace, "challenges", mapping["challenge_id"],
            "attachments", row["id"],
        )
        self.assertFalse(os.path.samefile(staged, destination))
        self.assertIsNotNone(provenance)


if __name__ == "__main__":
    unittest.main()
