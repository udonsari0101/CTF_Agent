"""Offline install-to-install invitation, retry, and sender-policy checks."""

from __future__ import annotations

import gc
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import uuid
import warnings
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

warnings.filterwarnings("ignore", category=ResourceWarning, message=r"unclosed database.*")

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings, connect, initialize  # noqa: E402
from ctf_agent.direct_transfer import (  # noqa: E402
    DirectInvitationManager, DirectTransferError,
)
from ctf_agent.direct_transfer_client import (  # noqa: E402
    DirectTransferClient, DirectTransferClientError, _normalize_invitation_url,
)
from ctf_agent.direct_transfer_jobs import DirectSendJobs  # noqa: E402
from ctf_agent.direct_transfer_outbox import DirectTransferOutbox  # noqa: E402
from ctf_agent.storage_layout import StorageLayout  # noqa: E402
from ctf_agent.transfer_uploads import (  # noqa: E402
    MIN_FREE_BYTES, TransferUploadError, TransferUploadManager,
)
from ctf_agent.workspace_transfer import export_challenge, export_workspace  # noqa: E402
from ctf_agent.main import create_app  # noqa: E402
from ctf_agent.transfer_export_cleanup import (  # noqa: E402
    EXPORT_TTL_SECONDS, TransferExportManager,
)


class DirectTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ctf-direct-transfer-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = self._installation(root / "source", "https://source.example")
        self.target = self._installation(root / "target", "https://receiver.example")
        self.source_workspace = self._workspace(self.source, "Source workspace")
        self.source_challenge = uuid.uuid4().hex
        stamp = "2026-11-04T00:00:00+00:00"
        with closing(connect(self.source[0])) as db, db:
            db.execute(
                """INSERT INTO challenges(id,workspace_id,name,category,description,
                   status,notes,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (self.source_challenge, self.source_workspace, "Puzzle", "web",
                 "Challenge text", "pending", "Private notes", stamp, stamp),
            )
        self.uploads = TransferUploadManager(self.target[0])
        self.manager = DirectInvitationManager(self.target[0], self.uploads, self.target[2])
        self.workspace_bundle = root / "workspace.zip"
        export_workspace(
            self.source[0], self.source[2], self.source[1], self.source_workspace,
            self.workspace_bundle,
        )

    def tearDown(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            gc.collect()

    @staticmethod
    def _installation(root: Path, origin: str):
        settings = Settings(
            data_dir=root / "data", db_dir=root / "db",
            config_dir=root / "config", log_dir=root / "logs",
            public_origin=origin, storage_min_free_bytes=0,
        )
        initialize(settings)

        @contextmanager
        def database():
            db = connect(settings)
            try:
                with db:
                    yield db
            finally:
                db.close()

        layout = StorageLayout(settings, database)
        with closing(connect(settings)) as db:
            owner = db.execute(
                "SELECT value FROM meta WHERE key='legacy_owner_id'"
            ).fetchone()[0]
        return settings, owner, layout

    @staticmethod
    def _workspace(installation, name: str) -> str:
        settings, owner, _layout = installation
        workspace_id = uuid.uuid4().hex
        stamp = "2026-11-04T00:00:00+00:00"
        with closing(connect(settings)) as db, db:
            db.execute(
                """INSERT INTO workspaces(id,name,description,flag_format,
                   open_challenge_after_create,created_at,updated_at,owner_user_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (workspace_id, name, "", None, 0, stamp, stamp, owner),
            )
        return workspace_id

    def _offer(self, archive: Path, scope: str, destination: str | None = None):
        data = archive.read_bytes()
        invite = self.manager.create(
            self.target[1], scope, destination, len(data), 3600,
        )
        return invite, data, hashlib.sha256(data).hexdigest()

    def test_workspace_invitation_resumes_and_imports_once(self):
        invite, data, digest = self._offer(self.workspace_bundle, "workspace")
        invitation_id, token = invite["invitation_id"], invite["token"]
        self.assertEqual(invite["url"],
                         f"https://receiver.example/api/transfers/direct/invitations/{invitation_id}")
        self.assertNotIn(token, json.dumps(self.manager.status(self.target[1], invitation_id)))
        with self.assertRaises(DirectTransferError):
            self.manager.prepare(invitation_id, "wrong" * 10, "workspace", len(data), digest)
        with self.assertRaises(DirectTransferError):
            self.manager.prepare(invitation_id, token, "challenge", len(data), digest)
        started = self.manager.prepare(invitation_id, token, "workspace", len(data), digest)
        self.assertEqual(started["offset"], 0)
        first = data[:30]
        self.manager.append(invitation_id, token, 0, first, hashlib.sha256(first).hexdigest())
        # Reconstruct both managers, as after a process restart, and resume
        # from durable offset rather than sending a second bundle.
        self.uploads = TransferUploadManager(self.target[0])
        self.manager = DirectInvitationManager(self.target[0], self.uploads, self.target[2])
        self.assertEqual(
            self.manager.append(invitation_id, token, 0, first, hashlib.sha256(first).hexdigest())["offset"],
            len(first),
        )
        with self.assertRaises(TransferUploadError):
            self.manager.append(invitation_id, token, 0, b"bad", hashlib.sha256(b"bad").hexdigest())
        with self.assertRaises(DirectTransferError):
            self.manager.prepare(invitation_id, token, "workspace", len(data), "0" * 64)
        self.assertEqual(
            self.manager.prepare(invitation_id, token, "workspace", len(data), digest)["offset"],
            len(first),
        )
        with self.assertRaises(TransferUploadError):
            self.manager.complete(invitation_id, token)
        rest = data[len(first):]
        self.manager.append(invitation_id, token, len(first), rest,
                            hashlib.sha256(rest).hexdigest())
        result = self.manager.complete(invitation_id, token)
        self.assertEqual(self.manager.complete(invitation_id, token), result)
        self.assertEqual(
            self.manager.prepare(invitation_id, token, "workspace", len(data), digest)["status"],
            "completed",
        )
        self.assertNotEqual(result["workspace_id"], self.source_workspace)
        with closing(connect(self.target[0])) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0], 1)

    def test_challenge_scope_destination_expiry_and_revoke(self):
        destination = self._workspace(self.target, "Destination")
        challenge_bundle = Path(self.temp.name) / "challenge.zip"
        export_challenge(
            self.source[0], self.source[2], self.source[1], self.source_workspace,
            self.source_challenge, challenge_bundle,
        )
        invite, data, digest = self._offer(challenge_bundle, "challenge", destination)
        invitation_id, token = invite["invitation_id"], invite["token"]
        self.manager.prepare(invitation_id, token, "challenge", len(data), digest)
        self.manager.append(invitation_id, token, 0, data, digest)
        result = self.manager.complete(invitation_id, token)
        self.assertEqual(result["workspace_id"], destination)
        with closing(connect(self.target[0])) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM challenges WHERE workspace_id=?", (destination,),
            ).fetchone()[0], 1)
        expired, _data, _digest = self._offer(self.workspace_bundle, "workspace")
        with closing(connect(self.target[0])) as db, db:
            db.execute("UPDATE direct_transfer_invitations SET expires_at=1 WHERE id=?",
                       (expired["invitation_id"],))
        with self.assertRaisesRegex(DirectTransferError, "expired"):
            self.manager.prepare(expired["invitation_id"], expired["token"],
                                 "workspace", len(data), digest)
        self.assertEqual(self.manager.cleanup_expired(), 1)
        self.assertEqual(self.manager.status(self.target[1], expired["invitation_id"])["status"],
                         "expired")
        revoked, _data, _digest = self._offer(self.workspace_bundle, "workspace")
        self.manager.revoke(self.target[1], revoked["invitation_id"])
        with self.assertRaises(DirectTransferError):
            self.manager.prepare(revoked["invitation_id"], revoked["token"],
                                 "workspace", len(data), digest)

    def test_terminal_invitation_retries_busy_upload_cleanup(self):
        for ending in ("revoked", "expired"):
            with self.subTest(ending=ending):
                invite, data, digest = self._offer(self.workspace_bundle, "workspace")
                invitation_id = invite["invitation_id"]
                self.manager.prepare(invitation_id, invite["token"],
                                     "workspace", len(data), digest)
                self.manager.append(invitation_id, invite["token"], 0,
                                    data[:30], hashlib.sha256(data[:30]).hexdigest())
                with closing(connect(self.target[0])) as db:
                    upload_id = db.execute(
                        "SELECT upload_id FROM direct_transfer_invitations WHERE id=?",
                        (invitation_id,),
                    ).fetchone()[0]
                stage = self.uploads._stage(self.target[1], upload_id)
                self.assertTrue(stage.exists())
                if ending == "expired":
                    with closing(connect(self.target[0])) as db, db:
                        db.execute(
                            "UPDATE direct_transfer_invitations SET expires_at=1 WHERE id=?",
                            (invitation_id,),
                        )
                with self.uploads._exclusive(upload_id):
                    if ending == "revoked":
                        self.manager.revoke(self.target[1], invitation_id)
                    else:
                        self.assertEqual(self.manager.cleanup_expired(), 1)
                    self.assertTrue(stage.exists())
                    self.assertEqual(self.manager.status(self.target[1], invitation_id)["status"],
                                     ending)
                self.assertEqual(self.manager.cleanup_expired(), 0)
                self.assertFalse(stage.exists())
                self.assertEqual(self.uploads.status(self.target[1], upload_id)["status"],
                                 "cancelled")
                with closing(connect(self.target[0])) as db:
                    self.assertIsNone(db.execute(
                        "SELECT upload_id FROM direct_transfer_invitations WHERE id=?",
                        (invitation_id,),
                    ).fetchone()[0])

    def test_ready_bundle_rechecks_owner_and_disk_floor(self):
        invite, data, digest = self._offer(self.workspace_bundle, "workspace")
        invitation_id, token = invite["invitation_id"], invite["token"]
        with patch("ctf_agent.transfer_uploads.shutil.disk_usage",
                   return_value=SimpleNamespace(free=MIN_FREE_BYTES + len(data) - 1)):
            with self.assertRaisesRegex(TransferUploadError, "free space"):
                self.manager.prepare(invitation_id, token, "workspace", len(data), digest)
        self.assertEqual(self.manager.status(self.target[1], invitation_id)["status"], "issued")
        self.manager.prepare(invitation_id, token, "workspace", len(data), digest)
        self.manager.append(invitation_id, token, 0, data, digest)
        with closing(connect(self.target[0])) as db:
            upload_id = db.execute(
                "SELECT upload_id FROM direct_transfer_invitations WHERE id=?",
                (invitation_id,),
            ).fetchone()[0]
        self.uploads.finalize(self.target[1], upload_id)
        with closing(connect(self.target[0])) as db, db:
            db.execute("UPDATE users SET active=0 WHERE id=?", (self.target[1],))
        with self.assertRaises(DirectTransferError):
            self.manager.complete(invitation_id, token)
        self.assertEqual(self.uploads.status(self.target[1], upload_id)["status"], "ready")
        with closing(connect(self.target[0])) as db, db:
            db.execute("UPDATE users SET active=1 WHERE id=?", (self.target[1],))
        self.assertIn("workspace_id", self.manager.complete(invitation_id, token))

    def test_sender_url_dns_policy_and_resume(self):
        invitation_id = "a" * 32
        url = f"https://receiver.example/api/transfers/direct/invitations/{invitation_id}"
        for bad_url in (
            url.replace("https:", "http:"),
            url.replace("receiver.example", "127.0.0.1"),
            url.replace("receiver.example", "user:pass@receiver.example"),
            url + "?next=https://other.example", url + "/other",
        ):
            with self.assertRaises(DirectTransferClientError):
                _normalize_invitation_url(bad_url, set(), set())
        with self.assertRaises(DirectTransferClientError):
            _normalize_invitation_url(url, {"other.example"}, set())
        with self.assertRaises(DirectTransferClientError):
            _normalize_invitation_url(url, set(), {"receiver.example"})
        self.assertEqual(_normalize_invitation_url(url, set(), set())[0], "receiver.example")

        def mixed_dns(_host, _port, **_kwargs):
            return [(None, None, None, None, ("8.8.8.8", 443)),
                    (None, None, None, None, ("127.0.0.1", 443))]

        client = DirectTransferClient(resolver=mixed_dns)
        with self.assertRaises(DirectTransferClientError):
            client._address("receiver.example", 443)
        calls = []

        def fake_request(_host, _port, _path, _token, method, suffix, body, **kwargs):
            calls.append((method, suffix, body, kwargs))
            if suffix == "/prepare":
                return {"status": "uploading", "offset": 3}
            if suffix.startswith("/chunks"):
                return {"status": "uploading", "offset": 6}
            return {"workspace_id": "new"}

        archive = Path(self.temp.name) / "small.zip"
        archive.write_bytes(b"abcdef")
        with patch.object(client, "_request", side_effect=fake_request):
            self.assertEqual(client.send_bundle(url, "a" * 43, archive, scope="workspace"),
                             {"workspace_id": "new"})
        self.assertEqual(calls[1][1], "/chunks?offset=3")
        self.assertEqual(calls[1][2], b"def")
        self.assertEqual(calls[1][3]["chunk_digest"], hashlib.sha256(b"def").hexdigest())

    def test_complete_lost_response_busy_retry_and_dns_timeout(self):
        invitation_id = "a" * 32
        url = f"https://receiver.example/api/transfers/direct/invitations/{invitation_id}"
        archive = Path(self.temp.name) / "retry.zip"
        archive.write_bytes(b"abcdef")
        client = DirectTransferClient()
        for first_error in (
            DirectTransferClientError("network_error", "Secure connection failed."),
            DirectTransferClientError("receiver_rejected", "Receiver is busy.", status_code=409),
        ):
            with self.subTest(code=first_error.code):
                calls = []

                def fake_request(_host, _port, _path, _token, method, suffix, _body, **_kwargs):
                    calls.append(suffix)
                    if suffix == "/prepare":
                        return {"status": "uploading" if len(calls) == 1 else "completed",
                                "offset": len(archive.read_bytes()) if len(calls) > 1 else 0}
                    if suffix.startswith("/chunks"):
                        return {"status": "uploading", "offset": len(archive.read_bytes())}
                    if calls.count("/complete") == 1:
                        raise first_error
                    return {"workspace_id": "imported"}

                with patch.object(client, "_request", side_effect=fake_request), \
                     patch("ctf_agent.direct_transfer_client.time.sleep"):
                    self.assertEqual(client.send_bundle(url, "a" * 43, archive,
                                                        scope="workspace"),
                                     {"workspace_id": "imported"})
                self.assertEqual(calls.count("/complete"), 2)
                self.assertEqual(calls.count("/prepare"), 2)

        release = threading.Event()

        def stalled_dns(_host, _port, **_kwargs):
            release.wait(1)
            return [(None, None, None, None, ("8.8.8.8", 443))]

        with patch("ctf_agent.direct_transfer_client.DNS_TIMEOUT_SECONDS", 0.01):
            try:
                with self.assertRaisesRegex(DirectTransferClientError, "timed out"):
                    DirectTransferClient(resolver=stalled_dns)._address("receiver.example", 443)
            finally:
                release.set()

    def test_authenticated_source_to_bearer_receiver_api(self):
        root = Path(self.temp.name)
        source_settings = Settings(
            root / "api-source-data", root / "api-source-db",
            root / "api-source-config", root / "api-source-logs",
            public_origin="https://source.example", storage_min_free_bytes=0,
            auth_mode="nologin",
        )
        target_settings = Settings(
            root / "api-target-data", root / "api-target-db",
            root / "api-target-config", root / "api-target-logs",
            public_origin="https://receiver.example", storage_min_free_bytes=0,
            auth_mode="nologin",
        )
        with TestClient(create_app(source_settings)) as source_client, \
             TestClient(create_app(target_settings)) as target_client:
            source_csrf = source_client.get("/api/auth/state").json()["csrf_token"]
            target_csrf = target_client.get("/api/auth/state").json()["csrf_token"]
            source_client.headers.update({"x-csrf-token": source_csrf})
            target_client.headers.update({"x-csrf-token": target_csrf})
            created = source_client.post("/api/workspaces", json={"name": "API source"})
            self.assertEqual(created.status_code, 201, created.text)
            source_workspace = created.json()["id"]
            challenge = source_client.post(
                f"/api/workspaces/{source_workspace}/challenges",
                json={"name": "API challenge", "description": "Source text"},
            )
            self.assertEqual(challenge.status_code, 201, challenge.text)
            invite_response = target_client.post(
                "/api/transfers/direct/invitations",
                json={"scope": "workspace", "max_size": 1024 * 1024},
            )
            self.assertEqual(invite_response.status_code, 201, invite_response.text)
            invite = invite_response.json()
            no_csrf = target_client.post(
                "/api/transfers/direct/invitations",
                json={"scope": "workspace", "max_size": 1024 * 1024},
                headers={"x-csrf-token": ""},
            )
            self.assertEqual(no_csrf.status_code, 403, no_csrf.text)
            self.assertNotIn(invite["token"], json.dumps(target_client.get(
                f"/api/transfers/direct/invitations/{invite['invitation_id']}"
            ).json()))
            rejected = target_client.post(
                f"/api/transfers/direct/invitations/{invite['invitation_id']}/prepare",
                json={"scope": "workspace", "size": 100, "sha256": "0" * 64},
                headers={"authorization": "Bearer " + "x" * 43},
            )
            self.assertEqual(rejected.status_code, 401, rejected.text)
            non_receiver_path = target_client.post(
                f"/api/transfers/direct/invitations/{invite['invitation_id']}/prepare/extra",
                json={}, headers={"authorization": "Bearer " + invite["token"],
                                  "x-csrf-token": ""},
            )
            self.assertEqual(non_receiver_path.status_code, 403, non_receiver_path.text)

            def route_request(_client, _host, _port, path, token, method, suffix,
                              body, **kwargs):
                headers = {"authorization": f"Bearer {token}",
                           "x-csrf-token": "",
                           "content-type": "application/octet-stream" if method == "PUT"
                           else "application/json"}
                if kwargs.get("chunk_digest"):
                    headers["x-chunk-sha256"] = kwargs["chunk_digest"]
                # The transfer receiver gets no target browser CSRF header.
                response = target_client.request(method, path + suffix,
                                                 content=body, headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                return response.json()

            with patch.object(DirectTransferClient, "_request", route_request):
                sent = source_client.post(
                    f"/api/workspaces/{source_workspace}/transfer/direct",
                    json={"invitation_url": invite["url"], "token": invite["token"]},
                )
                self.assertEqual(sent.status_code, 202, sent.text)
                job_id = sent.json()["job_id"]
                for _ in range(100):
                    source_status = source_client.get(
                        f"/api/transfers/direct/sends/{job_id}"
                    ).json()
                    if source_status["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                        break
                    time.sleep(0.05)
            self.assertEqual(source_status["status"], "completed", source_status)
            imported_workspace = source_status["result"]["workspace_id"]
            self.assertNotEqual(imported_workspace, source_workspace)
            final_status = target_client.get(
                f"/api/transfers/direct/invitations/{invite['invitation_id']}"
            ).json()
            self.assertEqual(final_status["status"], "completed")
            self.assertEqual(final_status["result"], source_status["result"])
            imported_challenges = target_client.get(
                f"/api/workspaces/{imported_workspace}/challenges"
            ).json()["challenges"]
            self.assertEqual(len(imported_challenges), 1)
            export_root = source_settings.data_dir / "workspaces" / ".transfers" / "exports"
            self.assertEqual(list(export_root.iterdir()), [])

            # Lose the HTTP response after a chunk was durably accepted. The
            # next source job must use its retained ZIP, and target prepare
            # must report the already stored offset for that exact checksum.
            second_invite = target_client.post(
                "/api/transfers/direct/invitations",
                json={"scope": "workspace", "max_size": 1024 * 1024},
            ).json()
            lost_once = [False]
            resumed_offsets = []

            def unreliable_request(client_obj, host, port, path, token,
                                   method, suffix, body, **kwargs):
                reply = route_request(client_obj, host, port, path, token,
                                      method, suffix, body, **kwargs)
                if suffix == "/prepare":
                    resumed_offsets.append(reply["offset"])
                if suffix.startswith("/chunks") and not lost_once[0]:
                    lost_once[0] = True
                    raise DirectTransferClientError(
                        "network_error", "Secure connection to receiver failed.",
                    )
                return reply

            send_body = {"invitation_url": second_invite["url"],
                         "token": second_invite["token"]}
            with patch.object(DirectTransferClient, "_request", unreliable_request):
                first_try = source_client.post(
                    f"/api/workspaces/{source_workspace}/transfer/direct",
                    json=send_body,
                )
                self.assertEqual(first_try.status_code, 202, first_try.text)
                for _ in range(100):
                    first_status = source_client.get(
                        f"/api/transfers/direct/sends/{first_try.json()['job_id']}"
                    ).json()
                    if first_status["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(first_status["status"], "failed", first_status)
                outbox_root = source_settings.data_dir / "workspaces" / ".transfers" / "outbox"
                snapshots = list(outbox_root.glob("*/*.zip"))
                self.assertEqual(len(snapshots), 1)
                retained_digest = hashlib.sha256(snapshots[0].read_bytes()).hexdigest()
                with source_client.app.state.direct_transfer_outbox.slot(
                    source_client.get("/api/auth/state").json()["user"]["id"],
                    source_workspace, None, second_invite["url"],
                    "z" * 43, False,
                ) as (_other_id, _other_archive, new_export):
                    self.assertTrue(new_export)
                retry = source_client.post(
                    f"/api/workspaces/{source_workspace}/transfer/direct",
                    json=send_body,
                )
                self.assertEqual(retry.status_code, 202, retry.text)
                for _ in range(100):
                    retry_status = source_client.get(
                        f"/api/transfers/direct/sends/{retry.json()['job_id']}"
                    ).json()
                    if retry_status["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                        break
                    time.sleep(0.05)
            self.assertEqual(retry_status["status"], "completed", retry_status)
            self.assertGreater(resumed_offsets[-1], 0)
            with closing(connect(target_settings)) as db:
                received_digest = db.execute(
                    "SELECT sha256 FROM direct_transfer_invitations WHERE id=?",
                    (second_invite["invitation_id"],),
                ).fetchone()[0]
            self.assertEqual(received_digest, retained_digest)
            self.assertEqual(list(outbox_root.glob("*/*.zip")), [])

            invalid_send = source_client.post(
                f"/api/workspaces/{source_workspace}/transfer/direct",
                json={"invitation_url": "http://127.0.0.1/api/transfers/direct/invitations/"
                      + invite["invitation_id"], "token": invite["token"]},
            )
            self.assertEqual(invalid_send.status_code, 422, invalid_send.text)
            self.assertEqual(list(export_root.iterdir()), [])

    def test_sender_connects_to_pinned_ip_without_cookie_or_redirect(self):
        target = []

        class FakeSocket:
            def shutdown(self, _direction):
                pass

        class FakeResponse:
            status = 200

            def read(self, _limit):
                return b'{"status":"uploading","offset":0}'

        class FakeConnection:
            def __init__(self, host, port, *, timeout, context):
                target.append(("origin", host, port, context.check_hostname))
                self.sock = None

            def request(self, method, path, *, body, headers):
                self.sock = self._create_connection(("ignored", 443))
                target.append(("request", method, path, body, headers))

            def getresponse(self):
                return FakeResponse()

            def close(self):
                pass

        def resolver(_host, _port, **_kwargs):
            return [(None, None, None, None, ("8.8.8.8", 443))]

        def create_connection(destination, timeout, source_address):
            target.append(("socket", destination))
            return FakeSocket()

        client = DirectTransferClient(resolver=resolver)
        with patch("ctf_agent.direct_transfer_client.http.client.HTTPSConnection", FakeConnection), \
             patch("ctf_agent.direct_transfer_client.socket.create_connection", create_connection):
            reply = client._request(
                "receiver.example", 443,
                "/api/transfers/direct/invitations/" + "a" * 32,
                "s" * 43, "POST", "/prepare", b"{}",
            )
        self.assertEqual(reply["offset"], 0)
        self.assertEqual(target[0], ("origin", "receiver.example", 443, True))
        self.assertEqual(target[1], ("socket", ("8.8.8.8", 443)))
        headers = target[2][4]
        self.assertEqual(headers["Authorization"], "Bearer " + "s" * 43)
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("Proxy-Authorization", headers)

    def test_stale_manual_export_cleanup_skips_active_download(self):
        exports = TransferExportManager(self.target[0])
        archive, lock = exports.reserve()
        archive.write_bytes(b"private export")
        old = time.time() - EXPORT_TTL_SECONDS - 10
        os.utime(archive, (old, old))
        try:
            self.assertEqual(exports.cleanup_stale(), 0)
            self.assertTrue(archive.exists())
        finally:
            lock.release()
        self.assertEqual(exports.cleanup_stale(), 1)
        self.assertFalse(archive.exists())

    def test_outbox_lock_hash_and_worker_restart(self):
        settings, owner, _layout = self.source
        outbox = DirectTransferOutbox(settings)
        invitation_url = "https://receiver.example/api/transfers/direct/invitations/" + "a" * 32
        token = "s" * 43
        with outbox.slot(owner, self.source_workspace, None,
                         invitation_url, token, False) as (outbox_id, archive, fresh):
            self.assertTrue(fresh)
            archive.write_bytes(self.workspace_bundle.read_bytes())
            outbox.publish(outbox_id, archive)
            with closing(connect(settings)) as db, db:
                row = db.execute(
                    "SELECT token_hash FROM direct_transfer_outbox WHERE id=?",
                    (outbox_id,),
                ).fetchone()
                self.assertEqual(row["token_hash"], hashlib.sha256(token.encode()).hexdigest())
                self.assertNotEqual(row["token_hash"], token)
                db.execute("UPDATE direct_transfer_outbox SET updated_at=1 WHERE id=?",
                           (outbox_id,))
            self.assertEqual(outbox.cleanup_stale(), 0)
            self.assertTrue(archive.exists())
            with closing(connect(settings)) as db, db:
                db.execute("UPDATE direct_transfer_outbox SET updated_at=? WHERE id=?",
                           (int(time.time()), outbox_id))
        with outbox.slot(owner, self.source_workspace, None,
                         invitation_url, token, False) as (same_id, same_archive, fresh):
            self.assertEqual(same_id, outbox_id)
            self.assertFalse(fresh)
            self.assertEqual(same_archive.read_bytes(), self.workspace_bundle.read_bytes())
        with outbox.slot(owner, self.source_workspace, None,
                         invitation_url, "z" * 43, False) as (other_id, _archive, fresh):
            self.assertNotEqual(other_id, outbox_id)
            self.assertTrue(fresh)
        with closing(connect(settings)) as db, db:
            db.execute("UPDATE direct_transfer_outbox SET updated_at=1 WHERE id=?",
                       (outbox_id,))
        self.assertEqual(outbox.cleanup_stale(), 1)
        self.assertFalse(archive.exists())

        jobs = DirectSendJobs(settings)
        key = jobs.key(owner, self.source_workspace, None, invitation_url, token, False)
        job, lock = jobs.start(owner, key)
        self.assertEqual(job["status"], "queued")
        lock.release()  # The process died before its worker completed.
        restarted = DirectSendJobs(settings)
        self.assertEqual(restarted.status(owner, job["job_id"])["status"], "interrupted")
        retry, retry_lock = restarted.start(owner, key)
        try:
            self.assertNotEqual(retry["job_id"], job["job_id"])
            self.assertEqual(retry["status"], "queued")
            self.assertTrue(restarted.cancel(owner, retry["job_id"])["cancel_requested"])
            restarted.fail(retry["job_id"], "cancelled", "Direct transfer was cancelled.")
            self.assertEqual(restarted.status(owner, retry["job_id"])["status"], "cancelled")
        finally:
            retry_lock.release()


if __name__ == "__main__":
    unittest.main()
