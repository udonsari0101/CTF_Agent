"""Exercise the authenticated ZIP transfer contract without model execution."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings  # noqa: E402
from ctf_agent.main import create_app  # noqa: E402


class TransferApiTest(unittest.TestCase):
    def test_workspace_and_challenge_round_trip_with_owner_scope(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            app = create_app(Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            ))
            with TestClient(app) as client:
                csrf = client.get("/api/auth/state").json()["csrf_token"]
                client.headers.update({"x-csrf-token": csrf})
                workspace = client.post(
                    "/api/workspaces", json={"name": "Transfer source"}
                ).json()["id"]
                challenge_response = client.post(
                    f"/api/workspaces/{workspace}/challenges",
                    json={"name": "Round trip", "description": "Original text"},
                )
                self.assertEqual(challenge_response.status_code, 201, challenge_response.text)
                challenge = challenge_response.json()["id"]

                def upload_and_import(bundle: bytes, destination: str | None = None):
                    digest = hashlib.sha256(bundle).hexdigest()
                    created = client.post(
                        "/api/transfers/uploads",
                        json={"size": len(bundle), "sha256": digest},
                    )
                    self.assertEqual(created.status_code, 201, created.text)
                    upload_id = created.json()["upload_id"]
                    endpoint = f"/api/transfers/uploads/{upload_id}"
                    stored = client.put(
                        endpoint + "/chunks?offset=0", content=bundle,
                        headers={"content-type": "application/octet-stream"},
                    )
                    self.assertEqual(stored.status_code, 200, stored.text)
                    self.assertEqual(stored.json()["offset"], len(bundle))
                    finalized = client.post(endpoint + "/finalize")
                    self.assertEqual(finalized.status_code, 200, finalized.text)
                    self.assertEqual(finalized.json()["status"], "ready")
                    query = f"?workspace_id={destination}" if destination else ""
                    preview = client.get(endpoint + "/preview" + query)
                    self.assertEqual(preview.status_code, 200, preview.text)
                    result = client.post(endpoint + "/import", json={
                        **({"workspace_id": destination} if destination else {})
                    })
                    self.assertEqual(result.status_code, 200, result.text)
                    retry = client.post(endpoint + "/import", json={
                        **({"workspace_id": destination} if destination else {})
                    })
                    self.assertEqual(retry.status_code, 200, retry.text)
                    self.assertEqual(result.json(), retry.json())
                    return preview.json(), result.json()

                downloaded = client.get(f"/api/workspaces/{workspace}/transfer")
                self.assertEqual(downloaded.status_code, 200, downloaded.text)
                self.assertEqual(downloaded.headers["content-type"], "application/zip")
                preview, imported = upload_and_import(downloaded.content)
                self.assertEqual(preview["scope"], "workspace")
                self.assertEqual(preview["challenge_count"], 1)
                self.assertNotEqual(imported["workspace_id"], workspace)
                listed = client.get("/api/workspaces").json()["workspaces"]
                self.assertEqual(len(listed), 2)

                single = client.get(
                    f"/api/workspaces/{workspace}/challenges/{challenge}/transfer"
                )
                self.assertEqual(single.status_code, 200, single.text)
                preview, imported_challenge = upload_and_import(single.content, workspace)
                self.assertEqual(preview["scope"], "challenge")
                self.assertNotEqual(imported_challenge["challenge_id"], challenge)
                challenges = client.get(
                    f"/api/workspaces/{workspace}/challenges"
                ).json()["challenges"]
                self.assertEqual(len(challenges), 2)


if __name__ == "__main__":
    unittest.main()
