"""Offline lifecycle check: trash hides a problem without deleting its data."""

from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import gc
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local_test_client import TestClient
from ctf_agent.db import Settings, connect
from ctf_agent.main import create_app


def run() -> None:
    with TemporaryDirectory(ignore_cleanup_errors=True) as temp:
        root = Path(temp)
        settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                            storage_min_free_bytes=0, auth_mode="nologin")
        app = create_app(settings)
        with TestClient(app) as client:
            csrf = client.get("/api/auth/state").json()["csrf_token"]
            client.headers.update({"x-csrf-token": csrf})
            workspace = client.post("/api/workspaces", json={"name": "test"}).json()["id"]
            challenge = client.post(f"/api/workspaces/{workspace}/challenges",
                                    json={"name": "retain me", "description": "for diagnostics"}).json()["id"]
            clone = client.post(f"/api/workspaces/{workspace}/challenges/{challenge}/clone")
            assert clone.status_code == 201, clone.text
            assert clone.json()["canonical_name"] == "retain me"
            clone_id = clone.json()["id"]
            groups = client.get(f"/api/workspaces/{workspace}/clone-groups").json()["groups"]
            assert len(groups) == 1 and {item["id"] for item in groups[0]["members"]} == {challenge, clone_id}
            split = client.put(f"/api/workspaces/{workspace}/challenges/{clone_id}/clone-group",
                               json={"target_challenge_id": None})
            assert split.status_code == 200, split.text
            remaining = client.get(f"/api/workspaces/{workspace}/clone-groups").json()["groups"]
            assert len(remaining) == 1 and [item['id'] for item in remaining[0]['members']] == [challenge]
            joined = client.put(f"/api/workspaces/{workspace}/challenges/{clone_id}/clone-group",
                                json={"target_challenge_id": challenge})
            assert joined.status_code == 200, joined.text
            base = f"/api/workspaces/{workspace}/challenges/{challenge}"
            payload = b"preserved challenge evidence"
            staged = f"/api/workspaces/{workspace}/staged-files"
            created_file = client.post(staged, json={
                "name": "evidence.bin", "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            assert created_file.status_code == 201, created_file.text
            file_url = f"{staged}/{created_file.json()['id']}"
            assert client.put(file_url + "/chunks?offset=0", content=payload,
                              headers={"content-type": "application/octet-stream"}).status_code == 200
            assert client.post(file_url + "/finalize").status_code == 200
            attached = client.post(base + f"/staged-files/{created_file.json()['id']}/attach")
            assert attached.status_code == 200, attached.text
            attachment_id = attached.json()["id"]
            with connect(settings) as db:
                db.execute("UPDATE challenges SET notes='preserved analysis' WHERE id=?", (challenge,))
            assert client.delete(base).status_code == 200
            assert client.get(base).status_code == 404
            assert [item["id"] for item in client.get(f"/api/workspaces/{workspace}/challenges").json()["challenges"]] == [clone_id]
            trash = client.get(f"/api/workspaces/{workspace}/trash").json()["challenges"]
            assert len(trash) == 1 and trash[0]["id"] == challenge
            with connect(settings) as db:
                db.execute("UPDATE challenges SET name='Renamed copy' WHERE id=?", (clone_id,))
            assert client.get(f"/api/workspaces/{workspace}/challenges/{clone_id}").json()["canonical_name"] == "retain me"
            grandclone = client.post(f"/api/workspaces/{workspace}/challenges/{clone_id}/clone")
            assert grandclone.status_code == 201, grandclone.text
            assert grandclone.json()["canonical_name"] == "retain me"
            assert client.post(f"/api/workspaces/{workspace}/trash/{challenge}/restore").status_code == 200
            assert client.get(base).status_code == 200
            assert client.get(base).json()["notes"] == "preserved analysis"
            restored_file = client.get(base + f"/attachments/{attachment_id}")
            assert restored_file.status_code == 200 and restored_file.content == payload
            assert client.delete(base).status_code == 200
            assert client.delete(f"/api/workspaces/{workspace}/trash/{challenge}").status_code == 200
            assert client.get(f"/api/workspaces/{workspace}/trash").json()["challenges"] == []
        gc.collect()
    print("PASS: challenge trash, restore and permanent delete")


if __name__ == "__main__":
    run()
