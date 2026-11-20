"""Offline regression for atomic Codex clone presets and attachment isolation."""

from __future__ import annotations

import errno
import hashlib
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local_test_client import TestClient

from ctf_agent.db import Settings, connect
from ctf_agent.main import clone_challenge_name, copy_regular_snapshot, create_app


def run() -> None:
    with TemporaryDirectory(ignore_cleanup_errors=True) as temp:
        root = Path(temp)
        settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        app = create_app(settings)
        with TestClient(app) as client:
            client.headers["x-csrf-token"] = client.get("/api/auth/state").json()["csrf_token"]
            workspace = client.post("/api/workspaces", json={"name": "batch"}).json()["id"]
            source = client.post(
                f"/api/workspaces/{workspace}/challenges",
                json={"name": "analyze", "description": "offline challenge"},
            ).json()["id"]
            owner = None
            with connect(settings) as db:
                owner = db.execute(
                    "SELECT owner_user_id FROM workspaces WHERE id=?", (workspace,)
                ).fetchone()[0]
            codex = app.state.accounts.create("codex", "test Codex", owner)["id"]
            claude = app.state.accounts.create("claude", "test Claude", owner)["id"]
            content = b"one immutable source attachment"
            staged = f"/api/workspaces/{workspace}/staged-files"
            file = client.post(staged, json={
                "name": "input.bin", "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })
            assert file.status_code == 201, file.text
            file_url = f"{staged}/{file.json()['id']}"
            assert client.put(
                file_url + "/chunks?offset=0", content=content,
                headers={"content-type": "application/octet-stream"},
            ).status_code == 200
            assert client.post(file_url + "/finalize").status_code == 200
            assert client.post(
                f"/api/workspaces/{workspace}/challenges/{source}"
                f"/staged-files/{file.json()['id']}/attach"
            ).status_code == 200

            endpoint = f"/api/workspaces/{workspace}/challenges/{source}/clone-batch"
            variants = [
                {"account_id": codex, "model": "gpt-6-sol", "reasoning_effort": "medium",
                 "service_tier": "fast", "subagents_enabled": False},
                {"account_id": codex, "model": "gpt-6-sol", "reasoning_effort": "xhigh",
                 "service_tier": None, "subagents_enabled": True,
                 "ultra_escalation_mode": "ask"},
            ]
            assert client.post(endpoint, json={"variants": variants + variants[:1]}).status_code == 422
            assert client.post(endpoint, json={"variants": [
                {**variants[0], "account_id": claude}
            ]}).status_code == 422
            assert client.post(endpoint, json={"variants": [{
                **variants[0], "reasoning_effort": "medium", "ultra_escalation_mode": "auto"
            }]}).status_code == 422
            with connect(settings) as db:
                assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 1

            response = client.post(endpoint, json={"variants": variants})
            assert response.status_code == 201, response.text
            clones = response.json()["clones"]
            assert len(clones) == 2
            assert len({item["id"] for item in clones}) == 2
            assert all(item["canonical_name"] == "analyze" for item in clones)
            assert all(item["status"] == "pending" and not item["flag"] for item in clones)
            for item, variant in zip(clones, variants):
                preset = item["solver_preset"]
                assert preset == {"provider": "codex", **{
                    "account_id": variant["account_id"], "model": variant["model"],
                    "reasoning_effort": variant["reasoning_effort"],
                    "service_tier": variant["service_tier"],
                    "subagents_enabled": variant["subagents_enabled"],
                    "ultra_escalation_mode": variant.get("ultra_escalation_mode", "off"),
                }}
                fresh = client.get(
                    f"/api/workspaces/{workspace}/challenges/{item['id']}"
                ).json()
                assert fresh["solver_preset"] == preset
                assert client.get(
                    f"/api/workspaces/{workspace}/challenges/{item['id']}"
                    f"/attachments/{item['attachments'][0]['id']}"
                ).content == content
            groups = client.get(f"/api/workspaces/{workspace}/clone-groups").json()["groups"]
            assert len(groups) == 1
            assert {member["id"] for member in groups[0]["members"]} == {
                source, clones[0]["id"], clones[1]["id"],
            }
            clone_attachment = app.state.storage_layout.legacy_attachment_path(
                workspace, clones[0]["id"], clones[0]["attachments"][0]["id"]
            )
            clone_attachment.write_bytes(b"independent work")
            source_attachment = app.state.storage_layout.legacy_attachment_path(
                workspace, source,
                client.get(f"/api/workspaces/{workspace}/challenges/{source}").json()["attachments"][0]["id"],
            )
            assert source_attachment.read_bytes() == content

            with connect(settings) as db:
                before = db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
                before_families = db.execute(
                    "SELECT COUNT(*) FROM challenge_clone_members"
                ).fetchone()[0]
            canonical_parent = app.state.storage_layout.legacy_workspace_path(workspace) / "challenges"
            before_paths = {path.name for path in canonical_parent.iterdir()}
            readable_parent = app.state.storage_layout.workspace_path(workspace)
            before_readable = {path.name for path in readable_parent.iterdir()}
            calls = 0

            def second_copy_fails(source_path, target_path, size):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError(errno.EIO, "simulated copy failure")
                return copy_regular_snapshot(source_path, target_path, size)

            with patch("ctf_agent.main.copy_regular_snapshot", second_copy_fails):
                failed = client.post(endpoint, json={"variants": variants})
            assert failed.status_code == 503, failed.text
            with connect(settings) as db:
                assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == before
                assert db.execute(
                    "SELECT COUNT(*) FROM challenge_clone_members"
                ).fetchone()[0] == before_families
                assert db.execute(
                    "SELECT COUNT(*) FROM storage_reservations"
                ).fetchone()[0] == 0
            assert {path.name for path in canonical_parent.iterdir()} == before_paths
            assert {path.name for path in readable_parent.iterdir()} == before_readable

            names = 0

            def second_publish_fails(db, ws, name):
                nonlocal names
                names += 1
                if names == 2:
                    raise RuntimeError("simulated transaction failure")
                return clone_challenge_name(db, ws, name)

            with patch("ctf_agent.main.clone_challenge_name", second_publish_fails):
                try:
                    client.post(endpoint, json={"variants": variants})
                except RuntimeError as exc:
                    assert "simulated transaction failure" in str(exc)
                else:
                    raise AssertionError("expected injected publication failure")
            with connect(settings) as db:
                assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == before
                assert db.execute(
                    "SELECT COUNT(*) FROM challenge_clone_members"
                ).fetchone()[0] == before_families
                assert db.execute(
                    "SELECT COUNT(*) FROM storage_reservations"
                ).fetchone()[0] == 0
            assert {path.name for path in canonical_parent.iterdir()} == before_paths
            assert {path.name for path in readable_parent.iterdir()} == before_readable
    print("PASS: Codex clone batch presets, lineage, files and atomic rollback")


if __name__ == "__main__":
    run()
