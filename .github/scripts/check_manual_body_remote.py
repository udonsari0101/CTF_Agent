"""Exercise persisted remote inference for manually created challenges."""

import sys
import tempfile
from pathlib import Path

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.main import create_app


def run() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        app = create_app(Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        ))
        with TestClient(app) as browser:
            browser.headers["x-csrf-token"] = browser.get("/api/auth/state").json()["csrf_token"]
            created = browser.post("/api/workspaces", json={"name": "remote inference"})
            assert created.status_code == 201, created.text
            workspace = created.json()["id"]
            base = f"/api/workspaces/{workspace}/challenges"

            def create(name: str, **fields) -> dict:
                response = browser.post(base, json={"name": name, **fields})
                assert response.status_code == 201, response.text
                return response.json()

            def edit(row: dict, **fields) -> dict:
                response = browser.patch(
                    f"{base}/{row['id']}", json=fields,
                    headers={"If-Match": row["edit_token"]},
                )
                assert response.status_code == 200, response.text
                return response.json()

            inferred = create(
                "binary", remote_mode="none",
                description="Connect with nc challenge.example.org 31337",
            )
            assert (inferred["remote_mode"], inferred["remote"]) == (
                "endpoint", "nc challenge.example.org 31337"
            )
            assert inferred["remote_origin"] == "description"
            reread = browser.get(f"{base}/{inferred['id']}").json()
            assert reread["remote"] == inferred["remote"]
            cloned = browser.post(f"{base}/{inferred['id']}/clone")
            assert cloned.status_code == 201, cloned.text
            assert cloned.json()["remote_origin"] == "description"
            inferred = edit(inferred, description="Connect with nc new.example.org 4444")
            assert (inferred["remote_mode"], inferred["remote"]) == (
                "endpoint", "nc new.example.org 4444"
            )
            assert inferred["remote_origin"] == "description"
            inferred = edit(inferred, description="This is an offline artifact.")
            assert (inferred["remote_mode"], inferred["remote"]) == ("unknown", "")

            explicit = create(
                "manual override", description="nc mentioned.example.org 1234",
                remote="nc chosen.example.org 5555", remote_mode="endpoint",
            )
            assert explicit["remote"] == "nc chosen.example.org 5555"
            assert explicit["remote_origin"] == "explicit"
            explicit = edit(explicit, description="nc another.example.org 3333")
            assert explicit["remote"] == "nc chosen.example.org 5555"

            same = create(
                "same as brief", description="nc same.example.org 5555",
                remote="nc same.example.org 5555", remote_mode="endpoint",
            )
            same = edit(same, description="nc changed.example.org 6666")
            assert same["remote"] == "nc same.example.org 5555"
            assert same["remote_origin"] == "explicit"

            ambiguous = create(
                "references", remote_mode="none",
                description="Choose http://one.example.org/ or http://two.example.org/",
            )
            assert (ambiguous["remote_mode"], ambiguous["remote"]) == ("none", "")
            reference = create(
                "analysis reference", remote_mode="none",
                description="Maybe try a tool like https://dogbolt.org/ to inspect the binary.",
            )
            assert (reference["remote_mode"], reference["remote"]) == ("none", "")
            print("PASS: manual body endpoint create/edit persistence and override")


if __name__ == "__main__":
    run()
