"""Offline check that an owned Codex credential exports as a private file."""

import sys
import gc
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local_test_client import TestClient
from ctf_agent.db import Settings
from ctf_agent.main import create_app


def main() -> None:
    with TemporaryDirectory() as temp:
        root = Path(temp)
        app = create_app(Settings(root / "data", root / "db", root / "config", root / "logs",
                                  storage_min_free_bytes=0, auth_mode="nologin"))
        with TestClient(app) as client:
            csrf = client.get("/api/auth/state").json()["csrf_token"]
            client.headers.update({"x-csrf-token": csrf})
            account = client.post("/api/accounts", json={"provider": "codex", "label": "test"}).json()
            endpoint = f"/api/accounts/{account['id']}/auth-file/export"
            assert client.get(endpoint).status_code == 405
            assert client.post(endpoint).status_code == 404
            target = root / "config" / "accounts" / account["id"] / "codex" / "auth.json"
            target.parent.mkdir(parents=True)
            original = b'{"OPENAI_API_KEY":"sk-test-local-only"}'
            target.write_bytes(original)
            response = client.post(endpoint)
            assert response.status_code == 200, response.text
            assert response.content == original
            assert response.headers["cache-control"] == "no-store"
            assert "attachment" in response.headers["content-disposition"]
        gc.collect()
    print("PASS: owned auth.json export")


if __name__ == "__main__":
    main()
