"""Offline regression for per-user Ultra default and avatar rotation."""

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
            state = client.get("/api/auth/state").json()
            assert state["user"]["ultra_escalation_default"] == "ask"
            client.headers.update({"x-csrf-token": state["csrf_token"]})
            response = client.patch("/api/auth/preferences", json={"ultra_escalation_default": "auto"})
            assert response.status_code == 200, response.text
            assert client.get("/api/auth/state").json()["user"]["ultra_escalation_default"] == "auto"
            assert client.patch("/api/auth/preferences", json={"ultra_escalation_default": "invalid"}).status_code == 422
            first = client.post("/api/auth/avatar/refresh").json()["avatar_seed"]
            second = client.post("/api/auth/avatar/refresh").json()["avatar_seed"]
            assert len(first) == 32 and first != second
            assert client.get("/api/auth/state").json()["user"]["avatar_seed"] == second
        gc.collect()
    print("PASS: Ultra default and avatar rotation persist")


if __name__ == "__main__":
    main()
