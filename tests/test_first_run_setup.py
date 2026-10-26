"""First-run web setup must be local opt-in and single use."""

from fastapi.testclient import TestClient

from ctf_agent.db import Settings
from ctf_agent.main import create_app


def settings(tmp_path, *, mode="password", allow=False):
    return Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs",
        auth_mode=mode, allow_web_bootstrap=allow,
    )


def test_first_admin_setup_is_single_use_and_survives_restart(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD", raising=False)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    config = settings(tmp_path, allow=True)
    with TestClient(create_app(config)) as client:
        state = client.get("/api/auth/state").json()
        assert state["configured"] is False
        assert state["setup_available"] is True
        created = client.post("/api/auth/setup", json={"username": "first-owner", "password": "pass"})
        assert created.status_code == 200
        assert created.json()["user"]["username"] == "first-owner"
        assert created.json()["user"]["role"] == "admin"
        client.headers["x-csrf-token"] = created.json()["csrf_token"]
        assert client.get("/api/workspaces").status_code == 200
        duplicate = client.post("/api/auth/setup", json={"username": "intruder", "password": "pass"})
        assert duplicate.status_code == 409
        assert client.post("/api/auth/logout").status_code == 200
        state = client.get("/api/auth/state").json()
        assert state["configured"] is True
        assert state["setup_available"] is False
        login = client.post("/api/auth/login", json={"username": "first-owner", "password": "pass"})
        assert login.status_code == 200

    with TestClient(create_app(config)) as restarted:
        state = restarted.get("/api/auth/state").json()
        assert state["configured"] is True
        assert state["setup_available"] is False
        assert restarted.post("/api/auth/setup", json={"username": "other", "password": "pass"}).status_code == 409


def test_web_setup_requires_explicit_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD", raising=False)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    with TestClient(create_app(settings(tmp_path))) as client:
        assert client.get("/api/auth/state").json()["setup_available"] is False
        assert client.post("/api/auth/setup", json={"username": "owner", "password": "pass"}).status_code == 404


def test_nologin_mode_never_exposes_web_setup(tmp_path):
    with TestClient(create_app(settings(tmp_path, mode="nologin", allow=True))) as client:
        assert client.get("/api/auth/state").json()["setup_available"] is False
        assert client.post("/api/auth/setup", json={"username": "owner", "password": "pass"}).status_code == 404
