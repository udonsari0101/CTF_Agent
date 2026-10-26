"""System resource snapshot and authenticated workspace API regressions."""

from pathlib import Path

from fastapi.testclient import TestClient

from ctf_agent.db import Settings, connect
from ctf_agent.main import create_app
from ctf_agent.resource_usage import ResourceMonitor


def _write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def test_resource_monitor_uses_proc_deltas_and_caches_small_numeric_snapshot(tmp_path):
    proc_stat = tmp_path / "stat"
    meminfo = tmp_path / "meminfo"
    _write(proc_stat, "cpu 100 0 100 700 100 0 0 0\n")
    _write(meminfo, "MemTotal: 16777216 kB\nMemAvailable: 6291456 kB\n")
    clock = [10.0]
    monitor = ResourceMonitor(
        proc_stat=proc_stat,
        meminfo=meminfo,
        cache_seconds=2,
        monotonic=lambda: clock[0],
    )

    _write(proc_stat, "cpu 150 0 150 800 100 0 0 0\n")
    first = monitor.snapshot()
    assert first == {
        "available": True,
        "scope": "system",
        "cpu_percent": 50.0,
        "memory_percent": 62.5,
        "memory_used_bytes": 10 * 1024**3,
        "memory_total_bytes": 16 * 1024**3,
    }

    _write(proc_stat, "cpu 150 0 150 1000 100 0 0 0\n")
    _write(meminfo, "MemTotal: 16777216 kB\nMemAvailable: 16777216 kB\n")
    clock[0] = 11.0
    assert monitor.snapshot() == first

    clock[0] = 13.0
    refreshed = monitor.snapshot()
    assert refreshed["cpu_percent"] == 0.0
    assert refreshed["memory_percent"] == 0.0


def test_resource_monitor_returns_concise_unavailable_state_for_bad_proc_files(tmp_path):
    proc_stat = tmp_path / "stat"
    meminfo = tmp_path / "meminfo"
    _write(proc_stat, "not-cpu private process detail\n")
    _write(meminfo, "MemTotal: unknown\n")
    monitor = ResourceMonitor(proc_stat=proc_stat, meminfo=meminfo, cache_seconds=0)

    assert monitor.snapshot() == {
        "available": False,
        "scope": "system",
        "cpu_percent": None,
        "memory_percent": None,
        "memory_used_bytes": None,
        "memory_total_bytes": None,
    }


def test_workspace_resource_api_requires_auth_and_workspace_ownership(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "resource-test-password")
    settings = Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs"
    )
    app = create_app(settings)
    expected = {
        "available": True,
        "scope": "system",
        "cpu_percent": 12.5,
        "memory_percent": 25.0,
        "memory_used_bytes": 4 * 1024**3,
        "memory_total_bytes": 16 * 1024**3,
    }
    app.state.resource_monitor = type("Monitor", (), {"snapshot": lambda self: expected})()

    with TestClient(app) as client:
        created = client.post("/api/auth/login", json={"password": "resource-test-password"})
        assert created.status_code == 200
        csrf = created.json()["csrf_token"]
        client.headers["X-CSRF-Token"] = csrf
        area = client.post("/api/workspaces", json={"name": "Visible resources"}).json()

        assert client.get(f"/api/workspaces/{area['id']}/resources").json() == expected
        assert client.get(f"/api/workspaces/{'f' * 32}/resources").status_code == 404

    with TestClient(app) as anonymous:
        assert anonymous.get(f"/api/workspaces/{area['id']}/resources").status_code == 401

    with connect(settings) as database:
        assert database.execute(
            "SELECT name FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0] == "Visible resources"
