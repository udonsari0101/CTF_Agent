import os
from pathlib import Path
import runpy

import pytest


ROOT = Path(__file__).parents[1]


def _browser_module() -> dict:
    return runpy.run_path(str(ROOT / "deploy" / "ctf-browser"))


def _job_tree(root: Path, name: str = "ctf-job-browser-test") -> Path:
    workdir = root / name / "competition" / "challenge" / "codex-workdir"
    (workdir / "tmp").mkdir(parents=True)
    return workdir


def test_browser_accepts_only_the_solver_job_topology(tmp_path):
    browser = _browser_module()
    scratch = tmp_path / "solver-scratch"
    workdir = _job_tree(scratch)

    assert browser["job_workdir"](workdir, scratch) == workdir
    assert browser["job_workdir"](workdir / "tmp", scratch) == workdir

    attestation = _job_tree(scratch, "ctf-attest-startup-check")
    assert browser["job_workdir"](attestation, scratch) == attestation

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="active solve job"):
        browser["job_workdir"](outside, scratch)

    invalid = _job_tree(scratch, "ctf-browser-test")
    with pytest.raises(ValueError, match="active solve job"):
        browser["job_workdir"](invalid, scratch)


def test_browser_rejects_symlinked_job_directories(tmp_path):
    browser = _browser_module()
    scratch = tmp_path / "solver-scratch"
    job = scratch / "ctf-job-symlink-test"
    real_competition = job / "real-competition"
    workdir = real_competition / "challenge" / "codex-workdir"
    workdir.mkdir(parents=True)
    try:
        (job / "competition").symlink_to(real_competition, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="unsafe"):
        browser["job_workdir"](job / "competition" / "challenge" / "codex-workdir", scratch)


def test_browser_manages_profile_headless_mode_and_listener_address(tmp_path):
    browser = _browser_module()
    runtime = tmp_path / "runtime"
    command = browser["browser_command"](
        [
            "--remote-debugging-port=9222",
            "--proxy-server=http://127.0.0.1:8080",
            "https://challenge.example/path",
        ],
        runtime,
    )

    assert command[0] == "/usr/bin/chromium"
    assert "--headless=new" in command
    assert "--no-sandbox" in command
    assert "--disable-dev-shm-usage" in command
    assert "--remote-debugging-address=127.0.0.1" in command
    assert command.index("--headless=new") < command.index("https://challenge.example/path")
    assert command.index("--remote-debugging-address=127.0.0.1") < command.index(
        "--remote-debugging-port=9222"
    )
    assert f"--user-data-dir={runtime / 'profile'}" in command
    assert f"--disk-cache-dir={runtime / 'cache'}" in command
    assert f"--crash-dumps-dir={runtime / 'crashes'}" in command

    for protected in browser["PROTECTED_OPTIONS"]:
        with pytest.raises(ValueError, match="manages"):
            browser["validate_options"]([protected])
        with pytest.raises(ValueError, match="manages"):
            browser["validate_options"]([protected + "=override"])


def test_browser_environment_drops_credentials_and_uses_job_runtime(monkeypatch, tmp_path):
    browser = _browser_module()
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-pass")
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", "must-not-pass")
    monkeypatch.setenv("LANG", "ko_KR.UTF-8")
    environment = browser["browser_environment"](runtime)

    assert set(environment) <= {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_RUNTIME_DIR",
    }
    assert environment["HOME"] == str(runtime / "home")
    assert environment["TMPDIR"] == str(runtime / "tmp")
    assert environment["XDG_RUNTIME_DIR"] == str(runtime / "xdg-runtime")
    assert environment["LANG"] == "ko_KR.UTF-8"
    assert not any("must-not-pass" in value for value in environment.values())


def test_browser_run_removes_ephemeral_profile(monkeypatch, tmp_path):
    browser = _browser_module()
    workdir = _job_tree(tmp_path / "solver-scratch")
    observed = {}

    class FakeProcess:
        pid = 987654

        def __init__(self, command, *, env, start_new_session):
            observed["command"] = command
            observed["env"] = env
            observed["start_new_session"] = start_new_session
            self.returncode = None

        def wait(self):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

    browser["run"].__globals__["job_workdir"] = lambda _cwd: workdir
    monkeypatch.setattr(browser["subprocess"], "Popen", FakeProcess)

    assert browser["run"](["--dump-dom", "https://challenge.example"]) == 0
    assert observed["start_new_session"] is True
    assert "--dump-dom" in observed["command"]
    assert not list(workdir.parents[2].glob(".ctf-browser-*"))
    assert observed["env"]["HOME"].startswith(str(workdir.parents[2]))


def test_browser_launcher_never_requests_host_devices_or_container_control():
    source = (ROOT / "deploy" / "ctf-browser").read_text(encoding="utf-8")
    for forbidden in (
        "/dev/kvm",
        "/dev/dri",
        "/var/run/docker.sock",
        "--privileged",
        "DISPLAY",
        "WAYLAND_DISPLAY",
    ):
        assert forbidden not in source
