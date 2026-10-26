from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_local_compose_is_nologin_and_keeps_data_and_database_separate():
    raw = (ROOT / "compose.local.yaml").read_text(encoding="utf-8")
    compose = yaml.safe_load(raw)

    web = compose["services"]["web"]
    solver = compose["services"]["solver"]
    init = compose["services"]["init-storage"]

    assert web["environment"]["CTF_AUTH_MODE"] == "${CTF_AUTH_MODE:-nologin}"
    assert web["environment"]["CTF_CTFD_ALLOW_INSECURE_HTTP"] == (
        "${CTF_CTFD_ALLOW_INSECURE_HTTP:-false}"
    )
    assert web["environment"]["CTF_COOKIE_SECURE"] == "false"
    assert web["ports"] == ["${CTF_LOCAL_BIND:-127.0.0.1}:${CTF_LOCAL_PORT:-5050}:5050"]
    assert "./.local/ctf_agent_data" in raw
    assert "./.local/Database/CTF_Agent" in raw
    assert init["user"] == "0:0"
    assert init["restart"] == "no"
    init_command = init["command"][0]
    for path in (
        "/data/workspaces",
        "/data/workspace_files",
        "/data/runtime",
        "/data/claude-runtime",
        "/data/.storage-budget.lock",
    ):
        assert path in init_command
    assert 'chown 0:"$$gid" /data /database' in init_command
    assert 'chmod 0750 /data /database' in init_command
    assert 'install -d -o 0 -g "$$gid" -m 0750 /data/solver-exchange/slots /data/solver-scratch' in init_command
    assert web["environment"]["CTF_SOLVER_MAX_CONCURRENT"] == "${CTF_SOLVER_MAX_CONCURRENT:-1}"
    assert all(f"solver-{index}" in compose["services"] for index in range(2, 7))
    assert all(
        compose["services"][f"solver-{index}"]["profiles"] == [f"solver-{index}"]
        for index in range(2, 7)
    )
    for index in range(2, 7):
        static = compose["services"][f"solver-{index}"]
        for key in (
            "image",
            "build",
            "user",
            "command",
            "environment",
            "read_only",
            "tmpfs",
            "cap_drop",
            "security_opt",
        ):
            assert static[key] == solver[key]
    autoscaler = compose["services"]["solver-autoscaler"]
    assert autoscaler["environment"]["CTF_SOLVER_STATIC_COUNT"] == "${CTF_SOLVER_STATIC_COUNT:-1}"
    assert autoscaler["cap_drop"] == ["ALL"]
    assert autoscaler["cap_add"] == ["CHOWN", "DAC_READ_SEARCH"]

    solver_targets = {mount["target"] for mount in solver["volumes"]}
    assert solver_targets == {
        "/solver-exchange", "/solver-input", "/solver-exchange/runtime", "/solver-scratch"
    }
    assert "/data" not in solver_targets and "/database" not in solver_targets
    assert solver["environment"]["CTF_SOLVER_LOCAL_DESKTOP"] == "true"
    assert solver["environment"]["CTF_SOLVER_DISK_SCRATCH"] == "true"
    assert "network_mode" not in solver
    assert solver["cap_drop"] == ["ALL"]
    assert solver["read_only"] is True
    assert "pids_limit" not in solver and "mem_limit" not in solver and "ulimits" not in solver
    assert not any("/solver-scratch:" in item for item in solver["tmpfs"])


def test_local_desktop_guide_has_copyable_install_and_fast_explorer_path():
    guide = (ROOT / "docs" / "docker-desktop.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    command = (
        "git clone https://github.com/udonsari0101/CTF_Agent.git ~/CTF_Agent && "
        "cd ~/CTF_Agent && CTF_AUTH_MODE=password CTF_ALLOW_WEB_BOOTSTRAP=true "
        "CTF_LOCAL_UID=$(id -u) CTF_LOCAL_GID=$(id -g) "
        "python3 deploy/local-compose.py up -d --build"
    )
    assert command in guide
    assert command in readme
    assert "CTF_Agent-*-local-windows.zip" in readme
    assert "Install.cmd" in readme
    assert "http://127.0.0.1:5050" in readme
    assert "workspace_files" in readme
    assert "explorer.exe" in guide
    assert "\\\\wsl.localhost\\<distribution>" in guide
    assert "/mnt/c" in guide
    assert "CTF_AUTH_MODE=nologin" in guide
    assert "maximum" in guide
    assert ".local/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
