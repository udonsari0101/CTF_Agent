from pathlib import Path
import sqlite3

import pytest

from ctf_agent.local_capacity import GIB, recommended_solver_concurrency


def _limits(tmp_path: Path, *, cpu: str, cpuset: str, maximum: int, current: int, available: int):
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "cpu.max").write_text(cpu, encoding="utf-8")
    (cgroup / "cpuset.cpus.effective").write_text(cpuset, encoding="utf-8")
    (cgroup / "memory.max").write_text(str(maximum), encoding="utf-8")
    (cgroup / "memory.current").write_text(str(current), encoding="utf-8")
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(f"MemAvailable: {available // 1024} kB\n", encoding="utf-8")
    return cgroup, meminfo


def test_local_capacity_uses_effective_cgroup_cpu_and_memory(tmp_path):
    cgroup, meminfo = _limits(
        tmp_path,
        cpu="800000 100000",
        cpuset="0-7",
        maximum=16 * GIB,
        current=2 * GIB,
        available=40 * GIB,
    )
    assert recommended_solver_concurrency(
        cgroup=cgroup, meminfo=meminfo, logical_cpus=32
    ) == 2


def test_local_capacity_uses_all_supported_hardware_without_six_worker_cap(tmp_path):
    cgroup, meminfo = _limits(
        tmp_path,
        cpu="max 100000",
        cpuset="0-15",
        maximum=128 * GIB,
        current=8 * GIB,
        available=96 * GIB,
    )
    assert recommended_solver_concurrency(
        cgroup=cgroup, meminfo=meminfo, logical_cpus=16
    ) == 8


def test_local_capacity_override_is_exact_positive_and_unbounded(tmp_path):
    assert recommended_solver_concurrency(override="4") == 4
    assert recommended_solver_concurrency(override="37") == 37
    with pytest.raises(ValueError):
        recommended_solver_concurrency(override="0")


def test_local_launcher_removes_old_high_slots_and_management_selects_all_profiles():
    import importlib.util

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    up = module.compose_commands(2, ["up", "-d", "--build"])
    assert up[0][-7:] == ["rm", "--stop", "--force", "solver-3", "solver-4", "solver-5", "solver-6"]
    assert "solver-2" in up[1] and "solver-3" not in up[1]
    down = module.compose_commands(2, ["down"])[0]
    assert all(f"solver-{index}" in down for index in range(2, 7))


def test_local_launcher_prepares_readable_workspace_root(tmp_path):
    import importlib.util

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_storage", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    target = module.prepare_readable_storage({"CTF_LOCAL_DATA": str(tmp_path / "data")})
    assert target == tmp_path / "data" / "workspace_files"
    assert target.is_dir() and not target.is_symlink()


def test_local_scale_down_protects_active_retired_claim_and_scratch_slots(tmp_path):
    import importlib.util

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_protected", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    data = tmp_path / "data"
    database_root = tmp_path / "database"
    db_path = database_root / "sqlite" / "ctf_agent.sqlite3"
    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE solver_slots(slot_id TEXT PRIMARY KEY,job_id TEXT UNIQUE)")
    environment = {"CTF_LOCAL_DATA": str(data), "CTF_LOCAL_DATABASE": str(database_root)}

    idle = data / "solver-exchange" / "slots" / "solver-6"
    idle.mkdir(parents=True)
    (idle / "worker.json").write_text("{}", encoding="utf-8")
    (idle / "runtime").mkdir()
    assert module.protected_solver_ceiling(environment) == 1
    (idle / "runtime" / "unexpected").write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeError):
        module.protected_solver_ceiling(environment)
    (idle / "runtime" / "unexpected").unlink()

    active = data / "solver-exchange" / "slots" / "solver-4" / "active"
    active.mkdir(parents=True)
    assert module.protected_solver_ceiling(environment) == 4
    active.rmdir()

    retired = data / "solver-exchange" / "slots" / "solver-5" / ".retired-job"
    retired.mkdir(parents=True)
    assert module.protected_solver_ceiling(environment) == 5
    retired.rmdir()

    scratch = data / "solver-scratch" / "solver-3"
    scratch.mkdir(parents=True)
    (scratch / "credential-copy").write_text("x", encoding="utf-8")
    assert module.protected_solver_ceiling(environment) == 3
    (scratch / "credential-copy").unlink()

    with sqlite3.connect(db_path) as db:
        db.execute("INSERT INTO solver_slots VALUES('solver-6','job')")
    assert module.protected_solver_ceiling(environment) == 6


def test_local_launcher_quiesces_web_and_retains_protected_profiles(monkeypatch):
    import importlib.util
    from types import SimpleNamespace

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_main", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    commands = []
    environments = []

    monkeypatch.setattr(module, "recommended_solver_concurrency", lambda: 2)
    monkeypatch.setattr(module, "protected_solver_ceiling", lambda _environment: 6)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **kwargs: (
            commands.append(command),
            environments.append(dict(kwargs["env"])),
            SimpleNamespace(returncode=0, stdout=""),
        )[-1],
    )
    monkeypatch.setattr(module.sys, "argv", ["local-compose.py", "up", "-d"])

    assert module.main() == 0
    assert commands[0][-3:] == ["stop", "web", "solver-autoscaler"]
    assert not any("rm" in command for command in commands[1:])
    assert "solver-6" in commands[-1]
    assert environments[-1]["CTF_SOLVER_MAX_CONCURRENT"] == "2"
    assert environments[-1]["CTF_SOLVER_RECOMMENDED_CONCURRENT"] == "2"
    assert environments[-1]["CTF_SOLVER_STATIC_COUNT"] == "6"


def test_local_start_is_recreated_as_up_so_new_capacity_and_profiles_apply():
    import importlib.util

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_start", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    assert module.normalize_arguments(["--ansi", "never", "start"]) == [
        "--ansi",
        "never",
        "up",
        "-d",
    ]
    assert module.normalize_arguments(["restart"]) == [
        "up",
        "-d",
        "--force-recreate",
    ]


def test_local_stop_cleans_controller_owned_dynamic_workers(monkeypatch):
    import importlib.util
    from types import SimpleNamespace

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_stop", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        stdout = (
            "abcdef123456|ctf_agent_local_autosolver_7|7\n"
            if command[:3] == ["docker", "ps", "-a"]
            else ""
        )
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(module, "recommended_solver_concurrency", lambda: 2)
    monkeypatch.setattr(
        module,
        "validate_local_autoscaled_containers",
        lambda rows, _environment: [identifier for identifier, _slot in rows],
    )
    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(module.sys, "argv", ["local-compose.py", "stop"])
    assert module.main() == 0
    assert commands[0][-3:] == ["stop", "web", "solver-autoscaler"]
    assert ["docker", "stop", "--time", "30", "abcdef123456"] in commands
    assert ["docker", "rm", "abcdef123456"] in commands
    assert commands[-1][-1] == "stop"


def test_local_dynamic_cleanup_requires_exact_template_image_and_mounts(tmp_path, monkeypatch):
    import importlib.util
    from copy import deepcopy

    from ctf_agent.solver_autoscaler import clone_payload

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_identity", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    data = (tmp_path / "data").resolve()
    exchange = data / "solver-exchange" / "slots" / "solver-1"
    runtime = exchange / "runtime"
    scratch = data / "solver-scratch" / "solver-1"
    template = {
        "Name": "/ctf_agent_local_solver",
        "Image": "sha256:" + "a" * 64,
        "Config": {
            "User": "1000:1000",
            "Cmd": ["python", "-m", "ctf_agent.solver_worker"],
            "Env": ["HOME=/solver-scratch/worker-home"],
            "Labels": {"org.opencontainers.image.revision": "local"},
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "NetworkMode": "ctf_agent_local_default",
        },
        "Mounts": [
            {"Type": "bind", "Source": str(exchange), "Destination": "/solver-exchange", "RW": True},
            {"Type": "bind", "Source": str(exchange), "Destination": "/solver-input", "RW": False},
            {"Type": "bind", "Source": str(runtime), "Destination": "/solver-exchange/runtime", "RW": False},
            {"Type": "bind", "Source": str(scratch), "Destination": "/solver-scratch", "RW": True},
        ],
    }
    payload = clone_payload(template, 7)
    dynamic = {
        "Name": "/ctf_agent_local_autosolver_7",
        "Image": payload["Image"],
        "Config": {
            key: payload.get(key)
            for key in ("User", "Cmd", "Entrypoint", "WorkingDir", "StopSignal", "Healthcheck", "Env", "Labels")
        },
        "HostConfig": payload["HostConfig"],
        "Mounts": [
            {
                "Type": "bind",
                "Source": bind.rsplit(":", 2)[0],
                "Destination": bind.rsplit(":", 2)[1],
                "RW": bind.rsplit(":", 2)[2] == "rw",
            }
            for bind in payload["HostConfig"]["Binds"]
        ],
    }
    values = {"ctf_agent_local_solver": template, "abcdef123456": dynamic}
    monkeypatch.setattr(
        module,
        "_inspect_container",
        lambda identifier, _environment: values[identifier],
    )
    environment = {"CTF_LOCAL_DATA": str(data)}
    assert module.validate_local_autoscaled_containers(
        [("abcdef123456", 7)], environment
    ) == ["abcdef123456"]

    spoofed = deepcopy(dynamic)
    spoofed["Mounts"].append(
        {
            "Type": "bind",
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
            "RW": True,
        }
    )
    values["abcdef123456"] = spoofed
    with pytest.raises(RuntimeError, match="실행 격리"):
        module.validate_local_autoscaled_containers(
            [("abcdef123456", 7)], environment
        )


def test_local_compose_allows_explicit_capacity_above_static_profiles():
    import importlib.util

    path = Path(__file__).parents[1] / "deploy" / "local-compose.py"
    spec = importlib.util.spec_from_file_location("local_compose_large", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    commands = module.compose_commands(12, ["up", "-d"])
    assert len(commands) == 1
    assert all(f"solver-{index}" in commands[0] for index in range(2, 7))
    assert "solver-7" not in commands[0]
