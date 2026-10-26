import json
import os
import time
from copy import deepcopy
from pathlib import Path

import pytest

import ctf_agent.solver_autoscaler as autoscaler_module
from ctf_agent.solver_autoscaler import (
    MANAGED_LABEL,
    SLOT_LABEL,
    AutoscalerError,
    DockerEngine,
    SolverAutoscaler,
    clone_payload,
    read_control,
    validate_slot_container,
    write_status,
)


class _DockerResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self):
        return self._body


class _DockerConnection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, path, *, body=None, headers=None):
        self.requests.append((method, path, body, headers))

    def getresponse(self):
        return self.responses.pop(0)

    def close(self):
        pass


def test_docker_engine_negotiates_version_and_only_inspect_allows_missing(monkeypatch):
    connection = _DockerConnection(
        [
            _DockerResponse(200, b'{"ApiVersion":"1.47","MinAPIVersion":"1.24"}'),
            _DockerResponse(404, b'{"message":"No such container"}'),
            _DockerResponse(404, b'{"message":"No such image"}'),
        ]
    )
    monkeypatch.setattr(autoscaler_module, "_UnixConnection", lambda _path: connection)
    engine = DockerEngine("/test/docker.sock")

    assert engine.inspect("missing") is None
    with pytest.raises(AutoscalerError, match=r"/v1[.]47/containers/create"):
        engine.create("ctf-solver-7", {"Image": "sha256:" + "a" * 64})

    assert [(method, path) for method, path, _body, _headers in connection.requests] == [
        ("GET", "/version"),
        ("GET", "/v1.47/containers/missing/json"),
        ("POST", "/v1.47/containers/create?name=ctf-solver-7"),
    ]


def _template(tmp_path: Path):
    exchange = tmp_path / "solver-exchange" / "slots" / "solver-1"
    scratch = tmp_path / "solver-scratch" / "solver-1"
    runtime = exchange / "runtime"
    runtime.mkdir(parents=True)
    scratch.mkdir(parents=True)
    return {
        "Image": "sha256:" + "a" * 64,
        "State": {"Running": True},
        "Config": {
            "Image": "ctf-agent:current",
            "User": "10001:10001",
            "Cmd": ["python", "-m", "ctf_agent.solver_worker"],
            "Env": ["HOME=/solver-scratch/worker-home"],
            "Labels": {"com.docker.compose.service": "solver", "safe": "kept"},
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true", "apparmor=ctf-agent-solver"],
            "NetworkMode": "ctf_agent_solver_egress",
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
        },
        "Mounts": [
            {"Type": "bind", "Source": str(exchange), "Destination": "/solver-exchange", "RW": True},
            {"Type": "bind", "Source": str(exchange), "Destination": "/solver-input", "RW": False},
            {"Type": "bind", "Source": str(runtime), "Destination": "/solver-exchange/runtime", "RW": False},
            {"Type": "bind", "Source": str(scratch), "Destination": "/solver-scratch", "RW": True},
        ],
    }


def test_control_accepts_unbounded_positive_desired_count(tmp_path):
    path = tmp_path / "pool-control.json"
    now = time.time()
    path.write_text(
        json.dumps(
            {
                "protocol": 1,
                "desired": 37,
                "target": 37,
                "baseline": 6,
                "hard_max": 0,
                "open_jobs": 37,
                "updated_at": now,
            }
        ),
        encoding="utf-8",
    )
    assert read_control(path, now=now)["desired"] == 37
    with pytest.raises(AutoscalerError, match="stale"):
        read_control(path, now=now + 31)


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW is a Linux controller boundary")
def test_control_rejects_symlink_and_status_replaces_it_without_touching_target(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    control = tmp_path / "pool-control.json"
    control.symlink_to(target)
    with pytest.raises(AutoscalerError, match="unavailable"):
        read_control(control)

    status = tmp_path / "autoscaler.json"
    status.symlink_to(target)
    before = target.stat().st_mode
    write_status(status, {"protocol": 1, "ready": True})
    assert not status.is_symlink()
    assert json.loads(status.read_text(encoding="utf-8"))["ready"] is True
    assert target.stat().st_mode == before


@pytest.mark.skipif(os.name != "posix", reason="host ownership is enforced on Linux")
def test_autoscaler_refuses_web_owned_slot_parents(tmp_path):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        control_path=tmp_path / "control",
        storage_root=tmp_path,
    )
    with pytest.raises(AutoscalerError, match="host-owned"):
        scaler.reconcile({"desired": 2})
    assert engine.created == []


def test_clone_preserves_isolation_and_replaces_only_per_slot_binds(tmp_path):
    template = _template(tmp_path)
    payload = clone_payload(template, 12)
    assert payload["Image"].startswith("sha256:")
    assert payload["HostConfig"]["ReadonlyRootfs"] is True
    assert payload["HostConfig"]["CapDrop"] == ["ALL"]
    assert "apparmor=ctf-agent-solver" in payload["HostConfig"]["SecurityOpt"]
    assert payload["Labels"] == {
        "safe": "kept",
        MANAGED_LABEL: "true",
        SLOT_LABEL: "12",
    }
    binds = payload["HostConfig"]["Binds"]
    assert f"{tmp_path / 'solver-exchange' / 'slots' / 'solver-12'}:/solver-exchange:rw" in binds
    assert f"{tmp_path / 'solver-exchange' / 'slots' / 'solver-12'}:/solver-input:ro" in binds
    assert f"{tmp_path / 'solver-scratch' / 'solver-12'}:/solver-scratch:rw" in binds
    assert f"{tmp_path / 'solver-exchange' / 'slots' / 'solver-1' / 'runtime'}:/solver-exchange/runtime:ro" in binds


class _FakeEngine:
    def __init__(self, template):
        self.template = template
        self.containers = {"ctf_agent_solver": template}
        self.created = []
        self.started = []
        self.removed = []

    def inspect(self, name):
        return self.containers.get(name)

    def create(self, name, payload):
        self.created.append((name, payload))
        slot = int(payload["Labels"][SLOT_LABEL])
        mounts = []
        for bind in payload["HostConfig"]["Binds"]:
            source, destination, mode = bind.rsplit(":", 2)
            mounts.append(
                {
                    "Type": "bind",
                    "Source": source,
                    "Destination": destination,
                    "RW": mode == "rw",
                }
            )
        self.containers[name] = {
            "Image": payload["Image"],
            "State": {"Running": False},
            "Config": {
                "User": payload.get("User"),
                "Cmd": payload.get("Cmd"),
                "Entrypoint": payload.get("Entrypoint"),
                "WorkingDir": payload.get("WorkingDir"),
                "StopSignal": payload.get("StopSignal"),
                "Healthcheck": payload.get("Healthcheck"),
                "Env": payload.get("Env"),
                "Labels": payload["Labels"],
            },
            "HostConfig": payload["HostConfig"],
            "Labels": payload["Labels"],
            "Names": ["/" + name],
            "Mounts": mounts,
        }

    def start(self, name):
        self.started.append(name)
        self.containers[name]["State"] = {"Running": True}

    def stop(self, name, *, timeout=30):
        self.containers[name]["State"] = {"Running": False}

    def remove(self, name):
        self.removed.append(name)
        self.containers.pop(name, None)

    def managed(self):
        return [
            {**value, "Names": ["/" + name]}
            for name, value in self.containers.items()
            if (value.get("Labels") or {}).get(MANAGED_LABEL) == "true"
        ]


def test_autoscaler_grows_in_steps_and_removes_only_owned_surplus(tmp_path):
    engine = _FakeEngine(_template(tmp_path))
    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        control_path=tmp_path / "control",
        storage_root=tmp_path,
        step=3,
        require_protected_parents=False,
    )
    first = scaler.reconcile({"desired": 8})
    assert first["desired"] == 8
    assert first["available"] == 4
    assert first["created"] == 3
    assert first["removed"] == 0
    assert first["warming"] is True
    assert [item[0] for item in engine.created] == [
        "ctf_agent_solver_2",
        "ctf_agent_solver_3",
        "ctf_agent_solver_4",
    ]
    scaler.reconcile({"desired": 8})
    scaler.reconcile({"desired": 8})
    engine.containers["unrelated"] = {
        "State": {"Running": True},
        "Labels": {},
        "Names": ["/unrelated"],
    }
    result = scaler.reconcile({"desired": 3})
    assert result["removed"] == 5
    assert set(engine.removed) == {f"ctf_agent_solver_{index}" for index in range(4, 9)}
    assert "unrelated" in engine.containers


def test_autoscaler_retains_stopped_surplus_with_job_material(tmp_path):
    engine = _FakeEngine(_template(tmp_path))
    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        control_path=tmp_path / "control",
        storage_root=tmp_path,
        require_protected_parents=False,
    )
    scaler.reconcile({"desired": 2})
    active = tmp_path / "solver-exchange" / "slots" / "solver-2" / "active"
    active.mkdir()
    result = scaler.reconcile({"desired": 1})
    assert result["retained"] == 1
    assert "ctf_agent_solver_2" in engine.containers
    assert engine.containers["ctf_agent_solver_2"]["State"]["Running"] is True


def test_autoscaler_rejects_unowned_same_name_collision(tmp_path):
    engine = _FakeEngine(_template(tmp_path))
    engine.containers["ctf_agent_solver_2"] = {
        "Image": "sha256:" + "b" * 64,
        "State": {"Running": True},
        "Config": {"Labels": {}},
        "HostConfig": {},
        "Mounts": [],
    }
    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        control_path=tmp_path / "control",
        storage_root=tmp_path,
        require_protected_parents=False,
    )
    with pytest.raises(AutoscalerError):
        scaler.reconcile({"desired": 2})
    assert engine.removed == []


def test_container_validation_rejects_one_extra_host_bind(tmp_path):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    payload = clone_payload(template, 2)
    engine.create("ctf_agent_solver_2", payload)
    container = engine.inspect("ctf_agent_solver_2")
    container["Mounts"].append(
        {
            "Type": "bind",
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
            "RW": True,
        }
    )
    with pytest.raises(AutoscalerError, match="exact slot binds"):
        validate_slot_container(container, template, 2, managed_required=True)


def test_container_validation_accepts_equivalent_no_new_privileges_inspect_forms(tmp_path):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    engine.create("ctf_agent_solver_2", clone_payload(template, 2))
    container = engine.inspect("ctf_agent_solver_2")
    container["HostConfig"]["SecurityOpt"] = [
        "no-new-privileges",
        "apparmor=ctf-agent-solver",
    ]

    validate_slot_container(container, template, 2, managed_required=True)

    container["HostConfig"]["SecurityOpt"] = ["apparmor=ctf-agent-solver"]
    with pytest.raises(AutoscalerError, match="SecurityOpt"):
        validate_slot_container(container, template, 2, managed_required=True)


@pytest.mark.parametrize(
    ("field", "empty_value"),
    [
        ("CapAdd", []),
        ("Devices", []),
        ("DeviceRequests", []),
        ("DeviceCgroupRules", []),
        ("ExtraHosts", []),
        ("Dns", []),
        ("Ulimits", []),
        ("PortBindings", {}),
        ("Sysctls", {}),
    ],
)
def test_container_validation_accepts_equivalent_empty_host_config_forms(
    tmp_path, field, empty_value
):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    engine.create("ctf_agent_solver_2", clone_payload(template, 2))
    container = engine.inspect("ctf_agent_solver_2")
    container["HostConfig"][field] = empty_value

    validate_slot_container(container, template, 2, managed_required=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Privileged", True),
        ("CapAdd", ["SYS_ADMIN"]),
        ("Devices", [{"PathOnHost": "/dev/kvm"}]),
        ("DeviceRequests", [{"Count": -1, "Capabilities": [["gpu"]]}]),
        ("PidMode", "host"),
        ("UsernsMode", "host"),
        ("UTSMode", "host"),
        ("PortBindings", {"5050/tcp": [{"HostPort": "5050"}]}),
        ("ExtraHosts", ["host.docker.internal:host-gateway"]),
    ],
)
def test_container_validation_rejects_unexpected_privilege_fields(tmp_path, field, value):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    payload = clone_payload(template, 2)
    engine.create("ctf_agent_solver_2", payload)
    container = engine.inspect("ctf_agent_solver_2")
    container["HostConfig"][field] = value
    with pytest.raises(AutoscalerError, match="isolation"):
        validate_slot_container(container, template, 2, managed_required=True)


def test_static_count_six_accepts_compose_worker_without_dynamic_slot_env(tmp_path):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    static = deepcopy(template)
    static["State"] = {"Running": True}
    for mount in static["Mounts"]:
        destination = mount["Destination"]
        if destination in {"/solver-exchange", "/solver-input"}:
            mount["Source"] = str(
                tmp_path / "solver-exchange" / "slots" / "solver-2"
            )
        elif destination == "/solver-scratch":
            mount["Source"] = str(tmp_path / "solver-scratch" / "solver-2")
    engine.containers["ctf_agent_solver_2"] = static
    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        static_prefix="ctf_agent_solver_",
        static_count=6,
        control_path=tmp_path / "control",
        storage_root=tmp_path,
        require_protected_parents=False,
    )
    result = scaler.reconcile({"desired": 2})
    assert result["available"] == 2
    assert result["created"] == 0
    assert engine.created == []


def test_missing_static_worker_is_left_for_compose_instead_of_shadow_created(tmp_path):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        static_prefix="ctf_agent_solver_",
        static_count=6,
        control_path=tmp_path / "control",
        storage_root=tmp_path,
        require_protected_parents=False,
    )
    result = scaler.reconcile({"desired": 6})
    assert result["available"] == 1
    assert result["warming"] is True
    assert engine.created == []


def test_production_static_boundary_creates_the_first_dynamic_slot_seven(tmp_path):
    template = _template(tmp_path)
    engine = _FakeEngine(template)
    for slot in range(2, 7):
        static = deepcopy(template)
        for mount in static["Mounts"]:
            destination = mount["Destination"]
            if destination in {"/solver-exchange", "/solver-input"}:
                mount["Source"] = str(
                    tmp_path / "solver-exchange" / "slots" / f"solver-{slot}"
                )
            elif destination == "/solver-scratch":
                mount["Source"] = str(tmp_path / "solver-scratch" / f"solver-{slot}")
        engine.containers[f"ctf_agent_solver_{slot}"] = static

    scaler = SolverAutoscaler(
        engine,
        template_name="ctf_agent_solver",
        container_prefix="ctf_agent_solver_",
        static_prefix="ctf_agent_solver_",
        static_count=6,
        control_path=tmp_path / "control",
        storage_root=tmp_path,
        require_protected_parents=False,
    )
    result = scaler.reconcile({"desired": 7})

    assert result["available"] == 7
    assert [name for name, _payload in engine.created] == ["ctf_agent_solver_7"]
    payload = engine.created[0][1]
    assert payload["Labels"][SLOT_LABEL] == "7"
    assert any("solver-7:/solver-exchange:rw" in bind for bind in payload["HostConfig"]["Binds"])
