"""Docker host controller for demand-sized isolated solver containers.

The web process publishes a desired count and optionally exact slot IDs. This controller is
the sole component with access to the Docker socket.  It clones the already
attested first worker, substitutes only the per-slot exchange and scratch
binds, and removes only containers carrying its private ownership labels.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import signal
import socket
import stat
import time
import urllib.parse
from pathlib import Path
from typing import Any, Mapping


PROTOCOL = 1
MANAGED_LABEL = "io.github.ctf-agent.autoscaled"
SLOT_LABEL = "io.github.ctf-agent.solver-slot"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_MAX_CONTROL_BYTES = 64 * 1024


class AutoscalerError(RuntimeError):
    pass


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str):
        super().__init__("localhost", timeout=10)
        self.socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self.socket_path)
        self.sock = connection


class DockerEngine:
    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path
        self._api_version: str | None = None

    def _raw_request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        allow_not_found: bool = False,
    ) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        try:
            connection = _UnixConnection(self.socket_path)
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                data = response.read()
            finally:
                connection.close()
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise AutoscalerError("Docker Engine is unavailable") from exc
        if response.status == 404 and allow_not_found:
            return None
        if response.status < 200 or response.status >= 300:
            detail = data.decode("utf-8", "replace")[:500]
            raise AutoscalerError(f"Docker API {method} {path} returned {response.status}: {detail}")
        if not data:
            return None
        try:
            return json.loads(data)
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise AutoscalerError("Docker API returned an invalid JSON response") from exc

    def _version(self) -> str:
        if self._api_version is not None:
            return self._api_version
        details = self._raw_request("GET", "/version")
        version = details.get("ApiVersion") if isinstance(details, Mapping) else None
        if not isinstance(version, str) or not re.fullmatch(r"1[.][0-9]+", version):
            raise AutoscalerError("Docker Engine reported an invalid API version")
        self._api_version = version
        return version

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        allow_not_found: bool = False,
    ) -> Any:
        if not path.startswith("/"):
            raise AutoscalerError("Docker API path is invalid")
        versioned_path = f"/v{self._version()}{path}"
        return self._raw_request(
            method,
            versioned_path,
            payload,
            allow_not_found=allow_not_found,
        )

    def inspect(self, name: str) -> dict[str, Any] | None:
        return self.request(
            "GET",
            f"/containers/{urllib.parse.quote(name, safe='')}/json",
            allow_not_found=True,
        )

    def create(self, name: str, payload: Mapping[str, Any]) -> None:
        encoded = urllib.parse.quote(name, safe="")
        self.request("POST", f"/containers/create?name={encoded}", payload)

    def start(self, name: str) -> None:
        self.request("POST", f"/containers/{urllib.parse.quote(name, safe='')}/start")

    def stop(self, name: str, *, timeout: int = 30) -> None:
        self.request(
            "POST",
            f"/containers/{urllib.parse.quote(name, safe='')}/stop?t={max(0, timeout)}",
        )

    def remove(self, name: str) -> None:
        self.request("DELETE", f"/containers/{urllib.parse.quote(name, safe='')}?v=1")

    def managed(self) -> list[dict[str, Any]]:
        filters = urllib.parse.quote(json.dumps({"label": [f"{MANAGED_LABEL}=true"]}))
        result = self.request("GET", f"/containers/json?all=1&filters={filters}")
        return result if isinstance(result, list) else []


def read_control(path: Path, *, now: float | None = None, max_age: float = 30.0) -> dict[str, Any]:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if os.name == "posix":
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            state = os.fstat(descriptor)
            if not stat.S_ISREG(state.st_mode) or state.st_size > _MAX_CONTROL_BYTES:
                raise AutoscalerError("solver capacity control is not a regular bounded file")
            chunks = bytearray()
            while len(chunks) <= _MAX_CONTROL_BYTES:
                chunk = os.read(descriptor, min(65536, _MAX_CONTROL_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            if len(chunks) > _MAX_CONTROL_BYTES:
                raise AutoscalerError("solver capacity control is oversized")
            value = json.loads(bytes(chunks).decode("utf-8", "strict"))
        finally:
            os.close(descriptor)
    except (OSError, ValueError, TypeError) as exc:
        raise AutoscalerError("solver capacity control is unavailable") from exc
    if not isinstance(value, dict) or value.get("protocol") != PROTOCOL:
        raise AutoscalerError("solver capacity control protocol is invalid")
    fields: dict[str, int] = {}
    for key in ("desired", "target", "baseline", "hard_max", "open_jobs"):
        item = value.get(key)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise AutoscalerError("solver capacity control contains an invalid count")
        fields[key] = item
    if fields["desired"] < 1 or fields["target"] < 1 or fields["baseline"] < 1:
        raise AutoscalerError("solver capacity control requires a positive worker count")
    if fields["target"] > fields["desired"]:
        raise AutoscalerError("solver capacity control target exceeds retained workers")
    slots = value.get("slots")
    if slots is not None:
        if (
            not isinstance(slots, list)
            or len(slots) != fields["desired"]
            or not slots
            or slots[0] != 1
            or any(
                not isinstance(slot, int) or isinstance(slot, bool) or slot < 1
                for slot in slots
            )
            or slots != sorted(set(slots))
        ):
            raise AutoscalerError("solver capacity control has invalid slot identities")
        fields["slots"] = slots
    updated = value.get("updated_at")
    if not isinstance(updated, (int, float)) or isinstance(updated, bool):
        raise AutoscalerError("solver capacity control timestamp is invalid")
    if (now if now is not None else time.time()) - float(updated) > max_age:
        raise AutoscalerError("solver capacity control is stale")
    return fields


def _slot_source(source: str, destination: str, slot: int) -> str:
    path = Path(source)
    if destination in {"/solver-exchange", "/solver-input"}:
        if not re.fullmatch(r"solver-[1-9][0-9]*", path.name):
            raise AutoscalerError("template exchange bind is not a solver slot")
        return str(path.parent / f"solver-{slot}")
    if destination == "/solver-scratch":
        if not re.fullmatch(r"solver-[1-9][0-9]*", path.name):
            raise AutoscalerError("template scratch bind is not a solver slot")
        return str(path.parent / f"solver-{slot}")
    return source


def _open_directory(path: Path, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name == "posix":
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, dir_fd=dir_fd)


def _open_relative_directory(root: Path, parts: tuple[str, ...]) -> int:
    """Open a fixed directory chain without following a swapped link."""

    descriptor = _open_directory(root)
    try:
        for part in parts:
            if not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise AutoscalerError("solver storage path component is invalid")
            child = _open_directory(Path(part), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_protected_parent(descriptor: int) -> os.stat_result:
    state = os.fstat(descriptor)
    if not stat.S_ISDIR(state.st_mode):
        raise AutoscalerError("solver slot parent is invalid")
    if os.name == "posix" and (
        state.st_uid != 0 or state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise AutoscalerError("solver slot parent is not host-owned and protected")
    return state


def _open_or_create_child(parent: int, name: str, mode: int) -> int:
    try:
        os.mkdir(name, mode=mode, dir_fd=parent)
    except FileExistsError:
        pass
    try:
        return _open_directory(Path(name), dir_fd=parent)
    except OSError as exc:
        raise AutoscalerError("solver slot path is invalid") from exc


def _same_directory_entry(parent: int, name: str, descriptor: int) -> bool:
    opened = os.fstat(descriptor)
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == opened.st_dev
        and current.st_ino == opened.st_ino
    )


def _prepare_managed_slot(slot: int, storage_root: Path) -> None:
    """Prepare immutable bind roots before Docker resolves their host paths."""

    slots_parent = _open_relative_directory(storage_root, ("solver-exchange", "slots"))
    scratch_parent = _open_relative_directory(storage_root, ("solver-scratch",))
    try:
        slots_state = _require_protected_parent(slots_parent)
        _require_protected_parent(scratch_parent)
        exchange_fd = _open_or_create_child(slots_parent, f"solver-{slot}", 0o1770)
        scratch_fd = _open_or_create_child(scratch_parent, f"solver-{slot}", 0o700)
        try:
            template_scratch = _open_relative_directory(
                storage_root, ("solver-scratch", "solver-1")
            )
            try:
                scratch_owner = os.fstat(template_scratch)
            finally:
                os.close(template_scratch)

            # The parent makes the exchange inode stable. Sticky root ownership
            # then protects its runtime child while UID/GID 10001 writes jobs.
            if hasattr(os, "fchown"):
                os.fchown(exchange_fd, 0, slots_state.st_gid)
            os.fchmod(exchange_fd, 0o1770)

            runtime_fd = _open_or_create_child(exchange_fd, "runtime", 0o770)
            try:
                if hasattr(os, "fchown"):
                    os.fchown(runtime_fd, 0, slots_state.st_gid)
                os.fchmod(runtime_fd, 0o770)
                if not _same_directory_entry(exchange_fd, "runtime", runtime_fd):
                    raise AutoscalerError("solver runtime mountpoint changed during preparation")
            finally:
                os.close(runtime_fd)

            scratch_state = os.fstat(scratch_fd)
            scratch_target = (scratch_owner.st_uid, scratch_owner.st_gid)
            scratch_current = (scratch_state.st_uid, scratch_state.st_gid)
            if scratch_current == scratch_target:
                if stat.S_IMODE(scratch_state.st_mode) != 0o700:
                    raise AutoscalerError("solver scratch slot permissions are invalid")
            else:
                # Set the mode while this process still owns the newly-created
                # inode.  The controller needs CAP_CHOWN only; it deliberately
                # does not receive CAP_FOWNER.
                if scratch_state.st_uid != 0:
                    raise AutoscalerError("solver scratch slot ownership is invalid")
                os.fchmod(scratch_fd, 0o700)
                if hasattr(os, "fchown"):
                    os.fchown(scratch_fd, *scratch_target)
                changed = os.fstat(scratch_fd)
                if (changed.st_uid, changed.st_gid) != scratch_target:
                    raise AutoscalerError("solver scratch slot ownership was not applied")
            if not _same_directory_entry(slots_parent, f"solver-{slot}", exchange_fd):
                raise AutoscalerError("solver exchange slot changed during preparation")
            if not _same_directory_entry(scratch_parent, f"solver-{slot}", scratch_fd):
                raise AutoscalerError("solver scratch slot changed during preparation")
        finally:
            os.close(exchange_fd)
            os.close(scratch_fd)
    finally:
        os.close(slots_parent)
        os.close(scratch_parent)


def _prepare_slot(
    template: Mapping[str, Any],
    slot: int,
    storage_root: Path,
    *,
    require_protected_parents: bool = True,
) -> None:
    mounts = template.get("Mounts")
    if not isinstance(mounts, list):
        raise AutoscalerError("template mounts are unavailable")
    required = {"/solver-exchange", "/solver-input", "/solver-scratch"}
    seen: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, Mapping):
            continue
        destination, source = mount.get("Destination"), mount.get("Source")
        if destination not in required or not isinstance(source, str):
            continue
        seen.add(destination)
    if seen != required:
        raise AutoscalerError("template is missing an isolated solver bind")
    if os.name == "posix" and require_protected_parents:
        try:
            _prepare_managed_slot(slot, storage_root)
        except OSError as exc:
            raise AutoscalerError("solver slot ownership preparation failed") from exc
        return

    # Development-host fallback. Production and Linux CI use the dirfd path.
    for relative in (
        Path("solver-exchange") / "slots" / f"solver-{slot}",
        Path("solver-scratch") / f"solver-{slot}",
    ):
        target = storage_root / relative
        parent_state = target.parent.lstat()
        if stat.S_ISLNK(parent_state.st_mode) or not stat.S_ISDIR(parent_state.st_mode):
            raise AutoscalerError("solver slot parent is invalid")
        target.mkdir(mode=0o700, exist_ok=True)
        if target.is_symlink() or not target.is_dir():
            raise AutoscalerError("solver slot path is invalid")
    runtime = storage_root / "solver-exchange" / "slots" / f"solver-{slot}" / "runtime"
    runtime.mkdir(mode=0o755, exist_ok=True)
    if runtime.is_symlink() or not runtime.is_dir():
        raise AutoscalerError("solver runtime mountpoint is invalid")


def clone_payload(template: Mapping[str, Any], slot: int) -> dict[str, Any]:
    if slot < 2:
        raise AutoscalerError("only additional solver slots may be cloned")
    config = template.get("Config")
    host = template.get("HostConfig")
    mounts = template.get("Mounts")
    if not isinstance(config, Mapping) or not isinstance(host, Mapping) or not isinstance(mounts, list):
        raise AutoscalerError("solver template inspection is incomplete")
    image = template.get("Image")
    if not isinstance(image, str) or not image.startswith("sha256:"):
        raise AutoscalerError("solver template image is not immutable")
    labels = {
        str(key): str(value)
        for key, value in (config.get("Labels") or {}).items()
        if not str(key).startswith("com.docker.compose.")
    }
    labels.update({MANAGED_LABEL: "true", SLOT_LABEL: str(slot)})
    environment = [
        str(item)
        for item in (config.get("Env") or [])
        if not str(item).startswith("CTF_SOLVER_SLOT_INDEX=")
    ]
    environment.append(f"CTF_SOLVER_SLOT_INDEX={slot}")
    binds = []
    required = {"/solver-exchange", "/solver-input", "/solver-scratch"}
    seen: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, Mapping) or mount.get("Type") != "bind":
            raise AutoscalerError("solver template contains an unsupported mount")
        source, destination = mount.get("Source"), mount.get("Destination")
        if not isinstance(source, str) or not isinstance(destination, str):
            raise AutoscalerError("solver template bind is invalid")
        if destination in required:
            seen.add(destination)
        source = _slot_source(source, destination, slot)
        binds.append(f"{source}:{destination}:{'rw' if mount.get('RW') else 'ro'}")
    if seen != required:
        raise AutoscalerError("solver template isolation binds are incomplete")
    host_keys = (
        "ReadonlyRootfs", "CapDrop", "SecurityOpt", "Tmpfs", "Dns",
        "RestartPolicy", "NetworkMode", "Memory", "MemorySwap", "NanoCpus",
        "PidsLimit", "Init", "IpcMode", "ShmSize",
    )
    host_config = {key: host[key] for key in host_keys if key in host and host[key] is not None}
    host_config["Binds"] = binds
    payload: dict[str, Any] = {
        "Image": image,
        "Env": environment,
        "Labels": labels,
        "HostConfig": host_config,
    }
    for key in ("User", "Cmd", "Entrypoint", "WorkingDir", "StopSignal", "Healthcheck"):
        if key in config and config[key] is not None:
            payload[key] = config[key]
    return payload


def _normalized_security_options(value: Any) -> tuple[str, ...] | None:
    """Normalize Docker's two equivalent no-new-privileges inspect forms."""

    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return tuple(
        sorted(
            "no-new-privileges"
            if item in {"no-new-privileges", "no-new-privileges:true"}
            else item
            for item in value
        )
    )


_OPTIONAL_SEQUENCE_HOST_FIELDS = frozenset(
    {
        "CapAdd",
        "CapDrop",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "Links",
        "ExtraHosts",
        "VolumesFrom",
        "GroupAdd",
        "ReadonlyPaths",
        "MaskedPaths",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "Ulimits",
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
    }
)
_OPTIONAL_MAPPING_HOST_FIELDS = frozenset({"PortBindings", "Sysctls", "Tmpfs"})


def _host_option_equal(key: str, value: Any, template_value: Any) -> bool:
    """Compare Docker HostConfig values after only lossless empty normalization."""

    if key == "SecurityOpt":
        return _normalized_security_options(value) == _normalized_security_options(
            template_value
        )
    if key in _OPTIONAL_SEQUENCE_HOST_FIELDS:
        if value is None:
            value = []
        if template_value is None:
            template_value = []
        return (
            isinstance(value, list)
            and isinstance(template_value, list)
            and value == template_value
        )
    if key in _OPTIONAL_MAPPING_HOST_FIELDS:
        if value is None:
            value = {}
        if template_value is None:
            template_value = {}
        return (
            isinstance(value, Mapping)
            and isinstance(template_value, Mapping)
            and value == template_value
        )
    return value == template_value


def validate_slot_container(
    container: Mapping[str, Any],
    template: Mapping[str, Any],
    slot: int,
    *,
    managed_required: bool,
    allow_release_mismatch: bool = False,
) -> None:
    if allow_release_mismatch:
        current_image = container.get("Image")
        if not isinstance(current_image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", current_image):
            raise AutoscalerError("solver container image identity is invalid")
    elif container.get("Image") != template.get("Image"):
        raise AutoscalerError("solver container image does not match the template")
    config = container.get("Config") or {}
    template_config = template.get("Config") or {}
    labels = config.get("Labels") or {}
    template_labels = template_config.get("Labels") or {}
    if managed_required and (
        labels.get(MANAGED_LABEL) != "true" or labels.get(SLOT_LABEL) != str(slot)
    ):
        raise AutoscalerError("solver container ownership label is invalid")
    current_release = labels.get("org.opencontainers.image.revision")
    template_release = template_labels.get("org.opencontainers.image.revision")
    if allow_release_mismatch and template_release is not None and not (
        isinstance(current_release, str) and re.fullmatch(r"[0-9a-f]{40}", current_release)
    ):
        raise AutoscalerError("solver container release identity is invalid")
    if not allow_release_mismatch and current_release != template_release:
        raise AutoscalerError("solver container release label does not match the template")
    for key in ("User", "Cmd", "Entrypoint", "WorkingDir", "StopSignal", "Healthcheck"):
        if config.get(key) != template_config.get(key):
            raise AutoscalerError("solver container process configuration is invalid")
    release_environment = (
        "CTF_RELEASE_SHA=",
        "CTF_IMAGE_CODEX_VERSION=",
        "CTF_IMAGE_CLAUDE_VERSION=",
    )
    expected_environment = [
        str(item)
        for item in (template_config.get("Env") or [])
        if not str(item).startswith("CTF_SOLVER_SLOT_INDEX=")
        and not (allow_release_mismatch and str(item).startswith(release_environment))
    ]
    if managed_required:
        expected_environment.append(f"CTF_SOLVER_SLOT_INDEX={slot}")
    expected_environment.sort()
    actual_environment = sorted(
        str(item)
        for item in (config.get("Env") or [])
        if not (allow_release_mismatch and str(item).startswith(release_environment))
    )
    if actual_environment != expected_environment:
        raise AutoscalerError("solver container environment is invalid")
    host = container.get("HostConfig") or {}
    template_host = template.get("HostConfig") or {}
    for key in (
        "ReadonlyRootfs",
        "CapDrop",
        "CapAdd",
        "SecurityOpt",
        "NetworkMode",
        "Privileged",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "PidMode",
        "UsernsMode",
        "UTSMode",
        "CgroupnsMode",
        "PublishAllPorts",
        "PortBindings",
        "Links",
        "ExtraHosts",
        "VolumesFrom",
        "GroupAdd",
        "Sysctls",
        "Cgroup",
        "CgroupParent",
        "ReadonlyPaths",
        "MaskedPaths",
        "OomKillDisable",
        "AutoRemove",
        "Runtime",
        "Isolation",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "RestartPolicy",
        "Tmpfs",
        "Memory",
        "MemoryReservation",
        "MemorySwap",
        "MemorySwappiness",
        "NanoCpus",
        "CpuShares",
        "CpuPeriod",
        "CpuQuota",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
        "CpusetCpus",
        "CpusetMems",
        "Ulimits",
        "BlkioWeight",
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
        "PidsLimit",
        "Init",
        "IpcMode",
        "ShmSize",
    ):
        if not _host_option_equal(key, host.get(key), template_host.get(key)):
            raise AutoscalerError(
                f"solver container isolation does not match the template ({key})"
            )
    mounts = container.get("Mounts")
    template_mounts = template.get("Mounts")
    if not isinstance(mounts, list) or not isinstance(template_mounts, list):
        raise AutoscalerError("solver container mounts are unavailable")
    expected_mounts: list[tuple[str, str, str, bool, str]] = []
    for mount in template_mounts:
        if (
            not isinstance(mount, Mapping)
            or mount.get("Type") != "bind"
            or not isinstance(mount.get("Source"), str)
            or not isinstance(mount.get("Destination"), str)
        ):
            raise AutoscalerError("solver template mount is invalid")
        expected_mounts.append(
            (
                "bind",
                _slot_source(str(mount["Source"]), str(mount["Destination"]), slot),
                str(mount["Destination"]),
                bool(mount.get("RW")),
                str(mount.get("Propagation") or "rprivate"),
            )
        )
    actual_mounts: list[tuple[str, str, str, bool, str]] = []
    for mount in mounts:
        if (
            not isinstance(mount, Mapping)
            or not isinstance(mount.get("Type"), str)
            or not isinstance(mount.get("Source"), str)
            or not isinstance(mount.get("Destination"), str)
        ):
            raise AutoscalerError("solver container mount is invalid")
        actual_mounts.append(
            (
                str(mount["Type"]),
                str(mount["Source"]),
                str(mount["Destination"]),
                bool(mount.get("RW")),
                str(mount.get("Propagation") or "rprivate"),
            )
        )
    if sorted(actual_mounts) != sorted(expected_mounts):
        raise AutoscalerError("solver container does not own the exact slot binds")


def _slot_is_idle(storage_root: Path, slot: int) -> bool:
    """Fail closed unless the stopped worker slot contains no job material."""

    exchange = storage_root / "solver-exchange" / "slots" / f"solver-{slot}"
    scratch = storage_root / "solver-scratch" / f"solver-{slot}"
    for path in (exchange, scratch):
        try:
            state = path.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(state.st_mode) or not stat.S_ISDIR(state.st_mode):
            return False
    try:
        if next(scratch.iterdir(), None) is not None:
            return False
        for entry in exchange.iterdir():
            if entry.name in {"worker.json", "worker.lock"}:
                if entry.is_symlink() or not entry.is_file():
                    return False
                continue
            if entry.name == "runtime":
                if entry.is_symlink() or not entry.is_dir():
                    return False
                if next(entry.iterdir(), None) is not None:
                    return False
                continue
            return False
    except OSError:
        return False
    return True


def write_status(path: Path, payload: Mapping[str, Any]) -> None:
    """Publish controller health atomically for the unprivileged web process."""

    parent = path.parent
    try:
        parent_fd = _open_directory(parent)
    except OSError as exc:
        raise AutoscalerError("autoscaler status directory is invalid") from exc
    temporary = f".autoscaler-status-{secrets.token_hex(16)}"
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if os.name == "posix":
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        published_state = os.fstat(descriptor)
        os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != published_state.st_dev
            or current.st_ino != published_state.st_ino
        ):
            raise AutoscalerError("autoscaler status publication was replaced")
        os.fsync(parent_fd)
    except OSError as exc:
        raise AutoscalerError("autoscaler status publication failed") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_fd)


class SolverAutoscaler:
    def __init__(
        self,
        engine: DockerEngine,
        *,
        template_name: str,
        container_prefix: str,
        control_path: Path,
        static_prefix: str | None = None,
        static_count: int = 1,
        static_slots: set[int] | None = None,
        storage_root: Path = Path("/data"),
        step: int = 8,
        require_protected_parents: bool = True,
    ):
        if not _NAME.fullmatch(template_name) or not _NAME.fullmatch(container_prefix):
            raise AutoscalerError("solver container naming policy is invalid")
        if static_prefix is not None and not _NAME.fullmatch(static_prefix):
            raise AutoscalerError("static solver container naming policy is invalid")
        if static_count < 1:
            raise AutoscalerError("static solver count must be positive")
        if static_slots is not None and (
            1 not in static_slots
            or any(not isinstance(slot, int) or isinstance(slot, bool) or slot < 1
                   or slot > static_count for slot in static_slots)
        ):
            raise AutoscalerError("static solver slot identities are invalid")
        if step < 1:
            raise AutoscalerError("autoscale step must be positive")
        self.engine = engine
        self.template_name = template_name
        self.container_prefix = container_prefix
        self.static_prefix = static_prefix or container_prefix
        self.static_count = static_count
        self.static_slots = (
            set(static_slots) if static_slots is not None else set(range(1, static_count + 1))
        )
        self.control_path = control_path
        self.storage_root = storage_root
        self.step = step
        self.require_protected_parents = bool(require_protected_parents)

    def name(self, slot: int) -> str:
        if slot == 1:
            return self.template_name
        prefix = self.static_prefix if slot in self.static_slots else self.container_prefix
        return f"{prefix}{slot}"

    def _slot_of(self, container: Mapping[str, Any]) -> int | None:
        labels = container.get("Labels") or {}
        if labels.get(MANAGED_LABEL) != "true":
            return None
        raw = labels.get(SLOT_LABEL)
        try:
            slot = int(raw)
        except (TypeError, ValueError):
            return None
        return slot if slot >= 2 else None

    def reconcile(self, control: Mapping[str, Any]) -> dict[str, Any]:
        desired = int(control["desired"])
        slots = control.get("slots")
        if slots is None:
            # Protocol-one controls from older web releases remain dense.
            selected = list(range(1, desired + 1))
        elif (
            not isinstance(slots, list)
            or not slots
            or len(slots) != desired
            or slots[0] != 1
            or any(not isinstance(slot, int) or isinstance(slot, bool) or slot < 1 for slot in slots)
            or slots != sorted(set(slots))
        ):
            raise AutoscalerError("solver capacity control has invalid slot identities")
        else:
            selected = slots
        selected_set = set(selected)
        template = self.engine.inspect(self.template_name)
        if not template or not (template.get("State") or {}).get("Running"):
            raise AutoscalerError("the first solver container is not running")
        created = 0
        available = 1
        available_slots = [1]
        for slot in selected[1:]:
            name = self.name(slot)
            current = self.engine.inspect(name)
            if current is not None:
                managed_required = slot not in self.static_slots
                try:
                    validate_slot_container(
                        current,
                        template,
                        slot,
                        managed_required=managed_required,
                    )
                except AutoscalerError:
                    labels = ((current.get("Config") or {}).get("Labels") or {})
                    owned = (
                        managed_required
                        and labels.get(MANAGED_LABEL) == "true"
                        and labels.get(SLOT_LABEL) == str(slot)
                    )
                    if not owned:
                        raise
                    # A private label alone is insufficient proof. The old
                    # container must still be an exact clone in every field
                    # except immutable image/release identity.
                    validate_slot_container(
                        current,
                        template,
                        slot,
                        managed_required=True,
                        allow_release_mismatch=True,
                    )
                    # Release transitions may leave a controller-owned worker
                    # on an old image. Keep its exchange data and recreate the
                    # container so restart recovery can resume that slot.
                    if not _slot_is_idle(self.storage_root, slot):
                        # Keep a claimed old-release worker alive until its
                        # job and private cleanup finish. The new template
                        # can replace it on a later idle reconciliation.
                        if not (current.get("State") or {}).get("Running"):
                            self.engine.start(name)
                        available += 1
                        available_slots.append(slot)
                        continue
                    if (current.get("State") or {}).get("Running"):
                        self.engine.stop(name)
                    self.engine.remove(name)
                    current = None
            if current is not None:
                state = current.get("State") or {}
                if not state.get("Running"):
                    self.engine.start(name)
                available += 1
                available_slots.append(slot)
                continue
            # Compose owns warm/static workers. During parallel startup they
            # can appear after this controller; wait instead of creating an
            # identically named container without Compose ownership metadata.
            if slot in self.static_slots:
                continue
            if created >= self.step:
                continue
            _prepare_slot(
                template,
                slot,
                self.storage_root,
                require_protected_parents=self.require_protected_parents,
            )
            self.engine.create(name, clone_payload(template, slot))
            self.engine.start(name)
            created += 1
            available += 1
            available_slots.append(slot)
        removed = 0
        retained = 0
        for container in self.engine.managed():
            slot = self._slot_of(container)
            if slot is None or slot in selected_set:
                continue
            names = container.get("Names") or []
            expected = "/" + self.name(slot)
            if expected not in names:
                raise AutoscalerError("managed solver slot conflicts with the static profile policy")
            name = self.name(slot)
            current = self.engine.inspect(name)
            if current is None:
                continue
            validate_slot_container(
                current,
                template,
                slot,
                managed_required=True,
                allow_release_mismatch=True,
            )
            if not _slot_is_idle(self.storage_root, slot):
                retained += 1
                continue
            was_running = bool((current.get("State") or {}).get("Running"))
            if was_running:
                self.engine.stop(name)
            # The worker may have begun writing between the first check and
            # Docker stop. Never remove a container while its slot is active.
            if not _slot_is_idle(self.storage_root, slot):
                if was_running:
                    self.engine.start(name)
                retained += 1
                continue
            self.engine.remove(name)
            removed += 1
        template_labels = (template.get("Config") or {}).get("Labels") or {}
        return {
            "desired": desired,
            "available": available,
            "slots": selected,
            "available_slots": available_slots,
            "created": created,
            "removed": removed,
            "retained": retained,
            "warming": available < desired,
            "template_image": template.get("Image"),
            "template_release": template_labels.get("org.opencontainers.image.revision"),
        }


def main() -> int:
    control = Path(os.environ.get("CTF_SOLVER_CONTROL", "/data/solver-exchange/pool-control.json"))
    status_path = Path(
        os.environ.get(
            "CTF_SOLVER_AUTOSCALE_STATUS",
            str(control.parent / "autoscaler.json"),
        )
    )
    template = os.environ.get("CTF_SOLVER_TEMPLATE_CONTAINER", "ctf_agent_solver")
    prefix = os.environ.get("CTF_SOLVER_CONTAINER_PREFIX", "ctf_agent_solver_")
    static_prefix = os.environ.get("CTF_SOLVER_STATIC_PREFIX", prefix)
    static_count = max(1, int(os.environ.get("CTF_SOLVER_STATIC_COUNT", "6")))
    raw_static_slots = os.environ.get("CTF_SOLVER_STATIC_SLOTS")
    if raw_static_slots is None:
        static_slots = None
    else:
        parts = raw_static_slots.split(",")
        if not parts or any(not re.fullmatch(r"[1-9][0-9]*", part) for part in parts):
            raise AutoscalerError("static solver slot identities are invalid")
        static_slots = {int(part) for part in parts}
        if len(static_slots) != len(parts):
            raise AutoscalerError("static solver slot identities are duplicated")
    interval = max(0.2, float(os.environ.get("CTF_SOLVER_AUTOSCALE_INTERVAL", "1")))
    step = max(1, int(os.environ.get("CTF_SOLVER_AUTOSCALE_STEP", "8")))
    once = os.environ.get("CTF_SOLVER_AUTOSCALE_ONCE", "").lower() in {"1", "true", "yes"}
    scaler = SolverAutoscaler(
        DockerEngine(os.environ.get("CTF_DOCKER_SOCKET", "/var/run/docker.sock")),
        template_name=template,
        container_prefix=prefix,
        static_prefix=static_prefix,
        static_count=static_count,
        static_slots=static_slots,
        control_path=control,
        storage_root=Path(os.environ.get("CTF_SOLVER_STORAGE_ROOT", "/data")),
        step=step,
    )
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            result = scaler.reconcile(read_control(control))
            write_status(
                status_path,
                {
                    "protocol": PROTOCOL,
                    "ready": True,
                    **result,
                    "updated_at": time.time(),
                },
            )
        except AutoscalerError as exc:
            print(f"solver_autoscaler_waiting: {exc}", flush=True)
            try:
                write_status(
                    status_path,
                    {
                        "protocol": PROTOCOL,
                        "ready": False,
                        "error": str(exc),
                        "updated_at": time.time(),
                    },
                )
            except AutoscalerError:
                pass
        except Exception:
            # Keep controller heartbeat explicit across transient filesystem
            # and Docker failures without exposing exception details to web.
            print("solver_autoscaler_waiting: controller operation failed", flush=True)
            try:
                write_status(
                    status_path,
                    {
                        "protocol": PROTOCOL,
                        "ready": False,
                        "error": "solver autoscaler operation failed",
                        "updated_at": time.time(),
                    },
                )
            except Exception:
                pass
        if once:
            break
        deadline = time.monotonic() + interval
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
