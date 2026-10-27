"""Start the local Compose stack with a resource-sized solver pool."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ctf_agent.local_capacity import recommended_solver_concurrency
from ctf_agent.solver_autoscaler import AutoscalerError, validate_slot_container


STATIC_SOLVER_COUNT = 6
ALL_PROFILES = [
    item
    for index in range(2, STATIC_SOLVER_COUNT + 1)
    for item in ("--profile", f"solver-{index}")
]


def _compose_base() -> list[str]:
    return ["docker", "compose", "-f", str(ROOT / "compose.local.yaml")]


def _local_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else ROOT / path


def verify_external_database(environment: dict[str, str]) -> None:
    """Refuse to start containers against an unmounted or wrong database VHD."""

    home_value = environment.get("CTF_LOCAL_HOME", "")
    config_path = Path(home_value) / ".local-config.json" if home_value else None
    config = {}
    if config_path and config_path.exists():
        if config_path.is_symlink() or not config_path.is_file():
            raise RuntimeError("Local installation settings are invalid")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise RuntimeError("Local installation settings are invalid")
    mount_value = environment.get("CTF_LOCAL_DB_MOUNT", "")
    configured_mount = config.get("database_mount", "")
    if not isinstance(configured_mount, str) or (configured_mount and configured_mount != mount_value):
        raise RuntimeError("The configured external database VHD is unavailable")
    if mount_value and home_value and (Path(home_value) / ".current-release").is_file() and not config:
        raise RuntimeError("External database installation settings are missing")
    if not mount_value:
        return
    if not re.fullmatch(r"/mnt/wsl/[A-Za-z0-9_-]+", mount_value):
        raise RuntimeError("External database mount path is invalid")
    mount = Path(mount_value)
    database = environment.get("CTF_LOCAL_FS_DATABASE", environment.get("CTF_LOCAL_DATABASE", ""))
    if database != str(mount / "Database" / "CTF_Agent"):
        raise RuntimeError("External database path does not match its mount")
    marker = mount / ".ctf-agent-db-volume"
    with Path("/proc/self/mountinfo").open(encoding="utf-8") as stream:
        filesystems = [
            line.split(" - ", 1)[1].split()[0]
            for line in stream if " - " in line
            if line.split(" - ", 1)[0].split()[4] == mount_value
        ]
    updating = environment.get("CTF_UPDATE_IN_PROGRESS") == "true"
    if (not filesystems or (not updating and "ext4" not in filesystems)
            or mount.is_symlink() or not mount.is_dir()
            or marker.is_symlink() or not marker.is_file()
            or marker.stat().st_size > 64):
        raise RuntimeError("The external database VHD is unavailable")
    volume_id = marker.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{32}", volume_id):
        raise RuntimeError("The external database volume marker is invalid")
    if config and config.get("database_volume_id") != volume_id:
        raise RuntimeError("The mounted database VHD does not match this installation")
    if updating and not (mount / "Database" / "CTF_Agent" / "sqlite" / "ctf_agent.sqlite3").is_file():
        raise RuntimeError("The existing external database is unavailable")
    for path in (mount / "Database", mount / "Database" / "CTF_Agent"):
        if path.is_symlink():
            raise RuntimeError("External database path contains a symlink")


def prepare_readable_storage(environment: dict[str, str]) -> Path:
    """Create the bind-mounted readable root as the invoking WSL user."""

    data_root = _local_path(
        environment.get("CTF_LOCAL_FS_DATA", environment.get("CTF_LOCAL_DATA", "./.local/ctf_agent_data"))
    )
    target = data_root / "workspace_files"
    for path in (data_root, target):
        if path.is_symlink():
            raise RuntimeError(f"local storage path must not be a symlink: {path}")
        path.mkdir(mode=0o750, parents=True, exist_ok=True)
    return target


def protected_solver_ceiling(environment: dict[str, str] | None = None) -> int:
    """Keep every slot that may still contain an in-flight credential copy."""

    env = environment or os.environ
    data_root = _local_path(env.get("CTF_LOCAL_FS_DATA", env.get("CTF_LOCAL_DATA", "./.local/ctf_agent_data")))
    database_root = _local_path(env.get("CTF_LOCAL_FS_DATABASE", env.get("CTF_LOCAL_DATABASE", "./.local/Database/CTF_Agent")))
    database = database_root / "sqlite" / "ctf_agent.sqlite3"
    protected = 1
    if database.is_file():
        try:
            with sqlite3.connect(database, timeout=15) as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA busy_timeout=15000")
                exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_slots'"
                ).fetchone()
                if exists:
                    for (slot_id,) in connection.execute("SELECT slot_id FROM solver_slots"):
                        if slot_id == "default":
                            index = 1
                        elif isinstance(slot_id, str) and re.fullmatch(r"solver-([2-9]|[1-9][0-9]+)", slot_id):
                            index = int(slot_id[7:])
                        else:
                            raise RuntimeError("지원하지 않는 solver 슬롯 정보가 있습니다.")
                        protected = max(protected, index)
        except sqlite3.Error as exc:
            raise RuntimeError("solver 슬롯 상태를 확인할 수 없습니다.") from exc
    indices = set()
    for root in (data_root / "solver-exchange" / "slots", data_root / "solver-scratch"):
        if root.exists() and (root.is_symlink() or not root.is_dir()):
            raise RuntimeError("solver 슬롯 루트 경로를 확인할 수 없습니다.")
        if not root.exists():
            continue
        for entry in root.iterdir():
            matched = re.fullmatch(r"solver-([1-9][0-9]*)", entry.name)
            if matched and int(matched.group(1)) >= 2:
                indices.add(int(matched.group(1)))
    for index in sorted(indices):
        exchange = data_root / "solver-exchange" / "slots" / f"solver-{index}"
        scratch = data_root / "solver-scratch" / f"solver-{index}"
        try:
            if exchange.exists() and (exchange.is_symlink() or not exchange.is_dir()):
                raise RuntimeError("solver 슬롯 경로를 확인할 수 없습니다.")
            if scratch.exists() and (scratch.is_symlink() or not scratch.is_dir()):
                raise RuntimeError("solver 임시 작업 경로를 확인할 수 없습니다.")
            exchange_busy = False
            if exchange.exists():
                for entry in exchange.iterdir():
                    if entry.name in {"worker.json", "worker.lock"}:
                        continue
                    if entry.name == "runtime":
                        if entry.is_symlink() or not entry.is_dir():
                            raise RuntimeError("solver runtime 경로를 확인할 수 없습니다.")
                        if next(entry.iterdir(), None) is not None:
                            raise RuntimeError("보조 solver runtime 경로가 비어 있지 않습니다.")
                        continue
                    exchange_busy = True
            scratch_busy = scratch.exists() and next(scratch.iterdir(), None) is not None
        except OSError as exc:
            raise RuntimeError("solver 작업 경로를 확인할 수 없습니다.") from exc
        if exchange_busy or scratch_busy:
            protected = max(protected, index)
    return protected


def compose_commands(count: int, arguments: list[str]) -> list[list[str]]:
    base = _compose_base()
    actions = {"up", "down", "stop", "rm", "kill", "restart", "start", "ps", "logs", "config", "pull", "build"}
    action = next((item for item in arguments if item in actions), "up")
    if action not in {"up", "start"}:
        return [base + ALL_PROFILES + arguments]
    selected = [
        item
        for index in range(2, min(count, STATIC_SOLVER_COUNT) + 1)
        for item in ("--profile", f"solver-{index}")
    ]
    commands = []
    inactive = [
        f"solver-{index}"
        for index in range(max(2, count + 1), STATIC_SOLVER_COUNT + 1)
    ]
    if inactive:
        commands.append(base + ALL_PROFILES + ["rm", "--stop", "--force", *inactive])
    commands.append(base + selected + arguments)
    return commands


def normalize_arguments(arguments: list[str]) -> list[str]:
    """Make managed start recreate services so capacity/env changes apply."""

    normalized = list(arguments)
    try:
        index = normalized.index("start")
    except ValueError:
        try:
            index = normalized.index("restart")
        except ValueError:
            return normalized
        return normalized[:index] + ["up", "-d", "--force-recreate"] + normalized[index + 1 :]
    return normalized[:index] + ["up", "-d"] + normalized[index + 1 :]


def remove_autoscaled_containers(environment: dict[str, str]) -> int:
    """Remove only controller-owned local replicas before Compose handoff."""

    listed = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=io.github.ctf-agent.autoscaled=true",
            "--filter",
            "name=ctf_agent_local_autosolver_",
            "--format",
            '{{.ID}}|{{.Names}}|{{.Label "io.github.ctf-agent.solver-slot"}}',
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if listed.returncode:
        return listed.returncode
    rows = []
    for row in listed.stdout.splitlines():
        parts = row.strip().split("|")
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{12,64}", parts[0]):
            raise RuntimeError("자동 확장 solver 컨테이너 정보를 확인할 수 없습니다.")
        try:
            slot = int(parts[2])
        except ValueError as exc:
            raise RuntimeError("자동 확장 solver 슬롯을 확인할 수 없습니다.") from exc
        if slot < 2 or parts[1] != f"ctf_agent_local_autosolver_{slot}":
            raise RuntimeError("자동 확장 solver 컨테이너 소유권을 확인할 수 없습니다.")
        rows.append((parts[0], slot))
    identifiers = validate_local_autoscaled_containers(rows, environment)
    if not identifiers:
        return 0
    stopped = subprocess.run(
        ["docker", "stop", "--time", "30", *identifiers],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    if stopped.returncode:
        return stopped.returncode
    removed = subprocess.run(
        ["docker", "rm", *identifiers],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    return removed.returncode


def _inspect_container(identifier: str, environment: dict[str, str]) -> dict:
    inspected = subprocess.run(
        ["docker", "inspect", identifier],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if inspected.returncode:
        raise RuntimeError("solver 컨테이너 정보를 확인할 수 없습니다.")
    try:
        value = json.loads(inspected.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("solver 컨테이너 정보를 확인할 수 없습니다.") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeError("solver 컨테이너 정보를 확인할 수 없습니다.")
    return value[0]


def _validate_local_template(template: dict, environment: dict[str, str]) -> None:
    expected_user = (
        f"{environment.get('CTF_LOCAL_UID', '1000')}:"
        f"{environment.get('CTF_LOCAL_GID', '1000')}"
    )
    config = template.get("Config") or {}
    labels = config.get("Labels") or {}
    host = template.get("HostConfig") or {}
    image = template.get("Image")
    if (
        template.get("Name") != "/ctf_agent_local_solver"
        or not isinstance(image, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)
        or labels.get("org.opencontainers.image.revision")
        != environment.get("CTF_RELEASE_SHA", "local")
        or config.get("User") != expected_user
        or config.get("Cmd") != ["python", "-m", "ctf_agent.solver_worker"]
        or host.get("ReadonlyRootfs") is not True
        or set(host.get("CapDrop") or []) != {"ALL"}
        or not _local_security_options_match(template, environment)
    ):
        raise RuntimeError("로컬 solver 기준 컨테이너의 실행 격리를 확인할 수 없습니다.")
    data_root = _local_path(
        environment.get("CTF_LOCAL_DATA", "./.local/ctf_agent_data")
    ).resolve()
    expected = {
        "/solver-exchange": (
            data_root / "solver-exchange" / "slots" / "solver-1",
            True,
        ),
        "/solver-input": (
            data_root / "solver-exchange" / "slots" / "solver-1",
            False,
        ),
        "/solver-exchange/runtime": (
            data_root / "solver-exchange" / "slots" / "solver-1" / "runtime",
            False,
        ),
        "/solver-scratch": (
            data_root / "solver-scratch" / "solver-1",
            True,
        ),
    }
    mounts = template.get("Mounts") or []
    actual = {}
    for mount in mounts:
        if (
            not isinstance(mount, dict)
            or mount.get("Type") != "bind"
            or not isinstance(mount.get("Source"), str)
            or not isinstance(mount.get("Destination"), str)
        ):
            raise RuntimeError("로컬 solver 기준 컨테이너의 mount를 확인할 수 없습니다.")
        destination = mount["Destination"]
        if destination in actual:
            raise RuntimeError("로컬 solver 기준 컨테이너의 mount를 확인할 수 없습니다.")
        actual[destination] = (Path(mount["Source"]), bool(mount.get("RW")))
    if actual != expected:
        raise RuntimeError("로컬 solver 기준 컨테이너의 mount를 확인할 수 없습니다.")


def _local_security_options_match(template: dict, environment: dict[str, str]) -> bool:
    """Accept the exact local policy, or the verified old public template for cleanup."""
    options = (template.get("HostConfig") or {}).get("SecurityOpt") or []
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        return False
    normalized = ["no-new-privileges" if item == "no-new-privileges:true" else item
                  for item in options]
    if normalized.count("no-new-privileges") != 1:
        return False
    policies = [item[len("seccomp="):] for item in normalized if item.startswith("seccomp=")]
    if len(normalized) == 2 and len(policies) == 1:
        try:
            expected = json.loads((ROOT / "deploy/local-seccomp.json").read_text(encoding="utf-8"))
            return json.loads(policies[0]) == expected
        except (ValueError, OSError):
            return False
    if normalized == ["no-new-privileges"]:
        # The previous release is still selected until the new stack is up.
        # Its idle autoscaled workers may use the old public template. Compare
        # the immutable image ID and OCI labels, not a mutable local tag or the
        # new release's .image-ref (which already points to the new image).
        previous_id = _previous_release_image_id(environment)
        return bool(previous_id and template.get("Image") == previous_id)
    return False


def _previous_release_image_id(environment: dict[str, str]) -> str | None:
    home_value = environment.get("CTF_LOCAL_HOME", "")
    if not home_value:
        return None
    home = Path(home_value)
    marker = home / ".current-release"
    try:
        if (not home.is_absolute() or home.is_symlink() or (home / "releases").is_symlink()
                or marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 128):
            return None
        tag = marker.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag):
            return None
        previous = home / "releases" / tag
        reference_file = previous / ".image-ref"
        revision_file = previous / ".release-revision"
        if (previous.is_symlink() or reference_file.is_symlink() or revision_file.is_symlink()
                or not reference_file.is_file() or not revision_file.is_file()
                or reference_file.stat().st_size > 256 or revision_file.stat().st_size > 128):
            return None
        reference = reference_file.read_text(encoding="ascii").strip()
        revision = revision_file.read_text(encoding="ascii").strip()
        if (not re.fullmatch(r"ghcr\.io/udonsari0101/ctf-agent-public@sha256:[0-9a-f]{64}", reference)
                or not re.fullmatch(r"[0-9a-f]{40}", revision)):
            return None
        result = subprocess.run(["docker", "image", "inspect", reference],
                                check=True, capture_output=True, text=True)
        values = json.loads(result.stdout)
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            return None
        image = values[0]
        labels = (image.get("Config") or {}).get("Labels") or {}
        image_id = image.get("Id")
        if (not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
                or labels.get("org.opencontainers.image.revision") != revision
                or labels.get("org.opencontainers.image.source") != "https://github.com/udonsari0101/CTF_Agent"):
            return None
        return image_id
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError,
            subprocess.CalledProcessError):
        return None


def validate_local_autoscaled_containers(
    rows: list[tuple[str, int]], environment: dict[str, str]
) -> list[str]:
    """Return IDs only after exact template and per-slot identity checks."""

    if not rows:
        return []
    template = _inspect_container("ctf_agent_local_solver", environment)
    _validate_local_template(template, environment)
    identifiers = []
    for identifier, slot in rows:
        container = _inspect_container(identifier, environment)
        if container.get("Name") != f"/ctf_agent_local_autosolver_{slot}":
            raise RuntimeError("자동 확장 solver 컨테이너 소유권을 확인할 수 없습니다.")
        try:
            validate_slot_container(
                container,
                template,
                slot,
                managed_required=True,
            )
        except AutoscalerError as exc:
            raise RuntimeError(
                "자동 확장 solver 컨테이너의 실행 격리를 확인할 수 없습니다."
            ) from exc
        identifiers.append(identifier)
    return identifiers


def main() -> int:
    requested_count = recommended_solver_concurrency()
    effective_count = requested_count
    arguments = normalize_arguments(sys.argv[1:] or ["up", "-d", "--build"])
    environment = os.environ.copy()
    verify_external_database(environment)
    prepare_readable_storage(environment)
    actions = {"up", "down", "stop", "rm", "kill", "restart", "start", "ps", "logs", "config", "pull", "build"}
    action = next((item for item in arguments if item in actions), "up")
    if action in {"up", "start"} and (ROOT / ".local-runtime.json").exists():
        from local_runtime import select_image
        environment["CTF_LOCAL_RUNTIME_IMAGE"] = select_image(ROOT)
    if action in {"up", "start", "down", "stop", "rm", "kill"}:
        # Stop the coordinator first so it cannot claim a higher slot between
        # the host-side inspection and removal of an idle worker container.
        quiesce = subprocess.run(
            _compose_base() + ALL_PROFILES + ["stop", "web", "solver-autoscaler"],
            cwd=ROOT,
            env=environment,
            check=False,
        )
        if quiesce.returncode:
            return quiesce.returncode
        if action in {"up", "start"}:
            effective_count = max(requested_count, protected_solver_ceiling(environment))
        handoff = remove_autoscaled_containers(environment)
        if handoff:
            return handoff
    # The web coordinator must retain the desired capacity separately from the
    # number of worker profiles kept alive to drain protected higher slots.
    environment["CTF_SOLVER_MAX_CONCURRENT"] = str(requested_count)
    environment["CTF_SOLVER_RECOMMENDED_CONCURRENT"] = str(requested_count)
    environment["CTF_SOLVER_STATIC_COUNT"] = str(min(effective_count, STATIC_SOLVER_COUNT))
    print(f"solver workers: {effective_count} (requested: {requested_count})", flush=True)
    for command in compose_commands(effective_count, arguments):
        result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
