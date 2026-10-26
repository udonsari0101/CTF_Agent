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


def prepare_readable_storage(environment: dict[str, str]) -> Path:
    """Create the bind-mounted readable root as the invoking WSL user."""

    data_root = _local_path(
        environment.get("CTF_LOCAL_DATA", "./.local/ctf_agent_data")
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
    data_root = _local_path(env.get("CTF_LOCAL_DATA", "./.local/ctf_agent_data"))
    database_root = _local_path(env.get("CTF_LOCAL_DATABASE", "./.local/Database/CTF_Agent"))
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
        or set(host.get("SecurityOpt") or []) != {"no-new-privileges:true"}
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
    prepare_readable_storage(environment)
    actions = {"up", "down", "stop", "rm", "kill", "restart", "start", "ps", "logs", "config", "pull", "build"}
    action = next((item for item in arguments if item in actions), "up")
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
