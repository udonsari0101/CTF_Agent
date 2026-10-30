"""Start the local Compose stack with a resource-sized solver pool."""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing, contextmanager
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


def _verify_database_bind_alias(environment: dict[str, str], database: str) -> None:
    home_value = environment.get("CTF_LOCAL_HOME", "")
    alias = Path(home_value) / ".database-bind" if home_value else None
    if (alias is None or environment.get("CTF_LOCAL_DATABASE") != str(alias)
            or not alias.is_symlink() or os.readlink(alias) != database):
        raise RuntimeError("The Docker database bind alias is missing or targets a different disk")


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
    if (mount_value and environment.get("CTF_UPDATE_IN_PROGRESS") == "true"
            and environment.get("CTF_HOST_UPDATE_ATTESTED") != "true"):
        raise RuntimeError(
            "An external database VHD update requires the trusted WSL launcher; "
            "the in-app updater cannot verify the host mount"
        )
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
    _verify_database_bind_alias(environment, database)
    marker = mount / ".ctf-agent-db-volume"
    with Path("/proc/self/mountinfo").open(encoding="utf-8") as stream:
        filesystems = [
            line.split(" - ", 1)[1].split()[0]
            for line in stream if " - " in line
            if line.split(" - ", 1)[0].split()[4] == mount_value
        ]
    updating = environment.get("CTF_UPDATE_IN_PROGRESS") == "true"
    if (not filesystems or "ext4" not in filesystems
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


def verify_installed_database(environment: dict[str, str]) -> dict[str, object] | None:
    """An installed release must never boot with a newly created database."""

    home_value = environment.get("CTF_LOCAL_HOME", "")
    if not home_value:
        return None
    home = Path(home_value)
    release_marker = home / ".current-release"
    config_path = home / ".local-config.json"
    if release_marker.is_symlink():
        raise RuntimeError("Installed release metadata is invalid")
    if not release_marker.is_file():
        if config_path.exists() or config_path.is_symlink():
            raise RuntimeError("Local installation is incomplete; refusing to create a new database")
        # The first installation has no selected release until it is healthy.
        return None
    if config_path.is_symlink() or not config_path.is_file():
        raise RuntimeError("Local installation settings are missing")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError("Local installation settings are invalid")
    database_root = _local_path(environment.get(
        "CTF_LOCAL_FS_DATABASE",
        environment.get("CTF_LOCAL_DATABASE", str(home / "Database" / "CTF_Agent")),
    ))
    configured_database = config.get("database_path", str(home / "Database" / "CTF_Agent"))
    if not isinstance(configured_database, str) or database_root != Path(configured_database):
        raise RuntimeError("Local database path differs from the installed settings")
    database = database_root / "sqlite" / "ctf_agent.sqlite3"
    if database.is_symlink() or not database.is_file() or database.stat().st_size == 0:
        raise RuntimeError(
            "The existing local database is unavailable; refusing to start with an empty database"
        )
    try:
        return _probe_sqlite(database)
    except (sqlite3.Error, ValueError, OSError) as exc:
        raise RuntimeError(
            "The existing local database is not initialized; refusing to replace it"
        ) from exc


def _probe_sqlite(database: Path) -> dict[str, object]:
    with closing(sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('meta', 'users', 'workspaces')"
        )}
        if tables != {"meta", "users", "workspaces"}:
            raise ValueError("required tables are missing")
        owner = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone()
        user = db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if not owner or not isinstance(owner[0], str) or not owner[0] or not user:
            raise ValueError("the initialized owner or user is missing")
        return {"owner": owner[0]}


def verify_first_install_database(environment: dict[str, str]) -> None:
    """A first install may have no user yet, but its host SQLite must exist."""

    database_root = _local_path(environment.get(
        "CTF_LOCAL_FS_DATABASE", environment.get("CTF_LOCAL_DATABASE", "")))
    database = database_root / "sqlite" / "ctf_agent.sqlite3"
    if database.is_symlink() or not database.is_file() or database.stat().st_size == 0:
        raise RuntimeError("The first web start did not create SQLite on the selected host database disk")
    try:
        with closing(sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
            db.execute("PRAGMA query_only=ON")
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('meta', 'users', 'workspaces')"
            )}
            if tables != {"meta", "users", "workspaces"}:
                raise ValueError("required initial tables are missing")
    except (sqlite3.Error, ValueError, OSError) as exc:
        raise RuntimeError("The first web start did not initialize SQLite on the host disk") from exc


@contextmanager
def _bind_canary(environment: dict[str, str]):
    """Prove Docker sees this live host mount, not a stale snapshot with the same DB owner."""

    database = _local_path(environment.get(
        "CTF_LOCAL_FS_DATABASE", environment.get("CTF_LOCAL_DATABASE", "")))
    directory = database / "sqlite"
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("The original database directory is unavailable")
    descriptor, name = tempfile.mkstemp(prefix=".ctf-agent-bind-", dir=directory)
    path = Path(name)
    nonce = secrets.token_hex(32)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(nonce)
            stream.flush()
            os.fsync(stream.fileno())
        yield path.name, nonce
    finally:
        path.unlink(missing_ok=True)


def _docker_output(command: list[str], *, timeout: int = 30) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Docker database visibility could not be verified") from exc
    if result.returncode:
        raise RuntimeError("Docker database visibility could not be verified")
    return result.stdout.strip()


def _web_sees_canary(name: str, nonce: str) -> bool:
    return _docker_output([
        # The web drops every capability. Root inside that container cannot
        # read a 0600 file owned by the WSL user without CAP_DAC_OVERRIDE.
        # Match the host owner of the temporary nonce instead.
        "docker", "exec", "--user", f"{os.getuid()}:{os.getgid()}", "ctf_agent_local",
        "cat", f"/database/sqlite/{name}",
    ]) == nonce


def _database_bind_failure_marker(environment: dict[str, str]) -> Path | None:
    home = environment.get("CTF_LOCAL_HOME", "")
    return Path(home) / ".database-bind-failed" if home else None


def _mark_database_bind_failure(environment: dict[str, str]) -> None:
    marker = _database_bind_failure_marker(environment)
    if marker is None:
        return
    if marker.is_symlink() or marker.parent.is_symlink():
        raise RuntimeError("Database bind failure marker path is invalid")
    descriptor, name = tempfile.mkstemp(prefix=".database-bind-failed-", dir=marker.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write("database bind verification failed\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)


def _clear_database_bind_failure(environment: dict[str, str]) -> None:
    marker = _database_bind_failure_marker(environment)
    if marker is not None:
        if marker.is_symlink():
            raise RuntimeError("Database bind failure marker path is invalid")
        marker.unlink(missing_ok=True)


def _stop_running_stack_on_bind_failure(environment: dict[str, str]) -> None:
    # A stale web must not continue serving a newly initialized database.
    # Only stop containers after the project/service identity is verified.
    # A bind failure may be caused by Docker reporting a different database
    # Source. Identify our web by project/service and /data before stopping;
    # requiring the broken /database Source here would leave it running.
    web = _current_web_container(environment, require_database_source=False)
    if web is None and not _running_solver_containers():
        return
    # A solver that keeps writing a stale shadow database is unsafe even if
    # its process is active. Stop every local writer without removing volumes.
    _stop_local_stack(environment)


def _current_web_container(environment: dict[str, str], *, require_database_source: bool = True) -> dict | None:
    names = _docker_output(["docker", "ps", "-a", "--format", "{{.Names}}"])
    if "ctf_agent_local" not in names.splitlines():
        return None
    value = json.loads(_docker_output(["docker", "inspect", "ctf_agent_local"]))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeError("The local web container identity is invalid")
    container = value[0]
    labels = (container.get("Config") or {}).get("Labels") or {}
    mounts = {item.get("Destination"): item for item in container.get("Mounts") or []
              if isinstance(item, dict)}
    expected_data = environment.get("CTF_LOCAL_DATA", "")
    expected_database = environment.get("CTF_LOCAL_DATABASE", "")
    database_source = mounts.get("/database", {}).get("Source")
    legacy_source = environment.get("CTF_LOCAL_FS_DATABASE", "")
    # Docker may resolve a WSL-home symlink in Mounts.Source. HostConfig
    # retains the bind source requested by Compose, allowing us to tell a new
    # alias bind from a legacy direct /mnt/wsl bind with the same resolved path.
    host_config = container.get("HostConfig") or {}
    configured_sources = [item.get("Source") for item in host_config.get("Mounts") or []
                          if isinstance(item, dict) and item.get("Type") == "bind"
                          and item.get("Target") == "/database"]
    for bind in host_config.get("Binds") or []:
        if isinstance(bind, str):
            fields = bind.split(":")
            if len(fields) >= 2 and fields[1] == "/database":
                configured_sources.append(fields[0])
    if require_database_source and len(set(configured_sources)) > 1:
        raise RuntimeError("The local web database bind configuration is ambiguous")
    configured_source = configured_sources[0] if configured_sources else database_source
    legacy_bind = bool(environment.get("CTF_LOCAL_DB_MOUNT")
                       and legacy_source and configured_source == legacy_source
                       and configured_source != expected_database)
    accepted = {expected_database}
    if environment.get("CTF_LOCAL_DB_MOUNT") and legacy_source:
        accepted.add(legacy_source)
    if (container.get("Name") != "/ctf_agent_local"
            or labels.get("com.docker.compose.project") != "ctf_agent_local"
            or labels.get("com.docker.compose.service") != "web"
            or mounts.get("/data", {}).get("Type") != "bind"
            or mounts["/data"].get("Source") != expected_data
            or (require_database_source and mounts.get("/database", {}).get("Type") != "bind")
            or (require_database_source and configured_source not in accepted)):
        raise RuntimeError("The local web container does not match this installation")
    container["_legacy_database_bind"] = legacy_bind
    return container


def _running_solver_containers() -> bool:
    names = _docker_output(["docker", "ps", "--format", "{{.Names}}"])
    return any(re.fullmatch(r"ctf_agent_local_(?:solver(?:_[2-9][0-9]*)?|autosolver_[2-9][0-9]*)", name)
               for name in names.splitlines())


def _preflight_database_binding(
    environment: dict[str, str], host: dict[str, object], *,
    allow_stopped_web_with_solvers: bool = False,
) -> bool:
    """Return whether existing Compose containers need fresh bind mounts."""

    image = environment.get("CTF_LOCAL_RUNTIME_IMAGE", "")
    database = environment.get("CTF_LOCAL_DATABASE", "")
    if not image or not database:
        raise RuntimeError("Local runtime or database path is unavailable")
    with _bind_canary(environment) as (name, nonce):
        try:
            visible = _docker_output([
                "docker", "run", "--rm", "--network", "none", "--read-only",
                "--security-opt", "no-new-privileges", "--user", "0:0",
                "--mount", f"type=bind,source={database},target=/probe,readonly",
                "--entrypoint", "cat", image, f"/probe/sqlite/{name}",
            ]) == nonce
        except RuntimeError as exc:
            _mark_database_bind_failure(environment)
            _stop_running_stack_on_bind_failure(environment)
            raise RuntimeError(
                "Docker cannot see the original database mount. Reconnect the VHD and Docker Desktop; do not reinstall"
            ) from exc
        if not visible:
            _mark_database_bind_failure(environment)
            _stop_running_stack_on_bind_failure(environment)
            raise RuntimeError(
                "Docker cannot see the original database mount. Reconnect the VHD and Docker Desktop; do not reinstall"
            )
        try:
            web = _current_web_container(environment)
        except RuntimeError as exc:
            _mark_database_bind_failure(environment)
            _stop_running_stack_on_bind_failure(environment)
            raise RuntimeError(
                "The local web container has an unexpected database bind; local containers were stopped"
            ) from exc
        if web is None:
            _clear_database_bind_failure(environment)
            return False
        running = (web.get("State") or {}).get("Running") is True
        if running:
            try:
                visible = _web_sees_canary(name, nonce)
            except RuntimeError as exc:
                _mark_database_bind_failure(environment)
                _stop_running_stack_on_bind_failure(environment)
                raise RuntimeError(
                    "The running web container database bind could not be verified"
                ) from exc
            if not visible:
                _mark_database_bind_failure(environment)
                _stop_running_stack_on_bind_failure(environment)
                raise RuntimeError(
                    "The running web container has a stale database bind; local containers were stopped"
                )
            if web.get("_legacy_database_bind"):
                if _running_solver_containers():
                    raise RuntimeError(
                        "Solver containers are running; legacy database bind migration was postponed"
                    )
                _clear_database_bind_failure(environment)
                return True
            _clear_database_bind_failure(environment)
            return False
        if _running_solver_containers() and not allow_stopped_web_with_solvers:
            raise RuntimeError("Solver containers are running; database bind repair was cancelled")
        _clear_database_bind_failure(environment)
        return True


def _quiesce_for_installer(environment: dict[str, str], *, installed: bool) -> None:
    """Stop idle writers only after the installer has drained all solve claims."""

    data = _local_path(environment.get("CTF_LOCAL_FS_DATA", environment.get("CTF_LOCAL_DATA", "")))
    drain = data / "deployment-drain"
    if drain.is_symlink() or not drain.is_file():
        raise RuntimeError("The installer deployment drain is unavailable")
    details = drain.stat()
    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
            or details.st_uid != os.getuid() or details.st_size):
        raise RuntimeError("The installer deployment drain is invalid")
    if installed:
        database_root = _local_path(environment.get(
            "CTF_LOCAL_FS_DATABASE", environment.get("CTF_LOCAL_DATABASE", "")))
        database = database_root / "sqlite" / "ctf_agent.sqlite3"
        if database.is_symlink() or not database.is_file():
            raise RuntimeError("The installed database is unavailable")
        with closing(sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, timeout=15)) as connection:
            connection.execute("PRAGMA query_only=ON")
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_slots'"
            ).fetchone()
            if table and connection.execute("SELECT 1 FROM solver_slots LIMIT 1").fetchone():
                raise RuntimeError("Active solver jobs have not drained")
    elif _current_web_container(environment) is not None or _running_solver_containers():
        raise RuntimeError("Unregistered local containers require manual inspection")
    _stop_local_stack(environment)


def _verify_web_database_after_start(environment: dict[str, str], host: dict[str, object]) -> None:
    """Do not leave a web service running against a stale bind after Compose."""

    with _bind_canary(environment) as (name, nonce):
        for attempt in range(6):
            try:
                web = _current_web_container(environment)
                if not web or (web.get("State") or {}).get("Running") is not True:
                    raise RuntimeError("The local web container is not running")
                visible = _web_sees_canary(name, nonce)
            except RuntimeError as exc:
                if attempt < 5:
                    time.sleep(1)
                    continue
                _mark_database_bind_failure(environment)
                _stop_running_stack_on_bind_failure(environment)
                raise RuntimeError(
                    "The web database could not be verified; the coordinator was stopped"
                ) from exc
            if not visible:
                _mark_database_bind_failure(environment)
                _stop_running_stack_on_bind_failure(environment)
                raise RuntimeError("The web container has the wrong database; the coordinator was stopped")
            _clear_database_bind_failure(environment)
            return


def _stop_local_stack(environment: dict[str, str]) -> None:
    # Emergency post-start failure: do not leave solver workers operating while
    # their coordinator saw a different database. Compose stop keeps all data.
    stopped = subprocess.run(_compose_base() + ALL_PROFILES + ["stop"], cwd=ROOT,
                             env=environment, check=False)
    if stopped.returncode:
        raise RuntimeError("The local database writers could not be stopped")
    listed = _docker_output([
        "docker", "ps", "--filter", "label=io.github.ctf-agent.autoscaled=true",
        "--filter", "name=ctf_agent_local_autosolver_", "--format",
        '{{.ID}}|{{.Names}}|{{.Label "io.github.ctf-agent.solver-slot"}}',
    ])
    rows = []
    for line in listed.splitlines():
        parts = line.split("|")
        if (len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{12,64}", parts[0])
                or not re.fullmatch(r"[2-9][0-9]*", parts[2])
                or parts[1] != f"ctf_agent_local_autosolver_{parts[2]}"):
            raise RuntimeError("An autoscaled local solver could not be verified for stopping")
        rows.append((parts[0], int(parts[2])))
    identifiers = []
    for identifier, slot in rows:
        inspected = json.loads(_docker_output(["docker", "inspect", identifier]))
        if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
            raise RuntimeError("An autoscaled local solver identity is invalid")
        container = inspected[0]
        labels = ((container.get("Config") or {}).get("Labels") or {})
        mounts = {item.get("Destination"): item for item in container.get("Mounts") or []
                  if isinstance(item, dict)}
        if (not isinstance(container.get("Id"), str)
                or not container["Id"].startswith(identifier)
                or container.get("Name") != f"/ctf_agent_local_autosolver_{slot}"
                or labels.get("io.github.ctf-agent.autoscaled") != "true"
                or labels.get("io.github.ctf-agent.solver-slot") != str(slot)
                or mounts.get("/data", {}).get("Type") != "bind"
                or mounts["/data"].get("Source") != environment.get("CTF_LOCAL_DATA")):
            raise RuntimeError("An autoscaled local solver ownership check failed")
        identifiers.append(identifier)
    if identifiers:
        stopped = subprocess.run(["docker", "stop", "--time", "30", *identifiers],
                                 cwd=ROOT, env=environment, check=False)
        if stopped.returncode:
            raise RuntimeError("An autoscaled database writer could not be stopped")


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


def protected_solver_slots(environment: dict[str, str] | None = None) -> set[int]:
    """Keep exact slots that may still contain an in-flight credential copy."""

    env = environment or os.environ
    data_root = _local_path(env.get("CTF_LOCAL_FS_DATA", env.get("CTF_LOCAL_DATA", "./.local/ctf_agent_data")))
    database_root = _local_path(env.get("CTF_LOCAL_FS_DATABASE", env.get("CTF_LOCAL_DATABASE", "./.local/Database/CTF_Agent")))
    database = database_root / "sqlite" / "ctf_agent.sqlite3"
    protected = {1}
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
                        protected.add(index)
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
            protected.add(index)
    return protected


def protected_solver_ceiling(environment: dict[str, str] | None = None) -> int:
    """Legacy high-water helper; not a worker count."""

    return max(protected_solver_slots(environment))


def _selected_slots(count: int, protected: set[int]) -> set[int]:
    selected = set(protected) | {1}
    candidate = 1
    while len(selected) < count:
        selected.add(candidate)
        candidate += 1
    return selected


def compose_commands(count: int, arguments: list[str], *, slots: set[int] | None = None) -> list[list[str]]:
    base = _compose_base()
    actions = {"up", "down", "stop", "rm", "kill", "restart", "start", "ps", "logs", "config", "pull", "build"}
    action = next((item for item in arguments if item in actions), "up")
    if action not in {"up", "start"}:
        return [base + ALL_PROFILES + arguments]
    selected_slots = slots if slots is not None else set(range(1, count + 1))
    selected = [
        item
        for index in sorted(selected_slots)
        if 2 <= index <= STATIC_SOLVER_COUNT
        for item in ("--profile", f"solver-{index}")
    ]
    commands = []
    inactive = [
        f"solver-{index}" for index in range(2, STATIC_SOLVER_COUNT + 1)
        if index not in selected_slots
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


def remove_autoscaled_containers(
    environment: dict[str, str], *, protected_slots: set[int] | None = None,
    retained_slots: set[int] | None = None,
) -> int:
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
    validated = validate_local_autoscaled_containers(rows, environment)
    protected = protected_slots if protected_slots is not None else protected_solver_slots(environment)
    identifiers = [
        identifier for (identifier, slot), verified in zip(rows, validated)
        if identifier == verified and slot not in protected
    ]
    if len(validated) != len(rows) or any(
        identifier != verified for (identifier, _slot), verified in zip(rows, validated)
    ):
        raise RuntimeError("solver container identity list changed during validation")
    if retained_slots is not None:
        retained_slots.update(slot for _identifier, slot in rows if slot in protected)
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
    effective_slots = _selected_slots(requested_count, {1})
    retained_dynamic: set[int] = set()
    arguments = normalize_arguments(sys.argv[1:] or ["up", "-d", "--build"])
    environment = os.environ.copy()
    actions = {"up", "down", "stop", "rm", "kill", "restart", "start", "ps", "logs", "config", "pull", "build", "preflight", "quiesce", "verify-fresh-install"}
    action = next((item for item in arguments if item in actions), "up")
    verify_external_database(environment)
    if action == "verify-fresh-install":
        verify_first_install_database(environment)
        _preflight_database_binding(environment, {})
        _verify_web_database_after_start(environment, {})
        return 0
    host_database = None
    if action in {"up", "start", "restart", "preflight", "quiesce"}:
        host_database = verify_installed_database(environment)
    if action == "preflight":
        if host_database is not None:
            _preflight_database_binding(
                environment, host_database, allow_stopped_web_with_solvers=True)
        return 0
    if action == "quiesce":
        _quiesce_for_installer(environment, installed=host_database is not None)
        return 0
    prepare_readable_storage(environment)
    if action in {"up", "start"} and (ROOT / ".local-runtime.json").exists():
        from local_runtime import select_image
        environment["CTF_LOCAL_RUNTIME_IMAGE"] = select_image(ROOT)
    if action in {"up", "start"} and host_database is not None:
        if _preflight_database_binding(environment, host_database):
            if "--force-recreate" not in arguments:
                arguments.append("--force-recreate")
            print("Recreating stopped or stale local containers to refresh the database bind.", flush=True)
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
        protected = protected_solver_slots(environment)
        if action in {"up", "start"}:
            effective_slots = _selected_slots(requested_count, protected)
        handoff = remove_autoscaled_containers(
            environment, protected_slots=protected, retained_slots=retained_dynamic
        )
        if handoff:
            return handoff
    # The web coordinator must retain the desired capacity separately from the
    # number of worker profiles kept alive to drain protected higher slots.
    environment["CTF_SOLVER_MAX_CONCURRENT"] = str(requested_count)
    environment["CTF_SOLVER_RECOMMENDED_CONCURRENT"] = str(requested_count)
    static_slots = {
        slot for slot in effective_slots
        if slot <= STATIC_SOLVER_COUNT and slot not in retained_dynamic
    }
    environment["CTF_SOLVER_STATIC_COUNT"] = str(STATIC_SOLVER_COUNT)
    environment["CTF_SOLVER_STATIC_SLOTS"] = ",".join(map(str, sorted(static_slots)))
    print(f"solver workers: {len(effective_slots)} (requested: {requested_count})", flush=True)
    for command in compose_commands(len(effective_slots), arguments, slots=static_slots):
        result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        if result.returncode:
            return result.returncode
    if action in {"up", "start"} and host_database is not None:
        _verify_web_database_after_start(environment, host_database)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
