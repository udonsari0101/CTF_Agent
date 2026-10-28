"""Remove only the local application runtime, preserving both data bind roots."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path


VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
AUTOSOLVER = re.compile(r"ctf_agent_local_autosolver_([2-9]|[1-9][0-9]+)\Z")
IMAGE = re.compile(
    r"(?:ctf-agent-local:(?:latest|rollback-[0-9a-f]{12})|"
    r"ctf-agent-local-runtime:[0-9a-f]{64}|"
    r"ctf-agent-toolchain:local|ctf-agent-updater:local)\Z"
)
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
MANAGED_LABEL = "io.github.ctf-agent.autoscaled"
SLOT_LABEL = "io.github.ctf-agent.solver-slot"


def docker(*arguments: str, allow_missing: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *arguments], capture_output=True, text=True, timeout=180, check=False
    )
    if result.returncode and not allow_missing:
        raise RuntimeError(f"Docker command failed: {' '.join(arguments[:2])}")
    return result


def inspect(name: str) -> dict | None:
    result = docker("inspect", name, allow_missing=True)
    if result.returncode:
        return None
    try:
        value, = json.loads(result.stdout)
        if isinstance(value, dict):
            return value
    except (ValueError, TypeError):
        pass
    raise RuntimeError(f"Could not verify installed container: {name}")


def release_root(home: Path) -> tuple[str, Path]:
    if not home.is_absolute() or home == Path("/") or home.is_symlink():
        raise ValueError("Invalid installation path")
    home = home.resolve(strict=True)
    version_file = home / ".current-release"
    if version_file.is_symlink() or not version_file.is_file():
        raise ValueError("Installed release marker is missing")
    version = version_file.read_text(encoding="ascii").strip()
    if not VERSION.fullmatch(version):
        raise ValueError("Installed release marker is invalid")
    releases = home / "releases"
    target = releases / version
    if releases.is_symlink() or target.is_symlink() or not target.is_dir():
        raise ValueError("Installed release directory is invalid")
    revision_file = target / ".release-revision"
    if revision_file.is_symlink() or not revision_file.is_file() or not REVISION.fullmatch(
        revision_file.read_text(encoding="ascii").strip()
    ):
        raise ValueError("Installed release revision is invalid")
    if not (target / "compose.local.yaml").is_file():
        raise ValueError("Installed Compose file is missing")
    return version, target


def verify_containers(home: Path) -> list[str]:
    web = inspect("ctf_agent_local")
    if web is not None:
        labels = (web.get("Config") or {}).get("Labels") or {}
        if web.get("Name") != "/ctf_agent_local" or labels.get("com.docker.compose.project") != "ctf_agent_local":
            raise RuntimeError("The web container does not belong to this local installation")
    updater = inspect("ctf_agent_local_updater")
    if updater is not None:
        environment = dict(
            item.split("=", 1) for item in (updater.get("Config") or {}).get("Env", [])
            if isinstance(item, str) and "=" in item
        )
        if (updater.get("Name") != "/ctf_agent_local_updater"
                or (updater.get("Config") or {}).get("Image") != "ctf-agent-updater:local"
                or environment.get("CTF_LOCAL_HOME") != str(home)):
            raise RuntimeError("The update container does not belong to this local installation")
    listed = docker(
        "ps", "-a", "--filter", f"label={MANAGED_LABEL}=true",
        "--filter", "name=ctf_agent_local_autosolver_", "--format", "{{.Names}}"
    )
    dynamic = []
    for name in listed.stdout.splitlines():
        match = AUTOSOLVER.fullmatch(name.strip())
        container = inspect(name.strip())
        labels = ((container or {}).get("Config") or {}).get("Labels") or {}
        if not match or container is None or container.get("Name") != "/" + name.strip() or (
            labels.get(MANAGED_LABEL) != "true" or labels.get(SLOT_LABEL) != match.group(1)
        ):
            raise RuntimeError("An autoscaled container could not be verified")
        dynamic.append(name.strip())
    return dynamic


def remove_release_files(home: Path) -> None:
    home = home.resolve(strict=True)
    releases = home / "releases"
    if releases.is_symlink() or releases.resolve(strict=True) != home / "releases":
        raise RuntimeError("Release directory is not an owned local path")
    for entry in releases.iterdir():
        if not VERSION.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        marker = entry / ".release-revision"
        if marker.is_symlink() or not marker.is_file() or not REVISION.fullmatch(
            marker.read_text(encoding="ascii").strip()
        ) or not (entry / "compose.local.yaml").is_file():
            continue
        if entry.resolve(strict=True).parent != releases:
            raise RuntimeError("Release path escaped the installation")
        shutil.rmtree(entry)
    if not any(releases.iterdir()):
        releases.rmdir()
    for name in (".current-release", ".toolchain-image", ".updater-image", ".local-config.json"):
        marker = home / name
        if marker.is_symlink():
            raise RuntimeError("An installation marker is a symlink")
        if marker.is_file():
            marker.unlink()
    launcher = home / ".launcher"
    if launcher.is_symlink():
        raise RuntimeError("Launcher directory is a symlink")
    if launcher.is_dir():
        for name in ("start.sh", "uninstall.py"):
            path = launcher / name
            if path.is_symlink():
                raise RuntimeError("Launcher file is a symlink")
            if path.is_file():
                path.unlink()
        if not any(launcher.iterdir()):
            launcher.rmdir()


def verify_external_database(mount: Path, database: Path, volume_id: str) -> None:
    """Keep uninstall from targeting an unmounted or substituted DB path."""

    if (not re.fullmatch(r"/mnt/wsl/[A-Za-z0-9_-]+", str(mount))
            or database != mount / "Database" / "CTF_Agent"
            or not re.fullmatch(r"[0-9a-f]{32}", volume_id)):
        raise RuntimeError("External database settings are invalid")
    with Path("/proc/self/mountinfo").open(encoding="utf-8") as stream:
        mounted = any(
            line.split(" - ", 1)[0].split()[4] == str(mount)
            and line.split(" - ", 1)[1].split()[0] == "ext4"
            for line in stream if " - " in line
        )
    marker = mount / ".ctf-agent-db-volume"
    if (not mounted or mount.is_symlink() or not mount.is_dir()
            or marker.is_symlink() or not marker.is_file()
            or marker.stat().st_size > 64
            or marker.read_text(encoding="ascii").strip() != volume_id
            or (mount / "Database").is_symlink() or database.is_symlink()):
        raise RuntimeError("The configured external database VHD is unavailable")


@contextmanager
def stop_host_updater(control: Path, *, external: bool):
    """Hold the uninstall and worker locks while removing a VHD-backed runtime."""

    if not external:
        yield
        return
    import fcntl

    if control.is_symlink() or not control.is_dir() or control.stat().st_uid != os.getuid():
        raise RuntimeError("The update control directory is not owned by this installation")
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    uninstall_fd = os.open(control / ".uninstall.lock", flags, 0o600)
    worker_fd = None
    stop = control / "stop-worker"
    lock_acquired = False
    stop_info = None
    valid_stop = False
    try:
        info = os.fstat(uninstall_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size or info.st_uid != os.getuid()):
            raise RuntimeError("The uninstall control lock is invalid")
        try:
            fcntl.flock(uninstall_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another uninstall is running") from exc
        lock_acquired = True
        if any(path.exists() or path.is_symlink() for path in
               (control / "request.json", control / "running.json")):
            raise RuntimeError("An update is queued or running; wait for it to finish")
        try:
            marker_fd = os.open(stop, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            marker_fd = None
        else:
            os.close(marker_fd)
        stop_info = stop.lstat()
        if (not stat.S_ISREG(stop_info.st_mode) or stop_info.st_nlink != 1
                or stop_info.st_size or stop_info.st_uid != os.getuid()):
            raise RuntimeError("The host worker stop marker is invalid")
        valid_stop = True
        worker_fd = os.open(control / "worker.lock", flags, 0o600)
        info = os.fstat(worker_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size or info.st_uid != os.getuid()):
            raise RuntimeError("The host worker lock is invalid")
        deadline = time.monotonic() + 15
        while True:
            try:
                fcntl.flock(worker_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("The host updater did not stop")
                time.sleep(0.2)
        if any(path.exists() or path.is_symlink() for path in
               (control / "request.json", control / "running.json")):
            raise RuntimeError("An update started during uninstall handoff")
        if stop.lstat() != stop_info:
            raise RuntimeError("The host worker stop marker changed")
        yield
    finally:
        try:
            if lock_acquired and valid_stop and (stop.exists() or stop.is_symlink()):
                if stop.lstat() == stop_info:
                    stop.unlink()
        finally:
            if worker_fd is not None:
                os.close(worker_fd)
            os.close(uninstall_fd)


def uninstall(home: Path) -> None:
    _version, release = release_root(home)
    home = home.resolve(strict=True)
    config_file = home / ".local-config.json"
    if config_file.is_symlink() or not config_file.is_file():
        raise RuntimeError("Local installation settings are missing")
    config = json.loads(config_file.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError("Local installation settings are invalid")
    default_database = home / "Database" / "CTF_Agent"
    database_value = config.get("database_path", str(default_database))
    mount_value = config.get("database_mount", "")
    volume_id = config.get("database_volume_id", "")
    if not all(isinstance(value, str) for value in (database_value, mount_value, volume_id)):
        raise RuntimeError("Local database settings are invalid")
    database = Path(database_value)
    if mount_value:
        verify_external_database(Path(mount_value), database, volume_id)
        database_alias = home / ".database-bind"
        if database_alias.is_symlink():
            if os.readlink(database_alias) != str(database):
                raise RuntimeError("The database bind link points to a different path")
        elif database_alias.exists():
            raise RuntimeError("The database bind path is occupied by another file")
    elif database != default_database or volume_id:
        raise RuntimeError("Local database settings are invalid")
    control = home / "ctf_agent_data" / "update-control"
    if (control / "running.json").exists() or (control / "request.json").exists():
        raise RuntimeError("An update is queued or running; wait for it to finish")
    with stop_host_updater(control, external=bool(mount_value)):
        if release_root(home)[1] != release:
            raise RuntimeError("The installed release changed while uninstall was starting")
        _uninstall_runtime(home, release, database, database_alias if mount_value else None)


def _uninstall_runtime(home: Path, release: Path, database: Path, database_alias: Path | None) -> None:
    docker("info")
    dynamic = verify_containers(home)
    updater = inspect("ctf_agent_local_updater")
    if updater is not None:
        docker("rm", "-f", "ctf_agent_local_updater")
    command = ["compose", "-f", str(release / "compose.local.yaml")]
    for number in range(2, 7):
        command += ["--profile", f"solver-{number}"]
    environment = dict(os.environ)
    environment["CTF_LOCAL_DATA"] = str(home / "ctf_agent_data")
    environment["CTF_LOCAL_DATABASE"] = str(database_alias or database)
    result = subprocess.run(
        ["docker", *command, "down", "--remove-orphans"],
        cwd=release, env=environment, capture_output=True, text=True, timeout=240, check=False,
    )
    if result.returncode:
        raise RuntimeError("Could not stop the local Compose stack")
    for name in dynamic:
        docker("rm", "-f", name)
    listed = docker("image", "ls", "--format", "{{.Repository}}:{{.Tag}}")
    tags = sorted({tag for tag in listed.stdout.splitlines() if IMAGE.fullmatch(tag)})
    for tag in tags:
        if tag.startswith("ctf-agent-local-runtime:"):
            details = docker("image", "inspect", tag)
            try:
                image, = json.loads(details.stdout)
                labels = (image.get("Config") or {}).get("Labels") or {}
                if labels.get("io.github.ctf-agent.local-runtime") != tag.split(":", 1)[1]:
                    raise ValueError("Local runtime image identity mismatch")
            except (ValueError, TypeError) as exc:
                raise RuntimeError("A local runtime image could not be verified") from exc
        docker("image", "rm", tag)
    local_runtime = docker(
        "image", "ls", "--filter", "label=io.github.ctf-agent.local-runtime",
        "--no-trunc", "--format", "{{.ID}}",
    )
    for image_id in sorted(set(local_runtime.stdout.splitlines())):
        if not IMAGE_ID.fullmatch(image_id):
            raise RuntimeError("A local runtime image ID could not be verified")
        details = docker("image", "inspect", image_id)
        try:
            image, = json.loads(details.stdout)
            labels = (image.get("Config") or {}).get("Labels") or {}
            if (not re.fullmatch(r"[0-9a-f]{64}", labels.get("io.github.ctf-agent.local-runtime", ""))
                    or any(not IMAGE.fullmatch(tag) for tag in image.get("RepoTags") or [])):
                raise ValueError("Local runtime image ownership mismatch")
        except (ValueError, TypeError) as exc:
            raise RuntimeError("A local runtime image could not be verified") from exc
        docker("image", "rm", image_id)
    dangling = docker(
        "image", "ls", "--filter", "label=io.github.ctf-agent.local-install=true",
        "--no-trunc", "--format", "{{.ID}}",
    )
    for image_id in sorted(set(dangling.stdout.splitlines())):
        if not IMAGE_ID.fullmatch(image_id):
            raise RuntimeError("A local image ID could not be verified")
        metadata = docker("image", "inspect", image_id)
        try:
            image, = json.loads(metadata.stdout)
            labels = (image.get("Config") or {}).get("Labels") or {}
            other_tags = image.get("RepoTags") or []
            if labels.get("io.github.ctf-agent.local-install") != "true" or any(
                not IMAGE.fullmatch(tag) for tag in other_tags
            ):
                raise ValueError("Image ownership mismatch")
        except (ValueError, TypeError) as exc:
            raise RuntimeError("A local image could not be verified") from exc
        docker("image", "rm", image_id)
    remove_release_files(home)
    if database_alias is not None and database_alias.is_symlink():
        database_alias.unlink()
    print("CTF Agent runtime removed.")
    print(f"Preserved data: {home / 'ctf_agent_data'}")
    print(f"Preserved database: {database}")
    print("WSL and Docker Desktop were not removed.")


if __name__ == "__main__":
    try:
        uninstall(Path(os.environ["CTF_LOCAL_HOME"]))
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Uninstall stopped: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
