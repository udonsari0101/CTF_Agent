"""Public release discovery and the isolated local installer update worker."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path


REPOSITORY = "udonsari0101/CTF_Agent"
LATEST_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
MAX_ARCHIVE_BYTES = 150 * 1024 * 1024
MAX_UNPACKED_BYTES = 300 * 1024 * 1024
_LATEST_CACHE: tuple[float, dict] | None = None
_LATEST_LOCK = threading.Lock()


def version_tuple(value: str) -> tuple[int, int, int] | None:
    matched = VERSION.fullmatch(value)
    return tuple(map(int, matched.groups())) if matched else None


def latest_release() -> dict:
    global _LATEST_CACHE
    with _LATEST_LOCK:
        if _LATEST_CACHE and time.monotonic() - _LATEST_CACHE[0] < 300:
            return dict(_LATEST_CACHE[1])
        request = urllib.request.Request(
            LATEST_URL,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "ctf-agent-release-check"},
        )
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError("Release metadata is too large")
        payload = json.loads(raw)
        tag = payload.get("tag_name")
        if not isinstance(tag, str) or version_tuple(tag) is None or payload.get("draft") or payload.get("prerelease"):
            raise ValueError("Invalid published release")
        names = {item.get("name") for item in payload.get("assets", []) if isinstance(item, dict)}
        archive = f"CTF_Agent-{tag}-local-windows.zip"
        if archive not in names or archive + ".sha256" not in names:
            raise ValueError("Release installer assets are missing")
        result = {
            "tag": tag,
            "notes": str(payload.get("body") or "")[:16_000],
            "published_at": payload.get("published_at"),
            "url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
        }
        _LATEST_CACHE = (time.monotonic(), result)
        return dict(result)


def control_root(data_dir: Path) -> Path:
    return data_dir / "update-control"


def read_status(root: Path) -> dict:
    try:
        value = json.loads((root / "status.json").read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, OSError, ValueError):
        return {}


def queue_update(root: Path, tag: str) -> str:
    if version_tuple(tag) is None:
        raise ValueError("Invalid release version")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (root / "running.json").exists():
        raise FileExistsError("Update already running")
    request_id = uuid.uuid4().hex
    request = {"id": request_id, "tag": tag, "created_at": time.time()}
    temporary = root / f".request-{request_id}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(request, stream)
            stream.flush()
            os.fsync(stream.fileno())
        if (root / "running.json").exists():
            raise FileExistsError("Update already running")
        os.link(temporary, root / "request.json")
    finally:
        temporary.unlink(missing_ok=True)
    return request_id


def _status(root: Path, phase: str, **values) -> None:
    value = {"phase": phase, "updated_at": time.time(), **values}
    temporary = root / f".status-{uuid.uuid4().hex}"
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, root / "status.json")


def _download(url: str, target: Path, maximum: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ctf-agent-release-update"})
    total = 0
    with urllib.request.urlopen(request, timeout=30) as response, target.open("xb") as stream:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise ValueError("Release asset exceeds size limit")
            stream.write(chunk)


def _verify_and_extract(archive: Path, checksum: Path, tag: str, destination: Path) -> Path:
    expected_name = archive.name
    line = checksum.read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-f]{64})  (CTF_Agent-v[0-9]+\.[0-9]+\.[0-9]+-local-windows\.zip)", line)
    if not match or match.group(2) != expected_name:
        raise ValueError("Release checksum format is invalid")
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != match.group(1):
        raise ValueError("Release checksum mismatch")
    prefix = f"CTF_Agent-{tag}/"
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        names = set()
        for item in bundle.infolist():
            name = item.filename
            parts = name.split("/")
            mode = (item.external_attr >> 16) & 0o170000
            if (not name.startswith(prefix) or name in names or item.is_dir()
                    or ".." in parts or "" in parts or mode not in {0, 0o100000}):
                raise ValueError("Release archive contains an invalid entry")
            names.add(name)
            total += item.file_size
            if total > MAX_UNPACKED_BYTES:
                raise ValueError("Release archive expands beyond limit")
        required = {prefix + value for value in ("VERSION", "COMMIT", "installer/install.sh", "app/compose.local.yaml")}
        if not required.issubset(names):
            raise ValueError("Release archive is incomplete")
        for item in bundle.infolist():
            target = destination.joinpath(*item.filename.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    root = destination / f"CTF_Agent-{tag}"
    if (root / "VERSION").read_text(encoding="utf-8").strip() != tag:
        raise ValueError("Release version does not match")
    if not re.fullmatch(r"[0-9a-f]{40}", (root / "COMMIT").read_text(encoding="ascii").strip()):
        raise ValueError("Release revision is invalid")
    return root


def _run_with_heartbeat(command: list[str], root: Path, request: dict, phase: str, *, env: dict[str, str]) -> bool:
    with subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
        while process.poll() is None:
            _status(root, phase, request_id=request["id"], tag=request["tag"])
            time.sleep(5)
        return process.returncode == 0


def _healthy(root: Path, request: dict, *, expected_sha: str | None = None) -> bool:
    for _ in range(36):
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", "ctf_agent_local"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            if expected_sha is None:
                return True
            release = subprocess.run(
                ["docker", "inspect", "--format", '{{range .Config.Env}}{{println .}}{{end}}', "ctf_agent_local"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if release.returncode == 0 and f"CTF_RELEASE_SHA={expected_sha}" in release.stdout.splitlines():
                return True
        _status(root, "health_check", request_id=request["id"], tag=request["tag"])
        time.sleep(5)
    return False


def _compose_mount_environment(home: Path) -> dict[str, str]:
    """Keep Docker's bind sources distinct from paths visible inside the updater."""
    result = subprocess.run(
        ["docker", "inspect", "ctf_agent_local"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode:
        raise RuntimeError("Installed container mounts are unavailable")
    try:
        container, = json.loads(result.stdout)
        mounts = {
            item["Destination"]: item["Source"]
            for item in container["Mounts"]
            if item.get("Type") == "bind" and item.get("Destination") in {"/data", "/database"}
        }
        if set(mounts) != {"/data", "/database"} or any(
            not isinstance(source, str) or not source.startswith("/") for source in mounts.values()
        ):
            raise ValueError("Missing bind mounts")
        current_env = dict(item.split("=", 1) for item in container["Config"]["Env"] if "=" in item)
        auth_mode = current_env["CTF_AUTH_MODE"]
        if auth_mode not in {"password", "nologin"}:
            raise ValueError("Unsupported auth mode")
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("Installed container mounts are invalid") from exc
    return {
        "CTF_LOCAL_DATA": mounts["/data"],
        "CTF_LOCAL_DATABASE": mounts["/database"],
        "CTF_LOCAL_FS_DATA": str(home / "ctf_agent_data"),
        "CTF_LOCAL_FS_DATABASE": str(home / "Database" / "CTF_Agent"),
        "CTF_LOCAL_AUTH_MODE": auth_mode,
        "CTF_AUTH_MODE": auth_mode,
    }


def _rollback(home: Path, previous: str, root: Path, request: dict, mount_environment: dict[str, str]) -> bool:
    target = home / "releases" / previous
    revision_file = target / ".release-revision"
    if not revision_file.is_file():
        return False
    env = dict(os.environ)
    env.update({
        "CTF_LOCAL_HOME": str(home),
        "CTF_LOCAL_UID": os.environ["CTF_LOCAL_UID"], "CTF_LOCAL_GID": os.environ["CTF_LOCAL_GID"],
        "CTF_RELEASE_SHA": revision_file.read_text(encoding="ascii").strip(),
        "CTF_RELEASE_VERSION": previous, "CTF_ALLOW_WEB_BOOTSTRAP": "true",
    })
    env.update(mount_environment)
    _status(root, "rolling_back", request_id=request["id"], tag=request["tag"])
    rollback_tag = "ctf-agent-local:rollback-" + env["CTF_RELEASE_SHA"][:12]
    restored_image = subprocess.run(
        ["docker", "image", "tag", rollback_tag, "ctf-agent-local:latest"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if restored_image.returncode:
        return False
    if not _run_with_heartbeat(["python3", str(target / "deploy" / "local-compose.py"), "up", "-d", "--no-build", "--force-recreate"],
                               root, request, "rolling_back", env=env):
        return False
    return _healthy(root, request)


def _apply(home: Path, root: Path, request: dict) -> None:
    tag = request["tag"]
    if version_tuple(tag) is None:
        raise ValueError("Invalid update tag")
    previous_file = home / ".current-release"
    previous = previous_file.read_text(encoding="ascii").strip() if previous_file.exists() else ""
    if version_tuple(previous) is None or version_tuple(tag) <= version_tuple(previous):
        raise ValueError("Release is not newer than the installed version")
    if shutil.disk_usage(home).free < 15 * 1024**3:
        raise ValueError("At least 15 GB free space is required for an update")
    latest = latest_release()
    if latest["tag"] != tag:
        raise ValueError("Requested release is no longer latest")
    name = f"CTF_Agent-{tag}-local-windows.zip"
    base = f"https://github.com/{REPOSITORY}/releases/download/{tag}/"
    _status(root, "downloading", request_id=request["id"], tag=tag)
    with tempfile.TemporaryDirectory(prefix=".update-", dir=home / "releases") as temporary:
        scratch = Path(temporary)
        archive, checksum = scratch / name, scratch / (name + ".sha256")
        _download(base + name, archive, MAX_ARCHIVE_BYTES)
        _download(base + name + ".sha256", checksum, 1024)
        _status(root, "verifying", request_id=request["id"], tag=tag)
        bundle = _verify_and_extract(archive, checksum, tag, scratch)
        old_revision = (home / "releases" / previous / ".release-revision").read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{40}", old_revision):
            raise ValueError("Previous release revision is unavailable")
        preserved = subprocess.run(
            ["docker", "image", "tag", "ctf-agent-local:latest", "ctf-agent-local:rollback-" + old_revision[:12]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if preserved.returncode:
            raise RuntimeError("Previous image could not be preserved")
        mount_environment = _compose_mount_environment(home)
        env = dict(os.environ)
        env["CTF_LOCAL_HOME"] = str(home)
        env["CTF_UPDATE_IN_PROGRESS"] = "true"
        env["CTF_LOCAL_UID"] = os.environ["CTF_LOCAL_UID"]
        env["CTF_LOCAL_GID"] = os.environ["CTF_LOCAL_GID"]
        env.update(mount_environment)
        success = _run_with_heartbeat(
            ["bash", str(bundle / "installer" / "install.sh")], root, request, "installing", env=env,
        )
        if success:
            success = _healthy(root, request, expected_sha=(bundle / "COMMIT").read_text(encoding="ascii").strip())
        if not success:
            restored = _rollback(home, previous, root, request, mount_environment)
            if restored:
                previous_file.write_text(previous + "\n", encoding="ascii")
            raise RuntimeError("Update failed; previous release restored" if restored else "Update and rollback failed")
        previous_file.write_text(tag + "\n", encoding="ascii")
        _status(root, "completed", request_id=request["id"], tag=tag, previous=previous)


def worker_loop() -> None:
    import fcntl
    home = Path(os.environ["CTF_LOCAL_HOME"]).resolve(strict=True)
    root = control_root(home / "ctf_agent_data")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = root / "worker.lock"
    with lock.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (root / "running.json").exists():
            (root / "running.json").unlink()
            _status(root, "failed", message="The previous update process stopped unexpectedly")
        while True:
            request_path = root / "request.json"
            running_path = root / "running.json"
            if not request_path.exists():
                status = read_status(root)
                phase = status.pop("phase", "idle")
                status.pop("updated_at", None)
                _status(root, phase, **status)
                time.sleep(5)
                continue
            os.replace(request_path, running_path)
            try:
                request = json.loads(running_path.read_text(encoding="utf-8"))
                if not isinstance(request, dict) or not re.fullmatch(r"[0-9a-f]{32}", request.get("id", "")):
                    raise ValueError("Invalid update request")
                _apply(home, root, request)
            except Exception as exc:
                message = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else "Update failed"
                _status(root, "failed", message=message[:240])
            finally:
                running_path.unlink(missing_ok=True)


if __name__ == "__main__":
    worker_loop()
