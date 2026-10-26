#!/usr/bin/env python3
"""Host-side updater for an existing digest-pinned CTF Agent deployment.

The web process may request only the newest published release. This helper
resolves its Git tag to a commit and that commit to an immutable GHCR digest,
then delegates deployment to the existing host rollout and rollback scripts.
It never builds an image on the Docker host.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"sha256:[0-9a-f]{64}\Z")
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{2,5})?/[a-z0-9][a-z0-9._/-]{1,200}\Z")


def _version(value: str) -> tuple[int, int, int] | None:
    match = VERSION.fullmatch(value)
    return tuple(map(int, match.groups())) if match else None


def _read_json(url: str, maximum: int = 256 * 1024) -> dict:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ctf-agent-host-update"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("GitHub response exceeds the expected size")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Invalid GitHub response")
    return value


def _latest_release(repository: str) -> str:
    payload = _read_json(f"https://api.github.com/repos/{repository}/releases/latest")
    tag = payload.get("tag_name")
    if (
        not isinstance(tag, str) or _version(tag) is None
        or payload.get("draft") or payload.get("prerelease")
    ):
        raise ValueError("No valid published release")
    assets = {item.get("name") for item in payload.get("assets", []) if isinstance(item, dict)}
    archive = f"CTF_Agent-{tag}-local-windows.zip"
    if archive not in assets or archive + ".sha256" not in assets:
        raise ValueError("Published release assets are incomplete")
    return tag


def _tag_revision(repository: str, tag: str) -> str:
    if _version(tag) is None:
        raise ValueError("Invalid release tag")
    encoded = urllib.parse.quote(tag, safe="")
    payload = _read_json(f"https://api.github.com/repos/{repository}/git/ref/tags/{encoded}")
    target = payload.get("object")
    for _ in range(3):
        if not isinstance(target, dict):
            break
        revision = target.get("sha")
        kind = target.get("type")
        if not isinstance(revision, str) or not HEX40.fullmatch(revision):
            break
        if kind == "commit":
            return revision
        if kind != "tag":
            break
        target = _read_json(f"https://api.github.com/repos/{repository}/git/tags/{revision}").get("object")
    raise ValueError("Release tag does not resolve to a commit")


def _image_ref(image: str, revision: str) -> str:
    if not HEX40.fullmatch(revision):
        raise ValueError("Invalid image revision")
    result = subprocess.run(
        ["docker", "manifest", "inspect", "--verbose", f"{image}:{revision}"],
        capture_output=True, timeout=90, check=False,
    )
    if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
        raise RuntimeError("Published image manifest is unavailable")
    manifest = json.loads(result.stdout)
    descriptor = manifest.get("Descriptor") if isinstance(manifest, dict) else None
    digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("Published image digest is invalid")
    return f"{image}@{digest}"


def _write_json(directory: Path, name: str, payload: dict, mode: int = 0o644) -> None:
    temporary = directory / f".{name}-{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, directory / name)
    finally:
        temporary.unlink(missing_ok=True)


def _status(control: Path, phase: str, **fields: object) -> None:
    _write_json(control, "status.json", {
        "mode": "production", "phase": phase, "updated_at": time.time(), **fields,
    })


def _regular_text(path: Path, maximum: int = 1024) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError("Expected a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.read(descriptor, maximum + 1).decode("utf-8").strip()
    finally:
        os.close(descriptor)


def _current_revision(release_root: Path) -> str:
    revision = _regular_text(release_root / "current", 80)
    if not HEX40.fullmatch(revision):
        raise ValueError("Current release revision is invalid")
    return revision


def _current_version(control: Path, revision: str, repository: str) -> str:
    marker = json.loads(_regular_text(control / "current-version.json", 512))
    if not isinstance(marker, dict) or set(marker) != {"tag", "revision", "repository"}:
        raise ValueError("Current version marker is invalid")
    tag = marker["tag"]
    if (
        not isinstance(tag, str) or _version(tag) is None
        or marker["revision"] != revision or marker["repository"] != repository
    ):
        raise ValueError("Current version marker is stale")
    return tag


def _request(control: Path) -> dict:
    request = json.loads(_regular_text(control / "running.json", 2048))
    if (
        not isinstance(request, dict) or set(request) != {"id", "tag", "created_at"}
        or not isinstance(request["id"], str) or not REQUEST_ID.fullmatch(request["id"])
        or not isinstance(request["tag"], str) or _version(request["tag"]) is None
        or type(request["created_at"]) not in {int, float}
    ):
        raise ValueError("Update request is invalid")
    return request


def _run_rollout(command: list[str], control: Path, request: dict, image: str) -> bool:
    environment = dict(os.environ)
    environment["CTF_EXPECTED_IMAGE_REPOSITORY"] = image
    process = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while process.poll() is None:
        _status(control, "installing", request_id=request["id"], tag=request["tag"])
        time.sleep(5)
    return process.returncode == 0


def _refresh_host_helper(image_ref: str, rollout: Path) -> bool:
    """Install reviewed helper files from the just-verified running image."""

    helper = Path(__file__).absolute()
    for destination in (helper, rollout):
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("Installed updater files are not root-owned regular files")
    current = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", "ctf_agent"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if current.returncode or current.stdout.strip() != image_ref:
        raise RuntimeError("Running image is not the verified release")
    with tempfile.TemporaryDirectory(prefix=".ctf-update-", dir=helper.parent) as temporary:
        scratch = Path(temporary)
        replacements = (
            ("production-update.py", helper),
            ("remote-rollout.sh", rollout),
        )
        changed = []
        for name, destination in replacements:
            target = scratch / name
            result = subprocess.run(
                ["docker", "cp", f"ctf_agent:/app/deploy/{name}", str(target)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False,
            )
            info = target.lstat() if target.exists() else None
            if result.returncode or info is None or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise RuntimeError("Release updater files are unavailable")
            if name.endswith(".py"):
                compile(target.read_bytes(), str(target), "exec")
            else:
                subprocess.run(["sh", "-n", str(target)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(target.read_bytes()).digest():
                changed.append((name, destination))
        if not changed:
            return False
        prepared = []
        replaced = []
        try:
            for name, destination in changed:
                backup = scratch / (name + ".previous")
                shutil.copyfile(destination, backup)
                replacement = destination.with_name(f".{destination.name}-{uuid.uuid4().hex}.tmp")
                shutil.copyfile(scratch / name, replacement)
                os.chown(replacement, 0, 0)
                os.chmod(replacement, 0o555)
                prepared.append((destination, replacement, backup))
            # The executing Python process retains its code until the worker
            # exits; systemd restarts it against the new validated source.
            for destination, replacement, backup in prepared:
                os.replace(replacement, destination)
                replaced.append((destination, backup))
        except Exception:
            for destination, backup in reversed(replaced):
                restore = destination.with_name(f".{destination.name}-{uuid.uuid4().hex}.rollback")
                shutil.copyfile(backup, restore)
                os.chown(restore, 0, 0)
                os.chmod(restore, 0o555)
                os.replace(restore, destination)
            raise
        finally:
            for _destination, replacement, _backup in prepared:
                replacement.unlink(missing_ok=True)
        return True


def _apply(control: Path, release_root: Path, rollout: Path, repository: str, image: str, request: dict) -> bool:
    current_revision = _current_revision(release_root)
    current_tag = _current_version(control, current_revision, repository)
    tag = request["tag"]
    if _version(tag) <= _version(current_tag):
        raise ValueError("Requested release is not newer")
    _status(control, "verifying", request_id=request["id"], tag=tag)
    if _latest_release(repository) != tag:
        raise ValueError("Requested release is no longer latest")
    revision = _tag_revision(repository, tag)
    if revision == current_revision:
        raise ValueError("Release already runs on this host")
    image_ref = _image_ref(image, revision)
    if not _run_rollout(
        ["sh", str(rollout), revision, image_ref, str(release_root)],
        control, request, image,
    ):
        raise RuntimeError("Update failed; the release script retained or restored the previous version")
    if _current_revision(release_root) != revision:
        raise RuntimeError("Release marker did not advance after rollout")
    _write_json(control, "current-version.json", {"tag": tag, "revision": revision, "repository": repository})
    _status(control, "completed", request_id=request["id"], tag=tag, previous=current_tag)
    try:
        return _refresh_host_helper(image_ref, rollout)
    except Exception:
        # The application rollout already succeeded. A helper refresh failure
        # must not trigger a fake deployment rollback; keep the previous helper.
        return False


def _validate_paths(release_root: Path, rollout: Path) -> Path:
    if release_root.is_symlink() or rollout.is_symlink():
        raise ValueError("Invalid production update paths")
    release_root = release_root.resolve(strict=True)
    rollout = rollout.resolve(strict=True)
    if (
        not release_root.is_dir()
        or not rollout.is_file()
        or rollout.stat().st_uid != 0 or rollout.stat().st_mode & 0o022
        or release_root.stat().st_uid != 0
    ):
        raise ValueError("Invalid production update paths")
    control = release_root.parent / "update-control"
    if control.is_symlink():
        raise ValueError("Invalid update control path")
    control.mkdir(mode=0o700, exist_ok=True)
    if not control.is_dir() or control.resolve() != control:
        raise ValueError("Invalid update control path")
    # The web process owns the data root and must be able to queue requests.
    os.chown(control, 10001, 10001)
    os.chmod(control, 0o700)
    return control


def _config(path: Path) -> tuple[Path, Path, str, str]:
    if path.is_symlink():
        raise ValueError("Invalid updater configuration")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 4096:
        raise ValueError("Invalid updater configuration")
    value = json.loads(_regular_text(path, 4096))
    if not isinstance(value, dict) or set(value) != {"release_root", "rollout_script", "repository", "image"}:
        raise ValueError("Invalid updater configuration")
    root, rollout, repository, image = (
        value["release_root"], value["rollout_script"], value["repository"], value["image"]
    )
    if (
        not all(isinstance(item, str) for item in (root, rollout, repository, image))
        or not root.startswith("/") or not rollout.startswith("/")
        or not REPOSITORY.fullmatch(repository) or not IMAGE.fullmatch(image)
        or "//" in image or "/../" in image or image.endswith(("/", "."))
    ):
        raise ValueError("Invalid updater configuration")
    return Path(root), Path(rollout), repository, image


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--bootstrap-version")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Production updater must run as root")
    release_root, rollout, repository, image = _config(args.config)
    control = _validate_paths(release_root, rollout)
    release_root = release_root.resolve(strict=True)
    rollout = rollout.resolve(strict=True)
    if args.check_config:
        return
    if args.bootstrap_version is not None:
        if _version(args.bootstrap_version) is None:
            raise SystemExit("Invalid bootstrap version")
        _write_json(control, "current-version.json", {
            "tag": args.bootstrap_version, "revision": _current_revision(release_root),
            "repository": repository,
        })
        return
    lock_path = control / "worker.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(lock_fd, "wb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (control / "running.json").exists():
            (control / "running.json").unlink()
            _status(control, "failed", message="The previous update process stopped unexpectedly")
        while True:
            incoming = control / "request.json"
            running = control / "running.json"
            if not incoming.exists():
                status_path = control / "status.json"
                try:
                    prior = json.loads(_regular_text(status_path, 2048))
                    phase = prior.get("phase", "idle")
                    rest = {key: prior[key] for key in ("request_id", "tag", "previous", "message") if key in prior}
                except (FileNotFoundError, OSError, ValueError, TypeError):
                    phase, rest = "idle", {}
                _status(control, phase, **rest)
                time.sleep(5)
                continue
            if running.exists():
                _status(control, "failed", message="Another update is still running")
                time.sleep(5)
                continue
            os.replace(incoming, running)
            restart_for_new_helper = False
            try:
                request = _request(control)
                restart_for_new_helper = _apply(control, release_root, rollout, repository, image, request)
            except Exception:
                _status(control, "failed", message="Update failed; the current release was preserved or rolled back where possible")
            finally:
                running.unlink(missing_ok=True)
            if restart_for_new_helper:
                # systemd restarts the service and reopens the newly installed
                # helper after the flock above is released.
                return


if __name__ == "__main__":
    main()
