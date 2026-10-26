"""Private, bounded solver session snapshots shared only through the exchange.

The web coordinator owns access control and long term storage.  The worker only
creates and restores a single sanitized archive for the current isolated job.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


SNAPSHOT_LIMIT = 512 * 1024 * 1024
SNAPSHOT_FREE_RESERVE = 1024 * 1024 * 1024
SNAPSHOT_FILE_LIMIT = 20_000
BASELINE_FILE_LIMIT = 50_000
BASELINE_PATH_BYTES_LIMIT = 8 * 1024 * 1024
WORKDIR_REL = "competition/challenge/codex-workdir"
_SCRATCH_NAME = re.compile(r"ctf-job-[A-Za-z0-9_-]{6,64}\Z")
_SESSION_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_PRIVATE_NAMES = frozenset({
    "auth.json", ".credentials.json", ".api-key", ".env", ".npmrc",
    ".netrc", "id_rsa", "id_ed25519", "credentials", "secrets.json",
})
_SKIP_DIRS = frozenset({
    ".git", ".ssh", ".aws", ".config", "cache", "tmp", "node_modules",
    "__pycache__", ".pytest_cache", ".venv", "venv",
})


class ContinuationInvalid(ValueError):
    """The staged snapshot cannot be used; normal retry remains available."""


@dataclass(frozen=True)
class ContinuationInput:
    provider: str
    session_id: str
    scratch_name: str
    mode: str
    archive_size: int
    archive_sha256: str
    input_sha256: str


def _regular_file(path: Path, maximum: int) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum


def _load_json(path: Path, maximum: int = 4096) -> dict:
    if not _regular_file(path, maximum):
        raise ContinuationInvalid("invalid continuation metadata")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ContinuationInvalid("invalid continuation metadata") from exc
    if not isinstance(value, dict):
        raise ContinuationInvalid("invalid continuation metadata")
    return value


def read_input(active: Path, provider: str) -> ContinuationInput | None:
    """Validate trusted staging metadata before reusing an old absolute cwd."""
    root = active / "continuation-input"
    if not root.exists():
        return None
    if root.is_symlink() or not root.is_dir():
        raise ContinuationInvalid("invalid continuation directory")
    meta = _load_json(root / "meta.json")
    mode = _load_json(root / "mode.json")
    if set(meta) != {
        "version", "provider", "session_id", "scratch_name", "workdir_rel",
        "archive_sha256", "archive_size", "input_sha256",
    } or set(mode) != {"version", "mode"}:
        raise ContinuationInvalid("invalid continuation schema")
    if meta["version"] != 1 or mode["version"] != 1:
        raise ContinuationInvalid("invalid continuation version")
    if meta["provider"] not in {"codex", "claude"} or mode["mode"] not in {"session", "workspace"}:
        raise ContinuationInvalid("invalid continuation mode")
    if mode["mode"] == "session" and meta["provider"] != provider:
        raise ContinuationInvalid("invalid continuation provider")
    if not isinstance(meta["session_id"], str) or (
        meta["session_id"] and not _SESSION_ID.fullmatch(meta["session_id"])
    ) or (mode["mode"] == "session" and not meta["session_id"]):
        raise ContinuationInvalid("invalid continuation session")
    if not isinstance(meta["scratch_name"], str) or not _SCRATCH_NAME.fullmatch(meta["scratch_name"]):
        raise ContinuationInvalid("invalid continuation scratch")
    if meta["workdir_rel"] != WORKDIR_REL:
        raise ContinuationInvalid("invalid continuation workdir")
    if not isinstance(meta["archive_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", meta["archive_sha256"]):
        raise ContinuationInvalid("invalid continuation digest")
    if not isinstance(meta["input_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", meta["input_sha256"]):
        raise ContinuationInvalid("invalid continuation input digest")
    if type(meta["archive_size"]) is not int or not 0 < meta["archive_size"] <= SNAPSHOT_LIMIT:
        raise ContinuationInvalid("invalid continuation size")
    return ContinuationInput(
        meta["provider"], meta["session_id"], meta["scratch_name"],
        mode["mode"], meta["archive_size"], meta["archive_sha256"],
        meta["input_sha256"],
    )


def _private_path(relative: PurePosixPath) -> bool:
    return any(
        part in _PRIVATE_NAMES or part.startswith(".env.") or part in _SKIP_DIRS
        for part in relative.parts
    )


def _provider_paths(root: Path, provider: str) -> list[tuple[Path, str]]:
    if provider == "claude":
        return [(root / "home" / "claude" / "projects", "provider/projects")]
    # An ID resume is backed by the rollout under sessions/.  SQLite/index
    # files are deliberately omitted because they are broader account state.
    return [(root / "home" / "sessions", "provider/sessions")]


def workspace_baseline(workdir: Path) -> dict[str, tuple[int, int, int, int]] | None:
    """Record cheap file identities after input extraction, before the agent runs."""
    baseline: dict[str, tuple[int, int, int, int]] = {}
    path_bytes = 0
    for current, dirs, files in os.walk(workdir, followlinks=False):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
        for name in files:
            path = current_path / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                relative = path.relative_to(workdir).as_posix()
                path_bytes += len(relative.encode("utf-8", errors="surrogateescape"))
                if len(baseline) >= BASELINE_FILE_LIMIT or path_bytes > BASELINE_PATH_BYTES_LIMIT:
                    return None
                baseline[relative] = (
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino,
                )
    return baseline


def _source_files(root: Path, provider: str, baseline: dict[str, tuple[int, int, int, int]]):
    sources = [(root / WORKDIR_REL, "workdir"), *_provider_paths(root, provider)]
    for source, prefix in sources:
        if not source.exists() or source.is_symlink():
            continue
        if source.is_file():
            info = source.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                if info.st_size > SNAPSHOT_LIMIT:
                    raise ContinuationInvalid("continuation file exceeds size limit")
                yield source, PurePosixPath(prefix)
            continue
        if not source.is_dir():
            continue
        for current, dirs, files in os.walk(source, followlinks=False):
            current_path = Path(current)
            relative_dir = current_path.relative_to(source)
            dirs[:] = [
                name for name in dirs
                if not _private_path(PurePosixPath(*relative_dir.parts, name))
                and not (current_path / name).is_symlink()
            ]
            for name in files:
                relative = PurePosixPath(*relative_dir.parts, name)
                if _private_path(relative):
                    continue
                if prefix == "workdir":
                    if relative.as_posix() in {"AGENTS.md", "CLAUDE.md", "notes/RELATED.json"}:
                        continue
                    try:
                        info = (current_path / name).lstat()
                    except OSError:
                        continue
                    identity = (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino)
                    if baseline.get(relative.as_posix()) == identity:
                        continue
                path = current_path / name
                info = path.lstat()
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    if info.st_size > SNAPSHOT_LIMIT:
                        raise ContinuationInvalid("continuation file exceeds size limit")
                    yield path, PurePosixPath(prefix, *relative.parts)


def _write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, separators=(",", ":"), sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def capture_snapshot(
    active: Path, job_root: Path, provider: str, session_id: str | None,
    input_sha256: str, baseline: dict[str, tuple[int, int, int, int]] | None,
) -> bool:
    """Stage a private snapshot only after all provider processes have exited."""
    if provider not in {"codex", "claude"} or not _SCRATCH_NAME.fullmatch(job_root.name):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", input_sha256):
        return False
    if baseline is None:
        return False
    try:
        # The coordinator may briefly copy the archive into the durable store.
        # Keep room for both copies plus a fixed minimum before writing either.
        if shutil.disk_usage(active).free < 2 * SNAPSHOT_LIMIT + SNAPSHOT_FREE_RESERVE:
            return False
    except OSError:
        return False
    if session_id is None:
        session_id = ""
    if session_id and not _SESSION_ID.fullmatch(session_id):
        return False
    output = active / "continuation"
    if output.exists():
        return False
    try:
        output.mkdir(mode=0o700)
        archive = output / "snapshot.tar.gz"
        raw_size = 0
        file_count = 0
        history_count = 0
        with tarfile.open(archive, "w:gz", compresslevel=1) as tar:
            for source, name in _source_files(job_root, provider, baseline):
                info = source.lstat()
                raw_size += info.st_size
                file_count += 1
                if raw_size > SNAPSHOT_LIMIT or file_count > SNAPSHOT_FILE_LIMIT:
                    raise ContinuationInvalid("continuation exceeds size limit")
                if session_id and name.parts[0] == "provider":
                    if provider == "claude":
                        if (
                            len(name.parts) >= 4
                            and name.parts[1] == "projects"
                            and name.name == session_id + ".jsonl"
                        ):
                            history_count += 1
                    elif (
                        len(name.parts) >= 3
                        and name.parts[1] == "sessions"
                        and name.name.endswith(session_id + ".jsonl")
                    ):
                        history_count += 1
                descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(descriptor, "rb") as stream:
                    current = os.fstat(stream.fileno())
                    if not stat.S_ISREG(current.st_mode) or current.st_size != info.st_size or current.st_nlink != 1:
                        raise ContinuationInvalid("continuation changed during capture")
                    entry = tarfile.TarInfo(str(name))
                    entry.size = current.st_size
                    entry.mode = 0o600
                    tar.addfile(entry, stream)
        if not file_count:
            raise ContinuationInvalid("empty continuation")
        if not history_count:
            session_id = ""
        if not _regular_file(archive, SNAPSHOT_LIMIT):
            raise ContinuationInvalid("continuation exceeds size limit")
        with archive.open("r+b") as stream:
            stream.flush()
            os.fsync(stream.fileno())
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        _write_json(output / "meta.json", {
            "version": 1,
            "provider": provider,
            "session_id": session_id,
            "scratch_name": job_root.name,
            "workdir_rel": WORKDIR_REL,
            "archive_sha256": digest,
            "archive_size": archive.stat().st_size,
            "input_sha256": input_sha256,
        })
        return True
    except (OSError, ValueError, tarfile.TarError):
        shutil.rmtree(output, ignore_errors=True)
        return False


def _archive_target(job_root: Path, name: str, mode: str, provider: str) -> Path | None:
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts or any(part in {".", "..", ""} for part in pure.parts):
        raise ContinuationInvalid("unsafe continuation path")
    if _private_path(pure):
        raise ContinuationInvalid("private continuation path")
    if pure.parts[0] == "workdir" and len(pure.parts) >= 2:
        if pure.parts[1:] in {
            ("AGENTS.md",), ("CLAUDE.md",), ("notes", "RELATED.json"),
        }:
            raise ContinuationInvalid("base workspace file cannot be restored")
        return job_root / WORKDIR_REL / Path(*pure.parts[1:])
    if mode == "workspace":
        return None
    if pure.parts[0] != "provider" or len(pure.parts) < 2:
        raise ContinuationInvalid("unexpected continuation path")
    if provider == "claude":
        if pure.parts[1] != "projects" or len(pure.parts) < 3:
            raise ContinuationInvalid("unexpected Claude history path")
        return job_root / "home" / "claude" / Path(*pure.parts[1:])
    if pure.parts[1] == "sessions" and len(pure.parts) >= 3:
        return job_root / "home" / Path(*pure.parts[1:])
    raise ContinuationInvalid("unexpected Codex history path")


def restore_snapshot(active: Path, job_root: Path, staged: ContinuationInput) -> bool:
    """Validate the whole archive, then restore regular files without links."""
    archive = active / "continuation-input" / "snapshot.tar.gz"
    if not _regular_file(archive, SNAPSHOT_LIMIT) or archive.stat().st_size != staged.archive_size:
        return False
    try:
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != staged.archive_sha256:
                return False
        total = 0
        count = 0
        with tarfile.open(archive, "r:gz") as tar:
            entries = tar.getmembers()
            for entry in entries:
                if not entry.isfile() or entry.size < 0:
                    raise ContinuationInvalid("unsafe continuation entry")
                total += entry.size
                count += 1
                if total > SNAPSHOT_LIMIT or count > SNAPSHOT_FILE_LIMIT:
                    raise ContinuationInvalid("continuation exceeds size limit")
                _archive_target(job_root, entry.name, staged.mode, staged.provider)
            for entry in entries:
                target = _archive_target(job_root, entry.name, staged.mode, staged.provider)
                if target is None:
                    continue
                relative = target.relative_to(job_root)
                cursor = job_root
                for part in relative.parts[:-1]:
                    cursor = cursor / part
                    if cursor.is_symlink():
                        raise ContinuationInvalid("continuation destination is a link")
                    if cursor.exists() and not cursor.is_dir():
                        raise ContinuationInvalid("continuation destination is not a directory")
                    cursor.mkdir(mode=0o700, exist_ok=True)
                if target.is_symlink():
                    # Immutable challenge input is restaged from the current job.
                    continue
                if target.exists() and not target.is_file():
                    raise ContinuationInvalid("continuation destination is not a file")
                source = tar.extractfile(entry)
                if source is None:
                    raise ContinuationInvalid("missing continuation entry")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(descriptor, "wb") as output, source:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                target.chmod(0o600)
        return True
    except (OSError, ValueError, tarfile.TarError, EOFError):
        return False
