"""Safely prepare archive attachments for the isolated solver workspace.

The original ctf_agent driver expanded zip, tar, 7z, and single-file compressed
attachments before starting an agent.  The web service keeps uploaded bytes
immutable, so this adapter leaves every raw attachment in ``attachments/`` and
places disposable expansions below ``extracted/`` in the job scratch.
"""

from __future__ import annotations

import bz2
import dataclasses
import errno
import gzip
import json
import lzma
import math
import os
import re
import secrets
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Iterator


ZIP_EXTENSIONS = {".zip", ".jar", ".apk"}
TAR_EXTENSIONS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"}
SEVEN_ZIP_EXTENSIONS = {".7z"}
SINGLE_EXTENSIONS = {".gz", ".bz2", ".xz"}

def _nonnegative_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    if not re.fullmatch(r"[0-9]{1,19}", raw):
        raise RuntimeError(f"{name} must be a non-negative integer")
    value = int(raw)
    if value > 2**63 - 1:
        raise RuntimeError(f"{name} is too large")
    return value


# Zero means unlimited, matching CTF Agent's disk-backed extraction. Operators
# can opt into tighter caps. Every streamed write independently preserves the
# filesystem free-space floor, so an expansion cannot consume the whole host.
MAX_ARCHIVE_OUTPUT_BYTES = _nonnegative_env("CTF_SOLVER_ARCHIVE_MAX_BYTES", 0)
MAX_ARCHIVE_MEMBERS = _nonnegative_env("CTF_SOLVER_ARCHIVE_MAX_MEMBERS", 0)
MAX_ARCHIVE_SECONDS = _nonnegative_env("CTF_SOLVER_ARCHIVE_MAX_SECONDS", 0)
MIN_ARCHIVE_FREE_BYTES = _nonnegative_env("CTF_SOLVER_MIN_FREE_BYTES", 1024 * 1024 * 1024)
MAX_ARCHIVE_COMPRESSION_RATIO = _nonnegative_env("CTF_SOLVER_ARCHIVE_MAX_RATIO", 0)
MAX_ARCHIVE_MEMORY_BYTES = _nonnegative_env("CTF_SOLVER_ARCHIVE_MAX_MEMORY", 0)
MAX_NESTED_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_CHILD_REQUEST_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_CHILD_RESULT_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_CHILD_OPEN_FILES = 64
ARCHIVE_CHILD_WALL_GRACE_SECONDS = 0.5
ARCHIVE_LAUNCHER = Path("/usr/local/libexec/ctf-agent-archive-launcher")

_RECOVERABLE_ARCHIVE_CODES = {
    "archive_compression_ratio",
    "archive_expansion_limit",
    "archive_member_limit",
    "archive_scratch_full",
    "archive_time_limit",
    # A collision is ambiguous to materialize, but the immutable raw archive
    # remains safe and useful to the isolated solver.  Discard the complete
    # staging directory and continue instead of refusing the whole job.
    "unsafe_archive_collision",
}
_FATAL_SAFETY_MESSAGES = {
    "archive_source_changed": "첨부 압축파일 원본의 안전성을 다시 확인할 수 없습니다.",
    "invalid_archive_metadata": "첨부 압축파일의 크기 정보를 안전하게 확인할 수 없습니다.",
    "unsafe_archive_collision": "첨부 압축파일에 중복되거나 충돌하는 경로가 있습니다.",
    "unsafe_archive_entry": "첨부 압축파일에 링크 또는 특수 파일이 있어 해제를 거부했습니다.",
    "unsafe_archive_path": "첨부 압축파일에 안전하지 않은 경로가 있습니다.",
}
_SKIP_REASONS = {
    "destination_collision",
    "encrypted_archive",
    "extractor_crashed",
    "extractor_isolation_unavailable",
    "extractor_result_invalid",
    "extractor_timeout",
    "input_limit",
    "invalid_or_unsupported_archive",
    "nested_depth_limit",
    "safe_7z_extractor_unavailable",
    "truncated_archive",
    "unreadable_archive",
    *_RECOVERABLE_ARCHIVE_CODES,
}

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_DEVICE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE
)


class ArchiveSafetyError(ValueError):
    """An archive violated a boundary and must refuse the solver job."""

    def __init__(self, code: str, public_message: str):
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


class _ArchiveFormatError(Exception):
    """A non-dangerous parse/codec/password failure; the raw file remains usable."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _nested_safety_error(error: BaseException) -> ArchiveSafetyError | None:
    """Recover a writer refusal wrapped by a third-party decoder."""

    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, ArchiveSafetyError):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


@dataclass(frozen=True, slots=True)
class ArchivePolicy:
    max_output_bytes: int = MAX_ARCHIVE_OUTPUT_BYTES
    max_members: int = MAX_ARCHIVE_MEMBERS
    max_nested_depth: int = MAX_NESTED_ARCHIVE_DEPTH
    max_member_depth: int = 32
    max_path_bytes: int = 4_096
    max_component_bytes: int = 255
    max_compression_ratio: int = MAX_ARCHIVE_COMPRESSION_RATIO
    compression_ratio_floor_bytes: int = 16 * 1024 * 1024
    max_seconds: float = MAX_ARCHIVE_SECONDS
    min_free_bytes: int = MIN_ARCHIVE_FREE_BYTES
    max_memory_bytes: int = MAX_ARCHIVE_MEMORY_BYTES

    def __post_init__(self) -> None:
        positive_values = (
            self.max_member_depth,
            self.max_path_bytes,
            self.max_component_bytes,
            self.compression_ratio_floor_bytes,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in positive_values):
            raise ValueError("archive limits must be positive integers")
        nonnegative_values = (
            self.max_output_bytes,
            self.max_members,
            self.max_compression_ratio,
            self.min_free_bytes,
            self.max_memory_bytes,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > 2**63 - 1
            for value in nonnegative_values
        ):
            raise ValueError("archive size, member, and free-space limits must be non-negative integers")
        caps = (
            (self.max_member_depth, 32),
            (self.max_path_bytes, 4_096),
            (self.max_component_bytes, 255),
            (self.compression_ratio_floor_bytes, 16 * 1024 * 1024),
        )
        if any(value > maximum for value, maximum in caps):
            raise ValueError("archive limits cannot exceed the server safety ceiling")
        if not isinstance(self.max_nested_depth, int) or isinstance(self.max_nested_depth, bool) or self.max_nested_depth < 0:
            raise ValueError("archive nesting depth must be a non-negative integer")
        if self.max_nested_depth > MAX_NESTED_ARCHIVE_DEPTH:
            raise ValueError("archive nesting depth cannot exceed the server safety ceiling")
        if (
            not isinstance(self.max_seconds, (int, float))
            or isinstance(self.max_seconds, bool)
            or not math.isfinite(self.max_seconds)
            or self.max_seconds < 0
        ):
            raise ValueError("archive time limit must be non-negative")


@dataclass(frozen=True, slots=True)
class ArchiveInput:
    relative_path: Path
    source_path: Path


@dataclass(frozen=True, slots=True)
class ArchiveAction:
    source: str
    kind: str
    depth: int
    status: str
    destination: str | None = None
    members: int = 0
    bytes_written: int = 0
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ArchiveReport:
    actions: tuple[ArchiveAction, ...] = ()

    @property
    def expanded(self) -> tuple[ArchiveAction, ...]:
        return tuple(action for action in self.actions if action.status == "expanded")

    def brief_lines(self) -> list[str]:
        if not self.actions:
            return []
        lines = [
            "## Prepared attachments",
            "",
            "Raw uploads remain unchanged and read-only under `attachments/`.",
            "Safely expanded copies are disposable job data under `extracted/`.",
            "",
        ]
        for action in self.actions:
            source = _markdown_code(action.source)
            if action.status == "expanded" and action.destination:
                destination = _markdown_code(action.destination)
                lines.append(
                    f"- `{source}` -> `{destination}` ({action.kind}, "
                    f"{action.members} files/directories, {action.bytes_written} bytes)"
                )
            else:
                reason = action.reason or "not_extracted"
                lines.append(f"- `{source}` was not expanded ({reason}); use the raw file if needed.")
        return lines


def _action_payload(action: ArchiveAction) -> dict[str, object]:
    return {
        "source": action.source,
        "kind": action.kind,
        "depth": action.depth,
        "status": action.status,
        "destination": action.destination,
        "members": action.members,
        "bytes_written": action.bytes_written,
        "reason": action.reason,
    }


def _report_from_payload(payload: object, policy: ArchivePolicy, *, input_count: int) -> ArchiveReport:
    if not isinstance(payload, list) or (
        policy.max_members and len(payload) > policy.max_members + input_count
    ):
        raise ValueError("invalid archive action count")
    actions: list[ArchiveAction] = []
    total_members = 0
    total_bytes = 0
    for raw in payload:
        if not isinstance(raw, dict) or set(raw) != {
            "source",
            "kind",
            "depth",
            "status",
            "destination",
            "members",
            "bytes_written",
            "reason",
        }:
            raise ValueError("invalid archive action")
        source = raw["source"]
        kind = raw["kind"]
        depth = raw["depth"]
        status = raw["status"]
        destination = raw["destination"]
        members = raw["members"]
        bytes_written = raw["bytes_written"]
        reason = raw["reason"]
        if (
            not isinstance(source, str)
            or not source
            or len(source.encode("utf-8")) > policy.max_path_bytes
            or _CONTROL.search(source)
            or kind not in {"zip", "tar", "7z", "gz", "bz2", "xz"}
            or isinstance(depth, bool)
            or not isinstance(depth, int)
            or depth < 0
            or depth > policy.max_nested_depth + 1
            or status not in {"expanded", "skipped"}
            or isinstance(members, bool)
            or not isinstance(members, int)
            or members < 0
            or isinstance(bytes_written, bool)
            or not isinstance(bytes_written, int)
            or bytes_written < 0
        ):
            raise ValueError("invalid archive action values")
        _member_parts(source, policy)
        if status == "expanded":
            if not isinstance(destination, str) or reason is not None:
                raise ValueError("invalid expanded archive action")
            destination_parts = _member_parts(destination, policy)
            if len(destination_parts) < 2 or destination_parts[0] != "extracted":
                raise ValueError("invalid archive destination")
        elif destination is not None or reason not in _SKIP_REASONS:
            raise ValueError("invalid skipped archive action")
        total_members += members
        total_bytes += bytes_written
        if (
            (policy.max_members and total_members > policy.max_members)
            or (policy.max_output_bytes and total_bytes > policy.max_output_bytes)
        ):
            raise ValueError("archive report exceeds policy")
        actions.append(
            ArchiveAction(
                source,
                kind,
                depth,
                status,
                destination,
                members,
                bytes_written,
                reason,
            )
        )
    return ArchiveReport(tuple(actions))


@dataclass(slots=True)
class _Budget:
    policy: ArchivePolicy
    space_root: Path
    started_at: float = field(default_factory=time.monotonic)
    written: int = 0
    members: int = 0

    def checkpoint(self) -> tuple[int, int]:
        return self.written, self.members

    def restore(self, checkpoint: tuple[int, int]) -> None:
        self.written, self.members = checkpoint

    def check_time(self) -> None:
        if self.policy.max_seconds and time.monotonic() - self.started_at > self.policy.max_seconds:
            raise ArchiveSafetyError(
                "archive_time_limit",
                "첨부 압축 해제가 안전 실행 시간을 초과해 작업을 중단했습니다.",
            )

    def register_members(self, count: int) -> None:
        self.check_time()
        if count < 0 or (
            self.policy.max_members and self.members + count > self.policy.max_members
        ):
            raise ArchiveSafetyError(
                "archive_member_limit",
                "첨부 압축파일의 항목 수가 안전 한도를 초과했습니다.",
            )
        self.members += count

    def check_declared_bytes(self, amount: int) -> None:
        if amount < 0 or (
            self.policy.max_output_bytes and self.written + amount > self.policy.max_output_bytes
        ):
            raise ArchiveSafetyError(
                "archive_expansion_limit",
                "첨부 압축 해제 크기가 작업공간 안전 한도를 초과했습니다.",
            )

    def check_ratio(self, amount: int, packed_size: int) -> None:
        if not self.policy.max_compression_ratio:
            return
        maximum = max(
            self.policy.compression_ratio_floor_bytes,
            packed_size * self.policy.max_compression_ratio,
        )
        if amount > maximum:
            raise ArchiveSafetyError(
                "archive_compression_ratio",
                "첨부 압축파일의 압축률이 안전 한도를 초과했습니다.",
            )

    def consume(self, amount: int, *, archive_start: int, packed_size: int) -> None:
        self.check_time()
        if amount < 0 or (
            self.policy.max_output_bytes and self.written + amount > self.policy.max_output_bytes
        ):
            raise ArchiveSafetyError(
                "archive_expansion_limit",
                "첨부 압축 해제 크기가 작업공간 안전 한도를 초과했습니다.",
            )
        expanded = self.written + amount - archive_start
        self.check_ratio(expanded, packed_size)
        try:
            free = shutil.disk_usage(self.space_root).free
        except OSError as exc:
            raise ArchiveSafetyError(
                "archive_scratch_full",
                "압축 해제 작업공간의 여유 공간을 확인하지 못했습니다.",
            ) from exc
        if free - amount < self.policy.min_free_bytes:
            raise ArchiveSafetyError(
                "archive_scratch_full",
                "압축 해제 작업공간의 여유 공간이 부족합니다.",
            )
        self.written += amount


@dataclass(frozen=True, slots=True)
class _Entry:
    name: str
    parts: tuple[str, ...]
    is_dir: bool
    size: int
    source: object


def _markdown_code(value: str) -> str:
    return _CONTROL.sub(" ", value).replace("`", "'")[:4_096]


def _suffixes(path: Path) -> str:
    return "".join(path.suffixes).lower()


@contextmanager
def _open_regular(path: Path) -> Iterator[tuple[BinaryIO, int]]:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ArchiveSafetyError(
                "archive_source_changed",
                "첨부 압축파일 원본의 안전성을 다시 확인할 수 없습니다.",
            )
        stream = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        with stream:
            yield stream, details.st_size
    except ArchiveSafetyError:
        raise
    except OSError as exc:
        raise _ArchiveFormatError("unreadable_archive") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def archive_kind(path: Path) -> str | None:
    suffix = _suffixes(path)
    if path.suffix.lower() in ZIP_EXTENSIONS:
        return "zip"
    if any(suffix.endswith(extension) for extension in TAR_EXTENSIONS):
        return "tar"
    if path.suffix.lower() in SEVEN_ZIP_EXTENSIONS:
        return "7z"
    if path.suffix.lower() in SINGLE_EXTENSIONS:
        return path.suffix.lower()[1:]
    try:
        with _open_regular(path) as (stream, _):
            head = stream.read(512)
    except _ArchiveFormatError:
        return None
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gz"
    if head.startswith(b"BZh"):
        return "bz2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def _member_parts(name: object, policy: ArchivePolicy) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or _CONTROL.search(name):
        raise ArchiveSafetyError("unsafe_archive_path", "첨부 압축파일에 안전하지 않은 경로가 있습니다.")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//") or _DRIVE.match(normalized):
        raise ArchiveSafetyError("unsafe_archive_path", "첨부 압축파일에 안전하지 않은 경로가 있습니다.")
    raw_parts = PurePosixPath(normalized).parts
    parts: list[str] = []
    for part in raw_parts:
        if part in ("", "."):
            continue
        if (
            part == ".."
            or ":" in part
            or part.endswith((" ", "."))
            or _WINDOWS_DEVICE.fullmatch(part)
            or len(os.fsencode(part)) > policy.max_component_bytes
        ):
            raise ArchiveSafetyError("unsafe_archive_path", "첨부 압축파일에 안전하지 않은 경로가 있습니다.")
        parts.append(part)
    if not parts or len(parts) > policy.max_member_depth:
        raise ArchiveSafetyError("unsafe_archive_path", "첨부 압축파일에 안전하지 않은 경로가 있습니다.")
    if len("/".join(parts).encode("utf-8")) > policy.max_path_bytes:
        raise ArchiveSafetyError("unsafe_archive_path", "첨부 압축파일에 안전하지 않은 경로가 있습니다.")
    return tuple(parts)


def _collision_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


def _validate_entries(entries: list[_Entry], budget: _Budget, packed_size: int) -> None:
    kinds: dict[tuple[str, ...], bool] = {}
    materialized: set[tuple[str, ...]] = set()
    declared = 0
    for entry in entries:
        key = _collision_key(entry.parts)
        if key in kinds:
            raise ArchiveSafetyError(
                "unsafe_archive_collision",
                "첨부 압축파일에 중복되거나 충돌하는 경로가 있습니다.",
            )
        if any(kinds.get(key[:index]) is False for index in range(1, len(key))):
            raise ArchiveSafetyError(
                "unsafe_archive_collision",
                "첨부 압축파일에 중복되거나 충돌하는 경로가 있습니다.",
            )
        if not entry.is_dir and any(len(other) > len(key) and other[: len(key)] == key for other in kinds):
            raise ArchiveSafetyError(
                "unsafe_archive_collision",
                "첨부 압축파일에 중복되거나 충돌하는 경로가 있습니다.",
            )
        kinds[key] = entry.is_dir
        for length in range(1, len(key) + 1):
            materialized.add(key[:length])
        if not entry.is_dir:
            if entry.size < 0:
                raise ArchiveSafetyError(
                    "invalid_archive_metadata",
                    "첨부 압축파일의 크기 정보를 안전하게 확인할 수 없습니다.",
                )
            declared += entry.size
    # Count implicit parent directories too.  Otherwise a few thousand deeply
    # nested file entries could consume far more than the advertised member
    # limit in tmpfs inodes.
    budget.register_members(len(materialized))
    budget.check_declared_bytes(declared)
    budget.check_ratio(declared, packed_size)


def _ensure_directory(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for part in parts:
        current = current / part
        try:
            details = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ArchiveSafetyError(
                "unsafe_archive_collision",
                "첨부 압축파일에 중복되거나 충돌하는 경로가 있습니다.",
            )
    return current


@contextmanager
def _new_output(root: Path, parts: tuple[str, ...]) -> Iterator[BinaryIO]:
    parent = _ensure_directory(root, parts[:-1])
    target = parent / parts[-1]
    descriptor = None
    try:
        descriptor = os.open(
            target,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        output = os.fdopen(descriptor, "w+b", closefd=True)
        descriptor = None
        with output:
            yield output
    except FileExistsError as exc:
        raise ArchiveSafetyError(
            "unsafe_archive_collision",
            "첨부 압축파일에 중복되거나 충돌하는 경로가 있습니다.",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


@contextmanager
def _existing_output(path: Path) -> Iterator[BinaryIO]:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ArchiveSafetyError(
                "unsafe_archive_entry",
                "압축 해제 결과에 링크 또는 특수 파일이 있어 작업을 중단했습니다.",
            )
        stream = os.fdopen(descriptor, "r+b", closefd=True)
        descriptor = None
        with stream:
            yield stream
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _copy_stream(
    source: BinaryIO,
    output: BinaryIO,
    *,
    expected: int,
    budget: _Budget,
    archive_start: int,
    packed_size: int,
) -> int:
    written = 0
    while True:
        budget.check_time()
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        if written + len(chunk) > expected:
            raise ArchiveSafetyError(
                "invalid_archive_metadata",
                "첨부 압축파일의 실제 크기가 기록된 안전 범위를 벗어났습니다.",
            )
        budget.consume(len(chunk), archive_start=archive_start, packed_size=packed_size)
        output.write(chunk)
        written += len(chunk)
    if written != expected:
        raise _ArchiveFormatError("truncated_archive")
    return written


def _zip_entries(archive: zipfile.ZipFile, policy: ArchivePolicy) -> list[_Entry]:
    entries: list[_Entry] = []
    for info in archive.infolist():
        parts = _member_parts(info.filename, policy)
        mode = (info.external_attr >> 16) & 0o177777
        # The upper external-attribute word contains a POSIX mode only for
        # Unix-created ZIP entries.  DOS/Windows archives use different bits;
        # interpreting those as st_mode rejects ordinary explicit directory
        # entries.  We never ask zipfile to materialize a link, so non-Unix
        # entries are still safely written as a regular file or directory.
        kind = stat.S_IFMT(mode) if info.create_system == 3 else 0
        # Some DOS tools mark an explicit directory only with the low-word
        # directory attribute and omit the conventional trailing slash.
        dos_directory = (
            info.create_system in {0, 10}
            and bool(info.external_attr & 0x10)
            and info.file_size == 0
        )
        is_dir = info.is_dir() or dos_directory
        if info.flag_bits & 0x1:
            raise _ArchiveFormatError("encrypted_archive")
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (
            kind != 0 and (kind == stat.S_IFDIR) != is_dir
        ):
            raise ArchiveSafetyError(
                "unsafe_archive_entry",
                "첨부 압축파일에 링크 또는 특수 파일이 있어 해제를 거부했습니다.",
            )
        entries.append(_Entry(info.filename, parts, is_dir, 0 if is_dir else info.file_size, info))
    return entries


def _extract_zip(stream: BinaryIO, packed_size: int, destination: Path, budget: _Budget) -> tuple[int, int]:
    start_written, start_members = budget.checkpoint()
    try:
        with zipfile.ZipFile(stream) as archive:
            entries = _zip_entries(archive, budget.policy)
            _validate_entries(entries, budget, packed_size)
            for entry in entries:
                if entry.is_dir:
                    _ensure_directory(destination, entry.parts)
                    continue
                with archive.open(entry.source) as source, _new_output(destination, entry.parts) as output:
                    _copy_stream(
                        source,
                        output,
                        expected=entry.size,
                        budget=budget,
                        archive_start=start_written,
                        packed_size=packed_size,
                    )
    except ArchiveSafetyError:
        raise
    except _ArchiveFormatError:
        raise
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, OSError) as exc:
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            raise ArchiveSafetyError(
                "archive_scratch_full",
                "첨부 압축 해제 중 격리 작업공간의 여유 공간이 부족해졌습니다.",
            ) from exc
        raise _ArchiveFormatError("invalid_or_unsupported_archive") from exc
    return budget.written - start_written, budget.members - start_members


def _tar_entries(archive: tarfile.TarFile, policy: ArchivePolicy) -> list[_Entry]:
    entries: list[_Entry] = []
    for member in archive:
        if policy.max_members and len(entries) >= policy.max_members + 1:
            raise ArchiveSafetyError(
                "archive_member_limit",
                "첨부 압축파일의 항목 수가 안전 한도를 초과했습니다.",
            )
        # GNU tar commonly records the archive root as a directory named
        # ``.``.  It materializes no path and is safe to ignore.  A non-directory
        # entry with the same name must still be refused by _member_parts.
        if member.isdir() and member.name in {".", "./"}:
            continue
        parts = _member_parts(member.name, policy)
        if member.issym() or member.islnk() or member.isdev() or member.isfifo() or not (member.isdir() or member.isfile()):
            raise ArchiveSafetyError(
                "unsafe_archive_entry",
                "첨부 압축파일에 링크 또는 특수 파일이 있어 해제를 거부했습니다.",
            )
        entries.append(_Entry(member.name, parts, member.isdir(), 0 if member.isdir() else member.size, member))
    return entries


def _extract_tar(stream: BinaryIO, packed_size: int, destination: Path, budget: _Budget) -> tuple[int, int]:
    start_written, start_members = budget.checkpoint()
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as archive:
            entries = _tar_entries(archive, budget.policy)
            _validate_entries(entries, budget, packed_size)
            for entry in entries:
                if entry.is_dir:
                    _ensure_directory(destination, entry.parts)
                    continue
                source = archive.extractfile(entry.source)
                if source is None:
                    raise _ArchiveFormatError("truncated_archive")
                with source, _new_output(destination, entry.parts) as output:
                    _copy_stream(
                        source,
                        output,
                        expected=entry.size,
                        budget=budget,
                        archive_start=start_written,
                        packed_size=packed_size,
                    )
    except ArchiveSafetyError:
        raise
    except _ArchiveFormatError:
        raise
    except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as exc:
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            raise ArchiveSafetyError(
                "archive_scratch_full",
                "첨부 압축 해제 중 격리 작업공간의 여유 공간이 부족해졌습니다.",
            ) from exc
        raise _ArchiveFormatError("invalid_or_unsupported_archive") from exc
    return budget.written - start_written, budget.members - start_members


def _extract_single(
    stream: BinaryIO,
    packed_size: int,
    destination: Path,
    budget: _Budget,
    *,
    kind: str,
    archive_name: str,
) -> tuple[int, int]:
    start_written, start_members = budget.checkpoint()
    output_name = Path(archive_name).stem or "payload"
    parts = _member_parts(output_name, budget.policy)
    budget.register_members(1)
    opener = {
        "gz": lambda source: gzip.GzipFile(fileobj=source, mode="rb"),
        "bz2": lambda source: bz2.BZ2File(source, mode="rb"),
        "xz": lambda source: lzma.LZMAFile(source, mode="rb"),
    }[kind]
    try:
        with opener(stream) as source, _new_output(destination, parts) as output:
            written = 0
            while True:
                budget.check_time()
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                budget.consume(len(chunk), archive_start=start_written, packed_size=packed_size)
                output.write(chunk)
                written += len(chunk)
    except ArchiveSafetyError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError) as exc:
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            raise ArchiveSafetyError(
                "archive_scratch_full",
                "첨부 압축 해제 중 격리 작업공간의 여유 공간이 부족해졌습니다.",
            ) from exc
        raise _ArchiveFormatError("invalid_or_unsupported_archive") from exc
    return budget.written - start_written, budget.members - start_members


def _seven_zip_entries(archive, policy: ArchivePolicy) -> list[_Entry]:
    entries: list[_Entry] = []
    for member in archive.files:
        parts = _member_parts(member.filename, policy)
        file_type = member.st_fmt
        is_dir = bool(member.is_directory or file_type == stat.S_IFDIR)
        unsafe_mode = file_type is not None and not (
            (is_dir and file_type == stat.S_IFDIR)
            or (not is_dir and file_type in (0, stat.S_IFREG))
        )
        if member.is_symlink or member.is_junction or member.is_socket or unsafe_mode:
            raise ArchiveSafetyError(
                "unsafe_archive_entry",
                "첨부 압축파일에 링크 또는 특수 파일이 있어 해제를 거부했습니다.",
            )
        size = member.uncompressed
        if not isinstance(size, int) or isinstance(size, bool):
            raise ArchiveSafetyError(
                "invalid_archive_metadata",
                "첨부 압축파일의 크기 정보를 안전하게 확인할 수 없습니다.",
            )
        entries.append(_Entry(member.filename, parts, is_dir, 0 if is_dir else size, member))
    return entries


def _extract_7z(stream: BinaryIO, packed_size: int, destination: Path, budget: _Budget) -> tuple[int, int]:
    try:
        import py7zr
        from py7zr.io import Py7zIO, WriterFactory
    except ImportError as exc:  # pragma: no cover - pinned runtime dependency
        raise _ArchiveFormatError("safe_7z_extractor_unavailable") from exc

    start_written, start_members = budget.checkpoint()

    class BoundedFile(Py7zIO):
        def __init__(self, target: Path, expected: int):
            self.target = target
            self.expected = expected
            self.position = 0
            self.length = 0
            self.closed = False
            with _new_output(destination, target.relative_to(destination).parts):
                pass

        def write(self, value) -> int:
            if self.closed:
                raise ValueError("archive output is closed")
            payload = bytes(value)
            end = self.position + len(payload)
            if end > self.expected:
                raise ArchiveSafetyError(
                    "invalid_archive_metadata",
                    "첨부 압축파일의 실제 크기가 기록된 안전 범위를 벗어났습니다.",
                )
            growth = max(0, end - self.length)
            if growth:
                budget.consume(growth, archive_start=start_written, packed_size=packed_size)
            with _existing_output(self.target) as stream:
                stream.seek(self.position)
                written = stream.write(payload)
            self.position += written
            self.length = max(self.length, self.position)
            return written

        def read(self, size=None) -> bytes:
            if self.closed:
                raise ValueError("archive output is closed")
            with _existing_output(self.target) as stream:
                stream.seek(self.position)
                payload = stream.read(-1 if size is None else size)
            self.position += len(payload)
            return payload

        def seek(self, offset: int, whence: int = 0) -> int:
            if self.closed:
                raise ValueError("archive output is closed")
            if whence == os.SEEK_SET:
                position = offset
            elif whence == os.SEEK_CUR:
                position = self.position + offset
            elif whence == os.SEEK_END:
                position = self.length + offset
            else:
                raise ValueError("invalid archive seek mode")
            if position < 0 or position > self.expected:
                raise ArchiveSafetyError(
                    "invalid_archive_metadata",
                    "첨부 압축파일의 실제 크기가 기록된 안전 범위를 벗어났습니다.",
                )
            self.position = position
            return position

        def flush(self) -> None:
            return None

        def size(self) -> int:
            return self.length

        def finish(self) -> None:
            self._close()
            if self.length != self.expected:
                raise _ArchiveFormatError("truncated_archive")

        def abort(self) -> None:
            self._close()

        def _close(self) -> None:
            self.closed = True

    class Factory(WriterFactory):
        def __init__(self, expected: dict[tuple[str, ...], int]):
            self.expected = expected
            self.products: list[BoundedFile] = []

        def create(self, filename: str) -> Py7zIO:
            candidate = Path(filename)
            try:
                relative = candidate.relative_to(destination) if candidate.is_absolute() else candidate
            except ValueError as exc:
                raise ArchiveSafetyError(
                    "unsafe_archive_path",
                    "첨부 압축파일에 안전하지 않은 경로가 있습니다.",
                ) from exc
            parts = _member_parts(relative.as_posix(), budget.policy)
            key = _collision_key(parts)
            if key not in self.expected:
                raise ArchiveSafetyError(
                    "unsafe_archive_path",
                    "첨부 압축파일에 안전하지 않은 경로가 있습니다.",
                )
            product = BoundedFile(destination.joinpath(*parts), self.expected.pop(key))
            self.products.append(product)
            return product

        def finish(self) -> None:
            failure = None
            try:
                for product in self.products:
                    try:
                        product.finish()
                    except Exception as exc:
                        failure = failure or exc
            finally:
                self.products.clear()
            if failure:
                raise failure

        def abort(self) -> None:
            for product in self.products:
                try:
                    product.abort()
                except Exception:
                    pass
            self.products.clear()

    factory = None
    try:
        with py7zr.SevenZipFile(stream, mode="r") as archive:
            if archive.needs_password():
                raise _ArchiveFormatError("encrypted_archive")
            entries = _seven_zip_entries(archive, budget.policy)
            _validate_entries(entries, budget, packed_size)
            for entry in entries:
                if entry.is_dir:
                    _ensure_directory(destination, entry.parts)
            expected = {
                _collision_key(entry.parts): entry.size
                for entry in entries
                if not entry.is_dir
            }
            factory = Factory(expected)
            archive.extractall(path=destination, factory=factory)
            factory.finish()
            for entry in entries:
                if entry.is_dir:
                    continue
                target = destination.joinpath(*entry.parts)
                if not target.exists() and entry.size == 0:
                    with _new_output(destination, entry.parts):
                        pass
                elif not target.is_file() or target.stat().st_size != entry.size:
                    raise _ArchiveFormatError("truncated_archive")
    except ArchiveSafetyError:
        if factory:
            factory.abort()
        raise
    except _ArchiveFormatError:
        if factory:
            factory.abort()
        raise
    except Exception as exc:
        if factory:
            factory.abort()
        safety_error = _nested_safety_error(exc)
        if safety_error is not None:
            raise safety_error from exc
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            raise ArchiveSafetyError(
                "archive_scratch_full",
                "첨부 압축 해제 중 격리 작업공간의 여유 공간이 부족해졌습니다.",
            ) from exc
        raise _ArchiveFormatError("invalid_or_unsupported_archive") from exc
    return budget.written - start_written, budget.members - start_members


def _extract_one(
    source: Path,
    kind: str,
    destination: Path,
    budget: _Budget,
) -> tuple[int, int]:
    with _open_regular(source) as (stream, packed_size):
        if kind == "zip":
            return _extract_zip(stream, packed_size, destination, budget)
        if kind == "tar":
            return _extract_tar(stream, packed_size, destination, budget)
        if kind == "7z":
            return _extract_7z(stream, packed_size, destination, budget)
        if kind in {"gz", "bz2", "xz"}:
            return _extract_single(
                stream,
                packed_size,
                destination,
                budget,
                kind=kind,
                archive_name=source.name,
            )
    raise _ArchiveFormatError("unsupported_archive")


def _safe_remove(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _atomic_extract(source: Path, kind: str, destination: Path, budget: _Budget) -> tuple[int, int]:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".archive-stage-", dir=destination.parent))
    checkpoint = budget.checkpoint()
    try:
        result = _extract_one(source, kind, staging, budget)
        if destination.exists() or destination.is_symlink():
            raise _ArchiveFormatError("destination_collision")
        os.replace(staging, destination)
        return result
    except Exception:
        budget.restore(checkpoint)
        _safe_remove(staging)
        raise


def _nested_archives(root: Path) -> list[tuple[Path, str]]:
    result: list[tuple[Path, str]] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            details = (current_path / name).lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
                raise ArchiveSafetyError(
                    "unsafe_archive_entry",
                    "압축 해제 결과에 링크 또는 특수 파일이 있어 작업을 중단했습니다.",
                )
        for name in filenames:
            path = current_path / name
            details = path.lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise ArchiveSafetyError(
                    "unsafe_archive_entry",
                    "압축 해제 결과에 링크 또는 특수 파일이 있어 작업을 중단했습니다.",
                )
            kind = archive_kind(path)
            if kind:
                result.append((path, kind))
    return sorted(result, key=lambda item: item[0].as_posix())


def _extract_attachment_archives_direct(
    workdir: Path,
    inputs: Iterable[ArchiveInput],
    *,
    policy: ArchivePolicy | None = None,
) -> ArchiveReport:
    """Expand detected inputs and up to three nested layers inside ``workdir``.

    Format/password failures are recorded in the read-only challenge brief and
    leave the raw attachment available.  Boundary violations raise
    :class:`ArchiveSafetyError` so the worker can publish a clear safe refusal.
    """

    workdir = Path(workdir).resolve()
    policy = policy or ArchivePolicy()
    budget = _Budget(policy, workdir)
    actions: list[ArchiveAction] = []
    queue: list[tuple[Path, str, int, str, Path]] = []
    extracted_root = workdir / "extracted"

    for item in sorted(inputs, key=lambda value: value.relative_path.as_posix()):
        kind = archive_kind(item.source_path)
        if not kind:
            continue
        stem = item.relative_path.stem or "archive"
        safe_stem = _member_parts(stem, policy)
        if len(safe_stem) != 1:
            raise ArchiveSafetyError(
                "unsafe_archive_path",
                "첨부 압축파일 이름을 안전하게 작업공간에 배치할 수 없습니다.",
            )
        destination = extracted_root / f"{safe_stem[0]}_extracted"
        queue.append((item.source_path, kind, 0, item.relative_path.as_posix(), destination))

    while queue:
        source, kind, depth, display_source, destination = queue.pop(0)
        if destination.exists() or destination.is_symlink():
            actions.append(ArchiveAction(display_source, kind, depth, "skipped", reason="destination_collision"))
            continue
        try:
            bytes_written, members = _atomic_extract(source, kind, destination, budget)
        except ArchiveSafetyError as exc:
            if exc.code not in _RECOVERABLE_ARCHIVE_CODES:
                raise
            actions.append(ArchiveAction(display_source, kind, depth, "skipped", reason=exc.code))
            continue
        except _ArchiveFormatError as exc:
            actions.append(ArchiveAction(display_source, kind, depth, "skipped", reason=exc.reason))
            continue
        relative_destination = destination.relative_to(workdir).as_posix()
        actions.append(
            ArchiveAction(
                display_source,
                kind,
                depth,
                "expanded",
                destination=relative_destination,
                members=members,
                bytes_written=bytes_written,
            )
        )
        nested = _nested_archives(destination)
        for nested_source, nested_kind in nested:
            nested_display = nested_source.relative_to(workdir).as_posix()
            nested_destination = nested_source.parent / f"{nested_source.stem}_extracted"
            if depth >= policy.max_nested_depth:
                actions.append(
                    ArchiveAction(
                        nested_display,
                        nested_kind,
                        depth + 1,
                        "skipped",
                        reason="nested_depth_limit",
                    )
                )
                continue
            queue.append((nested_source, nested_kind, depth + 1, nested_display, nested_destination))

    return ArchiveReport(tuple(actions))


def _policy_payload(policy: ArchivePolicy) -> dict[str, object]:
    return {field.name: getattr(policy, field.name) for field in dataclasses.fields(ArchivePolicy)}


def _fallback_report(candidates: list[tuple[ArchiveInput, str]], reason: str) -> ArchiveReport:
    return ArchiveReport(
        tuple(
            ArchiveAction(item.relative_path.as_posix(), kind, 0, "skipped", reason=reason)
            for item, kind in candidates
        )
    )


def _clear_untrusted_expansions(workdir: Path) -> None:
    root = workdir / "extracted"
    try:
        details = root.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(details.st_mode):
        root.unlink()
    elif stat.S_ISDIR(details.st_mode):
        shutil.rmtree(root)
    else:
        root.unlink()


def _read_child_result(path: Path) -> object:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size <= 0
            or details.st_size > MAX_ARCHIVE_CHILD_RESULT_BYTES
        ):
            raise ValueError("invalid archive child result")
        chunks: list[bytes] = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("truncated archive child result")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("oversized archive child result")
        return json.loads(b"".join(chunks))
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _discard_child_result(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _archive_child_command(*, require_apparmor: bool) -> list[str] | None:
    if require_apparmor:
        try:
            details = ARCHIVE_LAUNCHER.lstat()
        except OSError:
            return None
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
            or not details.st_mode & 0o111
        ):
            return None
        executable = str(ARCHIVE_LAUNCHER)
    else:
        executable = sys.executable
    return [executable, str(Path(__file__).resolve()), "--archive-child"]


def _terminate_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _validate_published_tree(workdir: Path, report: ArchiveReport, policy: ArchivePolicy) -> None:
    expanded = report.expanded
    root = workdir / "extracted"
    if not root.exists() and not root.is_symlink():
        if expanded:
            raise ValueError("missing archive output root")
        return
    details = root.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise ValueError("invalid archive output root")
    root_resolved = root.resolve()
    allowed = {action.destination for action in expanded}
    allowed_roots = [Path(destination).relative_to("extracted") for destination in allowed if destination]
    expected_count = sum(action.members for action in expanded) + len(expanded)
    expected_size = sum(action.bytes_written for action in expanded)
    count = 0
    size = 0

    def refuse_walk_error(error: OSError) -> None:
        raise error

    for current, directories, filenames in os.walk(
        root,
        followlinks=False,
        onerror=refuse_walk_error,
    ):
        current_path = Path(current)
        if not current_path.resolve().is_relative_to(root_resolved):
            raise ValueError("archive output escaped root")
        for name in [*directories, *filenames]:
            candidate = current_path / name
            candidate_details = candidate.lstat()
            relative = candidate.relative_to(root)
            if not any(relative == allowed_root or relative.is_relative_to(allowed_root) for allowed_root in allowed_roots):
                raise ValueError("unreported archive output")
            count += 1
            if policy.max_members and count > policy.max_members + len(expanded):
                raise ValueError("archive output member count exceeded")
            if stat.S_ISLNK(candidate_details.st_mode):
                raise ValueError("archive output link")
            if stat.S_ISREG(candidate_details.st_mode):
                if candidate_details.st_nlink != 1:
                    raise ValueError("archive output hard link")
                size += candidate_details.st_size
                if policy.max_output_bytes and size > policy.max_output_bytes:
                    raise ValueError("archive output size exceeded")
            elif not stat.S_ISDIR(candidate_details.st_mode):
                raise ValueError("archive output special file")
    if count != expected_count or size != expected_size:
        raise ValueError("archive output does not match child report")
    for destination in allowed:
        if destination is None:
            raise ValueError("missing archive output destination")
        candidate = workdir / destination
        if (
            not candidate.exists()
            or candidate.is_symlink()
            or not candidate.is_dir()
            or not candidate.resolve().is_relative_to(root_resolved)
        ):
            raise ValueError("missing archive output")


def extract_attachment_archives(
    workdir: Path,
    inputs: Iterable[ArchiveInput],
    *,
    policy: ArchivePolicy | None = None,
) -> ArchiveReport:
    """Expand archives in a disposable, separately isolated helper process."""

    workdir = Path(workdir).resolve()
    policy = policy or ArchivePolicy()
    materialized_inputs = tuple(inputs)
    candidates: list[tuple[ArchiveInput, str]] = []
    for item in sorted(materialized_inputs, key=lambda value: value.relative_path.as_posix()):
        kind = archive_kind(item.source_path)
        if kind:
            candidates.append((item, kind))
    if not candidates:
        return ArchiveReport()
    if policy.max_members and len(candidates) > policy.max_members:
        return _fallback_report(candidates[: policy.max_members], "input_limit")

    request = {
        "protocol": 1,
        "workdir": str(workdir.resolve()),
        "inputs": [
            {
                "relative_path": item.relative_path.as_posix(),
                "source_path": str(item.source_path.resolve()),
            }
            for item, _kind in candidates
        ],
        "policy": _policy_payload(policy),
    }
    request_bytes = json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(request_bytes) > MAX_ARCHIVE_CHILD_REQUEST_BYTES:
        return _fallback_report(candidates, "input_limit")

    require_apparmor = (
        os.name == "posix"
        and os.environ.get("CTF_SOLVER_EXTERNAL_SANDBOX", "").strip().lower() == "true"
    )
    command = _archive_child_command(require_apparmor=require_apparmor)
    if command is None:
        return _fallback_report(candidates, "extractor_isolation_unavailable")
    result_path = workdir / f".archive-result-{os.getpid()}-{secrets.token_hex(8)}"
    command.append(str(result_path))
    environment = {
        "HOME": str(workdir),
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin" if os.name == "posix" else os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "TMPDIR": str(workdir / "tmp"),
    }
    if require_apparmor:
        environment["CTF_ARCHIVE_REQUIRE_APPARMOR"] = "1"
    process = None
    popen_options: dict[str, object] = {
        "cwd": workdir,
        "env": environment,
        "stdin": subprocess.PIPE,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "posix":
        popen_options["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **popen_options)
        process.communicate(
            input=request_bytes,
            timeout=(
                policy.max_seconds + ARCHIVE_CHILD_WALL_GRACE_SECONDS
                if policy.max_seconds
                else None
            ),
        )
    except subprocess.TimeoutExpired:
        if process is not None:
            _terminate_child(process)
        _clear_untrusted_expansions(workdir)
        _discard_child_result(result_path)
        return _fallback_report(candidates, "extractor_timeout")
    except (OSError, ValueError):
        if process is not None:
            _terminate_child(process)
        _clear_untrusted_expansions(workdir)
        _discard_child_result(result_path)
        return _fallback_report(candidates, "extractor_isolation_unavailable")

    try:
        if process.returncode != 0:
            _clear_untrusted_expansions(workdir)
            return _fallback_report(candidates, "extractor_crashed")
        payload = _read_child_result(result_path)
        if not isinstance(payload, dict) or set(payload) != {"protocol", "status", "actions", "error"}:
            raise ValueError("invalid archive child envelope")
        if payload["protocol"] != 1 or payload["status"] not in {"ok", "unsafe"}:
            raise ValueError("invalid archive child status")
        if payload["status"] == "unsafe":
            error = payload["error"]
            if (
                payload["actions"] is not None
                or not isinstance(error, dict)
                or set(error) != {"code"}
                or error["code"] not in _FATAL_SAFETY_MESSAGES
            ):
                raise ValueError("invalid archive child safety error")
            _clear_untrusted_expansions(workdir)
            code = error["code"]
            raise ArchiveSafetyError(code, _FATAL_SAFETY_MESSAGES[code])
        if payload["error"] is not None:
            raise ValueError("unexpected archive child error")
        report = _report_from_payload(payload["actions"], policy, input_count=len(candidates))
        _validate_published_tree(workdir, report, policy)
        return report
    except ArchiveSafetyError:
        raise
    except (OSError, ValueError, json.JSONDecodeError, UnicodeError):
        _clear_untrusted_expansions(workdir)
        return _fallback_report(candidates, "extractor_result_invalid")
    finally:
        _discard_child_result(result_path)


def _lower_limit(resource_module, name: str, requested: int) -> None:
    limit = getattr(resource_module, name, None)
    if limit is None:
        raise RuntimeError("required resource limit is unavailable")
    _soft, hard = resource_module.getrlimit(limit)
    target = requested if hard == resource_module.RLIM_INFINITY else min(requested, hard)
    if target <= 0:
        raise RuntimeError("required resource limit is unusable")
    resource_module.setrlimit(limit, (target, target))


def _apply_child_resource_limits(policy: ArchivePolicy) -> None:
    if os.name != "posix":
        return
    import resource

    if policy.max_memory_bytes:
        _lower_limit(resource, "RLIMIT_AS", policy.max_memory_bytes)
    if policy.max_seconds:
        _lower_limit(resource, "RLIMIT_CPU", max(1, math.ceil(policy.max_seconds)))
    if policy.max_output_bytes:
        _lower_limit(
            resource,
            "RLIMIT_FSIZE",
            max(policy.max_output_bytes, MAX_ARCHIVE_CHILD_RESULT_BYTES),
        )
    _lower_limit(resource, "RLIMIT_NOFILE", MAX_ARCHIVE_CHILD_OPEN_FILES)
    _lower_limit(resource, "RLIMIT_NPROC", 1)
    if hasattr(resource, "RLIMIT_CORE"):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _child_isolation_ready() -> bool:
    if os.environ.get("CTF_ARCHIVE_REQUIRE_APPARMOR") != "1":
        return True
    try:
        current = Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
        label = current.removesuffix(" (enforce)")
        parts = label.split("//&")
        if (
            not current.endswith(" (enforce)")
            or len(parts) != 2
            or set(parts) != {"ctf-agent-solver", "ctf-agent-command"}
        ):
            return False
        try:
            os.listdir("/solver-exchange")
        except PermissionError:
            pass
        else:
            return False
        try:
            Path(f"/proc/{os.getppid()}/environ").read_bytes()
        except PermissionError:
            pass
        else:
            return False
    except (OSError, ValueError):
        return False
    return True


def _write_child_result(path: Path, payload: dict[str, object]) -> None:
    content = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if not content or len(content) > MAX_ARCHIVE_CHILD_RESULT_BYTES:
        raise ValueError("archive child result exceeds limit")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "archive child result write failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _archive_child_main(result_path: Path) -> int:
    try:
        if (
            result_path.parent.resolve() != Path.cwd().resolve()
            or not re.fullmatch(r"\.archive-result-[0-9]+-[0-9a-f]{16}", result_path.name)
            or result_path.exists()
            or result_path.is_symlink()
        ):
            return 64
    except OSError:
        return 64
    if not _child_isolation_ready():
        return 73
    request_bytes = sys.stdin.buffer.read(MAX_ARCHIVE_CHILD_REQUEST_BYTES + 1)
    if not request_bytes or len(request_bytes) > MAX_ARCHIVE_CHILD_REQUEST_BYTES:
        return 74
    try:
        request = json.loads(request_bytes)
        if not isinstance(request, dict) or set(request) != {"protocol", "workdir", "inputs", "policy"}:
            return 74
        if request["protocol"] != 1 or not isinstance(request["policy"], dict):
            return 74
        expected_policy_keys = {field.name for field in dataclasses.fields(ArchivePolicy)}
        if set(request["policy"]) != expected_policy_keys:
            return 74
        policy = ArchivePolicy(**request["policy"])
        _apply_child_resource_limits(policy)
        workdir = Path(request["workdir"])
        if not workdir.is_absolute() or workdir.resolve() != Path.cwd().resolve():
            return 74
        raw_inputs = request["inputs"]
        if not isinstance(raw_inputs, list) or (
            policy.max_members and len(raw_inputs) > policy.max_members
        ):
            return 74
        inputs: list[ArchiveInput] = []
        for raw in raw_inputs:
            if not isinstance(raw, dict) or set(raw) != {"relative_path", "source_path"}:
                return 74
            relative = raw["relative_path"]
            source = raw["source_path"]
            if not isinstance(relative, str) or not isinstance(source, str) or not Path(source).is_absolute():
                return 74
            _member_parts(relative, policy)
            inputs.append(ArchiveInput(Path(relative), Path(source)))
        report = _extract_attachment_archives_direct(workdir, inputs, policy=policy)
        payload: dict[str, object] = {
            "protocol": 1,
            "status": "ok",
            "actions": [_action_payload(action) for action in report.actions],
            "error": None,
        }
    except ArchiveSafetyError as exc:
        if exc.code not in _FATAL_SAFETY_MESSAGES:
            return 75
        payload = {
            "protocol": 1,
            "status": "unsafe",
            "actions": None,
            "error": {"code": exc.code},
        }
    except Exception:
        return 75
    try:
        _write_child_result(result_path, payload)
    except (OSError, ValueError):
        return 76
    return 0


__all__ = [
    "ArchiveAction",
    "ArchiveInput",
    "ArchivePolicy",
    "ArchiveReport",
    "ArchiveSafetyError",
    "MAX_ARCHIVE_MEMBERS",
    "MAX_ARCHIVE_OUTPUT_BYTES",
    "MAX_NESTED_ARCHIVE_DEPTH",
    "archive_kind",
    "extract_attachment_archives",
]


if __name__ == "__main__":  # pragma: no cover - exercised through the parent IPC
    if len(sys.argv) != 3 or sys.argv[1] != "--archive-child":
        raise SystemExit(64)
    raise SystemExit(_archive_child_main(Path(sys.argv[2])))
