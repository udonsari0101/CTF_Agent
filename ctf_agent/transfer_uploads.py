"""Owner-scoped, resumable upload staging for workspace ZIP64 bundles.

Only the authenticated owner can access an upload session. A ready bundle is
immutable; ``import_slot`` holds a cross-process lock until its caller has
finished importing and marks the session consumed on success.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import stat
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

from .db import Settings, connect
from .process_lock import ProcessFileLock


CHUNK_BYTES = 8 * 1024 * 1024
HASH_READ_BYTES = 1024 * 1024
MIN_FREE_BYTES = 5 * 1024**3
MAX_ACTIVE_PER_OWNER = 2
STALE_SECONDS = 7 * 24 * 3600
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class TransferUploadError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _directory(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        # Several web workers may initialize the manager at once.
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise TransferUploadError("unsafe_path", "Upload directory is not a directory.")


class TransferUploadManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = Path(settings.data_dir) / ".transfer_uploads"
        self.lock_root = Path(settings.config_dir) / ".locks" / "transfer_uploads"
        _directory(self.root)
        _directory(self.lock_root)
        with closing(connect(settings)) as db, db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS transfer_upload_sessions(
                   id TEXT PRIMARY KEY,
                   owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   size INTEGER NOT NULL,
                   offset INTEGER NOT NULL DEFAULT 0,
                   expected_sha256 TEXT,
                   sha256 TEXT,
                   status TEXT NOT NULL CHECK(status IN
                       ('uploading','ready','consumed','cancelled','expired')),
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL)"""
            )
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_transfer_upload_owner
                   ON transfer_upload_sessions(owner_user_id,status,updated_at)"""
            )

    @staticmethod
    def _identifier(value: str, label: str) -> str:
        if not isinstance(value, str) or not _HEX32.fullmatch(value):
            raise TransferUploadError("invalid_id", f"Invalid {label}.")
        return value

    def _stage(self, owner: str, upload_id: str, *, create_parent: bool = False) -> Path:
        self._identifier(owner, "owner ID")
        self._identifier(upload_id, "upload ID")
        parent = self.root / owner
        if create_parent:
            _directory(parent)
        else:
            try:
                if not stat.S_ISDIR(parent.lstat().st_mode):
                    raise TransferUploadError("unsafe_path", "Upload directory is invalid.")
            except FileNotFoundError as exc:
                raise TransferUploadError("missing_file", "Upload file is missing.") from exc
        return parent / f"{upload_id}.part"

    def _lock(self, upload_id: str) -> ProcessFileLock:
        self._identifier(upload_id, "upload ID")
        return ProcessFileLock(self.lock_root / f"{upload_id}.lock")

    @contextmanager
    def _exclusive(self, upload_id: str) -> Iterator[None]:
        lock = self._lock(upload_id)
        if not lock.try_acquire():
            raise TransferUploadError("busy", "Another upload operation is in progress.")
        try:
            yield
        finally:
            lock.release()

    @staticmethod
    def _row(db: sqlite3.Connection, owner: str, upload_id: str) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM transfer_upload_sessions WHERE id=? AND owner_user_id=?",
            (upload_id, owner),
        ).fetchone()
        if row is None:
            raise TransferUploadError("not_found", "Upload was not found for this user.")
        return row

    @staticmethod
    def _result(row: sqlite3.Row) -> dict:
        return {
            "upload_id": row["id"], "size": row["size"],
            "offset": row["offset"], "status": row["status"],
            "sha256": row["sha256"],
        }

    @property
    def free_floor(self) -> int:
        return max(MIN_FREE_BYTES, self.settings.storage_min_free_bytes)

    def create(self, owner_user_id: str, size: int,
               expected_sha256: str | None = None) -> dict:
        owner = self._identifier(owner_user_id, "owner ID")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > 2**63 - 1:
            raise TransferUploadError("invalid_size", "Bundle size is invalid.")
        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str) or not _HEX64.fullmatch(expected_sha256)
        ):
            raise TransferUploadError("invalid_digest", "Bundle SHA-256 is invalid.")
        upload_id = uuid.uuid4().hex
        stage = self._stage(owner, upload_id, create_parent=True)
        now = int(time.time())
        created = False
        try:
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if not db.execute(
                    "SELECT 1 FROM users WHERE id=? AND active=1", (owner,)
                ).fetchone():
                    raise TransferUploadError("owner_inactive", "Upload owner is inactive.")
                active = db.execute(
                    """SELECT COUNT(*) FROM transfer_upload_sessions
                       WHERE owner_user_id=? AND status IN ('uploading','ready')""",
                    (owner,),
                ).fetchone()[0]
                if active >= MAX_ACTIVE_PER_OWNER:
                    raise TransferUploadError("owner_limit", "Too many active bundle uploads.")
                reserved = db.execute(
                    """SELECT COALESCE(SUM(size-offset),0) FROM transfer_upload_sessions
                       WHERE status='uploading'"""
                ).fetchone()[0]
                free = shutil.disk_usage(self.root).free
                if free - reserved - size < self.free_floor:
                    raise TransferUploadError("low_space", "Insufficient free space for the bundle.")
                descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
                created = True
                db.execute(
                    """INSERT INTO transfer_upload_sessions(
                       id,owner_user_id,size,offset,expected_sha256,
                       sha256,status,created_at,updated_at)
                       VALUES(?,?,?,0,?,NULL,'uploading',?,?)""",
                    (upload_id, owner, size, expected_sha256, now, now),
                )
            return self.status(owner, upload_id)
        except BaseException:
            if created:
                stage.unlink(missing_ok=True)
            raise

    def status(self, owner_user_id: str, upload_id: str) -> dict:
        owner = self._identifier(owner_user_id, "owner ID")
        self._identifier(upload_id, "upload ID")
        with closing(connect(self.settings)) as db:
            return self._result(self._row(db, owner, upload_id))

    def _open_stage(self, owner: str, upload_id: str, *, writable: bool):
        stage = self._stage(owner, upload_id)
        try:
            if not stat.S_ISREG(stage.lstat().st_mode):
                raise TransferUploadError("unsafe_path", "Upload file is not regular.")
        except FileNotFoundError as exc:
            raise TransferUploadError("missing_file", "Upload file could not be read.") from exc
        flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(stage, flags)
        except OSError as exc:
            raise TransferUploadError("missing_file", "Upload file could not be read.") from exc
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise TransferUploadError("unsafe_path", "Upload file is not regular.")
        return os.fdopen(descriptor, "r+b" if writable else "rb")

    def append(self, owner_user_id: str, upload_id: str, offset: int,
               data: bytes, chunk_sha256: str | None = None) -> dict:
        owner = self._identifier(owner_user_id, "owner ID")
        self._identifier(upload_id, "upload ID")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise TransferUploadError("invalid_offset", "Chunk offset is invalid.")
        if not isinstance(data, bytes) or not 0 < len(data) <= CHUNK_BYTES:
            raise TransferUploadError("invalid_chunk", "Chunk must contain 1 byte to 8 MiB.")
        digest = hashlib.sha256(data).hexdigest()
        if chunk_sha256 is not None and (not isinstance(chunk_sha256, str)
                                         or not _HEX64.fullmatch(chunk_sha256)
                                         or chunk_sha256 != digest):
            raise TransferUploadError("invalid_digest", "Chunk SHA-256 does not match.")
        with self._exclusive(upload_id):
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                row = self._row(db, owner, upload_id)
                if row["status"] != "uploading":
                    raise TransferUploadError("wrong_state", "Upload is not accepting chunks.")
                if offset + len(data) > row["size"]:
                    raise TransferUploadError("invalid_offset", "Chunk exceeds bundle size.")
                with self._open_stage(owner, upload_id, writable=True) as stage:
                    actual = os.fstat(stage.fileno()).st_size
                    if actual < row["offset"]:
                        raise TransferUploadError("missing_data", "Upload file is shorter than recorded progress.")
                    if actual > row["offset"]:
                        # Recover a crash after fsync but before the DB commit.
                        stage.truncate(row["offset"])
                        stage.flush()
                        os.fsync(stage.fileno())
                    if offset < row["offset"]:
                        if offset + len(data) > row["offset"]:
                            raise TransferUploadError("invalid_offset", "Chunk overlaps uncommitted progress.")
                        stage.seek(offset)
                        if stage.read(len(data)) != data:
                            raise TransferUploadError("chunk_conflict", "Retried chunk differs from stored bytes.")
                        return self._result(row)
                    if offset != row["offset"]:
                        raise TransferUploadError("invalid_offset", "Chunk offset does not match upload progress.")
                    if shutil.disk_usage(self.root).free - len(data) < self.free_floor:
                        raise TransferUploadError("low_space", "Insufficient free space for the chunk.")
                    stage.seek(offset)
                    stage.write(data)
                    stage.flush()
                    os.fsync(stage.fileno())
                db.execute(
                    "UPDATE transfer_upload_sessions SET offset=?,updated_at=? WHERE id=?",
                    (offset + len(data), int(time.time()), upload_id),
                )
                return self._result(self._row(db, owner, upload_id))

    def finalize(self, owner_user_id: str, upload_id: str) -> dict:
        owner = self._identifier(owner_user_id, "owner ID")
        with self._exclusive(upload_id):
            # Hashing a multi-gigabyte bundle must not hold SQLite's writer lock.
            with closing(connect(self.settings)) as db:
                row = self._row(db, owner, upload_id)
                if row["status"] == "ready":
                    with self._open_stage(owner, upload_id, writable=False) as stage:
                        if os.fstat(stage.fileno()).st_size != row["size"]:
                            raise TransferUploadError("missing_data", "Ready bundle size has changed.")
                    return self._result(row)
                if row["status"] != "uploading" or row["offset"] != row["size"]:
                    raise TransferUploadError("incomplete", "Upload is not complete.")
                digest = hashlib.sha256()
                copied = 0
                with self._open_stage(owner, upload_id, writable=False) as stage:
                    before = os.fstat(stage.fileno())
                    while chunk := stage.read(HASH_READ_BYTES):
                        copied += len(chunk)
                        if copied > row["size"]:
                            raise TransferUploadError("changed_file", "Bundle changed during verification.")
                        digest.update(chunk)
                    after = os.fstat(stage.fileno())
                    if (copied != row["size"] or after.st_size != row["size"]
                            or (before.st_dev, before.st_ino, before.st_mtime_ns)
                            != (after.st_dev, after.st_ino, after.st_mtime_ns)):
                        raise TransferUploadError("changed_file", "Bundle changed during verification.")
                actual_digest = digest.hexdigest()
                if row["expected_sha256"] and row["expected_sha256"] != actual_digest:
                    raise TransferUploadError("invalid_digest", "Bundle SHA-256 does not match.")
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                current = self._row(db, owner, upload_id)
                if (current["status"] != "uploading" or current["offset"] != row["offset"]
                        or current["size"] != row["size"]):
                    raise TransferUploadError("changed_file", "Upload changed during verification.")
                db.execute(
                    """UPDATE transfer_upload_sessions SET status='ready',sha256=?,updated_at=?
                       WHERE id=?""",
                    (actual_digest, int(time.time()), upload_id),
                )
                return self._result(self._row(db, owner, upload_id))

    def ready_path(self, owner_user_id: str, upload_id: str) -> Path:
        owner = self._identifier(owner_user_id, "owner ID")
        with closing(connect(self.settings)) as db:
            row = self._row(db, owner, upload_id)
            if row["status"] != "ready":
                raise TransferUploadError("wrong_state", "Bundle is not ready for import.")
        stage = self._stage(owner, upload_id)
        try:
            if not stat.S_ISREG(stage.lstat().st_mode):
                raise TransferUploadError("missing_file", "Ready bundle file is missing.")
        except FileNotFoundError as exc:
            raise TransferUploadError("missing_file", "Ready bundle file is missing.") from exc
        return stage

    def _complete_locked(self, owner: str, upload_id: str) -> None:
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, owner, upload_id)
            if row["status"] == "consumed":
                return
            if row["status"] != "ready":
                raise TransferUploadError("wrong_state", "Bundle has not been finalized.")
            db.execute(
                "UPDATE transfer_upload_sessions SET status='consumed',updated_at=? WHERE id=?",
                (int(time.time()), upload_id),
            )
        stage = self._stage(owner, upload_id)
        if stage.is_file() and not stage.is_symlink():
            try:
                stage.unlink()
            except OSError:
                # Already consumed; stale cleanup can retry removal.
                pass

    @contextmanager
    def import_slot(self, owner_user_id: str, upload_id: str) -> Iterator[Path]:
        """Hold the upload lock across preview/import; consume on success only."""
        owner = self._identifier(owner_user_id, "owner ID")
        with self._exclusive(upload_id):
            path = self.ready_path(owner, upload_id)
            yield path
            self._complete_locked(owner, upload_id)

    def complete(self, owner_user_id: str, upload_id: str) -> None:
        owner = self._identifier(owner_user_id, "owner ID")
        with self._exclusive(upload_id):
            self._complete_locked(owner, upload_id)

    def cancel(self, owner_user_id: str, upload_id: str) -> None:
        owner = self._identifier(owner_user_id, "owner ID")
        with self._exclusive(upload_id):
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                row = self._row(db, owner, upload_id)
                if row["status"] == "consumed":
                    return
                db.execute(
                    "UPDATE transfer_upload_sessions SET status='cancelled',updated_at=? WHERE id=?",
                    (int(time.time()), upload_id),
                )
            stage = self._stage(owner, upload_id)
            if stage.is_file() and not stage.is_symlink():
                stage.unlink()

    def cleanup_stale(self, *, older_than_seconds: int = STALE_SECONDS) -> int:
        if older_than_seconds < 0:
            raise ValueError("Stale age must be nonnegative")
        threshold = int(time.time()) - older_than_seconds
        with closing(connect(self.settings)) as db:
            rows = db.execute(
                """SELECT id,owner_user_id FROM transfer_upload_sessions
                   WHERE status IN ('uploading','ready','cancelled','consumed')
                     AND updated_at < ?""",
                (threshold,),
            ).fetchall()
        cleaned = 0
        for row in rows:
            try:
                with self._exclusive(row["id"]):
                    with closing(connect(self.settings)) as db, db:
                        db.execute("BEGIN IMMEDIATE")
                        current = self._row(db, row["owner_user_id"], row["id"])
                        if current["updated_at"] >= threshold:
                            continue
                        db.execute(
                            "UPDATE transfer_upload_sessions SET status='expired' WHERE id=?",
                            (row["id"],),
                        )
                    try:
                        stage = self._stage(row["owner_user_id"], row["id"])
                    except TransferUploadError:
                        stage = None
                    if stage is not None and stage.is_file() and not stage.is_symlink():
                        stage.unlink()
                    cleaned += 1
            except TransferUploadError as exc:
                if exc.code != "busy":
                    raise
        return cleaned
