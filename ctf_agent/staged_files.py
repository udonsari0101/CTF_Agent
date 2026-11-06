"""Workspace-level, resumable files prepared before a challenge is published.

The upload protocol intentionally mirrors challenge attachments.  Staged files
remain in their workspace and can be linked to more than one challenge without
copying multi-gigabyte payloads on the usual same-filesystem deployment.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import logging
import os
import re
import shutil
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from fastapi import Body, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from .process_lock import ProcessFileLock
from .storage_budget import (
    StorageBudgetError, get_storage_budget, storage_http_status,
    storage_io_http_response,
)
from .uploads import CHUNK_BYTES, EXPIRY_SECONDS, MAX_ACTIVE_UPLOADS_PER_USER, UploadInit

ASYNC_VERIFY_BYTES = 256 * 1024 * 1024


class StagedFileManager:
    def __init__(self, app, settings, validate_filename, stamp):
        self.app, self.settings = app, settings
        self.layout = app.state.storage_layout
        self.validate_filename, self.stamp = validate_filename, stamp
        self.budget = get_storage_budget(app, settings)
        self.guard = threading.Lock()
        self.locks: dict[str, threading.Lock] = {}
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS workspace_staged_files (
                    id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    name TEXT NOT NULL, size INTEGER NOT NULL, last_modified INTEGER,
                    offset INTEGER NOT NULL DEFAULT 0, expected_sha256 TEXT,
                    sha256 TEXT, status TEXT NOT NULL DEFAULT 'uploading'
                        CHECK(status IN ('uploading','ready','cancelled')),
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_staged_files
                    ON workspace_staged_files(workspace_id,owner_user_id,status,created_at);
                CREATE TABLE IF NOT EXISTS workspace_staged_chunks (
                    file_id TEXT NOT NULL REFERENCES workspace_staged_files(id) ON DELETE CASCADE,
                    offset INTEGER NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
                    PRIMARY KEY(file_id,offset)
                );
                CREATE TABLE IF NOT EXISTS workspace_staged_attachments (
                    staged_file_id TEXT NOT NULL REFERENCES workspace_staged_files(id) ON DELETE CASCADE,
                    attachment_id TEXT NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,
                    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
                    storage_mode TEXT NOT NULL CHECK(storage_mode IN ('link','copy')),
                    PRIMARY KEY(staged_file_id,challenge_id),
                    UNIQUE(attachment_id)
                );
            """)
            columns = {item[1] for item in db.execute(
                "PRAGMA table_info(workspace_staged_files)"
            )}
            for name, kind in (
                ("verified_dev", "TEXT"),
                ("verified_ino", "TEXT"),
                ("verified_mtime_ns", "INTEGER"),
                ("verifying", "INTEGER NOT NULL DEFAULT 0"),
                ("verification_error", "TEXT"),
            ):
                if name not in columns:
                    db.execute(f"ALTER TABLE workspace_staged_files ADD COLUMN {name} {kind}")
        self.reconcile()
        self.reconcile_copies()

    @contextmanager
    def db(self):
        connection = self.app.state.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def lock(self, file_id: str) -> threading.Lock:
        with self.guard:
            return self.locks.setdefault(file_id, threading.Lock())

    @staticmethod
    def reservation(file_id: str) -> str:
        return "staged-file:" + file_id

    @staticmethod
    def sync_directory(path: Path) -> None:
        """Persist a published directory entry before its database row commits."""
        if hasattr(os, "O_DIRECTORY"):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def workspace(self, workspace_id: str, user: dict) -> None:
        self.app.state.require_workspace_owner(workspace_id, user)

    def directory(self, workspace_id: str, *, create: bool = False) -> Path:
        try:
            workspace = self.layout.legacy_workspace_path(workspace_id, create=create)
        except ValueError:
            raise HTTPException(400, "Invalid workspace storage path.") from None
        try:
            workspace_info = os.lstat(workspace)
        except FileNotFoundError:
            raise HTTPException(409, "Workspace storage path is missing.") from None
        if not stat.S_ISDIR(workspace_info.st_mode):
            raise HTTPException(409, "Workspace storage path is unsafe.")
        target = workspace / ".staged"
        if create:
            try:
                target.mkdir(mode=0o750, exist_ok=True)
            except FileExistsError:
                # A broken symlink is not an upload directory.  Keep this a
                # client-visible conflict rather than a server error.
                raise HTTPException(409, "Workspace staging path is unsafe.") from None
        try:
            details = os.lstat(target)
        except FileNotFoundError:
            return target
        if not stat.S_ISDIR(details.st_mode):
            raise HTTPException(409, "Workspace staging path is not a directory.")
        return target

    def path(self, row, suffix: str, *, create: bool = False) -> Path:
        if suffix not in {"part", "ready"}:
            raise ValueError("invalid staged-file suffix")
        file_id = row["id"]
        if len(file_id) != 32 or any(char not in "0123456789abcdef" for char in file_id):
            raise HTTPException(400, "Invalid staged-file identifier.")
        return self.directory(row["workspace_id"], create=create) / f"{file_id}.{suffix}"

    @staticmethod
    def regular(path: Path, size: int | None = None) -> bool:
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            return False
        return stat.S_ISREG(details.st_mode) and (size is None or details.st_size == size)

    @staticmethod
    def fingerprint(details: os.stat_result) -> tuple[str, str, int]:
        # A hardlink changes ctime but not mtime, so including ctime would
        # force a full 20 GiB hash after every successful link.
        return str(details.st_dev), str(details.st_ino), details.st_mtime_ns

    def verify_lock(self, file_id: str) -> ProcessFileLock:
        return ProcessFileLock(
            self.app.state.uploads.process_lock_root / f"staged-verify-{file_id}.lock"
        )

    @classmethod
    def verified_stat(cls, path: Path, size: int) -> os.stat_result:
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            raise HTTPException(409, "The staged file is missing.") from None
        if not stat.S_ISREG(details.st_mode) or details.st_size != size:
            raise HTTPException(409, "The staged file is missing or changed.")
        return details

    @classmethod
    def hash_stable_file(cls, path: Path, size: int, *, cancel=None) -> tuple[str, os.stat_result]:
        before = cls.verified_stat(path, size)
        digest = hashlib.sha256()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise HTTPException(409, "The staged file is unsafe.")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                while piece := handle.read(1024 * 1024):
                    if cancel is not None and cancel.is_set():
                        raise InterruptedError("Staged file reuse was cancelled.")
                    digest.update(piece)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (before.st_size != after.st_size or
                cls.fingerprint(before) != cls.fingerprint(after)):
            raise HTTPException(409, "The staged file changed during verification.")
        return digest.hexdigest(), after

    def link_verified_sha256(self, workspace_id: str, owner_user_id: str,
                             digest: str, destination: Path,
                             *, max_size: int | None = None, cancel=None) -> int | None:
        """Replace an import-owned file with an identical staged hardlink.

        A database digest alone is insufficient: the source is hashed again
        while its deletion lock is held.  A missing, changed, or busy staged
        file simply leaves the caller's normal CTFd download path available.
        """
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            return None
        with self.db() as db:
            candidates = db.execute(
                """SELECT id FROM workspace_staged_files
                   WHERE workspace_id=? AND owner_user_id=? AND status='ready'
                     AND sha256=? AND (? IS NULL OR size<=?)
                   ORDER BY created_at,id""",
                (workspace_id, owner_user_id, digest, max_size, max_size),
            ).fetchall()
        for candidate in candidates:
            file_id = candidate["id"]
            process_lock = self.verify_lock(file_id)
            if not process_lock.try_acquire():
                continue
            try:
                with self.lock(file_id):
                    with self.db() as db:
                        row = db.execute(
                            """SELECT * FROM workspace_staged_files
                               WHERE id=? AND workspace_id=? AND owner_user_id=?
                                 AND status='ready' AND sha256=?""",
                            (file_id, workspace_id, owner_user_id, digest),
                        ).fetchone()
                    if row is None:
                        continue
                    try:
                        source = self.path(row, "ready")
                        actual, _ = self.hash_stable_file(source, row["size"], cancel=cancel)
                    except HTTPException:
                        continue
                    if actual != digest:
                        continue
                    temporary = destination.with_name(
                        destination.name + ".staged-" + uuid.uuid4().hex
                    )
                    try:
                        try:
                            os.link(source, temporary, follow_symlinks=False)
                        except OSError as exc:
                            if exc.errno in {
                                errno.EXDEV, errno.EPERM, errno.EACCES,
                                getattr(errno, "ENOTSUP", -1),
                            }:
                                return None
                            raise
                        if not self.regular(temporary, row["size"]):
                            return None
                        os.replace(temporary, destination)
                        self.sync_directory(destination.parent)
                        return row["size"]
                    finally:
                        temporary.unlink(missing_ok=True)
            finally:
                process_lock.release()
        return None

    def row(self, workspace_id: str, file_id: str, user: dict):
        self.workspace(workspace_id, user)
        with self.db() as db:
            row = db.execute(
                """SELECT * FROM workspace_staged_files
                   WHERE id=? AND workspace_id=? AND owner_user_id=?""",
                (file_id, workspace_id, user["id"]),
            ).fetchone()
        if row is None or row["status"] == "cancelled":
            raise HTTPException(404, "Staged file not found.")
        return row

    def result(self, row) -> dict:
        value = {
            key: row[key] for key in (
                "id", "workspace_id", "name", "size", "offset", "status",
                "last_modified", "sha256", "updated_at",
            )
        } | {"chunk_bytes": CHUNK_BYTES, "verification_error": row["verification_error"]}
        if row["verifying"]:
            value["status"] = "verifying"
        if row["status"] == "ready":
            value["storage_path"] = (
                f"workspaces/{row['workspace_id']}/.staged/{row['id']}.ready"
            )
            try:
                value["file_available"] = self.regular(
                    self.path(row, "ready"), row["size"],
                )
            except (HTTPException, OSError):
                value["file_available"] = False
        return value

    def list(self, workspace_id: str, user: dict) -> dict:
        self.workspace(workspace_id, user)
        with self.db() as db:
            rows = db.execute(
                """SELECT * FROM workspace_staged_files
                   WHERE workspace_id=? AND owner_user_id=? AND status IN ('uploading','ready')
                   ORDER BY created_at,id""",
                (workspace_id, user["id"]),
            ).fetchall()
            links = db.execute(
                """SELECT staged_file_id,COUNT(*) AS linked_count
                   FROM workspace_staged_attachments
                   WHERE staged_file_id IN (SELECT id FROM workspace_staged_files
                       WHERE workspace_id=? AND owner_user_id=?)
                   GROUP BY staged_file_id""",
                (workspace_id, user["id"]),
            ).fetchall()
        counts = {row["staged_file_id"]: row["linked_count"] for row in links}
        return {"files": [self.result(row) | {"linked_count": counts.get(row["id"], 0)}
                          for row in rows]}

    def create(self, workspace_id: str, payload: UploadInit, user: dict) -> dict:
        self.workspace(workspace_id, user)
        name = self.validate_filename(payload.name)
        file_id, timestamp = uuid.uuid4().hex, int(time.time())
        row = {"id": file_id, "workspace_id": workspace_id}
        target = self.path(row, "part", create=True)

        def prepare():
            with target.open("xb") as handle:
                handle.flush()
                os.fsync(handle.fileno())

        def insert(db):
            active = db.execute(
                """SELECT COUNT(*) FROM workspace_staged_files
                   WHERE owner_user_id=? AND status='uploading'""",
                (user["id"],),
            ).fetchone()[0]
            if active >= MAX_ACTIVE_UPLOADS_PER_USER:
                raise HTTPException(429, "Too many simultaneous file uploads.")
            db.execute(
                """INSERT INTO workspace_staged_files
                   (id,owner_user_id,workspace_id,name,size,last_modified,
                    expected_sha256,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (file_id, user["id"], workspace_id, name, payload.size,
                 payload.last_modified, payload.sha256, timestamp, timestamp),
            )

        try:
            self.budget.reserve(
                self.reservation(file_id), "staged-file", user["id"],
                workspace_id, None, 0, prepare=prepare, db_update=insert,
            )
        except StorageBudgetError as exc:
            target.unlink(missing_ok=True)
            raise HTTPException(storage_http_status(exc), str(exc)) from None
        except HTTPException:
            target.unlink(missing_ok=True)
            raise
        except OSError as exc:
            target.unlink(missing_ok=True)
            status, message = storage_io_http_response(exc)
            raise HTTPException(status, message) from None
        return self.result(self.row(workspace_id, file_id, user))

    def manifest(self, workspace_id: str, file_id: str, start: int, user: dict) -> dict:
        self.row(workspace_id, file_id, user)
        with self.db() as db:
            chunks = db.execute(
                """SELECT offset,size,sha256 FROM workspace_staged_chunks
                   WHERE file_id=? AND offset>=? ORDER BY offset LIMIT 1000""",
                (file_id, max(0, start)),
            ).fetchall()
        return {
            "chunks": [dict(item) for item in chunks],
            "next_offset": chunks[-1]["offset"] + chunks[-1]["size"]
            if len(chunks) == 1000 else None,
        }

    def chunk(self, workspace_id: str, file_id: str, offset: int,
              content: bytes, user: dict) -> dict:
        if offset < 0:
            raise HTTPException(400, "Invalid upload offset.")
        if not content or len(content) > CHUNK_BYTES:
            raise HTTPException(413, f"Chunk must be 1 to {CHUNK_BYTES} bytes.")
        digest = hashlib.sha256(content).hexdigest()
        with self.lock(file_id):
            row = self.row(workspace_id, file_id, user)
            if row["status"] != "uploading" or row["verifying"]:
                raise HTTPException(409, "Staged upload is not active.")
            with self.db() as db:
                old = db.execute(
                    "SELECT size,sha256 FROM workspace_staged_chunks WHERE file_id=? AND offset=?",
                    (file_id, offset),
                ).fetchone()
            if old is not None:
                if old["size"] != len(content) or old["sha256"] != digest:
                    raise HTTPException(409, "A different chunk is already stored at this offset.")
                return self.result(row)
            if row["offset"] != offset or offset + len(content) > row["size"]:
                raise HTTPException(409, "Upload offset changed. Refresh and resume.")
            target = self.path(row, "part")
            if not self.regular(target) or target.stat().st_size < offset:
                raise HTTPException(409, "Staged upload file is incomplete.")

            def current(db):
                fresh = db.execute(
                    "SELECT status,offset,verifying FROM workspace_staged_files WHERE id=?",
                    (file_id,),
                ).fetchone()
                return bool(fresh and fresh["status"] == "uploading" and not fresh["verifying"]
                            and fresh["offset"] == offset)

            def write():
                flags = os.O_RDWR | (getattr(os, "O_NOFOLLOW", 0))
                descriptor = os.open(target, flags)
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise OSError(errno.EINVAL, "Staged upload target is not regular")
                    with os.fdopen(descriptor, "r+b", closefd=False) as handle:
                        handle.seek(offset)
                        handle.write(content)
                        handle.truncate(offset + len(content))
                        handle.flush()
                        os.fsync(handle.fileno())
                finally:
                    os.close(descriptor)

            def commit(db):
                db.execute(
                    "INSERT INTO workspace_staged_chunks VALUES(?,?,?,?)",
                    (file_id, offset, len(content), digest),
                )
                db.execute(
                    "UPDATE workspace_staged_files SET offset=?,updated_at=? WHERE id=?",
                    (offset + len(content), int(time.time()), file_id),
                )

            try:
                self.budget.reserve(
                    self.reservation(file_id), "staged-file", user["id"],
                    workspace_id, None, len(content),
                )
                self.budget.commit_reserved_write(
                    self.reservation(file_id), len(content), write,
                    precheck=current, db_update=commit,
                )
            except StorageBudgetError as exc:
                raise HTTPException(storage_http_status(exc), str(exc)) from None
            except OSError as exc:
                status, message = storage_io_http_response(exc)
                raise HTTPException(status, message) from None
            return self.result(self.row(workspace_id, file_id, user))

    def finalize(self, workspace_id: str, file_id: str, user: dict) -> dict:
        with self.lock(file_id):
            row = self.row(workspace_id, file_id, user)
            if row["status"] == "ready":
                return self.result(row)
            if row["status"] != "uploading" or row["offset"] != row["size"]:
                raise HTTPException(409, "Finish uploading before finalizing the file.")
            part, ready = self.path(row, "part"), self.path(row, "ready")
            candidate = part if self.regular(part) else ready
            if not self.regular(candidate, row["size"]):
                raise HTTPException(409, "Staged file size does not match the upload.")
            digest, checked = self.hash_stable_file(candidate, row["size"])
            if row["expected_sha256"] and digest != row["expected_sha256"]:
                raise HTTPException(409, "Staged file SHA-256 does not match the source.")

            def publish():
                if part.exists():
                    if ready.exists():
                        raise HTTPException(409, "A conflicting finalized file exists.")
                    os.replace(part, ready)
                    if os.name != "nt":
                        os.chmod(ready, 0o440)
                    self.sync_directory(ready.parent)

            def complete(db):
                verified = self.verified_stat(ready, row["size"])
                if self.fingerprint(verified) != self.fingerprint(checked):
                    raise HTTPException(409, "The staged file changed during finalization.")
                device, inode, mtime_ns = self.fingerprint(verified)
                db.execute(
                    """UPDATE workspace_staged_files
                       SET status='ready',sha256=?,updated_at=?,verifying=0,
                           verification_error=NULL,
                           verified_dev=?,verified_ino=?,verified_mtime_ns=?
                       WHERE id=? AND status='uploading' AND offset=size""",
                    (digest, int(time.time()), device, inode, mtime_ns, file_id),
                )

            try:
                self.budget.release(
                    self.reservation(file_id), cleanup=publish, db_update=complete,
                )
            except StorageBudgetError as exc:
                raise HTTPException(storage_http_status(exc), str(exc)) from None
            except OSError as exc:
                status, message = storage_io_http_response(exc)
                raise HTTPException(status, message) from None
            return self.result(self.row(workspace_id, file_id, user))

    def start_finalize(self, workspace_id: str, file_id: str, user: dict) -> dict:
        row = self.row(workspace_id, file_id, user)
        if row["status"] == "ready" or row["verifying"]:
            return self.result(row)
        if row["status"] != "uploading" or row["offset"] != row["size"]:
            raise HTTPException(409, "Finish uploading before finalizing the file.")
        entered = threading.Event()
        thread = threading.Thread(
            target=self._background_finalize,
            args=(workspace_id, file_id, dict(user), entered), daemon=True,
            name=f"staged-finalize-{file_id[:8]}",
        )
        thread.start()
        if not entered.wait(5):
            raise HTTPException(503, "File verification did not start. Retry status shortly.")
        return self.result(self.row(workspace_id, file_id, user))

    def _background_finalize(self, workspace_id: str, file_id: str,
                             user: dict, entered: threading.Event) -> None:
        process_lock = self.verify_lock(file_id)
        if not process_lock.try_acquire():
            entered.set()
            return
        try:
            with self.lock(file_id):
                row = self.row(workspace_id, file_id, user)
                if row["status"] == "ready":
                    entered.set()
                    return
                if row["status"] != "uploading" or row["offset"] != row["size"]:
                    entered.set()
                    return
                with self.db() as db:
                    db.execute(
                        """UPDATE workspace_staged_files SET verifying=1,
                           verification_error=NULL,updated_at=? WHERE id=?""",
                        (int(time.time()), file_id),
                    )
            entered.set()
            with self.app.state.uploads.finalize_slot(user["id"]):
                self.finalize(workspace_id, file_id, user)
        except BaseException as exc:
            logging.exception("Background staged-file verification failed")
            message = exc.detail if isinstance(exc, HTTPException) else "File verification failed. Retry finalization."
            with self.db() as db:
                db.execute(
                    """UPDATE workspace_staged_files SET verifying=0,
                       verification_error=?,updated_at=? WHERE id=? AND status='uploading'""",
                    (str(message), int(time.time()), file_id),
                )
        finally:
            entered.set()
            process_lock.release()

    @staticmethod
    def attachment_id(file_id: str, challenge_id: str) -> str:
        return uuid.uuid5(uuid.NAMESPACE_URL, f"ctf-agent/staged/{file_id}/{challenge_id}").hex

    @staticmethod
    def copy_reservation(file_id: str, challenge_id: str) -> str:
        return f"staged-copy:{file_id}:{challenge_id}"

    def copy_lock(self, file_id: str, challenge_id: str) -> ProcessFileLock:
        return ProcessFileLock(
            self.app.state.uploads.process_lock_root /
            f"staged-copy-{file_id}-{challenge_id}.lock"
        )

    def _copy_to_attachment(self, source: Path, destination: Path, size: int,
                            *, owner: str, workspace: str, challenge: str,
                            file_id: str, digest: str) -> None:
        copy_lock = self.copy_lock(file_id, challenge)
        if not copy_lock.try_acquire():
            raise HTTPException(409, "This staged file is already being copied into the challenge.")
        reservation = self.copy_reservation(file_id, challenge)
        reserved = False
        completed = False
        floor = self.budget.minimum_free_bytes
        try:
            free = shutil.disk_usage(destination.parent).free
        except OSError as exc:
            copy_lock.release()
            raise HTTPException(503, "Could not check destination free space.") from exc
        if free - size < floor:
            copy_lock.release()
            raise HTTPException(507, "Insufficient free space to copy this staged file.")
        temporary = destination.with_name(destination.name + ".copying")
        try:
            self.budget.reserve(reservation, "staged-copy", owner, workspace, challenge, size)
            reserved = True
            if self.regular(temporary):
                temporary.unlink()
            elif temporary.exists() or temporary.is_symlink():
                raise HTTPException(409, "Previous staged-file copy needs cleanup.")
            checksum = hashlib.sha256()
            with source.open("rb") as read, temporary.open("xb") as write:
                while data := read.read(4 * 1024 * 1024):
                    if shutil.disk_usage(destination.parent).free - len(data) < floor:
                        raise HTTPException(507, "Insufficient free space during staged-file copy.")
                    write.write(data)
                    checksum.update(data)
                write.flush()
                os.fsync(write.fileno())
            if checksum.hexdigest() != digest:
                raise HTTPException(409, "The staged file changed during copy.")
            os.replace(temporary, destination)
            completed = True
            self.sync_directory(destination.parent)
        except StorageBudgetError as exc:
            raise HTTPException(storage_http_status(exc), str(exc)) from None
        except OSError as exc:
            status, message = storage_io_http_response(exc)
            raise HTTPException(status, message) from None
        finally:
            try:
                if self.regular(temporary):
                    temporary.unlink()
                if reserved and not completed:
                    self.budget.release(reservation)
            finally:
                copy_lock.release()

    def attach(self, workspace_id: str, challenge_id: str, file_id: str,
               user: dict, mode: str = "link") -> dict:
        if mode not in {"link", "copy"}:
            raise HTTPException(400, "Attachment mode must be link or copy.")
        with self.lock(file_id):
            row = self.row(workspace_id, file_id, user)
            if row["status"] != "ready":
                raise HTTPException(409, "Finish the staged upload before attaching it.")
            source = self.path(row, "ready")
            details = self.verified_stat(source, row["size"])
            current = self.fingerprint(details)
            saved = (row["verified_dev"], row["verified_ino"], row["verified_mtime_ns"])
            if current != saved:
                digest, details = self.hash_stable_file(source, row["size"])
                if digest != row["sha256"]:
                    raise HTTPException(409, "The staged file SHA-256 changed. Upload it again.")
                current = self.fingerprint(details)
                with self.db() as db:
                    db.execute(
                        """UPDATE workspace_staged_files SET verified_dev=?,
                           verified_ino=?,verified_mtime_ns=? WHERE id=?""",
                        (*current, file_id),
                    )
            attachment_id = self.attachment_id(file_id, challenge_id)
            with self.db() as db:
                existing = db.execute(
                    """SELECT a.id,a.original_name,a.size,a.created_at,s.storage_mode
                       FROM workspace_staged_attachments s
                       JOIN attachments a ON a.id=s.attachment_id
                       WHERE s.staged_file_id=? AND s.challenge_id=?""",
                    (file_id, challenge_id),
                ).fetchone()
                if existing:
                    return dict(existing)
                challenge = db.execute(
                    "SELECT 1 FROM challenges WHERE id=? AND workspace_id=?",
                    (challenge_id, workspace_id),
                ).fetchone()
                if not challenge:
                    raise HTTPException(404, "Challenge not found in this workspace.")
                ctfd_table = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ctfd_jobs'"
                ).fetchone()
                if ctfd_table:
                    columns = {item[1] for item in db.execute("PRAGMA table_info(ctfd_jobs)")}
                    if {"mode", "target_challenge_id"} <= columns and db.execute(
                        """SELECT 1 FROM ctfd_jobs WHERE owner_user_id=? AND workspace_id=?
                           AND mode='refresh' AND target_challenge_id=?
                           AND status IN ('queued','running') LIMIT 1""",
                        (user["id"], workspace_id, challenge_id),
                    ).fetchone():
                        raise HTTPException(409, "CTFd refresh is in progress for this challenge.")
            destination = self.layout.legacy_attachment_path(
                workspace_id, challenge_id, attachment_id, create_parent=True,
            )
            created = False
            copied = False
            actual_mode = mode
            if destination.exists() or destination.is_symlink():
                if not self.regular(destination, row["size"]):
                    raise HTTPException(409, "Attachment destination already exists.")
                if os.path.samefile(source, destination):
                    actual_mode = "link"
                else:
                    checksum = hashlib.sha256()
                    with destination.open("rb") as handle:
                        while piece := handle.read(1024 * 1024):
                            checksum.update(piece)
                    if checksum.hexdigest() != row["sha256"]:
                        raise HTTPException(409, "Attachment destination already exists.")
                    actual_mode = "copy"
            else:
                if mode == "copy":
                    self._copy_to_attachment(source, destination, row["size"],
                                             owner=user["id"], workspace=workspace_id,
                                             challenge=challenge_id, file_id=file_id,
                                             digest=row["sha256"])
                    created = True
                    copied = True
                else:
                    try:
                        os.link(source, destination, follow_symlinks=False)
                        created = True
                        self.sync_directory(destination.parent)
                    except OSError as exc:
                        if created:
                            try:
                                destination.unlink()
                            except OSError:
                                logging.warning("Deferred unsynced staged hardlink cleanup: %s", destination)
                        if exc.errno != errno.EXDEV or created:
                            status, message = storage_io_http_response(exc)
                            raise HTTPException(status, message) from None
                        self._copy_to_attachment(source, destination, row["size"],
                                                 owner=user["id"], workspace=workspace_id,
                                                 challenge=challenge_id, file_id=file_id,
                                                 digest=row["sha256"])
                        actual_mode = "copy"
                        created = True
                        copied = True
            try:
                with self.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    fresh = db.execute(
                        "SELECT status FROM workspace_staged_files WHERE id=? AND workspace_id=?",
                        (file_id, workspace_id),
                    ).fetchone()
                    if not fresh or fresh["status"] != "ready":
                        raise HTTPException(409, "Staged file state changed.")
                    if not db.execute(
                        "SELECT 1 FROM challenges WHERE id=? AND workspace_id=?",
                        (challenge_id, workspace_id),
                    ).fetchone():
                        raise HTTPException(404, "Challenge not found in this workspace.")
                    db.execute(
                        """INSERT INTO attachments
                           (id,workspace_id,challenge_id,original_name,stored_name,size,created_at)
                           VALUES(?,?,?,?,?,?,?)""",
                        (attachment_id, workspace_id, challenge_id, row["name"],
                         attachment_id, row["size"], self.stamp()),
                    )
                    db.execute(
                        """INSERT INTO workspace_staged_attachments
                           (staged_file_id,attachment_id,challenge_id,storage_mode)
                           VALUES(?,?,?,?)""",
                        (file_id, attachment_id, challenge_id, actual_mode),
                    )
                    result = db.execute(
                        "SELECT id,original_name,size,created_at FROM attachments WHERE id=?",
                        (attachment_id,),
                    ).fetchone()
            except BaseException:
                if created and self.regular(destination):
                    destination.unlink()
                if copied:
                    self.budget.release(self.copy_reservation(file_id, challenge_id))
                raise
            if actual_mode == "copy":
                self.budget.release(self.copy_reservation(file_id, challenge_id))
            try:
                with self.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    attachment = db.execute(
                        "SELECT * FROM attachments WHERE id=?", (attachment_id,),
                    ).fetchone()
                    self.layout.ensure_attachment_view(
                        db, workspace_id, challenge_id, attachment, view_wins=False,
                    )
            except (OSError, RuntimeError, ValueError):
                # The UUID attachment is already committed; the readable view
                # is rebuilt on the next challenge sync or download.
                logging.warning("Staged attachment readable view deferred")
            return dict(result) | {"storage_mode": actual_mode}

    def _delete_unpublished(self, row) -> None:
        self._remove_orphan_attachments(row)
        for suffix in ("part", "ready"):
            path = self.path(row, suffix)
            if path.is_symlink():
                raise HTTPException(409, "Staged file path is unsafe.")
            if self.regular(path):
                path.unlink()

    def _remove_orphan_attachments(self, row) -> None:
        """Clear a link/copy left by a crash before attachment metadata commits."""
        source = self.path(row, "ready")
        with self.db() as db:
            challenges = db.execute(
                "SELECT id FROM challenges WHERE workspace_id=?", (row["workspace_id"],)
            ).fetchall()
            published = {item["id"] for item in db.execute(
                "SELECT id FROM attachments WHERE workspace_id=?", (row["workspace_id"],)
            )}
        for challenge in challenges:
            attachment_id = self.attachment_id(row["id"], challenge["id"])
            if attachment_id in published:
                continue
            destination = self.layout.legacy_attachment_path(
                row["workspace_id"], challenge["id"], attachment_id,
            )
            temporary = destination.with_name(destination.name + ".copying")
            for candidate in (temporary, destination):
                if not self.regular(candidate):
                    continue
                if candidate == temporary:
                    candidate.unlink()
                    continue
                if self.regular(source) and os.path.samefile(source, candidate):
                    candidate.unlink()
                    continue
                if candidate.stat().st_size != row["size"] or not row["sha256"]:
                    continue
                checksum = hashlib.sha256()
                with candidate.open("rb") as handle:
                    while piece := handle.read(1024 * 1024):
                        checksum.update(piece)
                if checksum.hexdigest() == row["sha256"]:
                    candidate.unlink()

    def delete(self, workspace_id: str, file_id: str, user: dict) -> dict:
        process_lock = self.verify_lock(file_id)
        if not process_lock.try_acquire():
            raise HTTPException(409, "File verification is in progress. Retry deletion afterward.")
        try:
            return self._delete_locked(workspace_id, file_id, user)
        finally:
            process_lock.release()

    def _delete_locked(self, workspace_id: str, file_id: str, user: dict) -> dict:
        with self.lock(file_id):
            row = self.row(workspace_id, file_id, user)
            try:
                self.budget.release(
                    self.reservation(file_id),
                    cleanup=lambda: self._delete_unpublished(row),
                    db_update=lambda db: db.execute(
                        "DELETE FROM workspace_staged_files WHERE id=? AND workspace_id=?",
                        (file_id, workspace_id),
                    ),
                )
            except StorageBudgetError as exc:
                raise HTTPException(storage_http_status(exc), str(exc)) from None
            except OSError as exc:
                status, message = storage_io_http_response(exc)
                raise HTTPException(status, message) from None
            return {"ok": True}

    def cancel_workspace(self, workspace_id: str, user: dict) -> bool:
        self.workspace(workspace_id, user)
        with self.db() as db:
            rows = db.execute(
                """SELECT id FROM workspace_staged_files
                   WHERE workspace_id=? AND owner_user_id=?
                   AND status IN ('uploading','ready')""",
                (workspace_id, user["id"]),
            ).fetchall()
        for item in rows:
            lock = self.lock(item["id"])
            if not lock.acquire(blocking=False):
                return False
            lock.release()
            try:
                self.delete(workspace_id, item["id"], user)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
        return True

    def reconcile(self) -> None:
        def rebuild():
            with self.db() as db:
                rows = db.execute(
                    "SELECT * FROM workspace_staged_files WHERE status IN ('uploading','ready')"
                ).fetchall()
            live = set()
            active_uploads = {}
            busy_workspaces = set()

            def process_row(row):
                if row["verifying"]:
                    process_lock = self.verify_lock(row["id"])
                    if process_lock.try_acquire():
                        try:
                            with self.db() as db:
                                db.execute(
                                    """UPDATE workspace_staged_files SET verifying=0,
                                       verification_error=? WHERE id=?""",
                                    ("Verification was interrupted. Retry finalization.", row["id"]),
                                )
                        finally:
                            process_lock.release()
                try:
                    part, ready = self.path(row, "part"), self.path(row, "ready")
                except (HTTPException, OSError):
                    # The data mount can be temporarily absent at startup.
                    # Keep metadata so restoring the mount can recover the file.
                    if row["status"] == "uploading":
                        active_uploads[row["id"]] = row
                    return
                if row["status"] == "uploading":
                    if self.regular(part):
                        actual = part.stat().st_size
                        if actual >= row["offset"]:
                            if actual > row["offset"]:
                                with part.open("r+b") as handle:
                                    handle.truncate(row["offset"])
                                    handle.flush()
                                    os.fsync(handle.fileno())
                            live.add(part)
                            active_uploads[row["id"]] = row
                            return
                    elif row["offset"] == row["size"] and self.regular(ready, row["size"]):
                        live.add(ready)  # finalize can resume after rename
                        active_uploads[row["id"]] = row
                        return
                    elif row["offset"] == 0 and not part.exists():
                        part.parent.mkdir(parents=True, exist_ok=True)
                        part.touch(exist_ok=False)
                        live.add(part)
                        active_uploads[row["id"]] = row
                        return
                    with self.db() as db:
                        db.execute(
                            "UPDATE workspace_staged_files SET status='cancelled' WHERE id=?",
                            (row["id"],),
                        )
                elif self.regular(ready):
                    live.add(ready)

            for row in rows:
                workspace_lock = self.app.state.uploads.process_workspace_lock(
                    row["workspace_id"]
                )
                if not workspace_lock.try_acquire():
                    busy_workspaces.add(row["workspace_id"])
                    if row["status"] == "uploading":
                        active_uploads[row["id"]] = row
                    continue
                try:
                    process_row(row)
                except (FileNotFoundError, HTTPException):
                    # Another process or mount transition may remove a path
                    # between listing and stat.  Keep its row for retry.
                    if row["status"] == "uploading":
                        active_uploads[row["id"]] = row
                finally:
                    workspace_lock.release()
            root = self.layout.legacy_root
            try:
                workspaces = list(root.iterdir())
            except FileNotFoundError:
                workspaces = []
            for workspace in workspaces:
                if workspace.name in busy_workspaces:
                    continue
                try:
                    workspace_mode = os.lstat(workspace).st_mode
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(workspace_mode):
                    continue
                staged = workspace / ".staged"
                try:
                    staged_mode = os.lstat(staged).st_mode
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(staged_mode):
                    continue
                try:
                    candidates = list(staged.iterdir())
                except FileNotFoundError:
                    continue
                for candidate in candidates:
                    if candidate in live or not self.regular(candidate):
                        continue
                    stem, dot, suffix = candidate.name.rpartition(".")
                    if (dot and suffix in {"part", "ready"} and len(stem) == 32
                            and all(char in "0123456789abcdef" for char in stem)):
                        candidate.unlink(missing_ok=True)
            with self.db() as db:
                reservations = db.execute(
                    "SELECT * FROM storage_reservations WHERE kind='staged-file'"
                ).fetchall()
            return {
                item["reservation_key"]: (
                    active_uploads[file_id]["owner_user_id"],
                    active_uploads[file_id]["workspace_id"], None,
                    item["remaining_bytes"],
                )
                for item in reservations
                for file_id in [item["reservation_key"].removeprefix("staged-file:")]
                if item["reservation_key"].startswith("staged-file:")
                and file_id in active_uploads
            }

        self.budget.reconcile_kind("staged-file", rebuild)

    def reconcile_copies(self) -> None:
        """Remove partial copies whose writer no longer owns its process lock."""
        for reservation in self.budget.snapshot(kind="staged-copy"):
            key = reservation["reservation_key"]
            parts = key.split(":")
            if len(parts) != 3 or parts[0] != "staged-copy":
                continue
            _, file_id, challenge_id = parts
            workspace_lock = self.app.state.uploads.process_workspace_lock(
                reservation["workspace_id"]
            )
            if not workspace_lock.try_acquire():
                continue
            copy_lock = self.copy_lock(file_id, challenge_id)
            if not copy_lock.try_acquire():
                workspace_lock.release()
                continue
            try:
                def cleanup():
                    with self.db() as db:
                        published = db.execute(
                            "SELECT 1 FROM attachments WHERE id=?",
                            (self.attachment_id(file_id, challenge_id),),
                        ).fetchone()
                    destination = self.layout.legacy_attachment_path(
                        reservation["workspace_id"], challenge_id,
                        self.attachment_id(file_id, challenge_id),
                    )
                    temporary = destination.with_name(destination.name + ".copying")
                    if temporary.is_symlink():
                        raise OSError("Unsafe staged-copy temporary file")
                    if self.regular(temporary):
                        temporary.unlink()
                    if not published:
                        if destination.is_symlink():
                            raise OSError("Unsafe staged-copy destination")
                        if self.regular(destination):
                            destination.unlink()

                try:
                    self.budget.release(key, cleanup=cleanup)
                except (OSError, ValueError):
                    logging.warning("Deferred stale staged-file copy cleanup: %s", key)
            finally:
                copy_lock.release()
                workspace_lock.release()

    def cleanup(self) -> None:
        threshold = int(time.time()) - EXPIRY_SECONDS
        with self.db() as db:
            rows = db.execute(
                """SELECT * FROM workspace_staged_files
                   WHERE status='uploading' AND verifying=0 AND updated_at<?""",
                (threshold,),
            ).fetchall()
        for row in rows:
            lock = self.lock(row["id"])
            if not lock.acquire(blocking=False):
                continue
            process_lock = self.app.state.uploads.process_workspace_lock(row["workspace_id"])
            if not process_lock.try_acquire():
                lock.release()
                continue
            try:
                with self.db() as db:
                    fresh = db.execute(
                        "SELECT * FROM workspace_staged_files WHERE id=?", (row["id"],),
                    ).fetchone()
                if (not fresh or fresh["status"] != "uploading" or fresh["verifying"]
                        or fresh["updated_at"] >= threshold):
                    continue

                def still_stale(db):
                    current = db.execute(
                        "SELECT status,verifying,updated_at FROM workspace_staged_files WHERE id=?",
                        (row["id"],),
                    ).fetchone()
                    return current is None or (
                        current["status"] == "uploading" and not current["verifying"]
                        and current["updated_at"] < threshold
                    )

                self.budget.release(
                    self.reservation(row["id"]),
                    cleanup=lambda: self._delete_unpublished(fresh),
                    db_update=lambda db: db.execute(
                        "DELETE FROM workspace_staged_files WHERE id=?", (row["id"],),
                    ),
                    precheck=still_stale,
                )
            except (HTTPException, OSError, StorageBudgetError):
                pass
            finally:
                process_lock.release()
                lock.release()


def register_staged_files(app, require_auth, settings, validate_filename, stamp) -> None:
    manager = StagedFileManager(app, settings, validate_filename, stamp)
    app.state.staged_files = manager
    uploads = app.state.uploads

    @app.post("/api/workspaces/{workspace_id}/staged-files", status_code=201)
    def create(workspace_id: str, payload: UploadInit,
               user: dict = Depends(require_auth)):
        with uploads.try_workspace_lock(workspace_id):
            return manager.create(workspace_id, payload, user)

    @app.get("/api/workspaces/{workspace_id}/staged-files")
    def list_files(workspace_id: str, user: dict = Depends(require_auth)):
        return manager.list(workspace_id, user)

    @app.get("/api/workspaces/{workspace_id}/staged-files/{file_id}")
    def status(workspace_id: str, file_id: str, user: dict = Depends(require_auth)):
        return manager.result(manager.row(workspace_id, file_id, user))

    @app.get("/api/workspaces/{workspace_id}/staged-files/{file_id}/content")
    def download(workspace_id: str, file_id: str,
                 user: dict = Depends(require_auth)):
        row = manager.row(workspace_id, file_id, user)
        if row["status"] != "ready":
            raise HTTPException(409, "Staged file upload is not finished.")
        target = manager.path(row, "ready")
        if not manager.regular(target, row["size"]):
            raise HTTPException(409, "The staged file is missing or changed.")
        return FileResponse(target, filename=row["name"],
                            media_type="application/octet-stream")

    @app.get("/api/workspaces/{workspace_id}/staged-files/{file_id}/chunks")
    def manifest(workspace_id: str, file_id: str, start: int = 0,
                 user: dict = Depends(require_auth)):
        return manager.manifest(workspace_id, file_id, start, user)

    @app.put("/api/workspaces/{workspace_id}/staged-files/{file_id}/chunks")
    def chunk(workspace_id: str, file_id: str, offset: int,
              content: bytes = Body(media_type="application/octet-stream"),
              user: dict = Depends(require_auth)):
        with uploads.try_workspace_lock(workspace_id):
            return manager.chunk(workspace_id, file_id, offset, content, user)

    @app.post("/api/workspaces/{workspace_id}/staged-files/{file_id}/finalize")
    def finalize(workspace_id: str, file_id: str,
                 user: dict = Depends(require_auth)):
        row = manager.row(workspace_id, file_id, user)
        if row["verifying"] or row["size"] >= ASYNC_VERIFY_BYTES:
            result = manager.start_finalize(workspace_id, file_id, user)
            return JSONResponse(result, status_code=202 if result["status"] == "verifying" else 200)
        with uploads.finalize_slot(user["id"]):
            with uploads.try_workspace_lock(workspace_id):
                return manager.finalize(workspace_id, file_id, user)

    @app.delete("/api/workspaces/{workspace_id}/staged-files/{file_id}")
    def delete(workspace_id: str, file_id: str,
               user: dict = Depends(require_auth)):
        with uploads.try_workspace_lock(workspace_id):
            return manager.delete(workspace_id, file_id, user)

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/staged-files/{file_id}/attach")
    def attach(workspace_id: str, challenge_id: str, file_id: str,
               mode: str = "link",
               user: dict = Depends(require_auth)):
        with uploads.finalize_slot(user["id"]):
            with uploads.try_workspace_lock(workspace_id):
                return manager.attach(workspace_id, challenge_id, file_id, user, mode)

    async def cleanup_loop():
        while True:
            try:
                await asyncio.to_thread(manager.cleanup)
            except OSError:
                pass
            await asyncio.sleep(3600)

    tasks = {}

    async def startup():
        tasks[asyncio.get_running_loop()] = asyncio.create_task(cleanup_loop())

    async def shutdown():
        task = tasks.pop(asyncio.get_running_loop(), None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app.router.add_event_handler("startup", startup)
    app.router.add_event_handler("shutdown", shutdown)
