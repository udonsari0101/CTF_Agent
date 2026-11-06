"""Durable source ZIP snapshot for retrying the same direct invitation.

Only a hash of the invitation token is persisted. A failed network send keeps
the exact exported ZIP so a later request, even after process restart, can
resume the receiver's offset and checksum. Stale snapshots expire after seven
days; active sends hold a cross-process lock that cleanup will not bypass.
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
from .direct_transfer_client import MAX_BUNDLE_BYTES
from .process_lock import ProcessFileLock
from .storage_budget import StorageBudget
from .transfer_uploads import MIN_FREE_BYTES


OUTBOX_TTL_SECONDS = 7 * 24 * 3600
MAX_ACTIVE_PER_OWNER = 2
EXPORT_RESERVATION_KIND = "direct_export"
_EXPORT_RESERVATION_PREFIX = "direct-export:"


class DirectOutboxError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _directory(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise DirectOutboxError("unsafe_path", "Source transfer directory is invalid.")
    if os.name != "nt":
        path.chmod(0o700)


class DirectTransferOutbox:
    def __init__(self, settings: Settings, budget: StorageBudget | None = None):
        self.settings = settings
        self.budget = budget or StorageBudget(
            settings.data_dir, lambda: connect(settings),
            minimum_free_bytes=settings.storage_min_free_bytes,
        )
        self.root = Path(settings.data_dir) / "workspaces" / ".transfers" / "outbox"
        self.lock_root = Path(settings.config_dir) / ".locks" / "direct_outbox"
        _directory(self.root)
        _directory(self.lock_root)
        with closing(connect(settings)) as db, db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS direct_transfer_outbox(
                   id TEXT PRIMARY KEY,
                   owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   source_workspace_id TEXT NOT NULL,
                   source_challenge_id TEXT NOT NULL,
                   scope TEXT NOT NULL CHECK(scope IN ('workspace','challenge')),
                   destination_url TEXT NOT NULL,
                   token_hash TEXT NOT NULL,
                   include_remote INTEGER NOT NULL CHECK(include_remote IN (0,1)),
                   lock_key TEXT NOT NULL,
                   status TEXT NOT NULL CHECK(status IN ('exporting','ready','completed')),
                   size INTEGER NOT NULL DEFAULT 0,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL,
                   UNIQUE(owner_user_id,source_workspace_id,source_challenge_id,
                          destination_url,token_hash,include_remote))"""
            )
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_direct_outbox_stale
                   ON direct_transfer_outbox(status,updated_at)"""
            )

    def _archive(self, owner: str, outbox_id: str) -> Path:
        if (len(owner) != 32 or len(outbox_id) != 32
                or any(char not in "0123456789abcdef" for char in owner + outbox_id)):
            raise DirectOutboxError("invalid_id", "Source transfer identifier is invalid.")
        directory = self.root / owner
        _directory(directory)
        return directory / f"{outbox_id}.zip"

    @staticmethod
    def _reservation_key(lock_key: str, outbox_id: str) -> str:
        return f"{_EXPORT_RESERVATION_PREFIX}{lock_key}:{outbox_id}"

    def reservation_key(self, outbox_id: str) -> str:
        with closing(connect(self.settings)) as db:
            row = db.execute(
                "SELECT lock_key FROM direct_transfer_outbox WHERE id=?", (outbox_id,),
            ).fetchone()
        if row is None:
            raise DirectOutboxError("missing_snapshot", "Source snapshot was not found.")
        return self._reservation_key(row["lock_key"], outbox_id)

    @staticmethod
    def _checked_unlink(path: Path) -> None:
        try:
            details = path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(details.st_mode):
            raise DirectOutboxError("unsafe_path", "Source snapshot path is invalid.")
        path.unlink()

    def _remove_partial(self, archive: Path) -> None:
        self._checked_unlink(archive)
        # The ZIP writer creates a hidden staging file in the same directory.
        # A process crash can leave it behind even if the published ZIP is gone.
        for staging in archive.parent.glob(f".{archive.name}.*.tmp"):
            self._checked_unlink(staging)

    def _discard_locked(self, owner: str, outbox_id: str,
                        lock_key: str, *, delete_row: bool) -> None:
        """With the per-key lock held, remove an abandoned export atomically.

        The reservation survives if file cleanup fails. It is only released
        after both the ZIP and any crash-left staging files are removed.
        """
        archive = self._archive(owner, outbox_id)
        self.budget.release(
            self._reservation_key(lock_key, outbox_id),
            cleanup=lambda: self._remove_partial(archive),
            db_update=(lambda db: db.execute(
                "DELETE FROM direct_transfer_outbox WHERE id=?", (outbox_id,),
            )) if delete_row else None,
        )

    @staticmethod
    def _key(owner: str, workspace: str, challenge: str, scope: str,
             url: str, token_hash: str, include_remote: bool) -> str:
        parts = (owner, workspace, challenge, scope, url, token_hash, str(int(include_remote)))
        return hashlib.sha256("\0".join(parts).encode()).hexdigest()

    @contextmanager
    def slot(self, owner_user_id: str, workspace_id: str,
             challenge_id: str | None, destination_url: str,
             token: str, include_remote: bool) -> Iterator[tuple[str, Path, bool]]:
        """Reserve or resume one snapshot; hold its lock through the send."""
        challenge = challenge_id or ""
        scope = "challenge" if challenge else "workspace"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        key = self._key(owner_user_id, workspace_id, challenge, scope,
                        destination_url, token_hash, include_remote)
        lock = ProcessFileLock(self.lock_root / f"{key}.lock")
        if not lock.try_acquire():
            raise DirectOutboxError("busy", "This direct transfer is already in progress.")
        try:
            now = int(time.time())
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if not db.execute(
                    "SELECT 1 FROM users WHERE id=? AND active=1", (owner_user_id,),
                ).fetchone():
                    raise DirectOutboxError("owner_inactive", "Source owner is inactive.")
                if not db.execute(
                    "SELECT 1 FROM workspaces WHERE id=? AND owner_user_id=?",
                    (workspace_id, owner_user_id),
                ).fetchone():
                    raise DirectOutboxError("source_missing", "Source workspace was not found.")
                if challenge and not db.execute(
                    "SELECT 1 FROM challenges WHERE id=? AND workspace_id=?",
                    (challenge, workspace_id),
                ).fetchone():
                    raise DirectOutboxError("source_missing", "Source challenge was not found.")
                row = db.execute(
                    "SELECT * FROM direct_transfer_outbox WHERE lock_key=?",
                    (key,),
                ).fetchone()
                if row is None:
                    active = db.execute(
                        """SELECT COUNT(*) FROM direct_transfer_outbox
                           WHERE owner_user_id=? AND status IN ('exporting','ready')""",
                        (owner_user_id,),
                    ).fetchone()[0]
                    if active >= MAX_ACTIVE_PER_OWNER:
                        raise DirectOutboxError("owner_limit", "Too many pending source transfers.")
                    outbox_id = uuid.uuid4().hex
                    db.execute(
                        """INSERT INTO direct_transfer_outbox
                           (id,owner_user_id,source_workspace_id,source_challenge_id,
                            scope,destination_url,token_hash,include_remote,
                            lock_key,status,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?,'exporting',?,?)""",
                        (outbox_id, owner_user_id, workspace_id, challenge, scope,
                         destination_url, token_hash, int(include_remote), key, now, now),
                    )
                    newly_exported = True
                else:
                    if row["updated_at"] <= now - OUTBOX_TTL_SECONDS:
                        raise DirectOutboxError("expired", "Source snapshot expired; create a new invitation.")
                    outbox_id = row["id"]
                    newly_exported = row["status"] == "exporting"
                    if row["status"] == "completed":
                        raise DirectOutboxError("completed", "This source transfer already completed.")
            archive = self._archive(owner_user_id, outbox_id)
            if newly_exported:
                # An exporting row can survive a crash before publication; the
                # receiver has never seen it, so a fresh export is safe. The
                # per-key lock proves any previous exporter is no longer live.
                self._discard_locked(owner_user_id, outbox_id, key, delete_row=False)
            else:
                try:
                    details = archive.lstat()
                except FileNotFoundError as exc:
                    raise DirectOutboxError("missing_snapshot", "Source snapshot is missing; create a new invitation.") from exc
                if not stat.S_ISREG(details.st_mode) or details.st_size != row["size"]:
                    raise DirectOutboxError("changed_snapshot", "Source snapshot changed; create a new invitation.")
            try:
                yield outbox_id, archive, newly_exported
            finally:
                # Export failure never reached the receiver; release its row
                # and partial ZIP. A ready row is retained for exact-SHA retry.
                with closing(connect(self.settings)) as db:
                    current = db.execute(
                        "SELECT status FROM direct_transfer_outbox WHERE id=?",
                        (outbox_id,),
                    ).fetchone()
                    if current is not None and current["status"] == "exporting":
                        self._discard_locked(owner_user_id, outbox_id, key, delete_row=True)
        finally:
            lock.release()

    def publish(self, outbox_id: str, archive: Path) -> None:
        try:
            details = archive.lstat()
        except FileNotFoundError as exc:
            raise DirectOutboxError("missing_snapshot", "Source snapshot is missing.") from exc
        if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= MAX_BUNDLE_BYTES:
            raise DirectOutboxError("invalid_size", "Source snapshot size is invalid.")
        if shutil.disk_usage(self.root).free < max(MIN_FREE_BYTES, self.settings.storage_min_free_bytes):
            raise DirectOutboxError("outbox_full", "Insufficient free space for the source snapshot.")
        if os.name != "nt":
            archive.chmod(0o600)
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM direct_transfer_outbox WHERE id=?", (outbox_id,),
            ).fetchone()
            if row is None or row["status"] != "exporting":
                raise DirectOutboxError("wrong_state", "Source snapshot is not ready for publication.")
            db.execute(
                """UPDATE direct_transfer_outbox SET status='ready',size=?,updated_at=?
                   WHERE id=?""",
                (details.st_size, int(time.time()), outbox_id),
            )

    def complete(self, outbox_id: str, archive: Path) -> None:
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM direct_transfer_outbox WHERE id=?", (outbox_id,),
            ).fetchone()
            if row is None or row["status"] != "ready":
                raise DirectOutboxError("wrong_state", "Source snapshot is not ready.")
            db.execute(
                "UPDATE direct_transfer_outbox SET status='completed',updated_at=? WHERE id=?",
                (int(time.time()), outbox_id),
            )
        archive.unlink(missing_ok=True)
        with closing(connect(self.settings)) as db, db:
            db.execute("DELETE FROM direct_transfer_outbox WHERE id=?", (outbox_id,))

    def cleanup_stale(self) -> int:
        now = int(time.time())
        with closing(connect(self.settings)) as db:
            rows = db.execute(
                """SELECT id,owner_user_id,lock_key FROM direct_transfer_outbox
                   WHERE status IN ('exporting','completed') OR updated_at<=?
                   LIMIT 100""",
                (now - OUTBOX_TTL_SECONDS,),
            ).fetchall()
        cleaned = 0
        for row in rows:
            lock = ProcessFileLock(self.lock_root / f"{row['lock_key']}.lock")
            if not lock.try_acquire():
                continue
            try:
                with closing(connect(self.settings)) as db:
                    current = db.execute(
                        "SELECT * FROM direct_transfer_outbox WHERE id=?", (row["id"],),
                    ).fetchone()
                    if current is None or (current["status"] not in {"exporting", "completed"}
                                           and current["updated_at"] > now - OUTBOX_TTL_SECONDS):
                        continue
                    self._discard_locked(
                        current["owner_user_id"], current["id"], current["lock_key"],
                        delete_row=True,
                    )
                    cleaned += 1
            finally:
                lock.release()
        # A crash may occur after a ZIP is published but before its reservation
        # is released. Conversely, a reservation can outlive a deleted row.
        # Only the matching per-key lock can prove that no exporter is active.
        for reservation in self.budget.snapshot(kind=EXPORT_RESERVATION_KIND):
            reservation_key = reservation["reservation_key"]
            match = re.fullmatch(r"direct-export:([0-9a-f]{64}):([0-9a-f]{32})",
                                 reservation_key)
            if match is None:
                continue
            lock_key, outbox_id = match.groups()
            lock = ProcessFileLock(self.lock_root / f"{lock_key}.lock")
            if not lock.try_acquire():
                continue
            try:
                with closing(connect(self.settings)) as db:
                    row = db.execute(
                        "SELECT * FROM direct_transfer_outbox WHERE id=?", (outbox_id,),
                    ).fetchone()
                if row is not None and row["lock_key"] != lock_key:
                    continue
                if row is not None and row["status"] == "exporting":
                    self._discard_locked(row["owner_user_id"], outbox_id,
                                         lock_key, delete_row=True)
                    cleaned += 1
                elif row is None:
                    self._discard_locked(reservation["owner_user_id"], outbox_id,
                                         lock_key, delete_row=False)
                    cleaned += 1
                else:
                    # Ready ZIP remains available for an exact-SHA retry.
                    self.budget.release(reservation_key)
            finally:
                lock.release()
        return cleaned
