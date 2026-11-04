"""Durable source ZIP snapshot for retrying the same direct invitation.

Only a hash of the invitation token is persisted. A failed network send keeps
the exact exported ZIP so a later request, even after process restart, can
resume the receiver's offset and checksum. Stale snapshots expire after seven
days; active sends hold a cross-process lock that cleanup will not bypass.
"""

from __future__ import annotations

import hashlib
import os
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


OUTBOX_TTL_SECONDS = 7 * 24 * 3600
MAX_ACTIVE_PER_OWNER = 2
MAX_OWNER_BYTES = 40 * 1024**3
MAX_GLOBAL_BYTES = 100 * 1024**3


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
    def __init__(self, settings: Settings):
        self.settings = settings
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
                # receiver has never seen it, so a fresh export is safe.
                if archive.is_symlink():
                    raise DirectOutboxError("unsafe_path", "Source snapshot path is invalid.")
                archive.unlink(missing_ok=True)
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
                with closing(connect(self.settings)) as db, db:
                    current = db.execute(
                        "SELECT status FROM direct_transfer_outbox WHERE id=?",
                        (outbox_id,),
                    ).fetchone()
                    if current is not None and current["status"] == "exporting":
                        db.execute("DELETE FROM direct_transfer_outbox WHERE id=?", (outbox_id,))
                        archive.unlink(missing_ok=True)
        finally:
            lock.release()

    def publish(self, outbox_id: str, archive: Path) -> None:
        try:
            details = archive.lstat()
        except FileNotFoundError as exc:
            raise DirectOutboxError("missing_snapshot", "Source snapshot is missing.") from exc
        if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= MAX_BUNDLE_BYTES:
            raise DirectOutboxError("invalid_size", "Source snapshot exceeds the direct transfer limit.")
        if os.name != "nt":
            archive.chmod(0o600)
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM direct_transfer_outbox WHERE id=?", (outbox_id,),
            ).fetchone()
            if row is None or row["status"] != "exporting":
                raise DirectOutboxError("wrong_state", "Source snapshot is not ready for publication.")
            owner_bytes = db.execute(
                """SELECT COALESCE(SUM(size),0) FROM direct_transfer_outbox
                   WHERE owner_user_id=? AND status='ready'""",
                (row["owner_user_id"],),
            ).fetchone()[0]
            global_bytes = db.execute(
                "SELECT COALESCE(SUM(size),0) FROM direct_transfer_outbox WHERE status='ready'"
            ).fetchone()[0]
            if (owner_bytes + details.st_size > MAX_OWNER_BYTES
                    or global_bytes + details.st_size > MAX_GLOBAL_BYTES):
                raise DirectOutboxError("outbox_full", "Source transfer snapshot limit was reached.")
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
                   WHERE status='completed' OR updated_at<=?
                   LIMIT 100""",
                (now - OUTBOX_TTL_SECONDS,),
            ).fetchall()
        cleaned = 0
        for row in rows:
            lock = ProcessFileLock(self.lock_root / f"{row['lock_key']}.lock")
            if not lock.try_acquire():
                continue
            try:
                with closing(connect(self.settings)) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    current = db.execute(
                        "SELECT * FROM direct_transfer_outbox WHERE id=?", (row["id"],),
                    ).fetchone()
                    if current is None or (current["status"] != "completed"
                                           and current["updated_at"] > now - OUTBOX_TTL_SECONDS):
                        continue
                    archive = self._archive(current["owner_user_id"], current["id"])
                    if archive.is_symlink():
                        raise DirectOutboxError("unsafe_path", "Source snapshot path is invalid.")
                    archive.unlink(missing_ok=True)
                    db.execute("DELETE FROM direct_transfer_outbox WHERE id=?", (current["id"],))
                    cleaned += 1
            finally:
                lock.release()
        return cleaned
