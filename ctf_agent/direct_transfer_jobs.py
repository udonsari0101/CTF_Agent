"""Owner-scoped durable status for background direct-transfer sends.

The invitation token never enters this table. A worker holds a cross-process
lock while it runs; after a process dies, status lookup marks its orphaned job
interrupted. Resubmitting the same token starts a new worker on the outbox ZIP.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path

from .db import Settings, connect
from .process_lock import ProcessFileLock


ACTIVE = ("queued", "exporting", "sending")
MAX_ACTIVE_PER_OWNER = 2
MAX_ACTIVE_GLOBAL = 4
JOB_HISTORY_SECONDS = 30 * 24 * 3600


class DirectSendJobError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class DirectSendJobs:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.lock_root = Path(settings.config_dir) / ".locks" / "direct_send_jobs"
        self.lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(connect(settings)) as db, db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS direct_transfer_send_jobs(
                   id TEXT PRIMARY KEY,
                   owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   job_key TEXT NOT NULL,
                   status TEXT NOT NULL CHECK(status IN
                       ('queued','exporting','sending','completed','failed','cancelled','interrupted')),
                   offset INTEGER NOT NULL DEFAULT 0,
                   size INTEGER,
                   result_json TEXT,
                   error_code TEXT,
                   error_text TEXT,
                   cancel_requested INTEGER NOT NULL DEFAULT 0,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL)"""
            )
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_direct_send_owner
                   ON direct_transfer_send_jobs(owner_user_id,status,updated_at)"""
            )
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_direct_send_key
                   ON direct_transfer_send_jobs(job_key,created_at)"""
            )

    @staticmethod
    def key(owner: str, workspace_id: str, challenge_id: str | None,
            destination_url: str, token: str, include_remote: bool) -> str:
        parts = (owner, workspace_id, challenge_id or "", destination_url,
                 hashlib.sha256(token.encode()).hexdigest(), str(int(include_remote)))
        return hashlib.sha256("\0".join(parts).encode()).hexdigest()

    def _lock(self, key: str) -> ProcessFileLock:
        return ProcessFileLock(self.lock_root / f"{key}.lock")

    @staticmethod
    def _row(db: sqlite3.Connection, job_id: str, owner: str):
        if (not isinstance(job_id, str) or len(job_id) != 32
                or any(char not in "0123456789abcdef" for char in job_id)):
            raise DirectSendJobError("not_found", "Transfer job was not found.")
        row = db.execute(
            "SELECT * FROM direct_transfer_send_jobs WHERE id=? AND owner_user_id=?",
            (job_id, owner),
        ).fetchone()
        if row is None:
            raise DirectSendJobError("not_found", "Transfer job was not found.")
        return row

    @staticmethod
    def _result(row) -> dict:
        return {
            "job_id": row["id"], "status": row["status"],
            "offset": row["offset"], "size": row["size"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "error": row["error_text"],
            "cancel_requested": bool(row["cancel_requested"]),
        }

    def start(self, owner: str, key: str) -> tuple[dict, ProcessFileLock | None]:
        """Reserve a worker lock; caller starts a thread then passes it lock."""
        lock = self._lock(key)
        if not lock.try_acquire():
            with closing(connect(self.settings)) as db:
                row = db.execute(
                    """SELECT * FROM direct_transfer_send_jobs WHERE job_key=?
                       AND owner_user_id=? AND status IN ('queued','exporting','sending')
                       ORDER BY created_at DESC LIMIT 1""",
                    (key, owner),
                ).fetchone()
                if row is not None:
                    return self._result(row), None
            raise DirectSendJobError("busy", "A transfer is already starting.")
        try:
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                last = db.execute(
                    """SELECT * FROM direct_transfer_send_jobs
                       WHERE job_key=? AND owner_user_id=?
                       ORDER BY created_at DESC LIMIT 1""",
                    (key, owner),
                ).fetchone()
                if last is not None and last["status"] == "completed":
                    result = self._result(last)
                    lock.release()
                    return result, None
                # Acquiring the lock proves no old worker is alive, even when
                # a killed process left its durable status as sending.
                if last is not None and last["status"] in ACTIVE:
                    db.execute(
                        """UPDATE direct_transfer_send_jobs SET status='interrupted',
                           error_code='interrupted',error_text='Transfer worker stopped; retry with the same invitation.',
                           updated_at=? WHERE id=?""",
                        (int(time.time()), last["id"]),
                    )
                owner_active = db.execute(
                    """SELECT COUNT(*) FROM direct_transfer_send_jobs
                       WHERE owner_user_id=? AND status IN ('queued','exporting','sending')""",
                    (owner,),
                ).fetchone()[0]
                global_active = db.execute(
                    """SELECT COUNT(*) FROM direct_transfer_send_jobs
                       WHERE status IN ('queued','exporting','sending')"""
                ).fetchone()[0]
                if owner_active >= MAX_ACTIVE_PER_OWNER or global_active >= MAX_ACTIVE_GLOBAL:
                    raise DirectSendJobError("owner_limit", "Too many active direct transfers.")
                job_id = uuid.uuid4().hex
                now = int(time.time())
                db.execute(
                    """INSERT INTO direct_transfer_send_jobs
                       (id,owner_user_id,job_key,status,created_at,updated_at)
                       VALUES(?,?,?,'queued',?,?)""",
                    (job_id, owner, key, now, now),
                )
            return self.status(owner, job_id), lock
        except BaseException:
            lock.release()
            raise

    def _reconcile(self, job_id: str, owner: str, key: str) -> bool:
        lock = self._lock(key)
        if not lock.try_acquire():
            return False
        try:
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                row = self._row(db, job_id, owner)
                if row["status"] in ACTIVE:
                    db.execute(
                        """UPDATE direct_transfer_send_jobs SET status='interrupted',
                           error_code='interrupted',error_text='Transfer worker stopped; retry with the same invitation.',
                           updated_at=? WHERE id=?""",
                        (int(time.time()), job_id),
                    )
                    return True
        finally:
            lock.release()
        return False

    def cleanup_stale(self) -> int:
        """Reconcile up to 100 dead workers and trim old terminal statuses."""
        with closing(connect(self.settings)) as db:
            rows = db.execute(
                """SELECT id,owner_user_id,job_key FROM direct_transfer_send_jobs
                   WHERE status IN ('queued','exporting','sending') LIMIT 100"""
            ).fetchall()
        reconciled = sum(self._reconcile(row["id"], row["owner_user_id"], row["job_key"])
                         for row in rows)
        with closing(connect(self.settings)) as db, db:
            old = db.execute(
                """SELECT id FROM direct_transfer_send_jobs
                   WHERE status IN ('completed','failed','cancelled','interrupted')
                     AND updated_at<? LIMIT 100""",
                (int(time.time()) - JOB_HISTORY_SECONDS,),
            ).fetchall()
            for row in old:
                db.execute("DELETE FROM direct_transfer_send_jobs WHERE id=?", (row["id"],))
        return reconciled + len(old)

    def status(self, owner: str, job_id: str) -> dict:
        with closing(connect(self.settings)) as db:
            row = self._row(db, job_id, owner)
        if row["status"] in ACTIVE:
            self._reconcile(job_id, owner, row["job_key"])
            with closing(connect(self.settings)) as db:
                row = self._row(db, job_id, owner)
        return self._result(row)

    def cancelled(self, job_id: str) -> bool:
        with closing(connect(self.settings)) as db:
            row = db.execute(
                "SELECT cancel_requested FROM direct_transfer_send_jobs WHERE id=?",
                (job_id,),
            ).fetchone()
        return row is None or bool(row[0])

    def update(self, job_id: str, status: str, *, offset: int | None = None,
               size: int | None = None) -> None:
        if status not in ACTIVE:
            raise ValueError("Invalid active job status")
        with closing(connect(self.settings)) as db, db:
            db.execute(
                """UPDATE direct_transfer_send_jobs SET status=?,
                   offset=COALESCE(?,offset),size=COALESCE(?,size),updated_at=?
                   WHERE id=? AND status IN ('queued','exporting','sending')""",
                (status, offset, size, int(time.time()), job_id),
            )

    def finish(self, job_id: str, result: dict) -> None:
        with closing(connect(self.settings)) as db, db:
            db.execute(
                """UPDATE direct_transfer_send_jobs SET status='completed',
                   result_json=?,error_code=NULL,error_text=NULL,updated_at=?
                   WHERE id=?""",
                (json.dumps(result, separators=(",", ":")), int(time.time()), job_id),
            )

    def fail(self, job_id: str, code: str, message: str) -> None:
        cancelled = code == "cancelled" or self.cancelled(job_id)
        with closing(connect(self.settings)) as db, db:
            db.execute(
                """UPDATE direct_transfer_send_jobs SET status=?,error_code=?,
                   error_text=?,updated_at=? WHERE id=?
                   AND status IN ('queued','exporting','sending')""",
                ("cancelled" if cancelled else "failed", code, message,
                 int(time.time()), job_id),
            )

    def cancel(self, owner: str, job_id: str) -> dict:
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, job_id, owner)
            if row["status"] in ACTIVE:
                db.execute(
                    """UPDATE direct_transfer_send_jobs SET cancel_requested=1,
                       updated_at=? WHERE id=?""",
                    (int(time.time()), job_id),
                )
        return self.status(owner, job_id)
