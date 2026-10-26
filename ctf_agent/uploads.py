"""Persistent resumable original-file uploads. Files are never opened as programs."""
import asyncio
import hashlib
import os
import re
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from fastapi import Body, Depends, HTTPException
from pydantic import BaseModel, Field

from .process_lock import ProcessFileLock
from .storage_budget import StorageBudgetError, get_storage_budget

CHUNK_BYTES = 8 * 1024 * 1024
EXPIRY_SECONDS = 7 * 24 * 3600
MAX_ACTIVE_UPLOADS_PER_USER = 16


class UploadInit(BaseModel):
    name: str = Field(min_length=1, max_length=240)
    size: int = Field(ge=0, le=2**63 - 1)
    last_modified: int | None = None
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class UploadManager:
    def __init__(self, app, settings, validate_filename, stamp):
        self.app, self.settings = app, settings
        self.layout = app.state.storage_layout
        self.validate_filename, self.stamp = validate_filename, stamp
        self.root = (settings.data_dir / "workspaces" / ".uploads").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        lock_base = Path(getattr(settings, "config_dir", settings.data_dir))
        self.process_lock_root = lock_base / ".locks" / "uploads"
        self.locks, self.workspace_locks, self.lock_guard = {}, {}, threading.Lock()
        # Finalizing hashes the complete (potentially multi-GiB) file. Keep
        # that CPU/disk work within the two CPU web-container budget and make
        # duplicate requests fail before they queue on a workspace lock.
        self.finalize_slot_lock = threading.Lock()
        self.finalize_inflight_total = 0
        self.finalize_inflight_by_owner = {}
        with self.db() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS upload_sessions (
                id TEXT PRIMARY KEY,owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
                name TEXT NOT NULL,size INTEGER NOT NULL,last_modified INTEGER,offset INTEGER NOT NULL DEFAULT 0,
                expected_sha256 TEXT,sha256 TEXT,status TEXT NOT NULL DEFAULT 'uploading',
                attachment_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_upload_owner ON upload_sessions(owner_user_id,status,updated_at);
                CREATE TABLE IF NOT EXISTS upload_chunks (
                upload_id TEXT NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
                offset INTEGER NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,PRIMARY KEY(upload_id,offset));""")
        self.budget = get_storage_budget(app, settings)
        self.reconcile()

    @contextmanager
    def db(self):
        connection = self.app.state.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def lock(self, upload_id):
        with self.lock_guard:
            return self.locks.setdefault(upload_id, threading.Lock())

    def workspace_lock(self, workspace_id):
        with self.lock_guard:
            return self.workspace_locks.setdefault(workspace_id, threading.RLock())

    def process_workspace_lock(self, workspace_id):
        digest = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
        return ProcessFileLock(self.process_lock_root / f"workspace-{digest}.lock")

    @contextmanager
    def try_workspace_lock(self, workspace_id):
        """Enter a web workspace lifecycle lock without parking a worker."""
        lock = self.workspace_lock(workspace_id)
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "이 작업공간에서 다른 저장 작업이 진행 중입니다. 잠시 후 다시 시도해 주세요.")
        process_lock = self.process_workspace_lock(workspace_id)
        if not process_lock.try_acquire():
            lock.release()
            raise HTTPException(409, "다른 서버 프로세스에서 이 작업공간을 저장 중입니다. 잠시 후 다시 시도해 주세요.")
        try:
            yield
        finally:
            process_lock.release()
            lock.release()

    @contextmanager
    def finalize_slot(self, owner_user_id):
        """Reserve one owner slot and one of two global hashing slots."""
        with self.finalize_slot_lock:
            if self.finalize_inflight_by_owner.get(owner_user_id, 0):
                raise HTTPException(409, "이미 완료 검증 중인 첨부파일이 있습니다.")
            if self.finalize_inflight_total >= 2:
                raise HTTPException(429, "첨부파일 완료 검증이 사용 중입니다. 잠시 후 다시 시도해 주세요.")
            self.finalize_inflight_total += 1
            self.finalize_inflight_by_owner[owner_user_id] = 1
        try:
            yield
        finally:
            with self.finalize_slot_lock:
                self.finalize_inflight_total -= 1
                self.finalize_inflight_by_owner.pop(owner_user_id, None)

    def stage(self, row):
        owner, upload_id = row["owner_user_id"], row["id"]
        if not all(re.fullmatch(r"[0-9a-f]{32}", value) for value in (owner, upload_id)):
            raise HTTPException(400, "잘못된 업로드 경로입니다.")
        target = (self.root / owner / f"{upload_id}.part").resolve()
        if not target.is_relative_to(self.root):
            raise HTTPException(400, "잘못된 업로드 경로입니다.")
        return target

    def cleanup_unpublished(self, row) -> None:
        """Remove only this session's verified regular crash-tail files."""

        paths = [
            self.stage(row),
            self.layout.legacy_attachment_path(
                row["workspace_id"], row["challenge_id"], row["attachment_id"],
                create_parent=False,
            ),
        ]
        removable = []
        for path in paths:
            try:
                details = os.lstat(path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(details.st_mode):
                raise OSError("unsafe unpublished upload artifact")
            removable.append(path)
        for path in removable:
            path.unlink()

    @staticmethod
    def reservation(upload_id):
        return "upload:" + upload_id

    def reconcile(self):
        """Recover crash tails and rebuild future-byte reservations."""
        def rebuild():
            with self.db() as db:
                rows = db.execute("SELECT * FROM upload_sessions WHERE status='uploading'").fetchall()
            expected = {}
            active_stages = set()
            for row in rows:
                target = destination = None
                try:
                    target = self.stage(row)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.is_symlink():
                        raise OSError("symlink upload stage")
                    offset, size = int(row["offset"]), int(row["size"])
                    destination = self.layout.legacy_attachment_path(
                        row["workspace_id"], row["challenge_id"], row["attachment_id"],
                        create_parent=True,
                    )
                    if not target.exists():
                        # finalize uses an atomic move before its metadata commit. A
                        # crash in that gap is retryable from this unpublished file.
                        if (offset == size and destination.is_file() and
                                not destination.is_symlink() and destination.stat().st_size == size):
                            expected[self.reservation(row["id"])] = (
                                row["owner_user_id"], row["workspace_id"], row["challenge_id"], 0
                            )
                            continue
                        if offset:
                            raise OSError("missing upload stage")
                        with target.open("xb") as handle:
                            handle.flush()
                            os.fsync(handle.fileno())
                    actual = target.stat().st_size
                    if not 0 <= offset <= size or actual < offset:
                        raise OSError("incomplete upload stage")
                    if actual > offset:
                        with target.open("r+b") as handle:
                            handle.truncate(offset)
                            handle.flush()
                            os.fsync(handle.fileno())
                    active_stages.add(target)
                    # Uploads reserve only the chunk currently being written.
                    # A declared multi-gigabyte size must not hold the shared
                    # volume hostage while no bytes are in flight.
                except (OSError, HTTPException):
                    try:
                        self.cleanup_unpublished(row)
                    except OSError:
                        pass
                    with self.db() as db:
                        db.execute(
                            "UPDATE upload_sessions SET status='cancelled',updated_at=? WHERE id=?",
                            (int(time.time()), row["id"]),
                        )
                        self.layout.forget(db, "attachment", row["attachment_id"])
            for orphan in self.root.glob("*/*.part"):
                if (orphan in active_stages or not re.fullmatch(r"[0-9a-f]{32}", orphan.parent.name)
                        or not re.fullmatch(r"[0-9a-f]{32}\.part", orphan.name)):
                    continue
                try:
                    orphan.unlink(missing_ok=True)
                except OSError:
                    pass
            return expected

        self.budget.reconcile_kind("upload", rebuild)

    def challenge(self, workspace_id, challenge_id, user):
        self.app.state.require_workspace_owner(workspace_id, user)
        with self.db() as db:
            if not db.execute("SELECT 1 FROM challenges WHERE id=? AND workspace_id=?", (challenge_id, workspace_id)).fetchone():
                raise HTTPException(404, "문제를 찾을 수 없습니다.")

    def row(self, upload_id, user, validate_challenge=True):
        with self.db() as db:
            row = db.execute("SELECT * FROM upload_sessions WHERE id=? AND owner_user_id=?", (upload_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "업로드를 찾을 수 없습니다.")
        if validate_challenge:
            self.challenge(row["workspace_id"], row["challenge_id"], user)
        return row

    def result(self, row):
        return {key: row[key] for key in ("id", "workspace_id", "challenge_id", "name", "size", "offset", "status", "last_modified", "sha256", "attachment_id", "updated_at")} | {"chunk_bytes": CHUNK_BYTES}

    def create(self, workspace_id, challenge_id, payload, user):
        self.challenge(workspace_id, challenge_id, user)
        name = self.validate_filename(payload.name)
        upload_id, attachment_id, timestamp = uuid.uuid4().hex, uuid.uuid4().hex, int(time.time())
        target = (self.root / user["id"] / f"{upload_id}.part").resolve()
        if not target.is_relative_to(self.root):
            raise HTTPException(400, "잘못된 업로드 경로입니다.")
        try:
            def prepare():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as handle:
                    handle.flush()
                    os.fsync(handle.fileno())
            def insert(connection):
                solver = getattr(self.app.state, "solver_jobs", None)
                if solver is not None and solver.has_open_challenge(
                    user["id"], workspace_id, challenge_id, connection=connection
                ):
                    raise HTTPException(
                        409,
                        "풀이가 대기 또는 실행 중입니다. 중단과 격리 정리가 끝난 뒤 첨부를 올려 주세요.",
                    )
                ctfd_table = connection.execute(
                    """SELECT 1 FROM sqlite_master
                        WHERE type='table' AND name='ctfd_jobs'"""
                ).fetchone()
                if ctfd_table:
                    columns = {
                        row[1] for row in connection.execute("PRAGMA table_info(ctfd_jobs)")
                    }
                    if {"mode", "target_challenge_id"} <= columns and connection.execute(
                        """SELECT 1 FROM ctfd_jobs
                            WHERE owner_user_id=? AND workspace_id=?
                              AND mode='refresh' AND target_challenge_id=?
                              AND status IN ('queued','running') LIMIT 1""",
                        (user["id"], workspace_id, challenge_id),
                    ).fetchone():
                        raise HTTPException(
                            409,
                            "CTFd refresh is in progress. Add the attachment after it finishes.",
                        )
                active = connection.execute(
                    "SELECT COUNT(*) FROM upload_sessions WHERE owner_user_id=? AND status='uploading'",
                    (user["id"],),
                ).fetchone()[0]
                if active >= MAX_ACTIVE_UPLOADS_PER_USER:
                    raise HTTPException(
                        429,
                        f"동시에 진행할 수 있는 업로드는 사용자당 {MAX_ACTIVE_UPLOADS_PER_USER}개입니다. "
                        "기존 업로드를 완료하거나 취소한 뒤 다시 시도하세요.",
                    )
                self.layout.reserve_attachment(
                    connection, workspace_id, challenge_id, attachment_id, name
                )
                connection.execute("""INSERT INTO upload_sessions(id,owner_user_id,workspace_id,challenge_id,name,size,last_modified,
                    expected_sha256,attachment_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (upload_id, user["id"], workspace_id, challenge_id, name, payload.size, payload.last_modified,
                     payload.sha256, attachment_id, timestamp, timestamp))
            self.budget.reserve(
                self.reservation(upload_id), "upload", user["id"], workspace_id,
                challenge_id, 0, db_update=insert, prepare=prepare,
            )
        except StorageBudgetError as exc:
            target.unlink(missing_ok=True)
            raise HTTPException(507, str(exc)) from None
        except HTTPException:
            target.unlink(missing_ok=True)
            raise
        except OSError:
            target.unlink(missing_ok=True)
            raise HTTPException(507, "업로드 임시 파일을 만들 수 없습니다.") from None
        row = self.row(upload_id, user)
        return self.result(row)

    def chunk(self, upload_id, offset, content, user):
        if not content or len(content) > CHUNK_BYTES:
            raise HTTPException(413, f"청크는 1바이트 이상 {CHUNK_BYTES // (1024 * 1024)}MiB 이하로 보내 주세요.")
        if offset < 0:
            raise HTTPException(400, "잘못된 업로드 위치입니다.")
        checksum = hashlib.sha256(content).hexdigest()
        self.row(upload_id, user)
        with self.lock(upload_id):
            row = self.row(upload_id, user)
            if row["status"] != "uploading":
                raise HTTPException(409, "진행 중인 업로드가 아닙니다.")
            with self.db() as db:
                previous = db.execute("SELECT size,sha256 FROM upload_chunks WHERE upload_id=? AND offset=?", (upload_id, offset)).fetchone()
            if previous:
                if previous["size"] != len(content) or previous["sha256"] != checksum:
                    raise HTTPException(409, "같은 위치에 다른 청크가 이미 저장되어 있습니다.")
                return self.result(row)
            if offset != row["offset"] or offset + len(content) > row["size"]:
                raise HTTPException(409, "업로드 위치가 다릅니다. 진행 상태를 다시 확인하세요.")
            target = self.stage(row)

            def precheck(connection):
                current = connection.execute(
                    "SELECT * FROM upload_sessions WHERE id=? AND owner_user_id=?",
                    (upload_id, user["id"]),
                ).fetchone()
                if not current or current["status"] != "uploading":
                    raise HTTPException(409, "진행 중인 업로드가 아닙니다.")
                committed = connection.execute(
                    "SELECT size,sha256 FROM upload_chunks WHERE upload_id=? AND offset=?",
                    (upload_id, offset),
                ).fetchone()
                if committed:
                    if committed["size"] != len(content) or committed["sha256"] != checksum:
                        raise HTTPException(409, "같은 위치에 다른 청크가 이미 저장되어 있습니다.")
                    return False
                if current["offset"] != offset or offset + len(content) > current["size"]:
                    raise HTTPException(409, "업로드 위치가 다릅니다. 진행 상태를 다시 확인하세요.")
                return True

            def write():
                with target.open("r+b") as handle:
                    if handle.seek(0, 2) < offset:
                        raise HTTPException(409, "임시 파일이 불완전합니다. 새 업로드를 시작하세요.")
                    handle.seek(offset)
                    handle.write(content)
                    handle.truncate(offset + len(content))
                    handle.flush()
                    os.fsync(handle.fileno())

            def commit(connection):
                connection.execute(
                    "INSERT INTO upload_chunks VALUES(?,?,?,?)",
                    (upload_id, offset, len(content), checksum),
                )
                connection.execute(
                    "UPDATE upload_sessions SET offset=?,updated_at=? WHERE id=?",
                    (offset + len(content), int(time.time()), upload_id),
                )
            try:
                # Reserve one bounded chunk immediately before it is written.
                # This keeps arbitrary total file sizes resumable without
                # allowing an idle declaration to exhaust all shared capacity.
                self.budget.reserve(
                    self.reservation(upload_id), "upload", row["owner_user_id"],
                    row["workspace_id"], row["challenge_id"], len(content),
                )
                self.budget.commit_reserved_write(
                    self.reservation(upload_id), len(content), write,
                    precheck=precheck, db_update=commit,
                )
            except StorageBudgetError as exc:
                raise HTTPException(507, str(exc)) from None
            except OSError:
                raise HTTPException(507, "청크를 저장하지 못했습니다. 공간을 확인하고 이어서 올려 주세요.") from None
            return self.result(self.row(upload_id, user))

    def finalize(self, upload_id, user):
        self.row(upload_id, user)
        with self.lock(upload_id):
            row = self.row(upload_id, user)
            if row["status"] == "completed":
                return self.result(row)
            if row["status"] != "uploading" or row["offset"] != row["size"]:
                raise HTTPException(409, "파일 전송을 먼저 완료하세요.")
            try:
                destination = self.layout.legacy_attachment_path(
                    row["workspace_id"], row["challenge_id"], row["attachment_id"],
                    create_parent=True,
                )
            except ValueError:
                raise HTTPException(400, "잘못된 첨부 경로입니다.") from None
            directory, source = destination.parent, self.stage(row)
            candidate = source if source.exists() else destination
            if not candidate.is_file() or candidate.stat().st_size != row["size"]:
                raise HTTPException(409, "파일 크기가 일치하지 않습니다. 업로드 상태를 확인하세요.")
            checksum = hashlib.sha256()
            with candidate.open("rb") as handle:
                while piece := handle.read(1024 * 1024):
                    checksum.update(piece)
            digest = checksum.hexdigest()
            if row["expected_sha256"] and digest != row["expected_sha256"]:
                raise HTTPException(409, "파일 검증값이 일치하지 않습니다. 원본 파일을 확인하세요.")
            # Atomic rename and deterministic attachment IDs make finalize retryable
            # even if the process stops after renaming but before the DB commit.
            self.challenge(row["workspace_id"], row["challenge_id"], user)

            def publish():
                if source.exists():
                    if destination.exists():
                        raise HTTPException(409, "첨부 저장 위치를 확인할 수 없습니다.")
                    os.replace(source, destination)
                    if hasattr(os, "O_DIRECTORY"):
                        descriptor = os.open(directory, os.O_DIRECTORY)
                        try:
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)

            def ready(connection):
                current = connection.execute(
                    "SELECT status,offset,size FROM upload_sessions WHERE id=? AND owner_user_id=?",
                    (upload_id, user["id"]),
                ).fetchone()
                if current and current["status"] == "completed":
                    return False
                if (not current or current["status"] != "uploading"
                        or current["offset"] != current["size"]):
                    raise HTTPException(409, "파일 전송 상태가 변경되었습니다.")
                return True

            def complete(connection):
                connection.execute("INSERT OR IGNORE INTO attachments(id,workspace_id,challenge_id,original_name,stored_name,size,created_at) VALUES(?,?,?,?,?,?,?)",
                                   (row["attachment_id"], row["workspace_id"], row["challenge_id"], row["name"], row["attachment_id"], row["size"], self.stamp()))
                attachment = connection.execute(
                    "SELECT * FROM attachments WHERE id=?", (row["attachment_id"],)
                ).fetchone()
                self.layout.ensure_attachment_view(
                    connection, row["workspace_id"], row["challenge_id"],
                    attachment, view_wins=False,
                )
                connection.execute("UPDATE upload_sessions SET status='completed',sha256=?,updated_at=? WHERE id=?", (digest, int(time.time()), upload_id))
            self.budget.release(
                self.reservation(upload_id), db_update=complete,
                cleanup=publish, precheck=ready,
            )
            return self.result(self.row(upload_id, user))

    def cancel(self, upload_id, user):
        self.row(upload_id, user, validate_challenge=False)
        with self.lock(upload_id):
            row = self.row(upload_id, user, validate_challenge=False)
            if row["status"] == "completed":
                raise HTTPException(409, "완료된 파일은 문제의 첨부파일 메뉴에서 삭제하세요.")
            target = self.stage(row)

            def cancellable(connection):
                current = connection.execute(
                    "SELECT status FROM upload_sessions WHERE id=? AND owner_user_id=?",
                    (upload_id, user["id"]),
                ).fetchone()
                if current and current["status"] == "completed":
                    raise HTTPException(409, "완료된 파일은 문제의 첨부파일 메뉴에서 삭제하세요.")
                return True

            self.budget.release(
                self.reservation(upload_id),
                db_update=lambda connection: (
                    connection.execute(
                        "UPDATE upload_sessions SET status='cancelled',updated_at=? WHERE id=?",
                        (int(time.time()), upload_id),
                    ),
                    self.layout.forget(connection, "attachment", row["attachment_id"]),
                ),
                cleanup=lambda: self.cleanup_unpublished(row),
                precheck=cancellable,
            )
            return {"ok": True}

    def cleanup(self):
        with self.db() as db:
            rows = db.execute("SELECT * FROM upload_sessions WHERE status!='completed' AND updated_at<?", (int(time.time()) - EXPIRY_SECONDS,)).fetchall()
        removed = 0
        for row in rows:
            lock = self.lock(row["id"])
            if not lock.acquire(blocking=False):
                continue
            process_lock = self.process_workspace_lock(row["workspace_id"])
            if not process_lock.try_acquire():
                lock.release()
                continue
            try:
                with self.db() as db:
                    fresh = db.execute("SELECT * FROM upload_sessions WHERE id=?", (row["id"],)).fetchone()
                if not fresh or fresh["updated_at"] >= int(time.time()) - EXPIRY_SECONDS or fresh["status"] == "completed":
                    continue
                target = self.stage(fresh)
                threshold = int(time.time()) - EXPIRY_SECONDS

                def still_stale(connection, upload_id=row["id"]):
                    current = connection.execute(
                        "SELECT status,updated_at FROM upload_sessions WHERE id=?", (upload_id,)
                    ).fetchone()
                    return current is None or (
                        current["status"] != "completed" and current["updated_at"] < threshold
                    )

                released = self.budget.release(
                    self.reservation(row["id"]),
                    db_update=lambda connection, upload_id=row["id"], attachment_id=row["attachment_id"]: (
                        connection.execute("DELETE FROM upload_sessions WHERE id=?", (upload_id,)),
                        self.layout.forget(connection, "attachment", attachment_id),
                    ),
                    cleanup=lambda: self.cleanup_unpublished(fresh),
                    precheck=still_stale,
                )
                removed += int(released)
            finally:
                process_lock.release()
                lock.release()
        return {"removed": removed, "expiry_days": 7}

    def cancel_workspace(self, workspace_id, user, challenge_id=None):
        with self.db() as db:
            rows = db.execute("SELECT * FROM upload_sessions WHERE workspace_id=? AND owner_user_id=? AND status='uploading'", (workspace_id, user["id"])).fetchall()
        for row in rows:
            if challenge_id and row["challenge_id"] != challenge_id:
                continue
            lock = self.lock(row["id"])
            if not lock.acquire(blocking=False):
                return False
            try:
                target = self.stage(row)

                def still_uploading(connection, upload_id=row["id"]):
                    current = connection.execute(
                        "SELECT status FROM upload_sessions WHERE id=?", (upload_id,)
                    ).fetchone()
                    return bool(current and current["status"] == "uploading")

                self.budget.release(
                    self.reservation(row["id"]),
                    db_update=lambda connection, upload_id=row["id"], attachment_id=row["attachment_id"]: (
                        connection.execute(
                            "UPDATE upload_sessions SET status='cancelled',updated_at=? WHERE id=?",
                            (int(time.time()), upload_id),
                        ),
                        self.layout.forget(connection, "attachment", attachment_id),
                    ),
                    cleanup=lambda: self.cleanup_unpublished(row),
                    precheck=still_uploading,
                )
            finally:
                lock.release()
        return True

    def cancel_challenge(self, workspace_id, challenge_id, user):
        return self.cancel_workspace(workspace_id, user, challenge_id)


def register_uploads(app, require_auth, settings, validate_filename, stamp):
    manager = UploadManager(app, settings, validate_filename, stamp)
    app.state.uploads = manager

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/uploads", status_code=201)
    def initialize(workspace_id: str, challenge_id: str, payload: UploadInit, user: dict = Depends(require_auth)):
        manager.challenge(workspace_id, challenge_id, user)
        with manager.try_workspace_lock(workspace_id):
            return manager.create(workspace_id, challenge_id, payload, user)

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/uploads")
    def list_uploads(workspace_id: str, challenge_id: str, user: dict = Depends(require_auth)):
        manager.challenge(workspace_id, challenge_id, user)
        with manager.db() as db:
            rows = db.execute("SELECT * FROM upload_sessions WHERE owner_user_id=? AND workspace_id=? AND challenge_id=? AND status='uploading' ORDER BY created_at", (user["id"], workspace_id, challenge_id)).fetchall()
        return {"uploads": [manager.result(row) for row in rows]}

    @app.get("/api/uploads/{upload_id}")
    def status(upload_id: str, user: dict = Depends(require_auth)):
        return manager.result(manager.row(upload_id, user))

    @app.get("/api/uploads/{upload_id}/chunks")
    def manifest(upload_id: str, start: int = 0, user: dict = Depends(require_auth)):
        manager.row(upload_id, user)
        with manager.db() as db:
            rows = db.execute("SELECT offset,size,sha256 FROM upload_chunks WHERE upload_id=? AND offset>=? ORDER BY offset LIMIT 1000", (upload_id, max(0, start))).fetchall()
        return {"chunks": [dict(row) for row in rows], "next_offset": rows[-1]["offset"] + rows[-1]["size"] if len(rows) == 1000 else None}

    @app.put("/api/uploads/{upload_id}/chunks")
    def put_chunk(upload_id: str, offset: int, content: bytes = Body(media_type="application/octet-stream"), user: dict = Depends(require_auth)):
        row = manager.row(upload_id, user)
        with manager.try_workspace_lock(row["workspace_id"]):
            return manager.chunk(upload_id, offset, content, user)

    @app.post("/api/uploads/{upload_id}/finalize")
    def finalize(upload_id: str, user: dict = Depends(require_auth)):
        row = manager.row(upload_id, user)
        # Acquire the nonblocking, service-specific allowance before the
        # blocking workspace lock. Duplicate requests cannot consume AnyIO's
        # shared worker threads while a multi-GiB checksum is in progress.
        with manager.finalize_slot(user["id"]):
            with manager.try_workspace_lock(row["workspace_id"]):
                return manager.finalize(upload_id, user)

    @app.delete("/api/uploads/{upload_id}")
    def cancel(upload_id: str, user: dict = Depends(require_auth)):
        row = manager.row(upload_id, user, validate_challenge=False)
        with manager.try_workspace_lock(row["workspace_id"]):
            return manager.cancel(upload_id, user)

    @app.post("/api/admin/uploads/cleanup", dependencies=[Depends(app.state.require_admin)])
    def cleanup():
        return manager.cleanup()

    async def cleanup_loop():
        while True:
            try:
                await asyncio.to_thread(manager.cleanup)
            except OSError:
                pass
            await asyncio.sleep(3600)

    cleanup_tasks = {}

    async def startup():
        cleanup_tasks[asyncio.get_running_loop()] = asyncio.create_task(cleanup_loop())

    async def shutdown():
        task = cleanup_tasks.pop(asyncio.get_running_loop(), None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app.router.add_event_handler("startup", startup)
    app.router.add_event_handler("shutdown", shutdown)
