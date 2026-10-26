"""Owner-scoped, opt-in CTFd flag submission.

Flag persistence calls this module through a best-effort queue hook.  Remote
network work always happens after the local transaction has committed, so a
slow or unavailable CTFd site cannot delay the flag appearing in the UI or a
Telegram notification.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .credential_vault import CredentialVault, CredentialVaultError
from .ctfd import CTFdClient, CTFdError, Limits, normalize_url
from .process_lock import ProcessFileLock


MAX_ATTEMPTS = 3
RETRY_DELAYS = (2, 10)
CANCEL_WAIT_SECONDS = 10.0


CONNECTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS ctfd_submit_connections (
    workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    auth_type TEXT NOT NULL CHECK(auth_type IN ('token','password')),
    credentials_ciphertext TEXT NOT NULL,
    auto_submit INTEGER NOT NULL DEFAULT 0 CHECK(auto_submit IN (0,1)),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts BETWEEN 1 AND 3),
    generation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ctfd_submit_connection_owner
    ON ctfd_submit_connections(owner_user_id,workspace_id);
CREATE TABLE IF NOT EXISTS ctfd_submit_jobs (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_generation TEXT NOT NULL,
    ctfd_id INTEGER NOT NULL,
    flag_digest TEXT NOT NULL,
    completion_source TEXT NOT NULL CHECK(completion_source IN ('manual','agent')),
    status TEXT NOT NULL CHECK(status IN (
        'queued','running','retry','correct','already_solved','incorrect',
        'rate_limited','auth_error','network_error','paused','partial','failed',
        'superseded','disabled'
    )),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    result_code TEXT,
    display_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(workspace_id,challenge_id,flag_digest)
);
CREATE INDEX IF NOT EXISTS idx_ctfd_submit_jobs_due
    ON ctfd_submit_jobs(status,next_attempt_at,created_at);
CREATE INDEX IF NOT EXISTS idx_ctfd_submit_jobs_owner
    ON ctfd_submit_jobs(owner_user_id,workspace_id,created_at);
CREATE TABLE IF NOT EXISTS ctfd_submit_worker_claim (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    job_id TEXT NOT NULL UNIQUE REFERENCES ctfd_submit_jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ctfd_submit_blocks (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY(workspace_id,challenge_id)
);
CREATE INDEX IF NOT EXISTS idx_ctfd_submit_blocks_owner
    ON ctfd_submit_blocks(owner_user_id,workspace_id);
"""


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _flag_digest(flag: str) -> str:
    return hashlib.sha256(flag.encode("utf-8")).hexdigest()


class ConnectionInput(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    auth_type: str = Field(min_length=1, max_length=20)
    token: str = Field(default="", max_length=4096)
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=4096)


class SubmissionSettingsInput(BaseModel):
    auto_submit: bool


class _CombinedCancellation:
    """Minimal cancellation interface consumed by the pinned HTTP transport."""

    def __init__(self, *events: threading.Event):
        self.events = events

    def is_set(self) -> bool:
        return any(event.is_set() for event in self.events)


class _FileCancellation:
    """Cancellation event shared through marker files across app processes."""

    def __init__(self, *markers: Path):
        self.markers = markers
        self.local = threading.Event()

    def set(self) -> None:
        self.local.set()
        for marker in self.markers:
            marker.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(marker, flags, 0o600)
            os.close(descriptor)

    def is_set(self) -> bool:
        return self.local.is_set() or any(marker.is_file() for marker in self.markers)


class CTFdSubmitService:
    def __init__(self, app, settings):
        self.app = app
        self.settings = settings
        self.vault = CredentialVault(settings)
        self.stop_event = threading.Event()
        self.wakeup = threading.Event()
        self.worker: threading.Thread | None = None
        self.cancel_lock = threading.Lock()
        self.cancel_condition = threading.Condition(self.cancel_lock)
        self.job_cancellations: dict[str, _FileCancellation] = {}
        # Saving a connection performs synchronous DNS/login/API work in
        # AnyIO's shared worker pool. Reject excess probes immediately rather
        # than allowing slow sites to exhaust threads needed by other routes.
        self.validation_slot_lock = threading.Lock()
        self.validation_condition = threading.Condition(self.validation_slot_lock)
        self.validation_inflight_total = 0
        self.validation_inflight_by_owner: dict[str, int] = {}
        self.validation_cancellations: dict[str, tuple[str, _FileCancellation]] = {}
        lock_base = Path(getattr(settings, "config_dir", getattr(settings, "data_dir", Path("."))))
        self.lock_root = lock_base / ".locks" / "ctfd-submit"
        self.worker_lock_path = self.lock_root / "worker.lock"
        with self.db() as db:
            db.executescript(CONNECTION_SCHEMA)
            db.execute("BEGIN IMMEDIATE")
            columns = {
                row["name"] for row in db.execute("PRAGMA table_info(ctfd_submit_connections)")
            }
            if "max_attempts" not in columns:
                db.execute(
                    "ALTER TABLE ctfd_submit_connections ADD COLUMN max_attempts "
                    "INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts BETWEEN 1 AND 3)"
                )
            db.execute(
                "UPDATE ctfd_submit_jobs SET status='network_error',result_code='retry_limit',"
                "display_message='자동 제출 재시도 한도에 도달했습니다.',completed_at=?,updated_at=? "
                "WHERE status IN ('queued','retry') AND attempts>=?",
                (_stamp(), _stamp(), MAX_ATTEMPTS),
            )

    @contextmanager
    def db(self):
        connection = self.app.state.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._run, name="ctfd-auto-submit", daemon=True)
        self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.wakeup.set()
        # The processing thread owns a cross-process lock and publishes its own
        # retry state while unwinding. A rolling replacement must never rewrite
        # another process's live remote claim.
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=10)
        if self.worker and not self.worker.is_alive():
            self.worker = None

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                handled = self.process_once()
            except (sqlite3.Error, OSError):
                handled = False
            if not handled:
                self.wakeup.wait(1)
                self.wakeup.clear()

    def _scope_path(self, prefix: str, value: str, suffix: str) -> Path:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return self.lock_root / f"{prefix}-{digest}.{suffix}"

    def _job_cancel_marker(self, job_id: str) -> Path:
        return self._scope_path("job", job_id, "cancel")

    def _validation_lock(self, scope: str, value: str) -> ProcessFileLock:
        return ProcessFileLock(self._scope_path(f"validation-{scope}", value, "lock"))

    def _validation_marker(self, scope: str, value: str) -> Path:
        return self._scope_path(f"validation-{scope}", value, "cancel")

    @contextmanager
    def workspace_slot(self, workspace_id: str):
        """Share the workspace lifecycle boundary with upload/delete routes.

        Connection validation can perform a password login.  Taking the same
        nonblocking workspace lease used by deletion means a delete that has
        entered its lifecycle transaction cannot be followed by a new remote
        credential request from another rolling process.
        """

        uploads = getattr(self.app.state, "uploads", None)
        if uploads is not None and hasattr(uploads, "try_workspace_lock"):
            with uploads.try_workspace_lock(workspace_id):
                yield
            return
        yield

    def _cancel_jobs(self, job_ids: list[str]) -> None:
        with self.cancel_condition:
            events = [self.job_cancellations.get(job_id) for job_id in job_ids]
        for job_id, event in zip(job_ids, events):
            try:
                (event or _FileCancellation(self._job_cancel_marker(job_id))).set()
            except OSError:
                # The worker lease wait remains the authoritative return
                # boundary even when a marker volume is temporarily unwritable.
                pass

    def _cancel_validation_scope(self, *, owner_user_id=None, workspace_id=None,
                                 wait_seconds: float = CANCEL_WAIT_SECONDS) -> bool:
        if (owner_user_id is None) == (workspace_id is None):
            raise ValueError("exactly one validation cancellation scope is required")
        with self.validation_condition:
            for owner, (active_workspace, cancellation) in list(
                self.validation_cancellations.items()
            ):
                if owner_user_id == owner or workspace_id == active_workspace:
                    try:
                        cancellation.set()
                    except OSError:
                        pass
        if owner_user_id is not None:
            scope, value = "owner", owner_user_id
        else:
            scope, value = "workspace", workspace_id
        try:
            _FileCancellation(self._validation_marker(scope, value)).set()
        except OSError:
            pass
        lease = self._validation_lock(scope, value)
        try:
            bounded_wait = float(wait_seconds)
        except (TypeError, ValueError):
            bounded_wait = CANCEL_WAIT_SECONDS
        if not math.isfinite(bounded_wait):
            bounded_wait = CANCEL_WAIT_SECONDS
        deadline = time.monotonic() + min(10.0, max(0.0, bounded_wait))
        while not lease.try_acquire():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(.02, remaining))
        lease.release()
        return True

    def cancel_owner(self, owner_user_id: str) -> bool:
        """Publish a terminal state and interrupt every job owned by a disabled user."""
        validation_stopped = self._cancel_validation_scope(owner_user_id=owner_user_id)
        timestamp = _stamp()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            job_ids = [
                row["id"] for row in db.execute(
                    """SELECT j.id FROM ctfd_submit_jobs j
                       LEFT JOIN ctfd_submit_worker_claim c ON c.job_id=j.id
                       WHERE j.owner_user_id=? AND
                         (j.status='running' OR c.job_id IS NOT NULL)""",
                    (owner_user_id,),
                )
            ]
            db.execute(
                "UPDATE ctfd_submit_jobs SET status='disabled',result_code='user_disabled',"
                "display_message='사용자 계정이 비활성화되어 자동 제출을 취소했습니다.',"
                "completed_at=?,updated_at=? WHERE owner_user_id=? "
                "AND status IN ('queued','retry','running')",
                (timestamp, timestamp, owner_user_id),
            )
        self._cancel_jobs(job_ids)
        self.wakeup.set()
        jobs_stopped = self._wait_for_cancelled_jobs(job_ids, CANCEL_WAIT_SECONDS)
        return validation_stopped and jobs_stopped

    def _wait_for_cancelled_jobs(self, job_ids: list[str], wait_seconds: float) -> bool:
        if not job_ids:
            return True
        try:
            wait_seconds = float(wait_seconds)
        except (TypeError, ValueError):
            wait_seconds = CANCEL_WAIT_SECONDS
        if not math.isfinite(wait_seconds):
            wait_seconds = CANCEL_WAIT_SECONDS
        deadline = time.monotonic() + min(10.0, max(0.0, wait_seconds))
        with self.cancel_condition:
            while any(job_id in self.job_cancellations for job_id in job_ids):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.cancel_condition.wait(remaining)
        # A rolling peer owns this lease for the full remote request. Waiting
        # for it closes the same return boundary for jobs absent from this
        # process's in-memory cancellation registry.
        lease = ProcessFileLock(self.worker_lock_path)
        while not lease.try_acquire():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(.02, remaining))
        lease.release()
        return True

    def _factory(self, credentials: dict[str, Any], url: str):
        factory = getattr(self.app.state, "ctfd_client_factory", CTFdClient)
        return factory(
            url=url,
            auth_type=credentials["auth_type"],
            token=credentials.get("token", ""),
            username=credentials.get("username", ""),
            password=credentials.get("password", ""),
            limits=Limits(files=0, file_bytes=0, total_bytes=4 * 1024 * 1024,
                          json_bytes=2 * 1024 * 1024, timeout=10, duration=30),
        )

    @staticmethod
    def _scope(owner_user_id: str, workspace_id: str) -> str:
        return f"ctfd-submit:{owner_user_id}:{workspace_id}"

    def _credentials(self, body: ConnectionInput) -> tuple[str, dict[str, str]]:
        url = normalize_url(body.url, site=True)
        if body.auth_type == "token":
            if not body.token or body.username or body.password:
                raise CTFdError("토큰 인증에는 액세스 토큰만 입력하세요.")
            credentials = {"auth_type": "token", "token": body.token}
        elif body.auth_type == "password":
            if not body.username or not body.password or body.token:
                raise CTFdError("아이디·비밀번호 인증에는 아이디와 비밀번호만 입력하세요.")
            credentials = {
                "auth_type": "password",
                "username": body.username,
                "password": body.password,
            }
        else:
            raise CTFdError("자동 제출은 토큰 또는 아이디·비밀번호 인증을 지원합니다.")
        return url, credentials

    @contextmanager
    def validation_slot(self, owner_user_id: str, workspace_id: str):
        """Reserve one remote connection-validation slot without waiting."""
        with self.validation_condition:
            if self.validation_inflight_by_owner.get(owner_user_id, 0) >= 1:
                raise HTTPException(409, "This account already has a CTFd connection check in progress.")
            if self.validation_inflight_total >= 4:
                raise HTTPException(429, "The CTFd connection check service is busy. Try again shortly.")
            self.validation_inflight_total += 1
            self.validation_inflight_by_owner[owner_user_id] = 1
        owner_lease = self._validation_lock("owner", owner_user_id)
        workspace_lease = self._validation_lock("workspace", workspace_id)
        if not owner_lease.try_acquire():
            with self.validation_condition:
                self.validation_inflight_total -= 1
                self.validation_inflight_by_owner.pop(owner_user_id, None)
            raise HTTPException(409, "This account already has a CTFd connection check in progress.")
        if not workspace_lease.try_acquire():
            owner_lease.release()
            with self.validation_condition:
                self.validation_inflight_total -= 1
                self.validation_inflight_by_owner.pop(owner_user_id, None)
            raise HTTPException(409, "This workspace already has a CTFd connection check in progress.")
        markers = (
            self._validation_marker("owner", owner_user_id),
            self._validation_marker("workspace", workspace_id),
        )
        try:
            for marker in markers:
                marker.unlink(missing_ok=True)
            cancellation = _FileCancellation(*markers)
        except BaseException:
            workspace_lease.release()
            owner_lease.release()
            with self.validation_condition:
                self.validation_inflight_total -= 1
                self.validation_inflight_by_owner.pop(owner_user_id, None)
            raise
        with self.validation_condition:
            self.validation_cancellations[owner_user_id] = (workspace_id, cancellation)
        try:
            yield cancellation
        finally:
            with self.validation_condition:
                self.validation_inflight_total -= 1
                self.validation_inflight_by_owner.pop(owner_user_id, None)
                current = self.validation_cancellations.get(owner_user_id)
                if current is not None and current[1] is cancellation:
                    self.validation_cancellations.pop(owner_user_id, None)
                self.validation_condition.notify_all()
            workspace_lease.release()
            owner_lease.release()

    @staticmethod
    def _connection_error(exc: CTFdError) -> str:
        """Translate safe client failures without echoing remote or input data."""

        original = str(exc)
        if original in {
            "토큰 인증에는 액세스 토큰만 입력하세요.",
            "아이디·비밀번호 인증에는 아이디와 비밀번호만 입력하세요.",
            "자동 제출은 토큰 또는 아이디·비밀번호 인증을 지원합니다.",
        }:
            return original
        message = original.lower()
        if "rate limit" in message:
            return "CTFd가 연결 확인 요청을 제한했습니다. 잠시 후 다시 시도하세요."
        if any(term in message for term in ("login failed", "username and password", "access token", "denied access", "authentication")):
            return "CTFd 인증에 실패했습니다. 선택한 인증 방식과 계정 정보를 확인하세요."
        if "https" in message:
            return "인증 정보를 사용할 때는 HTTPS 주소를 입력하세요."
        if any(term in message for term in ("complete http", "invalid url", "base url", "host or port")):
            return "올바른 CTFd 사이트 주소를 입력하세요."
        if any(term in message for term in ("public internet", "resolved")):
            return "공개 인터넷에서 접근할 수 있는 CTFd 주소만 연결할 수 있습니다."
        if any(term in message for term in ("timed out", "remote request failed")):
            return "CTFd 연결 확인 시간이 초과되었습니다. 사이트 상태를 확인하세요."
        # The CTFd client deliberately emits credential-safe errors, but a
        # fixed fallback also prevents a plugin/factory error from reaching UI.
        return "CTFd 연결을 검증하지 못했습니다. URL과 인증 정보를 확인하세요."

    def save_connection(self, workspace_id: str, user: dict, body: ConnectionInput) -> dict:
        self.app.state.require_workspace_owner(workspace_id, user)
        try:
            with self.validation_slot(user["id"], workspace_id) as cancellation:
                # The remote check shares the workspace lifecycle lease with
                # uploads and deletion.  It is nonblocking, so a slow request
                # cannot park another AnyIO worker behind the same workspace.
                with self.workspace_slot(workspace_id):
                    url, credentials = self._credentials(body)
                    # The allowance and workspace lease are acquired before
                    # factory/plugin code and therefore before DNS, login, or
                    # any remote request.
                    with self.db() as db:
                        active = db.execute(
                            """SELECT 1 FROM workspaces w JOIN users u ON u.id=w.owner_user_id
                               WHERE w.id=? AND w.owner_user_id=? AND u.active=1""",
                            (workspace_id, user["id"]),
                        ).fetchone()
                    if not active:
                        raise HTTPException(404, "The workspace or user is no longer available.")
                    client = self._factory(credentials, url)
                    try:
                        if hasattr(client, "cancel_event"):
                            client.cancel_event = cancellation
                        if cancellation.is_set():
                            raise CTFdError("The workspace or user is no longer available.")
                        client.validate()
                    finally:
                        client.clear_credentials()
                    ciphertext = self.vault.encrypt(
                        credentials,
                        scope=self._scope(user["id"], workspace_id),
                    )

                    timestamp, generation = _stamp(), uuid.uuid4().hex
                    cancelled_jobs: list[str] = []
                    with self.db() as db:
                        db.execute("BEGIN IMMEDIATE")
                        workspace = db.execute(
                            """SELECT 1 FROM workspaces w JOIN users u ON u.id=w.owner_user_id
                               WHERE w.id=? AND w.owner_user_id=? AND u.active=1""",
                            (workspace_id, user["id"]),
                        ).fetchone()
                        if not workspace:
                            raise HTTPException(404, "작업공간을 찾을 수 없습니다.")
                        # A new credential or destination always returns to the
                        # safe default. The owner must explicitly review and
                        # enable it again.
                        db.execute(
                            """INSERT INTO ctfd_submit_connections
                               (workspace_id,owner_user_id,url,auth_type,credentials_ciphertext,auto_submit,max_attempts,generation,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?)
                                ON CONFLICT(workspace_id) DO UPDATE SET
                                  owner_user_id=excluded.owner_user_id,url=excluded.url,auth_type=excluded.auth_type,
                                  credentials_ciphertext=excluded.credentials_ciphertext,generation=excluded.generation,
                                  auto_submit=0,max_attempts=excluded.max_attempts,
                                  updated_at=excluded.updated_at""",
                            (workspace_id, user["id"], url, body.auth_type, ciphertext,
                             0, MAX_ATTEMPTS, generation, timestamp, timestamp),
                        )
                        # Jobs created for an older credential/site generation
                        # must never silently submit through a newly connected
                        # account.
                        cancelled_jobs = [
                            row["id"] for row in db.execute(
                                """SELECT j.id FROM ctfd_submit_jobs j
                                   LEFT JOIN ctfd_submit_worker_claim c ON c.job_id=j.id
                                   WHERE j.workspace_id=? AND j.connection_generation!=?
                                     AND (j.status='running' OR c.job_id IS NOT NULL)""",
                                (workspace_id, generation),
                            )
                        ]
                        db.execute(
                            "UPDATE ctfd_submit_jobs SET status='disabled',result_code='connection_replaced',"
                            "display_message='CTFd 연결이 변경되어 이 자동 제출을 취소했습니다.',completed_at=?,updated_at=? "
                            "WHERE workspace_id=? AND status IN ('queued','retry','running') AND connection_generation!=?",
                            (timestamp, timestamp, workspace_id, generation),
                        )
                    self._cancel_jobs(cancelled_jobs)
                    if not self._wait_for_cancelled_jobs(cancelled_jobs, CANCEL_WAIT_SECONDS):
                        raise HTTPException(
                            409,
                            "새 CTFd 연결은 저장했지만 이전 제출 요청을 중단하고 있습니다. 잠시 후 상태를 다시 확인하세요.",
                        )
                    return self.connection_state(workspace_id, user)
        except CTFdError as exc:
            raise HTTPException(400, self._connection_error(exc)) from None
        except CredentialVaultError:
            raise HTTPException(503, "인증 정보 암호화 저장소를 사용할 수 없습니다.") from None

    def connection_state(self, workspace_id: str, user: dict) -> dict:
        self.app.state.require_workspace_owner(workspace_id, user)
        with self.db() as db:
            row = db.execute(
                "SELECT url,auth_type,auto_submit,created_at,updated_at FROM ctfd_submit_connections "
                "WHERE workspace_id=? AND owner_user_id=?",
                (workspace_id, user["id"]),
            ).fetchone()
        if not row:
            return {"connected": False, "auto_submit": False}
        return {
            "connected": True,
            "url": row["url"],
            "auth_type": row["auth_type"],
            "auto_submit": bool(row["auto_submit"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def client_for_import(self, workspace_id: str, user: dict):
        """Build a short-lived importer from the owner's saved connection.

        The encrypted credential never leaves the server-side service boundary.
        Import routes call this while holding the workspace lifecycle lock, so
        replacing or deleting the connection cannot race the credential handoff.
        The returned client still owns the normal import limits and clears its
        credentials when the durable import worker exits.
        """

        self.app.state.require_workspace_owner(workspace_id, user)
        with self.db() as db:
            row = db.execute(
                """SELECT url,auth_type,credentials_ciphertext,generation
                     FROM ctfd_submit_connections
                    WHERE workspace_id=? AND owner_user_id=?""",
                (workspace_id, user["id"]),
            ).fetchone()
        if not row:
            raise HTTPException(
                409,
                "CTFd 연결을 먼저 저장한 뒤 다시 시도하세요.",
            )
        try:
            credentials = self.vault.decrypt(
                row["credentials_ciphertext"],
                scope=self._scope(user["id"], workspace_id),
            )
        except CredentialVaultError:
            raise HTTPException(
                409,
                "저장된 CTFd 인증 정보를 사용할 수 없습니다. 연결을 다시 저장하세요.",
            ) from None
        if credentials.get("auth_type") != row["auth_type"]:
            raise HTTPException(
                409,
                "저장된 CTFd 인증 정보가 연결 설정과 일치하지 않습니다. 연결을 다시 저장하세요.",
            )
        factory = getattr(self.app.state, "ctfd_client_factory", CTFdClient)
        try:
            client = factory(
                url=row["url"],
                auth_type=credentials["auth_type"],
                token=credentials.get("token", ""),
                username=credentials.get("username", ""),
                password=credentials.get("password", ""),
            )
            # This opaque generation lets an import preview prove that the
            # saved connection it borrowed still exists unchanged when the
            # durable job is enqueued.  It is never returned by the API.
            client.saved_connection_generation = row["generation"]
            return client
        finally:
            # The client constructor copies immutable strings into its private
            # fields, so discard the decrypted dictionary immediately.
            credentials.clear()

    def import_connection_matches(
        self,
        workspace_id: str,
        owner_user_id: str,
        url: str,
        generation: str,
        *,
        connection=None,
    ) -> bool:
        """Check a borrowed importer against the current encrypted connection."""

        if (
            not isinstance(generation, str)
            or not re.fullmatch(r"[0-9a-f]{32}", generation)
        ):
            return False
        owns_connection = connection is None
        db = connection or self.app.state.connect()
        try:
            row = db.execute(
                """SELECT 1 FROM ctfd_submit_connections
                    WHERE workspace_id=? AND owner_user_id=? AND url=?
                      AND generation=?""",
                (workspace_id, owner_user_id, url, generation),
            ).fetchone()
            return row is not None
        finally:
            if owns_connection:
                db.close()

    def set_auto_submit(self, workspace_id: str, user: dict, enabled: bool) -> dict:
        self.app.state.require_workspace_owner(workspace_id, user)
        cancelled_jobs: list[str] = []
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT 1 FROM ctfd_submit_connections WHERE workspace_id=? AND owner_user_id=?",
                (workspace_id, user["id"]),
            ).fetchone()
            if not row:
                if enabled:
                    raise HTTPException(409, "자동 제출을 켜기 전에 CTFd 계정을 연결하고 검증하세요.")
                return {"connected": False, "auto_submit": False}
            db.execute(
                "UPDATE ctfd_submit_connections SET auto_submit=?,updated_at=? "
                "WHERE workspace_id=? AND owner_user_id=?",
                (int(enabled), _stamp(), workspace_id, user["id"]),
            )
            if not enabled:
                cancelled_jobs = [
                    row["id"] for row in db.execute(
                        """SELECT j.id FROM ctfd_submit_jobs j
                           LEFT JOIN ctfd_submit_worker_claim c ON c.job_id=j.id
                           WHERE j.workspace_id=? AND j.owner_user_id=?
                             AND (j.status='running' OR c.job_id IS NOT NULL)""",
                        (workspace_id, user["id"]),
                    )
                ]
                db.execute(
                    "UPDATE ctfd_submit_jobs SET status='disabled',result_code='auto_submit_disabled',"
                    "display_message='자동 제출이 꺼져 이 Flag를 전송하지 않았습니다.',"
                    "completed_at=?,updated_at=? WHERE workspace_id=? AND owner_user_id=? "
                    "AND status IN ('queued','retry','running')",
                    (_stamp(), _stamp(), workspace_id, user["id"]),
                )
        self._cancel_jobs(cancelled_jobs)
        if not self._wait_for_cancelled_jobs(cancelled_jobs, CANCEL_WAIT_SECONDS):
            raise HTTPException(
                409,
                "자동 제출은 껐지만 전송 중인 요청을 중단하고 있습니다. 잠시 후 상태를 다시 확인하세요.",
            )
        return self.connection_state(workspace_id, user)

    def delete_connection(self, workspace_id: str, user: dict) -> dict:
        self.app.state.require_workspace_owner(workspace_id, user)
        # Serialize the final delete with validation *and* its credential save.
        # Without this lifecycle lease a validation that started just after a
        # cancellation scan could recreate the connection after DELETE 200.
        with self.workspace_slot(workspace_id):
            return self._delete_connection_locked(workspace_id, user)

    def _delete_connection_locked(self, workspace_id: str, user: dict) -> dict:
        if not self._cancel_validation_scope(workspace_id=workspace_id):
            raise HTTPException(
                409,
                "The connection check is still stopping. Try again shortly.",
            )
        timestamp = _stamp()
        cancelled_jobs: list[str] = []
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            cancelled_jobs = [
                row["id"] for row in db.execute(
                    """SELECT j.id FROM ctfd_submit_jobs j
                       LEFT JOIN ctfd_submit_worker_claim c ON c.job_id=j.id
                       WHERE j.workspace_id=? AND j.owner_user_id=?
                         AND (j.status='running' OR c.job_id IS NOT NULL)""",
                    (workspace_id, user["id"]),
                )
            ]
            db.execute(
                "DELETE FROM ctfd_submit_connections WHERE workspace_id=? AND owner_user_id=?",
                (workspace_id, user["id"]),
            )
            db.execute(
                "UPDATE ctfd_submit_jobs SET status='disabled',result_code='connection_deleted',"
                "display_message='CTFd 연결이 삭제되어 이 자동 제출을 취소했습니다.',completed_at=?,updated_at=? "
                "WHERE workspace_id=? AND owner_user_id=? AND status IN ('queued','retry','running')",
                (timestamp, timestamp, workspace_id, user["id"]),
            )
        self._cancel_jobs(cancelled_jobs)
        if not self._wait_for_cancelled_jobs(cancelled_jobs, CANCEL_WAIT_SECONDS):
            raise HTTPException(
                409,
                "CTFd 연결은 해제했지만 전송 중인 요청을 중단하고 있습니다. 잠시 후 상태를 다시 확인하세요.",
            )
        return {"connected": False, "auto_submit": False}

    def _cancel_resource(self, workspace_id: str, user: dict, *, challenge_id: str | None,
                         wait_seconds: float) -> bool:
        """Make queued and in-flight submissions terminal before resource deletion.

        The database transition commits before cancellation is signalled. A
        late remote response therefore cannot update local solve state. The
        bounded wait lets deletion routes avoid removing challenge files while
        an in-process HTTP client is still unwinding.
        """

        self.app.state.require_workspace_owner(workspace_id, user)
        timestamp = _stamp()
        condition = "workspace_id=? AND owner_user_id=?"
        qualified_condition = "j.workspace_id=? AND j.owner_user_id=?"
        parameters: list[Any] = [workspace_id, user["id"]]
        result_code = "workspace_deleting"
        display_message = "작업공간 삭제 요청으로 자동 제출을 취소했습니다."
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            workspace = db.execute(
                "SELECT 1 FROM workspaces WHERE id=? AND owner_user_id=?",
                (workspace_id, user["id"]),
            ).fetchone()
            if not workspace:
                raise HTTPException(404, "작업공간을 찾을 수 없습니다.")
            if challenge_id is not None:
                challenge = db.execute(
                    "SELECT 1 FROM challenges WHERE id=? AND workspace_id=?",
                    (challenge_id, workspace_id),
                ).fetchone()
                if not challenge:
                    raise HTTPException(404, "문제를 찾을 수 없습니다.")
                condition += " AND challenge_id=?"
                qualified_condition += " AND j.challenge_id=?"
                parameters.append(challenge_id)
                result_code = "challenge_deleting"
                display_message = "문제 삭제 요청으로 자동 제출을 취소했습니다."
                db.execute(
                    """INSERT OR IGNORE INTO ctfd_submit_blocks
                       (workspace_id,challenge_id,owner_user_id,created_at) VALUES(?,?,?,?)""",
                    (workspace_id, challenge_id, user["id"], timestamp),
                )
            else:
                # Disable the connection and tombstone every current challenge
                # in the same transaction. A flag event racing the delete route
                # cannot enqueue fresh remote work after cancellation commits.
                db.execute(
                    "UPDATE ctfd_submit_connections SET auto_submit=0,updated_at=? "
                    "WHERE workspace_id=? AND owner_user_id=?",
                    (timestamp, workspace_id, user["id"]),
                )
                db.execute(
                    """INSERT OR IGNORE INTO ctfd_submit_blocks
                       (workspace_id,challenge_id,owner_user_id,created_at)
                       SELECT ?,id,?,? FROM challenges WHERE workspace_id=?""",
                    (workspace_id, user["id"], timestamp, workspace_id),
                )
            job_ids = [
                row["id"] for row in db.execute(
                    f"""SELECT j.id FROM ctfd_submit_jobs j
                         LEFT JOIN ctfd_submit_worker_claim c ON c.job_id=j.id
                         WHERE {qualified_condition}
                           AND (j.status='running' OR c.job_id IS NOT NULL)""",
                    parameters,
                )
            ]
            db.execute(
                f"""UPDATE ctfd_submit_jobs SET status='disabled',result_code=?,display_message=?,
                     completed_at=?,updated_at=? WHERE {condition}
                     AND status IN ('queued','retry','running')""",
                (result_code, display_message, timestamp, timestamp, *parameters),
            )
        self._cancel_jobs(job_ids)
        return self._wait_for_cancelled_jobs(job_ids, wait_seconds)

    def cancel_workspace(self, workspace_id: str, user: dict,
                         wait_seconds: float = CANCEL_WAIT_SECONDS) -> bool:
        validation_stopped = self._cancel_validation_scope(
            workspace_id=workspace_id, wait_seconds=wait_seconds,
        )
        jobs_stopped = self._cancel_resource(
            workspace_id, user, challenge_id=None, wait_seconds=wait_seconds,
        )
        return validation_stopped and jobs_stopped

    def cancel_challenge(self, workspace_id: str, challenge_id: str, user: dict,
                         wait_seconds: float = CANCEL_WAIT_SECONDS) -> bool:
        return self._cancel_resource(
            workspace_id, user, challenge_id=challenge_id, wait_seconds=wait_seconds,
        )

    def release_delete_block(self, workspace_id: str, user: dict, *,
                             challenge_id: str | None = None) -> None:
        """Remove a delete-intent tombstone when the local delete aborts.

        Cancellation makes already queued/running submissions terminal, so it
        is safe to reopen future enqueueing if another subsystem prevents the
        resource deletion. Ownership is included in the DELETE even when the
        workspace disappeared concurrently.
        """

        condition = "workspace_id=? AND owner_user_id=?"
        parameters: list[Any] = [workspace_id, user["id"]]
        if challenge_id is not None:
            condition += " AND challenge_id=?"
            parameters.append(challenge_id)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                f"DELETE FROM ctfd_submit_blocks WHERE {condition}",
                parameters,
            )

    def enqueue_flag(self, owner_user_id: str, workspace_id: str, challenge_id: str,
                     flag: str, completion_source: str = "agent") -> bool:
        """Queue a committed flag; false means an intentional no-op.

        SQLite failures propagate so the safe application hook can distinguish
        transient storage failure from disabled/deduplicated submission and ask
        the durable solver hook to retry.
        """

        if (not isinstance(flag, str) or not flag or len(flag) > 4000 or
                completion_source not in {"manual", "agent"}):
            return False
        digest, timestamp = _flag_digest(flag), _stamp()
        try:
            with self.db() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    """SELECT c.flag,c.ctfd_id,c.ctfd_url,s.url,s.generation,s.max_attempts
                       FROM challenges c
                       JOIN workspaces w ON w.id=c.workspace_id
                       JOIN users u ON u.id=w.owner_user_id AND u.active=1
                       JOIN ctfd_submit_connections s ON s.workspace_id=w.id
                       WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=?
                         AND s.owner_user_id=? AND s.auto_submit=1
                         AND NOT EXISTS (
                           SELECT 1 FROM ctfd_submit_blocks b
                           WHERE b.workspace_id=c.workspace_id AND b.challenge_id=c.id
                             AND b.owner_user_id=w.owner_user_id
                         )""",
                    (challenge_id, workspace_id, owner_user_id, owner_user_id),
                ).fetchone()
                if (not row or row["flag"] != flag or type(row["ctfd_id"]) is not int or
                        not row["ctfd_url"] or normalize_url(row["ctfd_url"], site=True) != row["url"] or
                        type(row["max_attempts"]) is not int or
                        not 1 <= row["max_attempts"] <= MAX_ATTEMPTS):
                    return False
                # Keep the historic attempts ceiling as a rollback-safe remote
                # call budget. A one-call QA job starts at MAX_ATTEMPTS-1, so
                # both this release and an older compatible release make one
                # claim and can never retry it.
                initial_attempts = MAX_ATTEMPTS - row["max_attempts"]
                inserted = db.execute(
                    """INSERT OR IGNORE INTO ctfd_submit_jobs
                       (id,workspace_id,challenge_id,owner_user_id,connection_generation,ctfd_id,
                        flag_digest,completion_source,status,attempts,next_attempt_at,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?, 'queued',?,?,?,?)""",
                    (uuid.uuid4().hex, workspace_id, challenge_id, owner_user_id,
                     row["generation"], row["ctfd_id"], digest, completion_source,
                     initial_attempts, int(time.time()), timestamp, timestamp),
                ).rowcount
        except CTFdError:
            return False
        if inserted:
            self.wakeup.set()
        return bool(inserted)

    def _claim(self):
        timestamp = int(time.time())
        claimed = None
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            finished = _stamp()
            db.execute(
                """UPDATE ctfd_submit_jobs SET status='disabled',result_code='user_disabled',
                     display_message='사용자 계정이 비활성화되어 자동 제출을 취소했습니다.',
                     completed_at=?,updated_at=?
                   WHERE status IN ('queued','retry') AND EXISTS (
                     SELECT 1 FROM users u WHERE u.id=ctfd_submit_jobs.owner_user_id AND u.active=0
                   )""",
                (finished, finished),
            )
            row = db.execute(
                "SELECT j.* FROM ctfd_submit_jobs j JOIN users u ON u.id=j.owner_user_id "
                "WHERE j.status IN ('queued','retry') AND u.active=1 "
                "AND j.attempts<? AND j.next_attempt_at<=? ORDER BY j.created_at,j.id LIMIT 1",
                (MAX_ATTEMPTS, timestamp),
            ).fetchone()
            if not row:
                return None
            # The write transaction orders stale-marker removal before any
            # concurrent OFF/delete transaction can publish a new cancel.
            self._job_cancel_marker(row["id"]).unlink(missing_ok=True)
            changed = db.execute(
                "UPDATE ctfd_submit_jobs SET status='running',attempts=attempts+1,updated_at=? "
                "WHERE id=? AND status IN ('queued','retry')",
                (_stamp(), row["id"]),
            ).rowcount
            if not changed:
                return None
            db.execute(
                "INSERT OR REPLACE INTO ctfd_submit_worker_claim(singleton,job_id) VALUES(1,?)",
                (row["id"],),
            )
            claimed = {**dict(row), "attempts": row["attempts"] + 1}
        cancellation = _FileCancellation(self._job_cancel_marker(claimed["id"]))
        with self.cancel_condition:
            self.job_cancellations[claimed["id"]] = cancellation
        claimed["_cancel_event"] = cancellation
        return claimed

    def _load_job(self, job: dict) -> tuple[dict, dict] | None:
        with self.db() as db:
            row = db.execute(
                """SELECT j.*,c.flag,c.status AS challenge_status,c.completion_source AS current_source,
                          s.url,s.auth_type,s.credentials_ciphertext,s.auto_submit,s.generation,
                          w.owner_user_id AS workspace_owner,u.active AS owner_active
                   FROM ctfd_submit_jobs j
                   JOIN challenges c ON c.id=j.challenge_id AND c.workspace_id=j.workspace_id
                   JOIN workspaces w ON w.id=j.workspace_id
                   JOIN users u ON u.id=w.owner_user_id
                   LEFT JOIN ctfd_submit_connections s ON s.workspace_id=j.workspace_id
                   WHERE j.id=?""",
                (job["id"],),
            ).fetchone()
        if not row:
            return None
        details = dict(row)
        if (not details["owner_active"] or details["workspace_owner"] != job["owner_user_id"] or
                not details["generation"] or details["generation"] != job["connection_generation"] or
                not details["auto_submit"]):
            disabled = not details["owner_active"]
            self._finish(
                job["id"], "disabled",
                "user_disabled" if disabled else "connection_unavailable",
                "사용자 계정이 비활성화되어 자동 제출을 취소했습니다."
                if disabled else "검증된 CTFd 연결이 더 이상 활성화되어 있지 않습니다.",
            )
            return None
        if not isinstance(details["flag"], str) or _flag_digest(details["flag"]) != job["flag_digest"]:
            self._finish(job["id"], "superseded", "flag_changed",
                         "더 새로운 Flag가 저장되어 이전 자동 제출을 취소했습니다.")
            return None
        try:
            credentials = self.vault.decrypt(
                details["credentials_ciphertext"],
                scope=self._scope(job["owner_user_id"], job["workspace_id"]),
            )
        except CredentialVaultError:
            self._finish(job["id"], "auth_error", "credential_unavailable",
                         "저장된 CTFd 인증 정보를 열 수 없습니다. 계정을 다시 연결하세요.")
            return None
        if credentials.get("auth_type") != details["auth_type"]:
            self._finish(job["id"], "auth_error", "credential_scope_mismatch",
                         "저장된 CTFd 인증 정보가 올바르지 않습니다. 계정을 다시 연결하세요.")
            return None
        return details, credentials

    def _interrupt_job(self, job: dict) -> None:
        timestamp = _stamp()
        retry = job["attempts"] < MAX_ATTEMPTS
        with self.db() as db:
            db.execute(
                """UPDATE ctfd_submit_jobs SET status=?,result_code='worker_stopping',
                     display_message=?,next_attempt_at=?,completed_at=?,updated_at=?
                   WHERE id=? AND status='running'""",
                (
                    "retry" if retry else "network_error",
                    "서버 종료로 제출이 중단되어 다음 시작 때 다시 시도합니다."
                    if retry else "서버 종료로 제출이 중단되었고 재시도 한도에 도달했습니다.",
                    int(time.time()),
                    None if retry else timestamp,
                    timestamp,
                    job["id"],
                ),
            )

    def _job_still_running(self, job_id: str) -> bool:
        with self.db() as db:
            row = db.execute(
                "SELECT 1 FROM ctfd_submit_jobs WHERE id=? AND status='running'",
                (job_id,),
            ).fetchone()
        return bool(row)

    def _recover_abandoned_claims(self) -> None:
        """Recover claims only while this process owns the global worker lock."""

        timestamp = _stamp()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM ctfd_submit_worker_claim WHERE singleton=1")
            db.execute(
                "UPDATE ctfd_submit_jobs SET status='retry',result_code='worker_interrupted',"
                "next_attempt_at=?,completed_at=NULL,updated_at=? "
                "WHERE status='running' AND attempts<?",
                (int(time.time()), timestamp, MAX_ATTEMPTS),
            )
            db.execute(
                "UPDATE ctfd_submit_jobs SET status='network_error',result_code='worker_interrupted',"
                "display_message='The automatic submission retry limit was reached after a worker interruption.',"
                "completed_at=?,updated_at=? WHERE status='running'",
                (timestamp, timestamp),
            )

    def process_once(self) -> bool:
        lease = ProcessFileLock(self.worker_lock_path)
        if not lease.try_acquire():
            return False
        try:
            self._recover_abandoned_claims()
            return self._process_once_locked()
        finally:
            lease.release()

    def _process_once_locked(self) -> bool:
        job = self._claim()
        if not job:
            return False
        try:
            return self._process_claimed(job)
        finally:
            with self.cancel_condition:
                if self.job_cancellations.get(job["id"]) is job["_cancel_event"]:
                    self.job_cancellations.pop(job["id"], None)
                    self.cancel_condition.notify_all()
            with self.db() as db:
                db.execute(
                    "DELETE FROM ctfd_submit_worker_claim WHERE singleton=1 AND job_id=?",
                    (job["id"],),
                )

    def _process_claimed(self, job: dict) -> bool:
        if self.stop_event.is_set():
            self._interrupt_job(job)
            return True
        loaded = self._load_job(job)
        if not loaded:
            return True
        details, credentials = loaded
        if self.stop_event.is_set():
            credentials.clear()
            self._interrupt_job(job)
            return True
        client = None
        try:
            client = self._factory(credentials, details["url"])
            # The built-in client observes this event while connecting/reading,
            # allowing normal shutdown to interrupt its bounded HTTP request.
            if hasattr(client, "cancel_event"):
                client.cancel_event = _CombinedCancellation(self.stop_event, job["_cancel_event"])
            # Connection replacement, unlinking and the OFF toggle publish a
            # terminal job state. Check it at the last point before network I/O;
            # any response already in flight is also ignored by _finish().
            if not self._job_still_running(job["id"]):
                return True
            result = client.submit(job["ctfd_id"], details["flag"])
        except CTFdError as exc:
            if self.stop_event.is_set():
                self._interrupt_job(job)
            else:
                self._handle_error(job, str(exc))
        except Exception:
            # An injected/third-party client must not kill the durable worker or
            # leak its exception text into the database/API.
            if self.stop_event.is_set():
                self._interrupt_job(job)
            else:
                self._retry_or_finish(job, "transport_error")
        else:
            if self.stop_event.is_set():
                self._interrupt_job(job)
            else:
                self._handle_result(job, result)
        finally:
            if client is not None:
                try:
                    client.clear_credentials()
                except Exception:
                    pass
            credentials.clear()
        return True

    def _handle_error(self, job: dict, message: str) -> None:
        lowered = message.lower()
        if "rate limit" in lowered:
            self._finish(job["id"], "rate_limited", "rate_limited",
                         "CTFd가 자동 제출 요청을 제한했습니다. 다시 시도하기 전에 상태를 확인하세요.")
        elif any(term in lowered for term in ("denied", "login failed", "authentication", "username and password", "access token", "csrf")):
            self._finish(job["id"], "auth_error", "authentication_failed",
                         "CTFd가 저장된 인증 정보를 거부했습니다. 계정을 다시 연결하세요.")
        elif any(term in lowered for term in (
                "timed out", "time limit", "could not be resolved", "remote request failed",
                "response ended", "http 500", "http 502", "http 503", "http 504")):
            self._retry_or_finish(job, "network_error")
        else:
            self._finish(job["id"], "failed", "remote_error",
                         "CTFd가 자동 제출을 처리하지 못했습니다. 연결과 문제 정보를 확인하세요.")

    def _retry_or_finish(self, job: dict, code: str) -> None:
        if job["attempts"] < MAX_ATTEMPTS:
            delay = RETRY_DELAYS[min(job["attempts"] - 1, len(RETRY_DELAYS) - 1)]
            with self.db() as db:
                db.execute(
                    "UPDATE ctfd_submit_jobs SET status='retry',result_code=?,"
                    "display_message='네트워크 오류가 발생해 자동 제출을 다시 시도합니다.',"
                    "next_attempt_at=?,updated_at=? WHERE id=? AND status='running'",
                    (code, int(time.time()) + delay, _stamp(), job["id"]),
                )
            self.wakeup.set()
        else:
            self._finish(job["id"], "network_error", code,
                         "정해진 횟수만큼 다시 시도했지만 CTFd에 연결하지 못했습니다.")

    def _handle_result(self, job: dict, result: Any) -> None:
        status = result.get("status", "") if isinstance(result, dict) else ""
        status = status.lower() if isinstance(status, str) else ""
        if status == "ratelimited":
            status = "rate_limited"
        mapping = {
            "correct": ("correct", "accepted", "CTFd가 Flag를 정답으로 처리했습니다."),
            "already_solved": ("already_solved", "already_solved", "CTFd에서 이미 완료된 문제입니다."),
            "incorrect": ("incorrect", "incorrect", "CTFd가 Flag를 오답으로 처리했습니다. 자동으로 다시 제출하지 않습니다."),
            "rate_limited": ("rate_limited", "rate_limited", "CTFd가 제출 요청을 제한했습니다. 자동으로 다시 제출하지 않습니다."),
            "authentication_required": ("auth_error", "authentication_failed", "CTFd가 저장된 인증 정보를 거부했습니다. 계정을 다시 연결하세요."),
            "paused": ("paused", "ctf_paused", "CTFd가 일시 중지되었습니다. Flag는 로컬에 그대로 저장되어 있습니다."),
            "partial": ("partial", "partial", "CTFd가 부분 정답으로 처리했습니다. CTFd 사이트에서 확인하세요."),
        }
        local_status, code, message = mapping.get(
            status,
            ("failed", "unsupported_response", "CTFd가 지원하지 않는 제출 결과를 반환했습니다."),
        )
        self._finish(job["id"], local_status, code, message,
                     solve=local_status in {"correct", "already_solved"}, job=job)

    def _finish(self, job_id: str, status: str, code: str, message: str, *,
                solve: bool = False, job: dict | None = None) -> None:
        timestamp = _stamp()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE ctfd_submit_jobs SET status=?,result_code=?,display_message=?,completed_at=?,updated_at=? "
                "WHERE id=? AND status='running'",
                (status, code, message, timestamp, timestamp, job_id),
            ).rowcount
            if not changed or not solve or not job:
                return
            challenge = db.execute(
                """SELECT c.flag,c.status,c.completion_source,w.owner_user_id
                   FROM challenges c JOIN workspaces w ON w.id=c.workspace_id
                   WHERE c.id=? AND c.workspace_id=?""",
                (job["challenge_id"], job["workspace_id"]),
            ).fetchone()
            if (not challenge or challenge["owner_user_id"] != job["owner_user_id"] or
                    not isinstance(challenge["flag"], str) or
                    _flag_digest(challenge["flag"]) != job["flag_digest"]):
                return
            previous = challenge["status"] if challenge["status"] != "solved" else None
            source = challenge["completion_source"] if challenge["status"] == "solved" and challenge["completion_source"] else job["completion_source"]
            db.execute(
                """UPDATE challenges SET
                     previous_status=CASE WHEN status='solved' THEN previous_status ELSE ? END,
                     status='solved',completion_source=?,updated_at=?
                   WHERE id=? AND workspace_id=?""",
                (previous, source, timestamp, job["challenge_id"], job["workspace_id"]),
            )

    def jobs_for(self, workspace_id: str, user: dict) -> dict:
        self.app.state.require_workspace_owner(workspace_id, user)
        with self.db() as db:
            rows = db.execute(
                """SELECT j.id,j.challenge_id,j.ctfd_id,j.completion_source,j.status,
                           (j.attempts-(? - COALESCE(s.max_attempts,?))) AS attempts,
                           j.result_code,j.display_message,j.created_at,j.updated_at,j.completed_at,
                           c.name AS challenge_name
                    FROM ctfd_submit_jobs j
                    JOIN challenges c ON c.id=j.challenge_id AND c.workspace_id=j.workspace_id
                    LEFT JOIN ctfd_submit_connections s
                      ON s.workspace_id=j.workspace_id
                     AND s.generation=j.connection_generation
                    WHERE j.workspace_id=? AND j.owner_user_id=?
                    ORDER BY j.created_at DESC,j.id DESC LIMIT 100""",
                (MAX_ATTEMPTS, MAX_ATTEMPTS, workspace_id, user["id"]),
            ).fetchall()
        return {"submissions": [dict(row) for row in rows]}


def register_ctfd_submit(app, require_auth, settings):
    service = CTFdSubmitService(app, settings)
    app.state.ctfd_submit = service

    def safe_flag_event(*args, **kwargs) -> bool:
        try:
            service.enqueue_flag(*args, **kwargs)
            # Auto-submit being off or an already queued digest is a completed
            # no-op. Only an exception asks the solver hook to retry.
            return True
        except Exception:
            return False

    app.state.ctfd_auto_submit_flag = safe_flag_event
    app.router.add_event_handler("startup", service.start)
    app.router.add_event_handler("shutdown", service.stop)

    @app.get("/api/workspaces/{workspace_id}/ctfd/connection", dependencies=[Depends(require_auth)])
    def get_connection(workspace_id: str, request: Request):
        return service.connection_state(workspace_id, request.state.user)

    @app.put("/api/workspaces/{workspace_id}/ctfd/connection", dependencies=[Depends(require_auth)])
    def put_connection(workspace_id: str, payload: ConnectionInput, request: Request):
        return service.save_connection(workspace_id, request.state.user, payload)

    @app.delete("/api/workspaces/{workspace_id}/ctfd/connection", dependencies=[Depends(require_auth)])
    def delete_connection(workspace_id: str, request: Request):
        return service.delete_connection(workspace_id, request.state.user)

    @app.get("/api/workspaces/{workspace_id}/ctfd/settings", dependencies=[Depends(require_auth)])
    def get_settings(workspace_id: str, request: Request):
        return service.connection_state(workspace_id, request.state.user)

    @app.put("/api/workspaces/{workspace_id}/ctfd/settings", dependencies=[Depends(require_auth)])
    def put_settings(workspace_id: str, payload: SubmissionSettingsInput, request: Request):
        return service.set_auto_submit(workspace_id, request.state.user, payload.auto_submit)

    @app.get("/api/workspaces/{workspace_id}/ctfd/submissions", dependencies=[Depends(require_auth)])
    def get_submissions(workspace_id: str, request: Request):
        return service.jobs_for(workspace_id, request.state.user)

    return service
