"""Durable web-side coordinator for the isolated solver worker.

Queued jobs live only in SQLite. Each worker-specific exchange receives one
claimed job, and that slot's next credential is never staged until its worker
has emitted a durable ``released`` event after cleaning its private PID
namespace. Independent containers provide bounded parallel slots. This module
runs in the trusted web container; workers never mount the application
database, account store, or workspace store.
"""

from __future__ import annotations

import contextlib
import concurrent.futures
import hashlib
import inspect
import json
import os
import platform
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .solver import ModelConfiguration, SelectedAccount, normalize_rate_limit_context
from .solver_worker import (
    EXCHANGE_PROTOCOL,
    MAX_AUTH_BYTES,
    MAX_JOB_SECONDS,
    MAX_OUTPUT_TEXT,
    REQUIRED_CLAUDE_VERSION,
    REQUIRED_CODEX_VERSION,
    runtime_tree_digest,
    valid_writeup,
)
from .process_lock import account_lifecycle_lock
from .solver_retry import (
    bounded_checkpoint_notes,
    decode_checkpoint,
    decode_solver_artifact,
    encode_checkpoint,
    encode_solver_artifact,
    merge_checkpoint,
    merge_continuation,
    parse_solver_artifact,
)
from .storage_budget import MAX_SQLITE_INTEGER, StorageBudget, StorageBudgetError
from .writeups import merge_generated_writeup, remove_generated_writeup


_ID = re.compile(r"[0-9a-f]{32}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{20,100}\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_OPEN_STATUSES = (
    "queued",
    "staging",
    "awaiting_credential",
    "running",
    "flag_found",
    "writing",
    "cleanup_blocked",
)
_TERMINAL_STATUSES = {"completed", "cancelled", "failed", "refused", "needs_input"}
_ALL_STATUSES = set(_OPEN_STATUSES) | _TERMINAL_STATUSES
_RESTORABLE_CHALLENGE_STATUSES = {
    "pending",
    "running",
    "stopped",
    "failed",
    "flag_found",
}
_MAX_EVENT_BYTES = MAX_OUTPUT_TEXT + 256 * 1024
_MIN_FREE_BYTES_AFTER_STAGE = 512 * 1024 * 1024
_STAGE_CONTROL_RESERVE = 2 * 1024 * 1024
_MAX_MANIFEST_BYTES = 512 * 1024
_VERSION = re.compile(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\Z")
_MAX_REMOTE_CHARS = 2000
MAX_WRITEUP_REFINEMENT_INSTRUCTION_BYTES = 12 * 1024
MAX_SOLVER_GUIDANCE_BYTES = 16 * 1024
MAX_SOLVER_GUIDANCE_PER_JOB = 100
_JOB_MODES = {"solve", "writeup_refine"}
_WRITEUP_INSTRUCTION_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_GUIDANCE_OPEN_STATUSES = {
    "queued",
    "staging",
    "awaiting_credential",
    "running",
    "flag_found",
    "writing",
}


def _credential_stage_name(provider: str) -> str:
    if provider == "codex":
        return "auth.json"
    if provider == "claude":
        return ".credentials.json"
    raise ExchangeError("invalid_provider", "공급자 선택을 확인할 수 없습니다.", category="model")


SCHEMA = """
CREATE TABLE IF NOT EXISTS solver_jobs (
    id TEXT PRIMARY KEY,
    job_mode TEXT NOT NULL DEFAULT 'solve' CHECK(job_mode IN ('solve','writeup_refine')),
    owner_user_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    challenge_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    account_label TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL CHECK(provider IN ('codex','claude')),
    model TEXT NOT NULL,
    reasoning_effort TEXT NOT NULL,
    max_reasoning_available INTEGER NOT NULL DEFAULT 0 CHECK(max_reasoning_available IN (0,1)),
    service_tier TEXT,
    codex_version TEXT NOT NULL DEFAULT '0.153.4',
    codex_runtime_sha256 TEXT,
    claude_version TEXT,
    claude_runtime_sha256 TEXT,
    status TEXT NOT NULL,
    previous_challenge_status TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
    last_event_sequence INTEGER NOT NULL DEFAULT 0,
    released_ingested INTEGER NOT NULL DEFAULT 0 CHECK(released_ingested IN (0,1)),
    flag TEXT,
    writeup_markdown TEXT,
    private_notes TEXT,
    solver_artifact_json TEXT,
    retry_checkpoint_json TEXT,
    writeup_instruction TEXT NOT NULL DEFAULT '',
    writeup_locale TEXT NOT NULL DEFAULT 'ko' CHECK(writeup_locale IN ('ko','en')),
    source_writeup_sha256 TEXT,
    source_solver_job_id TEXT,
    challenge_input_sha256 TEXT,
    challenge_base_sha256 TEXT,
    remote_mode TEXT NOT NULL DEFAULT 'unknown',
    flag_rejected_at REAL,
    error_json TEXT,
    flag_hooked INTEGER NOT NULL DEFAULT 0 CHECK(flag_hooked IN (0,1)),
    writeup_hooked INTEGER NOT NULL DEFAULT 0 CHECK(writeup_hooked IN (0,1)),
    worker_instance_id TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    released_at REAL
);
CREATE INDEX IF NOT EXISTS idx_solver_jobs_queue
    ON solver_jobs(status,created_at,id);
CREATE INDEX IF NOT EXISTS idx_solver_jobs_owner
    ON solver_jobs(owner_user_id,workspace_id,challenge_id,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_solver_one_open_challenge
    ON solver_jobs(owner_user_id,workspace_id,challenge_id)
    WHERE status IN ('queued','staging','awaiting_credential','running','flag_found','writing','cleanup_blocked');
CREATE TABLE IF NOT EXISTS challenge_writeups (
    challenge_id TEXT PRIMARY KEY REFERENCES challenges(id) ON DELETE CASCADE,
    markdown TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenge_writeups_updated
    ON challenge_writeups(updated_at,challenge_id);
CREATE TABLE IF NOT EXISTS solver_slot (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    job_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS solver_slots (
    slot_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS solver_job_events (
    job_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    event_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY(job_id,sequence)
);
CREATE TABLE IF NOT EXISTS solver_job_guidance (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES solver_jobs(id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('queued','staged','delivered','rejected')),
    provider_delivery TEXT CHECK(provider_delivery IN ('same_turn','next_turn')),
    error_code TEXT,
    created_at REAL NOT NULL,
    staged_at REAL,
    delivered_at REAL
);
CREATE INDEX IF NOT EXISTS idx_solver_job_guidance_delivery
    ON solver_job_guidance(job_id,status,created_at,id);
CREATE INDEX IF NOT EXISTS idx_solver_job_guidance_owner
    ON solver_job_guidance(owner_user_id,job_id,created_at,id);
CREATE TABLE IF NOT EXISTS solver_owner_service (
    owner_user_id TEXT PRIMARY KEY,
    last_served_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS account_lifecycle_blocks (
    owner_user_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    started_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS solver_retry_checkpoints (
    challenge_id TEXT PRIMARY KEY REFERENCES challenges(id) ON DELETE CASCADE,
    workspace_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    input_sha256 TEXT NOT NULL DEFAULT '',
    base_input_sha256 TEXT NOT NULL DEFAULT '',
    source_remote_mode TEXT NOT NULL DEFAULT 'unknown',
    source_job_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_solver_retry_checkpoint_owner
    ON solver_retry_checkpoints(owner_user_id,workspace_id,challenge_id);
CREATE TABLE IF NOT EXISTS solver_flag_hook_deliveries (
    job_id TEXT NOT NULL REFERENCES solver_jobs(id) ON DELETE CASCADE,
    flag_sha256 TEXT NOT NULL,
    delivered_at REAL NOT NULL,
    PRIMARY KEY(job_id,flag_sha256)
);
"""


class ExchangeError(RuntimeError):
    """A bounded coordinator error safe to show through the API."""

    def __init__(self, code: str, message: str, *, category: str = "solver", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.category = category
        self.retryable = retryable

    def public(self, *, stage: str = "queue") -> dict[str, Any]:
        return {
            "code": self.code,
            "message": str(self),
            "stage": stage,
            "category": self.category,
            "retryable": self.retryable,
        }


def normalize_writeup_refinement_instruction(value: str | None) -> str:
    """Return one bounded, display-safe optional editorial instruction."""

    if value is None:
        return ""
    if not isinstance(value, str):
        raise ExchangeError(
            "invalid_writeup_instruction",
            "write-up 보완 요청은 텍스트로 입력해 주세요.",
            category="input",
        )
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if _WRITEUP_INSTRUCTION_CONTROL.search(normalized):
        raise ExchangeError(
            "invalid_writeup_instruction",
            "write-up 보완 요청에 허용되지 않는 제어 문자가 있습니다.",
            category="input",
        )
    if len(normalized.encode("utf-8")) > MAX_WRITEUP_REFINEMENT_INSTRUCTION_BYTES:
        raise ExchangeError(
            "invalid_writeup_instruction",
            "write-up 보완 요청은 UTF-8 기준 12KiB까지 입력할 수 있습니다.",
            category="input",
        )
    return normalized


def normalize_solver_guidance(value: str | None) -> str:
    """Return one bounded owner-authored instruction for an active solve."""

    if not isinstance(value, str):
        raise ExchangeError(
            "invalid_solver_guidance",
            "추가 명령을 입력해 주세요.",
            category="input",
        )
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized or _WRITEUP_INSTRUCTION_CONTROL.search(normalized):
        raise ExchangeError(
            "invalid_solver_guidance",
            "추가 명령의 내용을 확인해 주세요.",
            category="input",
        )
    if len(normalized.encode("utf-8")) > MAX_SOLVER_GUIDANCE_BYTES:
        raise ExchangeError(
            "invalid_solver_guidance",
            "추가 명령은 UTF-8 기준 16KiB까지 입력할 수 있습니다.",
            category="input",
        )
    return normalized


class _StageCancelled(Exception):
    pass


def _migrate_solver_provider_constraint(db: sqlite3.Connection) -> None:
    """Widen the original provider CHECK without losing historical jobs.

    SQLite cannot alter a CHECK constraint in place.  Rebuild only when the
    exact legacy Codex-only predicate is present, copy every existing column,
    and recreate every explicit index.  The migration runs before the
    coordinator starts, with foreign-key enforcement temporarily disabled so
    existing flag-hook rows continue to reference the final table name.
    """

    row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='solver_jobs'"
    ).fetchone()
    create_sql = row[0] if row else None
    legacy = re.compile(r"CHECK\s*\(\s*provider\s*=\s*'codex'\s*\)", re.IGNORECASE)
    if not isinstance(create_sql, str) or not legacy.search(create_sql):
        return
    widened = legacy.sub("CHECK(provider IN ('codex','claude'))", create_sql, count=1)
    widened = re.sub(
        r"\ACREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:\"solver_jobs\"|solver_jobs)",
        "CREATE TABLE solver_jobs_provider_v2",
        widened,
        count=1,
        flags=re.IGNORECASE,
    )
    if widened == create_sql or "solver_jobs_provider_v2" not in widened:
        raise ExchangeError(
            "solver_schema_migration_failed",
            "solver 작업 저장소를 안전하게 갱신하지 못했습니다.",
            category="storage",
        )
    columns = [item[1] for item in db.execute("PRAGMA table_info(solver_jobs)")]
    if not columns or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in columns):
        raise ExchangeError(
            "solver_schema_migration_failed",
            "solver 작업 저장소 열 형식을 확인할 수 없습니다.",
            category="storage",
        )
    quoted = ",".join(f'"{name}"' for name in columns)
    indexes = [
        item[0]
        for item in db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='solver_jobs' AND sql IS NOT NULL"
        )
    ]
    db.commit()
    db.execute("PRAGMA foreign_keys=OFF")
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(widened)
        db.execute(
            f"INSERT INTO solver_jobs_provider_v2({quoted}) SELECT {quoted} FROM solver_jobs"
        )
        db.execute("DROP TABLE solver_jobs")
        db.execute("ALTER TABLE solver_jobs_provider_v2 RENAME TO solver_jobs")
        for index_sql in indexes:
            db.execute(index_sql)
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ExchangeError(
                "solver_schema_migration_failed",
                "solver 작업 저장소 연결 무결성을 확인할 수 없습니다.",
                category="storage",
            )
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.execute("PRAGMA foreign_keys=ON")


def _repair_recovered_cleanup_errors(db: sqlite3.Connection) -> None:
    """Remove a stale cleanup diagnostic after a verified successful release."""

    rows = db.execute(
        """SELECT j.id,j.error_json,e.event_json
           FROM solver_jobs j
           JOIN solver_job_events e ON e.job_id=j.id
          WHERE j.status='completed' AND j.released_ingested=1
            AND j.error_json IS NOT NULL
            AND e.sequence=(
                SELECT MAX(last.sequence) FROM solver_job_events last
                 WHERE last.job_id=j.id
            )"""
    ).fetchall()
    for row in rows:
        try:
            error = json.loads(row["error_json"])
            released = json.loads(row["event_json"])
        except (TypeError, ValueError):
            continue
        if (
            isinstance(error, dict)
            and error.get("code") == "process_cleanup_failed"
            and isinstance(released, dict)
            and released.get("kind") == "released"
            and released.get("status") == "completed"
            and not released.get("error")
        ):
            db.execute(
                "UPDATE solver_jobs SET error_json=NULL WHERE id=? AND status='completed'",
                (row["id"],),
            )


class SolverExchangeCoordinator:
    """Serialize, stage, ingest, and recover isolated solver jobs."""

    def __init__(
        self,
        database_path: Path,
        data_dir: Path,
        accounts_dir: Path,
        exchange_dir: Path,
        *,
        on_flag_committed: Callable[[str, str, str, str, str], Any] | None = None,
        on_writeup_committed: Callable[[str, str, str, str, str], Any] | None = None,
        storage_budget: StorageBudget | None = None,
        worker_max_age: float = 5.0,
        max_open_per_user: int | None = None,
        slot_id: str = "default",
        deliver_global_hooks: bool = True,
        defer_global_hooks: bool = False,
        accept_new_jobs: bool = True,
        host_managed_exchange: bool = False,
        enforce_host_ownership: bool = True,
        clock: Callable[[], float] = time.time,
    ):
        self.database_path = Path(database_path)
        self.data_dir = Path(data_dir)
        self.accounts_dir = Path(accounts_dir)
        self.exchange = Path(exchange_dir)
        self.on_flag_committed = on_flag_committed
        self.on_writeup_committed = on_writeup_committed
        self.worker_max_age = worker_max_age
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", slot_id):
            raise ValueError("solver slot_id must contain only letters, digits, '_' or '-'")
        self.slot_id = slot_id
        self.deliver_global_hooks = bool(deliver_global_hooks)
        self.defer_global_hooks = bool(defer_global_hooks)
        self.accept_new_jobs = bool(accept_new_jobs)
        self.host_managed_exchange = bool(host_managed_exchange)
        self.enforce_host_ownership = bool(enforce_host_ownership)
        configured_cap = max_open_per_user if max_open_per_user is not None else os.environ.get(
            "CTF_SOLVER_MAX_OPEN_PER_USER", "0"
        )
        try:
            self.max_open_per_user = int(configured_cap)
        except (TypeError, ValueError) as exc:
            raise ValueError("CTF_SOLVER_MAX_OPEN_PER_USER must be an integer") from exc
        if self.max_open_per_user < 0:
            raise ValueError("CTF_SOLVER_MAX_OPEN_PER_USER must be zero or greater")
        self.clock = clock
        self.stop_requested = threading.Event()
        self._activity = threading.Condition()
        self._active_ticks = 0
        self.last_block: dict[str, Any] | None = None
        self._prepare_exchange()
        with self._connect() as db:
            db.executescript(SCHEMA)
            columns = {row[1] for row in db.execute("PRAGMA table_info(solver_jobs)")}
            if "codex_version" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN codex_version TEXT NOT NULL DEFAULT '0.153.4'")
            if "codex_runtime_sha256" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN codex_runtime_sha256 TEXT")
            if "claude_version" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN claude_version TEXT")
            if "claude_runtime_sha256" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN claude_runtime_sha256 TEXT")
            if "private_notes" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN private_notes TEXT")
            if "solver_artifact_json" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN solver_artifact_json TEXT")
            if "retry_checkpoint_json" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN retry_checkpoint_json TEXT")
            if "challenge_input_sha256" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN challenge_input_sha256 TEXT")
            if "challenge_base_sha256" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN challenge_base_sha256 TEXT")
            if "remote_mode" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN remote_mode TEXT NOT NULL DEFAULT 'unknown'")
            if "flag_rejected_at" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN flag_rejected_at REAL")
            if "account_label" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN account_label TEXT NOT NULL DEFAULT ''")
            if "job_mode" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN job_mode TEXT NOT NULL DEFAULT 'solve'")
            if "writeup_instruction" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN writeup_instruction TEXT NOT NULL DEFAULT ''")
            if "writeup_locale" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN writeup_locale TEXT NOT NULL DEFAULT 'ko' CHECK(writeup_locale IN ('ko','en'))")
            if "source_writeup_sha256" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN source_writeup_sha256 TEXT")
            if "source_solver_job_id" not in columns:
                db.execute("ALTER TABLE solver_jobs ADD COLUMN source_solver_job_id TEXT")
            if "max_reasoning_available" not in columns:
                db.execute(
                    "ALTER TABLE solver_jobs ADD COLUMN max_reasoning_available "
                    "INTEGER NOT NULL DEFAULT 0 CHECK(max_reasoning_available IN (0,1))"
                )
            _migrate_solver_provider_constraint(db)
            _repair_recovered_cleanup_errors(db)
            # ``solver_slot`` was the generation-1 singleton claim. Preserve
            # an interrupted job in the first/default worker during the
            # additive migration to the bounded multi-worker slot table.
            if self.slot_id == "default":
                legacy_slot = db.execute(
                    "SELECT job_id FROM solver_slot WHERE singleton=1"
                ).fetchone()
                if legacy_slot:
                    legacy_job_id = legacy_slot["job_id"]
                    db.execute(
                        "INSERT OR IGNORE INTO solver_slots(slot_id,job_id) VALUES('default',?)",
                        (legacy_job_id,),
                    )
                    migrated = db.execute(
                        "SELECT slot_id,job_id FROM solver_slots WHERE slot_id='default' OR job_id=?",
                        (legacy_job_id,),
                    ).fetchall()
                    if len(migrated) != 1 or tuple(migrated[0]) != (
                        "default",
                        legacy_job_id,
                    ):
                        raise ExchangeError(
                            "solver_slot_migration_conflict",
                            "기존 solver 슬롯 정보를 안전하게 이전할 수 없습니다.",
                            category="safety",
                        )
                    db.execute("DELETE FROM solver_slot WHERE singleton=1 AND job_id=?", (legacy_job_id,))
            checkpoint_columns = {
                row[1] for row in db.execute("PRAGMA table_info(solver_retry_checkpoints)")
            }
            if "input_sha256" not in checkpoint_columns:
                db.execute(
                    "ALTER TABLE solver_retry_checkpoints ADD COLUMN input_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "base_input_sha256" not in checkpoint_columns:
                db.execute(
                    "ALTER TABLE solver_retry_checkpoints ADD COLUMN base_input_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "source_remote_mode" not in checkpoint_columns:
                db.execute(
                    "ALTER TABLE solver_retry_checkpoints ADD COLUMN source_remote_mode TEXT NOT NULL DEFAULT 'unknown'"
                )
        # ``solver_slots`` remains additive and FK-free so generation-one
        # databases can migrate in place. A crash or restore can therefore
        # leave a claim whose job row no longer exists. Remove only that
        # impossible claim under a write transaction.
        self._clear_stale_slot_claim()
        self.storage_budget = storage_budget or StorageBudget(self.data_dir, self._new_connection)
        # Interrupted ordinary staging is safe to rebuild. A cleanup-blocked
        # stage may still contain a credential copy, so only its owning slot's
        # verified release path may remove it.
        cleanup_blocked = self._cleanup_blocked_job_ids(own_slot=True)
        with self._lock():
            for path in self.exchange.glob(".staging-*"):
                if path.name.removeprefix(".staging-") not in cleanup_blocked:
                    _safe_remove_tree(path, self.exchange)
            runtime = self.exchange / "runtime"
            if runtime.exists() and (runtime.is_symlink() or not runtime.is_dir()):
                raise ExchangeError("invalid_runtime_path", "solver runtime 게시 경로를 확인할 수 없습니다.", category="safety")
            if runtime.is_dir():
                for path in runtime.glob(".staging-*"):
                    _safe_remove_tree(path, runtime)
            active = self.exchange / "active"
            if active.is_dir() and not active.is_symlink():
                for path in active.glob(".auth-*.tmp"):
                    if path.is_file() and not path.is_symlink() and path.resolve().parent == active.resolve():
                        path.unlink()
                _fsync(active)
            self.storage_budget.reconcile_kind(
                "solver", self._cleanup_blocked_reservations()
            )
            self.storage_budget.reconcile_kind("solver_runtime", {})

    def _prepare_exchange(self) -> None:
        if self.host_managed_exchange:
            try:
                state = self.exchange.lstat()
            except OSError as exc:
                raise ExchangeError(
                    "invalid_exchange",
                    "solver 교환 디렉터리를 확인할 수 없습니다.",
                    category="safety",
                ) from exc
            valid = stat.S_ISDIR(state.st_mode) and not stat.S_ISLNK(state.st_mode)
            if os.name == "posix" and self.enforce_host_ownership:
                valid = valid and (
                    state.st_uid == 0
                    and state.st_gid == os.getegid()
                    and stat.S_IMODE(state.st_mode) == 0o1770
                )
            if not valid:
                raise ExchangeError(
                    "invalid_exchange",
                    "호스트가 보호하는 solver 교환 디렉터리가 필요합니다.",
                    category="safety",
                )
            return
        self.exchange.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.exchange.is_symlink() or not self.exchange.is_dir():
            raise ExchangeError("invalid_exchange", "solver 교환 디렉터리를 확인할 수 없습니다.", category="safety")
        if os.name == "posix":
            self.exchange.chmod(0o700)

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = self._new_connection()
        try:
            with db:
                yield db
        finally:
            db.close()

    def _new_connection(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database_path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=15000")
        return db

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        """Cross-process lock for exchange mutations; SQLite protects the queue."""

        path = self.exchange / "worker.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            else:  # pragma: no cover - exercised on the Windows development host
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            yield
        finally:
            try:
                if os.name == "posix":
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                else:  # pragma: no cover
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(descriptor)

    def enqueue(
        self,
        owner_user_id: str,
        workspace_id: str,
        challenge_id: str,
        *,
        provider: str = "codex",
        codex_version: str = REQUIRED_CODEX_VERSION,
        codex_runtime_sha256: str | None = None,
        claude_version: str = REQUIRED_CLAUDE_VERSION,
        claude_runtime_sha256: str | None = None,
        configuration_override: ModelConfiguration | None = None,
        expected_account_id: str | None = None,
        max_reasoning_available: bool = False,
        job_mode: str = "solve",
        writeup_instruction: str | None = None,
        writeup_locale: str = "ko",
    ) -> dict[str, Any]:
        _require_id(workspace_id, "workspace")
        _require_id(challenge_id, "challenge")
        if job_mode not in _JOB_MODES:
            raise ExchangeError(
                "invalid_job_mode",
                "작업 유형을 확인할 수 없습니다.",
                category="safety",
            )
        if writeup_locale not in {"ko", "en"}:
            raise ExchangeError("invalid_writeup_locale", "지원하지 않는 write-up 언어입니다.", category="output")
        instruction = normalize_writeup_refinement_instruction(writeup_instruction)
        if job_mode == "solve" and instruction:
            raise ExchangeError(
                "invalid_writeup_instruction",
                "문제 풀이 작업에는 write-up 보완 요청을 사용할 수 없습니다.",
                category="input",
            )
        if provider not in {"codex", "claude"}:
            raise ExchangeError("invalid_provider", "공급자 선택을 확인할 수 없습니다.", category="model")
        if configuration_override is not None and (
            not isinstance(configuration_override, ModelConfiguration)
            or configuration_override.provider != provider
        ):
            raise ExchangeError(
                "invalid_model_configuration",
                "이번 실행의 모델 설정을 확인할 수 없습니다.",
                category="model",
            )
        if type(max_reasoning_available) is not bool or (
            max_reasoning_available and (job_mode != "solve" or provider != "codex")
        ):
            raise ExchangeError(
                "invalid_model_configuration",
                "자동 추론 승격 설정을 확인할 수 없습니다.",
                category="model",
            )
        if expected_account_id is not None and (
            not isinstance(expected_account_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", expected_account_id)
        ):
            raise ExchangeError(
                "invalid_account_binding",
                "이번 실행에 검증된 계정을 확인할 수 없습니다.",
                category="auth",
            )
        if not isinstance(codex_version, str) or not _VERSION.fullmatch(codex_version):
            raise ExchangeError("invalid_runtime_version", "Codex 실행 버전을 확인할 수 없습니다.", category="model")
        if codex_runtime_sha256 is not None and (
            not isinstance(codex_runtime_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", codex_runtime_sha256)
        ):
            raise ExchangeError("invalid_runtime_digest", "Codex runtime 무결성 값을 확인할 수 없습니다.", category="model")
        if provider == "codex" and codex_version != REQUIRED_CODEX_VERSION and codex_runtime_sha256 is None:
            raise ExchangeError("runtime_not_published", "선택한 Codex runtime이 solver에 게시되지 않았습니다.", category="model")
        if not isinstance(claude_version, str) or not _VERSION.fullmatch(claude_version):
            raise ExchangeError("invalid_runtime_version", "Claude 실행 버전을 확인할 수 없습니다.", category="model")
        if claude_runtime_sha256 is not None and (
            not isinstance(claude_runtime_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", claude_runtime_sha256)
        ):
            raise ExchangeError("invalid_runtime_digest", "Claude runtime 무결성 값을 확인할 수 없습니다.", category="model")
        if provider == "claude" and claude_version != REQUIRED_CLAUDE_VERSION and claude_runtime_sha256 is None:
            raise ExchangeError("runtime_not_published", "검증된 Claude runtime을 사용할 수 없습니다.", category="model")
        if not isinstance(owner_user_id, str) or not owner_user_id or len(owner_user_id) > 200 or _CONTROL.search(owner_user_id):
            raise ExchangeError("invalid_owner", "로그인 사용자를 확인할 수 없습니다.", category="auth")
        timestamp = self.clock()
        job_id = uuid.uuid4().hex
        stale_lifecycle_lease = None
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                challenge = db.execute(
                    """SELECT c.status,c.remote_mode,c.flag,c.completion_source,w.owner_user_id
                              FROM challenges c
                       JOIN workspaces w ON w.id=c.workspace_id
                       JOIN users u ON u.id=w.owner_user_id
                       WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=? AND u.active=1""",
                    (challenge_id, workspace_id, owner_user_id),
                ).fetchone()
                if not challenge:
                    raise ExchangeError("challenge_not_found", "문제를 찾을 수 없습니다.")
                if job_mode == "solve" and challenge["status"] == "solved":
                    raise ExchangeError("challenge_completed", "완료를 취소한 뒤 다시 풀이를 시작해 주세요.")
                source_writeup_sha256 = None
                source_solver_job_id = None
                source_private_notes = None
                source_solver_artifact_json = None
                verified_flag = None
                if job_mode == "writeup_refine":
                    verified_flag = challenge["flag"]
                    if (
                        challenge["status"] != "solved"
                        or challenge["completion_source"] != "agent"
                        or not isinstance(verified_flag, str)
                        or not verified_flag
                        or len(verified_flag) > 4000
                        or "\n" in verified_flag
                        or "\r" in verified_flag
                        or _CONTROL.search(verified_flag)
                    ):
                        raise ExchangeError(
                            "writeup_refinement_unavailable",
                            "Agent가 검증한 Flag와 write-up이 있는 완료 문제만 보완할 수 있습니다.",
                            category="input",
                        )
                    writeup_row = db.execute(
                        "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                        (challenge_id,),
                    ).fetchone()
                    markdown = writeup_row["markdown"] if writeup_row else None
                    if (
                        not isinstance(markdown, str)
                        or not markdown
                        or len(markdown.encode("utf-8")) > MAX_OUTPUT_TEXT
                        or _CONTROL.search(markdown)
                    ):
                        raise ExchangeError(
                            "writeup_refinement_unavailable",
                            "Agent가 검증한 Flag와 write-up이 있는 완료 문제만 보완할 수 있습니다.",
                            category="input",
                        )
                    source = db.execute(
                        """SELECT id,private_notes,solver_artifact_json
                           FROM solver_jobs
                           WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                             AND status='completed' AND released_ingested=1 AND flag=?
                             AND writeup_markdown=? AND flag_rejected_at IS NULL
                           ORDER BY created_at DESC,id DESC LIMIT 1""",
                        (owner_user_id, workspace_id, challenge_id, verified_flag, markdown),
                    ).fetchone()
                    if not source:
                        raise ExchangeError(
                            "writeup_refinement_unavailable",
                            "Agent가 생성하고 검증한 write-up 원본을 확인할 수 없습니다.",
                            category="safety",
                        )
                    try:
                        source_private_notes = bounded_checkpoint_notes(
                            source["private_notes"] if isinstance(source["private_notes"], str) else ""
                        )
                        source_artifact = decode_solver_artifact(source["solver_artifact_json"])
                        source_solver_artifact_json = encode_solver_artifact(source_artifact)
                    except (TypeError, ValueError) as exc:
                        raise ExchangeError(
                            "invalid_writeup_refinement_context",
                            "이전 solver 산출물을 안전하게 확인할 수 없습니다.",
                            category="safety",
                        ) from exc
                    source_writeup_sha256 = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
                    source_solver_job_id = source["id"]
                challenge_input_sha256 = _challenge_input_sha256(
                    db, owner_user_id, workspace_id, challenge_id
                )
                challenge_base_sha256 = _challenge_base_sha256(
                    db, owner_user_id, workspace_id, challenge_id
                )
                remote_mode = "none" if job_mode == "writeup_refine" else challenge["remote_mode"]
                if remote_mode not in {"unknown", "none", "endpoint"}:
                    raise ExchangeError(
                        "invalid_challenge_remote",
                        "문제의 원격 접속 상태를 확인할 수 없습니다.",
                        category="safety",
                    )
                tables = {
                    row["name"]
                    for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                        "('upload_sessions','ctfd_jobs','ctfd_job_challenges')"
                    )
                }
                if "upload_sessions" in tables and db.execute(
                    """SELECT 1 FROM upload_sessions
                       WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                          AND status='uploading' LIMIT 1""",
                    (owner_user_id, workspace_id, challenge_id),
                ).fetchone():
                    raise ExchangeError(
                        "challenge_upload_in_progress",
                        "진행 중인 첨부 업로드를 완료하거나 취소한 뒤 풀이를 시작해 주세요.",
                    )
                if {"ctfd_jobs", "ctfd_job_challenges"}.issubset(tables) and db.execute(
                    """SELECT 1 FROM ctfd_jobs j
                       JOIN ctfd_job_challenges m ON m.job_id=j.id
                       WHERE j.owner_user_id=? AND j.workspace_id=?
                          AND m.challenge_id=? AND m.skipped=0
                          AND j.status IN ('queued','running') LIMIT 1""",
                    (owner_user_id, workspace_id, challenge_id),
                ).fetchone():
                    raise ExchangeError(
                        "challenge_import_in_progress",
                        "CTFd 첨부 가져오기가 끝난 뒤 풀이를 시작해 주세요.",
                    )
                if "ctfd_jobs" in tables:
                    ctfd_columns = {
                        row[1] for row in db.execute("PRAGMA table_info(ctfd_jobs)")
                    }
                    if {"mode", "target_challenge_id"} <= ctfd_columns and db.execute(
                        """SELECT 1 FROM ctfd_jobs
                           WHERE owner_user_id=? AND workspace_id=?
                             AND mode='refresh' AND target_challenge_id=?
                             AND status IN ('queued','running') LIMIT 1""",
                        (owner_user_id, workspace_id, challenge_id),
                    ).fetchone():
                        raise ExchangeError(
                            "challenge_import_in_progress",
                            "CTFd refresh is in progress. Start the solve after it finishes.",
                        )
                lifecycle_block = db.execute(
                    "SELECT account_id FROM account_lifecycle_blocks WHERE owner_user_id=?",
                    (owner_user_id,),
                ).fetchone()
                if lifecycle_block:
                    candidate = account_lifecycle_lock(self.accounts_dir, owner_user_id)
                    if not candidate.try_acquire():
                        raise ExchangeError(
                            "account_busy",
                            "계정 인증 정보를 변경하는 작업이 진행 중입니다. 완료 후 다시 시도해 주세요.",
                            category="auth",
                            retryable=True,
                        )
                    # The marker outlived its process lease. Remove it inside
                    # this enqueue transaction and retain the lease until the
                    # new open job is committed, so a new mutation cannot slip
                    # between stale recovery and INSERT.
                    stale_lifecycle_lease = candidate
                    db.execute(
                        "DELETE FROM account_lifecycle_blocks WHERE owner_user_id=?",
                        (owner_user_id,),
                    )
                if expected_account_id is None:
                    account = db.execute(
                        """SELECT * FROM provider_accounts
                           WHERE owner_user_id=? AND provider=? AND selected=1""",
                        (owner_user_id, provider),
                    ).fetchone()
                else:
                    account = db.execute(
                        """SELECT * FROM provider_accounts
                           WHERE id=? AND owner_user_id=? AND provider=?""",
                        (expected_account_id, owner_user_id, provider),
                    ).fetchone()
                if not account:
                    raise ExchangeError("account_required", "선택된 모델 계정이 필요합니다.", category="auth")
                if configuration_override is not None:
                    # A per-run choice is already validated against this
                    # account's live catalog by the HTTP service.  It must not
                    # depend on the account having persistent defaults: a newly
                    # authenticated account can select its catalog defaults in
                    # the challenge panel without first changing global
                    # account preferences.
                    try:
                        selected = SelectedAccount(
                            str(account["id"]), owner_user_id, configuration_override
                        )
                    except ValueError as exc:
                        raise ExchangeError(
                            "invalid_account_binding",
                            "이번 실행에 사용할 계정을 확인할 수 없습니다.",
                            category="auth",
                        ) from exc
                else:
                    try:
                        selected = SelectedAccount.from_record(
                            dict(account),
                            owner_user_id,
                            require_selected=expected_account_id is None,
                        )
                    except ValueError as exc:
                        raise ExchangeError("model_configuration_required", "모델과 추론 수준을 먼저 선택해 주세요.", category="model") from exc
                configuration = configuration_override or selected.configuration
                snapshot = _optional_json(account["snapshot"])
                if snapshot.get("status") != "authenticated":
                    raise ExchangeError("account_login_required", "선택한 모델 계정에 로그인해 주세요.", category="auth")
                if provider == "claude" and configuration.service_tier is not None:
                    raise ExchangeError(
                        "invalid_model_configuration",
                        "Claude 풀이에서는 Fast 실행 속도를 사용할 수 없습니다.",
                        category="model",
                    )
                open_count = db.execute(
                    "SELECT COUNT(*) FROM solver_jobs WHERE owner_user_id=? AND status IN (%s)"
                    % ",".join("?" for _ in _OPEN_STATUSES),
                    (owner_user_id, *_OPEN_STATUSES),
                ).fetchone()[0]
                if self.max_open_per_user and open_count >= self.max_open_per_user:
                    raise ExchangeError(
                        "solver_queue_limit",
                        f"사용자별 대기·실행 작업은 최대 {self.max_open_per_user}개입니다.",
                        retryable=True,
                    )
                checkpoint_row = db.execute(
                    """SELECT checkpoint_json,input_sha256,base_input_sha256,source_remote_mode
                       FROM solver_retry_checkpoints
                       WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?""",
                    (owner_user_id, workspace_id, challenge_id),
                ).fetchone()
                retry_checkpoint_json = None
                if checkpoint_row and job_mode == "solve":
                    try:
                        checkpoint = decode_checkpoint(checkpoint_row["checkpoint_json"])
                    except (TypeError, ValueError) as exc:
                        raise ExchangeError(
                            "invalid_retry_checkpoint",
                            "이전 오답 풀이 기록을 안전하게 확인할 수 없습니다.",
                            category="safety",
                        ) from exc
                    exact_input = not checkpoint_row["input_sha256"] or secrets.compare_digest(
                        checkpoint_row["input_sha256"], challenge_input_sha256
                    )
                    remote_resume = bool(
                        checkpoint
                        and checkpoint.reason == "needs_remote"
                        and checkpoint_row["base_input_sha256"]
                        and secrets.compare_digest(
                            checkpoint_row["base_input_sha256"], challenge_base_sha256
                        )
                        and remote_mode in {"none", "endpoint"}
                        and (
                            checkpoint_row["source_remote_mode"] == "unknown"
                            or checkpoint_row["source_remote_mode"]
                            in {"none", "endpoint"}
                        )
                    )
                    if not exact_input and not remote_resume:
                        db.execute(
                            "DELETE FROM solver_retry_checkpoints WHERE challenge_id=?",
                            (challenge_id,),
                        )
                        checkpoint_row = None
                        checkpoint = None
                    elif checkpoint and checkpoint.reason == "needs_remote" and remote_mode == "unknown":
                        raise ExchangeError(
                            "remote_input_required",
                            "이 문제를 계속 풀려면 원격 접속 여부 또는 접속 정보를 먼저 입력해 주세요.",
                            category="input",
                        )
                    else:
                        retry_checkpoint_json = encode_checkpoint(checkpoint) if checkpoint else None
                        if exact_input and (
                            not checkpoint_row["input_sha256"]
                            or not checkpoint_row["base_input_sha256"]
                        ):
                            db.execute(
                                """UPDATE solver_retry_checkpoints
                                   SET input_sha256=?,base_input_sha256=?,source_remote_mode=?,updated_at=?
                                   WHERE challenge_id=?""",
                                (
                                    challenge_input_sha256,
                                    challenge_base_sha256,
                                    remote_mode,
                                    timestamp,
                                    challenge_id,
                                ),
                            )
                db.execute(
                    """INSERT INTO solver_jobs
                       (id,job_mode,owner_user_id,workspace_id,challenge_id,account_id,account_label,provider,model,
                        reasoning_effort,max_reasoning_available,service_tier,codex_version,codex_runtime_sha256,claude_version,claude_runtime_sha256,
                        retry_checkpoint_json,writeup_instruction,writeup_locale,source_writeup_sha256,source_solver_job_id,
                        challenge_input_sha256,challenge_base_sha256,remote_mode,status,previous_challenge_status,flag,private_notes,
                        solver_artifact_json,flag_hooked,created_at,updated_at)
                       VALUES(:id,:job_mode,:owner_user_id,:workspace_id,:challenge_id,:account_id,
                               :account_label,:provider,:model,:reasoning_effort,:max_reasoning_available,:service_tier,:codex_version,
                              :codex_runtime_sha256,:claude_version,:claude_runtime_sha256,:retry_checkpoint_json,
                              :writeup_instruction,:writeup_locale,:source_writeup_sha256,:source_solver_job_id,
                              :challenge_input_sha256,:challenge_base_sha256,:remote_mode,'queued',:previous_challenge_status,:flag,
                              :private_notes,:solver_artifact_json,:flag_hooked,:created_at,:updated_at)""",
                    {
                        "id": job_id,
                        "job_mode": job_mode,
                        "owner_user_id": owner_user_id,
                        "workspace_id": workspace_id,
                        "challenge_id": challenge_id,
                        "account_id": selected.account_id,
                        "account_label": account["label"],
                        "provider": configuration.provider,
                        "model": configuration.model,
                        "reasoning_effort": configuration.reasoning_effort,
                        "max_reasoning_available": int(
                            max_reasoning_available
                            and configuration.reasoning_effort != "max"
                        ),
                        "service_tier": configuration.service_tier,
                        "codex_version": codex_version,
                        "codex_runtime_sha256": codex_runtime_sha256,
                        "claude_version": claude_version,
                        "claude_runtime_sha256": claude_runtime_sha256,
                        "retry_checkpoint_json": retry_checkpoint_json,
                        "writeup_instruction": instruction,
                        "writeup_locale": writeup_locale,
                        "source_writeup_sha256": source_writeup_sha256,
                        "source_solver_job_id": source_solver_job_id,
                        "challenge_input_sha256": challenge_input_sha256,
                        "challenge_base_sha256": challenge_base_sha256,
                        "remote_mode": remote_mode,
                        "previous_challenge_status": (
                            challenge["status"] if job_mode == "solve" else None
                        ),
                        "flag": verified_flag,
                        "private_notes": source_private_notes,
                        "solver_artifact_json": source_solver_artifact_json,
                        "flag_hooked": 1 if job_mode == "writeup_refine" else 0,
                        "created_at": timestamp,
                        "updated_at": timestamp,
                    },
                )
                if job_mode == "solve":
                    db.execute(
                        """UPDATE challenges
                           SET previous_status=status,status='running',updated_at=?
                           WHERE id=? AND workspace_id=?""",
                        (_utc_stamp(timestamp), challenge_id, workspace_id),
                    )
        except sqlite3.IntegrityError as exc:
            if "idx_solver_one_open_challenge" in str(exc) or "UNIQUE constraint failed" in str(exc):
                if job_mode == "writeup_refine":
                    raise ExchangeError(
                        "writeup_refinement_already_active",
                        "이 문제의 풀이 또는 write-up 보완이 이미 대기 중이거나 실행 중입니다.",
                    ) from None
                raise ExchangeError("solve_already_active", "이 문제의 풀이가 이미 대기 중이거나 실행 중입니다.") from None
            raise ExchangeError("queue_storage_failed", "풀이 작업을 저장하지 못했습니다.", retryable=True) from None
        finally:
            if stale_lifecycle_lease is not None:
                stale_lifecycle_lease.release()
        return self.get(job_id, owner_user_id)

    def enqueue_writeup_refinement(
        self,
        owner_user_id: str,
        workspace_id: str,
        challenge_id: str,
        *,
        instruction: str | None = None,
        writeup_locale: str = "ko",
        provider: str = "codex",
        codex_version: str = REQUIRED_CODEX_VERSION,
        codex_runtime_sha256: str | None = None,
        claude_version: str = REQUIRED_CLAUDE_VERSION,
        claude_runtime_sha256: str | None = None,
        configuration_override: ModelConfiguration | None = None,
        expected_account_id: str | None = None,
    ) -> dict[str, Any]:
        return self.enqueue(
            owner_user_id,
            workspace_id,
            challenge_id,
            provider=provider,
            codex_version=codex_version,
            codex_runtime_sha256=codex_runtime_sha256,
            claude_version=claude_version,
            claude_runtime_sha256=claude_runtime_sha256,
            configuration_override=configuration_override,
            expected_account_id=expected_account_id,
            job_mode="writeup_refine",
            writeup_instruction=instruction,
            writeup_locale=writeup_locale,
        )

    def get(self, job_id: str, owner_user_id: str, *, after: int = 0, limit: int = 200) -> dict[str, Any]:
        if not _JOB_ID.fullmatch(job_id):
            raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise ExchangeError("invalid_cursor", "이벤트 위치를 확인할 수 없습니다.")
        limit = max(1, min(int(limit), 500))
        with self._connect() as db:
            row = db.execute(
                """SELECT j.*,cp.checkpoint_json AS current_retry_checkpoint_json
                   FROM solver_jobs j
                   LEFT JOIN solver_retry_checkpoints cp
                     ON cp.challenge_id=j.challenge_id
                    AND cp.workspace_id=j.workspace_id
                    AND cp.owner_user_id=j.owner_user_id
                   WHERE j.id=? AND j.owner_user_id=?""",
                (job_id, owner_user_id),
            ).fetchone()
            if not row:
                raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
            events = [
                _optional_json(item["event_json"])
                for item in db.execute(
                    "SELECT event_json FROM solver_job_events WHERE job_id=? AND sequence>? ORDER BY sequence LIMIT ?",
                    (job_id, after, limit),
                )
            ]
            guidance = [
                _public_guidance(item)
                for item in db.execute(
                    """SELECT id,job_id,message,status,provider_delivery,error_code,
                              created_at,staged_at,delivered_at
                       FROM solver_job_guidance
                       WHERE job_id=? AND owner_user_id=?
                       ORDER BY created_at,id""",
                    (job_id, owner_user_id),
                )
            ]
            position = None
            if row["status"] == "queued":
                position = db.execute(
                    """SELECT COUNT(*) FROM solver_jobs
                       WHERE status='queued' AND (created_at<? OR (created_at=? AND id<=?))""",
                    (row["created_at"], row["created_at"], row["id"]),
                ).fetchone()[0]
        return _public_job(row, events, position, guidance=guidance)

    def latest(
        self,
        owner_user_id: str,
        workspace_id: str,
        challenge_id: str,
        *,
        job_mode: str | None = None,
    ) -> dict[str, Any] | None:
        _require_id(workspace_id, "workspace")
        _require_id(challenge_id, "challenge")
        if job_mode is not None and job_mode not in _JOB_MODES:
            raise ExchangeError("invalid_job_mode", "작업 유형을 확인할 수 없습니다.", category="safety")
        with self._connect() as db:
            if job_mode is None:
                row = db.execute(
                    """SELECT id FROM solver_jobs WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                       ORDER BY created_at DESC,id DESC LIMIT 1""",
                    (owner_user_id, workspace_id, challenge_id),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT id FROM solver_jobs
                       WHERE owner_user_id=? AND workspace_id=? AND challenge_id=? AND job_mode=?
                       ORDER BY created_at DESC,id DESC LIMIT 1""",
                    (owner_user_id, workspace_id, challenge_id, job_mode),
                ).fetchone()
        return self.get(row["id"], owner_user_id) if row else None

    def add_guidance(
        self,
        job_id: str,
        owner_user_id: str,
        message: str,
    ) -> dict[str, Any]:
        """Durably queue owner-authored guidance for one active solve."""

        if not _JOB_ID.fullmatch(job_id):
            raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
        if (
            not isinstance(owner_user_id, str)
            or not owner_user_id
            or len(owner_user_id) > 200
            or _CONTROL.search(owner_user_id)
        ):
            raise ExchangeError(
                "invalid_owner",
                "로그인 사용자를 확인할 수 없습니다.",
                category="auth",
            )
        normalized = normalize_solver_guidance(message)
        guidance_id = uuid.uuid4().hex
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id,job_mode,status FROM solver_jobs WHERE id=? AND owner_user_id=?",
                (job_id, owner_user_id),
            ).fetchone()
            if not row:
                raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
            if row["job_mode"] != "solve":
                raise ExchangeError(
                    "solver_guidance_unavailable",
                    "추가 명령은 문제 풀이 작업에만 보낼 수 있습니다.",
                    category="input",
                )
            if row["status"] not in _GUIDANCE_OPEN_STATUSES:
                raise ExchangeError(
                    "solver_guidance_unavailable",
                    "현재 풀이 단계에는 추가 명령을 보낼 수 없습니다.",
                    category="input",
                )
            count = db.execute(
                "SELECT COUNT(*) FROM solver_job_guidance WHERE job_id=?",
                (job_id,),
            ).fetchone()[0]
            if count >= MAX_SOLVER_GUIDANCE_PER_JOB:
                raise ExchangeError(
                    "solver_guidance_limit_reached",
                    "이 풀이 작업의 추가 명령 수가 한도에 도달했습니다.",
                    category="input",
                )
            db.execute(
                """INSERT INTO solver_job_guidance(
                       id,job_id,owner_user_id,message,status,created_at
                   ) VALUES(?,?,?,?, 'queued',?)""",
                (guidance_id, job_id, owner_user_id, normalized, timestamp),
            )
            queued = db.execute(
                """SELECT id,job_id,message,status,provider_delivery,error_code,
                          created_at,staged_at,delivered_at
                   FROM solver_job_guidance WHERE id=?""",
                (guidance_id,),
            ).fetchone()
        return {
            "guidance": _public_guidance(queued),
            "job": self.get(job_id, owner_user_id),
        }

    def reject_candidate(self, job_id: str, owner_user_id: str) -> dict[str, Any]:
        """Record one agent candidate as wrong for the next isolated job.

        Only a released result belonging to the current owner can become a
        checkpoint.  The challenge and its agent write-up are reset in the
        same write transaction; manual completion is never changed here.
        """

        if not _JOB_ID.fullmatch(job_id):
            raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
        if not isinstance(owner_user_id, str) or not owner_user_id or len(owner_user_id) > 200 or _CONTROL.search(owner_user_id):
            raise ExchangeError("invalid_owner", "로그인 사용자를 확인할 수 없습니다.", category="auth")
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT j.*,c.flag AS challenge_flag,c.status AS challenge_status,
                           c.completion_source AS challenge_completion_source,
                           c.notes AS challenge_notes,
                           w.owner_user_id AS workspace_owner
                   FROM solver_jobs j
                   JOIN challenges c ON c.id=j.challenge_id AND c.workspace_id=j.workspace_id
                   JOIN workspaces w ON w.id=j.workspace_id
                   JOIN users u ON u.id=w.owner_user_id AND u.active=1
                   WHERE j.id=? AND j.owner_user_id=? AND w.owner_user_id=?""",
                (job_id, owner_user_id, owner_user_id),
            ).fetchone()
            if not row:
                raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
            if row["job_mode"] != "solve":
                raise ExchangeError(
                    "candidate_not_rejectable",
                    "write-up 보완 작업에서는 검증된 Flag를 오답으로 처리할 수 없습니다.",
                )
            if row["flag_rejected_at"] is not None:
                raise ExchangeError("candidate_already_rejected", "이미 오답으로 처리한 Flag입니다.")
            if (
                not row["released_ingested"]
                or row["released_at"] is None
                or row["status"] not in _TERMINAL_STATUSES
            ):
                raise ExchangeError(
                    "candidate_still_active",
                    "격리 풀이 정리가 끝난 뒤 Flag를 오답으로 처리해 주세요.",
                    retryable=True,
                )
            flag = row["flag"]
            if not isinstance(flag, str) or not flag:
                raise ExchangeError("candidate_not_found", "이 풀이 작업에는 발견된 Flag가 없습니다.")
            current_input_sha256 = _challenge_input_sha256(
                db, owner_user_id, row["workspace_id"], row["challenge_id"]
            )
            current_base_sha256 = _challenge_base_sha256(
                db, owner_user_id, row["workspace_id"], row["challenge_id"]
            )
            if row["challenge_input_sha256"] and row["challenge_input_sha256"] != current_input_sha256:
                raise ExchangeError(
                    "candidate_inputs_changed",
                    "풀이 이후 문제 설명·접속 정보 또는 첨부파일이 변경되어 이 결과를 재시도 기록으로 만들지 않았습니다.",
                )
            if db.execute(
                "SELECT 1 FROM solver_jobs WHERE owner_user_id=? AND workspace_id=? "
                "AND challenge_id=? AND status IN (%s) LIMIT 1"
                % ",".join("?" for _ in _OPEN_STATUSES),
                (
                    owner_user_id,
                    row["workspace_id"],
                    row["challenge_id"],
                    *_OPEN_STATUSES,
                ),
            ).fetchone():
                raise ExchangeError(
                    "candidate_retry_active",
                    "현재 풀이 작업의 격리 정리가 끝난 뒤 이전 Flag를 오답으로 처리해 주세요.",
                    retryable=True,
                )
            latest = db.execute(
                """SELECT id FROM solver_jobs
                   WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                     AND job_mode='solve' AND flag IS NOT NULL
                     AND flag_rejected_at IS NULL
                   ORDER BY created_at DESC,id DESC LIMIT 1""",
                (owner_user_id, row["workspace_id"], row["challenge_id"]),
            ).fetchone()
            if not latest or latest["id"] != job_id or row["challenge_flag"] != flag:
                raise ExchangeError(
                    "candidate_superseded",
                    "더 최근에 저장된 Flag가 있습니다. 문제 상태를 새로 불러와 주세요.",
                )
            if row["challenge_completion_source"] == "manual":
                raise ExchangeError(
                    "manual_completion_preserved",
                    "수동 완료 상태는 변경하지 않았습니다. 먼저 완료 취소 후 확인해 주세요.",
                )

            existing = db.execute(
                "SELECT * FROM solver_retry_checkpoints WHERE challenge_id=?",
                (row["challenge_id"],),
            ).fetchone()
            if existing and (
                existing["owner_user_id"] != owner_user_id
                or existing["workspace_id"] != row["workspace_id"]
            ):
                raise ExchangeError(
                    "invalid_retry_checkpoint",
                    "이전 오답 풀이 기록의 소유 범위를 확인할 수 없습니다.",
                    category="safety",
                )
            try:
                previous = (
                    decode_checkpoint(existing["checkpoint_json"])
                    if existing and (
                        not existing["input_sha256"]
                        or existing["input_sha256"] == current_input_sha256
                    )
                    else None
                )
                checkpoint = merge_checkpoint(
                    previous,
                    flag,
                    row["private_notes"] or "",
                    row["writeup_markdown"] or "",
                    decode_solver_artifact(row["solver_artifact_json"]),
                )
                encoded = encode_checkpoint(checkpoint)
            except OverflowError as exc:
                raise ExchangeError(
                    "retry_checkpoint_full",
                    "이 문제의 오답 풀이 기록이 안전한 보관 한도에 도달했습니다.",
                    category="storage",
                ) from exc
            except (TypeError, ValueError) as exc:
                raise ExchangeError(
                    "invalid_retry_checkpoint",
                    "이전 오답 풀이 기록을 안전하게 저장할 수 없습니다.",
                    category="safety",
                ) from exc

            db.execute(
                """INSERT INTO solver_retry_checkpoints
                       (challenge_id,workspace_id,owner_user_id,checkpoint_json,input_sha256,
                         base_input_sha256,source_remote_mode,source_job_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(challenge_id) DO UPDATE SET
                      checkpoint_json=excluded.checkpoint_json,
                      input_sha256=excluded.input_sha256,
                      base_input_sha256=excluded.base_input_sha256,
                      source_remote_mode=excluded.source_remote_mode,
                      source_job_id=excluded.source_job_id,
                     updated_at=excluded.updated_at""",
                (
                    row["challenge_id"],
                    row["workspace_id"],
                    owner_user_id,
                    encoded,
                    current_input_sha256,
                    current_base_sha256,
                    row["remote_mode"],
                    job_id,
                    timestamp,
                    timestamp,
                ),
            )
            db.execute(
                """UPDATE solver_jobs SET flag_rejected_at=?,flag_hooked=1,
                     writeup_hooked=1,updated_at=? WHERE id=?""",
                (timestamp, timestamp, job_id),
            )
            db.execute("DELETE FROM challenge_writeups WHERE challenge_id=?", (row["challenge_id"],))
            retained_notes = remove_generated_writeup(
                row["challenge_notes"], row["writeup_markdown"]
            )
            changed = db.execute(
                """UPDATE challenges SET flag=NULL,status='pending',previous_status=NULL,
                     completion_source=NULL,notes=?,updated_at=?
                   WHERE id=? AND workspace_id=? AND flag=?
                      AND (completion_source IS NULL OR completion_source!='manual')""",
                (
                    retained_notes,
                    _utc_stamp(timestamp),
                    row["challenge_id"],
                    row["workspace_id"],
                    flag,
                ),
            ).rowcount
            if changed != 1:
                raise ExchangeError(
                    "candidate_superseded",
                    "문제 상태가 변경되어 Flag를 오답으로 처리하지 않았습니다.",
                )
        return self.get(job_id, owner_user_id)

    def has_open_challenge(
        self,
        owner_user_id: str,
        workspace_id: str,
        challenge_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        """Check an ownership-bound challenge, optionally inside a caller transaction."""

        parameters = (owner_user_id, workspace_id, challenge_id, *_OPEN_STATUSES)
        query = (
            "SELECT 1 FROM solver_jobs WHERE owner_user_id=? AND workspace_id=? AND challenge_id=? "
            "AND status IN (%s) LIMIT 1" % ",".join("?" for _ in _OPEN_STATUSES)
        )
        if connection is not None:
            return connection.execute(query, parameters).fetchone() is not None
        with self._connect() as db:
            return db.execute(query, parameters).fetchone() is not None

    def has_open_account(
        self,
        owner_user_id: str,
        account_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        parameters = (owner_user_id, account_id, *_OPEN_STATUSES)
        query = (
            "SELECT 1 FROM solver_jobs WHERE owner_user_id=? AND account_id=? "
            "AND status IN (%s) LIMIT 1" % ",".join("?" for _ in _OPEN_STATUSES)
        )
        if connection is not None:
            return connection.execute(query, parameters).fetchone() is not None
        with self._connect() as db:
            return db.execute(query, parameters).fetchone() is not None

    def has_open_workspace(
        self,
        owner_user_id: str,
        workspace_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        parameters = (owner_user_id, workspace_id, *_OPEN_STATUSES)
        query = (
            "SELECT 1 FROM solver_jobs WHERE owner_user_id=? AND workspace_id=? "
            "AND status IN (%s) LIMIT 1" % ",".join("?" for _ in _OPEN_STATUSES)
        )
        if connection is not None:
            return connection.execute(query, parameters).fetchone() is not None
        with self._connect() as db:
            return db.execute(query, parameters).fetchone() is not None

    def has_open_jobs(self, *, connection: sqlite3.Connection | None = None) -> bool:
        query = "SELECT 1 FROM solver_jobs WHERE status IN (%s) LIMIT 1" % ",".join(
            "?" for _ in _OPEN_STATUSES
        )
        if connection is not None:
            return connection.execute(query, _OPEN_STATUSES).fetchone() is not None
        with self._connect() as db:
            return db.execute(query, _OPEN_STATUSES).fetchone() is not None

    def cancel(self, job_id: str, owner_user_id: str) -> dict[str, Any]:
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM solver_jobs WHERE id=? AND owner_user_id=?", (job_id, owner_user_id)).fetchone()
            if not row:
                raise ExchangeError("job_not_found", "풀이 작업을 찾을 수 없습니다.")
            if row["status"] == "queued":
                db.execute(
                    "UPDATE solver_jobs SET status='cancelled',cancel_requested=1,released_ingested=1,released_at=?,updated_at=? WHERE id=?",
                    (timestamp, timestamp, job_id),
                )
                db.execute(
                    """UPDATE solver_job_guidance SET status='rejected',
                         error_code='job_finished',delivered_at=?
                       WHERE job_id=? AND status IN ('queued','staged')""",
                    (timestamp, job_id),
                )
                if row["job_mode"] == "solve":
                    previous = row["previous_challenge_status"]
                    if previous not in _RESTORABLE_CHALLENGE_STATUSES:
                        previous = "pending"
                    db.execute(
                        """UPDATE challenges
                           SET status=?,previous_status=NULL,updated_at=?
                           WHERE id=? AND workspace_id=? AND status='running'""",
                        (
                            previous,
                            _utc_stamp(timestamp),
                            row["challenge_id"],
                            row["workspace_id"],
                        ),
                    )
            elif row["status"] not in _TERMINAL_STATUSES:
                db.execute("UPDATE solver_jobs SET cancel_requested=1,updated_at=? WHERE id=?", (timestamp, job_id))
        return self.get(job_id, owner_user_id)

    def cancel_challenge(self, workspace_id: str, challenge_id: str, owner_user_id: str) -> bool:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id FROM solver_jobs WHERE owner_user_id=? AND workspace_id=? AND challenge_id=? AND status IN (%s)"
                % ",".join("?" for _ in _OPEN_STATUSES),
                (owner_user_id, workspace_id, challenge_id, *_OPEN_STATUSES),
            ).fetchall()
        for row in rows:
            self.cancel(row["id"], owner_user_id)
        return not bool(rows)

    def cancel_workspace(self, workspace_id: str, owner_user_id: str) -> bool:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id FROM solver_jobs WHERE owner_user_id=? AND workspace_id=? AND status IN (%s)"
                % ",".join("?" for _ in _OPEN_STATUSES),
                (owner_user_id, workspace_id, *_OPEN_STATUSES),
            ).fetchall()
        for row in rows:
            self.cancel(row["id"], owner_user_id)
        return not bool(rows)

    def cancel_owner(self, owner_user_id: str) -> bool:
        """Terminalize queued work and request cancellation of an active owner job."""

        timestamp = self.clock()
        active_ids: list[str] = []
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                """SELECT id,status,job_mode,workspace_id,challenge_id,
                          previous_challenge_status
                   FROM solver_jobs WHERE owner_user_id=? AND status IN (%s)"""
                % ",".join("?" for _ in _OPEN_STATUSES),
                (owner_user_id, *_OPEN_STATUSES),
            ).fetchall()
            for row in rows:
                if row["status"] == "queued":
                    db.execute(
                        "UPDATE solver_jobs SET status='cancelled',cancel_requested=1,released_ingested=1,released_at=?,updated_at=? WHERE id=?",
                        (timestamp, timestamp, row["id"]),
                    )
                    db.execute(
                        """UPDATE solver_job_guidance SET status='rejected',
                             error_code='job_finished',delivered_at=?
                           WHERE job_id=? AND status IN ('queued','staged')""",
                        (timestamp, row["id"]),
                    )
                    if row["job_mode"] == "solve":
                        previous = row["previous_challenge_status"]
                        if previous not in _RESTORABLE_CHALLENGE_STATUSES:
                            previous = "pending"
                        db.execute(
                            """UPDATE challenges
                               SET status=?,previous_status=NULL,updated_at=?
                               WHERE id=? AND workspace_id=? AND status='running'""",
                            (
                                previous,
                                _utc_stamp(timestamp),
                                row["challenge_id"],
                                row["workspace_id"],
                            ),
                        )
                else:
                    active_ids.append(row["id"])
                    db.execute(
                        "UPDATE solver_jobs SET cancel_requested=1,updated_at=? WHERE id=?",
                        (timestamp, row["id"]),
                    )
        with self._lock():
            active = self.exchange / "active"
            if active.is_dir() and not active.is_symlink():
                try:
                    manifest = _read_json_file(active / "manifest.json", 512 * 1024)
                except ExchangeError:
                    manifest = {}
                if manifest.get("job_id") in active_ids:
                    _write_once(active / "cancel", b"cancel\n", 0o600)
        return not active_ids

    def request_stop(self) -> None:
        self.stop_requested.set()

    def reset_stop(self) -> None:
        self.stop_requested.clear()

    def wait_quiescent(self, timeout: float = 25.0) -> bool:
        """Boundedly join this coordinator's in-flight staging/tick work."""

        deadline = time.monotonic() + max(0.0, timeout)
        with self._activity:
            while self._active_ticks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._activity.wait(remaining)
        return True

    def _clear_stale_slot_claim(self) -> bool:
        """Delete this slot's claim only when its authoritative job is gone."""

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            removed = db.execute(
                """DELETE FROM solver_slots
                    WHERE slot_id=? AND NOT EXISTS (
                        SELECT 1 FROM solver_jobs j WHERE j.id=solver_slots.job_id
                    )""",
                (self.slot_id,),
            ).rowcount
        return bool(removed)

    def _cleanup_blocked_job_ids(self, *, own_slot: bool) -> set[str]:
        with self._connect() as db:
            if own_slot:
                rows = db.execute(
                    """SELECT j.id FROM solver_jobs j JOIN solver_slots s ON s.job_id=j.id
                        WHERE j.status='cleanup_blocked' AND s.slot_id=?""",
                    (self.slot_id,),
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT j.id FROM solver_jobs j JOIN solver_slots s ON s.job_id=j.id
                        WHERE j.status='cleanup_blocked'"""
                ).fetchall()
        return {str(row["id"]) for row in rows}

    def _cleanup_blocked_reservations(
        self,
    ) -> dict[str, tuple[str, str, str | None, int]]:
        """Preserve conservative remaining-byte promises until cleanup succeeds."""

        blocked = self._cleanup_blocked_job_ids(own_slot=False)
        expected: dict[str, tuple[str, str, str | None, int]] = {}
        for row in self.storage_budget.snapshot(kind="solver"):
            key = row.get("reservation_key")
            if not isinstance(key, str) or not key.startswith("solver:"):
                continue
            if key.removeprefix("solver:") not in blocked:
                continue
            expected[key] = (
                str(row["owner_user_id"]),
                str(row["workspace_id"]),
                str(row["challenge_id"]) if row.get("challenge_id") is not None else None,
                int(row["remaining_bytes"]),
            )
        return expected

    def health(self) -> dict[str, Any]:
        try:
            worker = self._worker_status(require_clean=False)
        except ExchangeError as exc:
            worker = {"ready": False, "error": exc.public(stage="worker")}
        with self._connect() as db:
            queued = db.execute("SELECT COUNT(*) FROM solver_jobs WHERE status='queued'").fetchone()[0]
            slot = db.execute(
                """SELECT s.job_id,j.id AS existing_job_id,j.status AS job_status
                     FROM solver_slots s LEFT JOIN solver_jobs j ON j.id=s.job_id
                    WHERE s.slot_id=?""",
                (self.slot_id,),
            ).fetchone()
        active = self.exchange / "active"
        active_exists = active.exists()
        consistency_error: dict[str, Any] | None = None
        cleanup_is_blocked = bool(slot and slot["job_status"] == "cleanup_blocked")
        if slot and slot["existing_job_id"] is None:
            consistency_error = ExchangeError(
                "stale_solver_slot",
                "solver 슬롯이 존재하지 않는 작업을 가리키고 있습니다.",
                category="safety",
                retryable=True,
            ).public(stage="worker")
        elif active_exists and not slot:
            consistency_error = ExchangeError(
                "orphan_active_job",
                "solver 작업 데이터와 일치하는 슬롯을 찾을 수 없습니다.",
                category="safety",
                retryable=True,
            ).public(stage="worker")
        elif active_exists and slot:
            try:
                manifest = _read_json_file(active / "manifest.json", 512 * 1024)
                if manifest.get("job_id") != slot["job_id"]:
                    raise ExchangeError(
                        "solver_slot_conflict",
                        "solver 작업 데이터와 슬롯 정보가 일치하지 않습니다.",
                        category="safety",
                        retryable=True,
                    )
            except ExchangeError as exc:
                consistency_error = exc.public(stage="worker")
        if cleanup_is_blocked and consistency_error is None:
            consistency_error = ExchangeError(
                "stage_cleanup_failed",
                "solver 임시 복사본을 아직 안전하게 정리하지 못했습니다.",
                category="safety",
                retryable=True,
            ).public(stage="cleanup")
        worker = dict(worker)
        worker["cleanup_blocked"] = cleanup_is_blocked
        blocked = consistency_error or self.last_block
        return {
            "ready": bool(worker.get("ready")) and blocked is None,
            "worker": worker,
            "queued": queued,
            "active": bool(slot and slot["existing_job_id"] is not None),
            "blocked": blocked,
            "network_policy": "general_internet",
            "supported_challenge_mode": "static_attachments_and_open_internet",
            "scratch_limit_bytes": None,
        }

    def publish_runtime(self, version: str, source_root: Path | None = None,
                        provider: str = "codex") -> dict[str, Any]:
        """Publish one verified CLI tree as an immutable job snapshot."""

        if provider not in {"codex", "claude"}:
            raise ExchangeError("invalid_provider", "Unknown runtime provider.", category="model")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ExchangeError("invalid_runtime_version", "Codex 실행 버전을 확인할 수 없습니다.", category="model")
        if source_root is None:
            if version != (REQUIRED_CODEX_VERSION if provider == "codex" else REQUIRED_CLAUDE_VERSION):
                raise ExchangeError("runtime_not_published", "선택한 Codex runtime 원본을 찾을 수 없습니다.", category="model")
            return {"version": version, "sha256": None, "source": "image"}
        source = Path(source_root)
        if source.name != f"{provider}-{version}" or source.is_symlink() or not source.is_dir():
            raise ExchangeError("invalid_runtime_path", "Codex runtime 원본 경로를 확인할 수 없습니다.", category="safety")
        files, total = _runtime_files(source, version, provider)
        source_digest = _runtime_digest_for_files(source, files)
        runtime_root = self.exchange / "runtime"
        destination = runtime_root / f"{provider}-{version}"
        with self._lock():
            runtime_root.mkdir(mode=0o755, exist_ok=True)
            if runtime_root.is_symlink() or runtime_root.resolve().parent != self.exchange.resolve():
                raise ExchangeError("invalid_runtime_path", "solver runtime 게시 경로를 확인할 수 없습니다.", category="safety")
            if destination.exists():
                published_files, published_total = _runtime_files(destination, version, provider)
                published_digest = _runtime_digest_for_files(destination, published_files)
                if (published_total != total or published_digest != source_digest) and not self.has_open_jobs():
                    # This is a derived copy and no job can still depend on it.
                    # Recreate it from the verified source before accepting work.
                    _make_tree_owner_writable(destination, runtime_root)
                    _safe_remove_tree(destination, runtime_root)
            if destination.exists():
                published = _runtime_files(destination, version, provider)
                digest = runtime_tree_digest(destination)
                if published[1] != total or digest != source_digest:
                    raise ExchangeError("runtime_integrity_failed", "게시된 Codex runtime이 원본과 일치하지 않습니다.", category="safety")
                return {"version": version, "sha256": digest, "source": "exchange"}
            if self.has_open_jobs():
                raise ExchangeError(
                    "runtime_busy",
                    "실행 또는 대기 중인 풀이를 중단하고 정리가 끝난 뒤 Codex를 변경해 주세요.",
                    category="model",
                    retryable=True,
                )
            staging = runtime_root / f".staging-{uuid.uuid4().hex}"
            reservation = f"solver-runtime:{version}:{uuid.uuid4().hex}"
            try:
                self.storage_budget.reserve(
                    reservation,
                    "solver_runtime",
                    "system",
                    "runtime",
                    version,
                    _checked_total(total, _STAGE_CONTROL_RESERVE),
                    prepare=lambda: staging.mkdir(mode=0o700),
                )
                for relative, size, executable in files:
                    source_file, target = source / relative, staging / relative
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

                    def copy_one(source_file=source_file, target=target, size=size, executable=executable):
                        _copy_regular_file(
                            source_file,
                            target,
                            expected_size=size,
                            cancelled=lambda: self.stop_requested.is_set(),
                            space_reserved=True,
                        )
                        target.chmod(0o555 if executable else 0o444)

                    if size:
                        self.storage_budget.commit_reserved_write(reservation, size, copy_one)
                    else:
                        copy_one()
                for directory in sorted(
                    (path for path in staging.rglob("*") if path.is_dir()),
                    key=lambda path: len(path.parts),
                    reverse=True,
                ):
                    directory.chmod(0o555)
                staging.chmod(0o555)
                digest = runtime_tree_digest(staging)
                if digest != source_digest:
                    raise ExchangeError("runtime_integrity_failed", "Codex runtime copy digest mismatch", category="safety")
                os.replace(staging, destination)
                _fsync(runtime_root)
                self.storage_budget.release(reservation)
                return {"version": version, "sha256": digest, "source": "exchange"}
            except BaseException:
                try:
                    # chmod from the immutable publication step may already
                    # have run; restore owner write only inside this verified
                    # hidden staging tree before cleanup.
                    _make_tree_owner_writable(staging, runtime_root)
                    self.storage_budget.release(
                        reservation,
                        cleanup=lambda: _safe_remove_tree(staging, runtime_root),
                    )
                except (StorageBudgetError, ExchangeError, OSError):
                    pass
                raise

    def tick(self) -> bool:
        """Perform one restart-safe coordinator step; intended for a thread."""

        with self._activity:
            self._active_ticks += 1
        try:
            return self._tick_once()
        finally:
            with self._activity:
                self._active_ticks -= 1
                self._activity.notify_all()

    def _tick_once(self) -> bool:

        with self._lock():
            self._clear_stale_slot_claim()
            self._remove_retired()
            # A transient filesystem failure while cleaning a hidden staging
            # copy used to leave the job in cleanup_blocked forever after its
            # slot had already been released. Retry that ownerless cleanup on
            # every coordinator tick before considering new work.
            hook_progress = self._retry_orphaned_stage_cleanups()
            if self.deliver_global_hooks and not self.defer_global_hooks:
                hook_progress = self._deliver_pending_hook_batch() or hook_progress
            with self._connect() as db:
                slot = db.execute(
                    """SELECT j.* FROM solver_slots s JOIN solver_jobs j ON j.id=s.job_id
                         WHERE s.slot_id=?""",
                    (self.slot_id,),
                ).fetchone()
            active = self.exchange / "active"
            if slot:
                if slot["status"] == "cleanup_blocked":
                    self.last_block = ExchangeError(
                        "stage_cleanup_failed",
                        "solver 임시 복사본을 아직 안전하게 정리하지 못했습니다.",
                        category="safety",
                        retryable=True,
                    ).public(stage="cleanup")
                    return hook_progress
                changed = self._tick_slot(dict(slot), active)
                if self.deliver_global_hooks and not self.defer_global_hooks:
                    self._deliver_pending_hooks(slot["id"])
                return changed or hook_progress
            if active.exists():
                return self._recover_orphan_active(active)
            if not self.accept_new_jobs:
                # A protected slot above the newly requested capacity remains
                # alive only long enough to ingest/release its existing job.
                self.last_block = None
                return hook_progress
            try:
                worker = self._worker_status(require_clean=True)
            except ExchangeError as exc:
                self.last_block = exc.public(stage="worker")
                return False
            job = self._claim_next(worker["instance_id"])
            if not job:
                self.last_block = None
                return hook_progress
            try:
                self._stage_initial(job, worker["instance_id"])
            except _StageCancelled:
                self._fail_staging(job["id"], "cancelled", None)
            except ExchangeError as exc:
                self._fail_staging(job["id"], "refused", exc.public(stage="staging"))
            except StorageBudgetError:
                error = ExchangeError(
                    "insufficient_solver_storage",
                    "격리 복사본을 만들 저장 공간이 부족합니다. 원본 파일은 보존되었습니다.",
                    category="storage",
                    retryable=True,
                )
                self._fail_staging(job["id"], "failed", error.public(stage="staging"))
            except (OSError, sqlite3.Error):
                error = ExchangeError("stage_storage_failed", "문제 파일을 격리 worker에 준비하지 못했습니다.", retryable=True)
                self._fail_staging(job["id"], "failed", error.public(stage="staging"))
            else:
                self.last_block = None
            return True

    def _claim_next(self, worker_instance_id: str) -> dict[str, Any] | None:
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM solver_slots WHERE slot_id=?", (self.slot_id,)
            ).fetchone():
                return None
            db.execute(
                """UPDATE solver_jobs SET status='cancelled',cancel_requested=1,released_ingested=1,
                   released_at=?,updated_at=? WHERE status='queued' AND NOT EXISTS
                   (SELECT 1 FROM users u WHERE u.id=solver_jobs.owner_user_id AND u.active=1)""",
                (timestamp, timestamp),
            )
            row = db.execute(
                """SELECT j.* FROM solver_jobs j
                   JOIN users u ON u.id=j.owner_user_id AND u.active=1
                   LEFT JOIN solver_owner_service s ON s.owner_user_id=j.owner_user_id
                   WHERE j.status='queued' AND NOT EXISTS (
                     SELECT 1 FROM solver_jobs earlier
                     WHERE earlier.owner_user_id=j.owner_user_id AND earlier.status='queued'
                       AND (earlier.created_at<j.created_at OR
                            (earlier.created_at=j.created_at AND earlier.id<j.id))
                   )
                   ORDER BY COALESCE(s.last_served_at,0),j.created_at,j.id LIMIT 1"""
            ).fetchone()
            if not row:
                return None
            challenge = db.execute(
                """SELECT c.status,c.completion_source,c.flag FROM challenges c
                   JOIN workspaces w ON w.id=c.workspace_id
                    WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=?""",
                (row["challenge_id"], row["workspace_id"], row["owner_user_id"]),
            ).fetchone()
            unavailable = not challenge
            if not unavailable and row["job_mode"] == "writeup_refine":
                writeup = db.execute(
                    "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                    (row["challenge_id"],),
                ).fetchone()
                digest = (
                    hashlib.sha256(writeup["markdown"].encode("utf-8")).hexdigest()
                    if writeup and isinstance(writeup["markdown"], str)
                    else None
                )
                unavailable = bool(
                    challenge["status"] != "solved"
                    or challenge["completion_source"] != "agent"
                    or challenge["flag"] != row["flag"]
                    or not isinstance(row["source_writeup_sha256"], str)
                    or digest is None
                    or not secrets.compare_digest(digest, row["source_writeup_sha256"])
                )
            elif not unavailable:
                unavailable = challenge["status"] == "solved"
            if unavailable:
                error = (
                    ExchangeError(
                        "writeup_source_changed",
                        "대기 중 기존 write-up 또는 검증된 Flag가 변경되어 보완 작업을 실행하지 않았습니다.",
                        category="safety",
                    )
                    if row["job_mode"] == "writeup_refine"
                    else ExchangeError(
                        "challenge_unavailable",
                        "대기 중인 문제를 더 이상 실행할 수 없습니다.",
                    )
                ).public(stage="staging")
                db.execute(
                    "UPDATE solver_jobs SET status='refused',released_ingested=1,error_json=?,released_at=?,updated_at=? WHERE id=?",
                    (json.dumps(error, ensure_ascii=False), timestamp, timestamp, row["id"]),
                )
                return None
            db.execute(
                "INSERT INTO solver_slots(slot_id,job_id) VALUES(?,?)",
                (self.slot_id, row["id"]),
            )
            db.execute(
                """INSERT INTO solver_owner_service(owner_user_id,last_served_at) VALUES(?,?)
                   ON CONFLICT(owner_user_id) DO UPDATE SET last_served_at=excluded.last_served_at""",
                (row["owner_user_id"], timestamp),
            )
            db.execute(
                """UPDATE solver_jobs SET status='staging',
                       previous_challenge_status=COALESCE(previous_challenge_status,?),
                       worker_instance_id=?,updated_at=?
                   WHERE id=?""",
                (challenge["status"], worker_instance_id, timestamp, row["id"]),
            )
            if row["job_mode"] == "solve":
                db.execute(
                    """UPDATE challenges
                       SET previous_status=CASE WHEN status='running' THEN previous_status ELSE status END,
                           status='running',updated_at=?
                       WHERE id=? AND workspace_id=?""",
                    (_utc_stamp(timestamp), row["challenge_id"], row["workspace_id"]),
                )
            return dict(db.execute("SELECT * FROM solver_jobs WHERE id=?", (row["id"],)).fetchone())

    def _tick_slot(self, job: dict[str, Any], active: Path) -> bool:
        with self._connect() as db:
            owner_active = db.execute(
                "SELECT 1 FROM users WHERE id=? AND active=1", (job["owner_user_id"],)
            ).fetchone()
            if not owner_active and not job["cancel_requested"]:
                db.execute(
                    "UPDATE solver_jobs SET cancel_requested=1,updated_at=? WHERE id=?",
                    (self.clock(), job["id"]),
                )
                job["cancel_requested"] = 1
        if not active.exists():
            if job["released_ingested"] or job["status"] in _TERMINAL_STATUSES:
                self._clear_slot(job["id"])
                return True
            # The web process may have stopped while building a hidden staging
            # directory.  Rebuild from DB; no credential was model-visible.
            try:
                worker = self._worker_status(require_clean=True)
                self._stage_initial(job, worker["instance_id"])
            except _StageCancelled:
                self._fail_staging(job["id"], "cancelled", None)
            except ExchangeError as exc:
                if exc.retryable:
                    self.last_block = exc.public(stage="staging")
                    return False
                self._fail_staging(job["id"], "refused", exc.public(stage="staging"))
            except StorageBudgetError:
                self.last_block = ExchangeError(
                    "insufficient_solver_storage",
                    "격리 복사본을 만들 저장 공간이 부족합니다. 원본 파일은 보존되었습니다.",
                    category="storage",
                    retryable=True,
                ).public(stage="staging")
                return False
            except (OSError, sqlite3.Error):
                self.last_block = ExchangeError(
                    "stage_storage_failed", "문제 파일을 격리 worker에 준비하지 못했습니다.", retryable=True
                ).public(stage="staging")
                return False
            return True
        manifest = _read_json_file(active / "manifest.json", 512 * 1024)
        if manifest.get("job_id") != job["id"] or manifest.get("protocol") != EXCHANGE_PROTOCOL:
            self.last_block = ExchangeError("active_job_mismatch", "격리 worker의 활성 작업과 DB 슬롯이 일치하지 않습니다.", category="safety").public(stage="worker")
            return False
        changed = self._ingest_events(job, active)
        with self._connect() as db:
            current = db.execute("SELECT * FROM solver_jobs WHERE id=?", (job["id"],)).fetchone()
        if not current:
            self.last_block = ExchangeError("active_job_missing", "활성 solver 작업의 DB 기록이 없습니다.", category="safety").public(stage="worker")
            return False
        current = dict(current)
        if current["cancel_requested"]:
            _write_once(active / "cancel", b"cancel\n", 0o600)
        elif not current["released_ingested"] and current["status"] in _GUIDANCE_OPEN_STATUSES:
            changed = self._sync_guidance(current, active) or changed
        request = active / "credential-request.json"
        if (
            request.is_file()
            and not (active / _credential_stage_name(current["provider"])).exists()
            and not current["released_ingested"]
            and not current["cancel_requested"]
        ):
            try:
                self._worker_status(require_clean=True)
                self._restage_auth(current, active)
                changed = True
            except _StageCancelled:
                _write_once(active / "cancel", b"cancel\n", 0o600)
            except ExchangeError as exc:
                self.last_block = exc.public(stage="auth")
        if current["released_ingested"]:
            self._capture_private_notes(current, active)
            self._retire_active(current["id"], active)
            self._clear_slot(current["id"])
            changed = True
        return changed

    def _sync_guidance(self, job: Mapping[str, Any], active: Path) -> bool:
        """Publish durable guidance into only this job's isolated control tree."""

        directory = active / "guidance"
        if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
            raise ExchangeError(
                "invalid_guidance_path",
                "추가 명령 전달 경로를 확인할 수 없습니다.",
                category="safety",
            )
        directory.mkdir(mode=0o700, exist_ok=True)
        if os.name == "posix":
            directory.chmod(0o700)
        with self._connect() as db:
            rows = db.execute(
                """SELECT id,job_id,owner_user_id,message,status,created_at
                   FROM solver_job_guidance
                   WHERE job_id=? AND owner_user_id=? AND status IN ('queued','staged')
                   ORDER BY created_at,id""",
                (job["id"], job["owner_user_id"]),
            ).fetchall()
        changed = False
        for row in rows:
            path = directory / f"{row['id']}.json"
            if path.exists():
                try:
                    payload = _read_json_file(path, MAX_SOLVER_GUIDANCE_BYTES + 1024)
                except ExchangeError:
                    raise ExchangeError(
                        "invalid_guidance_path",
                        "추가 명령 전달 파일을 확인할 수 없습니다.",
                        category="safety",
                    ) from None
                if payload != {
                    "protocol": EXCHANGE_PROTOCOL,
                    "job_id": row["job_id"],
                    "guidance_id": row["id"],
                    "message": row["message"],
                    "created_at": row["created_at"],
                }:
                    raise ExchangeError(
                        "invalid_guidance_path",
                        "추가 명령 전달 파일이 저장 기록과 일치하지 않습니다.",
                        category="safety",
                    )
            else:
                _write_json_file(
                    path,
                    {
                        "protocol": EXCHANGE_PROTOCOL,
                        "job_id": row["job_id"],
                        "guidance_id": row["id"],
                        "message": row["message"],
                        "created_at": row["created_at"],
                    },
                )
                changed = True
            if row["status"] == "queued":
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    updated = db.execute(
                        """UPDATE solver_job_guidance
                           SET status='staged',staged_at=?
                           WHERE id=? AND job_id=? AND owner_user_id=? AND status='queued'""",
                        (
                            self.clock(),
                            row["id"],
                            job["id"],
                            job["owner_user_id"],
                        ),
                    ).rowcount
                changed = bool(updated) or changed
        return changed

    def _capture_private_notes(
        self,
        job: Mapping[str, Any],
        active: Path,
        release_event: Mapping[str, Any] | None = None,
    ) -> None:
        """Copy private solve facts before the isolated exchange tree is retired.

        The public event stream deliberately omits these notes.  A terminal
        state is written before the release event, so a coordinator that sees
        the release can durably retain the facts needed for a later rejected
        candidate retry without retaining the worker scratch tree.
        """

        try:
            state = _read_json_file(active / "state.json", 6 * 1024 * 1024)
        except ExchangeError:
            return
        notes = state.get("private_notes")
        if (
            state.get("protocol") != EXCHANGE_PROTOCOL
            or state.get("job_id") != job["id"]
            or not isinstance(notes, str)
            or len(notes) > 1_000_000
            or len(notes.encode("utf-8")) > 4 * 1024 * 1024
            or _CONTROL.search(notes)
        ):
            return
        try:
            notes = bounded_checkpoint_notes(notes)
        except ValueError:
            return
        raw_artifact = state.get("solver_artifact")
        try:
            artifact = (
                parse_solver_artifact(raw_artifact)
                if raw_artifact is not None
                else None
            )
            artifact_json = encode_solver_artifact(artifact)
        except (TypeError, ValueError):
            artifact = None
            artifact_json = None
        status = (
            release_event.get("status")
            if release_event is not None
            else job.get("status")
        )
        error = (
            release_event.get("error")
            if release_event is not None
            else _optional_json(job.get("error_json"))
        )
        flag = state.get("flag") or (
            release_event.get("flag") if release_event is not None else job.get("flag")
        )
        reason = None
        if not flag:
            if status == "needs_input":
                reason = "needs_remote"
            elif status == "cancelled":
                reason = "cancelled"
            elif status in {"failed", "refused"}:
                code = error.get("code") if isinstance(error, Mapping) else None
                reason = (
                    "timeout" if code == "timeout"
                    else "turn_limit" if code == "flag_not_submitted"
                    else "provider_failure" if status == "failed"
                    else None
                )
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE solver_jobs SET private_notes=?,solver_artifact_json=?,updated_at=? WHERE id=?",
                (notes, artifact_json, timestamp, job["id"]),
            )
            if reason is None:
                return
            input_sha256 = job.get("challenge_input_sha256")
            base_sha256 = job.get("challenge_base_sha256")
            remote_mode = job.get("remote_mode")
            if (
                not isinstance(input_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", input_sha256)
                or not isinstance(base_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", base_sha256)
                or remote_mode not in {"unknown", "none", "endpoint"}
            ):
                return
            existing = db.execute(
                "SELECT source_job_id FROM solver_retry_checkpoints WHERE challenge_id=?",
                (job["challenge_id"],),
            ).fetchone()
            if existing and existing["source_job_id"] == job["id"]:
                return
            try:
                previous = decode_checkpoint(job.get("retry_checkpoint_json"))
                checkpoint = merge_continuation(
                    previous,
                    notes,
                    reason,
                    solver_artifact=artifact,
                )
                encoded = encode_checkpoint(checkpoint)
            except (TypeError, ValueError, OverflowError):
                return
            db.execute(
                """INSERT INTO solver_retry_checkpoints
                       (challenge_id,workspace_id,owner_user_id,checkpoint_json,input_sha256,
                        base_input_sha256,source_remote_mode,source_job_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(challenge_id) DO UPDATE SET
                     checkpoint_json=excluded.checkpoint_json,
                     input_sha256=excluded.input_sha256,
                     base_input_sha256=excluded.base_input_sha256,
                     source_remote_mode=excluded.source_remote_mode,
                     source_job_id=excluded.source_job_id,
                     updated_at=excluded.updated_at""",
                (
                    job["challenge_id"],
                    job["workspace_id"],
                    job["owner_user_id"],
                    encoded,
                    input_sha256,
                    base_sha256,
                    remote_mode,
                    job["id"],
                    timestamp,
                    timestamp,
                ),
            )

    def _recover_orphan_active(self, active: Path) -> bool:
        if active.is_symlink() or not active.is_dir() or active.resolve().parent != self.exchange.resolve():
            self.last_block = ExchangeError("invalid_active_path", "solver 활성 디렉터리 형식을 확인할 수 없습니다.", category="safety").public(stage="worker")
            return False
        try:
            manifest = _read_json_file(active / "manifest.json", 512 * 1024)
        except ExchangeError as exc:
            self.last_block = exc.public(stage="worker")
            return False
        job_id = manifest.get("job_id")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM solver_jobs WHERE id=?", (job_id,)).fetchone() if isinstance(job_id, str) else None
            if row:
                db.execute(
                    "INSERT OR IGNORE INTO solver_slots(slot_id,job_id) VALUES(?,?)",
                    (self.slot_id, job_id),
                )
                claimed = db.execute(
                    "SELECT slot_id,job_id FROM solver_slots WHERE slot_id=? OR job_id=?",
                    (self.slot_id, job_id),
                ).fetchall()
                if len(claimed) == 1 and tuple(claimed[0]) == (self.slot_id, job_id):
                    self.last_block = None
                    return True
                self.last_block = ExchangeError(
                    "solver_slot_conflict",
                    "solver 작업 데이터가 다른 슬롯 정보와 충돌합니다.",
                    category="safety",
                    retryable=True,
                ).public(stage="worker")
                return False
        self.last_block = ExchangeError("orphan_active_job", "소유 정보를 확인할 수 없는 solver 작업이 남아 새 작업을 차단했습니다.", category="safety").public(stage="worker")
        return False

    def _stage_initial(self, job: Mapping[str, Any], worker_instance_id: str) -> None:
        active = self.exchange / "active"
        if active.exists():
            raise ExchangeError("solver_slot_busy", "다른 solver 작업이 이미 준비되어 있습니다.", retryable=True)
        staging = self.exchange / f".staging-{job['id']}"
        _safe_remove_tree(staging, self.exchange)
        reservation = "solver:" + job["id"]
        try:
            record, attachments = self._stage_records(job)
            related_context = record.pop("_related_context", "")
            attachment_bytes = _attachment_total(attachments)
            source_writeup = record.pop("_source_writeup", None)
            source_writeup_bytes = (
                source_writeup.encode("utf-8")
                if isinstance(source_writeup, str)
                else b""
            )
            auth_size = _regular_file_size(
                self._auth_source(job),
                maximum_size=MAX_AUTH_BYTES,
                require_private=True,
            )
            total = _checked_total(
                attachment_bytes,
                auth_size,
                len(source_writeup_bytes),
                _STAGE_CONTROL_RESERVE,
            )

            def prepare_stage() -> None:
                staging.mkdir(mode=0o700)
                (staging / "challenge").mkdir(mode=0o700)

            self.storage_budget.reserve(
                reservation,
                "solver",
                job["owner_user_id"],
                job["workspace_id"],
                job["challenge_id"],
                total,
                prepare=prepare_stage,
            )
            challenge = staging / "challenge"
            self._copy_attachments(job["id"], job["workspace_id"], job["challenge_id"], attachments, challenge)
            if job["job_mode"] == "writeup_refine":
                if not source_writeup_bytes:
                    raise ExchangeError(
                        "invalid_writeup_refinement_context",
                        "보완할 write-up 원본을 확인할 수 없습니다.",
                        category="safety",
                    )
                self.storage_budget.commit_reserved_write(
                    reservation,
                    len(source_writeup_bytes),
                    lambda: _write_regular_file(
                        staging / "writeup-source.md", source_writeup_bytes, 0o600
                    ),
                )
            auth_temp = staging / ".auth.tmp"
            digest_box: dict[str, str] = {}

            def copy_auth() -> None:
                digest_box["value"] = self._copy_auth(job, auth_temp, expected_size=auth_size)

            self.storage_budget.commit_reserved_write(reservation, auth_size, copy_auth)
            digest = digest_box["value"]
            configuration = ModelConfiguration(
                provider=job["provider"],
                model=job["model"],
                reasoning_effort=job["reasoning_effort"],
                service_tier=job["service_tier"],
            )
            try:
                retry_checkpoint = decode_checkpoint(job.get("retry_checkpoint_json"))
                solver_artifact = decode_solver_artifact(job.get("solver_artifact_json"))
            except (TypeError, ValueError) as exc:
                raise ExchangeError(
                    "invalid_retry_checkpoint",
                    "이전 오답 풀이 기록을 안전하게 확인할 수 없습니다.",
                    category="safety",
                ) from exc
            execution_started = self.clock()
            is_refinement = job["job_mode"] == "writeup_refine"
            manifest = {
                    "protocol": EXCHANGE_PROTOCOL,
                    "job_id": job["id"],
                    "job_mode": job["job_mode"],
                    "writeup_locale": job["writeup_locale"],
                    "challenge_name": record["name"],
                    "challenge_text": record["description"],
                    "related_context": related_context,
                    "category": record.get("category") or "",
                    "flag_format": record.get("workspace_flag_format") or "",
                    "remote": "" if is_refinement else (record.get("remote") or ""),
                    "remote_mode": "none" if is_refinement else (record.get("remote_mode") or "unknown"),
                    **configuration.public(),
                    "max_reasoning_available": bool(job["max_reasoning_available"]),
                    "codex_version": job["codex_version"],
                    "codex_runtime_sha256": job["codex_runtime_sha256"],
                    "claude_version": job["claude_version"],
                    "claude_runtime_sha256": job["claude_runtime_sha256"],
                    "credential_file": _credential_stage_name(job["provider"]),
                    "auth_sha256": digest,
                    "max_seconds": MAX_JOB_SECONDS,
                    "created_at": execution_started,
                    "deadline_unix": (
                        execution_started + MAX_JOB_SECONDS
                        if MAX_JOB_SECONDS
                        else None
                    ),
                    # Match the original ctf_agent solve environment: every solve
                    # can use normal DNS and direct Internet sockets, regardless
                    # of whether the challenge metadata already names an endpoint.
                    # Editorial-only refinement remains tool-free and offline.
                    "network_enabled": not is_refinement,
                    "network_policy": "offline" if is_refinement else "general_internet",
                    "retry_checkpoint": retry_checkpoint.payload() if retry_checkpoint else None,
                }
            if is_refinement:
                manifest["refinement_context"] = {
                    "instruction": job["writeup_instruction"],
                    "verified_flag": job["flag"],
                    "private_notes": job["private_notes"] or "",
                    "solver_artifact": solver_artifact.payload() if solver_artifact else None,
                    "source_writeup_sha256": job["source_writeup_sha256"],
                    "source_solver_job_id": job["source_solver_job_id"],
                }
            manifest_size = len(_json_bytes(manifest))
            if manifest_size > _MAX_MANIFEST_BYTES:
                raise ExchangeError(
                    "manifest_too_large",
                    "문제 설명과 이전 오답 기록이 solver 제어 파일 한도를 초과했습니다.",
                    category="safety",
                )
            self.storage_budget.commit_reserved_write(
                reservation,
                manifest_size,
                lambda: _write_json_file(staging / "manifest.json", manifest),
            )
            os.replace(auth_temp, staging / _credential_stage_name(job["provider"]))
            _fsync(staging)
            if self._is_cancelled(job["id"]):
                raise _StageCancelled
            os.replace(staging, active)
            _fsync(self.exchange)
            with self._connect() as db:
                db.execute(
                    "UPDATE solver_jobs SET status='staging',worker_instance_id=?,updated_at=? WHERE id=?",
                    (worker_instance_id, self.clock(), job["id"]),
                )
            # Directory metadata and temporary rename headroom remain reserved
            # until the complete active tree and database slot are durable.
            self.storage_budget.release(reservation)
        except BaseException:
            try:
                self.storage_budget.release(
                    reservation,
                    cleanup=lambda: _safe_remove_tree(staging, self.exchange),
                )
            except (StorageBudgetError, ExchangeError, OSError):
                # Keep the conservative reservation if cleanup cannot be
                # proven; a later reconcile blocks rather than overcommits.
                pass
            raise

    def _stage_records(self, job: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        with self._connect() as db:
            # Keep the staged records and their material-input digest on one
            # SQLite snapshot.  In particular, a queued retry must never pair
            # an old POISON checkpoint with a flag format edited after enqueue.
            db.execute("BEGIN")
            record = db.execute(
                """SELECT c.*,w.flag_format AS workspace_flag_format FROM challenges c JOIN workspaces w ON w.id=c.workspace_id
                   WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=?""",
                (job["challenge_id"], job["workspace_id"], job["owner_user_id"]),
            ).fetchone()
            account = db.execute(
                "SELECT id FROM provider_accounts WHERE id=? AND owner_user_id=? AND provider=?",
                (job["account_id"], job["owner_user_id"], job["provider"]),
            ).fetchone()
            attachments = (
                []
                if job["job_mode"] == "writeup_refine"
                else db.execute(
                    "SELECT * FROM attachments WHERE workspace_id=? AND challenge_id=? ORDER BY created_at,id",
                    (job["workspace_id"], job["challenge_id"]),
                ).fetchall()
            )
            related_context = ""
            if job["job_mode"] == "solve":
                related_rows = db.execute(
                    """SELECT c.id,c.name,c.category,c.description,c.completion_source,c.flag,c.notes,w.markdown
                         FROM challenge_relations r
                         JOIN challenges c ON c.id=r.prerequisite_id AND c.workspace_id=r.workspace_id
                         LEFT JOIN challenge_writeups w ON w.challenge_id=c.id
                        WHERE r.workspace_id=? AND r.dependent_id=? AND c.status='solved'
                        ORDER BY r.created_at,c.id LIMIT 6""",
                    (job["workspace_id"], job["challenge_id"]),
                ).fetchall()
                if related_rows:
                    related_data = [
                        {"id": row["id"], "name": row["name"], "completion_source": row["completion_source"],
                         "category": row["category"], "description": (row["description"] or "")[:1200],
                         "flag": row["flag"], "notes": (row["notes"] or "")[:1800],
                         "writeup": (row["markdown"] or "")[:1800]}
                        for row in related_rows
                    ]
                    while related_data:
                        related_context = json.dumps(related_data, ensure_ascii=False)
                        if len(related_context.encode("utf-8")) <= 32_768:
                            break
                        related_data.pop()
                    if not related_data:
                        related_context = ""
            current_input_sha256 = _challenge_input_sha256(
                db,
                job["owner_user_id"],
                job["workspace_id"],
                job["challenge_id"],
            )
            current = None
            source_job = None
            if job["job_mode"] == "writeup_refine":
                current = db.execute(
                    """SELECT c.status,c.completion_source,c.flag,w.markdown
                       FROM challenges c
                       JOIN workspaces ws ON ws.id=c.workspace_id
                       JOIN challenge_writeups w ON w.challenge_id=c.id
                       WHERE c.id=? AND c.workspace_id=? AND ws.owner_user_id=?""",
                    (job["challenge_id"], job["workspace_id"], job["owner_user_id"]),
                ).fetchone()
                source_job = db.execute(
                    """SELECT id,status,released_ingested,flag,writeup_markdown,flag_rejected_at FROM solver_jobs
                       WHERE id=? AND owner_user_id=? AND workspace_id=? AND challenge_id=?""",
                    (
                        job["source_solver_job_id"],
                        job["owner_user_id"],
                        job["workspace_id"],
                        job["challenge_id"],
                    ),
                ).fetchone()
        if not record:
            raise ExchangeError("challenge_unavailable", "문제가 삭제되었거나 소유자가 변경되었습니다.")
        if not account:
            raise ExchangeError("account_unavailable", "선택했던 모델 계정을 더 이상 사용할 수 없습니다.", category="auth")
        source_writeup = None
        if job["job_mode"] == "writeup_refine":
            if not current or not source_job:
                raise ExchangeError(
                    "writeup_source_changed",
                    "보완 작업을 시작하기 전에 기존 write-up이 변경되었습니다.",
                    category="safety",
                )
            source_writeup = current["markdown"]
            source_digest = (
                hashlib.sha256(source_writeup.encode("utf-8")).hexdigest()
                if isinstance(source_writeup, str)
                else None
            )
            if (
                current["status"] != "solved"
                or current["completion_source"] != "agent"
                or current["flag"] != job["flag"]
                or source_job["status"] != "completed"
                or not source_job["released_ingested"]
                or source_job["flag"] != job["flag"]
                or source_job["writeup_markdown"] != source_writeup
                or source_job["flag_rejected_at"] is not None
                or source_digest is None
                or not isinstance(job["source_writeup_sha256"], str)
                or not secrets.compare_digest(source_digest, job["source_writeup_sha256"])
                or len(source_writeup.encode("utf-8")) > MAX_OUTPUT_TEXT
                or _CONTROL.search(source_writeup)
            ):
                raise ExchangeError(
                    "writeup_source_changed",
                    "보완 작업을 시작하기 전에 기존 write-up 또는 검증된 Flag가 변경되었습니다.",
                    category="safety",
                )
        bound_input_sha256 = job["challenge_input_sha256"]
        if bound_input_sha256 is not None and (
            not isinstance(bound_input_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", bound_input_sha256)
            or not secrets.compare_digest(bound_input_sha256, current_input_sha256)
        ):
            raise ExchangeError(
                "challenge_inputs_changed",
                "대기 중 문제의 설명·접속 정보·Flag 형식 또는 첨부파일이 변경되었습니다. 현재 자료로 풀이를 다시 시작해 주세요.",
                category="safety",
            )
        if job["retry_checkpoint_json"] is not None and bound_input_sha256 is None:
            raise ExchangeError(
                "invalid_retry_checkpoint",
                "이전 오답 풀이 기록과 문제 입력의 연결 정보를 확인할 수 없습니다.",
                category="safety",
            )
        if not isinstance(record["description"], str) or len(record["description"]) > 256_000:
            raise ExchangeError("challenge_description_too_large", "문제 설명이 solver 허용 범위를 넘었습니다.")
        remote = record["remote"]
        remote_mode = record["remote_mode"]
        if (
            not isinstance(remote, str)
            or len(remote) > _MAX_REMOTE_CHARS
            or _CONTROL.search(remote)
            or "\n" in remote
            or "\r" in remote
            or "`" in remote
        ):
            raise ExchangeError(
                "invalid_challenge_remote",
                "문제 원격 접속 정보가 solver 허용 범위를 벗어났습니다.",
                category="safety",
            )
        if (
            remote_mode not in {"unknown", "none", "endpoint"}
            or ((remote_mode == "endpoint") != bool(remote))
        ):
            raise ExchangeError(
                "invalid_challenge_remote",
                "문제의 원격 접속 상태와 접속 정보가 일치하지 않습니다.",
                category="safety",
            )
        result = dict(record)
        result["_related_context"] = related_context
        if source_writeup is not None:
            result["_source_writeup"] = source_writeup
        return result, [dict(item) for item in attachments]

    def _copy_attachments(
        self,
        job_id: str,
        workspace_id: str,
        challenge_id: str,
        attachments: list[dict[str, Any]],
        destination: Path,
    ) -> None:
        if not attachments:
            return
        output = destination / "attachments"
        output.mkdir(mode=0o700)
        source_root = self.data_dir / "workspaces" / workspace_id / "challenges" / challenge_id / "attachments"
        _assert_no_symlink_chain(self.data_dir, source_root)
        for index, row in enumerate(attachments, 1):
            stored = row.get("stored_name")
            if not isinstance(stored, str) or not _ID.fullmatch(stored):
                raise ExchangeError("invalid_attachment_path", "첨부파일 저장 경로를 확인할 수 없습니다.", category="safety")
            name = _stage_filename(index, row.get("original_name"))
            size = row.get("size")

            def copy_one() -> None:
                _copy_regular_file(
                    source_root / stored,
                    output / name,
                    expected_size=size,
                    cancelled=lambda: self.stop_requested.is_set() or self._is_cancelled(job_id),
                    space_reserved=True,
                    source_root=self.data_dir,
                    allow_hardlinks=True,
                )

            if size:
                self.storage_budget.commit_reserved_write("solver:" + job_id, size, copy_one)
            else:
                copy_one()

    def _auth_source(self, job: Mapping[str, Any]) -> Path:
        if job["provider"] == "codex":
            return self.accounts_dir / job["account_id"] / "codex" / "auth.json"
        if job["provider"] == "claude":
            return self.accounts_dir / job["account_id"] / "claude" / ".credentials.json"
        raise ExchangeError("invalid_provider", "공급자 선택을 확인할 수 없습니다.", category="model")

    def _copy_auth(self, job: Mapping[str, Any], destination: Path, *, expected_size: int | None = None) -> str:
        source = self._auth_source(job)
        _assert_no_symlink_chain(self.accounts_dir, source.parent)
        return _copy_regular_file(
            source,
            destination,
            expected_size=expected_size,
            maximum_size=MAX_AUTH_BYTES,
            require_private=True,
            cancelled=lambda: self.stop_requested.is_set() or self._is_cancelled(job["id"]),
            return_digest=True,
            space_reserved=expected_size is not None,
        )

    def _restage_auth(self, job: Mapping[str, Any], active: Path) -> None:
        if active.is_symlink() or active.resolve().parent != self.exchange.resolve():
            raise ExchangeError("invalid_active_path", "solver 활성 디렉터리를 확인할 수 없습니다.", category="safety")
        temporary = active / f".auth-{uuid.uuid4().hex}.tmp"
        reservation = "solver-auth:" + job["id"]
        try:
            auth_size = _regular_file_size(
                self._auth_source(job),
                maximum_size=MAX_AUTH_BYTES,
                require_private=True,
            )
            self.storage_budget.reserve(
                reservation,
                "solver",
                job["owner_user_id"],
                job["workspace_id"],
                job["challenge_id"],
                _checked_total(auth_size, _STAGE_CONTROL_RESERVE),
            )
            digest_box: dict[str, str] = {}

            def copy_auth() -> None:
                digest_box["value"] = self._copy_auth(job, temporary, expected_size=auth_size)

            self.storage_budget.commit_reserved_write(reservation, auth_size, copy_auth)
            digest = digest_box["value"]
            manifest = _read_json_file(active / "manifest.json", 512 * 1024)
            if manifest.get("job_id") != job["id"]:
                raise ExchangeError("active_job_mismatch", "활성 solver 작업이 변경되었습니다.", category="safety")
            manifest["auth_sha256"] = digest
            manifest_size = len(_json_bytes(manifest))
            self.storage_budget.commit_reserved_write(
                reservation,
                manifest_size,
                lambda: _write_json_file(active / "manifest.json", manifest),
            )
            if self._is_cancelled(job["id"]):
                raise _StageCancelled
            os.replace(temporary, active / _credential_stage_name(job["provider"]))
            _fsync(active)
        finally:
            temporary.unlink(missing_ok=True)
            try:
                self.storage_budget.release(reservation)
            except StorageBudgetError:
                pass

    def _worker_status(self, *, require_clean: bool) -> dict[str, Any]:
        value = _read_json_file(self.exchange / "worker.json", 128 * 1024)
        checks = value.get("checks")
        required = {
            "linux",
            "non_root",
            "exchange_exact",
            "data_absent",
            "database_absent",
            "root_read_only",
            "exchange_mounted_rw",
            "runtime_mounted_ro",
            "input_exact",
            "input_mounted_ro",
            "input_same_exchange",
            "scratch_exact",
            "scratch_directory",
            "scratch_not_symlink",
            "scratch_owned",
            "scratch_not_world_writable",
            "scratch_mounted_rw",
            "capabilities_dropped",
            "no_new_privileges",
            "trusted_inet_sockets",
            "security_boundary",
            "private_pid_namespace",
        }
        checked_at = value.get("checked_at")
        valid = (
            value.get("protocol") == EXCHANGE_PROTOCOL
            and value.get("ready") is True
            and value.get("sandbox_canary") is True
            and value.get("pid") == 1
            and isinstance(value.get("instance_id"), str)
            and 20 <= len(value["instance_id"]) <= 100
            and isinstance(checks, dict)
            and all(checks.get(name) is True for name in required)
            and isinstance(checked_at, (int, float))
            and not isinstance(checked_at, bool)
            and 0 <= self.clock() - checked_at <= self.worker_max_age
        )
        if require_clean:
            valid = valid and value.get("clean") is True
        if not valid:
            raise ExchangeError("solver_isolation_unavailable", "격리 worker의 최신 자체 점검을 확인할 수 없습니다.", category="safety", retryable=True)
        public_checks = {name: True for name in sorted(required)}
        for name in (
            "codex_runtime_attested",
            "claude_runtime_attested",
            "toolchain_browser_functional",
            "toolchain_trace_functional",
        ):
            if type(checks.get(name)) is bool:
                public_checks[name] = checks[name]
        return {
            "ready": True,
            "clean": value.get("clean") is True,
            "sandbox_canary": True,
            "instance_id": value["instance_id"],
            "checked_at": checked_at,
            "checks": public_checks,
        }

    def _ingest_events(self, job: Mapping[str, Any], active: Path) -> bool:
        directory = active / "events"
        if not directory.exists():
            return False
        if directory.is_symlink() or not directory.is_dir():
            self.last_block = ExchangeError("invalid_worker_events", "worker 이벤트 디렉터리를 확인할 수 없습니다.", category="safety").public(stage="worker")
            return False
        changed = False
        expected = int(job["last_event_sequence"]) + 1
        paths = sorted(directory.glob("[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].json"))
        for path in paths:
            sequence = int(path.stem)
            if sequence < expected:
                continue
            if sequence != expected:
                self.last_block = ExchangeError("worker_event_gap", "worker 이벤트 순서가 연속적이지 않습니다.", category="safety").public(stage="worker")
                return changed
            raw_event = _read_json_file(path, _MAX_EVENT_BYTES)
            event = _validate_event(
                _normalize_legacy_activity_bounds(raw_event), job["id"], sequence
            )
            if event["kind"] == "released":
                # Persist the bounded handoff before the job becomes terminal
                # and a concurrent API request can enqueue its successor.
                self._capture_private_notes(job, active, event)
            self._commit_event(job, event)
            # Secondary slots ingest concurrently, while the primary's global
            # durable scan serializes every external Telegram/CTFd callback.
            if self.deliver_global_hooks and not self.defer_global_hooks:
                self._deliver_pending_hooks(job["id"])
            expected += 1
            changed = True
        return changed

    def _commit_event(self, job: Mapping[str, Any], event: dict[str, Any]) -> None:
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM solver_jobs WHERE id=?", (job["id"],)).fetchone()
            if not current or event["sequence"] != current["last_event_sequence"] + 1:
                return
            challenge = db.execute(
                "SELECT name,status,completion_source,flag,notes FROM challenges WHERE id=? AND workspace_id=?",
                (job["challenge_id"], job["workspace_id"]),
            ).fetchone()
            is_refinement = current["job_mode"] == "writeup_refine"
            manual_override = bool(
                challenge
                and challenge["status"] == "solved"
                and challenge["completion_source"] == "manual"
            )
            stored_event = event
            refinement_error = None
            if is_refinement and event["kind"] in {"flag", "writeup"}:
                if event["kind"] == "flag":
                    refinement_error = ExchangeError(
                        "writeup_refinement_flag_event",
                        "write-up 보완 작업이 Flag 변경을 시도해 결과를 폐기했습니다.",
                        category="safety",
                    ).public(stage="writeup")
                else:
                    source = db.execute(
                        "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                        (job["challenge_id"],),
                    ).fetchone()
                    source_markdown = source["markdown"] if source else None
                    source_digest = (
                        hashlib.sha256(source_markdown.encode("utf-8")).hexdigest()
                        if isinstance(source_markdown, str)
                        else None
                    )
                    source_matches = bool(
                        challenge
                        and challenge["status"] == "solved"
                        and challenge["completion_source"] == "agent"
                        and challenge["flag"] == current["flag"] == event["flag"]
                        and source_digest is not None
                        and isinstance(current["source_writeup_sha256"], str)
                        and secrets.compare_digest(
                            source_digest, current["source_writeup_sha256"]
                        )
                    )
                    output_valid = bool(
                        challenge
                        and isinstance(current["flag"], str)
                        and valid_writeup(
                            event["writeup_markdown"], challenge["name"], current["flag"], current["writeup_locale"]
                        )
                    )
                    if not source_matches:
                        refinement_error = ExchangeError(
                            "writeup_source_changed",
                            "보완 중 기존 write-up 또는 검증된 Flag가 변경되어 결과를 폐기했습니다.",
                            category="safety",
                        ).public(stage="writeup")
                    elif not output_valid:
                        refinement_error = ExchangeError(
                            "writeup_style_invalid",
                            "보완 결과가 선택한 언어의 여섯 섹션 write-up 형식을 충족하지 않아 폐기했습니다.",
                            category="output",
                            retryable=True,
                        ).public(stage="writeup")
                if refinement_error is not None:
                    stored_event = {
                        "protocol": event["protocol"],
                        "job_id": event["job_id"],
                        "sequence": event["sequence"],
                        "kind": "error",
                        "error": refinement_error,
                        "terminal": False,
                        "created_at": event["created_at"],
                    }
            if manual_override and event["kind"] == "writeup" and refinement_error is None:
                stored_event = {
                    "protocol": event["protocol"],
                    "job_id": event["job_id"],
                    "sequence": event["sequence"],
                    "kind": "status",
                    "status": "interrupted",
                    "terminal": False,
                    "created_at": event["created_at"],
                }
            encoded = json.dumps(stored_event, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            inserted = db.execute(
                "INSERT OR IGNORE INTO solver_job_events(job_id,sequence,kind,event_json,created_at) VALUES(?,?,?,?,?)",
                (job["id"], event["sequence"], stored_event["kind"], encoded, timestamp),
            ).rowcount
            if not inserted:
                return
            updates: dict[str, Any] = {"last_event_sequence": event["sequence"], "updated_at": timestamp}
            kind = event["kind"]
            if refinement_error is not None:
                updates.update(
                    error_json=json.dumps(
                        refinement_error, ensure_ascii=False, separators=(",", ":")
                    ),
                    writeup_hooked=1,
                    cancel_requested=1,
                )
            elif kind == "progress" and event.get("code") == "reasoning_escalated":
                if (
                    current["job_mode"] != "solve"
                    or current["provider"] != "codex"
                    or not current["max_reasoning_available"]
                    or current["reasoning_effort"] != event["from_effort"]
                    or event["to_effort"] != "max"
                ):
                    raise ExchangeError(
                        "invalid_worker_event",
                        "자동 추론 승격 상태가 작업 설정과 일치하지 않습니다.",
                        category="safety",
                    )
                if current["cancel_requested"] or manual_override:
                    updates["cancel_requested"] = 1
                else:
                    updates.update(
                        reasoning_effort="max",
                        max_reasoning_available=0,
                    )
            elif kind == "status":
                state = event["status"]
                if state in {"running", "writing", "awaiting_credential"}:
                    updates["status"] = state
                elif state == "interrupted":
                    updates["status"] = "awaiting_credential"
            elif kind == "flag":
                candidate_changed = current["flag"] != event["flag"]
                already_delivered = False
                if candidate_changed:
                    already_delivered = db.execute(
                        "SELECT 1 FROM solver_flag_hook_deliveries WHERE job_id=? AND flag_sha256=?",
                        (job["id"], _flag_hook_digest(event["flag"])),
                    ).fetchone() is not None
                updates.update(
                    status="flag_found",
                    flag=event["flag"],
                    flag_hooked=(int(already_delivered) if candidate_changed else current["flag_hooked"]),
                )
                if manual_override:
                    updates.update(cancel_requested=1, flag_hooked=1, writeup_hooked=1)
                else:
                    db.execute(
                        """UPDATE challenges SET flag=?,status='flag_found',completion_source=NULL,updated_at=?
                           WHERE id=? AND workspace_id=?""",
                        (event["flag"], _utc_stamp(timestamp), job["challenge_id"], job["workspace_id"]),
                    )
            elif kind == "writeup":
                if current["flag"] != event["flag"]:
                    raise ExchangeError("worker_result_mismatch", "write-up의 flag가 먼저 저장된 결과와 일치하지 않습니다.", category="safety")
                if is_refinement:
                    # Keep the candidate private to the durable job until the
                    # worker has published a successful terminal release.  A
                    # provider/auth/quota/policy failure or cancellation can
                    # occur after this event; publishing here would replace a
                    # verified write-up for a job that ultimately failed.
                    updates.update(status="writing", writeup_markdown=event["writeup_markdown"])
                elif manual_override:
                    updates.update(status="writing", cancel_requested=1, flag_hooked=1, writeup_hooked=1)
                else:
                    updates.update(status="writing", writeup_markdown=event["writeup_markdown"])
                    writeup_timestamp = _utc_stamp(timestamp)
                    previous = db.execute(
                        "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                        (job["challenge_id"],),
                    ).fetchone()
                    merged_notes = merge_generated_writeup(
                        challenge["notes"],
                        event["writeup_markdown"],
                        previous["markdown"] if previous else None,
                    )
                    db.execute(
                        """INSERT INTO challenge_writeups(
                               challenge_id,markdown,created_at,updated_at
                           ) VALUES(?,?,?,?)
                           ON CONFLICT(challenge_id) DO UPDATE SET
                               markdown=excluded.markdown,
                               updated_at=excluded.updated_at
                           WHERE challenge_writeups.markdown<>excluded.markdown""",
                        (
                            job["challenge_id"],
                            event["writeup_markdown"],
                            writeup_timestamp,
                            writeup_timestamp,
                        ),
                    )
                    db.execute(
                        """UPDATE challenges SET status='solved',previous_status='flag_found',
                           completion_source='agent',notes=?,updated_at=?
                           WHERE id=? AND workspace_id=?""",
                        (
                            merged_notes,
                            writeup_timestamp,
                            job["challenge_id"],
                            job["workspace_id"],
                        ),
                    )
            elif kind == "error":
                updates["error_json"] = json.dumps(event["error"], ensure_ascii=False, separators=(",", ":"))
            elif kind == "guidance":
                guidance = db.execute(
                    """SELECT id,message,status FROM solver_job_guidance
                       WHERE id=? AND job_id=? AND owner_user_id=?""",
                    (
                        event["guidance_id"],
                        current["id"],
                        current["owner_user_id"],
                    ),
                ).fetchone()
                if not guidance or not secrets.compare_digest(
                    guidance["message"].encode("utf-8"),
                    event["message"].encode("utf-8"),
                ):
                    raise ExchangeError(
                        "invalid_worker_event",
                        "추가 명령 전달 이벤트가 저장 기록과 일치하지 않습니다.",
                        category="safety",
                    )
                if event["state"] == "delivered":
                    db.execute(
                        """UPDATE solver_job_guidance
                           SET status='delivered',provider_delivery=?,error_code=NULL,delivered_at=?
                           WHERE id=? AND status IN ('queued','staged')""",
                        (
                            event["provider_delivery"],
                            timestamp,
                            guidance["id"],
                        ),
                    )
                else:
                    db.execute(
                        """UPDATE solver_job_guidance
                           SET status='rejected',provider_delivery=NULL,error_code=?,delivered_at=?
                           WHERE id=? AND status IN ('queued','staged')""",
                        (event["error_code"], timestamp, guidance["id"]),
                    )
            elif kind == "released":
                status_value = event["status"]
                # The release event is the authoritative terminal outcome. A
                # worker can first publish process_cleanup_failed, restart in a
                # fresh PID namespace, and then release its already durable
                # successful result. Do not leave that transient cleanup error
                # attached to a recovered completed job.
                release_error = event.get("error")
                updates["error_json"] = (
                    json.dumps(
                        release_error,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    if release_error
                    else None
                )
                # A flag can remain valid when only the write-up turn fails.
                # Keep the challenge at flag_found while making the job itself
                # terminal so a later retry is possible.
                final_status = "failed" if status_value == "flag_found" else status_value
                refinement_release_error: dict[str, Any] | None = None
                if is_refinement and status_value == "completed":
                    # A rejected write-up/flag event already recorded the
                    # authoritative bounded error.  The worker can still emit
                    # its precomputed completed release while observing the
                    # cancel marker, but that must neither publish nor replace
                    # the original diagnostic.
                    prior_refinement_error = _optional_json(current["error_json"])
                    if prior_refinement_error:
                        final_status = "failed"
                        updates.update(
                            error_json=current["error_json"],
                            writeup_markdown=None,
                            writeup_hooked=1,
                        )
                    elif current["cancel_requested"]:
                        final_status = "cancelled"
                        updates.update(writeup_markdown=None, writeup_hooked=1)
                    else:
                        source = db.execute(
                            "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                            (job["challenge_id"],),
                        ).fetchone()
                        source_markdown = source["markdown"] if source else None
                        source_digest = (
                            hashlib.sha256(source_markdown.encode("utf-8")).hexdigest()
                            if isinstance(source_markdown, str)
                            else None
                        )
                        try:
                            current_input_sha256 = _challenge_input_sha256(
                                db,
                                current["owner_user_id"],
                                current["workspace_id"],
                                current["challenge_id"],
                            )
                        except ExchangeError:
                            current_input_sha256 = None
                        candidate = current["writeup_markdown"]
                        release_matches = bool(
                            isinstance(candidate, str)
                            and event.get("flag") == current["flag"]
                            and event.get("writeup_markdown") == candidate
                        )
                        source_matches = bool(
                            challenge
                            and challenge["status"] == "solved"
                            and challenge["completion_source"] == "agent"
                            and challenge["flag"] == current["flag"]
                            and source_digest is not None
                            and isinstance(current["source_writeup_sha256"], str)
                            and isinstance(current["challenge_input_sha256"], str)
                            and current_input_sha256 is not None
                            and secrets.compare_digest(
                                source_digest, current["source_writeup_sha256"]
                            )
                            and secrets.compare_digest(
                                current_input_sha256,
                                current["challenge_input_sha256"],
                            )
                        )
                        output_valid = bool(
                            release_matches
                            and challenge
                            and isinstance(current["flag"], str)
                            and valid_writeup(
                                candidate, challenge["name"], current["flag"], current["writeup_locale"]
                            )
                        )
                        if not source_matches:
                            refinement_release_error = ExchangeError(
                                "writeup_source_changed",
                                "보완 결과를 저장하기 전에 기존 write-up 또는 검증된 Flag가 변경되었습니다.",
                                category="safety",
                            ).public(stage="writeup")
                        elif not output_valid:
                            refinement_release_error = ExchangeError(
                                "writeup_result_mismatch",
                                "보완 작업의 최종 결과를 검증할 수 없어 기존 write-up을 보존했습니다.",
                                category="safety",
                            ).public(stage="writeup")
                        else:
                            writeup_timestamp = _utc_stamp(timestamp)
                            merged_notes = merge_generated_writeup(
                                challenge["notes"], candidate, source_markdown
                            )
                            db.execute(
                                """INSERT INTO challenge_writeups(
                                       challenge_id,markdown,created_at,updated_at
                                   ) VALUES(?,?,?,?)
                                   ON CONFLICT(challenge_id) DO UPDATE SET
                                       markdown=excluded.markdown,
                                       updated_at=excluded.updated_at
                                   WHERE challenge_writeups.markdown<>excluded.markdown""",
                                (
                                    job["challenge_id"],
                                    candidate,
                                    writeup_timestamp,
                                    writeup_timestamp,
                                ),
                            )
                            changed = db.execute(
                                """UPDATE challenges SET notes=?,updated_at=?
                                   WHERE id=? AND workspace_id=? AND status='solved'
                                     AND completion_source='agent' AND flag=?""",
                                (
                                    merged_notes,
                                    writeup_timestamp,
                                    job["challenge_id"],
                                    job["workspace_id"],
                                    current["flag"],
                                ),
                            ).rowcount
                            if changed != 1:
                                raise ExchangeError(
                                    "writeup_source_changed",
                                    "보완 결과를 저장하기 전에 문제 상태가 변경되었습니다.",
                                    category="safety",
                                )
                if refinement_release_error is not None:
                    final_status = "failed"
                    updates.update(
                        error_json=json.dumps(
                            refinement_release_error,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                        writeup_markdown=None,
                        writeup_hooked=1,
                    )
                elif is_refinement and status_value != "completed":
                    # A candidate belongs only to this attempt.  Do not expose
                    # or notify it when cancellation or a provider/auth/quota/
                    # policy failure wins the terminal outcome.
                    updates.update(writeup_markdown=None, writeup_hooked=1)
                updates.update(status=final_status, released_ingested=1)
                db.execute(
                    """UPDATE solver_job_guidance
                       SET status='rejected',provider_delivery=NULL,
                           error_code='job_finished',delivered_at=?
                       WHERE job_id=? AND status IN ('queued','staged')""",
                    (timestamp, current["id"]),
                )
                if event.get("flag") and not current["flag"]:
                    raise ExchangeError("worker_result_order", "released 전에 flag 이벤트가 저장되지 않았습니다.", category="safety")
                if is_refinement:
                    pass
                elif status_value in {"cancelled", "failed", "refused", "needs_input"} and not current["flag"]:
                    challenge_status = "stopped" if status_value in {"cancelled", "needs_input"} else "failed"
                    db.execute(
                        "UPDATE challenges SET status=?,updated_at=? WHERE id=? AND workspace_id=? AND status!='solved'",
                        (challenge_status, _utc_stamp(timestamp), job["challenge_id"], job["workspace_id"]),
                    )
                elif current["flag"] and status_value != "completed":
                    db.execute(
                        "UPDATE challenges SET status='flag_found',updated_at=? WHERE id=? AND workspace_id=? AND status!='solved'",
                        (_utc_stamp(timestamp), job["challenge_id"], job["workspace_id"]),
                    )
            assignments = ",".join(f"{key}=?" for key in updates)
            db.execute(f"UPDATE solver_jobs SET {assignments} WHERE id=?", (*updates.values(), job["id"]))

    def _deliver_pending_hook_batch(self, limit: int = 20) -> bool:
        """Retry durable notification hooks even after worker cleanup released the slot."""
        with self._connect() as db:
            rows = db.execute(
                """SELECT id FROM solver_jobs
                   WHERE (flag IS NOT NULL AND flag_hooked=0)
                      OR (writeup_markdown IS NOT NULL AND writeup_hooked=0
                          AND (job_mode<>'writeup_refine'
                               OR (status='completed' AND released_ingested=1)))
                   ORDER BY updated_at,id LIMIT ?""",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        changed = False
        for row in rows:
            changed = self._deliver_pending_hooks(row["id"]) or changed
        return changed

    def _deliver_pending_hooks(self, job_id: str) -> bool:
        # Defence in depth for direct callers: a secondary slot never invokes
        # an external hook. The primary sees committed rows on its next tick.
        if not self.deliver_global_hooks:
            return False
        changed = False
        with self._connect() as db:
            row = db.execute("SELECT * FROM solver_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return False
        if row["flag"] and not row["flag_hooked"]:
            candidate = row["flag"]
            if not self._invoke(
                self.on_flag_committed,
                row["owner_user_id"],
                row["workspace_id"],
                row["challenge_id"],
                candidate,
                row["id"],
            ):
                return False
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                timestamp = self.clock()
                inserted = db.execute(
                    "INSERT OR IGNORE INTO solver_flag_hook_deliveries(job_id,flag_sha256,delivered_at) VALUES(?,?,?)",
                    (job_id, _flag_hook_digest(candidate), timestamp),
                ).rowcount
                hooked = db.execute(
                    "UPDATE solver_jobs SET flag_hooked=1,updated_at=? WHERE id=? AND flag=?",
                    (timestamp, job_id, candidate),
                ).rowcount
            changed = bool(inserted or hooked)
        with self._connect() as db:
            row = db.execute("SELECT * FROM solver_jobs WHERE id=?", (job_id,)).fetchone()
        refinement_released = bool(
            row
            and row["job_mode"] == "writeup_refine"
            and row["status"] == "completed"
            and row["released_ingested"]
        )
        if (
            row
            and row["writeup_markdown"]
            and row["flag_hooked"]
            and not row["writeup_hooked"]
            and (row["job_mode"] != "writeup_refine" or refinement_released)
        ):
            if not self._invoke(
                self.on_writeup_committed,
                row["owner_user_id"],
                row["workspace_id"],
                row["challenge_id"],
                row["writeup_markdown"],
                row["id"],
            ):
                return changed
            with self._connect() as db:
                db.execute("UPDATE solver_jobs SET writeup_hooked=1,updated_at=? WHERE id=?", (self.clock(), job_id))
            changed = True
        return changed

    @staticmethod
    def _invoke(callback: Callable[..., Any] | None, *args: Any) -> bool:
        if callback is None:
            return True
        try:
            result = callback(*args)
            if inspect.isawaitable(result):
                # The coordinator intentionally runs in a worker thread.  API
                # integration supplies synchronous outbox-enqueue callbacks.
                raise TypeError("async hook is unsupported")
            return result is not False
        except Exception:
            return False

    def _fail_staging(self, job_id: str, status_value: str, error: dict[str, Any] | None) -> None:
        staging = self.exchange / f".staging-{job_id}"
        try:
            self.storage_budget.release(
                "solver:" + job_id,
                cleanup=lambda: _safe_remove_tree(staging, self.exchange),
            )
        except (StorageBudgetError, ExchangeError, OSError):
            # Do not erase a conservative reservation on an unproven cleanup.
            status_value = "cleanup_blocked"
            error = ExchangeError(
                "stage_cleanup_failed",
                "solver 임시 복사본 정리를 확인하지 못해 새 저장 작업을 차단했습니다.",
                category="safety",
            ).public(stage="cleanup")
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM solver_jobs WHERE id=?", (job_id,)).fetchone()
            if row:
                challenge_status = "stopped" if status_value == "cancelled" else "failed"
                db.execute(
                    """UPDATE solver_jobs SET status=?,released_ingested=1,error_json=?,released_at=?,updated_at=?
                       WHERE id=?""",
                    (
                        status_value,
                        json.dumps(error, ensure_ascii=False, separators=(",", ":")) if error else None,
                        timestamp,
                        timestamp,
                        job_id,
                    ),
                )
                db.execute(
                    "UPDATE challenges SET status=?,updated_at=? WHERE id=? AND workspace_id=? AND status!='solved'",
                    (challenge_status, _utc_stamp(timestamp), row["challenge_id"], row["workspace_id"]),
                )
            if status_value == "cleanup_blocked":
                db.execute(
                    "INSERT OR IGNORE INTO solver_slots(slot_id,job_id) VALUES(?,?)",
                    (self.slot_id, job_id),
                )
            else:
                db.execute(
                    "DELETE FROM solver_slots WHERE slot_id=? AND job_id=?",
                    (self.slot_id, job_id),
                )

    def _retire_active(self, job_id: str, active: Path) -> None:
        retired = self.exchange / f".retired-{job_id}"
        _safe_remove_tree(retired, self.exchange)
        if active.is_symlink() or active.resolve().parent != self.exchange.resolve():
            raise ExchangeError("invalid_active_path", "solver 활성 디렉터리를 안전하게 정리할 수 없습니다.", category="safety")
        os.replace(active, retired)
        _fsync(self.exchange)
        _safe_remove_tree(retired, self.exchange)

    def _clear_slot(self, job_id: str) -> None:
        timestamp = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM solver_slots WHERE slot_id=? AND job_id=?",
                (self.slot_id, job_id),
            )
            db.execute("UPDATE solver_jobs SET released_at=COALESCE(released_at,?),updated_at=? WHERE id=?", (timestamp, timestamp, job_id))

    def _remove_retired(self) -> None:
        for path in self.exchange.glob(".retired-*"):
            _safe_remove_tree(path, self.exchange)
        # An interrupted hidden stage may contain a credential copy.  It is
        # never executable and the DB slot can rebuild it from owned sources.
        # A cleanup-blocked stage is excluded because only the storage-budget
        # release path may prove that credential-bearing copy was removed.
        cleanup_blocked = self._cleanup_blocked_job_ids(own_slot=True)
        for path in self.exchange.glob(".staging-*"):
            if path.name.removeprefix(".staging-") not in cleanup_blocked:
                _safe_remove_tree(path, self.exchange)

    def _retry_orphaned_stage_cleanups(self) -> bool:
        """Terminalize staging failures once their private copy is gone.

        ``cleanup_blocked`` is open by design while untrusted copied material
        may remain. Its slot claim is retained so only the coordinator that
        owns the private staging directory may retry cleanup.
        The release is idempotent across a crash between filesystem cleanup
        and the final SQLite update.
        """

        with self._connect() as db:
            if self.slot_id == "default":
                # Generation-1 cleanup failures released the singleton claim.
                # Adopt one such row at a time after its legacy staging tree
                # has been migrated/removed, without touching claimed slots.
                db.execute(
                    """INSERT OR IGNORE INTO solver_slots(slot_id,job_id)
                       SELECT 'default',j.id FROM solver_jobs j
                        WHERE j.status='cleanup_blocked'
                          AND NOT EXISTS (SELECT 1 FROM solver_slots s WHERE s.job_id=j.id)
                        ORDER BY j.updated_at,j.id LIMIT 1"""
                )
            rows = db.execute(
                """SELECT j.id FROM solver_jobs j
                     JOIN solver_slots s ON s.job_id=j.id
                    WHERE j.status='cleanup_blocked' AND s.slot_id=?
                    ORDER BY j.updated_at,j.id LIMIT 20""",
                (self.slot_id,),
            ).fetchall()
        changed = False
        for row in rows:
            job_id = row["id"]
            staging = self.exchange / f".staging-{job_id}"
            try:
                self.storage_budget.release(
                    "solver:" + job_id,
                    cleanup=lambda path=staging: _safe_remove_tree(path, self.exchange),
                )
            except (StorageBudgetError, ExchangeError, OSError):
                continue
            timestamp = self.clock()
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                updated = db.execute(
                    """UPDATE solver_jobs SET status='failed',released_ingested=1,
                         released_at=COALESCE(released_at,?),updated_at=?
                       WHERE id=? AND status='cleanup_blocked' AND EXISTS (
                         SELECT 1 FROM solver_slots s
                          WHERE s.job_id=solver_jobs.id AND s.slot_id=?
                       )""",
                    (timestamp, timestamp, job_id, self.slot_id),
                ).rowcount
                if updated:
                    db.execute(
                        "DELETE FROM solver_slots WHERE slot_id=? AND job_id=?",
                        (self.slot_id, job_id),
                    )
            changed = bool(updated) or changed
        return changed

    def _is_cancelled(self, job_id: str) -> bool:
        with self._connect() as db:
            row = db.execute("SELECT cancel_requested FROM solver_jobs WHERE id=?", (job_id,)).fetchone()
        return self.stop_requested.is_set() or bool(row and row["cancel_requested"])


class SolverCoordinatorPool:
    """Demand-sized pool of independent PID-namespace workers over one queue.

    ``max_concurrent`` is the warm baseline, retained for compatibility with
    existing deployments. The pool grows to the number of open jobs and
    publishes the required container count for the host autoscaler. A
    positive ``hard_max_concurrent`` is an operator ceiling; zero makes
    resource estimates advisory instead of rejecting work.
    """

    def __init__(
        self,
        database_path: Path,
        data_dir: Path,
        accounts_dir: Path,
        exchange_root: Path,
        *,
        max_concurrent: int = 6,
        hard_max_concurrent: int = 0,
        host_managed_slots: bool = False,
        enforce_host_ownership: bool = True,
        on_flag_committed: Callable[[str, str, str, str, str], Any] | None = None,
        on_writeup_committed: Callable[[str, str, str, str, str], Any] | None = None,
        storage_budget: StorageBudget | None = None,
        worker_max_age: float = 5.0,
        max_open_per_user: int | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(max_concurrent, int) or isinstance(max_concurrent, bool):
            raise ValueError("CTF_SOLVER_MAX_CONCURRENT must be an integer")
        if max_concurrent < 1:
            raise ValueError("CTF_SOLVER_MAX_CONCURRENT must be positive")
        if not isinstance(hard_max_concurrent, int) or isinstance(hard_max_concurrent, bool):
            raise ValueError("CTF_SOLVER_AUTOSCALE_MAX must be an integer")
        if hard_max_concurrent < 0:
            raise ValueError("CTF_SOLVER_AUTOSCALE_MAX must be zero or positive")
        if hard_max_concurrent and hard_max_concurrent < max_concurrent:
            raise ValueError("CTF_SOLVER_AUTOSCALE_MAX must be at least the warm baseline")
        self.database_path = Path(database_path)
        self.data_dir = Path(data_dir)
        self.accounts_dir = Path(accounts_dir)
        self.host_managed_slots = bool(host_managed_slots)
        self.enforce_host_ownership = bool(enforce_host_ownership)
        self._coordinator_options = {
            "on_flag_committed": on_flag_committed,
            "on_writeup_committed": on_writeup_committed,
            "storage_budget": storage_budget,
            "worker_max_age": worker_max_age,
            "max_open_per_user": max_open_per_user,
            "clock": clock,
        }
        self.exchange_root = Path(exchange_root)
        self.exchange_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.exchange_root.is_symlink() or not self.exchange_root.is_dir():
            raise ExchangeError("invalid_exchange", "solver 교환 디렉터리를 확인할 수 없습니다.", category="safety")
        if self.host_managed_slots and os.name == "posix" and self.enforce_host_ownership:
            exchange_state = self.exchange_root.lstat()
            if not (
                exchange_state.st_uid == 0
                and exchange_state.st_gid == os.getegid()
                and stat.S_IMODE(exchange_state.st_mode) == 0o1770
            ):
                raise ExchangeError(
                    "invalid_exchange",
                    "solver 교환 루트의 호스트 보호를 확인할 수 없습니다.",
                    category="safety",
                )
        slots_root = self.exchange_root / "slots"
        if not self.host_managed_slots:
            slots_root.mkdir(mode=0o700, exist_ok=True)
        if slots_root.is_symlink() or not slots_root.is_dir() or slots_root.resolve().parent != self.exchange_root.resolve():
            raise ExchangeError("invalid_exchange", "solver 슬롯 디렉터리를 확인할 수 없습니다.", category="safety")
        if (
            self.host_managed_slots
            and os.name == "posix"
            and self.enforce_host_ownership
        ):
            slots_state = slots_root.lstat()
            scratch_root = self.data_dir / "solver-scratch"
            try:
                scratch_state = scratch_root.lstat()
            except OSError as exc:
                raise ExchangeError(
                    "invalid_solver_slot_root",
                    "호스트가 보호하는 solver 임시 경로가 필요합니다.",
                    category="safety",
                ) from exc
            if not (
                slots_state.st_uid == 0
                and slots_state.st_gid == os.getegid()
                and stat.S_IMODE(slots_state.st_mode) == 0o750
                and stat.S_ISDIR(scratch_state.st_mode)
                and not stat.S_ISLNK(scratch_state.st_mode)
                and scratch_state.st_uid == 0
                and scratch_state.st_gid == os.getegid()
                and stat.S_IMODE(scratch_state.st_mode) == 0o750
            ):
                raise ExchangeError(
                    "invalid_solver_slot_root",
                    "solver 슬롯 부모 경로의 호스트 보호를 확인할 수 없습니다.",
                    category="safety",
                )
        self._migrate_legacy_exchange(slots_root / "solver-1")
        self.minimum_concurrent = max_concurrent
        self.hard_max_concurrent = hard_max_concurrent
        self.demand_concurrent = max_concurrent
        self.requested_concurrent = max_concurrent
        protected_ceiling = self._protected_slot_ceiling(
            self.database_path, self.data_dir, slots_root
        )
        # Defer a capacity reduction while a higher slot owns a claim or
        # retains active/scratch data. All production worker containers remain
        # available, so that coordinator can finish and clean the job.
        self.host_desired_concurrent = max(max_concurrent, protected_ceiling)
        self.max_concurrent = self.host_desired_concurrent
        self.required_concurrent = max(max_concurrent, protected_ceiling)
        self.slots_root = slots_root
        self.coordinators: list[SolverExchangeCoordinator] = []
        self._slot_executors: list[concurrent.futures.ThreadPoolExecutor] = []
        self._ensure_coordinators(self.max_concurrent)
        if not self.coordinators:
            raise ExchangeError(
                "solver_slot_unavailable",
                "첫 solver 슬롯 경로가 준비되지 않았습니다.",
                category="safety",
            )
        self.max_concurrent = len(self.coordinators)
        self.primary = self.coordinators[0]
        self.exchange = self.primary.exchange
        self.last_block: dict[str, Any] | None = None
        self._hook_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="solver-hooks"
        )
        self._future_lock = threading.Lock()
        self._slot_futures: dict[int, concurrent.futures.Future[bool]] = {}
        self._slot_future_blocks: dict[int, dict[str, Any]] = {}
        self._hook_future: concurrent.futures.Future[bool] | None = None
        self._hook_block: dict[str, Any] | None = None
        self._stopping = False
        self._write_capacity_control(open_jobs=0)

    def _ensure_coordinators(self, count: int) -> None:
        """Create trusted coordinators and one execution thread per new slot."""

        while len(self.coordinators) < count:
            index = len(self.coordinators) + 1
            if self.host_managed_slots and not self._host_slot_ready(index):
                break
            coordinator = SolverExchangeCoordinator(
                self.database_path,
                self.data_dir,
                self.accounts_dir,
                self.slots_root / f"solver-{index}",
                slot_id="default" if index == 1 else f"solver-{index}",
                deliver_global_hooks=index == 1,
                defer_global_hooks=index == 1,
                accept_new_jobs=index <= self.requested_concurrent,
                host_managed_exchange=self.host_managed_slots,
                enforce_host_ownership=self.enforce_host_ownership,
                **self._coordinator_options,
            )
            self.coordinators.append(coordinator)
            self._slot_executors.append(
                concurrent.futures.ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix=f"solver-slot-{index}"
                )
            )

    def _host_slot_ready(self, index: int) -> bool:
        """Accept only slot bind roots hardened by the root host controller."""

        exchange = self.slots_root / f"solver-{index}"
        runtime = exchange / "runtime"
        scratch = self.data_dir / "solver-scratch" / f"solver-{index}"
        try:
            exchange_state = exchange.lstat()
            runtime_state = runtime.lstat()
            scratch_state = scratch.lstat()
        except OSError:
            return False
        if any(
            stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode)
            for item in (exchange_state, runtime_state, scratch_state)
        ):
            return False
        if os.name != "posix" or not self.enforce_host_ownership:
            return True
        expected_gid = os.getegid()
        return bool(
            exchange_state.st_uid == 0
            and exchange_state.st_gid == expected_gid
            and stat.S_IMODE(exchange_state.st_mode) == 0o1770
            and runtime_state.st_uid == 0
            and runtime_state.st_gid == expected_gid
            and stat.S_IMODE(runtime_state.st_mode) == 0o770
            and scratch_state.st_uid == os.geteuid()
            and scratch_state.st_gid == expected_gid
            and stat.S_IMODE(scratch_state.st_mode) == 0o700
        )

    def _trim_coordinators(self, count: int) -> None:
        """Release idle high-slot coordinators and their persistent threads."""

        while len(self.coordinators) > count:
            index = len(self.coordinators) - 1
            if index in self._slot_futures:
                raise RuntimeError("cannot trim a solver slot with an in-flight tick")
            self.coordinators.pop().request_stop()
            executor = self._slot_executors.pop()
            executor.shutdown(wait=True, cancel_futures=False)
            self._slot_future_blocks.pop(index, None)

    def _open_job_count(self) -> int:
        with sqlite3.connect(self.database_path, timeout=15) as db:
            db.execute("PRAGMA busy_timeout=15000")
            row = db.execute(
                "SELECT COUNT(*) FROM solver_jobs WHERE status IN (%s)"
                % ",".join("?" for _ in _OPEN_STATUSES),
                _OPEN_STATUSES,
            ).fetchone()
        return int(row[0]) if row else 0

    def _write_capacity_control(self, *, open_jobs: int) -> None:
        """Publish a non-secret, atomic target for the Docker host controller."""

        payload = {
            "protocol": 1,
            "desired": self.host_desired_concurrent,
            "target": self.requested_concurrent,
            "demand": self.demand_concurrent,
            "baseline": self.minimum_concurrent,
            "hard_max": self.hard_max_concurrent,
            "open_jobs": open_jobs,
            "required": self.required_concurrent,
            "updated_at": time.time(),
        }
        target = self.exchange_root / "pool-control.json"
        temporary = self.exchange_root / f".pool-control-{uuid.uuid4().hex}"
        temporary.write_bytes(_json_bytes(payload))
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        _fsync(self.exchange_root)

    def set_hard_max(self, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("solver autoscale maximum must be zero or positive")
        if value and value < self.minimum_concurrent:
            raise ValueError("solver autoscale maximum must be at least the warm baseline")
        with self._future_lock:
            self.hard_max_concurrent = value

    def reconcile_capacity(self) -> dict[str, int]:
        """Grow for demand and drain surplus slots without orphaning a job."""

        with self._future_lock:
            return self._reconcile_capacity_locked()

    def _reconcile_capacity_locked(self) -> dict[str, int]:
        open_jobs = self._open_job_count()
        demand = max(self.minimum_concurrent, open_jobs)
        if self.hard_max_concurrent:
            demand = min(demand, self.hard_max_concurrent)
        # Grow at a bounded rate so a large imported queue cannot create
        # hundreds of coordinators and threads in one request. Repeated 350ms
        # ticks converge without imposing a capacity ceiling.
        target = (
            min(demand, self.max_concurrent + 8)
            if demand > self.max_concurrent
            else demand
        )

        # Stop high slots from claiming before examining whether they can be
        # removed. A running future remains configured through cleanup.
        for index, item in enumerate(self.coordinators, 1):
            item.accept_new_jobs = index <= target
        protected = self._protected_slot_ceiling(
            self.database_path, self.data_dir, self.slots_root
        )
        # A done future is harvested later in this tick. Retain its slot for
        # one extra DB/filesystem scan so its final claim/cleanup commit cannot
        # race a host-side container removal.
        in_flight = max((index + 1 for index in self._slot_futures), default=1)
        host_desired = max(target, protected, in_flight)
        self.demand_concurrent = demand
        self.requested_concurrent = target
        self.required_concurrent = max(self.minimum_concurrent, protected)
        if host_desired < len(self.coordinators):
            self._trim_coordinators(host_desired)
        self._ensure_coordinators(host_desired)
        configured = len(self.coordinators)
        for index, item in enumerate(self.coordinators, 1):
            item.accept_new_jobs = index <= target
        changed = (
            configured != self.max_concurrent
            or host_desired != self.host_desired_concurrent
        )
        self.max_concurrent = configured
        self.host_desired_concurrent = host_desired
        control = self.exchange_root / "pool-control.json"
        try:
            heartbeat_due = time.time() - control.stat().st_mtime >= 10.0
        except OSError:
            heartbeat_due = True
        if changed or heartbeat_due:
            self._write_capacity_control(open_jobs=open_jobs)
        else:
            try:
                previous = json.loads(control.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                previous = {}
            if (
                previous.get("open_jobs") != open_jobs
                or previous.get("target") != target
                or previous.get("demand") != demand
                or previous.get("required") != self.required_concurrent
            ):
                self._write_capacity_control(open_jobs=open_jobs)
        return {
            "baseline": self.minimum_concurrent,
            "hard_max": self.hard_max_concurrent,
            "open_jobs": open_jobs,
            "demand": demand,
            "requested": target,
            "configured": configured,
        }

    @staticmethod
    def _protected_slot_ceiling(
        database_path: Path, data_dir: Path, slots_root: Path
    ) -> int:
        """Return the highest slot that must survive a capacity reduction."""

        protected = 1
        if database_path.is_file():
            with sqlite3.connect(database_path, timeout=15) as db:
                db.execute("PRAGMA busy_timeout=15000")
                exists = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_slots'"
                ).fetchone()
                if exists:
                    for (slot_id,) in db.execute("SELECT slot_id FROM solver_slots"):
                        index = _solver_slot_index(slot_id)
                        if index is None:
                            raise ExchangeError(
                                "invalid_solver_slot",
                                "solver 슬롯 식별자를 확인할 수 없습니다.",
                                category="safety",
                            )
                        protected = max(protected, index)
        scratch_root = data_dir / "solver-scratch"
        indices: set[int] = set()
        for root in (slots_root, scratch_root):
            if not root.exists():
                continue
            if root.is_symlink() or not root.is_dir():
                raise ExchangeError(
                    "invalid_solver_slot_root",
                    "solver 슬롯 경로를 확인할 수 없습니다.",
                    category="safety",
                )
            for entry in root.iterdir():
                matched = re.fullmatch(r"solver-([1-9][0-9]*)", entry.name)
                if matched:
                    indices.add(int(matched.group(1)))
        for index in sorted(item for item in indices if item >= 2):
            exchange = slots_root / f"solver-{index}"
            scratch = scratch_root / f"solver-{index}"
            if exchange.exists():
                if exchange.is_symlink() or not exchange.is_dir():
                    raise ExchangeError(
                        "invalid_exchange",
                        "solver 슬롯 경로를 확인할 수 없습니다.",
                        category="safety",
                    )
                try:
                    exchange_entries = list(exchange.iterdir())
                except OSError as exc:
                    raise ExchangeError(
                        "invalid_exchange",
                        "solver 슬롯 경로를 확인할 수 없습니다.",
                        category="safety",
                    ) from exc
                protected_entry = False
                for entry in exchange_entries:
                    if entry.name in {"worker.json", "worker.lock"}:
                        continue
                    if entry.name == "runtime":
                        if entry.is_symlink() or not entry.is_dir():
                            raise ExchangeError(
                                "invalid_runtime_path",
                                "solver runtime 경로를 확인할 수 없습니다.",
                                category="safety",
                            )
                        try:
                            runtime_nonempty = next(entry.iterdir(), None) is not None
                        except OSError as exc:
                            raise ExchangeError(
                                "invalid_runtime_path",
                                "solver runtime 경로를 확인할 수 없습니다.",
                                category="safety",
                            ) from exc
                        if runtime_nonempty:
                            raise ExchangeError(
                                "invalid_runtime_path",
                                "보조 solver runtime 경로가 비어 있지 않습니다.",
                                category="safety",
                            )
                        continue
                    protected_entry = True
                if protected_entry:
                    protected = max(protected, index)
            if scratch.exists():
                if scratch.is_symlink() or not scratch.is_dir():
                    raise ExchangeError(
                        "invalid_solver_scratch",
                        "solver 임시 작업 경로를 확인할 수 없습니다.",
                        category="safety",
                    )
                try:
                    scratch_nonempty = next(scratch.iterdir(), None) is not None
                except OSError as exc:
                    raise ExchangeError(
                        "invalid_solver_scratch",
                        "solver 임시 작업 경로를 확인할 수 없습니다.",
                        category="safety",
                    ) from exc
                if scratch_nonempty:
                    protected = max(protected, index)
        return protected

    def _migrate_legacy_exchange(self, first_slot: Path) -> None:
        """Move generation-1 active/runtime trees into slot one once."""

        first_slot.mkdir(parents=True, exist_ok=True, mode=0o700)
        if first_slot.is_symlink() or first_slot.resolve().parent.name != "slots":
            raise ExchangeError("invalid_exchange", "solver 첫 슬롯을 확인할 수 없습니다.", category="safety")
        lock_path = self.exchange_root / "pool.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            legacy_active = self.exchange_root / "active"
            target_active = first_slot / "active"
            if legacy_active.exists():
                if target_active.exists():
                    raise ExchangeError(
                        "legacy_exchange_conflict",
                        "기존 작업과 첫 solver 슬롯이 동시에 남아 있어 복구할 수 없습니다.",
                        category="safety",
                    )
                if legacy_active.is_symlink() or legacy_active.resolve().parent != self.exchange_root.resolve():
                    raise ExchangeError("invalid_active_path", "기존 solver 작업 경로를 확인할 수 없습니다.", category="safety")
                os.replace(legacy_active, target_active)
            legacy_runtime = self.exchange_root / "runtime"
            target_runtime = first_slot / "runtime"
            target_runtime.mkdir(mode=0o755, exist_ok=True)
            if legacy_runtime.is_dir() and not legacy_runtime.is_symlink():
                for source in legacy_runtime.iterdir():
                    if source.name.startswith(".staging-"):
                        _safe_remove_tree(source, legacy_runtime)
                    else:
                        destination = target_runtime / source.name
                        if destination.exists():
                            self._verify_legacy_runtime_pair(source, destination)
                            continue
                        try:
                            os.replace(source, destination)
                        except PermissionError:
                            # Some bind-mount/filesystem combinations permit
                            # reading the immutable publication but reject a
                            # directory rename. Copy through a private sibling,
                            # verify the exact runtime digest, then publish it
                            # atomically. The legacy source remains available
                            # until a host-side release cleanup removes it.
                            self._copy_legacy_runtime(source, destination)
            for path in self.exchange_root.glob(".staging-*"):
                _safe_remove_tree(path, self.exchange_root)
            _fsync(first_slot)
            _fsync(self.exchange_root)
        finally:
            try:
                if os.name == "posix":
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @staticmethod
    def _verify_legacy_runtime_pair(source: Path, destination: Path) -> None:
        if not source.name.startswith("codex-"):
            raise ExchangeError(
                "invalid_runtime_path",
                "기존 Codex runtime 경로를 확인할 수 없습니다.",
                category="safety",
            )
        version = source.name.removeprefix("codex-")
        source_files, source_total = _runtime_files(source, version)
        destination_files, destination_total = _runtime_files(destination, version)
        if (
            source_total != destination_total
            or len(source_files) != len(destination_files)
            or _runtime_digest_for_files(source, source_files)
            != _runtime_digest_for_files(destination, destination_files)
        ):
            raise ExchangeError(
                "legacy_exchange_conflict",
                "기존 Codex runtime과 첫 solver 슬롯의 runtime이 일치하지 않습니다.",
                category="safety",
            )

    @classmethod
    def _copy_legacy_runtime(cls, source: Path, destination: Path) -> None:
        if not source.name.startswith("codex-"):
            raise ExchangeError(
                "invalid_runtime_path",
                "기존 Codex runtime 경로를 확인할 수 없습니다.",
                category="safety",
            )
        version = source.name.removeprefix("codex-")
        files, total = _runtime_files(source, version)
        if shutil.disk_usage(destination.parent).free - total < _MIN_FREE_BYTES_AFTER_STAGE:
            raise ExchangeError(
                "insufficient_solver_storage",
                "solver runtime을 이전할 저장 공간이 부족합니다.",
                category="storage",
                retryable=True,
            )
        staging = destination.parent / f".legacy-migration-{uuid.uuid4().hex}"
        try:
            staging.mkdir(mode=0o700)
            for relative, size, executable in files:
                target = staging / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _copy_regular_file(
                    source / relative,
                    target,
                    expected_size=size,
                    cancelled=lambda: False,
                    space_reserved=True,
                )
                target.chmod(0o555 if executable else 0o444)
            for directory in sorted(
                (path for path in staging.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                directory.chmod(0o555)
            staging.chmod(0o555)
            if runtime_tree_digest(staging) != _runtime_digest_for_files(source, files):
                raise ExchangeError(
                    "runtime_integrity_failed",
                    "이전한 Codex runtime이 원본과 일치하지 않습니다.",
                    category="safety",
                )
            os.replace(staging, destination)
            _fsync(destination.parent)
        except BaseException:
            if staging.exists():
                _make_tree_owner_writable(staging, destination.parent)
                _safe_remove_tree(staging, destination.parent)
            raise

    def __getattr__(self, name: str) -> Any:
        return getattr(self.primary, name)

    def tick(self) -> bool:
        changed = False
        with self._future_lock:
            if not self._stopping:
                before = (self.max_concurrent, self.requested_concurrent)
                self._reconcile_capacity_locked()
                changed = before != (self.max_concurrent, self.requested_concurrent)
            if not self._stopping:
                for index, item in enumerate(self.coordinators[: self.max_concurrent]):
                    if index not in self._slot_futures:
                        try:
                            self._slot_futures[index] = self._slot_executors[index].submit(
                                item.tick
                            )
                        except RuntimeError:
                            # A concurrent shutdown must fail closed without
                            # terminating the long-running service loop.
                            self._slot_future_blocks[index] = ExchangeError(
                                "coordinator_thread_unavailable",
                                "solver 작업 스레드를 준비하지 못했습니다.",
                                retryable=True,
                            ).public(stage="coordinator")
                if self._hook_future is None:
                    self._hook_future = self._hook_executor.submit(
                        self.primary._deliver_pending_hook_batch
                    )
            for index, future in list(self._slot_futures.items()):
                if not future.done():
                    continue
                del self._slot_futures[index]
                try:
                    changed = future.result() or changed
                    self._slot_future_blocks.pop(index, None)
                except ExchangeError as exc:
                    self._slot_future_blocks[index] = exc.public(stage="coordinator")
                except sqlite3.Error:
                    self._slot_future_blocks[index] = ExchangeError(
                        "coordinator_storage_failed",
                        "solver 작업 상태를 처리하지 못했습니다.",
                        retryable=True,
                    ).public(stage="coordinator")
                except Exception:
                    self._slot_future_blocks[index] = ExchangeError(
                        "coordinator_failed",
                        "solver 작업 처리를 계속할 수 없습니다.",
                        retryable=True,
                    ).public(stage="coordinator")
            if self._hook_future is not None and self._hook_future.done():
                future = self._hook_future
                self._hook_future = None
                try:
                    changed = future.result() or changed
                    self._hook_block = None
                except Exception:
                    # Pending DB markers remain retryable by the next scan.
                    self._hook_block = ExchangeError(
                        "solver_hook_dispatch_failed",
                        "solver 알림 처리를 다시 시도합니다.",
                        retryable=True,
                    ).public(stage="coordinator")
        blocks = [
            item.last_block
            for item in self.coordinators[: self.max_concurrent]
            if item.last_block
        ]
        blocks.extend(
            value
            for index, value in self._slot_future_blocks.items()
            if index < self.max_concurrent
        )
        if self._hook_block:
            blocks.append(self._hook_block)
        self.last_block = blocks[0] if blocks else None
        return changed

    def publish_runtime(self, version: str, source_root: Path | None = None,
                        provider: str = "codex") -> dict[str, Any]:
        # Every worker mounts slot one's immutable runtime tree read-only.
        return self.primary.publish_runtime(version, source_root, provider)

    def request_stop(self) -> None:
        self._stopping = True
        for item in self.coordinators:
            item.request_stop()

    def reset_stop(self) -> None:
        self._stopping = False
        for item in self.coordinators:
            item.reset_stop()

    def wait_quiescent(self, timeout: float = 25.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._future_lock:
            pending = list(self._slot_futures.values())
            if self._hook_future is not None:
                pending.append(self._hook_future)
        if pending:
            _, unfinished = concurrent.futures.wait(
                pending, timeout=max(0.0, deadline - time.monotonic())
            )
            if unfinished:
                return False
        outcomes = [
            item.wait_quiescent(max(0.0, deadline - time.monotonic()))
            for item in self.coordinators
        ]
        return all(outcomes)

    def cancel_owner(self, owner_user_id: str) -> bool:
        outcomes = [item.cancel_owner(owner_user_id) for item in self.coordinators]
        return all(outcomes)

    def health(self) -> dict[str, Any]:
        snapshots = [item.health() for item in self.coordinators[: self.max_concurrent]]
        try:
            protected = self._protected_slot_ceiling(
                self.database_path, self.data_dir, self.slots_root
            )
        except ExchangeError as exc:
            protected = self.max_concurrent
            protected_error = exc.public(stage="coordinator")
        else:
            protected_error = None
        required = max(self.minimum_concurrent, protected)
        required_snapshots = snapshots[: min(self.max_concurrent, required)]
        blocks = [item.get("blocked") for item in required_snapshots if item.get("blocked")]
        blocks.extend(
            value
            for index, value in self._slot_future_blocks.items()
            if index < required
        )
        if self._hook_block:
            blocks.append(self._hook_block)
        if protected_error:
            blocks.append(protected_error)
        pool_block = blocks[0] if blocks else None
        ready_workers = sum(bool(item.get("ready")) for item in snapshots)
        required_ready = sum(bool(item.get("ready")) for item in required_snapshots)
        active_workers = sum(bool(item.get("active")) for item in snapshots)
        workers = []
        for index, item in enumerate(snapshots, 1):
            worker = dict(item.get("worker") or {})
            worker["slot"] = index
            worker["draining"] = index > self.requested_concurrent
            workers.append(worker)
        ready_states = [worker for worker in workers if worker.get("ready") is True]
        all_ready = (
            self.max_concurrent >= required
            and required_ready == required
            and pool_block is None
        )
        aggregate_clean = all_ready and all(
            worker.get("clean") is True for worker in workers[:required]
        )
        cleanup_blocked = any(
            worker.get("cleanup_blocked") is True for worker in workers
        )
        base = dict(snapshots[0])
        base.update(
            ready=all_ready,
            active=active_workers,
            worker={
                "ready": all_ready,
                "sandbox_canary": all_ready,
                "clean": aggregate_clean,
                "cleanup_blocked": cleanup_blocked,
                "configured": self.max_concurrent,
                "requested": self.requested_concurrent,
                "draining": self.max_concurrent - self.requested_concurrent,
                "warming": max(0, self.demand_concurrent - self.max_concurrent),
                "demand": self.demand_concurrent,
                "required": required,
                "ready_count": ready_workers,
                "active_count": active_workers,
                "workers": workers,
            },
            capacity={
                "configured": self.max_concurrent,
                "requested": self.requested_concurrent,
                "draining": self.max_concurrent - self.requested_concurrent,
                "warming": max(0, self.demand_concurrent - self.max_concurrent),
                "demand": self.demand_concurrent,
                "required": required,
                "ready": ready_workers,
                "active": active_workers,
            },
            blocked=pool_block,
        )
        return base


def _challenge_input_sha256(
    db: sqlite3.Connection,
    owner_user_id: str,
    workspace_id: str,
    challenge_id: str,
) -> str:
    """Bind retry advice to the exact material inputs of one owned challenge."""

    return hashlib.sha256(
        _json_bytes(
            _challenge_input_payload(
                db, owner_user_id, workspace_id, challenge_id, include_remote=True
            )
        )
    ).hexdigest()


def _challenge_base_sha256(
    db: sqlite3.Connection,
    owner_user_id: str,
    workspace_id: str,
    challenge_id: str,
) -> str:
    """Bind a remote-request continuation to every input except remote state."""

    return hashlib.sha256(
        _json_bytes(
            _challenge_input_payload(
                db, owner_user_id, workspace_id, challenge_id, include_remote=False
            )
        )
    ).hexdigest()


def _challenge_input_payload(
    db: sqlite3.Connection,
    owner_user_id: str,
    workspace_id: str,
    challenge_id: str,
    *,
    include_remote: bool,
) -> dict[str, Any]:

    challenge = db.execute(
        """SELECT c.name,c.category,c.description,c.remote,c.remote_mode,w.flag_format
           FROM challenges c JOIN workspaces w ON w.id=c.workspace_id
           WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=?""",
        (challenge_id, workspace_id, owner_user_id),
    ).fetchone()
    if not challenge:
        raise ExchangeError("challenge_not_found", "문제를 찾을 수 없습니다.")
    attachments = [
        dict(row)
        for row in db.execute(
            """SELECT id,original_name,stored_name,size FROM attachments
               WHERE workspace_id=? AND challenge_id=? ORDER BY id""",
            (workspace_id, challenge_id),
        )
    ]
    payload: dict[str, Any] = {
        "name": challenge["name"],
        "category": challenge["category"],
        "description": challenge["description"],
        "flag_format": challenge["flag_format"],
        "attachments": attachments,
    }
    if include_remote:
        payload.update(remote=challenge["remote"], remote_mode=challenge["remote_mode"])
    return payload


def _solver_slot_index(slot_id: object) -> int | None:
    if slot_id == "default":
        return 1
    if isinstance(slot_id, str):
        matched = re.fullmatch(r"solver-([2-9]|[1-9][0-9]+)", slot_id)
        if matched:
            return int(matched.group(1))
    return None


def _flag_hook_digest(flag: str) -> str:
    """Identify one candidate without adding another plaintext flag copy."""

    return hashlib.sha256(flag.encode("utf-8")).hexdigest()


def _public_guidance(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "job_id": row["job_id"],
        "message": row["message"],
        "status": row["status"],
        "provider_delivery": row["provider_delivery"],
        "error_code": row["error_code"],
        "created_at": row["created_at"],
        "staged_at": row["staged_at"],
        "delivered_at": row["delivered_at"],
    }


def _public_job(
    row: Mapping[str, Any],
    events: list[dict[str, Any]],
    position: int | None,
    *,
    guidance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    error = _optional_json(row["error_json"])
    refinement_published = bool(
        row["job_mode"] != "writeup_refine"
        or (row["status"] == "completed" and row["released_ingested"])
    )
    if not refinement_published:
        events = [
            {key: value for key, value in event.items() if key != "writeup_markdown"}
            for event in events
        ]
    try:
        if row["job_mode"] == "writeup_refine":
            checkpoint = None
        else:
            current = row["current_retry_checkpoint_json"]
            checkpoint = decode_checkpoint(current if current is not None else row["retry_checkpoint_json"])
    except (KeyError, TypeError, ValueError):
        checkpoint = None
    result = {
        "id": row["id"],
        "job_mode": row["job_mode"],
        "writeup_locale": row["writeup_locale"],
        "workspace_id": row["workspace_id"],
        "challenge_id": row["challenge_id"],
        "account_label": row["account_label"],
        "status": row["status"],
        "cancel_requested": bool(row["cancel_requested"]),
        "configuration": {
            "provider": row["provider"],
            "model": row["model"],
            "reasoning_effort": row["reasoning_effort"],
            "service_tier": row["service_tier"],
        },
        "max_reasoning_available": bool(row["max_reasoning_available"]),
        "runtime_version": row["claude_version"] if row["provider"] == "claude" else row["codex_version"],
        "runtime_sha256": row["claude_runtime_sha256"] if row["provider"] == "claude" else row["codex_runtime_sha256"],
        "remote_mode": row["remote_mode"],
        "network_policy": (
            "offline" if row["job_mode"] == "writeup_refine" else "general_internet"
        ),
        "has_custom_instruction": bool(row["writeup_instruction"]),
        "guidance_allowed": bool(
            row["job_mode"] == "solve" and row["status"] in _GUIDANCE_OPEN_STATUSES
        ),
        "source_solver_job_id": (
            row["source_solver_job_id"] if row["job_mode"] == "writeup_refine" else None
        ),
        "supported_challenge_mode": "static_attachments_and_open_internet",
        "flag": row["flag"],
        "flag_rejected": row["flag_rejected_at"] is not None,
        "retry_checkpoint": (
            {
                "revision": checkpoint.revision,
                "rejected_count": len(checkpoint.rejected_flags),
                "reason": checkpoint.reason,
            }
            if checkpoint else None
        ),
        "writeup_markdown": (
            row["writeup_markdown"] if refinement_published else None
        ),
        "error": error or None,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "released_at": row["released_at"],
        "last_event_sequence": row["last_event_sequence"],
        "events": events,
        "guidance": guidance or [],
    }
    if position is not None:
        result["queue_position"] = position
    return result


def _normalize_legacy_activity_bounds(value: dict[str, Any]) -> dict[str, Any]:
    """Accept only the three-byte overrun emitted by the former UTF-8 bounder."""

    if value.get("kind") != "activity":
        return value
    marker = "…"
    marker_size = len(marker.encode("utf-8"))
    normalized = value
    for field, maximum in (("command", 2048), ("output", 8 * 1024), ("message", 4 * 1024)):
        text = value.get(field)
        if not isinstance(text, str) or not text.endswith(marker):
            continue
        encoded = text.encode("utf-8")
        if not maximum < len(encoded) <= maximum + marker_size:
            continue
        if normalized is value:
            normalized = dict(value)
        prefix = encoded[: maximum - marker_size].decode("utf-8", errors="ignore").rstrip()
        normalized[field] = prefix + marker
    return normalized


def _validate_event(value: dict[str, Any], job_id: str, sequence: int) -> dict[str, Any]:
    common = {"protocol", "job_id", "sequence", "kind", "created_at"}
    allowed = {
        "status": common | {"status", "flag", "terminal"},
        "progress": common | {"code", "reason", "from_effort", "to_effort"},
        "activity": common | {
            "phase", "tool", "summary", "command", "output", "message",
            "exit_code", "duration_ms"
        },
        "guidance": common | {
            "guidance_id", "state", "message", "provider_delivery", "error_code"
        },
        "flag": common | {"flag"},
        "writeup": common | {"flag", "writeup_markdown", "terminal"},
        "error": common | {"error", "flag", "terminal"},
        "cancelled": common | {"flag", "terminal"},
        "released": common | {"status", "flag", "writeup_markdown", "error", "terminal"},
    }
    kind = value.get("kind")
    created = value.get("created_at")
    if (
        kind not in allowed
        or set(value) - allowed[kind]
        or value.get("protocol") != EXCHANGE_PROTOCOL
        or value.get("job_id") != job_id
        or value.get("sequence") != sequence
        or not isinstance(created, (int, float))
        or isinstance(created, bool)
    ):
        raise ExchangeError("invalid_worker_event", "worker 이벤트 형식을 확인할 수 없습니다.", category="safety")
    if kind == "status" and value.get("status") not in {"running", "writing", "awaiting_credential", "interrupted"}:
        raise ExchangeError("invalid_worker_event", "worker 상태 이벤트를 확인할 수 없습니다.", category="safety")
    if kind == "progress" and value.get("code") not in {
        "executing", "analyzing", "waiting_for_model", "inspecting_files",
        "validating_flag", "drafting_writeup", "provider_auth_retry", "provider_access_check",
        "provider_quota_retry", "provider_rate_limit_retry",
        "provider_overloaded_retry", "provider_connection_retry",
        "provider_retrying", "reasoning_escalated", "researching",
    }:
        raise ExchangeError("invalid_worker_event", "worker 진행 이벤트를 확인할 수 없습니다.", category="safety")
    if kind == "progress":
        escalation_fields = {"reason", "from_effort", "to_effort"}
        present = escalation_fields & set(value)
        if value.get("code") == "reasoning_escalated":
            if (
                present != escalation_fields
                or value.get("reason") != "agent_max_required_with_work_evidence"
                or not isinstance(value.get("from_effort"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", value["from_effort"])
                or value["from_effort"] == "max"
                or value.get("to_effort") != "max"
            ):
                raise ExchangeError("invalid_worker_event", "자동 추론 승격 이벤트를 확인할 수 없습니다.", category="safety")
        elif present:
            raise ExchangeError("invalid_worker_event", "worker 진행 이벤트 형식을 확인할 수 없습니다.", category="safety")
    if kind == "activity":
        if (
            value.get("phase") not in {"started", "completed"}
            or value.get("tool") not in {"shell", "web_search", "file", "analysis", "tool"}
            or not isinstance(value.get("summary"), str)
            or not value["summary"]
            or len(value["summary"].encode("utf-8")) > 400
            or _CONTROL.search(value["summary"])
        ):
            raise ExchangeError("invalid_worker_event", "worker 활동 이벤트를 확인할 수 없습니다.", category="safety")
        command = value.get("command")
        if command is not None and (
            not isinstance(command, str)
            or not command
            or len(command.encode("utf-8")) > 2048
            or _CONTROL.search(command)
        ):
            raise ExchangeError("invalid_worker_event", "worker 명령 이벤트를 확인할 수 없습니다.", category="safety")
        for field, maximum in (("output", 8 * 1024), ("message", 4 * 1024)):
            text = value.get(field)
            if text is not None and (
                not isinstance(text, str)
                or not text
                or len(text.encode("utf-8")) > maximum
                or _WRITEUP_INSTRUCTION_CONTROL.search(text)
            ):
                raise ExchangeError(
                    "invalid_worker_event",
                    "worker 활동 내용을 확인할 수 없습니다.",
                    category="safety",
                )
        exit_code = value.get("exit_code")
        if exit_code is not None and (
            type(exit_code) is not int or not -(2**31) <= exit_code <= 2**31 - 1
        ):
            raise ExchangeError("invalid_worker_event", "worker 활동 결과를 확인할 수 없습니다.", category="safety")
        duration_ms = value.get("duration_ms")
        if duration_ms is not None and (
            type(duration_ms) is not int or not 0 <= duration_ms <= 2**63 - 1
        ):
            raise ExchangeError("invalid_worker_event", "worker 활동 결과를 확인할 수 없습니다.", category="safety")
    if kind == "guidance":
        state = value.get("state")
        delivery = value.get("provider_delivery")
        error_code = value.get("error_code")
        try:
            normalized_message = normalize_solver_guidance(value.get("message"))
        except ExchangeError:
            raise ExchangeError(
                "invalid_worker_event",
                "추가 명령 전달 이벤트를 확인할 수 없습니다.",
                category="safety",
            ) from None
        if (
            set(value) != allowed["guidance"]
            or
            not isinstance(value.get("guidance_id"), str)
            or not _ID.fullmatch(value["guidance_id"])
            or normalized_message != value.get("message")
            or state not in {"delivered", "rejected"}
            or (
                state == "delivered"
                and (delivery not in {"same_turn", "next_turn"} or error_code is not None)
            )
            or (
                state == "rejected"
                and (
                    delivery is not None
                    or not isinstance(error_code, str)
                    or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_code)
                )
            )
        ):
            raise ExchangeError("invalid_worker_event", "추가 명령 전달 이벤트를 확인할 수 없습니다.", category="safety")
    if kind in {"flag", "writeup"} or value.get("flag") is not None:
        flag = value.get("flag")
        if not isinstance(flag, str) or not flag or len(flag) > 4000 or "\n" in flag or "\r" in flag or _CONTROL.search(flag):
            raise ExchangeError("invalid_worker_result", "worker flag 결과를 확인할 수 없습니다.", category="safety")
    if value.get("writeup_markdown") is not None:
        markdown = value["writeup_markdown"]
        if not isinstance(markdown, str) or not markdown or len(markdown) > MAX_OUTPUT_TEXT or _CONTROL.search(markdown):
            raise ExchangeError("invalid_worker_result", "worker write-up 결과를 확인할 수 없습니다.", category="safety")
    if value.get("error") is not None:
        error = value["error"]
        required = {"code", "message", "stage", "category", "retryable"}
        if not isinstance(error, dict) or not required.issubset(error) or set(error) - (required | {"provider_code", "requirements", "quota"}):
            raise ExchangeError("invalid_worker_error", "worker 오류 결과를 확인할 수 없습니다.", category="safety")
        for key in ("code", "message", "stage", "category"):
            if not isinstance(error.get(key), str) or not error[key] or len(error[key]) > 1000 or _CONTROL.search(error[key]):
                raise ExchangeError("invalid_worker_error", "worker 오류 결과를 확인할 수 없습니다.", category="safety")
        if error.get("provider_code") is not None and not re.fullmatch(r"(?:TAC|CVP)(?:[-_][A-Z0-9]{1,12})?", error["provider_code"], re.I):
            raise ExchangeError("invalid_worker_error", "worker 공급자 코드를 확인할 수 없습니다.", category="safety")
        if error.get("quota") is not None and normalize_rate_limit_context(error["quota"]) != error["quota"]:
            raise ExchangeError("invalid_worker_error", "worker 사용량 정보를 확인할 수 없습니다.", category="safety")
        if type(error.get("retryable")) is not bool:
            raise ExchangeError("invalid_worker_error", "worker 재시도 상태를 확인할 수 없습니다.", category="safety")
    if kind == "released" and (value.get("terminal") is not True or value.get("status") not in (_TERMINAL_STATUSES | {"flag_found"})):
        raise ExchangeError("invalid_worker_release", "worker 정리 완료 이벤트를 확인할 수 없습니다.", category="safety")
    return value


def _read_json_file(path: Path, maximum: int) -> dict[str, Any]:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > maximum:
            raise ExchangeError("invalid_control_file", "solver 제어 파일 형식을 확인할 수 없습니다.", category="safety")
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(descriptor, min(65_536, maximum + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        if len(chunks) > maximum:
            raise ValueError
        return _strict_object(bytes(chunks))
    except FileNotFoundError as exc:
        raise ExchangeError("worker_unavailable", "격리 worker 상태를 아직 확인할 수 없습니다.", retryable=True) from exc
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise ExchangeError("invalid_control_file", "solver 제어 파일 형식을 확인할 수 없습니다.", category="safety") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _strict_object(raw: bytes) -> dict[str, Any]:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if not isinstance(value, dict):
        raise ValueError
    return value


def _write_json_file(path: Path, payload: Mapping[str, Any]) -> None:
    encoded = _json_bytes(payload)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync(path.parent)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _checked_total(*values: int) -> int:
    if any(type(value) is not int or value < 0 for value in values):
        raise ExchangeError("invalid_storage_size", "solver 저장 크기를 확인할 수 없습니다.", category="storage")
    total = sum(values)
    if total > MAX_SQLITE_INTEGER:
        raise ExchangeError("solver_input_too_large", "solver 입력 전체 크기가 지원 범위를 넘었습니다.", category="storage")
    return total


def _attachment_total(attachments: list[dict[str, Any]]) -> int:
    sizes: list[int] = []
    for row in attachments:
        value = row.get("size")
        if type(value) is not int or value < 0:
            raise ExchangeError("invalid_attachment_size", "첨부 파일 크기를 확인할 수 없습니다.", category="safety")
        sizes.append(value)
    return _checked_total(*sizes)


def _regular_file_size(source: Path, *, maximum_size: int, require_private: bool) -> int:
    descriptor = None
    try:
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ExchangeError("invalid_source_file", "solver 입력 파일 형식을 확인할 수 없습니다.", category="safety")
        if require_private and os.name == "posix" and details.st_mode & 0o077:
            raise ExchangeError("invalid_auth_permissions", "Codex 인증 파일 권한이 안전하지 않습니다.", category="auth")
        if details.st_size < 2 or details.st_size > maximum_size:
            raise ExchangeError("invalid_auth_file", "Codex 인증 파일 크기를 확인할 수 없습니다.", category="auth")
        return int(details.st_size)
    except FileNotFoundError as exc:
        raise ExchangeError("account_login_required", "선택한 Codex 계정에 다시 로그인해 주세요.", category="auth") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _runtime_files(root: Path, version: str,
                   provider: str = "codex") -> tuple[list[tuple[Path, int, bool]], int]:
    if root.is_symlink() or not root.is_dir():
        raise ExchangeError("invalid_runtime", "Codex runtime 디렉터리를 확인할 수 없습니다.", category="safety")
    resolved = root.resolve()
    result: list[tuple[Path, int, bool]] = []
    total = 0
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        if not current_path.resolve().is_relative_to(resolved):
            raise ExchangeError("invalid_runtime", "Codex runtime 경로가 게시 범위를 벗어납니다.", category="safety")
        # npm creates node_modules/.bin as a directory of symlinks. The solver
        # executes the verified package's bin/codex.js directly, so this one
        # launcher directory is unnecessary and is never published.
        if current_path == root / "node_modules" and ".bin" in directories:
            launcher = current_path / ".bin"
            details = launcher.lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
                raise ExchangeError("invalid_runtime", "Codex npm launcher 경로를 확인할 수 없습니다.", category="safety")
            directories.remove(".bin")
        for name in directories:
            count += 1
            path = current_path / name
            details = path.lstat()
            if count > 100_000 or stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
                raise ExchangeError("invalid_runtime", "Codex runtime 디렉터리 형식을 확인할 수 없습니다.", category="safety")
        for name in files:
            count += 1
            path = current_path / name
            details = path.lstat()
            if (
                count > 100_000
                or stat.S_ISLNK(details.st_mode)
                or not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
            ):
                raise ExchangeError("invalid_runtime", "Codex runtime 파일 형식을 확인할 수 없습니다.", category="safety")
            total = _checked_total(total, int(details.st_size))
            result.append((path.relative_to(root), int(details.st_size), bool(details.st_mode & 0o111)))
    if provider == "codex":
        package_path = root / "node_modules" / "@openai" / "codex" / "package.json"
        script = root / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    elif provider == "claude":
        architecture = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
        if not architecture:
            raise ExchangeError("invalid_runtime", "Unsupported Claude runtime architecture.", category="model")
        package_path = root / "node_modules" / "@anthropic-ai" / "claude-code" / "package.json"
        script = root / "node_modules" / "@anthropic-ai" / f"claude-code-linux-{architecture}" / "claude"
    else:
        raise ExchangeError("invalid_provider", "Unknown runtime provider.", category="model")
    package = _read_json_file(package_path, 512 * 1024)
    if package.get("version") != version or not script.is_file() or script.is_symlink():
        raise ExchangeError("invalid_runtime", "Codex runtime 패키지 버전을 확인할 수 없습니다.", category="safety")
    result.sort(key=lambda item: item[0].as_posix())
    return result, total


def _runtime_digest_for_files(root: Path, files: list[tuple[Path, int, bool]]) -> str:
    digest = hashlib.sha256()
    for relative, expected_size, _executable in files:
        encoded = relative.as_posix().encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        source = root / relative
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        copied = 0
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size != expected_size:
                raise ExchangeError("invalid_runtime", "Codex runtime 파일이 검사 중 변경되었습니다.", category="safety")
            while chunk := os.read(descriptor, 4 * 1024 * 1024):
                copied += len(chunk)
                digest.update(chunk)
        finally:
            os.close(descriptor)
        if copied != expected_size:
            raise ExchangeError("invalid_runtime", "Codex runtime 파일이 검사 중 변경되었습니다.", category="safety")
    return digest.hexdigest()


def _make_tree_owner_writable(path: Path, parent: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or path.resolve().parent != parent.resolve():
        raise ExchangeError("invalid_cleanup_path", "Codex runtime 임시 경로를 정리할 수 없습니다.", category="safety")
    for current, directories, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            candidate = Path(current) / name
            if candidate.is_symlink():
                raise ExchangeError("invalid_cleanup_path", "Codex runtime 임시 경로에 링크가 있습니다.", category="safety")
            candidate.chmod(0o600)
        for name in directories:
            candidate = Path(current) / name
            if candidate.is_symlink():
                raise ExchangeError("invalid_cleanup_path", "Codex runtime 임시 경로에 링크가 있습니다.", category="safety")
            candidate.chmod(0o700)
    path.chmod(0o700)


def _write_once(path: Path, content: bytes, mode: int) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        return
    try:
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync(path.parent)


def _write_regular_file(path: Path, content: bytes, mode: int) -> None:
    """Create one complete control file without following or replacing paths."""

    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short control-file write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size != len(content):
            raise OSError("invalid control file")
    finally:
        os.close(descriptor)
    _fsync(path.parent)


def _open_readonly_beneath(path: Path, root: Path | None) -> int:
    """Open a file without following components below a trusted root."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if root is None:
        return os.open(path, flags)
    root = Path(root)
    path = Path(path)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ExchangeError(
            "invalid_source_file",
            "solver 입력 파일이 데이터 폴더 밖을 가리킵니다.",
            category="safety",
        ) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ExchangeError(
            "invalid_source_file",
            "solver 입력 파일 경로를 확인할 수 없습니다.",
            category="safety",
        )

    if (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and os.open in getattr(os, "supports_dir_fd", set())
    ):
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = None
        try:
            directory_fd = os.open(root, directory_flags)
            for component in relative.parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            return os.open(relative.parts[-1], flags, dir_fd=directory_fd)
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    # Docker Desktop runs the production boundary in Linux. Native Windows
    # tests retain the existing complete-chain check as their fallback.
    _assert_no_symlink_chain(root, path)
    return os.open(path, flags)


def _content_snapshot(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_size),
        int(details.st_mtime_ns),
        int(details.st_ctime_ns),
    )


def _copy_regular_file(
    source: Path,
    destination: Path,
    *,
    expected_size: Any,
    cancelled: Callable[[], bool],
    maximum_size: int | None = None,
    require_private: bool = False,
    return_digest: bool = False,
    space_reserved: bool = False,
    source_root: Path | None = None,
    allow_hardlinks: bool = False,
) -> str:
    source_fd = destination_fd = None
    digest = hashlib.sha256()
    copied = 0
    try:
        if require_private and allow_hardlinks:
            raise ExchangeError(
                "invalid_source_file",
                "계정 인증 파일에는 첨부파일 링크 규칙을 적용할 수 없습니다.",
                category="safety",
            )
        source_fd = _open_readonly_beneath(source, source_root)
        details = os.fstat(source_fd)
        if not stat.S_ISREG(details.st_mode) or (not allow_hardlinks and details.st_nlink != 1):
            raise ExchangeError("invalid_source_file", "solver 입력 파일 형식을 확인할 수 없습니다.", category="safety")
        initial_source = _content_snapshot(details)
        if require_private and os.name == "posix" and details.st_mode & 0o077:
            raise ExchangeError("invalid_auth_permissions", "Codex 인증 파일 권한이 안전하지 않습니다.", category="auth")
        if maximum_size is not None and (details.st_size < 2 or details.st_size > maximum_size):
            raise ExchangeError("invalid_auth_file", "Codex 인증 파일 크기를 확인할 수 없습니다.", category="auth")
        if expected_size is not None and (type(expected_size) is not int or expected_size < 0 or details.st_size != expected_size):
            raise ExchangeError("attachment_size_mismatch", "첨부파일 크기가 저장된 정보와 일치하지 않습니다.", category="safety")
        if not require_private and not space_reserved:
            try:
                free = shutil.disk_usage(destination.parent).free
            except OSError as exc:
                raise ExchangeError(
                    "solver_storage_unavailable",
                    "격리 복사본의 남은 저장공간을 확인할 수 없습니다.",
                    category="storage",
                    retryable=True,
                ) from exc
            if free - details.st_size < _MIN_FREE_BYTES_AFTER_STAGE:
                raise ExchangeError(
                    "insufficient_solver_storage",
                    "격리 복사본을 만들 저장공간이 부족합니다. 원본 파일은 보존되었습니다.",
                    category="storage",
                    retryable=True,
                )
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        while True:
            if cancelled():
                raise _StageCancelled
            chunk = os.read(source_fd, 4 * 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if maximum_size is not None and copied > maximum_size:
                raise ExchangeError("invalid_auth_file", "Codex 인증 파일 크기를 확인할 수 없습니다.", category="auth")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
        if expected_size is not None and copied != expected_size:
            raise ExchangeError("attachment_size_mismatch", "첨부파일 크기가 저장된 정보와 일치하지 않습니다.", category="safety")
        os.fsync(destination_fd)
        if _content_snapshot(os.fstat(source_fd)) != initial_source:
            raise ExchangeError(
                "attachment_changed_during_staging",
                "첨부파일이 solver로 복사되는 동안 변경되었습니다. 다시 시도해 주세요.",
                category="storage",
                retryable=True,
            )
        destination_details = os.fstat(destination_fd)
        if (
            not stat.S_ISREG(destination_details.st_mode)
            or destination_details.st_nlink != 1
            or destination_details.st_size != copied
        ):
            raise ExchangeError(
                "invalid_source_file",
                "solver 입력 파일 복사본을 확인할 수 없습니다.",
                category="safety",
            )
    except FileNotFoundError as exc:
        raise ExchangeError(
            "account_login_required" if require_private else "attachment_missing",
            "선택한 Codex 계정에 다시 로그인해 주세요." if require_private else "첨부파일이 저장소에 없습니다.",
            category="auth" if require_private else "storage",
        ) from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    return digest.hexdigest() if return_digest else ""


def _assert_no_symlink_chain(root: Path, target: Path) -> None:
    if root.is_symlink():
        raise ExchangeError("invalid_source_path", "solver 데이터 저장소에 링크를 사용할 수 없습니다.", category="safety")
    resolved_root = root.resolve(strict=True)
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ExchangeError("invalid_source_path", "solver 입력 경로가 데이터 저장소 밖을 가리킵니다.", category="safety") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.exists() and cursor.is_symlink():
            raise ExchangeError("invalid_source_path", "solver 입력 경로에 링크를 사용할 수 없습니다.", category="safety")
    try:
        resolved = target.resolve(strict=True)
    except FileNotFoundError:
        # An empty challenge intentionally has no source attachments directory.
        resolved = target.resolve(strict=False)
    if not resolved.is_relative_to(resolved_root):
        raise ExchangeError("invalid_source_path", "solver 입력 경로가 데이터 저장소 밖을 가리킵니다.", category="safety")


def _safe_remove_tree(path: Path, parent: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.resolve().parent != parent.resolve():
        raise ExchangeError("invalid_cleanup_path", "solver 임시 경로를 안전하게 정리할 수 없습니다.", category="safety")
    shutil.rmtree(path)
    _fsync(parent)


def _stage_filename(index: int, value: Any) -> str:
    name = str(value or "attachment.bin").replace("\\", "/").split("/")[-1].strip()
    name = "".join(character if ord(character) >= 32 and character not in '<>:"|?*' else "_" for character in name)
    if not name or name in {".", ".."}:
        name = "attachment.bin"
    return f"{index:04d}_{name[:180]}"


def _optional_json(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


def _require_id(value: str, kind: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ExchangeError(f"invalid_{kind}_id", f"{kind} 식별자를 확인할 수 없습니다.")


def _fsync(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc_stamp(timestamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


__all__ = ["ExchangeError", "SolverExchangeCoordinator", "SolverCoordinatorPool"]
