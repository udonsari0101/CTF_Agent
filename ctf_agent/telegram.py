"""Per-user Telegram bots, linking, and reliable CTF notifications.

Bot tokens are entered by their owners and encrypted with a local key. Link
secrets are single-use values; only their SHA-256 digests are stored in SQLite.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from .process_lock import ProcessFileLock


LINK_TTL_SECONDS = 10 * 60
START_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
BOT_USERNAME = re.compile(r"^[A-Za-z0-9_]{5,32}$")
BOT_TOKEN = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{30,}$")
_SAFE_JOB_SETTING = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}$")
_COPY_TEXT_MAX_CHARACTERS = 256
_SOLVER_ALERT_STATUSES = frozenset({"failed", "refused", "needs_input"})
_SOLVER_ALERT_REASONS = {
    "remote_input_required": "원격 접속 정보가 필요합니다. 문제 화면에서 원격 대상을 입력하거나 대상 없음을 선택한 뒤 다시 시작하세요.",
    "auth_required": "모델 계정 연결을 확인하고 다시 로그인한 뒤 풀이를 다시 시작하세요.",
    "account_workspace_mismatch": "선택한 모델 계정을 다시 연결한 뒤 풀이를 다시 시작하세요.",
    "daybreak_route_rejected": "계정의 Daybreak 권한과 선택 모델을 확인한 뒤 다시 시도하세요.",
    "codex_attestation_unavailable": "다른 지원 모델을 선택하거나 관리자에게 Codex 실행 환경 확인을 요청하세요.",
    "access_denied": "계정의 모델 권한을 확인하거나 사용 가능한 다른 모델을 선택하세요.",
    "model_unavailable": "계정에서 사용할 수 있는 다른 모델을 선택한 뒤 다시 시도하세요.",
    "policy_security": "공급자의 보안 작업 정책으로 중단되었습니다. 다른 지원 모델이나 계정을 선택하세요.",
    "provider_tools_unavailable": "풀이 도구를 지원하는 다른 모델을 선택한 뒤 다시 시도하세요.",
    "usage_limit_exceeded": "계정 사용량이 초기화된 뒤 또는 다른 계정으로 다시 시도하세요.",
    "session_budget_exceeded": "새 풀이 세션이나 다른 계정으로 다시 시도하세요.",
    "rate_limit_exceeded": "공급자 요청 제한이 해제된 뒤 다시 시도하세요.",
    "quota_exceeded": "계정 사용량이 초기화된 뒤 또는 다른 계정으로 다시 시도하세요.",
    "context_limit": "새 풀이 작업으로 다시 시작하거나 더 큰 컨텍스트를 지원하는 모델을 선택하세요.",
    "provider_request_rejected": "선택한 모델 설정을 확인한 뒤 다시 시도하세요.",
    "provider_unavailable": "일시적인 공급자 오류입니다. 잠시 뒤 다시 시도하세요.",
    "remote_resolution_failed": "문제의 원격 주소를 확인한 뒤 다시 시도하세요.",
    "timeout": "풀이 시간이 초과되었습니다. 문제 상태를 확인한 뒤 다시 시도하세요.",
    "flag_not_submitted": "제한된 풀이 횟수 안에 Flag를 확인하지 못했습니다. 새 풀이를 시작하세요.",
    "writeup_style_invalid": "write-up 형식을 확인하지 못했습니다. 기존 내용은 유지됐으며 보완을 다시 요청할 수 있습니다.",
    "writeup_source_changed": "보완 중 원본 write-up 또는 Flag가 변경됐습니다. 최신 내용을 확인한 뒤 다시 요청하세요.",
    "writeup_refinement_flag_event": "write-up 보완 결과가 Flag 변경을 포함해 폐기됐습니다. 기존 Flag와 write-up은 유지됩니다.",
}
_SYSTEM_CANCEL_ALERT_CODES = frozenset(
    {"writeup_style_invalid", "writeup_source_changed", "writeup_refinement_flag_event"}
)
_SOLVER_ALERT_FALLBACK = {
    "needs_input": "추가 입력이 필요합니다. 문제 화면에서 필요한 정보를 보완한 뒤 다시 시작하세요.",
    "refused": "현재 설정으로 풀이를 시작할 수 없습니다. 문제와 계정 설정을 확인하세요.",
    "failed": "풀이를 완료하지 못했습니다. 문제 화면에서 상태를 확인한 뒤 다시 시도하세요.",
}
_OUTBOX_TABLE_SQL = """
CREATE TABLE notification_outbox (
    id TEXT PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK(event_type IN ('flag_found','writeup_ready','solver_alert')),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    job_id TEXT,
    priority INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','processing','sent','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    claimed_at INTEGER,
    last_error_code TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
)
"""


def _ensure_notification_outbox(db: sqlite3.Connection) -> None:
    """Add solver alerts without discarding durable flag/write-up deliveries."""

    row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='notification_outbox'"
    ).fetchone()
    if row is None:
        db.execute(_OUTBOX_TABLE_SQL)
    else:
        columns = {column[1] for column in db.execute("PRAGMA table_info(notification_outbox)")}
        definition = str(row[0] or "").lower()
        if "job_id" not in columns or "solver_alert" not in definition:
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='notification_outbox_legacy'"
            ).fetchone():
                raise sqlite3.OperationalError("unfinished notification outbox migration")
            db.execute("ALTER TABLE notification_outbox RENAME TO notification_outbox_legacy")
            db.execute("DROP INDEX IF EXISTS idx_notification_outbox_due")
            db.execute(_OUTBOX_TABLE_SQL)
            legacy_columns = {
                column[1] for column in db.execute("PRAGMA table_info(notification_outbox_legacy)")
            }
            job_id = "job_id" if "job_id" in legacy_columns else "NULL"
            db.execute(
                """INSERT INTO notification_outbox(
                       id,event_key,user_id,event_type,workspace_id,challenge_id,job_id,
                       priority,status,attempts,next_attempt_at,claimed_at,last_error_code,created_at,sent_at
                   )
                   SELECT id,event_key,user_id,event_type,workspace_id,challenge_id,"""
                + job_id
                + """,priority,status,attempts,next_attempt_at,claimed_at,last_error_code,created_at,sent_at
                   FROM notification_outbox_legacy"""
            )
            db.execute("DROP TABLE notification_outbox_legacy")
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_notification_outbox_due "
        "ON notification_outbox(status,next_attempt_at,priority,created_at)"
    )


def utc_stamp(timestamp: int | None = None) -> str:
    moment = datetime.fromtimestamp(timestamp, timezone.utc) if timestamp is not None else datetime.now(timezone.utc)
    return moment.isoformat(timespec="seconds")


def telegram_text(value: Any) -> str:
    return "".join(character if character in "\n\t" or ord(character) >= 32 else "�" for character in str(value))


class TelegramToggle(BaseModel):
    enabled: bool


class TelegramBotInput(BaseModel):
    token: str


class TelegramAPIError(RuntimeError):
    """A token-safe error raised for a failed Bot API request."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code[:80]


class TelegramService:
    def __init__(
        self,
        database,
        settings,
        token: str,
        expected_bot_username: str = "",
        *,
        identity_verified: bool = False,
    ):
        self.database = database
        self.settings = settings
        self.token = token
        # A configured username is only an optional assertion.  The Bot API is
        # authoritative because a stale or copied compose value can otherwise
        # issue a valid one-time secret in a deep link to the wrong bot.
        self.expected_bot_username = expected_bot_username.lstrip("@")
        self.bot_username = ""
        self.identity_verified = False
        self.configuration_error: str | None = None
        if identity_verified:
            self._accept_bot_identity(self.expected_bot_username)
        self.client: httpx.AsyncClient | None = None
        self.start_count = 0
        self.poll_task: asyncio.Task | None = None
        self.bot_reconcile_task: asyncio.Task | None = None
        self.bot_poll_tasks: dict[str, asyncio.Task] = {}
        self.bot_poll_hashes: dict[str, str] = {}
        self.outbox_task: asyncio.Task | None = None
        self.wakeup: asyncio.Event | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.webhook_cleared = False
        # Runtime routes and the polling task use this lock to linearize a
        # bounded send with OFF, unlink, relink, and admin deactivation.
        self.delivery_locks: dict[str, asyncio.Lock] = {}
        lock_base = Path(getattr(settings, "config_dir", getattr(settings, "data_dir", Path("."))))
        self.delivery_lock_root = lock_base / ".locks" / "telegram-delivery"
        self.poll_lock_root = lock_base / ".locks" / "telegram-poll"
        self.key_path = lock_base / "telegram-bots.key"
        self._cipher: Fernet | None = None

    def _fernet(self) -> Fernet:
        if self._cipher is not None:
            return self._cipher
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(Fernet.generate_key())
                key_file.flush()
                os.fsync(key_file.fileno())
        try:
            for attempt in range(5):
                key = self.key_path.read_bytes()
                if key:
                    break
                time.sleep(.02)
            self._cipher = Fernet(key)
        except (OSError, ValueError) as exc:
            raise RuntimeError("Telegram token key is unavailable or invalid") from exc
        return self._cipher

    def _bot_row(self, user_id: str) -> sqlite3.Row | None:
        with self.database() as db:
            return db.execute(
                "SELECT token_ciphertext,token_hash,bot_username FROM telegram_bots WHERE user_id=?",
                (user_id,),
            ).fetchone()

    def _token_for(self, user_id: str) -> str | None:
        row = self._bot_row(user_id)
        if row is None:
            return self.token if self.configured else None
        try:
            return self._fernet().decrypt(row["token_ciphertext"].encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError, RuntimeError):
            return None

    @property
    def configured(self) -> bool:
        return bool(self.token and self.identity_verified and self.bot_username)

    async def start(self) -> None:
        self.start_count += 1
        if self.start_count > 1:
            return
        self.bot_username = ""
        self.identity_verified = False
        self.configuration_error = None
        self.loop = asyncio.get_running_loop()
        self.wakeup = asyncio.Event()
        if self.token:
            try:
                await self._discover_bot_identity()
            except TelegramAPIError as error:
                self.configuration_error = error.code
                if self.client:
                    await self.client.aclose()
                self.client = None
                self.loop = None
                return
            self.poll_task = asyncio.create_task(self._poll_loop(), name="telegram-update-poll")
        else:
            self.bot_reconcile_task = asyncio.create_task(
                self._reconcile_bots_loop(), name="telegram-bot-reconcile"
            )
        self.outbox_task = asyncio.create_task(self._outbox_loop(), name="telegram-notification-outbox")

    async def stop(self) -> None:
        if self.start_count == 0:
            return
        self.start_count -= 1
        if self.start_count:
            return
        tasks = [task for task in (self.poll_task, self.outbox_task, self.bot_reconcile_task) if task]
        tasks.extend(self.bot_poll_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.poll_task = self.outbox_task = self.bot_reconcile_task = None
        self.bot_poll_tasks.clear()
        self.bot_poll_hashes.clear()
        if self.client:
            await self.client.aclose()
        self.client = None
        self.loop = None

    def _accept_bot_identity(self, username: str) -> None:
        if not BOT_USERNAME.fullmatch(username) or not username.casefold().endswith("bot"):
            raise TelegramAPIError("invalid_bot_identity")
        self.bot_username = username
        self.identity_verified = True
        self.configuration_error = None

    async def _discover_bot_identity(self) -> None:
        body = await self._api("getMe", {})
        identity = body.get("result")
        if (
            not isinstance(identity, dict)
            or identity.get("is_bot") is not True
            or type(identity.get("id")) is not int
            or identity["id"] <= 0
            or not isinstance(identity.get("username"), str)
        ):
            raise TelegramAPIError("invalid_bot_identity")
        username = identity["username"]
        if self.expected_bot_username:
            if (
                not BOT_USERNAME.fullmatch(self.expected_bot_username)
                or self.expected_bot_username.casefold() != username.casefold()
            ):
                raise TelegramAPIError("bot_username_mismatch")
        self._accept_bot_identity(username)

    async def _api(self, method: str, payload: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
        if not self.client:
            self.client = httpx.AsyncClient(timeout=httpx.Timeout(35, connect=10))
        bot_token = token if token is not None else self.token
        if not bot_token:
            raise TelegramAPIError("bot_not_configured")
        try:
            response = await self.client.post(
                f"https://api.telegram.org/bot{bot_token}/{method}", json=payload
            )
            body = response.json()
        except (httpx.HTTPError, ValueError):
            raise TelegramAPIError("transport_error") from None
        if response.status_code >= 400 or not isinstance(body, dict) or not body.get("ok"):
            error_code = body.get("error_code") if isinstance(body, dict) else response.status_code
            raise TelegramAPIError(f"api_{error_code or 'error'}")
        return body

    async def save_bot(self, user_id: str, token: str) -> dict[str, Any]:
        token = token.strip()
        if not BOT_TOKEN.fullmatch(token):
            raise HTTPException(422, "Enter a valid Telegram bot token from BotFather.")
        try:
            identity = (await self._api("getMe", {}, token=token)).get("result")
        except TelegramAPIError:
            raise HTTPException(422, "Telegram could not verify this bot token.") from None
        if (not isinstance(identity, dict) or identity.get("is_bot") is not True
                or type(identity.get("id")) is not int or identity["id"] <= 0
                or not isinstance(identity.get("username"), str)
                or not BOT_USERNAME.fullmatch(identity["username"])):
            raise HTTPException(422, "Telegram returned an invalid bot identity.")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        ciphertext = self._fernet().encrypt(token.encode("utf-8")).decode("ascii")
        try:
            async with self.delivery_boundary(user_id):
                with self.database() as db:
                    db.execute("BEGIN IMMEDIATE")
                    existing = db.execute(
                        "SELECT token_hash FROM telegram_bots WHERE user_id=?", (user_id,)
                    ).fetchone()
                    changed = existing is None or existing["token_hash"] != digest
                    db.execute(
                        """INSERT INTO telegram_bots(user_id,token_ciphertext,token_hash,bot_id,bot_username,updated_at)
                           VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                           token_ciphertext=excluded.token_ciphertext,token_hash=excluded.token_hash,
                           bot_id=excluded.bot_id,bot_username=excluded.bot_username,updated_at=excluded.updated_at""",
                        (user_id, ciphertext, digest, identity["id"], identity["username"], utc_stamp()),
                    )
                    if changed:
                        db.execute("DELETE FROM telegram_link_tokens WHERE user_id=?", (user_id,))
                        db.execute(
                            "UPDATE telegram_settings SET chat_id=NULL,enabled=0,linked_at=NULL WHERE user_id=?",
                            (user_id,),
                        )
                        db.execute(
                            "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                            "WHERE user_id=? AND status IN ('pending','processing','failed')",
                            (user_id,),
                        )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "This bot is already connected to another user.") from None
        except TimeoutError:
            raise HTTPException(503, "Telegram delivery is still finishing. Try again shortly.") from None
        return self.settings_for(user_id)

    async def delete_bot(self, user_id: str) -> dict[str, Any]:
        try:
            async with self.delivery_boundary(user_id):
                with self.database() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("DELETE FROM telegram_bots WHERE user_id=?", (user_id,))
                    db.execute("DELETE FROM telegram_link_tokens WHERE user_id=?", (user_id,))
                    db.execute(
                        "UPDATE telegram_settings SET chat_id=NULL,enabled=0,linked_at=NULL WHERE user_id=?",
                        (user_id,),
                    )
                    db.execute(
                        "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                        "WHERE user_id=? AND status IN ('pending','processing','failed')",
                        (user_id,),
                    )
        except TimeoutError:
            raise HTTPException(503, "Telegram delivery is still finishing. Try again shortly.") from None
        return self.settings_for(user_id)

    @asynccontextmanager
    async def delivery_boundary(self, user_id: str, wait_seconds: float = 40.0):
        """Serialize delivery and settings changes across rolling processes."""

        local_lock = self.delivery_locks.setdefault(user_id, asyncio.Lock())
        async with local_lock:
            digest = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
            lease = ProcessFileLock(self.delivery_lock_root / f"user-{digest}.lock")
            deadline = time.monotonic() + max(0.0, float(wait_seconds))
            while not lease.try_acquire():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Telegram delivery boundary is busy")
                await asyncio.sleep(min(.02, remaining))
            try:
                yield
            finally:
                lease.release()

    def issue_link(self, user_id: str) -> dict[str, Any]:
        state = self.settings_for(user_id)
        if not state["configured"]:
            raise HTTPException(503, "Telegram 봇이 아직 설정되지 않았습니다.")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        timestamp, expires = int(time.time()), int(time.time()) + LINK_TTL_SECONDS
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM telegram_link_tokens WHERE expires_at<? OR used_at IS NOT NULL", (timestamp - 3600,))
            db.execute("DELETE FROM telegram_link_tokens WHERE user_id=? AND used_at IS NULL", (user_id,))
            db.execute(
                "INSERT INTO telegram_link_tokens(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                (digest, user_id, expires, utc_stamp(timestamp)),
            )
        return {
            "deep_link": f"https://t.me/{state['bot_username']}?start={token}",
            "expires_at": utc_stamp(expires),
        }

    def settings_for(self, user_id: str) -> dict[str, Any]:
        with self.database() as db:
            row = db.execute("SELECT * FROM telegram_settings WHERE user_id=?", (user_id,)).fetchone()
            bot = db.execute(
                "SELECT bot_username FROM telegram_bots WHERE user_id=?", (user_id,)
            ).fetchone()
        configured = bool(bot) or self.configured
        linked = bool(configured and row and row["chat_id"] is not None)
        return {
            "configured": configured,
            "bot_username": bot["bot_username"] if bot else (self.bot_username if self.configured else None),
            "configuration_error": self.configuration_error if not bot else None,
            "linked": linked,
            "enabled": bool(linked and row["enabled"]),
            "linked_at": row["linked_at"] if row else None,
            "last_success_at": row["last_success_at"] if row else None,
            "last_failure_at": row["last_failure_at"] if row else None,
            "last_failure_code": row["last_failure_code"] if row else None,
        }

    def admin_summary(self, user_id: str) -> dict[str, Any]:
        """Return status metadata without exposing the Telegram chat identifier."""
        state = self.settings_for(user_id)
        return {
            "telegram_linked": state["linked"],
            "telegram_enabled": state["enabled"],
            "telegram_last_success_at": state["last_success_at"],
            "telegram_last_failure_at": state["last_failure_at"],
        }

    def set_enabled(self, user_id: str, enabled: bool) -> dict[str, Any]:
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT chat_id FROM telegram_settings WHERE user_id=?", (user_id,)).fetchone()
            if not row or row["chat_id"] is None:
                raise HTTPException(409, "먼저 Telegram 계정을 연결하세요.")
            db.execute("UPDATE telegram_settings SET enabled=? WHERE user_id=?", (int(enabled), user_id))
            if not enabled:
                db.execute(
                    "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                    "WHERE user_id=? AND status IN ('pending','processing','failed')",
                    (user_id,),
                )
        return self.settings_for(user_id)

    async def set_enabled_serialized(self, user_id: str, enabled: bool) -> dict[str, Any]:
        try:
            async with self.delivery_boundary(user_id):
                return self.set_enabled(user_id, enabled)
        except TimeoutError:
            raise HTTPException(503, "Telegram delivery is still finishing. Try again shortly.") from None

    async def cancel_owner(self, user_id: str) -> bool:
        """Cancel delivery before an administrative deactivation returns."""
        try:
            async with self.delivery_boundary(user_id):
                with self.database() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                        "WHERE user_id=? AND status IN ('pending','processing','failed')",
                        (user_id,),
                    )
            return True
        except TimeoutError:
            return False

    def unlink(self, user_id: str) -> dict[str, Any]:
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM telegram_link_tokens WHERE user_id=?", (user_id,))
            db.execute(
                "UPDATE telegram_settings SET chat_id=NULL,enabled=0,linked_at=NULL WHERE user_id=?",
                (user_id,),
            )
            db.execute(
                "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                "WHERE user_id=? AND status IN ('pending','processing','failed')",
                (user_id,),
            )
        return self.settings_for(user_id)

    async def unlink_serialized(self, user_id: str) -> dict[str, Any]:
        try:
            async with self.delivery_boundary(user_id):
                return self.unlink(user_id)
        except TimeoutError:
            raise HTTPException(503, "Telegram delivery is still finishing. Try again shortly.") from None

    def enqueue(
        self,
        user_id: str,
        event_type: str,
        workspace_id: str,
        challenge_id: str,
        event_key: str,
        *,
        job_id: str | None = None,
    ) -> bool:
        if event_type not in ("flag_found", "writeup_ready"):
            raise ValueError("unsupported Telegram event")
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            if job_id is not None:
                column, hook, prefix = (
                    ("flag", "flag_hooked", "flag")
                    if event_type == "flag_found"
                    else ("writeup_markdown", "writeup_hooked", "writeup")
                )
                job = db.execute(
                    f"""SELECT {column} AS result_value FROM solver_jobs
                         WHERE id=? AND owner_user_id=? AND workspace_id=? AND challenge_id=?
                           AND {hook}=0""",
                    (job_id, user_id, workspace_id, challenge_id),
                ).fetchone()
                result_value = job["result_value"] if job else None
                expected = (
                    f"{prefix}:{challenge_id}:"
                    f"{hashlib.sha256((result_value or '').encode('utf-8')).hexdigest()}"
                )
                if (
                    not isinstance(result_value, str)
                    or not result_value
                    or not secrets.compare_digest(event_key, expected)
                ):
                    # A production solver callback always supplies its exact
                    # job.  Refuse a mismatched binding instead of guessing
                    # among older hooks with the same result value.
                    raise ValueError("solver result binding mismatch")
            setting = db.execute(
                """SELECT 1 FROM telegram_settings s
                   JOIN users u ON u.id=s.user_id AND u.active=1
                   WHERE s.user_id=? AND s.chat_id IS NOT NULL AND s.enabled=1""",
                (user_id,),
            ).fetchone()
            if not setting:
                return False
            inserted = db.execute(
                """INSERT OR IGNORE INTO notification_outbox
                   (id,event_key,user_id,event_type,workspace_id,challenge_id,job_id,
                    priority,status,attempts,next_attempt_at,created_at)
                   VALUES(?,?,?,?,?,?,?,?,'pending',0,?,?)""",
                (
                    uuid.uuid4().hex,
                    event_key,
                    user_id,
                    event_type,
                    workspace_id,
                    challenge_id,
                    job_id,
                    10 if event_type == "flag_found" else 20,
                    int(time.time()),
                    utc_stamp(),
                ),
            ).rowcount
        if inserted and self.loop and self.wakeup:
            self.loop.call_soon_threadsafe(self.wakeup.set)
        return bool(inserted)

    def enqueue_flag(
        self,
        user_id: str,
        workspace_id: str,
        challenge_id: str,
        flag: str,
        job_id: str | None = None,
    ) -> bool:
        digest = hashlib.sha256(flag.encode("utf-8")).hexdigest()
        return self.enqueue(
            user_id,
            "flag_found",
            workspace_id,
            challenge_id,
            f"flag:{challenge_id}:{digest}",
            job_id=job_id,
        )

    def enqueue_writeup(
        self,
        user_id: str,
        workspace_id: str,
        challenge_id: str,
        markdown: str,
        job_id: str | None = None,
    ) -> bool:
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        return self.enqueue(
            user_id,
            "writeup_ready",
            workspace_id,
            challenge_id,
            f"writeup:{challenge_id}:{digest}",
            job_id=job_id,
        )

    @staticmethod
    def _solver_alert_code(error_json: Any, status: str) -> str:
        try:
            value = json.loads(error_json) if isinstance(error_json, str) and len(error_json) <= 65_536 else None
        except (ValueError, TypeError):
            value = None
        code = value.get("code") if isinstance(value, dict) else None
        return code if code in _SOLVER_ALERT_REASONS else f"status_{status}"

    @staticmethod
    def _solver_alert_key(job_id: str, status: str) -> str:
        # One alert per committed job state.  The provider error can be
        # rewritten while cleanup finishes, but that must never create a
        # second terminal notification for the same state.
        return f"solver-alert:{job_id}:{status}"

    def enqueue_solver_alerts(self, limit: int = 100) -> bool:
        """Discover committed terminal states and durably record each once."""

        inserted = pending = 0
        timestamp = int(time.time())
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            marker = db.execute(
                "SELECT value FROM meta WHERE key='telegram_solver_alerts_started_at'"
            ).fetchone()
            try:
                cutoff = float(marker["value"]) if marker else time.time()
            except (TypeError, ValueError):
                cutoff = time.time()
            if marker is None:
                db.execute(
                    "INSERT INTO meta(key,value) VALUES('telegram_solver_alerts_started_at',?)",
                    (str(cutoff),),
                )
            rows = db.execute(
                """SELECT j.id,j.owner_user_id,j.workspace_id,j.challenge_id,j.status,j.error_json,
                          j.cancel_requested,
                          u.active,s.chat_id,s.enabled
                     FROM solver_jobs j
                     JOIN users u ON u.id=j.owner_user_id
                     JOIN workspaces w ON w.id=j.workspace_id AND w.owner_user_id=j.owner_user_id
                     JOIN challenges c ON c.id=j.challenge_id AND c.workspace_id=j.workspace_id
                     LEFT JOIN telegram_settings s ON s.user_id=j.owner_user_id
                    WHERE j.status IN ('failed','refused','needs_input')
                      AND j.released_ingested=1
                      AND COALESCE(j.released_at,j.updated_at)>=?
                      AND NOT (c.status='solved' AND c.completion_source='manual')
                      AND NOT EXISTS (
                          SELECT 1 FROM notification_outbox existing
                           WHERE existing.job_id=j.id AND existing.event_type='solver_alert'
                             AND existing.event_key=('solver-alert:' || j.id || ':' || j.status)
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM solver_jobs newer
                           WHERE newer.owner_user_id=j.owner_user_id
                             AND newer.workspace_id=j.workspace_id
                             AND newer.challenge_id=j.challenge_id
                             AND (newer.created_at>j.created_at
                                  OR (newer.created_at=j.created_at AND newer.id>j.id))
                      )
                    ORDER BY j.updated_at,j.id LIMIT ?""",
                (cutoff, max(1, min(int(limit), 500))),
            ).fetchall()
            for row in rows:
                code = self._solver_alert_code(row["error_json"], row["status"])
                if row["cancel_requested"] and code not in _SYSTEM_CANCEL_ALERT_CODES:
                    continue
                event_key = self._solver_alert_key(row["id"], row["status"])
                deliver = bool(row["active"] and row["chat_id"] is not None and row["enabled"])
                changed = db.execute(
                    """INSERT OR IGNORE INTO notification_outbox(
                           id,event_key,user_id,event_type,workspace_id,challenge_id,job_id,
                           priority,status,attempts,next_attempt_at,created_at
                       ) VALUES(?,?,?,?,?,?,?,15,?,0,?,?)""",
                    (
                        uuid.uuid4().hex,
                        event_key,
                        row["owner_user_id"],
                        "solver_alert",
                        row["workspace_id"],
                        row["challenge_id"],
                        row["id"],
                        "pending" if deliver else "cancelled",
                        timestamp,
                        utc_stamp(timestamp),
                    ),
                ).rowcount
                inserted += changed
                pending += changed if deliver else 0
        if pending and self.loop and self.wakeup:
            self.loop.call_soon_threadsafe(self.wakeup.set)
        return bool(inserted)

    def _offset(self, user_id: str | None = None) -> int:
        with self.database() as db:
            row = (
                db.execute("SELECT update_offset AS value FROM telegram_bots WHERE user_id=?", (user_id,)).fetchone()
                if user_id is not None else
                db.execute("SELECT value FROM meta WHERE key='telegram_update_offset'").fetchone()
            )
        try:
            return int(row["value"]) if row else 0
        except (TypeError, ValueError):
            return 0

    def _save_offset(self, update_id: int, user_id: str | None = None, token_hash: str | None = None) -> None:
        with self.database() as db:
            if user_id is not None:
                db.execute(
                    "UPDATE telegram_bots SET update_offset=MAX(update_offset,?) "
                    "WHERE user_id=? AND token_hash=?",
                    (update_id + 1, user_id, token_hash),
                )
                return
            db.execute(
                "INSERT INTO meta(key,value) VALUES('telegram_update_offset',?) "
                # Overlapping pollers can finish out of order during a rolling
                # restart. Never let an older response move the durable cursor
                # backwards and replay already handled updates.
                "ON CONFLICT(key) DO UPDATE SET value=CAST(MAX("
                "CAST(meta.value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",
                (str(update_id + 1),),
            )

    async def _poll_loop(self) -> None:
        delay = 1
        while True:
            try:
                if not self.webhook_cleared:
                    await self._api("deleteWebhook", {"drop_pending_updates": False})
                    self.webhook_cleared = True
                body = await self._api(
                    "getUpdates",
                    {"offset": self._offset(), "timeout": 20, "allowed_updates": ["message"]},
                )
                for update in body.get("result", []):
                    if isinstance(update, dict):
                        await self.handle_update(update)
                delay = 1
            except asyncio.CancelledError:
                raise
            except (TelegramAPIError, sqlite3.Error, OSError, TimeoutError, KeyError, TypeError):
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    async def _reconcile_bots_loop(self) -> None:
        while True:
            try:
                with self.database() as db:
                    bots = db.execute(
                        "SELECT b.user_id,b.token_hash FROM telegram_bots b "
                        "JOIN users u ON u.id=b.user_id AND u.active=1"
                    ).fetchall()
                active = {row["user_id"]: row["token_hash"] for row in bots}
                for user_id, task in list(self.bot_poll_tasks.items()):
                    if task.done() or active.get(user_id) != self.bot_poll_hashes.get(user_id):
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                        self.bot_poll_tasks.pop(user_id, None)
                        self.bot_poll_hashes.pop(user_id, None)
                for user_id, digest in active.items():
                    if user_id in self.bot_poll_tasks:
                        continue
                    token = self._token_for(user_id)
                    if token is None:
                        continue
                    self.bot_poll_hashes[user_id] = digest
                    self.bot_poll_tasks[user_id] = asyncio.create_task(
                        self._poll_bot(user_id, token, digest), name=f"telegram-poll-{user_id[:8]}"
                    )
            except asyncio.CancelledError:
                raise
            except (sqlite3.Error, OSError, RuntimeError):
                pass
            await asyncio.sleep(2)

    async def _poll_bot(self, user_id: str, token: str, digest: str) -> None:
        lock_name = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
        lease = ProcessFileLock(self.poll_lock_root / f"user-{lock_name}.lock")
        delay = 1
        while not lease.try_acquire():
            await asyncio.sleep(2)
        try:
            webhook_cleared = False
            while True:
                try:
                    if not webhook_cleared:
                        await self._api("deleteWebhook", {"drop_pending_updates": False}, token=token)
                        webhook_cleared = True
                    body = await self._api(
                        "getUpdates",
                        {"offset": self._offset(user_id), "timeout": 20, "allowed_updates": ["message"]},
                        token=token,
                    )
                    for update in body.get("result", []):
                        if isinstance(update, dict):
                            await self.handle_update(
                                update, bot_user_id=user_id, bot_token=token, token_hash=digest
                            )
                    delay = 1
                except asyncio.CancelledError:
                    raise
                except (TelegramAPIError, sqlite3.Error, OSError, TimeoutError, KeyError, TypeError):
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30)
        finally:
            lease.release()

    async def handle_update(
        self, update: dict[str, Any], *, bot_user_id: str | None = None,
        bot_token: str | None = None, token_hash: str | None = None,
    ) -> None:
        update_id = update.get("update_id")
        try:
            if bot_user_id is not None:
                row = self._bot_row(bot_user_id)
                if row is None or row["token_hash"] != token_hash:
                    return
            message = update.get("message") or {}
            chat = message.get("chat") or {}
            text = message.get("text")
            chat_id = chat.get("id")
            if not isinstance(text, str) or not isinstance(chat_id, int) or chat.get("type") != "private":
                return
            pieces = text.strip().split(maxsplit=1)
            command = pieces[0].split("@", 1)[0].lower() if pieces else ""
            if command != "/start":
                return
            async def respond(value: str) -> None:
                if bot_token is None:
                    await self._safe_message(chat_id, value)
                else:
                    await self._safe_message(chat_id, value, bot_token)
            if len(pieces) != 2 or not START_TOKEN.fullmatch(pieces[1]):
                await respond("웹사이트 설정에서 Telegram 연결 링크를 새로 발급해 주세요.")
                return
            try:
                link_owner = self._link_owner(pieces[1], bot_user_id)
                if link_owner is None:
                    result = "expired"
                else:
                    async with self.delivery_boundary(link_owner):
                        result = self._consume_link(pieces[1], chat_id, bot_user_id)
            except (OSError, TimeoutError):
                await respond("연결 처리가 지연되고 있습니다. 잠시 후 같은 링크로 다시 시도해 주세요.")
                return
            messages = {
                "linked": "Telegram 연결을 확인했습니다. 웹사이트 설정에서 알림을 켜 주세요.",
                "expired": "연결 링크가 만료되었거나 이미 사용되었습니다. 웹사이트에서 새 링크를 발급해 주세요.",
                "chat_in_use": "이 Telegram 대화는 이미 다른 사용자에게 연결되어 있습니다.",
            }
            await respond(messages[result])
        finally:
            if isinstance(update_id, int) and update_id >= 0:
                self._save_offset(update_id, bot_user_id, token_hash)

    def _consume_link(self, token: str, chat_id: int, bot_user_id: str | None = None) -> str:
        digest, timestamp = hashlib.sha256(token.encode()).hexdigest(), int(time.time())
        try:
            with self.database() as db:
                db.execute("BEGIN IMMEDIATE")
                link = db.execute(
                        """SELECT t.user_id FROM telegram_link_tokens t
                           JOIN users u ON u.id=t.user_id
                           WHERE t.token_hash=? AND t.used_at IS NULL AND t.expires_at>=? AND u.active=1""",
                        (digest, timestamp),
                    ).fetchone()
                if not link:
                    return "expired"
                if bot_user_id is not None and link["user_id"] != bot_user_id:
                    return "expired"
                used = db.execute(
                        "SELECT user_id FROM telegram_settings WHERE chat_id=? AND user_id!=?",
                        (chat_id, link["user_id"]),
                    ).fetchone() if bot_user_id is None else None
                if used:
                    return "chat_in_use"
                db.execute(
                        """INSERT INTO telegram_settings(user_id,chat_id,enabled,linked_at)
                           VALUES(?,?,0,?) ON CONFLICT(user_id) DO UPDATE SET
                           chat_id=excluded.chat_id,enabled=0,linked_at=excluded.linked_at,
                           last_failure_at=NULL,last_failure_code=NULL""",
                        (link["user_id"], chat_id, utc_stamp(timestamp)),
                    )
                db.execute(
                        "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                        "WHERE user_id=? AND status IN ('pending','processing','failed')",
                        (link["user_id"],),
                    )
                if db.execute(
                        "UPDATE telegram_link_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                        (timestamp, digest),
                ).rowcount != 1:
                    raise sqlite3.IntegrityError("link was concurrently consumed")
            return "linked"
        except sqlite3.IntegrityError:
            return "expired"

    def _link_owner(self, token: str, bot_user_id: str | None = None) -> str | None:
        digest, timestamp = hashlib.sha256(token.encode()).hexdigest(), int(time.time())
        with self.database() as db:
            row = db.execute(
                """SELECT t.user_id FROM telegram_link_tokens t
                   JOIN users u ON u.id=t.user_id
                   WHERE t.token_hash=? AND t.used_at IS NULL AND t.expires_at>=? AND u.active=1""",
                (digest, timestamp),
            ).fetchone()
        return row["user_id"] if row and (bot_user_id is None or row["user_id"] == bot_user_id) else None

    async def _safe_message(self, chat_id: int, text: str, token: str | None = None) -> None:
        try:
            if token is None:
                await self._api("sendMessage", {"chat_id": chat_id, "text": text})
            else:
                await self._api("sendMessage", {"chat_id": chat_id, "text": text}, token=token)
        except TelegramAPIError:
            pass

    @staticmethod
    def _job_row(db: sqlite3.Connection, row: dict[str, Any]) -> sqlite3.Row | None:
        job_id = row.get("job_id")
        if not isinstance(job_id, str):
            return None
        return db.execute(
            """SELECT j.id,j.owner_user_id,j.workspace_id,j.challenge_id,j.provider,j.model,
                      j.reasoning_effort,j.service_tier,j.status,j.error_json,j.cancel_requested,
                      j.released_ingested,j.flag,j.writeup_markdown,j.created_at,j.updated_at,
                      j.released_at,c.status AS challenge_status,
                      c.completion_source AS challenge_completion_source
                 FROM solver_jobs j
                 JOIN workspaces w ON w.id=j.workspace_id AND w.owner_user_id=j.owner_user_id
                 JOIN challenges c ON c.id=j.challenge_id AND c.workspace_id=j.workspace_id
                WHERE j.id=? AND j.owner_user_id=? AND j.workspace_id=? AND j.challenge_id=?""",
            (job_id, row["user_id"], row["workspace_id"], row["challenge_id"]),
        ).fetchone()

    @staticmethod
    def _job_context(
        db: sqlite3.Connection,
        job: sqlite3.Row,
        target_kind: str | None,
    ) -> dict[str, Any]:
        running_at = None
        for event in db.execute(
            "SELECT event_json,created_at FROM solver_job_events "
            "WHERE job_id=? AND kind='status' ORDER BY sequence",
            (job["id"],),
        ).fetchall():
            try:
                value = json.loads(event["event_json"]) if len(event["event_json"]) <= 4096 else None
            except (ValueError, TypeError):
                value = None
            if isinstance(value, dict) and value.get("status") == "running":
                running_at = event["created_at"]
                break
        target_at = None
        if target_kind is not None:
            target = db.execute(
                "SELECT created_at FROM solver_job_events WHERE job_id=? AND kind=? "
                "ORDER BY sequence DESC LIMIT 1",
                (job["id"], target_kind),
            ).fetchone()
            target_at = target["created_at"] if target else None
        if target_at is None:
            target_at = job["released_at"] if job["released_at"] is not None else job["updated_at"]
        start_at = running_at if running_at is not None else job["created_at"]
        elapsed = None
        if isinstance(start_at, (int, float)) and isinstance(target_at, (int, float)):
            elapsed = max(0, min(int(target_at - start_at), 31_536_000))
        provider = {"codex": "Codex", "claude": "Claude Code"}.get(job["provider"])
        model = job["model"] if isinstance(job["model"], str) and _SAFE_JOB_SETTING.fullmatch(job["model"]) else None
        effort = (
            job["reasoning_effort"]
            if isinstance(job["reasoning_effort"], str)
            and _SAFE_JOB_SETTING.fullmatch(job["reasoning_effort"])
            else None
        )
        tier = job["service_tier"]
        return {
            "solver_provider": provider,
            "solver_model": model,
            "solver_effort": effort,
            "solver_fast": tier == "fast",
            "solver_elapsed": elapsed,
            "solver_elapsed_includes_queue": running_at is None,
        }

    def _current_delivery(
        self,
        db: sqlite3.Connection,
        row: dict[str, Any],
    ) -> dict[str, Any] | None:
        event_type = row.get("event_type")
        if event_type == "solver_alert":
            job = self._job_row(db, row)
            if (
                job is None
                or job["status"] not in _SOLVER_ALERT_STATUSES
                or not job["released_ingested"]
                or (
                    job["cancel_requested"]
                    and self._solver_alert_code(job["error_json"], job["status"])
                    not in _SYSTEM_CANCEL_ALERT_CODES
                )
                or (
                    job["challenge_status"] == "solved"
                    and job["challenge_completion_source"] == "manual"
                )
            ):
                return None
            newer = db.execute(
                """SELECT 1 FROM solver_jobs
                    WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                      AND (created_at>? OR (created_at=? AND id>?)) LIMIT 1""",
                (
                    job["owner_user_id"],
                    job["workspace_id"],
                    job["challenge_id"],
                    job["created_at"],
                    job["created_at"],
                    job["id"],
                ),
            ).fetchone()
            code = self._solver_alert_code(job["error_json"], job["status"])
            expected = self._solver_alert_key(job["id"], job["status"])
            if newer or not secrets.compare_digest(row["event_key"], expected):
                return None
            current = dict(row)
            current.update(self._job_context(db, job, "released"))
            current["solver_status"] = job["status"]
            current["solver_error_code"] = code
            return current

        if event_type not in {"flag_found", "writeup_ready"}:
            return None
        value = row["flag"] if event_type == "flag_found" else row["writeup_markdown"]
        prefix = "flag" if event_type == "flag_found" else "writeup"
        expected = (
            f"{prefix}:{row['challenge_id']}:"
            f"{hashlib.sha256((value or '').encode('utf-8')).hexdigest()}"
        )
        if not isinstance(value, str) or not value or not secrets.compare_digest(row["event_key"], expected):
            return None
        current = dict(row)
        if row.get("job_id") is None:
            return current
        job = self._job_row(db, row)
        job_value = None if job is None else job["flag" if event_type == "flag_found" else "writeup_markdown"]
        if (
            not isinstance(job_value, str)
            or not secrets.compare_digest(
                hashlib.sha256(job_value.encode("utf-8")).digest(),
                hashlib.sha256(value.encode("utf-8")).digest(),
            )
        ):
            return None
        current.update(self._job_context(db, job, "flag" if event_type == "flag_found" else "writeup"))
        return current

    def _claim(self) -> dict[str, Any] | None:
        timestamp = int(time.time())
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            # A terminated worker may leave a claim behind. Make it retryable.
            db.execute(
                "UPDATE notification_outbox SET status='pending' "
                "WHERE status='processing' AND claimed_at<?",
                (timestamp - 120,),
            )
            while True:
                row = db.execute(
                    """SELECT o.*,s.chat_id,s.enabled,u.active,w.name AS workspace_name,
                              c.name AS challenge_name,c.flag,
                              cw.markdown AS writeup_markdown
                       FROM notification_outbox o
                       JOIN telegram_settings s ON s.user_id=o.user_id
                       JOIN users u ON u.id=o.user_id
                       JOIN workspaces w ON w.id=o.workspace_id AND w.owner_user_id=o.user_id
                       JOIN challenges c ON c.id=o.challenge_id AND c.workspace_id=o.workspace_id
                       LEFT JOIN challenge_writeups cw ON cw.challenge_id=c.id
                        WHERE o.status='pending' AND o.next_attempt_at<=?
                          AND (o.event_type NOT IN ('writeup_ready','solver_alert') OR NOT EXISTS (
                              SELECT 1 FROM notification_outbox f
                              WHERE f.user_id=o.user_id AND f.challenge_id=o.challenge_id
                                AND f.event_type='flag_found' AND f.status IN ('pending','processing','failed')
                          ))
                        ORDER BY o.priority,o.created_at,o.id LIMIT 1""",
                    (timestamp,),
                ).fetchone()
                if not row:
                    return None
                if not row["active"] or not row["enabled"] or row["chat_id"] is None:
                    db.execute("UPDATE notification_outbox SET status='cancelled' WHERE id=?", (row["id"],))
                    continue

                # The outbox keeps only content digests and an optional job
                # identity.  Re-read every mutable value under this claim
                # transaction so stale results and superseded failures cannot
                # be sent.
                current = self._current_delivery(db, dict(row))
                if current is None:
                    db.execute("UPDATE notification_outbox SET status='cancelled' WHERE id=?", (row["id"],))
                    continue
                changed = db.execute(
                    "UPDATE notification_outbox SET status='processing',claimed_at=? WHERE id=? AND status='pending'",
                    (timestamp, row["id"]),
                ).rowcount
                return current if changed == 1 else None

    @staticmethod
    def _elapsed_text(seconds: Any) -> str:
        if not isinstance(seconds, int) or seconds < 0:
            return "확인 불가"
        if seconds < 60:
            return f"{seconds}초"
        minutes, remaining = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes}분 {remaining}초" if remaining else f"{minutes}분"
        hours, minutes = divmod(minutes, 60)
        return f"{hours}시간 {minutes}분" if minutes else f"{hours}시간"

    def _job_context_text(self, row: dict[str, Any]) -> str:
        if row.get("solver_provider") is None:
            return ""
        provider = html.escape(telegram_text(row["solver_provider"]))
        model = html.escape(telegram_text(row.get("solver_model") or "확인 불가"))
        effort = html.escape(telegram_text(row.get("solver_effort") or "확인 불가"))
        tier = "Fast (1.5배)" if row.get("solver_fast") else "기본"
        elapsed_label = "대기 포함 소요 시간" if row.get("solver_elapsed_includes_queue") else "풀이 시간"
        elapsed = html.escape(self._elapsed_text(row.get("solver_elapsed")))
        return (
            f"\n실행: {provider} · {model}"
            f"\n추론: {effort} · 서비스 티어: {tier}"
            f"\n{elapsed_label}: {elapsed}"
        )

    def _notification(self, row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        origin = self.settings.public_origin.rstrip("/") if self.settings.public_origin else ""
        problem_url = f"{origin}/#w/{row['workspace_id']}/c/{row['challenge_id']}" if origin else ""
        writeup_download_url = (
            f"{origin}/api/workspaces/{row['workspace_id']}/challenges/"
            f"{row['challenge_id']}/writeup/download"
            if origin else ""
        )
        context = self._job_context_text(row)
        if row["event_type"] == "flag_found":
            flag = row["flag"] or "(현재 Flag 값이 비어 있습니다)"
            clean_flag = telegram_text(flag)
            display_flag = clean_flag if len(clean_flag) <= 3200 else clean_flag[:3200] + "…\n(전체 Flag는 웹에서 확인하세요.)"
            text = (
                f"🚩 <b>Flag 발견</b>\n작업공간: {html.escape(telegram_text(row['workspace_name']))}\n"
                f"문제: {html.escape(telegram_text(row['challenge_name']))}\n발견: {html.escape(telegram_text(row['created_at']))}"
                f"{context}\n\n"
                f"<code>{html.escape(display_flag)}</code>"
            )
            buttons: list[list[dict[str, Any]]] = []
            if row["flag"] and clean_flag == row["flag"] and len(row["flag"]) <= 256:
                buttons.append([{"text": "Flag 복사", "copy_text": {"text": row["flag"]}}])
            if problem_url:
                buttons.append([{"text": "문제 열기", "url": problem_url}])
        elif row["event_type"] == "writeup_ready":
            markdown = row.get("writeup_markdown")
            clean_markdown = telegram_text(markdown or "")
            exact_copy_available = bool(
                isinstance(markdown, str)
                and markdown
                and clean_markdown == markdown
                and len(markdown) <= _COPY_TEXT_MAX_CHARACTERS
            )
            text = (
                f"📝 <b>Write-up 완성</b>\n작업공간: {html.escape(telegram_text(row['workspace_name']))}\n"
                f"문제: {html.escape(telegram_text(row['challenge_name']))}\n완성: {html.escape(telegram_text(row['created_at']))}"
                f"{context}"
            )
            buttons = []
            if exact_copy_available:
                # Bot API CopyTextButton.text accepts 1-256 characters.  Pass
                # the artifact unchanged so this control never copies a URL or
                # a sanitized approximation of the Markdown.
                buttons.append([{
                    "text": "Write-up 복사",
                    "copy_text": {"text": markdown},
                }])
            if problem_url:
                buttons.append([
                    {"text": "MD 다운로드", "url": writeup_download_url},
                    {"text": "Write-up 보기·복사", "url": problem_url},
                ])
        else:
            status = row.get("solver_status")
            title = {
                "needs_input": "추가 입력 필요",
                "refused": "풀이 실행 거부",
                "failed": "풀이 실패",
            }.get(status, "풀이 상태 확인 필요")
            code = row.get("solver_error_code")
            reason = _SOLVER_ALERT_REASONS.get(code, _SOLVER_ALERT_FALLBACK.get(status, "문제 화면에서 상태를 확인하세요."))
            text = (
                f"⚠️ <b>{title}</b>\n작업공간: {html.escape(telegram_text(row['workspace_name']))}\n"
                f"문제: {html.escape(telegram_text(row['challenge_name']))}\n"
                f"안내: {html.escape(reason)}"
                f"{context}"
            )
            buttons = []
            if problem_url:
                buttons.append([{"text": "문제 확인", "url": problem_url}])
        payload: dict[str, Any] = {
            "chat_id": row["chat_id"], "text": text, "parse_mode": "HTML",
            "link_preview_options": {"is_disabled": True},
        }
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        return "sendMessage", payload

    def _sent(self, row: dict[str, Any]) -> None:
        timestamp = utc_stamp()
        with self.database() as db:
            changed = db.execute(
                "UPDATE notification_outbox SET status='sent',sent_at=?,claimed_at=NULL "
                "WHERE id=? AND status='processing'",
                (timestamp, row["id"]),
            ).rowcount
            if changed:
                db.execute(
                    "UPDATE telegram_settings SET last_success_at=?,last_failure_at=NULL,last_failure_code=NULL WHERE user_id=?",
                    (timestamp, row["user_id"]),
                )

    def _failed(self, row: dict[str, Any], code: str) -> None:
        attempts = int(row["attempts"]) + 1
        timestamp = int(time.time())
        # A flag alert is never discarded simply because Telegram was
        # temporarily unavailable. OFF/unlink explicitly cancels it; otherwise
        # retries continue at a capped interval so a write-up cannot overtake it.
        status = "pending"
        next_attempt = timestamp + min(2 ** attempts, 900)
        with self.database() as db:
            changed = db.execute(
                """UPDATE notification_outbox SET status=?,attempts=?,next_attempt_at=?,
                   claimed_at=NULL,last_error_code=? WHERE id=? AND status='processing'""",
                (status, attempts, next_attempt, code[:80], row["id"]),
            ).rowcount
            if changed:
                db.execute(
                    "UPDATE telegram_settings SET last_failure_at=?,last_failure_code=? WHERE user_id=?",
                    (utc_stamp(timestamp), code[:80], row["user_id"]),
                )

    def _revalidate_delivery(self, row: dict[str, Any]) -> dict[str, Any] | None:
        """Reload the claim immediately before sending while settings are locked."""
        with self.database() as db:
            current = db.execute(
                """SELECT o.*,s.chat_id,s.enabled,u.active,w.name AS workspace_name,
                          c.name AS challenge_name,c.flag,
                          cw.markdown AS writeup_markdown
                   FROM notification_outbox o
                   JOIN telegram_settings s ON s.user_id=o.user_id
                   JOIN users u ON u.id=o.user_id
                   JOIN workspaces w ON w.id=o.workspace_id AND w.owner_user_id=o.user_id
                   JOIN challenges c ON c.id=o.challenge_id AND c.workspace_id=o.workspace_id
                   LEFT JOIN challenge_writeups cw ON cw.challenge_id=c.id
                   WHERE o.id=? AND o.status='processing'""",
                (row["id"],),
            ).fetchone()
            if (not current or not current["active"] or not current["enabled"]
                    or current["chat_id"] is None or current["chat_id"] != row["chat_id"]):
                if current:
                    db.execute(
                        "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                        "WHERE id=? AND status='processing'",
                        (row["id"],),
                    )
                return None
            delivery = self._current_delivery(db, dict(current))
            if delivery is None:
                db.execute(
                    "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
                    "WHERE id=? AND status='processing'",
                    (row["id"],),
                )
                return None
            return delivery

    async def _outbox_loop(self) -> None:
        while True:
            try:
                row = self._claim()
                if not row:
                    if not self.wakeup:
                        await asyncio.sleep(1)
                    else:
                        self.wakeup.clear()
                        try:
                            await asyncio.wait_for(self.wakeup.wait(), timeout=1)
                        except TimeoutError:
                            pass
                    continue
                # Holding this process-wide lock across the bounded API call
                # gives OFF/unlink a clear boundary: if either operation has
                # returned, an old chat/flag delivery cannot happen afterwards.
                try:
                    async with self.delivery_boundary(row["user_id"]):
                        current = self._revalidate_delivery(row)
                        if current is None:
                            continue
                        method, payload = self._notification(current)
                        try:
                            if self.token:
                                await self._api(method, payload)
                            else:
                                token = self._token_for(row["user_id"])
                                if token is None:
                                    raise TelegramAPIError("bot_not_configured")
                                await self._api(method, payload, token=token)
                        except TelegramAPIError as exc:
                            self._failed(current, exc.code)
                        else:
                            self._sent(current)
                except TimeoutError:
                    self._failed(row, "delivery_busy")
            except asyncio.CancelledError:
                raise
            except (sqlite3.Error, OSError, KeyError, TypeError):
                await asyncio.sleep(1)


def register_telegram(app, require_auth, settings, database):
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS telegram_link_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_telegram_tokens_user
                ON telegram_link_tokens(user_id,expires_at);
            CREATE TABLE IF NOT EXISTS telegram_settings (
                user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                chat_id INTEGER,
                enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
                linked_at TEXT,
                last_success_at TEXT,
                last_failure_at TEXT,
                last_failure_code TEXT
            );
            CREATE TABLE IF NOT EXISTS telegram_bots (
                user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                token_ciphertext TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                bot_id INTEGER NOT NULL UNIQUE,
                bot_username TEXT NOT NULL,
                update_offset INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            """
        )
        definition = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='telegram_settings'"
        ).fetchone()[0]
        if "chat_id INTEGER UNIQUE" in definition:
            db.executescript(
                """ALTER TABLE telegram_settings RENAME TO telegram_settings_legacy;
                   CREATE TABLE telegram_settings (
                       user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                       chat_id INTEGER,enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
                       linked_at TEXT,last_success_at TEXT,last_failure_at TEXT,last_failure_code TEXT
                   );
                   INSERT INTO telegram_settings SELECT * FROM telegram_settings_legacy;
                   DROP TABLE telegram_settings_legacy;"""
            )
        _ensure_notification_outbox(db)
        # This deployment boundary prevents the newly introduced scanner from
        # replaying historical failures.  A job that terminates after the
        # boundary is still recovered after a process restart.
        db.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES('telegram_solver_alerts_started_at',?)",
            (str(time.time()),),
        )
        # Older releases stopped after ten transport failures. Resume those
        # durable alerts so a flag cannot be lost or overtaken by its write-up.
        db.execute(
            "UPDATE notification_outbox SET status='pending',next_attempt_at=?,claimed_at=NULL "
            "WHERE status='failed'",
            (int(time.time()),),
        )
        # The old installation-wide bot is not assigned to any user. Existing
        # chats must be reverified against each owner's newly registered bot.
        db.execute(
            "UPDATE telegram_settings SET chat_id=NULL,enabled=0,linked_at=NULL "
            "WHERE user_id NOT IN (SELECT user_id FROM telegram_bots)"
        )
        db.execute(
            "UPDATE notification_outbox SET status='cancelled',claimed_at=NULL "
            "WHERE user_id NOT IN (SELECT user_id FROM telegram_bots) "
            "AND status IN ('pending','processing','failed')"
        )

    service = TelegramService(database, settings, "")
    app.state.telegram = service
    app.state.telegram_user_summary = service.admin_summary

    def safe_flag_event(*args) -> bool:
        try:
            service.enqueue_flag(*args)
            # Disabled notifications and a deduplicated existing event are
            # successful no-ops. False is reserved for a transient enqueue
            # failure so a durable solver hook can retry it.
            return True
        except sqlite3.Error:
            return False

    def safe_writeup_event(*args) -> bool:
        try:
            service.enqueue_writeup(*args)
            return True
        except sqlite3.Error:
            return False

    def safe_solver_alerts() -> bool:
        try:
            return service.enqueue_solver_alerts()
        except sqlite3.Error:
            return False

    app.state.telegram_flag_found = safe_flag_event
    app.state.telegram_writeup_ready = safe_writeup_event
    app.state.telegram_solver_alerts = safe_solver_alerts

    app.router.add_event_handler("startup", service.start)
    app.router.add_event_handler("shutdown", service.stop)

    @app.get("/api/telegram", dependencies=[Depends(require_auth)])
    def telegram_settings(request: Request):
        return service.settings_for(request.state.user["id"])

    @app.put("/api/telegram/bot", dependencies=[Depends(require_auth)])
    async def save_telegram_bot(payload: TelegramBotInput, request: Request):
        return await service.save_bot(request.state.user["id"], payload.token)

    @app.delete("/api/telegram/bot", dependencies=[Depends(require_auth)])
    async def delete_telegram_bot(request: Request):
        return await service.delete_bot(request.state.user["id"])

    @app.post("/api/telegram/link", dependencies=[Depends(require_auth)])
    def create_telegram_link(request: Request):
        return service.issue_link(request.state.user["id"])

    @app.patch("/api/telegram", dependencies=[Depends(require_auth)])
    async def toggle_telegram(payload: TelegramToggle, request: Request):
        return await service.set_enabled_serialized(request.state.user["id"], payload.enabled)

    @app.delete("/api/telegram", dependencies=[Depends(require_auth)])
    async def unlink_telegram(request: Request):
        return await service.unlink_serialized(request.state.user["id"])

    return service
