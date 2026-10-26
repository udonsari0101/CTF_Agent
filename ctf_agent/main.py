"""Authenticated web application for managing CTF workspaces and original files."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import stat
import time
import tempfile
import unicodedata
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from logging.handlers import RotatingFileHandler

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AliasChoices, BaseModel, Field, field_validator

from .ctfd import connection_info
from .db import Settings, connect, initialize
from .flag_formats import normalize_flag_format
from .password_policy import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH
from .writeups import merge_generated_writeup, remove_generated_writeup

CURRENT_USER = ContextVar("ctf_current_user", default=None)
COOKIE = "ctf_session"
STATUSES = ("pending", "running", "stopped", "failed", "flag_found", "solved")
REMOTE_MODES = ("unknown", "none", "endpoint")
CLONE_COPY_CHUNK_BYTES = 8 * 1024 * 1024


class ChallengeCloneSourceChanged(RuntimeError):
    """The source attachment stopped being a stable regular-file snapshot."""


def clone_challenge_name(connection, workspace_id: str, source_name: str) -> str:
    """Allocate a short, readable copy name within one workspace."""

    occupied = {
        unicodedata.normalize("NFKC", row[0]).casefold()
        for row in connection.execute(
            "SELECT name FROM challenges WHERE workspace_id=?", (workspace_id,)
        )
    }
    copy_number = 1
    while True:
        suffix = " 복사본" if copy_number == 1 else f" 복사본 ({copy_number})"
        candidate = source_name[: 200 - len(suffix)].rstrip() + suffix
        if unicodedata.normalize("NFKC", candidate).casefold() not in occupied:
            return candidate
        copy_number += 1


def copy_regular_snapshot(source: Path, target: Path, expected_size: int) -> None:
    """Copy one attachment while rejecting symlinks and concurrent mutation."""

    source_flags = os.O_RDONLY
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        target_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    target_descriptor = None
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise ChallengeCloneSourceChanged
        target_descriptor = os.open(target, target_flags, 0o640)
        with os.fdopen(source_descriptor, "rb", closefd=False) as input_file, os.fdopen(
            target_descriptor, "wb", closefd=False
        ) as output_file:
            remaining = expected_size
            while remaining:
                chunk = input_file.read(min(CLONE_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise ChallengeCloneSourceChanged
                output_file.write(chunk)
                remaining -= len(chunk)
            if input_file.read(1):
                raise ChallengeCloneSourceChanged
            output_file.flush()
            os.fsync(output_file.fileno())
        after = os.fstat(source_descriptor)
        fingerprint = lambda details: (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(after):
            raise ChallengeCloneSourceChanged
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)
        os.close(source_descriptor)


def _legacy_attachment_post(scope) -> bool:
    return (
        scope.get("method") == "POST"
        and re.fullmatch(
            r"/api/workspaces/[^/]+/challenges/[^/]+/attachments",
            scope.get("path", ""),
        ) is not None
    )
WEB_DIR = Path(__file__).parent / "web"


class BodySizeLimit:
    """Bound request memory/tmp use before JSON or raw-chunk parsing."""

    def __init__(self, app, max_bytes: int, chunk_bytes: int = 8 * 1024 * 1024,
                 concurrent_bodies: int = 16, concurrent_chunks: int = 4,
                 authorize=None):
        self.app = app
        self.max_bytes = max_bytes
        self.chunk_bytes = chunk_bytes
        self.authorize = authorize
        self.body_gate = asyncio.Semaphore(concurrent_bodies)
        self.chunk_gate = asyncio.Semaphore(concurrent_chunks)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # This retired endpoint has no body parameter, so return its 410 without
        # reading or spooling a potentially huge legacy multipart request.
        if _legacy_attachment_post(scope):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length", b"")
        chunk_request = scope.get("path", "").startswith("/api/uploads/") and scope.get("path", "").endswith("/chunks")
        max_bytes = self.chunk_bytes if chunk_request else self.max_bytes

        async def reject(status=413, detail="요청 본문이 너무 큽니다."):
            response = JSONResponse({"detail": detail}, status_code=status,
                                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
            await response(scope, receive, send)

        if declared.isdigit() and int(declared) > max_bytes:
            return await reject()
        if scope.get("method") in {"GET", "HEAD", "OPTIONS"}:
            return await self.app(scope, receive, send)

        if self.authorize is not None:
            refused = self.authorize(scope)
            if refused is not None:
                status, detail = refused
                return await reject(status, detail)
        gate = self.chunk_gate if chunk_request else self.body_gate
        try:
            await asyncio.wait_for(gate.acquire(), timeout=2)
        except TimeoutError:
            return await reject(429, "동시에 처리 중인 업로드가 많습니다. 잠시 후 다시 시도하세요.")
        try:
            # Rejection happens before FastAPI parsing. Four concurrent 8 MiB
            # chunks bound both the tmpfs spool and the later bytes objects.
            with tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b") as buffer:
                received = 0
                deadline = asyncio.get_running_loop().time() + (180 if chunk_request else 30)
                while True:
                    try:
                        remaining = deadline - asyncio.get_running_loop().time()
                        if remaining <= 0:
                            return await reject(408, "Request upload timed out.")
                        message = await asyncio.wait_for(receive(), timeout=min(30, remaining))
                    except TimeoutError:
                        return await reject(408, "요청 전송 시간이 초과되었습니다.")
                    if message["type"] == "http.disconnect":
                        return
                    part = message.get("body", b"")
                    received += len(part)
                    if received > max_bytes:
                        return await reject()
                    buffer.write(part)
                    if not message.get("more_body", False):
                        break
                buffer.seek(0)
                replayed = False

                async def replay_receive():
                    nonlocal replayed
                    if replayed:
                        return await receive()
                    part = buffer.read(64 * 1024)
                    more_body = buffer.tell() < received
                    replayed = not more_body
                    return {"type": "http.request", "body": part, "more_body": more_body}

                await self.app(scope, replay_receive, send)
        finally:
            gate.release()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def validate_filename(filename: str | None) -> str:
    filename = unicodedata.normalize("NFC", filename or "")
    if (
        not filename or filename in (".", "..") or len(filename) > 240
        or any(c in filename for c in '/\\\x00')
        or any(unicodedata.category(c).startswith("C") for c in filename)
    ):
        raise HTTPException(400, "파일 이름에 경로나 제어 문자를 사용할 수 없습니다.")
    return filename


def export_filename(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")[:100] or "challenge"
    return f"{name}-notes.md"


def writeup_filename(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")[:100] or "challenge"
    return f"{name}-writeup.md"


class LoginInput(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        value = value.strip()
        if not value or any(unicodedata.category(char).startswith("C") for char in value):
            raise ValueError("사용할 수 있는 아이디를 입력하세요.")
        return value


class PasswordInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH,
    )


class UsernameInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_username: str = Field(min_length=1, max_length=100)

    @field_validator("new_username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        return LoginInput.valid_username(value)


class WorkspaceInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=10_000)
    flag_format: str | None = Field(default=None, max_length=500)
    open_challenge_after_create: bool = False

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("이름을 입력하세요.")
        return value.strip()

    @field_validator("flag_format")
    @classmethod
    def canonical_flag_format(cls, value: str | None) -> str | None:
        return normalize_flag_format(value)


class ChallengeInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    category: str = Field(default="", max_length=100)
    description: str = Field(default="", max_length=100_000)
    remote: str = Field(default="", max_length=2000)
    remote_mode: str | None = Field(default=None, pattern=r"^(unknown|none|endpoint)$")
    flag: str | None = Field(default=None, max_length=4000)

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("문제 이름을 입력하세요.")
        return value.strip()

    @field_validator("remote")
    @classmethod
    def safe_remote(cls, value: str) -> str:
        normalized = connection_info(value)
        if value.strip() and not normalized:
            raise ValueError("원격 접속 정보에 허용되지 않는 제어 문자가 있습니다.")
        return normalized

    @field_validator("remote_mode")
    @classmethod
    def mode_not_null(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("빈 문자열을 사용하세요. null은 허용하지 않습니다.")
        return value


class WorkspacePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10_000)
    flag_format: str | None = Field(default=None, max_length=500)
    open_challenge_after_create: bool | None = None

    @field_validator("open_challenge_after_create")
    @classmethod
    def option_not_null(cls, value: bool | None) -> bool:
        if value is None:
            raise ValueError("켜짐 또는 꺼짐을 사용하세요. null은 허용하지 않습니다.")
        return value

    @field_validator("name", "description")
    @classmethod
    def not_null(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("빈 문자열을 사용하세요. null은 허용하지 않습니다.")
        return value

    @field_validator("name")
    @classmethod
    def nonempty(cls, value: str) -> str:
        return WorkspaceInput.nonempty_name(value)

    @field_validator("flag_format")
    @classmethod
    def canonical_flag_format(cls, value: str | None) -> str | None:
        return normalize_flag_format(value)


class ChallengePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    category: str | None = Field(default=None, max_length=100)
    description: str | None = Field(default=None, max_length=100_000)
    remote: str | None = Field(default=None, max_length=2000)
    remote_mode: str | None = Field(default=None, pattern=r"^(unknown|none|endpoint)$")
    flag: str | None = Field(default=None, max_length=4000)


    @field_validator("name", "category", "description", "remote")
    @classmethod
    def not_null(cls, value: str | None) -> str:
        return WorkspacePatch.not_null(value)

    @field_validator("name")
    @classmethod
    def nonempty(cls, value: str) -> str:
        return ChallengeInput.nonempty_name(value)

    @field_validator("remote")
    @classmethod
    def safe_remote(cls, value: str) -> str:
        return ChallengeInput.safe_remote(value)

    @field_validator("remote_mode")
    @classmethod
    def mode_not_null(cls, value: str | None) -> str:
        return WorkspacePatch.not_null(value)


class ChallengeRelationInput(BaseModel):
    related_id: str = Field(
        validation_alias=AliasChoices("related_id", "prerequisite_id"),
        pattern=r"^[0-9a-f]{32}$",
    )


def normalize_remote_pair(mode: str | None, remote: str) -> tuple[str, str]:
    """Resolve legacy remote-only requests and enforce an explicit state pair."""

    normalized = ChallengeInput.safe_remote(remote)
    selected = mode or ("endpoint" if normalized else "unknown")
    if selected not in REMOTE_MODES:
        raise HTTPException(422, "원격 접속 상태를 확인할 수 없습니다.")
    if selected == "endpoint" and not normalized:
        raise HTTPException(422, "원격 대상이 있으면 접속 정보를 입력하세요.")
    if selected != "endpoint" and normalized:
        raise HTTPException(422, "원격 대상 상태와 접속 정보가 일치하지 않습니다.")
    return selected, normalized


def edit_token(row, fields: tuple[str, ...]) -> str:
    value = [row["id"], *[row[field] for field in fields]]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False).encode("utf-8")).hexdigest()


def workspace_result(row) -> dict:
    result = dict(row)
    result["open_challenge_after_create"] = bool(
        result.get("open_challenge_after_create", 0)
    )
    result["edit_token"] = edit_token(
        row, ("name", "description", "flag_format", "open_challenge_after_create")
    )
    return result


def challenge_result(row) -> dict:
    return {**dict(row), "edit_token": edit_token(row, ("name", "category", "description", "remote_mode", "remote", "flag")),
            "notes_token": edit_token(row, ("notes",))}


def check_edit_token(expected: str | None, actual: str) -> None:
    if expected is not None and not hmac.compare_digest(expected.strip('"').encode(), actual.encode()):
        raise HTTPException(409, "다른 화면에서 내용을 변경했습니다. 입력한 내용을 복사한 뒤 최신 내용을 다시 불러와 확인하세요.")


class StatusInput(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def tracking_state(cls, value: str) -> str:
        if value not in STATUSES or value == "solved":
            raise ValueError("완료는 수동 완료 메뉴를 이용하세요.")
        return value


class NotesInput(BaseModel):
    content: str = Field(max_length=2_000_000)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    initialize(settings)

    @contextmanager
    def database():
        connection = connect(settings)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def delete_transaction(submit_jobs, workspace_id: str,
                           challenge_id: str | None = None):
        """Rollback a CTFd delete tombstone if the local delete aborts."""

        try:
            with database() as connection:
                yield connection
        except BaseException:
            if submit_jobs:
                try:
                    submit_jobs.release_delete_block(
                        workspace_id,
                        CURRENT_USER.get(),
                        challenge_id=challenge_id,
                    )
                except Exception:
                    logging.exception("Failed to release CTFd delete tombstone")
            raise

    # Bootstrap only the migrated legacy administrator when no password exists.
    with database() as db:
        legacy_id = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone()[0]
        existing = db.execute("SELECT password_hash FROM users WHERE id=?", (legacy_id,)).fetchone()
        if settings.auth_mode == "password" and existing and not existing["password_hash"]:
            bootstrap = os.environ.get("CTF_BOOTSTRAP_PASSWORD", "")
            bootstrap_file = os.environ.get("CTF_BOOTSTRAP_PASSWORD_FILE", "")
            if bootstrap_file:
                # The file format permits a final line ending. Preserve every
                # other character because passwords are compared verbatim.
                bootstrap = Path(bootstrap_file).read_text(encoding="utf-8").rstrip("\r\n")
            if bootstrap:
                if not PASSWORD_MIN_LENGTH <= len(bootstrap) <= PASSWORD_MAX_LENGTH:
                    raise RuntimeError(
                        "CTF bootstrap password must be between "
                        f"{PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters."
                    )
                encoded = password_hash(bootstrap)
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (encoded, legacy_id))
                db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('admin_password_hash',?)", (encoded,))

    app = FastAPI(title="CTF Workspace", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.connect = lambda: connect(settings)

    from .resource_usage import ResourceMonitor
    app.state.resource_monitor = ResourceMonitor()

    from .writeups import WriteupStore
    app.state.writeups = WriteupStore(database)
    from .storage_layout import StorageArtifactError, StorageLayout
    app.state.storage_layout = StorageLayout(settings, database)

    def publish_writeup_artifacts(workspace_id, challenge_id, _notes, _markdown):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            app.state.storage_layout.sync_challenge(
                db, workspace_id, challenge_id
            )

    app.state.writeups.set_artifact_writer(publish_writeup_artifacts)

    def challenge_response(db, row, *, include_writeup: bool = True) -> dict:
        result = challenge_result(row)
        result.update(
            app.state.writeups.fields(
                db, row["id"], include_markdown=include_writeup,
            )
        )
        return result

    def challenge_relations(db, workspace_id: str, challenge_id: str) -> list[dict]:
        return [dict(row) for row in db.execute(
            """SELECT c.id,c.name,c.category,c.status,c.ctfd_id,c.ctfd_url
                 FROM challenge_relations r
                 JOIN challenges c ON c.id=CASE WHEN r.prerequisite_id=?
                     THEN r.dependent_id ELSE r.prerequisite_id END
                     AND c.workspace_id=r.workspace_id
                WHERE r.workspace_id=? AND (r.prerequisite_id=? OR r.dependent_id=?)
                ORDER BY r.created_at,c.id""",
            (challenge_id, workspace_id, challenge_id, challenge_id),
        )]

    def latest_solver_summary(db, workspace_id: str, challenge_id: str) -> dict | None:
        """Return the current owner's newest safe run metadata for list cards."""

        row = db.execute(
            """SELECT id,account_label,provider,model,reasoning_effort,service_tier,
                      status,created_at,released_at
               FROM solver_jobs
               WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                 AND job_mode='solve'
               ORDER BY created_at DESC,id DESC LIMIT 1""",
            (owner_id(), workspace_id, challenge_id),
        ).fetchone()
        if not row:
            return None
        result = {
            "account_label": row["account_label"],
            "status": row["status"],
            "configuration": {
                "provider": row["provider"],
                "model": row["model"],
                "reasoning_effort": row["reasoning_effort"],
                "service_tier": row["service_tier"],
            },
        }
        if row["status"] == "completed" and isinstance(
            row["released_at"], (int, float)
        ):
            running_at = None
            flag_at = None
            for event in db.execute(
                """SELECT kind,event_json,created_at
                     FROM solver_job_events
                     WHERE job_id=? AND kind IN ('status','flag')
                     ORDER BY sequence""",
                (row["id"],),
            ):
                if event["kind"] == "flag":
                    flag_at = event["created_at"]
                    continue
                if running_at is not None:
                    continue
                try:
                    payload = json.loads(event["event_json"])
                except (TypeError, ValueError):
                    continue
                if isinstance(payload, dict) and payload.get("status") == "running":
                    running_at = event["created_at"]
            started_at = running_at if running_at is not None else row["created_at"]
            finished_at = flag_at if flag_at is not None else row["released_at"]
            if isinstance(started_at, (int, float)) and isinstance(
                finished_at, (int, float)
            ):
                result["elapsed_seconds"] = max(
                    0, min(int(finished_at - started_at), 31_536_000)
                )
                result["elapsed_includes_queue"] = running_at is None
        return result

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        # Pydantic's default error response includes the original input, which can
        # contain passwords, provider codes or access tokens.
        return JSONResponse({"detail": [
            {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]}, status_code=422)

    audit_log = logging.getLogger(f"ctf_workspace.{uuid.uuid4().hex}")
    audit_log.setLevel(logging.INFO)
    audit_log.propagate = False
    log_handler = RotatingFileHandler(settings.log_dir / "web.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    audit_log.addHandler(log_handler)

    def close_log():
        audit_log.removeHandler(log_handler)
        log_handler.close()

    app.router.add_event_handler("shutdown", close_log)

    from .auth import register_auth
    require_auth, require_admin = register_auth(app, settings, database, password_hash, password_matches, CURRENT_USER)

    from .release_updates import (
        REPOSITORY, control_root, invalidate_release_cache, latest_release, production_release_profile,
        queue_update, read_status, version_tuple,
    )

    def installed_release_profile() -> tuple[str, str]:
        configured = os.environ.get("CTF_RELEASE_VERSION", "")
        if version_tuple(configured):
            return configured, REPOSITORY
        profile = production_release_profile(
            control_root(settings.data_dir), os.environ.get("CTF_RELEASE_SHA", "")
        )
        return profile.get("tag", ""), profile.get("repository", REPOSITORY)

    @app.get("/api/admin/updates", dependencies=[Depends(require_admin)])
    def release_update_info(refresh: bool = False):
        current, repository = installed_release_profile()
        root = control_root(settings.data_dir)
        status = read_status(root)
        if (root / "request.json").exists():
            status = {**status, "phase": "queued"}
        helper_ready = time.time() - float(status.get("updated_at") or 0) < 20
        try:
            if refresh:
                invalidate_release_cache(repository)
            latest = latest_release() if repository == REPOSITORY else latest_release(repository)
            error = None
        except Exception:
            latest = None
            error = "최신 릴리스를 조회하지 못했습니다."
        available = bool(
            latest and version_tuple(current) and
            version_tuple(latest["tag"]) > version_tuple(current)
        )
        return {
            "current": current or "unknown", "latest": latest,
            "available": available, "helper_ready": helper_ready,
            "status": status, "error": error,
        }

    @app.post("/api/admin/updates", status_code=202, dependencies=[Depends(require_admin)])
    def begin_release_update():
        current, repository = installed_release_profile()
        if version_tuple(current) is None:
            raise HTTPException(409, "이 설치 방식에서는 웹 업데이트를 사용할 수 없습니다.")
        root = control_root(settings.data_dir)
        status = read_status(root)
        if time.time() - float(status.get("updated_at") or 0) >= 20:
            raise HTTPException(503, "업데이트 실행기를 확인할 수 없습니다.")
        if status.get("phase") in {"downloading", "verifying", "installing", "health_check", "rolling_back"}:
            raise HTTPException(409, "업데이트가 이미 진행 중입니다.")
        try:
            invalidate_release_cache(repository)
            latest = latest_release() if repository == REPOSITORY else latest_release(repository)
        except Exception:
            raise HTTPException(503, "최신 릴리스를 확인하지 못했습니다.") from None
        if version_tuple(latest["tag"]) <= version_tuple(current):
            raise HTTPException(409, "이미 최신 버전입니다.")
        try:
            request_id = queue_update(root, latest["tag"])
        except FileExistsError:
            raise HTTPException(409, "업데이트가 이미 대기 중입니다.") from None
        return {"request_id": request_id, "tag": latest["tag"], "status": "queued"}

    def owner_id():
        user = CURRENT_USER.get()
        if not user:
            raise HTTPException(401, "로그인이 필요합니다.")
        return user["id"]

    def require_workspace_owner(workspace_id: str, user: dict):
        with database() as db:
            row = db.execute("SELECT * FROM workspaces WHERE id=? AND owner_user_id=?", (workspace_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "작업공간을 찾을 수 없습니다.")
        return dict(row)

    app.state.require_workspace_owner = require_workspace_owner

    def workspace_writer_lock(function):
        @wraps(function)
        def guarded(workspace_id: str, *args, **kwargs):
            require_workspace_owner(workspace_id, CURRENT_USER.get())
            with app.state.uploads.try_workspace_lock(workspace_id):
                return function(workspace_id, *args, **kwargs)
        return guarded

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        raw_length = request.headers.get("content-length", "")
        chunk_request = request.url.path.startswith("/api/uploads/") and request.url.path.endswith("/chunks")
        request_limit = 8 * 1024 * 1024 if chunk_request else 4 * 1024 * 1024
        if (not _legacy_attachment_post(request.scope)
                and raw_length.isdigit() and int(raw_length) > request_limit):
            return JSONResponse({"detail": "업로드 허용 크기를 초과했습니다."}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            # Only route templates are recorded: no IDs, credentials, query strings or bodies.
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            # This read-only endpoint is polled every five seconds. Its owner
            # check still runs on every request; omit only repetitive log I/O.
            if route_path != "/api/workspaces/{workspace_id}/resources":
                audit_log.info("method=%s route=%s status=%s", request.method, route_path, response.status_code)
        return response

    app.add_middleware(
        BodySizeLimit,
        max_bytes=4 * 1024 * 1024,
        chunk_bytes=8 * 1024 * 1024,
        authorize=app.state.preauthorize_body_request,
    )

    @app.get("/healthz")
    def health():
        return {"status": "ok", "release": os.environ.get("CTF_RELEASE_SHA", "dev")}

    readiness_lock = asyncio.Lock()
    readiness_cache = {"expires_at": 0.0, "ready": False}

    async def refresh_readiness() -> bool:
        """Bound the write/worker probe used by public health checks."""

        try:
            # This deliberately exercises a committed write, but the five-second
            # cache below prevents an unauthenticated health-check flood from
            # turning it into sustained SQLite writer contention.
            with database() as db:
                db.execute(
                    "INSERT INTO meta(key,value) VALUES('readiness',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (now(),),
                )
            solver = getattr(app.state, "solver", None)
            if solver is None:
                return False
            solver_health = await solver.health()
            return bool(solver_health.get("ready"))
        except Exception:
            return False

    @app.get("/readyz")
    async def ready():
        monotonic_now = time.monotonic()
        if monotonic_now >= readiness_cache["expires_at"]:
            # One caller refreshes the probe. Concurrent callers wait once, then
            # consume the same short-lived result instead of repeating DB/process
            # work. The public response exposes no queue, account, or error state.
            async with readiness_lock:
                monotonic_now = time.monotonic()
                if monotonic_now >= readiness_cache["expires_at"]:
                    readiness_cache["ready"] = await refresh_readiness()
                    readiness_cache["expires_at"] = time.monotonic() + 5.0
        if not readiness_cache["ready"]:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ok"}

    def workspace_row(db, workspace_id: str):
        row = db.execute("SELECT * FROM workspaces WHERE id=? AND owner_user_id=?", (workspace_id, owner_id())).fetchone()
        if not row:
            raise HTTPException(404, "작업공간을 찾을 수 없습니다.")
        return row

    def challenge_row(db, workspace_id: str, challenge_id: str):
        workspace_row(db, workspace_id)
        row = db.execute("SELECT * FROM challenges WHERE id=? AND workspace_id=?", (challenge_id, workspace_id)).fetchone()
        if not row:
            raise HTTPException(404, "이 작업공간에서 문제를 찾을 수 없습니다.")
        return row

    def challenge_directory(workspace_id: str, challenge_id: str) -> Path:
        try:
            return app.state.storage_layout.legacy_challenge_path(
                workspace_id, challenge_id
            )
        except ValueError:
            raise HTTPException(400, "잘못된 저장 경로입니다.") from None

    def sync_challenge_storage(db, workspace_id: str, challenge_id: str) -> None:
        try:
            app.state.storage_layout.sync_challenge(db, workspace_id, challenge_id)
        except StorageArtifactError as exc:
            raise HTTPException(409, str(exc)) from None

    def flag_committed(user_id: str, workspace_id: str, challenge_id: str, flag: str,
                       completion_source: str) -> bool:
        """Fan out only after the flag transaction is visible to readers."""
        delivered = True
        try:
            hook = getattr(app.state, "telegram_flag_found", None)
            if hook and hook(user_id, workspace_id, challenge_id, flag) is False:
                delivered = False
        except Exception:
            delivered = False
            audit_log.warning("notification_enqueue_failed event=flag_found")
        try:
            hook = getattr(app.state, "ctfd_auto_submit_flag", None)
            if hook and hook(user_id, workspace_id, challenge_id, flag, completion_source) is False:
                delivered = False
        except Exception:
            delivered = False
            audit_log.warning("ctfd_submit_enqueue_failed event=flag_found")
        return delivered

    def reject_active_solver(db, workspace_id: str, challenge_id: str) -> None:
        solver = getattr(app.state, "solver_jobs", None)
        if solver and solver.has_open_challenge(
            owner_id(), workspace_id, challenge_id, connection=db,
        ):
            raise HTTPException(
                409,
                "풀이가 대기 또는 실행 중입니다. 중단과 격리 정리가 끝난 뒤 변경하세요.",
            )

    def reject_active_workspace_solver(db, workspace_id: str) -> None:
        solver = getattr(app.state, "solver_jobs", None)
        if solver and solver.has_open_workspace(owner_id(), workspace_id, connection=db):
            raise HTTPException(
                409,
                "이 작업공간의 풀이를 중단하고 격리 정리가 끝난 뒤 삭제하세요.",
            )

    def reject_active_ctfd_import(db, workspace_id: str) -> None:
        if db.execute(
            """SELECT 1 FROM ctfd_jobs
               WHERE workspace_id=? AND status IN ('queued','running') LIMIT 1""",
            (workspace_id,),
        ).fetchone():
            raise HTTPException(
                409,
                "The CTFd import is still stopping. Try the delete again shortly.",
            )

    def reject_active_ctfd_refresh(db, workspace_id: str, challenge_id: str) -> None:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ctfd_jobs'"
        ).fetchone()
        if not table:
            return
        columns = {row[1] for row in db.execute("PRAGMA table_info(ctfd_jobs)")}
        if {"mode", "target_challenge_id"} <= columns and db.execute(
            """SELECT 1 FROM ctfd_jobs
                WHERE owner_user_id=? AND workspace_id=? AND mode='refresh'
                  AND target_challenge_id=? AND status IN ('queued','running')
                LIMIT 1""",
            (owner_id(), workspace_id, challenge_id),
        ).fetchone():
            raise HTTPException(
                409,
                "CTFd refresh is in progress. Change the challenge after it finishes.",
            )

    @app.get("/api/workspaces", dependencies=[Depends(require_auth)])
    def list_workspaces():
        with database() as db:
            rows = db.execute("""SELECT w.*, COUNT(c.id) AS challenge_count,
                SUM(CASE WHEN c.status='solved' THEN 1 ELSE 0 END) AS solved_count,
                SUM(CASE WHEN c.status='running' THEN 1 ELSE 0 END) AS running_count
                FROM workspaces w LEFT JOIN challenges c ON c.workspace_id=w.id
                WHERE w.owner_user_id=?
                GROUP BY w.id ORDER BY w.updated_at DESC,w.id DESC""", (owner_id(),)).fetchall()
        return {"workspaces": [workspace_result(row) for row in rows]}

    @app.post("/api/workspaces", status_code=201, dependencies=[Depends(require_auth)])
    def create_workspace(payload: WorkspaceInput):
        workspace_id, timestamp = uuid.uuid4().hex, now()
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            app.state.storage_layout.reserve_workspace(db, workspace_id, payload.name)
            db.execute("""INSERT INTO workspaces(
                id,name,description,flag_format,open_challenge_after_create,
                created_at,updated_at,owner_user_id
            ) VALUES(?,?,?,?,?,?,?,?)""", (
                workspace_id, payload.name, payload.description,
                payload.flag_format or None, int(payload.open_challenge_after_create),
                timestamp, timestamp, owner_id(),
            ))
            row = workspace_row(db, workspace_id)
        app.state.storage_layout.workspace_path(workspace_id, create=True)
        return workspace_result(row)

    @app.get("/api/workspaces/{workspace_id}", dependencies=[Depends(require_auth)])
    def get_workspace(workspace_id: str):
        with database() as db:
            return workspace_result(workspace_row(db, workspace_id))

    @app.get("/api/workspaces/{workspace_id}/resources", dependencies=[Depends(require_auth)])
    def workspace_resources(workspace_id: str):
        # Keep this owner check even though the payload contains aggregate values:
        # the polling URL remains valid only while the workspace is accessible.
        with database() as db:
            workspace_row(db, workspace_id)
        return app.state.resource_monitor.snapshot()

    @app.patch("/api/workspaces/{workspace_id}", dependencies=[Depends(require_auth)])
    def edit_workspace(workspace_id: str, payload: WorkspacePatch, if_match: str | None = Header(default=None)):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = workspace_row(db, workspace_id)
            check_edit_token(if_match, workspace_result(row)["edit_token"])
            values = {**dict(row), **payload.model_dump(exclude_unset=True)}
            if values["flag_format"] != row["flag_format"]:
                reject_active_workspace_solver(db, workspace_id)
            db.execute("""UPDATE workspaces
                           SET name=?,description=?,flag_format=?,
                               open_challenge_after_create=?,updated_at=?
                         WHERE id=?""", (
                values["name"], values["description"],
                values["flag_format"] or None,
                int(values["open_challenge_after_create"]), now(), workspace_id,
            ))
            return workspace_result(workspace_row(db, workspace_id))

    @app.delete("/api/workspaces/{workspace_id}", dependencies=[Depends(require_auth)])
    @workspace_writer_lock
    def delete_workspace(workspace_id: str):
        with database() as db:
            workspace_row(db, workspace_id)
        solver_jobs = getattr(app.state, "solver_jobs", None)
        if solver_jobs and not solver_jobs.cancel_workspace(workspace_id, owner_id()):
            raise HTTPException(409, "풀이를 중단하고 격리 정리 중입니다. 잠시 후 다시 삭제하세요.")
        jobs = getattr(app.state, "ctfd_jobs", None)
        if jobs and not jobs.cancel_workspace(workspace_id):
            raise HTTPException(409, "가져오기를 중단하고 있습니다. 잠시 후 다시 삭제하세요.")
        if not app.state.uploads.cancel_workspace(workspace_id, CURRENT_USER.get()):
            raise HTTPException(409, "파일 저장 중입니다. 업로드를 중단한 뒤 다시 삭제하세요.")
        submit_jobs = getattr(app.state, "ctfd_submit", None)
        if submit_jobs and not submit_jobs.cancel_workspace(workspace_id, CURRENT_USER.get()):
            try:
                submit_jobs.release_delete_block(workspace_id, CURRENT_USER.get())
            except Exception:
                logging.exception("Failed to release CTFd workspace delete tombstone")
            raise HTTPException(409, "자동 제출을 중단하고 있습니다. 잠시 후 다시 삭제하세요.")
        with delete_transaction(submit_jobs, workspace_id) as db:
            db.execute("BEGIN IMMEDIATE")
            workspace_row(db, workspace_id)
            reject_active_ctfd_import(db, workspace_id)
            reject_active_workspace_solver(db, workspace_id)
            try:
                target = app.state.storage_layout.legacy_workspace_path(workspace_id)
            except ValueError:
                raise HTTPException(400, "잘못된 저장 경로입니다.") from None
            readable_target = app.state.storage_layout.remove_workspace_view(
                db, workspace_id
            )
            app.state.storage_layout.plan_delete(
                db, "workspace", workspace_id, workspace_id
            )
            app.state.storage_layout.forget_workspace(db, workspace_id)
            db.execute("DELETE FROM workspaces WHERE id=?", (workspace_id,))
        app.state.storage_layout.finish_deletions()
        return {"ok": True}

    @app.get("/api/workspaces/{workspace_id}/challenges", dependencies=[Depends(require_auth)])
    def list_challenges(
        workspace_id: str,
        status: str | None = None,
        category: str | None = None,
        q: str = "",
        sort: str = "added_desc",
    ):
        if status and status not in STATUSES:
            raise HTTPException(400, "잘못된 상태 필터입니다.")
        order_by = {
            "added_desc": "c.created_at DESC,c.id DESC",
            "added_asc": "c.created_at ASC,c.id ASC",
            "name_asc": "c.name COLLATE NOCASE ASC,c.id ASC",
            "name_desc": "c.name COLLATE NOCASE DESC,c.id DESC",
            "solver_desc": (
                "latest_solver.started_at IS NULL,"
                "latest_solver.started_at DESC,c.created_at DESC,c.id DESC"
            ),
            "solver_asc": (
                "latest_solver.started_at IS NULL,"
                "latest_solver.started_at ASC,c.created_at ASC,c.id ASC"
            ),
        }.get(sort)
        if order_by is None:
            raise HTTPException(400, "잘못된 문제 정렬 방식입니다.")
        current_owner = owner_id()
        conditions, filter_params = ["c.workspace_id=?"], [workspace_id]
        if status:
            conditions.append("c.status=?")
            filter_params.append(status)
        if category:
            conditions.append("c.category=?")
            filter_params.append(category)
        if q:
            conditions.append(
                "(instr(lower(c.name),lower(?))>0 "
                "OR instr(lower(c.description),lower(?))>0)"
            )
            filter_params.extend([q, q])
        with database() as db:
            workspace_row(db, workspace_id)
            rows = db.execute(
                """SELECT c.*
                     FROM challenges c
                     LEFT JOIN (
                         SELECT challenge_id,MAX(created_at) AS started_at
                           FROM solver_jobs
                          WHERE owner_user_id=? AND workspace_id=? AND job_mode='solve'
                          GROUP BY challenge_id
                     ) latest_solver ON latest_solver.challenge_id=c.id
                    WHERE """ + " AND ".join(conditions) + " ORDER BY " + order_by,
                [current_owner, workspace_id, *filter_params],
            ).fetchall()
            counts = {key: 0 for key in STATUSES}
            for row in db.execute("SELECT status,COUNT(*) AS total FROM challenges WHERE workspace_id=? GROUP BY status", (workspace_id,)):
                counts[row["status"]] = row["total"]
            categories = [row[0] for row in db.execute("SELECT DISTINCT category FROM challenges WHERE workspace_id=? AND category!='' ORDER BY category", (workspace_id,))]
            results = [challenge_response(db, row, include_writeup=False) for row in rows]
            for result in results:
                result["latest_solver"] = latest_solver_summary(
                    db, workspace_id, result["id"]
                )
        return {"challenges": results, "counts": counts, "categories": categories}

    @app.post("/api/workspaces/{workspace_id}/challenges", status_code=201, dependencies=[Depends(require_auth)])
    def create_challenge(workspace_id: str, payload: ChallengeInput):
        challenge_id, timestamp = uuid.uuid4().hex, now()
        remote_mode, remote = normalize_remote_pair(payload.remote_mode, payload.remote)
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            workspace_row(db, workspace_id)
            app.state.storage_layout.reserve_challenge(
                db, workspace_id, challenge_id, payload.name
            )
            db.execute("""INSERT INTO challenges(id,workspace_id,name,category,description,remote,remote_mode,flag,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)""", (challenge_id, workspace_id, payload.name, payload.category, payload.description, remote, remote_mode, payload.flag or None, timestamp, timestamp))
            db.execute("UPDATE workspaces SET updated_at=? WHERE id=?", (timestamp, workspace_id))
            if payload.flag:
                db.execute("UPDATE challenges SET status='flag_found' WHERE id=?", (challenge_id,))
            result = challenge_response(db, challenge_row(db, workspace_id, challenge_id))
        app.state.storage_layout.challenge_path(workspace_id, challenge_id, create=True)
        app.state.storage_layout.write_notes(workspace_id, challenge_id, "")
        if payload.flag:
            flag_committed(owner_id(), workspace_id, challenge_id, payload.flag, "manual")
        return result

    @app.post(
        "/api/workspaces/{workspace_id}/challenges/{challenge_id}/clone",
        status_code=201,
        dependencies=[Depends(require_auth)],
    )
    @workspace_writer_lock
    def clone_challenge(workspace_id: str, challenge_id: str):
        """Create an unsolved, storage-independent copy of one challenge."""

        from .storage_budget import MAX_SQLITE_INTEGER, StorageBudgetError

        clone_id, timestamp = uuid.uuid4().hex, now()
        reservation_key = f"challenge-clone:{clone_id}"
        current_owner = owner_id()
        core_fields = ("name", "category", "description", "remote", "remote_mode")
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            source = challenge_row(db, workspace_id, challenge_id)
            reject_active_ctfd_refresh(db, workspace_id, challenge_id)
            attachments = db.execute(
                """SELECT id,original_name,stored_name,size,created_at
                     FROM attachments
                    WHERE workspace_id=? AND challenge_id=?
                    ORDER BY created_at,id""",
                (workspace_id, challenge_id),
            ).fetchall()
            source_fingerprint = tuple(source[field] for field in core_fields)
            attachment_fingerprint = tuple(
                tuple(row[field] for field in ("id", "original_name", "stored_name", "size"))
                for row in attachments
            )

        total_size = sum(int(row["size"]) for row in attachments)
        if total_size > MAX_SQLITE_INTEGER:
            raise HTTPException(413, "첨부파일 합계가 복제 가능한 크기를 넘었습니다.")

        layout = app.state.storage_layout
        clone_directory = layout.legacy_challenge_path(
            workspace_id, clone_id, create=False
        )
        copies = []
        for attachment in attachments:
            new_attachment_id = uuid.uuid4().hex
            copies.append(
                {
                    "id": new_attachment_id,
                    "original_name": attachment["original_name"],
                    "size": int(attachment["size"]),
                    "source": layout.legacy_attachment_path(
                        workspace_id, challenge_id, attachment["stored_name"]
                    ),
                    "target": layout.legacy_attachment_path(
                        workspace_id, clone_id, new_attachment_id,
                        create_parent=False,
                    ),
                }
            )

        reserved = False
        published = False
        readable_path = {}

        def publish_clone(connection):
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id=? AND owner_user_id=?",
                (workspace_id, current_owner),
            ).fetchone()
            current_source = connection.execute(
                "SELECT * FROM challenges WHERE id=? AND workspace_id=?",
                (challenge_id, workspace_id),
            ).fetchone()
            if not workspace or not current_source:
                raise HTTPException(404, "복제할 문제를 찾을 수 없습니다.")
            current_attachments = connection.execute(
                """SELECT id,original_name,stored_name,size
                     FROM attachments
                    WHERE workspace_id=? AND challenge_id=?
                    ORDER BY created_at,id""",
                (workspace_id, challenge_id),
            ).fetchall()
            if (
                tuple(current_source[field] for field in core_fields)
                != source_fingerprint
                or tuple(
                    tuple(
                        row[field]
                        for field in ("id", "original_name", "stored_name", "size")
                    )
                    for row in current_attachments
                )
                != attachment_fingerprint
            ):
                raise HTTPException(
                    409,
                    "복제 중 원본 문제가 변경되었습니다. 최신 내용을 확인한 뒤 다시 시도하세요.",
                )
            name = clone_challenge_name(
                connection, workspace_id, current_source["name"]
            )
            layout.reserve_challenge(connection, workspace_id, clone_id, name)
            readable_path["value"] = layout.challenge_path(
                workspace_id, clone_id, db=connection, create=True
            )
            connection.execute(
                """INSERT INTO challenges(
                       id,workspace_id,name,category,description,remote,remote_mode,
                       created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    clone_id,
                    workspace_id,
                    name,
                    current_source["category"],
                    current_source["description"],
                    current_source["remote"],
                    current_source["remote_mode"],
                    timestamp,
                    timestamp,
                ),
            )
            connection.executemany(
                """INSERT INTO attachments(
                       id,workspace_id,challenge_id,original_name,stored_name,size,created_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    (
                        copy["id"], workspace_id, clone_id,
                        copy["original_name"], copy["id"], copy["size"], timestamp,
                    )
                    for copy in copies
                ),
            )
            connection.execute(
                "UPDATE workspaces SET updated_at=? WHERE id=?",
                (timestamp, workspace_id),
            )

        try:
            app.state.storage_budget.reserve(
                reservation_key,
                "challenge_clone",
                current_owner,
                workspace_id,
                clone_id,
                total_size,
            )
            reserved = True
            clone_directory = layout.legacy_challenge_path(
                workspace_id, clone_id, create=True
            )
            attachments_directory = clone_directory / "attachments"
            if copies:
                attachments_directory.mkdir(mode=0o750, exist_ok=True)
            for copy in copies:
                copy_regular_snapshot(copy["source"], copy["target"], copy["size"])
            if hasattr(os, "O_DIRECTORY"):
                for directory in (attachments_directory, clone_directory):
                    if not directory.is_dir():
                        continue
                    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            app.state.storage_budget.release(
                reservation_key, db_update=publish_clone
            )
            reserved = False
            published = True
        except BaseException as exc:
            if reserved:
                try:
                    app.state.storage_budget.release(reservation_key)
                except Exception:
                    audit_log.exception("challenge_clone_reservation_cleanup_failed")
            if not published:
                try:
                    layout.finalize_deleted_view(
                        readable_path.get("value"), "challenge", clone_id
                    )
                    shutil.rmtree(clone_directory, ignore_errors=True)
                except Exception:
                    audit_log.exception("challenge_clone_file_cleanup_failed")
            if isinstance(exc, ChallengeCloneSourceChanged):
                raise HTTPException(
                    409,
                    "복제 중 원본 첨부파일이 변경되었습니다. 다시 시도하세요.",
                ) from None
            if isinstance(exc, StorageBudgetError):
                raise HTTPException(507, str(exc)) from None
            if isinstance(exc, OSError):
                raise HTTPException(
                    507,
                    "첨부파일 복사에 실패했습니다. 저장 공간과 파일 상태를 확인하세요.",
                ) from None
            raise

        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            sync_challenge_storage(db, workspace_id, clone_id)
            result = challenge_response(
                db, challenge_row(db, workspace_id, clone_id)
            )
            result["attachments"] = [
                dict(row)
                for row in db.execute(
                    """SELECT id,original_name,size,created_at
                         FROM attachments
                        WHERE workspace_id=? AND challenge_id=?
                        ORDER BY created_at,id""",
                    (workspace_id, clone_id),
                )
            ]
        return result

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}", dependencies=[Depends(require_auth)])
    def get_challenge(workspace_id: str, challenge_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            challenge_row(db, workspace_id, challenge_id)
            sync_challenge_storage(db, workspace_id, challenge_id)
            result = challenge_response(db, challenge_row(db, workspace_id, challenge_id))
            result["attachments"] = [dict(row) for row in db.execute("SELECT id,original_name,size,created_at FROM attachments WHERE workspace_id=? AND challenge_id=? ORDER BY created_at,id", (workspace_id, challenge_id))]
            related = challenge_relations(db, workspace_id, challenge_id)
            result["related_challenges"] = related
            result["prerequisites"] = related  # Compatibility with existing clients.
        return result

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/relations/candidates", dependencies=[Depends(require_auth)])
    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/prerequisites/candidates", dependencies=[Depends(require_auth)])
    def relation_candidates(workspace_id: str, challenge_id: str):
        with database() as db:
            challenge_row(db, workspace_id, challenge_id)
            return {"challenges": [dict(row) for row in db.execute(
                """SELECT id,name,category,status,ctfd_id,ctfd_url
                     FROM challenges WHERE workspace_id=? AND id<>?
                     ORDER BY name COLLATE NOCASE,id""", (workspace_id, challenge_id),
            )]}

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/relations", status_code=201, dependencies=[Depends(require_auth)])
    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/prerequisites", status_code=201, dependencies=[Depends(require_auth)])
    def add_relation(workspace_id: str, challenge_id: str, payload: ChallengeRelationInput):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            challenge_row(db, workspace_id, challenge_id)
            challenge_row(db, workspace_id, payload.related_id)
            if challenge_id == payload.related_id:
                raise HTTPException(400, "문제를 자기 자신과 연결할 수 없습니다.")
            first_id, second_id = sorted((challenge_id, payload.related_id))
            existing = db.execute(
                """SELECT 1 FROM challenge_relations WHERE workspace_id=? AND
                   ((prerequisite_id=? AND dependent_id=?) OR
                    (prerequisite_id=? AND dependent_id=?)) LIMIT 1""",
                (workspace_id, first_id, second_id, second_id, first_id),
            ).fetchone()
            if existing:
                raise HTTPException(409, "이미 연결된 문제입니다.")
            try:
                db.execute(
                    """INSERT INTO challenge_relations(workspace_id,prerequisite_id,dependent_id,created_at)
                       VALUES(?,?,?,?)""",
                    (workspace_id, first_id, second_id, now()),
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "이미 연결된 문제입니다.") from None
            related = challenge_relations(db, workspace_id, challenge_id)
            return {"related_challenges": related, "prerequisites": related}

    @app.delete("/api/workspaces/{workspace_id}/challenges/{challenge_id}/relations/{prerequisite_id}", dependencies=[Depends(require_auth)])
    @app.delete("/api/workspaces/{workspace_id}/challenges/{challenge_id}/prerequisites/{prerequisite_id}", dependencies=[Depends(require_auth)])
    def remove_relation(workspace_id: str, challenge_id: str, prerequisite_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            challenge_row(db, workspace_id, challenge_id)
            result = db.execute(
                """DELETE FROM challenge_relations WHERE workspace_id=? AND
                   ((prerequisite_id=? AND dependent_id=?) OR
                    (prerequisite_id=? AND dependent_id=?))""",
                (workspace_id, challenge_id, prerequisite_id, prerequisite_id, challenge_id),
            )
            if result.rowcount == 0:
                raise HTTPException(404, "연관 문제를 찾을 수 없습니다.")
            related = challenge_relations(db, workspace_id, challenge_id)
            return {"related_challenges": related, "prerequisites": related}

    @app.patch("/api/workspaces/{workspace_id}/challenges/{challenge_id}", dependencies=[Depends(require_auth)])
    def edit_challenge(workspace_id: str, challenge_id: str, payload: ChallengePatch, if_match: str | None = Header(default=None)):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            check_edit_token(if_match, challenge_result(row)["edit_token"])
            reject_active_solver(db, workspace_id, challenge_id)
            changes = payload.model_dump(exclude_unset=True)
            if changes.keys() & {"name", "category", "description", "remote", "remote_mode"}:
                reject_active_ctfd_refresh(db, workspace_id, challenge_id)
            values = {**dict(row), **changes}
            requested_mode = None if "remote" in changes and "remote_mode" not in changes else values["remote_mode"]
            values["remote_mode"], values["remote"] = normalize_remote_pair(
                requested_mode, values["remote"]
            )
            flag_changed = bool(values["flag"] and values["flag"] != row["flag"])
            db.execute("UPDATE challenges SET name=?,category=?,description=?,remote=?,remote_mode=?,flag=?,updated_at=? WHERE workspace_id=? AND id=?", (
                values["name"], values["category"], values["description"], values["remote"], values["remote_mode"], values["flag"] or None, now(), workspace_id, challenge_id,
            ))
            if flag_changed:
                db.execute("UPDATE challenges SET status='flag_found',previous_status=NULL,completion_source=NULL WHERE id=?", (challenge_id,))
            result = challenge_response(db, challenge_row(db, workspace_id, challenge_id))
        if flag_changed:
            flag_committed(owner_id(), workspace_id, challenge_id, values["flag"], "manual")
        return result

    @app.delete("/api/workspaces/{workspace_id}/challenges/{challenge_id}", dependencies=[Depends(require_auth)])
    @workspace_writer_lock
    def delete_challenge(workspace_id: str, challenge_id: str):
        with database() as db:
            challenge_row(db, workspace_id, challenge_id)
        solver_jobs = getattr(app.state, "solver_jobs", None)
        if solver_jobs and not solver_jobs.cancel_challenge(workspace_id, challenge_id, owner_id()):
            raise HTTPException(409, "풀이를 중단하고 격리 정리 중입니다. 잠시 후 다시 삭제하세요.")
        jobs = getattr(app.state, "ctfd_jobs", None)
        if jobs and not jobs.cancel_workspace(workspace_id):
            raise HTTPException(409, "가져오기를 중단하고 있습니다. 잠시 후 다시 삭제하세요.")
        if not app.state.uploads.cancel_challenge(workspace_id, challenge_id, CURRENT_USER.get()):
            raise HTTPException(409, "파일 저장 중입니다. 업로드를 중단한 뒤 다시 삭제하세요.")
        submit_jobs = getattr(app.state, "ctfd_submit", None)
        if submit_jobs and not submit_jobs.cancel_challenge(workspace_id, challenge_id, CURRENT_USER.get()):
            try:
                submit_jobs.release_delete_block(
                    workspace_id,
                    CURRENT_USER.get(),
                    challenge_id=challenge_id,
                )
            except Exception:
                logging.exception("Failed to release CTFd challenge delete tombstone")
            raise HTTPException(409, "자동 제출을 중단하고 있습니다. 잠시 후 다시 삭제하세요.")
        with delete_transaction(submit_jobs, workspace_id, challenge_id) as db:
            db.execute("BEGIN IMMEDIATE")
            challenge_row(db, workspace_id, challenge_id)
            reject_active_ctfd_import(db, workspace_id)
            reject_active_solver(db, workspace_id, challenge_id)
            target = challenge_directory(workspace_id, challenge_id)
            readable_target = app.state.storage_layout.remove_challenge_view(
                db, workspace_id, challenge_id
            )
            app.state.storage_layout.plan_delete(
                db, "challenge", challenge_id, workspace_id,
                challenge_id=challenge_id,
            )
            app.state.storage_layout.forget_challenge(db, challenge_id)
            db.execute("DELETE FROM challenges WHERE workspace_id=? AND id=?", (workspace_id, challenge_id))
        app.state.storage_layout.finish_deletions()
        return {"ok": True}

    @app.patch("/api/workspaces/{workspace_id}/challenges/{challenge_id}/status", dependencies=[Depends(require_auth)])
    def set_status(workspace_id: str, challenge_id: str, payload: StatusInput):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            reject_active_solver(db, workspace_id, challenge_id)
            if row["status"] == "solved":
                raise HTTPException(409, "완료 취소 후 상태를 변경하세요.")
            db.execute("UPDATE challenges SET status=?,updated_at=? WHERE workspace_id=? AND id=?", (payload.status, now(), workspace_id, challenge_id))
            return challenge_response(db, challenge_row(db, workspace_id, challenge_id))

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/complete", dependencies=[Depends(require_auth)])
    def complete_challenge(workspace_id: str, challenge_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            reject_active_solver(db, workspace_id, challenge_id)
            if row["status"] != "solved":
                db.execute("UPDATE challenges SET previous_status=status,status='solved',completion_source='manual',updated_at=? WHERE workspace_id=? AND id=?", (now(), workspace_id, challenge_id))
            return challenge_response(db, challenge_row(db, workspace_id, challenge_id))

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/reopen", dependencies=[Depends(require_auth)])
    def reopen_challenge(workspace_id: str, challenge_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            reject_active_solver(db, workspace_id, challenge_id)
            if row["status"] != "solved":
                raise HTTPException(409, "완료된 문제만 완료를 취소할 수 있습니다.")
            previous = row["previous_status"] if row["previous_status"] in STATUSES[:-1] else "pending"
            db.execute("UPDATE challenges SET status=?,previous_status=NULL,completion_source=NULL,updated_at=? WHERE workspace_id=? AND id=?", (previous, now(), workspace_id, challenge_id))
            return challenge_response(db, challenge_row(db, workspace_id, challenge_id))

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/attachments", dependencies=[Depends(require_auth)])
    def retired_attachment_upload(workspace_id: str, challenge_id: str):
        with database() as db:
            challenge_row(db, workspace_id, challenge_id)
        raise HTTPException(
            410,
            "기존 단일 요청 첨부 업로드는 종료되었습니다. 첨부파일 선택 화면의 이어 올리기를 사용해 주세요.",
        )

    def attachment_path(db, workspace_id: str, challenge_id: str, attachment_id: str):
        challenge_row(db, workspace_id, challenge_id)
        row = db.execute("SELECT * FROM attachments WHERE id=? AND workspace_id=? AND challenge_id=?", (attachment_id, workspace_id, challenge_id)).fetchone()
        if not row:
            raise HTTPException(404, "첨부파일을 찾을 수 없습니다.")
        try:
            app.state.storage_layout.ensure_attachment_view(
                db, workspace_id, challenge_id, row
            )
            target = app.state.storage_layout.legacy_attachment_path(
                workspace_id, challenge_id, row["stored_name"]
            )
        except ValueError:
            raise HTTPException(400, "잘못된 저장 경로입니다.")
        return row, target

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/attachments/{attachment_id}", dependencies=[Depends(require_auth)])
    def download_attachment(workspace_id: str, challenge_id: str, attachment_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row, target = attachment_path(db, workspace_id, challenge_id, attachment_id)
        if not target.is_file():
            raise HTTPException(404, "첨부파일이 저장소에 없습니다.")
        return FileResponse(target, filename=row["original_name"], media_type="application/octet-stream")

    @app.delete("/api/workspaces/{workspace_id}/challenges/{challenge_id}/attachments/{attachment_id}", dependencies=[Depends(require_auth)])
    @workspace_writer_lock
    def delete_attachment(workspace_id: str, challenge_id: str, attachment_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            attachment, target = attachment_path(
                db, workspace_id, challenge_id, attachment_id
            )
            # Solver enqueue uses the same SQLite write transaction boundary.
            # Whichever operation commits first either stages the complete
            # attachment set or makes this deletion return a clear conflict.
            reject_active_solver(db, workspace_id, challenge_id)
            reject_active_ctfd_refresh(db, workspace_id, challenge_id)
            readable_target = app.state.storage_layout.remove_attachment_view(
                db, workspace_id, challenge_id, attachment
            )
            app.state.storage_layout.plan_delete(
                db, "attachment", attachment_id, workspace_id,
                challenge_id=challenge_id,
                stored_name=attachment["stored_name"],
                readable_name=(readable_target.name if readable_target else ""),
            )
            app.state.storage_layout.forget(db, "attachment", attachment_id)
            db.execute("DELETE FROM attachments WHERE id=? AND workspace_id=? AND challenge_id=?", (attachment_id, workspace_id, challenge_id))
        app.state.storage_layout.finish_deletions()
        return {"ok": True}

    @app.put("/api/workspaces/{workspace_id}/challenges/{challenge_id}/notes", dependencies=[Depends(require_auth)])
    def save_notes(workspace_id: str, challenge_id: str, payload: NotesInput, if_match: str | None = Header(default=None)):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            sync_challenge_storage(db, workspace_id, challenge_id)
            row = challenge_row(db, workspace_id, challenge_id)
            check_edit_token(if_match, challenge_result(row)["notes_token"])
            reject_active_solver(db, workspace_id, challenge_id)
            artifact = app.state.writeups.fields(db, challenge_id)
            content = (
                merge_generated_writeup(
                    payload.content,
                    artifact["writeup_markdown"],
                    artifact["writeup_markdown"],
                )
                if artifact["has_writeup"]
                # Older browser tabs can still hold a pre-rejection copy with
                # legacy sentinels after the canonical artifact was deleted.
                # Strip that stale copy instead of restoring it as manual text.
                else remove_generated_writeup(payload.content)
            )
            db.execute("UPDATE challenges SET notes=?,updated_at=? WHERE workspace_id=? AND id=?", (content, now(), workspace_id, challenge_id))
            token = challenge_result(challenge_row(db, workspace_id, challenge_id))["notes_token"]
        try:
            app.state.storage_layout.write_notes(workspace_id, challenge_id, content)
        except StorageArtifactError as exc:
            raise HTTPException(409, str(exc)) from None
        # Return the effective server value and token together so the editor
        # baseline and optimistic-lock token describe one snapshot.
        return {
            "ok": True,
            "source": "manual",
            "notes": content,
            "notes_token": token,
        }

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/notes/upload", dependencies=[Depends(require_auth)])
    async def upload_notes(workspace_id: str, challenge_id: str, file: UploadFile = File(...), if_match: str | None = Header(default=None)):
        name = validate_filename(file.filename)
        if Path(name).suffix.lower() not in (".md", ".markdown", ".txt"):
            raise HTTPException(400, "Markdown 또는 텍스트 파일을 선택하세요.")
        with database() as db:
            challenge_row(db, workspace_id, challenge_id)
        raw = await file.read(2_000_001)
        await file.close()
        if len(raw) > 2_000_000:
            raise HTTPException(413, "노트는 2MB까지 업로드할 수 있습니다.")
        try:
            content = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise HTTPException(400, "UTF-8 텍스트 파일을 사용하세요.") from None
        return save_notes(workspace_id, challenge_id, NotesInput(content=content), if_match)

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/notes/download", dependencies=[Depends(require_auth)])
    def download_notes(workspace_id: str, challenge_id: str):
        from urllib.parse import quote

        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            sync_challenge_storage(db, workspace_id, challenge_id)
            row = challenge_row(db, workspace_id, challenge_id)
        filename = quote(export_filename(row["name"]), safe="")
        return Response(row["notes"], media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename}"})

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/writeup", dependencies=[Depends(require_auth)])
    def get_agent_writeup(workspace_id: str, challenge_id: str):
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            sync_challenge_storage(db, workspace_id, challenge_id)
            row = challenge_row(db, workspace_id, challenge_id)
            artifact = app.state.writeups.fields(db, row["id"])
        if not artifact["has_writeup"]:
            raise HTTPException(404, "Agent가 작성한 write-up이 없습니다.")
        return {
            "markdown": artifact["writeup_markdown"],
            "updated_at": artifact["writeup_updated_at"],
        }

    @app.get("/api/workspaces/{workspace_id}/challenges/{challenge_id}/writeup/download", dependencies=[Depends(require_auth)])
    def download_agent_writeup(workspace_id: str, challenge_id: str):
        from urllib.parse import quote

        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = challenge_row(db, workspace_id, challenge_id)
            sync_challenge_storage(db, workspace_id, challenge_id)
            row = challenge_row(db, workspace_id, challenge_id)
            artifact = app.state.writeups.fields(db, row["id"])
        if not artifact["has_writeup"]:
            raise HTTPException(404, "Agent가 작성한 write-up이 없습니다.")
        filename = quote(writeup_filename(row["name"]), safe="")
        return Response(
            artifact["writeup_markdown"],
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename}"},
        )

    from .uploads import register_uploads
    register_uploads(app, require_auth, settings, validate_filename, now)
    from .telegram import register_telegram
    register_telegram(app, require_auth, settings, database)
    from .ctfd_submit import register_ctfd_submit
    register_ctfd_submit(app, require_auth, settings)

    for module_name, function_name in (("accounts", "register_accounts"), ("ctfd", "register_ctfd")):
        try:
            module = importlib.import_module(f"ctf_agent.{module_name}")
        except ModuleNotFoundError as exc:
            if exc.name != f"ctf_agent.{module_name}":
                raise
        else:
            getattr(module, function_name)(app, require_auth, settings)

    from .solver_service import register_solver
    register_solver(app, require_auth, require_admin, settings, database)

    # Cloudflare and browsers may retain extension-based static assets for
    # several hours.  Give every immutable release its own asset namespace so
    # an HTML response can never pair new JavaScript with an older stylesheet.
    # ``dev`` keeps local runs predictable without accepting arbitrary path
    # material from an environment variable.
    release = os.environ.get("CTF_RELEASE_SHA", "dev")
    asset_version = release if re.fullmatch(r"[0-9a-f]{40}", release) else "dev"
    index_document = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    versioned_index = index_document.replace(
        '"/assets/', f'"/assets/{asset_version}/'
    )
    app.mount(
        f"/assets/{asset_version}",
        StaticFiles(directory=WEB_DIR),
        name="release-assets",
    )
    # Preserve the old paths for bookmarks and in-flight pre-deployment HTML.
    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

    @app.get("/")
    def index():
        return HTMLResponse(
            versioned_index,
            headers={"Cache-Control": "no-store"},
        )

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "5050")), workers=1)
