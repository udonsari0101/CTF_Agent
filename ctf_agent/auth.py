"""Local user authentication and administrator metadata management."""
import asyncio
import hashlib
import hmac
import inspect
import ipaddress
import secrets
import sqlite3
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from .password_policy import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH

COOKIE = "ctf_session"


def stamp():
    return datetime.now(timezone.utc).isoformat()


def safe_user(row):
    return {key: row[key] for key in ("id", "username", "role", "active", "created_at", "last_login_at")}


def username_value(value):
    value = value.strip()
    if not value or any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("사용할 수 있는 아이디를 입력하세요.")
    return value


class Login(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=100)
    # Keep accepting historical passwords shorter than the current creation
    # policy so an upgraded installation never locks out an existing user.
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    _username = field_validator("username")(username_value)


class FirstAdmin(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    _username = field_validator("username")(username_value)


class Password(BaseModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH,
    )


class Username(BaseModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_username: str = Field(min_length=1, max_length=100)
    _username = field_validator("new_username")(username_value)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH,
    )
    role: Literal["admin", "user"] = "user"
    _username = field_validator("username")(username_value)


class UserUpdate(BaseModel):
    active: bool | None = None
    role: Literal["admin", "user"] | None = None


class UserPassword(BaseModel):
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH,
    )


def register_auth(app, settings, database, make_hash, verify_hash, user_context):
    credential_work_gate = threading.BoundedSemaphore(2)
    automatic_session = None
    if settings.auth_mode == "nologin":
        with database() as db:
            local_id = db.execute(
                "SELECT value FROM meta WHERE key='legacy_owner_id'"
            ).fetchone()
            local_user = db.execute(
                "SELECT * FROM users WHERE id=?", (local_id["value"],)
            ).fetchone() if local_id else None
            if not local_user:
                raise RuntimeError("The local no-login user is unavailable.")
            # Background services validate the persisted active bit before
            # committing owner-scoped work.  The operator-selected no-login
            # mode therefore restores its one local owner if it was disabled.
            if not local_user["active"]:
                db.execute("UPDATE users SET active=1 WHERE id=?", (local_user["id"],))
                local_user = db.execute(
                    "SELECT * FROM users WHERE id=?", (local_user["id"],)
                ).fetchone()
            # Password sessions must not silently become valid again if the
            # deployment later returns to password mode.
            db.execute("DELETE FROM sessions")
        automatic_user = safe_user(local_user)
        automatic_user["role"] = "admin"
        automatic_session = {
            **automatic_user,
            "csrf_token": secrets.token_urlsafe(32),
            "token_hash": "",
        }

    def password_api_disabled(path: str) -> bool:
        return settings.auth_mode == "nologin" and (
            path in {"/api/auth/login", "/api/auth/setup", "/api/auth/logout", "/api/auth/password", "/api/auth/username"}
            or path == "/api/admin/users"
            or path.startswith("/api/admin/users/")
        )

    @contextmanager
    def credential_work():
        # PBKDF2 intentionally consumes CPU. Bound every user-triggered hash
        # or verification to the web container's two-CPU allocation without
        # parking additional AnyIO worker threads behind a semaphore.
        if not credential_work_gate.acquire(blocking=False):
            raise HTTPException(429, "계정 보안 작업이 처리 중입니다. 잠시 후 다시 시도해 주세요.")
        try:
            yield
        finally:
            credential_work_gate.release()
    def login_client_address(request):
        if not settings.trust_cf_connecting_ip:
            return request.client.host if request.client else "unknown"
        # This deployment publishes the container only on host loopback and
        # cloudflared is the sole public ingress. Cloudflare supplies exactly
        # one original visitor address in CF-Connecting-IP. Fail closed when
        # the explicitly trusted ingress contract is missing or malformed so
        # every visitor never silently collapses into the proxy's one address.
        value = request.headers.get("cf-connecting-ip", "")
        if not value or value != value.strip() or "," in value or len(value) > 45:
            raise HTTPException(400, "접속 주소 정보를 확인할 수 없습니다. Cloudflare 연결 설정을 확인해 주세요.")
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            raise HTTPException(400, "접속 주소 정보 형식이 올바르지 않습니다.") from None

    def origin_check(request):
        origin = request.headers.get("origin")
        expected = settings.public_origin or str(request.base_url).rstrip("/")
        if origin and origin.rstrip("/") != expected:
            raise HTTPException(403, "요청 출처를 확인할 수 없습니다.")
        if request.headers.get("sec-fetch-site") == "cross-site":
            raise HTTPException(403, "외부 사이트 요청은 허용하지 않습니다.")

    def session_for(request):
        token = request.cookies.get(COOKIE, "")
        if not token or len(token) > 200:
            return None
        with database() as db:
            return db.execute("""SELECT s.token_hash,s.csrf_token,s.expires_at,u.* FROM sessions s
                JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
                (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()

    def require_auth(request: Request) -> dict:
        if getattr(request.state, "user", None):
            return request.state.user
        session = automatic_session or session_for(request)
        if not session:
            raise HTTPException(401, "로그인이 필요합니다.")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin_check(request)
            if not hmac.compare_digest(request.headers.get("x-csrf-token", "").encode(), session["csrf_token"].encode()):
                raise HTTPException(403, "세션이 변경되었습니다. 새로고침 후 다시 시도하세요.")
        request.state.user = safe_user(session)
        request.state.session = {"csrf_token": session["csrf_token"], "token_hash": session["token_hash"]}
        return request.state.user

    def require_admin(request: Request) -> dict:
        user = require_auth(request)
        if user["role"] != "admin":
            raise HTTPException(403, "관리자 권한이 필요합니다.")
        return user

    app.state.require_auth = require_auth
    app.state.require_admin = require_admin

    def preauthorize_body_request(scope):
        # Read no body until every non-login mutation has a live session and
        # valid same-origin CSRF token. Anonymous slow uploads therefore never
        # occupy the bounded request-body gates.
        if password_api_disabled(scope.get("path", "")):
            return 404, "이 인증 모드에서는 사용할 수 없습니다."
        if scope.get("path") == "/api/auth/login":
            return None
        if scope.get("path") == "/api/auth/setup":
            return None if settings.auth_mode == "password" and settings.allow_web_bootstrap else (404, "초기 설정을 사용할 수 없습니다.")
        try:
            require_auth(Request(scope))
            return None
        except HTTPException as exc:
            return exc.status_code, exc.detail

    app.state.preauthorize_body_request = preauthorize_body_request

    @app.middleware("http")
    async def authenticated_context(request: Request, call_next):
        context_token = user_context.set(None)
        try:
            if password_api_disabled(request.url.path):
                return JSONResponse(
                    {"detail": "이 인증 모드에서는 사용할 수 없습니다."},
                    status_code=404,
                )
            if request.url.path == "/api/auth/setup" and not settings.allow_web_bootstrap:
                return JSONResponse({"detail": "초기 설정을 사용할 수 없습니다."}, status_code=404)
            if request.url.path.startswith("/api/") and request.url.path not in ("/api/auth/state", "/api/auth/login", "/api/auth/setup"):
                try:
                    user_context.set(require_auth(request))
                except HTTPException as exc:
                    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
            return await call_next(request)
        finally:
            user_context.reset(context_token)

    def issue_session_cookie(response, token):
        max_age = settings.session_hours * 3600
        response.set_cookie(COOKIE, token, max_age=max_age, httponly=True, secure=settings.cookie_secure, samesite="strict", path="/")

    @app.get("/api/auth/state")
    def state(request: Request):
        session = automatic_session or session_for(request)
        if automatic_session:
            configured = True
        else:
            with database() as db:
                configured = bool(db.execute("SELECT 1 FROM users WHERE password_hash!='' AND active=1 LIMIT 1").fetchone())
        return {
            "auth_mode": settings.auth_mode,
            "authentication_required": settings.auth_mode == "password",
            "configured": configured,
            "setup_available": bool(settings.auth_mode == "password" and settings.allow_web_bootstrap and not configured),
            "authenticated": bool(session),
            "csrf_token": session["csrf_token"] if session else None,
            "user": safe_user(session) if session else None,
            "username": session["username"] if session else None,
        }

    @app.post("/api/auth/setup")
    def setup(payload: FirstAdmin, request: Request, response: Response):
        if settings.auth_mode != "password" or not settings.allow_web_bootstrap:
            raise HTTPException(404, "초기 설정을 사용할 수 없습니다.")
        origin_check(request)
        with database() as db:
            if db.execute("SELECT 1 FROM users WHERE password_hash!='' LIMIT 1").fetchone():
                raise HTTPException(409, "관리자 계정이 이미 설정되었습니다. 로그인하세요.")
            owner = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone()
            owner_id = owner["value"] if owner else None
            if not owner_id or not db.execute("SELECT 1 FROM users WHERE id=?", (owner_id,)).fetchone():
                raise HTTPException(503, "초기 계정 상태를 확인할 수 없습니다.")
        with credential_work():
            encoded = make_hash(payload.password)
        token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        timestamp = int(time.time())
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM users WHERE password_hash!='' LIMIT 1").fetchone():
                raise HTTPException(409, "관리자 계정이 이미 설정되었습니다. 로그인하세요.")
            try:
                db.execute(
                    "UPDATE users SET username=?,password_hash=?,role='admin',active=1,last_login_at=? WHERE id=?",
                    (payload.username, encoded, stamp(), owner_id),
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "이미 사용 중인 아이디입니다.") from None
            db.execute(
                "INSERT INTO meta(key,value) VALUES('admin_username',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (payload.username,),
            )
            db.execute(
                "INSERT INTO sessions(token_hash,csrf_token,expires_at,user_id) VALUES(?,?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), csrf,
                 timestamp + settings.session_hours * 3600, owner_id),
            )
            user = db.execute("SELECT * FROM users WHERE id=?", (owner_id,)).fetchone()
        issue_session_cookie(response, token)
        return {"authenticated": True, "csrf_token": csrf, "username": user["username"], "user": safe_user(user)}

    @app.post("/api/auth/login")
    def login(payload: Login, request: Request, response: Response):
        origin_check(request)
        client = login_client_address(request)
        # Cloudflare's verified visitor address separates unrelated users behind
        # the tunnel. Limit the visitor across every requested username so an
        # attacker cannot cycle invented names to obtain unlimited expensive
        # password-hash checks.
        client = hashlib.sha256(client.encode()).hexdigest()
        timestamp = int(time.time())
        attempt_row_id = None
        # Admit an attempt while holding the write lock, before doing the slow
        # password hash. Counting only after verification lets a concurrent
        # burst observe the same stale count and bypass the limit. A successful
        # login removes this provisional row; a crashed request conservatively
        # consumes one slot until the five-minute window expires.
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM login_attempts WHERE attempted_at<?", (timestamp - 300,))
            attempts = db.execute("SELECT COUNT(*) FROM login_attempts WHERE client=?", (client,)).fetchone()[0]
            user = db.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()
            configured = bool(db.execute("SELECT 1 FROM users WHERE password_hash!='' LIMIT 1").fetchone())
            if configured and attempts < 10:
                attempt_row_id = db.execute(
                    "INSERT INTO login_attempts VALUES(?,?)", (client, timestamp)
                ).lastrowid
        if attempts >= 10:
            raise HTTPException(429, "로그인 시도가 많습니다. 5분 후 다시 시도하세요.")
        if not configured:
            raise HTTPException(503, "관리자 초기 비밀번호가 설정되지 않았습니다. 서버 설정을 확인하세요.")
        with credential_work():
            valid = verify_hash(payload.password, user["password_hash"]) if user else False
        if not user or not user["active"] or not valid:
            raise HTTPException(401, "아이디와 비밀번호를 확인하세요.")
        # Serialize the final credential check and session insert with password
        # changes. A login that verified the old hash just before a password
        # change must never create a valid session after that change commits.
        token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        max_age = settings.session_hours * 3600
        raced = False
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
            if (not current or not current["active"] or
                    not hmac.compare_digest(current["password_hash"].encode(), user["password_hash"].encode()) or
                    not hmac.compare_digest(current["username"].encode(), payload.username.encode())):
                raced = True
            else:
                # Remove only this successful request's provisional admission.
                # Earlier failures remain effective, so knowing credentials for
                # one account cannot reset the visitor-wide brute-force/CPU
                # allowance before attacking another account.
                db.execute(
                    "DELETE FROM login_attempts WHERE rowid=? AND client=?",
                    (attempt_row_id, client),
                )
                db.execute("DELETE FROM sessions WHERE expires_at<=?", (timestamp,))
                db.execute("UPDATE users SET last_login_at=? WHERE id=?", (stamp(), user["id"]))
                db.execute("INSERT INTO sessions(token_hash,csrf_token,expires_at,user_id) VALUES(?,?,?,?)",
                           (hashlib.sha256(token.encode()).hexdigest(), csrf, timestamp + max_age, user["id"]))
                user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if raced:
            raise HTTPException(401, "The account credentials changed while signing in. Try again.")
        issue_session_cookie(response, token)
        return {"authenticated": True, "csrf_token": csrf, "username": user["username"], "user": safe_user(user)}

    @app.post("/api/auth/logout", dependencies=[Depends(require_auth)])
    def logout(request: Request, response: Response):
        with database() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=? AND user_id=?", (request.state.session["token_hash"], request.state.user["id"]))
        response.delete_cookie(COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
        return {"ok": True}

    def verified_current(user_id, password):
        with database() as db:
            row = db.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not row or not verify_hash(password, row["password_hash"]):
            raise HTTPException(400, "현재 비밀번호를 확인하세요.")
        return row

    @app.post("/api/auth/password", dependencies=[Depends(require_auth)])
    def password(payload: Password, request: Request):
        user_id = request.state.user["id"]
        with credential_work():
            previous = verified_current(user_id, payload.current_password)
            updated_hash = make_hash(payload.new_password)
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("UPDATE users SET password_hash=? WHERE id=? AND password_hash=? AND active=1",
                               (updated_hash, user_id, previous["password_hash"])).rowcount
            if count != 1:
                raise HTTPException(409, "계정 정보가 변경되었습니다. 다시 로그인해 확인하세요.")
        return {"ok": True, "csrf_token": request.state.session["csrf_token"]}

    @app.post("/api/auth/username", dependencies=[Depends(require_auth)])
    def username(payload: Username, request: Request):
        with credential_work():
            previous = verified_current(request.state.user["id"], payload.current_password)
        try:
            with database() as db:
                count = db.execute(
                    """UPDATE users SET username=?
                       WHERE id=? AND username=? AND password_hash=? AND active=1""",
                    (
                        payload.new_username,
                        previous["id"],
                        previous["username"],
                        previous["password_hash"],
                    ),
                ).rowcount
                if count != 1:
                    raise HTTPException(409, "계정 정보가 변경되었습니다. 다시 로그인해 확인하세요.")
        except sqlite3.IntegrityError:
            raise HTTPException(409, "이미 사용 중인 아이디입니다.") from None
        return {"ok": True, "username": payload.new_username, "csrf_token": request.state.session["csrf_token"]}

    @app.get("/api/admin/users", dependencies=[Depends(require_admin)])
    def users():
        with database() as db:
            rows = db.execute("SELECT * FROM users ORDER BY created_at,id").fetchall()
            provider_columns = {row[1] for row in db.execute("PRAGMA table_info(provider_accounts)")}
            result = []
            for row in rows:
                item = safe_user(row)
                item["workspace_count"] = db.execute("SELECT COUNT(*) FROM workspaces WHERE owner_user_id=?", (row["id"],)).fetchone()[0]
                item["account_count"] = db.execute("SELECT COUNT(*) FROM provider_accounts WHERE owner_user_id=?", (row["id"],)).fetchone()[0] if "owner_user_id" in provider_columns else 0
                summary = getattr(app.state, "telegram_user_summary", None)
                if callable(summary):
                    values = summary(row["id"])
                    for key in ("telegram_linked", "telegram_enabled", "telegram_last_success_at", "telegram_last_failure_at"):
                        if key in values:
                            item[key] = values[key]
                result.append(item)
        return {"users": result}

    @app.post("/api/admin/users", status_code=201, dependencies=[Depends(require_admin)])
    def create_user(payload: UserCreate):
        with credential_work():
            encoded = make_hash(payload.password)
        user_id = uuid.uuid4().hex
        try:
            with database() as db:
                db.execute("INSERT INTO users VALUES(?,?,?,?,1,?,NULL)", (user_id, payload.username, encoded, payload.role, stamp()))
                result = safe_user(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())
        except sqlite3.IntegrityError:
            raise HTTPException(409, "이미 사용 중인 아이디입니다.") from None
        return result

    @app.patch("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
    async def update_user(user_id: str, payload: UserUpdate, request: Request):
        became_inactive = False
        drain_inactive = False
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                raise HTTPException(404, "사용자를 찾을 수 없습니다.")
            active = int(payload.active) if payload.active is not None else row["active"]
            role = payload.role or row["role"]
            if user_id == request.state.user["id"] and not active:
                raise HTTPException(409, "자신의 계정은 비활성화할 수 없습니다.")
            if row["active"] and row["role"] == "admin" and (not active or role != "admin"):
                count = db.execute("SELECT COUNT(*) FROM users WHERE active=1 AND role='admin'").fetchone()[0]
                if count <= 1:
                    raise HTTPException(409, "활성 관리자 계정을 한 개 이상 유지해야 합니다.")
            became_inactive = bool(row["active"] and not active)
            # A retry of a timed-out deactivation must run the cancellation
            # barriers again instead of reporting success immediately.
            drain_inactive = bool(not active and payload.active is not None)
            db.execute("UPDATE users SET active=?,role=? WHERE id=?", (active, role, user_id))
            if became_inactive:
                # Reactivating the account must not revive cookies that were
                # issued before an administrator disabled it.
                db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            result = safe_user(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())
        if drain_inactive:
            # The database state is authoritative. Each service also validates
            # users.active before committing work; these hooks promptly wake or
            # interrupt in-flight operations after the transaction commits.
            incomplete = []
            for service_name in ("telegram", "solver_jobs", "ctfd_submit", "ctfd_jobs"):
                service = getattr(app.state, service_name, None)
                cancel_owner = getattr(service, "cancel_owner", None)
                if callable(cancel_owner):
                    try:
                        if inspect.iscoroutinefunction(cancel_owner):
                            stopped = await cancel_owner(user_id)
                        else:
                            stopped = await asyncio.to_thread(cancel_owner, user_id)
                        if stopped is False:
                            incomplete.append(service_name)
                    except Exception:
                        incomplete.append(service_name)
            if incomplete:
                raise HTTPException(
                    503,
                    "The account is disabled, but background work is still stopping. Retry shortly.",
                )
        return result

    @app.post("/api/admin/users/{user_id}/password", dependencies=[Depends(require_admin)])
    def reset_password(user_id: str, payload: UserPassword):
        with credential_work():
            encoded = make_hash(payload.password)
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("UPDATE users SET password_hash=? WHERE id=?", (encoded, user_id)).rowcount != 1:
                raise HTTPException(404, "사용자를 찾을 수 없습니다.")
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return {"ok": True}

    return require_auth, require_admin
