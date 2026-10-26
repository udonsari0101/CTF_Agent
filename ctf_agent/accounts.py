"""Authenticated account management endpoints; credential files never leave the server."""

import asyncio
import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from .providers.claude import ClaudeAccount
from .providers.claude_runtime import ClaudeRuntime
from .providers.codex import CodexAccount, ProviderError, public_login_state
from .providers.runtime import CodexRuntime
from .providers.auth_file import install_auth_file, validate_auth_file, MAX_AUTH_BYTES
from .process_lock import account_lifecycle_lock
from .storage_budget import get_storage_budget


class AccountCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["codex", "claude"]
    label: str = Field(min_length=1, max_length=100)


class AccountUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(default=None, min_length=1, max_length=100)
    model: str | None = Field(default=None, max_length=200)
    reasoning_effort: str | None = Field(default=None, max_length=40)
    service_tier: Literal["fast"] | None = None
    ultracode: bool = False


class VersionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=5, max_length=24)


class CodeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=1, max_length=4096)


class AccountManager:
    def __init__(self, settings, app=None):
        self.app = app
        self.database = Path(settings.database_path)
        self.home = Path(settings.config_dir) / "accounts"
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.home.chmod(0o700)
        budget = None
        if app is not None and getattr(app.state, "connect", None) is not None:
            budget = get_storage_budget(app, settings)
        self.runtime = CodexRuntime(Path(settings.data_dir) / "runtime", budget)
        self.claude_runtime = ClaudeRuntime(Path(settings.data_dir) / "claude-runtime", budget)
        self.adapters = {}
        self.locks = {}
        self.lifecycle_lock = asyncio.Lock()
        # A pending interactive login retains the same cross-process lease
        # which solver enqueue must acquire.  The lease is released only after
        # the provider ceremony reaches a terminal state or is cancelled.
        self.pending_lifecycle_leases = {}
        # A Codex account adapter owns a Node app-server process while it is
        # serving a request.  Account limits are intentionally much larger
        # than the web container's process/memory budget, so cap short-lived
        # account probes independently of the number of registered accounts.
        # Up to two additional processes may be retained for interactive
        # login ceremonies (one per user) as bounded below.
        self.cli_gate = asyncio.Semaphore(4)
        self.active_cli_accounts: dict[str, int] = {}
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS provider_accounts (
                    id TEXT PRIMARY KEY, provider TEXT NOT NULL, label TEXT NOT NULL,
                    selected INTEGER NOT NULL DEFAULT 0, model TEXT, reasoning_effort TEXT,
                    snapshot TEXT, checked_at REAL, created_at REAL NOT NULL,
                    owner_user_id TEXT NOT NULL DEFAULT 'legacy', service_tier TEXT,
                    ultracode INTEGER NOT NULL DEFAULT 0 CHECK(ultracode IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS account_lifecycle_blocks (
                    owner_user_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    started_at REAL NOT NULL
                );
            """)
            has_meta = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
            legacy = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone() if has_meta else None
            self.legacy_owner_id = legacy[0] if legacy else "legacy"
            columns = {row[1] for row in db.execute("PRAGMA table_info(provider_accounts)")}
            if "owner_user_id" not in columns:
                db.execute("ALTER TABLE provider_accounts ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT 'legacy'")
            if "service_tier" not in columns:
                db.execute("ALTER TABLE provider_accounts ADD COLUMN service_tier TEXT")
            if "ultracode" not in columns:
                db.execute("ALTER TABLE provider_accounts ADD COLUMN ultracode INTEGER NOT NULL DEFAULT 0 CHECK(ultracode IN (0,1))")
            db.execute("UPDATE provider_accounts SET reasoning_effort='xhigh',ultracode=1 WHERE provider='claude' AND reasoning_effort='ultracode'")
            db.execute("UPDATE provider_accounts SET owner_user_id=? WHERE owner_user_id='legacy'", (self.legacy_owner_id,))
            db.execute("DROP INDEX IF EXISTS one_selected_account_per_provider")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_selected_account_per_owner_provider ON provider_accounts(owner_user_id,provider) WHERE selected=1")
            if has_meta:
                db.execute("INSERT INTO meta(key,value) VALUES('accounts_schema_version','3') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        self._recover_lifecycle_blocks()
        self._cleanup_deleted_account_dirs()

    def _cleanup_deleted_account_dirs(self):
        """Best-effort cleanup for unreachable account directories."""

        with self.connect() as db:
            live = {row[0] for row in db.execute("SELECT id FROM provider_accounts")}
        for path in self.home.iterdir():
            tombstone = re.fullmatch(r"\.deleted-[0-9a-f]{32}-[0-9a-f]{32}", path.name)
            orphan = re.fullmatch(r"[0-9a-f]{32}", path.name) and path.name not in live
            if not tombstone and not orphan:
                continue
            try:
                if path.is_symlink():
                    path.unlink()
                elif path.is_dir() and path.resolve().parent == self.home.resolve():
                    shutil.rmtree(path)
            except OSError:
                # No live account row references this path. Retry next startup.
                pass

    def _recover_lifecycle_blocks(self):
        """Remove only markers whose owning process lease is no longer held."""

        with self.connect() as db:
            rows = db.execute(
                "SELECT owner_user_id FROM account_lifecycle_blocks"
            ).fetchall()
        for row in rows:
            owner_id = row["owner_user_id"]
            lease = account_lifecycle_lock(self.home, owner_id)
            if not lease.try_acquire():
                continue
            try:
                with self.connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "DELETE FROM account_lifecycle_blocks WHERE owner_user_id=?",
                        (owner_id,),
                    )
            finally:
                lease.release()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def owner(self, owner_id):
        if owner_id is None and self.legacy_owner_id == "legacy":
            return "legacy"  # Standalone tests without an application user database.
        if not isinstance(owner_id, str) or not owner_id:
            raise HTTPException(401, "계정 소유자 인증이 필요합니다.")
        return owner_id

    def get(self, account_id, owner_id=None):
        owner_id = self.owner(owner_id)
        with self.connect() as db:
            row = db.execute("SELECT * FROM provider_accounts WHERE id = ? AND owner_user_id=?", (account_id, owner_id)).fetchone()
        if not row:
            raise HTTPException(404, "계정을 찾을 수 없습니다.")
        result = dict(row)
        result["selected"] = bool(result["selected"])
        result["ultracode"] = bool(result["ultracode"])
        result["snapshot"] = json.loads(result["snapshot"]) if result["snapshot"] else None
        result["stale"] = result["checked_at"] is None or time.time() - result["checked_at"] > 300
        adapter = self.adapters.get(account_id)
        result["login"] = public_login_state(adapter.login) if adapter else {"status": "idle"}
        return result

    def listing(self, owner_id=None):
        owner_id = self.owner(owner_id)
        with self.connect() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM provider_accounts WHERE owner_user_id=? ORDER BY created_at", (owner_id,))]
        return {"accounts": [self.get(account_id, owner_id) for account_id in ids]}

    async def models(self, account_id, owner_id=None):
        """Return the account catalog plus documented ChatGPT Fast support.

        Some Codex app-server releases omit ``serviceTiers`` even though the
        signed-in ChatGPT client supports the documented Fast configuration.
        Fill that protocol gap only for authenticated ChatGPT accounts and
        exact GPT-5.5/5.6 family models. API-key priority processing has
        different billing and therefore keeps the unmodified returned catalog.
        """
        account = self.get(account_id, owner_id)
        async with self.transient_adapter(account_id, owner_id) as adapter:
            response = await adapter.models()
        if response.get("status") != "available" or account["provider"] != "codex":
            return response
        identity = ((account.get("snapshot") or {}).get("identity") or {})
        account_type = re.sub(r"[^a-z]", "", str(identity.get("type", "")).lower())
        if account_type != "chatgpt":
            return response
        models = []
        for original in response.get("models", []):
            item = dict(original)
            model_id = str(item.get("model") or item.get("id") or "").lower()
            tiers = [dict(tier) for tier in (item.get("serviceTiers") or []) if isinstance(tier, dict)]
            if re.fullmatch(r"gpt-5\.(?:5|6)(?:-[a-z0-9.-]+)?", model_id) and not any(tier.get("id") == "fast" for tier in tiers):
                tiers.append({
                    "id": "fast",
                    "name": "1.5배 Fast",
                    "description": "ChatGPT Fast 모드: 응답 속도 1.5배, Standard 대비 크레딧 2.5배 사용",
                    "source": "official_documentation",
                })
            item["serviceTiers"] = tiers
            models.append(item)
        return {**response, "models": models}

    def create(self, provider, label, owner_id=None):
        owner_id = self.owner(owner_id)
        label = label.strip()
        if not label:
            raise HTTPException(422, "계정 이름을 입력해 주세요.")
        account_id = uuid.uuid4().hex
        with self.connect() as db:
            # Serialize the per-owner cap and initial-selection decision. A
            # deferred read followed by an insert can otherwise fail with
            # SQLITE_BUSY under concurrent account creation, or let both
            # callers decide that they are the first selected account.
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM provider_accounts WHERE owner_user_id=?", (owner_id,)).fetchone()[0] >= 50:
                raise HTTPException(409, "계정은 최대 50개까지 등록할 수 있습니다.")
            selected = not db.execute("SELECT 1 FROM provider_accounts WHERE owner_user_id=? AND provider=? AND selected=1", (owner_id, provider)).fetchone()
            db.execute("INSERT INTO provider_accounts(id,provider,label,selected,created_at,owner_user_id) VALUES(?,?,?,?,?,?)",
                       (account_id, provider, label, int(selected), time.time(), owner_id))
        return self.get(account_id, owner_id)

    def adapter(self, account_id, owner_id=None):
        account = self.get(account_id, owner_id)
        if account_id not in self.adapters:
            home = self.home / account_id
            preferences = {key: account.get(key) for key in ("model", "reasoning_effort", "service_tier")}
            self.adapters[account_id] = CodexAccount(home, self.runtime.command(), preferences) if account["provider"] == "codex" else ClaudeAccount(home, self.claude_runtime.command)
        return self.adapters[account_id]

    def lock(self, account_id):
        return self.locks.setdefault(account_id, asyncio.Lock())

    @asynccontextmanager
    async def transient_adapter(self, account_id, owner_id=None):
        """Lease an adapter for a bounded probe and stop its process after use.

        Adapter objects stay cached so their public login state and lightweight
        test doubles remain stable, but successful refresh/model requests must
        not leave one app-server process behind for every registered account.
        """
        async with self.cli_gate:
            adapter = self.adapter(account_id, owner_id)
            self.active_cli_accounts[account_id] = self.active_cli_accounts.get(account_id, 0) + 1
            try:
                yield adapter
            finally:
                remaining = self.active_cli_accounts.get(account_id, 1) - 1
                if remaining > 0:
                    self.active_cli_accounts[account_id] = remaining
                else:
                    self.active_cli_accounts.pop(account_id, None)
                    if adapter.login.get("status") not in ("starting", "pending"):
                        try:
                            await adapter.close()
                        except Exception:
                            # Probe results/errors are more useful than a
                            # secondary process-cleanup failure. Application
                            # shutdown makes a final best-effort close too.
                            pass

    async def reap_idle_adapters(self, exclude_account_id=None):
        """Stop completed/idle provider processes before another login."""
        for account_id in list(self.adapters):
            if account_id == exclude_account_id:
                continue
            async with self.lock(account_id):
                adapter = self.adapters.get(account_id)
                if (adapter is None or self.active_cli_accounts.get(account_id)
                        or adapter.login.get("status") in ("starting", "pending")):
                    continue
                try:
                    await adapter.close()
                except Exception:
                    pass

    async def refresh(self, account_id, owner_id=None):
        async with self.lock(account_id):
            previous = self.get(account_id, owner_id).get("snapshot") or {}
            try:
                async with self.transient_adapter(account_id, owner_id) as adapter:
                    snapshot = await adapter.snapshot()
                quota = snapshot.get("quota", {})
                old_quota = previous.get("quota", {})
                if (snapshot.get("status") == "authenticated" and previous.get("identity") == snapshot.get("identity")
                        and quota.get("status") != "available" and old_quota.get("buckets")):
                    snapshot["quota"] = {**old_quota, "status": quota.get("status"),
                                         "message": quota.get("message"), "error": quota.get("error"), "stale": True}
            except ProviderError as exc:
                snapshot = {"status": exc.code, "message": str(exc), "identity": previous.get("identity"),
                            "error": exc.public(), "quota": previous.get("quota", {"status": "unavailable", "buckets": []})}
                snapshot["quota"]["stale"] = True
            checked_at = time.time()
            with self.connect() as db:
                db.execute("UPDATE provider_accounts SET snapshot=?,checked_at=? WHERE id=?",
                           (json.dumps(snapshot), checked_at, account_id))
            return self.get(account_id, owner_id)

    async def select(self, account_id, owner_id=None):
        owner_id = self.owner(owner_id)
        with self.connect() as db:
            # Re-read ownership inside the same write transaction that changes
            # the selection. This closes select-vs-delete: a stale preflight
            # must not clear the owner's only selected account after its target
            # has already been removed.
            db.execute("BEGIN IMMEDIATE")
            account = db.execute(
                "SELECT provider FROM provider_accounts WHERE id=? AND owner_user_id=?",
                (account_id, owner_id),
            ).fetchone()
            if not account:
                raise HTTPException(404, "계정을 찾을 수 없습니다.")
            db.execute(
                "UPDATE provider_accounts SET selected=0 WHERE provider=? AND owner_user_id=?",
                (account["provider"], owner_id),
            )
            db.execute(
                "UPDATE provider_accounts SET selected=1 WHERE id=? AND owner_user_id=?",
                (account_id, owner_id),
            )
        return self.get(account_id, owner_id)

    async def update(self, account_id, values, owner_id=None):
        account = self.get(account_id, owner_id)
        if "label" in values and (not values["label"] or not values["label"].strip()):
            raise HTTPException(422, "계정 이름을 입력해 주세요.")
        if any(key in values for key in ("model", "reasoning_effort", "service_tier", "ultracode")):
            adapter = self.adapter(account_id, owner_id)
            if adapter.login.get("status") in ("starting", "pending"):
                raise ProviderError("로그인을 마친 뒤 모델 설정을 변경해 주세요.", "busy", stage="model")
            response = await self.models(account_id, owner_id)
            if response.get("status") != "available":
                raise ProviderError("이 공급자는 모델 목록 조회를 지원하지 않습니다.", "unsupported")
            model = values.get("model", account["model"])
            effort = values.get("reasoning_effort", account["reasoning_effort"])
            tier = values.get("service_tier", account["service_tier"])
            ultracode = values.get("ultracode", account["ultracode"] if model == account["model"] else False)
            if model != account["model"] and "ultracode" not in values:
                values["ultracode"] = False
            if model:
                chosen = next((item for item in response["models"] if model in (item.get("id"), item.get("model"))), None)
                if not chosen:
                    raise HTTPException(422, "이 계정에서 선택할 수 없는 모델입니다.")
                efforts = [item.get("reasoningEffort") for item in (chosen.get("supportedReasoningEfforts") or [])]
                if effort and effort not in efforts:
                    raise HTTPException(422, "선택한 모델에서 지원하지 않는 추론 수준입니다.")
                if tier and tier not in [item.get("id") for item in (chosen.get("serviceTiers") or [])]:
                    raise HTTPException(422, "이 계정과 모델에서 Fast 지원을 확인할 수 없습니다.")
                if ultracode and (account["provider"] != "claude" or chosen.get("supportsUltracode") is not True):
                    raise HTTPException(422, "이 Claude 모델에서는 Ultracode를 사용할 수 없습니다.")
            elif effort or tier or ultracode:
                raise HTTPException(422, "모델을 먼저 선택해 주세요.")
        if values:
            keys = [key for key in ("label", "model", "reasoning_effort", "service_tier", "ultracode") if key in values]
            with self.connect() as db:
                db.execute(f"UPDATE provider_accounts SET {','.join(key + '=?' for key in keys)} WHERE id=?",
                           (*[values[key].strip() if isinstance(values[key], str) else values[key] for key in keys], account_id))
            if any(key in values for key in ("model", "reasoning_effort", "service_tier", "ultracode")) and account_id in self.adapters:
                await self.adapters.pop(account_id).close()
        return self.get(account_id, owner_id)

    def no_login_in_progress(self, exclude_account_id=None):
        if any(account_id != exclude_account_id and adapter.login.get("status") in ("starting", "pending")
               for account_id, adapter in self.adapters.items()):
            raise ProviderError("계정 로그인을 완료하거나 취소한 뒤 업데이트해 주세요.", "busy")

    def require_login_slot(self, account_id, owner_id):
        """Allow one pending login per user and at most two per web instance."""
        owner_id = self.owner(owner_id)
        pending_ids = [candidate for candidate, adapter in self.adapters.items()
                       if candidate != account_id and adapter.login.get("status") in ("starting", "pending")]
        if not pending_ids:
            return
        placeholders = ",".join("?" for _ in pending_ids)
        with self.connect() as db:
            rows = db.execute(
                f"SELECT id,owner_user_id FROM provider_accounts WHERE id IN ({placeholders})",
                pending_ids,
            ).fetchall()
        if any(row["owner_user_id"] == owner_id for row in rows):
            raise ProviderError("진행 중인 다른 계정 로그인을 먼저 완료하거나 취소해 주세요.", "busy", stage="auth")
        if len(rows) >= 2:
            raise ProviderError("동시에 진행할 수 있는 계정 로그인 수에 도달했습니다. 잠시 후 다시 시도해 주세요.", "busy", stage="auth")

    def require_solver_idle(self, account_id, owner_id=None):
        owner_id = self.owner(owner_id)
        solver = getattr(getattr(self.app, "state", None), "solver_jobs", None)
        if solver is not None and solver.has_open_account(owner_id, account_id):
            raise ProviderError(
                "이 계정으로 대기 또는 실행 중인 풀이를 먼저 중단하고 격리 정리가 끝날 때까지 기다려 주세요.",
                "busy",
                stage="auth",
            )

    def _solver_idle_in_transaction(self, db, account_id, owner_id):
        """Recheck account ownership and solver state under the enqueue writer lock."""

        account = db.execute(
            "SELECT * FROM provider_accounts WHERE id=? AND owner_user_id=?",
            (account_id, owner_id),
        ).fetchone()
        if not account:
            raise HTTPException(404, "계정을 찾을 수 없습니다.")
        solver = getattr(getattr(self.app, "state", None), "solver_jobs", None)
        if solver is not None and solver.has_open_account(
            owner_id, account_id, connection=db
        ):
            raise ProviderError(
                "이 계정으로 대기 또는 실행 중인 풀이를 먼저 중단하고 격리 정리가 끝날 때까지 기다려 주세요.",
                "busy",
                stage="auth",
            )
        return dict(account)

    def _take_lifecycle_lease(self, account_id, owner_id, *, reuse_pending=False):
        """Acquire the owner lease shared with solver enqueue without waiting."""

        owner_id = self.owner(owner_id)
        pending = self.pending_lifecycle_leases.get(owner_id)
        if pending is not None:
            if not reuse_pending or pending["account_id"] != account_id:
                raise ProviderError(
                    "이 계정의 인증 작업이 진행 중입니다. 완료하거나 취소한 뒤 다시 시도해 주세요.",
                    "busy",
                    stage="auth",
                )
            self.pending_lifecycle_leases.pop(owner_id, None)
            watcher = pending.get("watcher")
            if watcher is not None and watcher is not asyncio.current_task():
                watcher.cancel()
            return owner_id, pending["lease"], pending.get("previous")
        lease = account_lifecycle_lock(self.home, owner_id)
        if not lease.try_acquire():
            raise ProviderError(
                "이 계정의 인증 작업이 다른 서버 프로세스에서 진행 중입니다. 잠시 후 다시 시도해 주세요.",
                "busy",
                stage="auth",
            )
        return owner_id, lease, None

    def _begin_lifecycle_mutation(
        self,
        account_id,
        owner_id,
        *,
        reuse_pending=False,
        mark_authenticating=False,
    ):
        """Take the process lease and order the final idle check with enqueue."""

        owner_id, lease, pending_previous = self._take_lifecycle_lease(
            account_id, owner_id, reuse_pending=reuse_pending
        )
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                account = self._solver_idle_in_transaction(db, account_id, owner_id)
                previous = (
                    pending_previous
                    if pending_previous is not None
                    else (account.get("snapshot"), account.get("checked_at"))
                )
                db.execute(
                    """INSERT INTO account_lifecycle_blocks(owner_user_id,account_id,started_at)
                       VALUES(?,?,?) ON CONFLICT(owner_user_id) DO UPDATE SET
                       account_id=excluded.account_id,started_at=excluded.started_at""",
                    (owner_id, account_id, time.time()),
                )
                if mark_authenticating:
                    transitional = {
                        "status": "authenticating",
                        "identity": None,
                        "quota": {
                            "status": "unavailable",
                            "buckets": [],
                            "stale": True,
                        },
                    }
                    db.execute(
                        "UPDATE provider_accounts SET snapshot=?,checked_at=? "
                        "WHERE id=? AND owner_user_id=?",
                        (json.dumps(transitional), time.time(), account_id, owner_id),
                    )
            return account, owner_id, lease, previous
        except BaseException:
            self._release_lifecycle_lease(owner_id, lease)
            raise

    def _release_lifecycle_lease(self, owner_id, lease):
        """Publish lifecycle completion before allowing another enqueue."""

        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "DELETE FROM account_lifecycle_blocks WHERE owner_user_id=?",
                    (owner_id,),
                )
        finally:
            lease.release()

    def _restore_snapshot(self, account_id, owner_id, previous):
        if previous is None:
            return
        snapshot, checked_at = previous
        with self.connect() as db:
            db.execute(
                "UPDATE provider_accounts SET snapshot=?,checked_at=? "
                "WHERE id=? AND owner_user_id=?",
                (snapshot, checked_at, account_id, owner_id),
            )

    def _finish_pending_lifecycle(self, owner_id, record, *, restore=False):
        if self.pending_lifecycle_leases.get(owner_id) is not record:
            return
        self.pending_lifecycle_leases.pop(owner_id, None)
        try:
            if restore:
                self._restore_snapshot(record["account_id"], owner_id, record.get("previous"))
            else:
                # A completed ceremony is verified by the normal refresh route.
                # Failed/expired ceremonies likewise remain non-runnable until
                # a fresh provider snapshot has been obtained.
                with self.connect() as db:
                    db.execute(
                        "UPDATE provider_accounts SET snapshot=?,checked_at=? "
                        "WHERE id=? AND owner_user_id=?",
                        (
                            json.dumps({
                                "status": "login_verification_required",
                                "identity": None,
                                "quota": {"status": "unavailable", "buckets": [], "stale": True},
                            }),
                            time.time(),
                            record["account_id"],
                            owner_id,
                        ),
                    )
        finally:
            self._release_lifecycle_lease(owner_id, record["lease"])

    async def _watch_login_lifecycle(self, owner_id, record):
        try:
            while record["adapter"].login.get("status") in ("starting", "pending"):
                await asyncio.sleep(0.1)
            self._finish_pending_lifecycle(owner_id, record)
        except asyncio.CancelledError:
            # The operation taking over this record owns and releases the lease.
            return

    def _retain_login_lease(self, account_id, owner_id, lease, previous, adapter):
        record = {
            "account_id": account_id,
            "lease": lease,
            "previous": previous,
            "adapter": adapter,
            "watcher": None,
        }
        self.pending_lifecycle_leases[owner_id] = record
        record["watcher"] = asyncio.create_task(
            self._watch_login_lifecycle(owner_id, record),
            name=f"account-login-lifecycle-{account_id}",
        )
        return record

    async def reset_codex(self):
        for account_id in list(self.adapters):
            async with self.lock(account_id):
                if isinstance(self.adapters.get(account_id), CodexAccount):
                    await self.adapters.pop(account_id).close()

    async def reset_claude(self):
        for account_id in list(self.adapters):
            async with self.lock(account_id):
                if isinstance(self.adapters.get(account_id), ClaudeAccount):
                    await self.adapters.pop(account_id).close()

    async def start_login(self, account_id, owner_id=None):
        async with self.lifecycle_lock:
            await self.reap_idle_adapters(exclude_account_id=account_id)
            async with self.lock(account_id):
                owner_id = self.owner(owner_id)
                existing = self.pending_lifecycle_leases.get(owner_id)
                reuse_pending = bool(
                    existing is not None
                    and existing["account_id"] == account_id
                    and existing["adapter"].login.get("status") in ("starting", "pending")
                )
                if existing is not None and existing["account_id"] == account_id and not reuse_pending:
                    self._finish_pending_lifecycle(owner_id, existing)
                self.require_login_slot(account_id, owner_id)
                _account, owner_id, lease, previous = self._begin_lifecycle_mutation(
                    account_id, owner_id, reuse_pending=reuse_pending, mark_authenticating=True
                )
                adapter = None
                retained = False
                try:
                    provider_runtime = self.runtime if _account["provider"] == "codex" else self.claude_runtime
                    if provider_runtime.busy:
                        raise ProviderError("Codex 업데이트가 끝난 뒤 로그인해 주세요.", "busy")
                    adapter = self.adapter(account_id, owner_id)
                    async with self.cli_gate:
                        result = public_login_state(await adapter.start_login())
                    if adapter.login.get("status") in ("starting", "pending"):
                        self._retain_login_lease(
                            account_id, owner_id, lease, previous, adapter
                        )
                        retained = True
                    return result
                except BaseException:
                    self._restore_snapshot(account_id, owner_id, previous)
                    raise
                finally:
                    if not retained:
                        if adapter is not None and adapter.login.get("status") not in ("starting", "pending"):
                            await adapter.close()
                        self._release_lifecycle_lease(owner_id, lease)

    async def login_status(self, account_id, owner_id=None):
        async with self.lifecycle_lock, self.lock(account_id):
            owner_id = self.owner(owner_id)
            adapter = self.adapter(account_id, owner_id)
            result = public_login_state(adapter.login)
            record = self.pending_lifecycle_leases.get(owner_id)
            if (record is not None and record["account_id"] == account_id
                    and adapter.login.get("status") not in ("starting", "pending")):
                self._finish_pending_lifecycle(owner_id, record)
            return result

    async def cancel_account_login(self, account_id, owner_id=None):
        async with self.lifecycle_lock, self.lock(account_id):
            _account, owner_id, lease, previous = self._begin_lifecycle_mutation(
                account_id, owner_id, reuse_pending=True
            )
            try:
                adapter = self.adapter(account_id, owner_id)
                async with self.cli_gate:
                    result = await adapter.cancel_login()
                self._restore_snapshot(account_id, owner_id, previous)
                return result
            finally:
                self._release_lifecycle_lease(owner_id, lease)

    async def submit_login_code(self, account_id, code, owner_id=None):
        async with self.lifecycle_lock, self.lock(account_id):
            owner_id = self.owner(owner_id)
            record = self.pending_lifecycle_leases.get(owner_id)
            if record is None or record["account_id"] != account_id:
                raise ProviderError("진행 중인 로그인이 없습니다.", "login_missing", stage="auth")
            adapter = self.adapter(account_id, owner_id)
            if not isinstance(adapter, ClaudeAccount):
                raise ProviderError("이 계정은 웹 코드 입력을 사용하지 않습니다.", "unsupported")
            async with self.cli_gate:
                return await adapter.submit_code(code)

    async def logout(self, account_id, owner_id=None):
        async with self.lifecycle_lock, self.lock(account_id):
            account, owner_id, lease, _previous = self._begin_lifecycle_mutation(
                account_id, owner_id, reuse_pending=True, mark_authenticating=True
            )
            adapter = None
            try:
                adapter = self.adapter(account_id, owner_id)
                async with self.cli_gate:
                    await adapter.cancel_login()
                    if isinstance(adapter, CodexAccount):
                        await adapter.request("account/logout")
                    else:
                        await adapter.logout()
                snapshot = {"status": "signed_out", "identity": None,
                            "quota": {"status": "unauthenticated", "buckets": [], "checked_at": time.time()}}
                with self.connect() as db:
                    db.execute(
                        "UPDATE provider_accounts SET snapshot=?,checked_at=? WHERE id=? AND owner_user_id=?",
                        (json.dumps(snapshot), time.time(), account_id, owner_id),
                    )
            except BaseException:
                # Provider logout may have removed credentials before reporting
                # an error. Keep the account non-runnable until refresh verifies
                # the resulting state.
                with self.connect() as db:
                    db.execute(
                        "UPDATE provider_accounts SET snapshot=?,checked_at=? WHERE id=? AND owner_user_id=?",
                        (
                            json.dumps({
                                "status": "auth_state_unknown",
                                "identity": None,
                                "quota": {"status": "unavailable", "buckets": [], "stale": True},
                            }),
                            time.time(), account_id, owner_id,
                        ),
                    )
                raise
            finally:
                try:
                    if adapter is not None:
                        await adapter.close()
                        self.adapters.pop(account_id, None)
                finally:
                    self._release_lifecycle_lease(owner_id, lease)
            return self.get(account_id, owner_id)

    async def delete(self, account_id, owner_id=None):
        async with self.lifecycle_lock, self.lock(account_id):
            if not re.fullmatch(r"[0-9a-f]{32}", account_id):
                raise HTTPException(400, "잘못된 계정 식별자입니다.")
            account, owner_id, lease, _previous = self._begin_lifecycle_mutation(
                account_id, owner_id, reuse_pending=True
            )
            directory = self.home / account_id
            tombstone = self.home / f".deleted-{account_id}-{uuid.uuid4().hex}"
            try:
                if directory.is_symlink() or directory.resolve().parent != self.home.resolve():
                    raise HTTPException(400, "잘못된 계정 저장 경로입니다.")
                adapter = self.adapters.get(account_id)
                if adapter:
                    await adapter.cancel_login()
                    await adapter.close()
                    self.adapters.pop(account_id, None)
                with self.connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    current = self._solver_idle_in_transaction(db, account_id, owner_id)
                    selected = bool(current["selected"])
                    provider = current["provider"]
                    db.execute(
                        "DELETE FROM provider_accounts WHERE id=? AND owner_user_id=?",
                        (account_id, owner_id),
                    )
                    if selected:
                        db.execute(
                            """UPDATE provider_accounts SET selected=1 WHERE id=(
                               SELECT id FROM provider_accounts WHERE provider=? AND owner_user_id=?
                               ORDER BY created_at,id LIMIT 1)""",
                            (provider, owner_id),
                        )
                moved = False
                if directory.exists():
                    try:
                        directory.rename(tombstone)
                        moved = True
                    except OSError:
                        # The row is already gone, so the canonical UUID path is
                        # unreachable and a later startup safely treats it as an
                        # orphan even when the atomic rename itself failed.
                        pass
                if moved:
                    try:
                        shutil.rmtree(tombstone)
                    except OSError:
                        # Startup cleanup retries this unreachable private tombstone.
                        pass
                # Keep the one-selected-account invariant even if another
                # process changed selection while slow filesystem cleanup ran.
                with self.connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    if not db.execute(
                        "SELECT 1 FROM provider_accounts WHERE owner_user_id=? AND provider=? AND selected=1",
                        (owner_id, provider),
                    ).fetchone():
                        db.execute(
                            """UPDATE provider_accounts SET selected=1 WHERE id=(
                               SELECT id FROM provider_accounts WHERE owner_user_id=? AND provider=?
                               ORDER BY created_at,id LIMIT 1)""",
                            (owner_id, provider),
                        )
                return {"ok": True}
            finally:
                self._release_lifecycle_lease(owner_id, lease)

    async def import_auth(self, account_id, raw: bytes, owner_id=None):
        account = self.get(account_id, owner_id)
        if account["provider"] != "codex":
            raise ProviderError("auth.json 업로드는 Codex 계정에서만 지원합니다.", "unsupported", stage="auth")
        validated = validate_auth_file(raw)
        async with self.lifecycle_lock, self.lock(account_id):
            account, owner_id, lease, previous = self._begin_lifecycle_mutation(
                account_id, owner_id, reuse_pending=True, mark_authenticating=True
            )
            if self.runtime.busy:
                self._restore_snapshot(account_id, owner_id, previous)
                self._release_lifecycle_lease(owner_id, lease)
                raise ProviderError("Codex 업데이트가 끝난 뒤 업로드해 주세요.", "busy", stage="auth")
            adapter = None
            try:
                adapter = self.adapter(account_id, owner_id)
                def save_snapshot(snapshot):
                    with self.connect() as db:
                        db.execute(
                            "UPDATE provider_accounts SET snapshot=?,checked_at=? WHERE id=? AND owner_user_id=?",
                            (json.dumps(snapshot), time.time(), account_id, owner_id),
                        )
                async with self.cli_gate:
                    await install_auth_file(adapter, validated, self.home, save_snapshot)
            except (OSError, sqlite3.Error):
                self._restore_snapshot(account_id, owner_id, previous)
                raise ProviderError("인증 파일 저장에 실패했습니다. 기존 인증 정보는 보존됩니다.", "auth_storage_error", stage="auth") from None
            except BaseException:
                self._restore_snapshot(account_id, owner_id, previous)
                raise
            finally:
                try:
                    if adapter is not None:
                        await adapter.close()
                        self.adapters.pop(account_id, None)
                finally:
                    self._release_lifecycle_lease(owner_id, lease)
            return self.get(account_id, owner_id)

    async def close(self):
        records = list(self.pending_lifecycle_leases.items())
        for _owner_id, record in records:
            watcher = record.get("watcher")
            if watcher is not None:
                watcher.cancel()
        await asyncio.gather(
            *(record["watcher"] for _owner_id, record in records if record.get("watcher") is not None),
            return_exceptions=True,
        )
        for owner_id, record in records:
            self._finish_pending_lifecycle(owner_id, record, restore=True)
        await self.runtime.close()
        await self.claude_runtime.close()
        await asyncio.gather(*(adapter.close() for adapter in self.adapters.values()), return_exceptions=True)


def register_accounts(app, require_auth, settings):
    manager = AccountManager(settings, app)
    app.state.accounts = manager
    router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

    def current_user(user=Depends(require_auth)):
        if isinstance(user, dict) and isinstance(user.get("id"), str) and user["id"]:
            return user
        # Compatibility for the former single-admin app; never accepted once users exist.
        if user == "admin" and manager.legacy_owner_id == "legacy":
            return {"id": "legacy", "role": "admin"}
        raise HTTPException(401, "로그인이 필요합니다.")

    def fallback_admin(user=Depends(current_user)):
        if user.get("role") != "admin":
            raise HTTPException(403, "관리자 권한이 필요합니다.")
        return user

    require_admin = getattr(app.state, "require_admin", fallback_admin)

    @app.exception_handler(ProviderError)
    async def provider_error(_request, exception):
        from fastapi.responses import JSONResponse
        status = 409 if exception.code == "busy" else 422 if exception.code.startswith("invalid_") else 503
        return JSONResponse({"detail": str(exception), **exception.public()}, status_code=status)

    @router.get("/accounts")
    async def list_accounts(user=Depends(current_user)):
        return manager.listing(user["id"])

    @router.post("/accounts", status_code=201)
    async def create_account(body: AccountCreate, user=Depends(current_user)):
        return manager.create(body.provider, body.label, user["id"])

    @router.get("/accounts/{account_id}")
    async def get_account(account_id: str, user=Depends(current_user)):
        return manager.get(account_id, user["id"])

    @router.patch("/accounts/{account_id}")
    async def update_account(account_id: str, body: AccountUpdate, user=Depends(current_user)):
        async with manager.lock(account_id):
            return await manager.update(account_id, body.model_dump(exclude_unset=True), user["id"])

    @router.delete("/accounts/{account_id}")
    async def delete_account(account_id: str, user=Depends(current_user)):
        return await manager.delete(account_id, user["id"])

    @router.post("/accounts/{account_id}/select")
    async def select_account(account_id: str, user=Depends(current_user)):
        return await manager.select(account_id, user["id"])

    @router.post("/accounts/{account_id}/refresh")
    async def refresh_account(account_id: str, user=Depends(current_user)):
        return await manager.refresh(account_id, user["id"])

    @router.get("/accounts/{account_id}/models")
    async def models(account_id: str, user=Depends(current_user)):
        async with manager.lock(account_id):
            return await manager.models(account_id, user["id"])

    @router.post("/accounts/{account_id}/login")
    async def start_login(account_id: str, user=Depends(current_user)):
        return await manager.start_login(account_id, user["id"])

    @router.get("/accounts/{account_id}/login")
    async def login_status(account_id: str, user=Depends(current_user)):
        return await manager.login_status(account_id, user["id"])

    @router.post("/accounts/{account_id}/login/cancel")
    async def cancel_login(account_id: str, user=Depends(current_user)):
        return await manager.cancel_account_login(account_id, user["id"])

    @router.post("/accounts/{account_id}/login/code")
    async def login_code(account_id: str, body: CodeInput, user=Depends(current_user)):
        return await manager.submit_login_code(account_id, body.code, user["id"])

    @router.post("/accounts/{account_id}/logout")
    async def logout(account_id: str, user=Depends(current_user)):
        return await manager.logout(account_id, user["id"])

    @router.post("/accounts/{account_id}/auth-file")
    async def upload_auth(account_id: str, file: UploadFile = File(...), user=Depends(current_user)):
        try:
            manager.get(account_id, user["id"])
            if file.filename != "auth.json":
                raise ProviderError("Codex에서 생성한 auth.json 파일을 선택해 주세요.", "invalid_auth_file", stage="auth")
            raw = await file.read(MAX_AUTH_BYTES + 1)
            if len(raw) > MAX_AUTH_BYTES:
                raise HTTPException(413, "auth.json은 2MiB까지 업로드할 수 있습니다.")
            return await manager.import_auth(account_id, raw, user["id"])
        finally:
            await file.close()

    @router.get("/providers/codex/runtime")
    async def runtime_status(user=Depends(current_user)):
        return {**await manager.runtime.status(), "can_manage": user.get("role") == "admin"}

    @router.get("/providers/claude/runtime")
    async def claude_runtime_status(user=Depends(current_user)):
        return {**await manager.claude_runtime.status(), "can_manage": user.get("role") == "admin"}

    @router.get("/providers/claude/catalog")
    async def claude_runtime_catalog(_admin=Depends(require_admin)):
        return await manager.claude_runtime.catalog()

    @router.post("/providers/claude/update", status_code=202)
    async def claude_runtime_update(body: VersionInput, _admin=Depends(require_admin)):
        async with manager.lifecycle_lock:
            manager.no_login_in_progress()
            return await manager.claude_runtime.update(body.version, manager.reset_claude)

    @router.post("/providers/claude/rollback")
    async def claude_runtime_rollback(_admin=Depends(require_admin)):
        async with manager.lifecycle_lock:
            manager.no_login_in_progress()
            return await manager.claude_runtime.rollback(manager.reset_claude)

    @router.get("/providers/codex/catalog")
    async def runtime_catalog(_admin=Depends(require_admin)):
        return await manager.runtime.catalog()

    @router.post("/providers/codex/update", status_code=202)
    async def runtime_update(body: VersionInput, _admin=Depends(require_admin)):
        async with manager.lifecycle_lock:
            manager.no_login_in_progress()
            return await manager.runtime.update(body.version, manager.reset_codex)

    @router.post("/providers/codex/rollback")
    async def runtime_rollback(_admin=Depends(require_admin)):
        async with manager.lifecycle_lock:
            manager.no_login_in_progress()
            try:
                return await manager.runtime.rollback(manager.reset_codex)
            except OSError:
                raise ProviderError("버전 복원에 실패하여 기존 선택을 유지합니다.") from None

    app.include_router(router)
    app.router.add_event_handler("shutdown", manager.close)
    return manager
