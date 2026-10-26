"""FastAPI integration for the durable isolated Codex solver."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any, Literal, Mapping

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from .providers.codex import ProviderError
from .solver import ModelConfiguration, SelectedAccount
from .solver_exchange import (
    MAX_SOLVER_GUIDANCE_BYTES,
    MAX_WRITEUP_REFINEMENT_INSTRUCTION_BYTES,
    ExchangeError,
    SolverCoordinatorPool,
    normalize_solver_guidance,
    normalize_writeup_refinement_instruction,
)
from .solver_worker import REQUIRED_CLAUDE_VERSION, REQUIRED_CODEX_VERSION
from .storage_budget import get_storage_budget


class SolveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["codex", "claude"] = "codex"
    account_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    model: str | None = Field(default=None, min_length=1, max_length=200)
    reasoning_effort: str | None = Field(default=None, min_length=1, max_length=40)
    service_tier: Literal["fast"] | None = None
    ultracode: bool = False
    writeup_locale: Literal["ko", "en"] = "ko"


class WriteupRefineInput(SolveInput):
    instruction: str | None = Field(
        default="",
        max_length=MAX_WRITEUP_REFINEMENT_INSTRUCTION_BYTES,
    )


class SolverCapacityInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maximum: int | None = Field(default=None, ge=1)


class SolverGuidanceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=MAX_SOLVER_GUIDANCE_BYTES)
    requested_delivery: Literal["same_turn", "next_turn"] = "same_turn"


async def _validated_configuration_override(
    accounts,
    owner_id: str,
    payload: SolveInput,
) -> tuple[ModelConfiguration | None, str | None, bool]:
    """Resolve a one-run execution override without persisting it."""

    fields = payload.model_fields_set
    has_override = bool(
        payload.model is not None
        or payload.reasoning_effort is not None
        or "service_tier" in fields
        or "ultracode" in fields
    )

    listed = accounts.listing(owner_id).get("accounts", [])
    candidates = []
    for account in listed:
        if account.get("provider") != payload.provider:
            continue
        if payload.account_id is not None:
            if isinstance(account.get("id"), str) and secrets.compare_digest(
                account["id"], payload.account_id
            ):
                candidates.append(account)
        elif account.get("selected") is True:
            candidates.append(account)
    if len(candidates) != 1:
        raise ExchangeError(
            "account_required",
            "선택된 모델 계정이 필요합니다.",
            category="auth",
        )
    account = candidates[0]
    record_owner = account.get("owner_user_id")
    account_id = account.get("id")
    if (
        not isinstance(record_owner, str)
        or not secrets.compare_digest(record_owner, owner_id)
        or not isinstance(account_id, str)
    ):
        raise ExchangeError(
            "account_required",
            "선택된 모델 계정이 필요합니다.",
            category="auth",
        )
    snapshot = account.get("snapshot")
    if not isinstance(snapshot, Mapping) or snapshot.get("status") != "authenticated":
        # Do not start an account-scoped model probe with credentials which the
        # server already knows are signed out or mid-login.  The coordinator
        # repeats this check in its enqueue transaction to close the race after
        # a successful catalog read.
        raise ExchangeError(
            "account_login_required",
            "선택한 모델 계정에 다시 로그인해 주세요.",
            category="auth",
        )
    if not has_override:
        try:
            selected = SelectedAccount.from_record(
                account, owner_id, require_selected=payload.account_id is None
            )
        except ValueError as exc:
            raise ExchangeError(
                "model_configuration_required",
                "모델과 추론 수준을 먼저 선택해 주세요.",
                category="model",
            ) from exc
        requested_configuration = selected.configuration
    else:
        model = payload.model or account.get("model")
        reasoning_effort = payload.reasoning_effort or account.get("reasoning_effort")
        if not model or not reasoning_effort:
            raise ExchangeError(
                "model_configuration_required",
                "모델과 추론 수준을 선택해 주세요.",
                category="model",
            )
        model_changed = model != account.get("model")
        if "service_tier" in fields:
            service_tier = payload.service_tier
        elif model_changed:
            service_tier = None
        else:
            service_tier = account.get("service_tier")
        ultracode = (
            payload.ultracode if "ultracode" in fields
            else False if model_changed
            else bool(account.get("ultracode", False))
        )
        try:
            requested_configuration = ModelConfiguration(
                provider=payload.provider,
                model=model,
                reasoning_effort=reasoning_effort,
                service_tier=service_tier,
                ultracode=ultracode,
            )
        except ValueError as exc:
            raise ExchangeError(
                "invalid_model_configuration",
                "이번 실행의 모델 설정을 확인해 주세요.",
                category="model",
            ) from exc

        try:
            selected = SelectedAccount(account_id, owner_id, requested_configuration)
        except ValueError as exc:
            raise ExchangeError(
                "invalid_account_binding",
                "이번 실행에 사용할 계정을 확인할 수 없습니다.",
                category="auth",
            ) from exc

    try:
        async with accounts.lock(selected.account_id):
            catalog = await accounts.models(selected.account_id, owner_id)
    except HTTPException as exc:
        if not has_override:
            return None, selected.account_id, False
        raise ExchangeError(
            "model_catalog_unavailable",
            "선택 계정의 모델 목록을 조회하지 못했습니다.",
            category="model",
            retryable=True,
        ) from exc
    except ProviderError as exc:
        if not has_override:
            return None, selected.account_id, False
        raise ExchangeError(
            "model_catalog_unavailable",
            "선택 계정의 모델 목록을 조회하지 못했습니다.",
            category=exc.category,
            retryable=exc.retryable,
        ) from exc
    if not isinstance(catalog, Mapping) or catalog.get("status") != "available":
        if not has_override:
            return None, selected.account_id, False
        raise ExchangeError(
            "model_catalog_unavailable",
            "선택 계정의 모델 목록을 조회하지 못했습니다.",
            category="model",
            retryable=True,
        )
    models = catalog.get("models")
    if not isinstance(models, list):
        models = []
    chosen = next(
        (
            item
            for item in models
            if isinstance(item, Mapping)
            and requested_configuration.model in (item.get("id"), item.get("model"))
        ),
        None,
    )
    if chosen is None and not has_override:
        return None, selected.account_id, False
    if chosen is None:
        raise ExchangeError(
            "invalid_model_configuration",
            "이 계정에서 선택할 수 없는 모델입니다.",
            category="model",
        )
    efforts = {
        item["reasoningEffort"]
        for item in (chosen.get("supportedReasoningEfforts") or [])
        if isinstance(item, Mapping) and isinstance(item.get("reasoningEffort"), str)
    }
    if requested_configuration.ultracode and not chosen.get("supportsUltracode"):
        raise ExchangeError(
            "invalid_model_configuration",
            "선택한 Claude 모델은 Ultracode를 지원하지 않습니다.",
            category="model",
        )
    if not has_override:
        return (
            None,
            selected.account_id,
            payload.provider == "codex"
            and requested_configuration.reasoning_effort not in {"max", "ultra"}
            and requested_configuration.reasoning_effort in efforts
            and "max" in efforts,
        )
    if requested_configuration.reasoning_effort not in efforts:
        raise ExchangeError(
            "invalid_model_configuration",
            "선택한 모델에서 지원하지 않는 추론 수준입니다.",
            category="model",
        )
    tiers = {
        item["id"]
        for item in (chosen.get("serviceTiers") or [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    if requested_configuration.service_tier is not None and (
        payload.provider == "claude"
        or requested_configuration.service_tier not in tiers
    ):
        raise ExchangeError(
            "invalid_model_configuration",
            "선택한 모델에서 지원하지 않는 실행 속도입니다.",
            category="model",
        )
    canonical_model = chosen.get("model") or chosen.get("id")
    if not isinstance(canonical_model, str):
        raise ExchangeError(
            "invalid_model_configuration",
            "선택한 모델 정보를 확인할 수 없습니다.",
            category="model",
        )
    try:
        configuration = ModelConfiguration(
            provider=payload.provider,
            model=canonical_model,
            reasoning_effort=requested_configuration.reasoning_effort,
            service_tier=requested_configuration.service_tier,
            ultracode=requested_configuration.ultracode,
        )
    except ValueError as exc:
        raise ExchangeError(
            "invalid_model_configuration",
            "선택한 모델 정보를 확인할 수 없습니다.",
            category="model",
        ) from exc
    max_reasoning_available = (
        payload.provider == "codex"
        and configuration.reasoning_effort not in {"max", "ultra"}
        and "max" in efforts
    )
    return configuration, selected.account_id, max_reasoning_available


class SolverService:
    def __init__(self, app, settings, database):
        self.app = app
        self.settings = settings
        self.database = database
        self.accounts = app.state.accounts
        exchange = Path(
            os.environ.get("CTF_SOLVER_EXCHANGE_WEB", str(Path(settings.data_dir) / "solver-exchange"))
        )
        raw_concurrency = os.environ.get("CTF_SOLVER_MAX_CONCURRENT", "6")
        try:
            max_concurrent = int(raw_concurrency)
        except ValueError as exc:
            raise RuntimeError("CTF_SOLVER_MAX_CONCURRENT must be an integer") from exc
        raw_recommended = os.environ.get("CTF_SOLVER_RECOMMENDED_CONCURRENT", raw_concurrency)
        raw_environment_max = os.environ.get("CTF_SOLVER_AUTOSCALE_MAX", "0")
        raw_web_pids_limit = os.environ.get("CTF_WEB_PIDS_LIMIT", "0")
        try:
            self.recommended_concurrent = int(raw_recommended)
            self.environment_max = int(raw_environment_max)
            self.web_pids_limit = int(raw_web_pids_limit)
        except ValueError as exc:
            raise RuntimeError("solver capacity settings must be integers") from exc
        if self.recommended_concurrent < 1:
            raise RuntimeError("CTF_SOLVER_RECOMMENDED_CONCURRENT must be positive")
        if self.environment_max < 0:
            raise RuntimeError("CTF_SOLVER_AUTOSCALE_MAX must be zero or positive")
        if self.web_pids_limit < 0:
            raise RuntimeError("CTF_WEB_PIDS_LIMIT must be zero or positive")
        if self.environment_max and self.environment_max < max_concurrent:
            raise RuntimeError("CTF_SOLVER_AUTOSCALE_MAX must be at least the warm baseline")
        self.baseline_concurrent = max_concurrent
        self.exchange = exchange
        self.autoscaler_required = os.environ.get(
            "CTF_SOLVER_AUTOSCALER_REQUIRED", "false"
        ).strip().lower() in {"1", "true", "yes"}
        self.autoscaler_status_path = Path(
            os.environ.get(
                "CTF_SOLVER_AUTOSCALE_STATUS",
                str(exchange / "autoscaler.json"),
            )
        )
        self.release_sha = os.environ.get("CTF_RELEASE_SHA", "").strip()
        self.admin_max = self._stored_admin_max()
        self.coordinator = SolverCoordinatorPool(
            settings.database_path,
            settings.data_dir,
            self.accounts.home,
            exchange,
            max_concurrent=max_concurrent,
            hard_max_concurrent=self._effective_hard_max(),
            host_managed_slots=self.autoscaler_required,
            on_flag_committed=self._flag_committed,
            on_writeup_committed=self._writeup_committed,
            storage_budget=get_storage_budget(app, settings),
        )
        self.stop_event: asyncio.Event | None = None
        self.wakeup: asyncio.Event | None = None
        self.task: asyncio.Task | None = None
        self.start_count = 0
        self.runtime_ready = False
        self.runtime_error: dict[str, Any] | None = None
        self.logger = logging.getLogger("ctf_workspace.solver")
        self._install_runtime_guards()

    def _stored_admin_max(self) -> int:
        with self.database() as db:
            row = db.execute(
                "SELECT value FROM meta WHERE key='solver_admin_max_concurrent'"
            ).fetchone()
        if not row:
            return 0
        try:
            value = int(row[0])
        except (TypeError, ValueError):
            return 0
        return value if value >= self.baseline_concurrent else 0

    def _effective_hard_max(self) -> int:
        candidates = [value for value in (self.environment_max, self.admin_max) if value]
        return min(candidates) if candidates else 0

    def set_admin_max(self, value: int) -> None:
        if value and value < self.baseline_concurrent:
            raise ExchangeError(
                "invalid_solver_capacity",
                f"최대 솔버 수는 기본 유지 수 {self.baseline_concurrent}개 이상이어야 합니다.",
                category="input",
            )
        self.admin_max = value
        self.coordinator.set_hard_max(self._effective_hard_max())

    def capacity_snapshot(self) -> dict[str, Any]:
        capacity = self.coordinator.reconcile_capacity()
        demand = capacity["demand"]
        estimated_web_pids = demand + 32
        pids_warning = bool(
            self.web_pids_limit and estimated_web_pids >= self.web_pids_limit
        )
        resource_warning = demand > self.recommended_concurrent
        warning = resource_warning or pids_warning
        limited = bool(
            capacity["hard_max"]
            and max(self.baseline_concurrent, capacity["open_jobs"])
            > capacity["hard_max"]
        )
        return {
            **capacity,
            "recommended": self.recommended_concurrent,
            "admin_max": self.admin_max,
            "environment_max": self.environment_max,
            "estimated_logical_cpus": demand * 2,
            "estimated_memory_bytes": demand * 6 * 1024**3,
            "estimated_web_pids": estimated_web_pids,
            "web_pids_limit": self.web_pids_limit,
            "web_pids_warning": pids_warning,
            "warning": warning,
            "limited": limited,
            "warning_message": (
                " ".join(
                    part
                    for part in (
                        (
                            f"현재 풀이 수요는 권장 동시 실행 {self.recommended_concurrent}개를 넘습니다. "
                            f"약 {demand * 2}개 논리 CPU와 {demand * 6} GiB 메모리를 기준으로 확장합니다."
                            if resource_warning
                            else ""
                        ),
                        (
                            f"웹 PID 제한 {self.web_pids_limit}개에 근접해 확장이 실패할 수 있습니다."
                            if pids_warning
                            else ""
                        ),
                    )
                    if part
                )
            ),
        }

    def _autoscaler_snapshot(self) -> dict[str, Any]:
        if not self.autoscaler_required:
            return {"required": False, "ready": True}
        path = self.autoscaler_status_path
        try:
            state = path.lstat()
            if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
                raise ValueError("invalid status path")
            if state.st_size > 65536:
                raise ValueError("oversized status")
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("invalid status")
            updated = value.get("updated_at")
            if (
                value.get("protocol") != 1
                or not isinstance(updated, (int, float))
                or isinstance(updated, bool)
                or time.time() - float(updated) > 10.0
            ):
                raise ValueError("stale status")
            if self.release_sha and value.get("template_release") != self.release_sha:
                raise ValueError("release mismatch")
            available = value.get("available")
            desired = value.get("desired")
            if (
                not isinstance(available, int)
                or isinstance(available, bool)
                or available < 1
                or not isinstance(desired, int)
                or isinstance(desired, bool)
                or desired < 1
            ):
                raise ValueError("invalid status count")
            return {
                "required": True,
                "ready": value.get("ready") is True,
                "available": available,
                "desired": desired,
                "warming": bool(value.get("warming")),
                "retained": int(value.get("retained") or 0),
                "updated_at": float(updated),
                "template_image": value.get("template_image"),
                "template_release": value.get("template_release"),
            }
        except (OSError, ValueError, TypeError, AttributeError):
            return {
                "required": True,
                "ready": False,
                "error": "solver 자동 확장 상태를 확인할 수 없습니다.",
            }

    def _flag_committed(
        self,
        owner: str,
        workspace: str,
        challenge: str,
        flag: str,
        job_id: str | None = None,
    ) -> bool:
        telegram = getattr(self.app.state, "telegram_flag_found", None)
        if callable(telegram):
            telegram_args = (owner, workspace, challenge, flag)
            if job_id is not None:
                telegram_args += (job_id,)
            if telegram(*telegram_args) is False:
                return False
        submit = getattr(self.app.state, "ctfd_auto_submit_flag", None)
        if callable(submit) and submit(owner, workspace, challenge, flag, "agent") is False:
            return False
        return True

    def _writeup_committed(
        self,
        owner: str,
        workspace: str,
        challenge: str,
        markdown: str,
        job_id: str | None = None,
    ) -> bool:
        # The coordinator persists the canonical write-up and generated note
        # block before this hook is eligible.  Rewriting it during notification
        # retry would let a delayed older solve hook roll a newer refinement
        # back to stale Markdown.
        database = getattr(self, "database", None)
        layout = getattr(getattr(self.app, "state", None), "storage_layout", None)
        if callable(database) and layout is not None:
            with database() as db:
                db.execute("BEGIN IMMEDIATE")
                layout.sync_challenge(db, workspace, challenge)
                row = db.execute(
                    "SELECT notes FROM challenges WHERE id=? AND workspace_id=?",
                    (challenge, workspace),
                ).fetchone()
            if not row:
                # A durable notification hook can race with challenge deletion.
                # There is no recipient artifact left to publish, so acknowledge
                # the stale hook instead of retrying it forever.
                return True
        telegram = getattr(self.app.state, "telegram_writeup_ready", None)
        if not callable(telegram):
            return True
        telegram_args = (owner, workspace, challenge, markdown)
        if job_id is not None:
            telegram_args += (job_id,)
        return telegram(*telegram_args) is not False

    def _runtime_source(self, version: str, selected: str | None) -> Path | None:
        if selected == version:
            return self.accounts.runtime.root / f"codex-{version}"
        if selected is None and version == REQUIRED_CODEX_VERSION:
            return None
        raise ExchangeError(
            "runtime_unavailable",
            "선택한 Codex runtime을 solver에서 확인할 수 없습니다.",
            category="model",
            retryable=True,
        )

    async def runtime_snapshot(self) -> dict[str, Any]:
        state = await self.accounts.runtime.status()
        version, selected = state.get("version"), state.get("selected")
        if not state.get("available") or not isinstance(version, str):
            raise ExchangeError(
                "runtime_unavailable",
                "Codex runtime이 준비되지 않았습니다.",
                category="model",
                retryable=True,
            )
        source = self._runtime_source(version, selected if isinstance(selected, str) else None)
        return await asyncio.to_thread(self.coordinator.publish_runtime, version, source)

    async def claude_runtime_snapshot(self) -> dict[str, Any]:
        state = await self.accounts.claude_runtime.status()
        version, selected = state.get("version"), state.get("selected")
        if not state.get("available") or not isinstance(version, str):
            raise ExchangeError("runtime_unavailable", "Claude Code 실행 파일을 확인하지 못했습니다.",
                                category="model", retryable=True)
        if selected:
            source = self.accounts.claude_runtime.root / f"claude-{version}"
        elif version == REQUIRED_CLAUDE_VERSION:
            source = None
        else:
            raise ExchangeError("runtime_unavailable", "Claude Code 실행 버전이 일치하지 않습니다.",
                                category="model", retryable=True)
        return await asyncio.to_thread(self.coordinator.publish_runtime, version, source, "claude")

    def _install_runtime_guards(self) -> None:
        runtime = self.accounts.runtime
        original_update = runtime.update
        original_rollback = runtime.rollback

        async def update(version: str, after_switch):
            if self.coordinator.has_open_jobs():
                raise ProviderError(
                    "대기 또는 실행 중인 풀이를 중단하고 격리 정리가 끝난 뒤 업데이트해 주세요.",
                    "busy",
                )

            async def switched():
                await after_switch()
                source = runtime.root / f"codex-{version}"
                await asyncio.to_thread(self.coordinator.publish_runtime, version, source)
                self.runtime_ready, self.runtime_error = True, None

            return await original_update(version, switched)

        async def rollback(after_switch):
            if self.coordinator.has_open_jobs():
                raise ProviderError(
                    "대기 또는 실행 중인 풀이를 중단하고 격리 정리가 끝난 뒤 복원해 주세요.",
                    "busy",
                )

            async def switched():
                await after_switch()
                state = await runtime.status()
                version = state.get("version")
                if not isinstance(version, str):
                    raise ProviderError("복원된 Codex runtime을 확인할 수 없습니다.")
                selected = state.get("selected")
                source = self._runtime_source(version, selected if isinstance(selected, str) else None)
                await asyncio.to_thread(self.coordinator.publish_runtime, version, source)
                self.runtime_ready, self.runtime_error = True, None

            return await original_rollback(switched)

        runtime.update = update
        runtime.rollback = rollback

        claude_runtime = self.accounts.claude_runtime
        original_claude_update = claude_runtime.update
        original_claude_rollback = claude_runtime.rollback

        async def update_claude(version: str, after_switch):
            if self.coordinator.has_open_jobs():
                raise ProviderError("진행 중인 풀이가 끝난 뒤 Claude Code를 업데이트해 주세요.", "busy")

            async def switched():
                await after_switch()
                await self.claude_runtime_snapshot()

            return await original_claude_update(version, switched)

        async def rollback_claude(after_switch):
            if self.coordinator.has_open_jobs():
                raise ProviderError("진행 중인 풀이가 끝난 뒤 Claude Code를 복원해 주세요.", "busy")

            async def switched():
                await after_switch()
                await self.claude_runtime_snapshot()

            return await original_claude_rollback(switched)

        claude_runtime.update = update_claude
        claude_runtime.rollback = rollback_claude

    async def start(self) -> None:
        self.start_count += 1
        if self.start_count > 1:
            return
        self.coordinator.reset_stop()
        self.stop_event = asyncio.Event()
        self.wakeup = asyncio.Event()
        try:
            async with self.accounts.lifecycle_lock:
                await self.runtime_snapshot()
            self.runtime_ready, self.runtime_error = True, None
        except ExchangeError as exc:
            self.runtime_ready, self.runtime_error = False, exc.public(stage="runtime")
        except Exception:
            self.runtime_ready = False
            self.runtime_error = ExchangeError(
                "runtime_unavailable", "Codex runtime 준비에 실패했습니다.", category="model", retryable=True
            ).public(stage="runtime")
        self.task = asyncio.create_task(self._loop(), name="solver-coordinator")

    async def stop(self) -> None:
        if self.start_count == 0:
            return
        self.start_count -= 1
        if self.start_count:
            return
        self.coordinator.request_stop()
        if self.stop_event:
            self.stop_event.set()
        if self.wakeup:
            self.wakeup.set()
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        joined = await asyncio.to_thread(self.coordinator.wait_quiescent, 25.0)
        if not joined:
            self.logger.error("solver_coordinator_shutdown_timeout")
        self.task = None

    async def _loop(self) -> None:
        assert self.stop_event is not None and self.wakeup is not None
        while not self.stop_event.is_set():
            try:
                changed = await asyncio.to_thread(self.coordinator.tick)
                delay = 0.05 if changed else 0.35
            except ExchangeError as exc:
                self.coordinator.last_block = exc.public(stage="coordinator")
                delay = 0.5
            except sqlite3.Error:
                self.coordinator.last_block = ExchangeError(
                    "coordinator_storage_failed",
                    "solver 작업 상태를 처리하지 못했습니다.",
                    retryable=True,
                ).public(stage="coordinator")
                delay = 0.5
            solver_alerts = getattr(self.app.state, "telegram_solver_alerts", None)
            if callable(solver_alerts):
                # The scanner runs after the coordinator transaction commits.
                # It also rediscovers a committed terminal job after a process
                # restart, closing the gap between state commit and enqueue.
                alerts_changed = await asyncio.to_thread(solver_alerts)
                if alerts_changed:
                    delay = min(delay, 0.05)
            try:
                await asyncio.wait_for(self.wakeup.wait(), timeout=delay)
                self.wakeup.clear()
            except TimeoutError:
                pass

    def notify(self) -> None:
        if self.wakeup:
            self.wakeup.set()

    async def health(self) -> dict[str, Any]:
        capacity = await asyncio.to_thread(self.capacity_snapshot)
        health = await asyncio.to_thread(self.coordinator.health)
        health["capacity"].update(capacity)
        autoscaler = await asyncio.to_thread(self._autoscaler_snapshot)
        required_workers = int(health["capacity"].get("required") or self.baseline_concurrent)
        autoscaler_ready = bool(
            autoscaler.get("ready")
            and (
                not autoscaler.get("required")
                or int(autoscaler.get("available") or 0) >= required_workers
            )
        )
        autoscaler["required_workers"] = required_workers
        health["autoscaler"] = autoscaler
        health["runtime_ready"] = self.runtime_ready
        health["runtime_error"] = self.runtime_error
        health["ready"] = bool(
            health.get("ready")
            and autoscaler_ready
            and self.runtime_ready
            and self.task
            and not self.task.done()
        )
        return health


def _raise_exchange(exc: ExchangeError) -> None:
    if exc.code.endswith("not_found"):
        status = 404
    elif exc.code.startswith("invalid_"):
        status = 422
    elif exc.category in {"storage", "safety"} and exc.retryable:
        status = 503
    elif exc.code in {"runtime_unavailable", "runtime_not_published"}:
        status = 503
    else:
        status = 409
    raise HTTPException(status, detail={**exc.public(), "message": str(exc)})


def register_solver(app, require_auth, require_admin, settings, database):
    """Register solver state/API. Call after accounts, Telegram, and CTFd."""

    if not hasattr(app.state, "accounts"):
        raise RuntimeError("register_accounts must run before register_solver")
    service = SolverService(app, settings, database)
    app.state.solver = service
    app.state.solver_jobs = service.coordinator
    router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

    def sync_solver_input(owner_id: str, workspace_id: str, challenge_id: str) -> None:
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            owned = db.execute(
                """SELECT 1 FROM challenges c JOIN workspaces w ON w.id=c.workspace_id
                    WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=?""",
                (challenge_id, workspace_id, owner_id),
            ).fetchone()
            if owned:
                app.state.storage_layout.sync_challenge(
                    db, workspace_id, challenge_id
                )

    @router.post("/workspaces/{workspace_id}/challenges/{challenge_id}/solver", status_code=202)
    async def start_solver(
        workspace_id: str,
        challenge_id: str,
        payload: SolveInput | None = None,
        user=Depends(require_auth),
    ):
        try:
            await asyncio.to_thread(
                sync_solver_input, user["id"], workspace_id, challenge_id
            )
            provider = payload.provider if payload is not None else "codex"
            async with service.accounts.lifecycle_lock:
                if service.accounts.runtime.busy or service.accounts.claude_runtime.busy:
                    raise ExchangeError("runtime_busy", "CLI 업데이트가 끝난 뒤 시작해 주세요.", retryable=True)
                configuration_override, expected_account_id, max_reasoning_available = (
                    await _validated_configuration_override(
                        service.accounts, user["id"], payload or SolveInput()
                    )
                )
                if provider == "codex":
                    if service.accounts.runtime.busy:
                        raise ExchangeError("runtime_busy", "Codex 업데이트가 끝난 뒤 시작해 주세요.", retryable=True)
                    runtime = await service.runtime_snapshot()
                    result = await asyncio.to_thread(
                        service.coordinator.enqueue,
                        user["id"],
                        workspace_id,
                        challenge_id,
                        provider=provider,
                        codex_version=runtime["version"],
                        codex_runtime_sha256=runtime["sha256"],
                        configuration_override=configuration_override,
                        expected_account_id=expected_account_id,
                        max_reasoning_available=max_reasoning_available,
                        writeup_locale=(payload.writeup_locale if payload else "ko"),
                    )
                    service.runtime_ready, service.runtime_error = True, None
                else:
                    if service.accounts.claude_runtime.busy:
                        raise ExchangeError("runtime_busy", "Claude Code 업데이트가 끝난 뒤 시작해 주세요.", retryable=True)
                    runtime = await service.claude_runtime_snapshot()
                    result = await asyncio.to_thread(
                        service.coordinator.enqueue,
                        user["id"],
                        workspace_id,
                        challenge_id,
                        provider=provider,
                        claude_version=runtime["version"],
                        claude_runtime_sha256=runtime["sha256"],
                        configuration_override=configuration_override,
                        expected_account_id=expected_account_id,
                        max_reasoning_available=max_reasoning_available,
                        writeup_locale=(payload.writeup_locale if payload else "ko"),
                    )
            service.notify()
            capacity = await asyncio.to_thread(service.capacity_snapshot)
            return {**result, "capacity": capacity}
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.post(
        "/workspaces/{workspace_id}/challenges/{challenge_id}/writeup/refine",
        status_code=202,
    )
    async def refine_writeup(
        workspace_id: str,
        challenge_id: str,
        payload: WriteupRefineInput | None = None,
        user=Depends(require_auth),
    ):
        payload = payload or WriteupRefineInput()
        try:
            await asyncio.to_thread(
                sync_solver_input, user["id"], workspace_id, challenge_id
            )
            instruction = normalize_writeup_refinement_instruction(payload.instruction)
            provider = payload.provider
            async with service.accounts.lifecycle_lock:
                if service.accounts.runtime.busy or service.accounts.claude_runtime.busy:
                    raise ExchangeError("runtime_busy", "CLI 업데이트가 끝난 뒤 시작해 주세요.", retryable=True)
                configuration_override, expected_account_id, _ = (
                    await _validated_configuration_override(
                        service.accounts, user["id"], payload
                    )
                )
                if provider == "codex":
                    if service.accounts.runtime.busy:
                        raise ExchangeError(
                            "runtime_busy",
                            "Codex 업데이트가 끝난 뒤 시작해 주세요.",
                            retryable=True,
                        )
                    runtime = await service.runtime_snapshot()
                    result = await asyncio.to_thread(
                        service.coordinator.enqueue_writeup_refinement,
                        user["id"],
                        workspace_id,
                        challenge_id,
                        instruction=instruction,
                        writeup_locale=payload.writeup_locale,
                        provider=provider,
                        codex_version=runtime["version"],
                        codex_runtime_sha256=runtime["sha256"],
                        configuration_override=configuration_override,
                        expected_account_id=expected_account_id,
                    )
                    service.runtime_ready, service.runtime_error = True, None
                else:
                    if service.accounts.claude_runtime.busy:
                        raise ExchangeError("runtime_busy", "Claude Code 업데이트가 끝난 뒤 시작해 주세요.", retryable=True)
                    runtime = await service.claude_runtime_snapshot()
                    result = await asyncio.to_thread(
                        service.coordinator.enqueue_writeup_refinement,
                        user["id"],
                        workspace_id,
                        challenge_id,
                        instruction=instruction,
                        writeup_locale=payload.writeup_locale,
                        provider=provider,
                        claude_version=runtime["version"],
                        claude_runtime_sha256=runtime["sha256"],
                        configuration_override=configuration_override,
                        expected_account_id=expected_account_id,
                    )
            service.notify()
            capacity = await asyncio.to_thread(service.capacity_snapshot)
            return {**result, "capacity": capacity}
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.get("/workspaces/{workspace_id}/challenges/{challenge_id}/writeup/refine")
    async def latest_writeup_refinement(
        workspace_id: str,
        challenge_id: str,
        user=Depends(require_auth),
    ):
        try:
            result = await asyncio.to_thread(
                service.coordinator.latest,
                user["id"],
                workspace_id,
                challenge_id,
                job_mode="writeup_refine",
            )
            if result is None:
                raise ExchangeError("job_not_found", "이 문제의 write-up 보완 작업이 없습니다.")
            return result
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.get("/workspaces/{workspace_id}/challenges/{challenge_id}/solver")
    async def latest_solver(workspace_id: str, challenge_id: str, user=Depends(require_auth)):
        try:
            result = await asyncio.to_thread(
                service.coordinator.latest,
                user["id"],
                workspace_id,
                challenge_id,
                job_mode="solve",
            )
            if result is None:
                raise ExchangeError("job_not_found", "이 문제의 solver 작업이 없습니다.")
            return result
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.get("/solver/jobs/{job_id}")
    async def solver_job(job_id: str, after: int = Query(0, ge=0), user=Depends(require_auth)):
        try:
            return await asyncio.to_thread(service.coordinator.get, job_id, user["id"], after=after)
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.post("/solver/jobs/{job_id}/cancel")
    async def cancel_solver(job_id: str, user=Depends(require_auth)):
        try:
            result = await asyncio.to_thread(service.coordinator.cancel, job_id, user["id"])
            service.notify()
            return result
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.post("/solver/jobs/{job_id}/guidance", status_code=202)
    async def guide_solver(
        job_id: str,
        payload: SolverGuidanceInput,
        user=Depends(require_auth),
    ):
        try:
            message = normalize_solver_guidance(payload.message)
            result = await asyncio.to_thread(
                service.coordinator.add_guidance,
                job_id,
                user["id"],
                message,
                payload.requested_delivery,
            )
            service.notify()
            return result
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.post("/solver/jobs/{job_id}/reject-flag")
    async def reject_solver_flag(job_id: str, user=Depends(require_auth)):
        try:
            result = await asyncio.to_thread(
                service.coordinator.reject_candidate, job_id, user["id"]
            )
            workspace_id = result.get("workspace_id")
            challenge_id = result.get("challenge_id")
            if isinstance(workspace_id, str) and isinstance(challenge_id, str):
                with database() as db:
                    row = db.execute(
                        "SELECT notes FROM challenges WHERE id=? AND workspace_id=?",
                        (challenge_id, workspace_id),
                    ).fetchone()
                if row:
                    app.state.storage_layout.write_notes(
                        workspace_id, challenge_id, row["notes"]
                    )
                    app.state.storage_layout.remove_writeup(
                        workspace_id, challenge_id
                    )
            return result
        except ExchangeError as exc:
            _raise_exchange(exc)

    @router.get("/solver/status")
    async def solver_status(_user=Depends(require_auth)):
        return await service.health()

    @router.get("/admin/solver-capacity", dependencies=[Depends(require_admin)])
    async def admin_solver_capacity():
        return await asyncio.to_thread(service.capacity_snapshot)

    @router.put("/admin/solver-capacity", dependencies=[Depends(require_admin)])
    async def update_solver_capacity(payload: SolverCapacityInput):
        value = payload.maximum or 0
        try:
            service.set_admin_max(value)
        except ExchangeError as exc:
            _raise_exchange(exc)
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            if value:
                db.execute(
                    """INSERT INTO meta(key,value) VALUES('solver_admin_max_concurrent',?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (str(value),),
                )
            else:
                db.execute("DELETE FROM meta WHERE key='solver_admin_max_concurrent'")
        service.notify()
        return await asyncio.to_thread(service.capacity_snapshot)

    app.include_router(router)
    app.router.add_event_handler("startup", service.start)
    app.router.add_event_handler("shutdown", service.stop)

    return service


__all__ = ["SolverService", "register_solver"]
