"""Documented Codex app-server account and model methods over private stdio."""

import asyncio
import json
import math
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

LOGIN_TIMEOUT_SECONDS = 600


def public_login_state(login: dict) -> dict:
    return {key: value for key, value in login.items() if key in {
        "status", "message", "error", "verification_url", "user_code", "accepts_code", "started_at"
    }}


async def stop_process(process):
    if process is None or process.returncode is not None:
        return
    try:
        process.terminate()
        await asyncio.wait_for(process.wait(), 5)
    except TimeoutError:
        try:
            process.kill()
            await process.wait()
        except ProcessLookupError:
            pass
    except ProcessLookupError:
        pass


class ProviderError(Exception):
    def __init__(self, message: str, code: str = "provider_unavailable", *, stage="connection", category=None, retryable=None, provider_code=None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.category = category or (stage if stage in {"auth", "quota", "model"} else "auth" if code.startswith(("auth_", "invalid_auth")) else "temporary")
        self.retryable = retryable if retryable is not None else code in {"provider_unavailable", "timeout", "busy"}
        self.provider_code = provider_code

    def public(self):
        result = {"code": self.code, "stage": self.stage, "category": self.category, "retryable": self.retryable}
        if self.provider_code:
            result["provider_code"] = self.provider_code
        return result


def provider_error(error: object, stage: str) -> ProviderError:
    """Classify upstream diagnostics without forwarding raw messages, tokens or paths."""
    error = error if isinstance(error, dict) else {}
    raw = json.dumps({key: error.get(key) for key in ("message", "code", "type")}, ensure_ascii=True)[:65536]
    lowered = raw.lower()
    identifier = re.search(r"\b(?:TAC|CVP)\b", raw)
    exact_code = error.get("code")
    if isinstance(exact_code, str) and re.fullmatch(r"(?:TAC|CVP)(?:[-_][A-Z0-9]{1,12})?", exact_code):
        provider_code = exact_code
    else:
        provider_code = identifier.group() if identifier else None
    if provider_code or any(term in lowered for term in ("policy_violation", "content_policy", "security_policy", "safety policy", "safety restriction")):
        return ProviderError("공급자 보안·정책 제한으로 요청이 거절되었습니다.", "policy_security", stage=stage,
                             category="policy_security", retryable=False, provider_code=provider_code)
    if error.get("code") == -32601:
        return ProviderError("설치된 Codex 버전이 이 기능을 지원하지 않습니다.", "unsupported", stage=stage, category="model", retryable=False)
    if error.get("code") == 401 or any(term in lowered for term in ("unauthorized", "authentication", "invalid_api_key", "token expired", '"401"')):
        return ProviderError("공급자 인증이 필요합니다. 계정 로그인 상태를 확인해 주세요.", "auth_required", stage=stage, category="auth", retryable=False)
    if error.get("code") == 429 or any(term in lowered for term in ("rate_limit", "rate limit", "quota", '"429"')):
        return ProviderError("공급자 사용량 제한에 도달했습니다. 초기화 시간을 확인해 주세요.", "quota_exceeded", stage=stage, category="quota", retryable=True)
    if any(term in lowered for term in ("model_not_found", "unsupported model", "model unavailable", "model access")):
        return ProviderError("선택한 모델을 사용할 수 없습니다. 계정의 모델 목록을 확인해 주세요.", "model_unavailable", stage=stage, category="model", retryable=False)
    return ProviderError("Codex 요청에 실패했습니다. 연결과 공급자 상태를 확인해 주세요.", "provider_error", stage=stage, category="temporary", retryable=True)


def isolated_environment(home: Path) -> dict[str, str]:
    # Never inherit host credentials, API keys, npm config, or provider settings.
    env = {key: os.environ[key] for key in (
        "PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TZ"
    ) if key in os.environ}
    for child in (home, home / "tmp", home / "config", home / "cache"):
        child.mkdir(parents=True, exist_ok=True, mode=0o700)
        child.chmod(0o700)
    env.update({"HOME": str(home), "USERPROFILE": str(home), "CODEX_HOME": str(home / "codex"),
                "CLAUDE_CONFIG_DIR": str(home / "claude"), "XDG_CONFIG_HOME": str(home / "config"),
                "XDG_CACHE_HOME": str(home / "cache"), "APPDATA": str(home / "config"),
                "LOCALAPPDATA": str(home / "cache"), "TMP": str(home / "tmp"),
                "TEMP": str(home / "tmp"), "TMPDIR": str(home / "tmp"),
                "NO_COLOR": "1", "TERM": "dumb", "DISABLE_AUTOUPDATER": "1"})
    return env


def official_login_url(value: object, provider: str) -> str:
    if not isinstance(value, str) or len(value) > 8192:
        raise ProviderError("로그인 주소를 확인할 수 없습니다.", "invalid_response")
    try:
        parts = urlsplit(value)
        valid_port = parts.port in (None, 443)
    except ValueError as exc:
        raise ProviderError("로그인 주소를 확인할 수 없습니다.", "invalid_response") from exc
    hosts = {"auth.openai.com", "chatgpt.com"} if provider == "codex" else {
        "claude.ai", "claude.com", "platform.claude.com", "console.anthropic.com", "platform.anthropic.com"
    }
    if (parts.scheme != "https" or parts.hostname not in hosts or parts.username or parts.password
            or not valid_port or any(ord(char) < 33 for char in value)):
        raise ProviderError("공식 로그인 주소가 아닙니다.", "invalid_response")
    return value


def normalize_rate_limits(payload: dict, *, now: float | None = None) -> dict:
    """Normalize the documented app-server quota snapshot without guessing.

    Window durations come from the provider, so a five-hour and a weekly
    allowance remain distinguishable without assuming that every account has
    both. A successful read can still report a reached workspace or spend
    limit; ``status`` describes the read while ``limited`` describes whether
    the provider says execution is currently blocked.
    """
    now = time.time() if now is None else now
    buckets = payload.get("rateLimitsByLimitId")
    if not isinstance(buckets, dict) or not buckets:
        single = payload.get("rateLimits")
        buckets = {single.get("limitId") or "codex": single} if isinstance(single, dict) else {}
    reached_types = {
        "rate_limit_reached",
        "workspace_owner_credits_depleted",
        "workspace_member_credits_depleted",
        "workspace_owner_usage_limit_reached",
        "workspace_member_usage_limit_reached",
    }

    def number(mapping, key):
        value = mapping.get(key)
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None

    def reached(value):
        if value in reached_types:
            return value
        # Future provider variants still mean a limit was reached, but their
        # unreviewed text must not flow into the browser.
        return "rate_limit_reached" if isinstance(value, str) and value else None

    result = []
    for bucket_id, bucket in buckets.items():
        if not isinstance(bucket, dict):
            continue
        windows = []
        for kind in ("primary", "secondary"):
            window = bucket.get(kind)
            if not isinstance(window, dict):
                continue
            minutes = number(window, "windowDurationMins")
            used = number(window, "usedPercent")
            resets = number(window, "resetsAt")
            if minutes is not None and minutes <= 0:
                minutes = None
            if used is not None and used < 0:
                used = None
            if resets is not None and resets < 0:
                resets = None
            if minutes is None:
                label = "기간 미제공"
            elif minutes % 1440 == 0:
                label = f"{minutes / 1440:g}일"
            elif minutes % 60 == 0:
                label = f"{minutes / 60:g}시간"
            else:
                label = f"{minutes:g}분"
            windows.append({"kind": kind, "label": label, "window_minutes": minutes,
                            "used_percent": used, "resets_at": resets,
                            "remaining_seconds": max(0, int(resets - now)) if resets is not None else None})
        reached_type = reached(bucket.get("rateLimitReachedType"))
        spend_control_reached = bucket.get("spendControlReached")
        spend_control_reached = spend_control_reached if isinstance(spend_control_reached, bool) else None
        credit_snapshot = bucket.get("credits")
        credits = None
        if isinstance(credit_snapshot, dict):
            has_credits = credit_snapshot.get("hasCredits")
            unlimited = credit_snapshot.get("unlimited")
            credits = {
                "has_credits": has_credits if isinstance(has_credits, bool) else None,
                "unlimited": unlimited if isinstance(unlimited, bool) else None,
            }
        individual_snapshot = bucket.get("individualLimit")
        individual_limit = None
        if isinstance(individual_snapshot, dict):
            remaining = number(individual_snapshot, "remainingPercent")
            resets = number(individual_snapshot, "resetsAt")
            if remaining is not None and remaining < 0:
                remaining = None
            if resets is not None and resets < 0:
                resets = None
            individual_limit = {
                "remaining_percent": remaining,
                "resets_at": resets,
                "remaining_seconds": max(0, int(resets - now)) if resets is not None else None,
            }
        result.append({"id": str(bucket_id), "name": bucket.get("limitName"),
                       "plan": bucket.get("planType"), "windows": windows,
                       "reached_type": reached_type,
                       "spend_control_reached": spend_control_reached,
                       "limited": bool(reached_type or spend_control_reached is True),
                       "credits": credits, "individual_limit": individual_limit})
    reset_snapshot = payload.get("rateLimitResetCredits")
    reset_credits = None
    if isinstance(reset_snapshot, dict):
        available_count = reset_snapshot.get("availableCount")
        if isinstance(available_count, int) and not isinstance(available_count, bool) and available_count >= 0:
            # Credit ids and backend display strings are deliberately omitted;
            # this endpoint only needs the authoritative available count.
            reset_credits = {"available_count": available_count}
    has_snapshot = bool(reset_credits) or any(
        bucket["windows"]
        or bucket["reached_type"]
        or bucket["spend_control_reached"] is not None
        or bucket["credits"] is not None
        or bucket["individual_limit"] is not None
        for bucket in result
    )
    return {"status": "available" if has_snapshot else "unavailable",
            "limited": any(bucket["limited"] for bucket in result),
            "buckets": result, "reset_credits": reset_credits, "checked_at": now}


class CodexAccount:
    ALLOWED_METHODS = frozenset({"initialize", "account/read", "account/login/start",
                                "account/login/cancel", "account/logout", "account/rateLimits/read", "model/list"})

    def __init__(self, home: Path, command: list[str], preferences=None):
        self.home, self.command = home, command
        self.process = None
        self.reader = None
        self.pending: dict[int, asyncio.Future] = {}
        self.sequence = 0
        self.start_lock = asyncio.Lock()
        self.login = {"status": "idle"}
        self.login_timer = None
        self.login_notifications = {}
        self.preferences = preferences or {}

    def configuration_arguments(self):
        args = ["-c", 'cli_auth_credentials_store="file"']
        for field, config_key in (("model", "model"), ("reasoning_effort", "model_reasoning_effort"), ("service_tier", "service_tier")):
            if self.preferences.get(field):
                args.extend(["-c", config_key + "=" + json.dumps(self.preferences[field])])
        if self.preferences.get("service_tier") == "fast":
            args.extend(["-c", "features.fast_mode=true"])
        return args

    async def start(self):
        async with self.start_lock:
            if self.process and self.process.returncode is None:
                return
            if not self.command:
                raise ProviderError("Codex CLI가 설치되지 않았습니다.", "cli_missing")
            env = isolated_environment(self.home)
            Path(env["CODEX_HOME"]).mkdir(mode=0o700, exist_ok=True)
            try:
                self.process = await asyncio.create_subprocess_exec(
                    *self.command, *self.configuration_arguments(), "app-server",
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, cwd=self.home, env=env, limit=1024 * 1024)
            except OSError as exc:
                raise ProviderError("Codex CLI를 시작할 수 없습니다.", "cli_missing") from exc
            self.reader = asyncio.create_task(self._read(self.process))
            try:
                await self._request("initialize", {"clientInfo": {"name": "ctf_account_manager", "version": "0.1.0"}})
                self.process.stdin.write(b'{"method":"initialized"}\n')
                await self.process.stdin.drain()
            except BaseException:
                await self.close()
                raise

    async def _read(self, process):
        try:
            while line := await process.stdout.readline():
                try:
                    message = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(message, dict):
                    continue
                if "id" in message and "method" not in message:
                    future = self.pending.get(message["id"]) if isinstance(message["id"], int) else None
                    if future and not future.done():
                        future.set_result(message)
                elif message.get("method") == "account/login/completed":
                    info = message.get("params", {})
                    failure = None
                    if isinstance(info, dict) and info.get("error"):
                        error = info["error"] if isinstance(info["error"], dict) else {"message": str(info["error"])}
                        failure = provider_error(error, "auth")
                    if isinstance(info, dict) and self.login.get("status") == "starting":
                        login_id = info.get("loginId")
                        if isinstance(login_id, str) and len(self.login_notifications) < 10:
                            self.login_notifications[login_id] = (info.get("success") is True, failure)
                    elif isinstance(info, dict) and self.login.get("status") == "pending" and info.get("loginId") == self.login.get("login_id"):
                        self._finish_login(info.get("success") is True, failure)
                elif "id" in message:
                    # Do not fulfill execution, approval, token-refresh, or other server requests.
                    process.stdin.write((json.dumps({"id": message["id"], "error": {
                        "code": -32601, "message": "Account management only"}}) + "\n").encode())
                    await process.stdin.drain()
        except (OSError, ValueError, asyncio.CancelledError):
            pass
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ProviderError("Codex 연결이 종료되었습니다."))
            if process is self.process and self.login.get("status") in ("starting", "pending"):
                self._finish_login(False)

    async def _request(self, method: str, params: dict | None = None):
        if method not in self.ALLOWED_METHODS:
            raise ProviderError("지원하지 않는 계정 작업입니다.", "unsupported")
        self.sequence += 1
        request_id = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        try:
            if self.process is None or self.process.returncode is not None:
                raise ProviderError("Codex 연결이 종료되었습니다.")
            request = {"id": request_id, "method": method}
            if params is not None:
                request["params"] = params
            self.process.stdin.write((json.dumps(request) + "\n").encode())
            await self.process.stdin.drain()
            message = await asyncio.wait_for(future, timeout=30)
            if "error" in message:
                stage = "quota" if method == "account/rateLimits/read" else "model" if method == "model/list" else "auth" if method.startswith("account/") else "connection"
                raise provider_error(message["error"], stage)
            result = message.get("result", {})
            if not isinstance(result, dict):
                raise ProviderError("Codex 응답 형식을 확인할 수 없습니다.", "invalid_response")
            return result
        except (TimeoutError, BrokenPipeError, ConnectionError) as exc:
            raise ProviderError("Codex 응답을 기다리는 시간이 초과되었습니다.", "timeout") from exc
        finally:
            self.pending.pop(request_id, None)

    async def request(self, method: str, params: dict | None = None):
        if method not in self.ALLOWED_METHODS or method == "initialize":
            raise ProviderError("지원하지 않는 계정 작업입니다.", "unsupported")
        await self.start()
        return await self._request(method, params)

    async def start_login(self):
        if self.login.get("status") in ("starting", "pending"):
            return public_login_state(self.login)
        self.login_notifications.clear()
        self.login = {"status": "starting", "started_at": time.time()}
        try:
            result = await self.request("account/login/start", {"type": "chatgptDeviceCode"})
            url = official_login_url(result.get("verificationUrl"), "codex")
            login_id, code = result.get("loginId"), result.get("userCode")
            if not isinstance(login_id, str) or not login_id or not isinstance(code, str) or not code or len(code) > 128:
                raise ProviderError("로그인 코드 응답을 확인할 수 없습니다.", "invalid_response")
            self.login = {"status": "pending", "login_id": login_id, "verification_url": url,
                          "user_code": code, "started_at": time.time()}
            if login_id in self.login_notifications:
                self._finish_login(*self.login_notifications[login_id])
            else:
                self.login_timer = asyncio.create_task(self._expire_login())
            return public_login_state(self.login)
        except BaseException as exc:
            self._finish_login(False, exc if isinstance(exc, ProviderError) else None)
            await self.close()
            raise
        finally:
            self.login_notifications.clear()

    def _cancel_login_timer(self):
        if self.login_timer and self.login_timer is not asyncio.current_task():
            self.login_timer.cancel()
        self.login_timer = None

    def _finish_login(self, success, failure=None):
        self._cancel_login_timer()
        self.login = {"status": "completed" if success else "failed",
                      "message": "로그인이 완료되었습니다." if success else "로그인에 실패했습니다. 다시 시도해 주세요."}
        if not success and failure:
            self.login.update({"message": str(failure), "error": failure.public()})

    async def _expire_login(self):
        await asyncio.sleep(LOGIN_TIMEOUT_SECONDS)
        await self.cancel_login()
        self.login = {"status": "expired", "message": "로그인 시간이 만료되었습니다."}

    async def cancel_login(self):
        pending = self.login
        self._cancel_login_timer()
        self.login = {"status": "cancelled"}
        try:
            if pending.get("status") == "pending" and self.process and self.process.returncode is None:
                await self._request("account/login/cancel", {"loginId": pending["login_id"]})
        except ProviderError:
            pass  # Terminating the private process also cancels its pending OAuth task.
        finally:
            await self.close()
        return self.login

    async def snapshot(self):
        response = await self.request("account/read", {"refreshToken": True})
        account = response.get("account")
        if account is not None and not isinstance(account, dict):
            raise ProviderError("Codex 계정 응답 형식을 확인할 수 없습니다.", "invalid_response")
        public = None if not isinstance(account, dict) else {
            key: account.get(key) for key in ("type", "email", "planType") if key in account
        }
        status = "authenticated" if account else "signed_out"
        error = None
        quota = {"status": "unauthenticated", "buckets": [], "checked_at": time.time()}
        if account and str(account.get("type", "")).lower() == "apikey":
            quota = {"status": "unsupported", "buckets": [], "checked_at": time.time(),
                     "message": "API 키 인증은 ChatGPT 구독 사용량을 제공하지 않습니다."}
        elif account:
            try:
                quota = normalize_rate_limits(await self.request("account/rateLimits/read"))
            except ProviderError as exc:
                quota = {"status": exc.code, "message": str(exc), "error": exc.public(), "buckets": [], "checked_at": time.time()}
                # account/read(refreshToken=true) can return the cached account even
                # when its managed refresh failed.  A quota 401 is therefore the
                # authoritative authentication check for ChatGPT accounts.
                if exc.category == "auth":
                    status = "auth_required"
                    error = exc.public()
        result = {"status": status, "identity": public, "quota": quota}
        if error is not None:
            result["error"] = error
        return result

    async def models(self):
        models, cursor = [], None
        for _ in range(10):
            result = await self.request("model/list", {"limit": 100, "includeHidden": False, "cursor": cursor})
            for model in result.get("data", []):
                if isinstance(model, dict):
                    models.append({key: model.get(key) for key in (
                        "id", "model", "displayName", "description", "defaultReasoningEffort", "supportedReasoningEfforts", "isDefault",
                        "serviceTiers", "defaultServiceTier")})
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return {"status": "available", "models": models}

    async def close(self):
        self._cancel_login_timer()
        await stop_process(self.process)
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        self.process = None
        self.reader = None
