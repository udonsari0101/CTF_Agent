"""Fixed Claude Code auth commands, with an OAuth URL/code bridge for containers."""

import asyncio
from datetime import datetime
import json
import math
import os
import re
import shutil
import stat
import time
from pathlib import Path

import httpx

from .codex import LOGIN_TIMEOUT_SECONDS, ProviderError, isolated_environment, official_login_url, stop_process


# Claude Code accepts documented aliases and full Anthropic model IDs. Keep
# the catalog explicit because the CLI does not expose an authenticated model
# list API that the account screen can query without starting a turn.
CLAUDE_MODEL_ALIASES = (
    ("default", "Default (recommended)"),
    ("claude-opus-5-5", "Opus 5.5"),
    ("claude-fable-5-1", "Fable 5.1"),
    ("claude-sonnet-5-5", "Sonnet 5.5"),
    ("claude-haiku-5-5", "Haiku 5.5"),
    ("claude-haiku-4-5-20251001", "Haiku 4.5"),
    ("claude-sonnet-5", "Sonnet 5"),
    ("claude-opus-5", "Opus 5"),
    ("claude-fable-5", "Fable 5"),
    ("claude-opus-4-8", "Opus 4.8"),
    ("claude-opus-4-7", "Opus 4.7"),
    ("claude-opus-4-6", "Opus 4.6"),
    ("claude-sonnet-4-6", "Sonnet 4.6"),
    ("best", "Best (automatic)"),
    ("fable", "Fable (automatic)"),
    ("opus", "Opus (automatic)"),
    ("sonnet", "Sonnet (automatic)"),
    ("haiku", "Haiku (automatic)"),
)
CLAUDE_EFFORTS = ("low", "medium", "high", "xhigh", "max")
CLAUDE_ULTRACODE_MODELS = frozenset({
    "claude-opus-5-5", "claude-fable-5-1", "claude-fable-5",
    "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5",
    "claude-sonnet-5", "claude-opus-4-8", "claude-opus-4-7",
})
_ANSI_CSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_ANSI_OSC = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
_ANSI_OSC_LINK = re.compile(r"\x1b\]8;;(https://[^\x07\x1b]+)(?:\x07|\x1b\\)")
_LOGIN_URL = re.compile(r"https://[^\s<>\x1b]+(?=[\s<>\x1b])")
CLAUDE_LINK_TIMEOUT_SECONDS = 45
CLAUDE_USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
CLAUDE_USAGE_CACHE_SECONDS = 600
CLAUDE_USAGE_BACKOFF_SECONDS = 900
CLAUDE_MODELS_URL = "https://api.anthropic.com/v1/models"
CLAUDE_API_VERSION = "2023-06-01"
CLAUDE_API_KEY_MAX_BYTES = 8192


def _usage_window(value: object, label: str) -> dict | None:
    if not isinstance(value, dict):
        return None
    used = value.get("utilization", value.get("percent"))
    if isinstance(used, bool) or not isinstance(used, (int, float)) or not math.isfinite(used):
        return None
    reset = value.get("resets_at")
    try:
        reset_at = datetime.fromisoformat(reset.replace("Z", "+00:00")).timestamp() if isinstance(reset, str) else float(reset)
    except (TypeError, ValueError, OverflowError):
        reset_at = None
    if reset_at is not None and not math.isfinite(reset_at):
        reset_at = None
    return {"label": label, "used_percent": max(0, min(100, float(used))), "resets_at": reset_at}


def normalize_claude_usage(payload: object) -> dict:
    """Retain only numeric account windows; the OAuth response schema is not public."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "buckets": [], "checked_at": time.time()}
    labels = {"five_hour": "5시간", "seven_day": "7일", "seven_day_opus": "Opus 7일",
              "seven_day_sonnet": "Sonnet 7일", "seven_day_oauth_apps": "Claude Code 7일"}
    windows = []
    for key, label in labels.items():
        window = _usage_window(payload.get(key), label)
        if window:
            windows.append(window)
    limits = payload.get("limits")
    if isinstance(limits, list):
        for limit in limits[:32]:
            if not isinstance(limit, dict):
                continue
            kind = limit.get("kind")
            if kind == "session" and not any(item["label"] == "5시간" for item in windows):
                window = _usage_window(limit, "5시간")
            elif kind == "weekly_all" and not any(item["label"] == "7일" for item in windows):
                window = _usage_window(limit, "7일")
            else:
                window = None
            if window:
                windows.append(window)
    exhausted = any(window["used_percent"] >= 100 for window in windows)
    return {"status": "quota_exceeded" if exhausted else "available" if windows else "unavailable",
            "source": "claude_oauth_usage", "limited": exhausted,
            "buckets": [{"id": "claude", "name": "Claude Code", "windows": windows,
                         "limited": exhausted,
                         "reached_type": "rate_limit_reached" if exhausted else None}] if windows else [],
            "checked_at": time.time()}


def _login_url_from_output(output: str) -> str | None:
    """Return only a complete official OAuth URL from Claude's terminal output."""
    plain = _ANSI_CSI.sub("", _ANSI_OSC.sub("", output))
    candidates = [match.group(1) for match in _ANSI_OSC_LINK.finditer(output)]
    candidates.extend(match.group() for match in _LOGIN_URL.finditer(plain))
    for candidate in candidates:
        candidate = candidate.rstrip("\"'.,)]}")
        try:
            url = official_login_url(candidate, "claude")
        except ProviderError:
            continue
        if "/oauth/" in url:
            return url
    return None


class ClaudeAccount:
    def __init__(self, home: Path, command=None, *, auth_kind: str = "oauth"):
        self.home = home
        self.command = command or (lambda: [shutil.which("claude")] if shutil.which("claude") else [])
        self.auth_kind = auth_kind
        self.process = None
        self.reader = None
        self.login = {"status": "idle"}
        self._usage_cache = None
        self._usage_next_fetch = 0.0

    async def _spawn(self, *arguments):
        command = self.command()
        if not command or not command[0] or command[0].lower().endswith((".cmd", ".ps1")):
            raise ProviderError("Claude Code CLI가 설치되지 않았습니다.", "cli_missing")
        env = isolated_environment(self.home)
        Path(env["CLAUDE_CONFIG_DIR"]).mkdir(mode=0o700, exist_ok=True)
        try:
            return await asyncio.create_subprocess_exec(*command, "auth", *arguments,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=env, cwd=self.home)
        except OSError as exc:
            raise ProviderError("Claude Code 인증 명령을 시작할 수 없습니다.") from exc

    async def start_login(self):
        if self.login.get("status") == "pending" and self.process and self.process.returncode is None:
            return self.login
        # Select the subscription flow explicitly so the CLI prints its OAuth
        # URL in a headless container instead of waiting on an interactive menu.
        self.process = await self._spawn("login", "--claudeai")
        self.login = {"status": "pending", "started_at": time.time(), "accepts_code": True}
        self.reader = asyncio.create_task(self._read_login(self.process))
        return self.login

    async def _read_login(self, process):
        buffer = ""
        continued = False
        try:
            async with asyncio.timeout(LOGIN_TIMEOUT_SECONDS):
                while True:
                    # A CLI waiting for a terminal prompt would otherwise leave
                    # the account screen on "preparing link" for ten minutes.
                    if "verification_url" in self.login:
                        chunk = await process.stdout.read(1024)
                    else:
                        chunk = await asyncio.wait_for(
                            process.stdout.read(1024), CLAUDE_LINK_TIMEOUT_SECONDS)
                    if not chunk:
                        break
                    # Keep raw CLI output private; expose only a validated provider URL.
                    buffer = (buffer + chunk.decode("utf-8", errors="replace"))[-16384:]
                    if url := _login_url_from_output(buffer):
                        self.login["verification_url"] = url
                    if not continued and re.search(r"press\s+enter\s+to\s+continue", _ANSI_CSI.sub("", buffer), re.I):
                        continued = True
                        if process.returncode is None:
                            try:
                                process.stdin.write(b"\n")
                                await process.stdin.drain()
                            except (OSError, ConnectionError):
                                pass
                await process.wait()
                self.login = {"status": "completed" if process.returncode == 0 else "failed",
                              "message": "로그인이 완료되었습니다." if process.returncode == 0 else
                              ("Claude Code가 인증 링크를 제공하지 않았습니다. 다시 시도해 주세요."
                               if "verification_url" not in self.login else "로그인에 실패했습니다. 다시 시도해 주세요.")}
        except TimeoutError:
            self.login = {"status": "expired", "message": (
                "Claude Code가 인증 링크를 제공하지 않았습니다. 다시 로그인해 주세요."
                if "verification_url" not in self.login else "로그인 시간이 만료되었습니다.")}
        except (OSError, ValueError):
            self.login = {"status": "failed", "message": "로그인 연결이 종료되었습니다. 다시 시도해 주세요."}
        finally:
            await stop_process(process)

    async def submit_code(self, code: str):
        if not self.process or self.process.returncode is not None or self.login.get("status") != "pending":
            raise ProviderError("진행 중인 로그인이 없습니다.", "login_missing")
        code = code.strip()
        if not code or len(code) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in code):
            raise ProviderError("인증 코드 형식을 확인해 주세요.", "invalid_code")
        try:
            self.process.stdin.write((code + "\n").encode())
            await self.process.stdin.drain()
        except (OSError, ConnectionError) as exc:
            await self.close()
            self.login = {"status": "failed"}
            raise ProviderError("로그인 연결이 종료되었습니다. 다시 시도해 주세요.") from exc
        return {"status": "pending", "message": "인증 코드를 전달했습니다."}

    async def _auth_command(self, name):
        process = await self._spawn(name)
        try:
            output = bytearray()
            async with asyncio.timeout(20):
                while chunk := await process.stdout.read(4096):
                    output.extend(chunk)
                    if len(output) > 65536:
                        raise ProviderError("Claude Code 응답이 허용 크기를 초과했습니다.", "invalid_response")
                await process.wait()
        except TimeoutError as exc:
            raise ProviderError("Claude Code 응답 시간이 초과되었습니다.", "timeout") from exc
        finally:
            await stop_process(process)
        return process.returncode, bytes(output)

    async def snapshot(self):
        if self.auth_kind == "api_key":
            await self.models()
            return {
                "status": "authenticated",
                "identity": {"authMethod": "api_key"},
                "quota": {
                    "status": "unsupported", "buckets": [], "checked_at": time.time(),
                    "message": "API 키 사용량은 Anthropic Console에서 확인해 주세요.",
                },
            }
        status, output = await self._auth_command("status")
        try:
            data = json.loads(output)
        except ValueError as exc:
            raise ProviderError("설치된 Claude Code의 인증 상태 형식을 지원하지 않습니다.", "unsupported") from exc
        if not isinstance(data, dict):
            raise ProviderError("Claude Code 인증 상태를 확인할 수 없습니다.", "invalid_response")
        authenticated = status == 0 and data.get("loggedIn") is True
        quota = await self._usage() if authenticated else {
            "status": "unauthenticated", "buckets": [], "checked_at": time.time()}
        return {"status": "authenticated" if authenticated else "signed_out",
                "identity": {key: data.get(key) for key in ("email", "authMethod", "subscriptionType") if key in data} if authenticated else None,
                "quota": quota}

    async def _usage(self) -> dict:
        now = time.monotonic()
        if now < self._usage_next_fetch and self._usage_cache is not None:
            return dict(self._usage_cache)
        credential = self.home / "claude" / ".credentials.json"
        try:
            if credential.is_symlink() or credential.stat().st_size > 65536:
                raise ValueError("invalid credential file")
            data = json.loads(credential.read_text(encoding="utf-8"))
            token = data["claudeAiOauth"]["accessToken"]
            if not isinstance(token, str) or not 16 <= len(token) <= 8192:
                raise ValueError("invalid OAuth token")
        except (OSError, ValueError, KeyError, TypeError):
            return {"status": "unsupported", "buckets": [], "checked_at": time.time(),
                    "message": "Claude 구독 사용량을 확인할 수 없습니다."}
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
                response = await client.get(CLAUDE_USAGE_URL, headers={
                    "Authorization": f"Bearer {token}", "anthropic-beta": "oauth-2025-04-20"})
            if response.status_code == 429:
                self._usage_next_fetch = now + CLAUDE_USAGE_BACKOFF_SECONDS
                self._usage_cache = {"status": "rate_limited", "buckets": [], "checked_at": time.time(),
                                     "message": "Claude 사용량 조회가 제한되었습니다. 잠시 후 다시 확인해 주세요."}
                return dict(self._usage_cache)
            response.raise_for_status()
            if len(response.content) > 65536:
                raise ValueError("usage response too large")
            quota = normalize_claude_usage(response.json())
            self._usage_cache = quota
            self._usage_next_fetch = now + CLAUDE_USAGE_CACHE_SECONDS
            return dict(quota)
        except (httpx.HTTPError, ValueError):
            self._usage_next_fetch = now + CLAUDE_USAGE_CACHE_SECONDS
            self._usage_cache = {"status": "unavailable", "buckets": [], "checked_at": time.time(),
                                 "message": "Claude 사용량을 조회하지 못했습니다."}
            return dict(self._usage_cache)

    def _api_key(self) -> str:
        credential = self.home / "claude" / ".api-key"
        descriptor = None
        try:
            if self.home.is_symlink() or credential.parent.is_symlink() or credential.is_symlink():
                raise ValueError("symlink credential path")
            descriptor = os.open(credential, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size < 20 or info.st_size > CLAUDE_API_KEY_MAX_BYTES
                or (os.name == "posix" and info.st_mode & 0o077)
            ):
                raise ValueError("invalid private credential")
            raw = os.read(descriptor, CLAUDE_API_KEY_MAX_BYTES + 1)
            key = raw.decode("ascii")
            if len(raw) != info.st_size or not re.fullmatch(r"[!-~]{20,8192}", key):
                raise ValueError("invalid private credential")
            return key
        except (OSError, ValueError, UnicodeError) as exc:
            raise ProviderError("Claude API 키를 다시 연결해 주세요.", "auth_required", stage="auth", retryable=False) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    async def probe_api_key(key: str) -> dict:
        """Fetch the account-specific API catalog without exposing the key or upstream body."""
        if not isinstance(key, str) or not re.fullmatch(r"[!-~]{20,8192}", key):
            raise ProviderError("API 키 형식을 확인해 주세요.", "invalid_api_key", stage="auth", retryable=False)
        models: list[dict] = []
        seen: set[str] = set()
        cursor = None
        try:
            async with httpx.AsyncClient(timeout=12, follow_redirects=False, trust_env=False) as client:
                for _ in range(10):
                    params = {"limit": "100"}
                    if cursor is not None:
                        params["after_id"] = cursor
                    response = await client.get(CLAUDE_MODELS_URL, params=params, headers={
                        "x-api-key": key, "anthropic-version": CLAUDE_API_VERSION,
                    })
                    if response.status_code in (401, 403):
                        raise ProviderError("Claude API 키 인증을 확인해 주세요.", "auth_required", stage="auth", retryable=False)
                    if response.status_code == 429:
                        raise ProviderError("Claude API 요청 제한에 도달했습니다.", "quota_exceeded", stage="quota", retryable=True)
                    if response.status_code != 200:
                        raise ProviderError("Claude 모델 목록을 확인하지 못했습니다.", "provider_unavailable", stage="model")
                    if len(response.content) > 512 * 1024:
                        raise ValueError("oversized model catalog")
                    payload = response.json()
                    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                        raise ValueError("invalid model catalog")
                    for item in payload["data"]:
                        if not isinstance(item, dict):
                            continue
                        model_id = item.get("id")
                        if not isinstance(model_id, str) or not re.fullmatch(r"claude-[A-Za-z0-9.-]{1,120}", model_id) or model_id in seen:
                            continue
                        seen.add(model_id)
                        display = item.get("display_name")
                        if not isinstance(display, str) or not display or len(display) > 160:
                            display = model_id
                        models.append({
                            "id": model_id, "model": model_id, "displayName": display,
                            "supportedReasoningEfforts": [
                                {"reasoningEffort": effort}
                                for effort in CLAUDE_EFFORTS
                                if effort != "xhigh" or model_id in CLAUDE_ULTRACODE_MODELS
                            ],
                            "supportsUltracode": model_id in CLAUDE_ULTRACODE_MODELS,
                            "serviceTiers": [],
                        })
                    if payload.get("has_more") is not True:
                        break
                    next_cursor = payload.get("last_id")
                    if not isinstance(next_cursor, str) or next_cursor == cursor:
                        raise ValueError("invalid model cursor")
                    cursor = next_cursor
        except (httpx.HTTPError, ValueError, UnicodeError, TypeError) as exc:
            raise ProviderError("Claude 모델 목록을 확인하지 못했습니다.", "provider_unavailable", stage="model") from exc
        if not models:
            raise ProviderError("이 API 키로 사용할 수 있는 Claude 모델이 없습니다.", "model_unavailable", stage="model", retryable=False)
        return {"status": "available", "source": "anthropic_api_models", "models": models}

    async def models(self):
        if self.auth_kind == "api_key":
            return await self.probe_api_key(self._api_key())
        return {
            "status": "available",
            "source": "claude_code_documented_models",
            "models": [
                {
                    "id": model,
                    "model": model,
                    "displayName": label,
                    "supportedReasoningEfforts": [
                        {"reasoningEffort": value}
                        for value in CLAUDE_EFFORTS
                        if value != "xhigh" or model in CLAUDE_ULTRACODE_MODELS
                    ],
                    "supportsUltracode": model in CLAUDE_ULTRACODE_MODELS,
                    "serviceTiers": [],
                }
                for model, label in CLAUDE_MODEL_ALIASES
            ],
        }

    async def logout(self):
        await self.cancel_login()
        if self.auth_kind == "api_key":
            target = self.home / "claude" / ".api-key"
            if self.home.is_symlink() or target.parent.is_symlink():
                raise ProviderError("계정 인증 저장 경로를 확인할 수 없습니다.", "invalid_auth_path", stage="auth")
            target.unlink(missing_ok=True)
            return
        status, _ = await self._auth_command("logout")
        if status:
            raise ProviderError("Claude Code 로그아웃에 실패했습니다.")

    async def cancel_login(self):
        await self.close()
        self.login = {"status": "cancelled"}
        return self.login

    async def close(self):
        if self.reader and self.reader is not asyncio.current_task() and not self.reader.done():
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        await stop_process(self.process)
        self.process = None
        self.reader = None
