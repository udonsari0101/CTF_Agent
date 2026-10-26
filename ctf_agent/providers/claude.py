"""Fixed Claude Code auth commands, with an OAuth URL/code bridge for containers."""

import asyncio
from datetime import datetime
import json
import math
import re
import shutil
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
    return {"status": "available" if windows else "unavailable", "source": "claude_oauth_usage",
            "buckets": [{"id": "claude", "name": "Claude Code", "windows": windows}] if windows else [],
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
    def __init__(self, home: Path, command=None):
        self.home = home
        self.command = command or (lambda: [shutil.which("claude")] if shutil.which("claude") else [])
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

    async def models(self):
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
                    ] + ([{"reasoningEffort": "ultracode"}] if model in CLAUDE_ULTRACODE_MODELS else []),
                    "serviceTiers": [],
                }
                for model, label in CLAUDE_MODEL_ALIASES
            ],
        }

    async def logout(self):
        await self.cancel_login()
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
