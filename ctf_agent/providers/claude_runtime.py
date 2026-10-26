"""Install and select exact Claude Code CLI versions from the service UI."""

import asyncio
import json
import os
import platform
import re
import shutil
import time
import uuid
from pathlib import Path

import httpx

from .codex import ProviderError, isolated_environment, stop_process
from .runtime import CodexRuntime, RUNTIME_INSTALL_RESERVATION, VERSION


class ClaudeRuntime(CodexRuntime):
    def __init__(self, root: Path, storage_budget=None):
        super().__init__(root, storage_budget)
        self.state_file = self.root / "claude-runtime.json"

    @staticmethod
    def _platform_package() -> str | None:
        architecture = platform.machine().lower()
        suffix = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(architecture)
        return f"claude-code-linux-{suffix}" if os.name == "posix" and suffix else None

    def version_command(self, version):
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            return []
        package = self._platform_package()
        if not package:
            return []
        root = self.root / f"claude-{version}" / "node_modules" / "@anthropic-ai"
        executable = root / package / "claude"
        manifest = root / "claude-code" / "package.json"
        try:
            if executable.is_symlink() or not executable.is_file() or not manifest.is_file():
                return []
            if json.loads(manifest.read_text(encoding="utf-8")).get("version") != version:
                return []
            if not executable.stat().st_mode & 0o111:
                return []
        except (OSError, ValueError):
            return []
        return [str(executable)]

    def command(self):
        selected = self.state().get("selected")
        if selected:
            return self.version_command(selected)
        binary = shutil.which("claude")
        return [binary] if binary and not binary.lower().endswith((".cmd", ".ps1")) else []

    async def status(self):
        result = await super().status()
        result["installed"] = sorted(
            version for path in self.root.glob("claude-*")
            if VERSION.fullmatch(version := path.name.removeprefix("claude-")) and self.version_command(version)
        )
        return result

    async def catalog(self):
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                response = await client.get("https://registry.npmjs.org/@anthropic-ai/claude-code/latest")
                response.raise_for_status()
                version = response.json().get("version")
            if not isinstance(version, str) or not VERSION.fullmatch(version):
                raise ValueError("unsupported version format")
            return {"latest": version, "checked_at": time.time()}
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError("Claude Code 최신 버전을 조회하지 못했습니다.") from exc

    async def verify(self, command):
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command, "--version", stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=isolated_environment(self.root / "probe"), cwd=self.root,
            )
            output, _ = await asyncio.wait_for(process.communicate(), 20)
            match = re.search(rb"\b([0-9]+\.[0-9]+\.[0-9]+)\b", output[:2048])
            if process.returncode != 0 or not match or match.group(1).decode() != self._verifying_version:
                raise ProviderError("Claude Code 실행 버전이 요청한 버전과 다릅니다.")
            process = await asyncio.create_subprocess_exec(
                *command, "--help", stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=isolated_environment(self.root / "probe"), cwd=self.root,
            )
            help_output, _ = await asyncio.wait_for(process.communicate(), 20)
            required = (b"--restricted", b"--output-format", b"--include-partial-messages",
                        b"--json-schema", b"--session-id", b"--resume", b"--model",
                        b"--effort", b"--allowedTools", b"--disallowedTools",
                        b"--permission-mode", b"--permission-prompts",
                        b"--disable-slash-commands", b"--settings")
            if process.returncode != 0 or any(option not in help_output for option in required):
                raise ProviderError("설치한 Claude Code가 필요한 풀이 옵션을 지원하지 않습니다.")
        except (OSError, TimeoutError) as exc:
            raise ProviderError("Claude Code 실행 파일을 검증하지 못했습니다.") from exc
        finally:
            await stop_process(process)

    async def _install(self, version: str, after_switch):
        async with self.lock:
            process = None
            stage = None
            created_destination = None
            previous_state = self.state()
            switched = False
            try:
                destination = self.root / f"claude-{version}"
                if not self.version_command(version):
                    stage = self.root / f"install-{uuid.uuid4().hex}"
                    reservation = "runtime:" + stage.name.removeprefix("install-")
                    if self.storage_budget is not None:
                        self.storage_budget.reserve(reservation, "runtime", "system", "runtime", None,
                                                    RUNTIME_INSTALL_RESERVATION)
                    stage.mkdir(mode=0o700)
                    env = isolated_environment(stage / "installer-home")
                    env["npm_config_cache"] = str(stage / ".npm-cache")
                    process = await asyncio.create_subprocess_exec(
                        shutil.which("npm"), "install", "--prefix", str(stage),
                        "--registry=https://registry.npmjs.org", "--ignore-scripts",
                        "--no-audit", "--no-fund", "--omit=dev",
                        f"@anthropic-ai/claude-code@{version}",
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                        env=env, cwd=stage,
                    )
                    await asyncio.wait_for(self._wait_for_install(process, stage), 300)
                    if process.returncode != 0:
                        raise ProviderError("Claude Code 패키지 설치에 실패했습니다.")
                    if self._tree_size(stage) > RUNTIME_INSTALL_RESERVATION:
                        raise ProviderError("Claude Code 설치 크기 제한을 초과했습니다.")
                    for disposable in (stage / ".npm-cache", stage / "installer-home"):
                        if disposable.is_dir() and not disposable.is_symlink():
                            shutil.rmtree(disposable)
                    if destination.exists():
                        raise ProviderError("기존 버전 디렉터리를 확인해야 합니다.")
                    stage.rename(destination)
                    created_destination = destination
                self.operation["status"] = "verifying"
                command = self.version_command(version)
                if not command:
                    raise ProviderError("Claude Code 실행 파일을 찾지 못했습니다.")
                self._verifying_version = version
                await self.verify(command)
                previous = previous_state.get("previous") if previous_state.get("selected") == version else previous_state.get("selected")
                self.save({"selected": version, "previous": previous, "updated_at": time.time()})
                switched = True
                await after_switch()
                self.operation = {"status": "completed", "version": version, "finished_at": time.time()}
            except asyncio.CancelledError:
                if process and process.returncode is None:
                    process.kill()
                    await process.wait()
                self.operation = {"status": "interrupted", "version": version}
                if switched:
                    self.save(previous_state)
                raise
            except Exception:
                if process and process.returncode is None:
                    process.kill()
                    await process.wait()
                if switched:
                    self.save(previous_state)
                self.operation = {"status": "failed", "version": version,
                                  "message": "Claude Code 업데이트에 실패했습니다. 이전 버전은 유지됩니다."}
            finally:
                for cleanup in (stage, created_destination if self.operation["status"] != "completed" else None):
                    if cleanup and cleanup.exists() and not cleanup.is_symlink() and cleanup.resolve().parent == self.root.resolve():
                        try:
                            shutil.rmtree(cleanup)
                        except OSError:
                            pass
                if stage is not None and self.storage_budget is not None:
                    self.storage_budget.release("runtime:" + stage.name.removeprefix("install-"))

    async def _rollback(self, after_switch):
        current = self.state()
        if not current.get("selected"):
            raise ProviderError("복원할 Claude Code 선택 버전이 없습니다.", "unavailable")
        previous = current.get("previous")
        command = self.version_command(previous) if previous else [shutil.which("claude")]
        if not command or not command[0]:
            raise ProviderError("이전 Claude Code 실행 파일을 찾지 못했습니다.", "unavailable")
        self._verifying_version = previous or os.environ.get("CTF_IMAGE_CLAUDE_VERSION", "2.1.310")
        await self.verify(command)
        try:
            self.save({"selected": previous, "previous": current["selected"], "updated_at": time.time()})
            await after_switch()
        except BaseException:
            self.save(current)
            raise
        return await self.status()
