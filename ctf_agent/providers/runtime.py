"""Install only exact versions of the official Codex npm package."""

import asyncio
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

import httpx

from ..codex_native import native_codex_binary
from .codex import CodexAccount, ProviderError, isolated_environment, stop_process


VERSION = re.compile(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\Z")
STAGE = re.compile(r"install-[0-9a-f]{32}\Z")
RUNTIME_INSTALL_RESERVATION = 1024 * 1024 * 1024


class CodexRuntime:
    def __init__(self, root: Path, storage_budget=None):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.storage_budget = storage_budget
        self._cleanup_interrupted()
        if self.storage_budget is not None:
            # No install subprocess survives application startup. Remove a
            # crash-left reservation only after its exact stage was removed.
            self.storage_budget.reconcile_kind("runtime", {})
        self.state_file = self.root / "codex-runtime.json"
        self.task = None
        self.operation = {"status": "idle"}
        self.lock = asyncio.Lock()
        self.status_lock = asyncio.Lock()
        self.status_cache = None
        self.rolling_back = False

    def _remove_child(self, path: Path):
        if path.parent.resolve() != self.root.resolve():
            raise RuntimeError("invalid runtime cleanup path")
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)

    def _cleanup_interrupted(self):
        for path in tuple(self.root.iterdir()):
            if STAGE.fullmatch(path.name) or path.name == "installer":
                self._remove_child(path)

    @staticmethod
    def _tree_size(root: Path) -> int:
        total = 0
        pending = [root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        total += entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    else:
                        total += entry.stat(follow_symlinks=False).st_size
        return total

    async def _wait_for_install(self, process, stage):
        while process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), 0.5)
            except TimeoutError:
                if self._tree_size(stage) > RUNTIME_INSTALL_RESERVATION:
                    process.kill()
                    await process.wait()
                    raise ProviderError("The Codex runtime package exceeded the safe installation size.")
                if (self.storage_budget is not None and
                        shutil.disk_usage(self.root).free < self.storage_budget.minimum_free_bytes):
                    process.kill()
                    await process.wait()
                    raise ProviderError("The Codex runtime update stopped before using reserved free space.")
        return process.returncode

    @property
    def busy(self):
        return self.rolling_back or bool(self.task and not self.task.done())

    def state(self):
        try:
            result = json.loads(self.state_file.read_text(encoding="utf-8"))
            return result if isinstance(result, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self, state):
        temporary = self.state_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(state), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.state_file)
        self.status_cache = None

    def version_command(self, version):
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            return []
        executable = self.root / f"codex-{version}" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
        node = shutil.which("node")
        return [node, str(executable)] if node and executable.is_file() else []

    def command(self):
        selected = self.state().get("selected")
        if selected:
            command = self.version_command(selected)
            if command:
                return command
            # An explicit selected version must not silently fall back to another one.
            return []
        binary = shutil.which("codex")
        if os.name == "nt" and binary and binary.lower().endswith((".cmd", ".ps1")):
            return []
        return [binary] if binary else []

    async def status(self):
        now = time.monotonic()
        cached = self.status_cache
        if not cached or now - cached[0] >= 5:
            async with self.status_lock:
                now = time.monotonic()
                cached = self.status_cache
                if not cached or now - cached[0] >= 5:
                    command = self.command()
                    version = None
                    if command:
                        process = None
                        try:
                            process = await asyncio.create_subprocess_exec(*command, "--version",
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                                env=isolated_environment(self.root / "probe"), cwd=self.root)
                            output, _ = await asyncio.wait_for(process.communicate(), 10)
                            match = re.search(rb"\b[0-9]+\.[0-9]+\.[0-9]+\b", output[:2048])
                            version = match.group().decode() if process.returncode == 0 and match else None
                        except (OSError, TimeoutError):
                            pass
                        finally:
                            await stop_process(process)
                    installed = sorted(
                        path.name.removeprefix("codex-")
                        for path in self.root.glob("codex-*")
                        if VERSION.fullmatch(path.name.removeprefix("codex-"))
                        and self.version_command(path.name.removeprefix("codex-"))
                    )
                    cached = (now, {
                        "available": version is not None,
                        "version": version,
                        "installed": installed,
                        "update_supported": bool(
                            shutil.which("npm") and shutil.which("node") and os.name != "nt"
                        ),
                    })
                    self.status_cache = cached
        state = self.state()
        return {
            **cached[1],
            "selected": state.get("selected"),
            "previous": state.get("previous"),
            "operation": dict(self.operation),
        }

    async def catalog(self):
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                response = await client.get("https://registry.npmjs.org/@openai/codex/latest")
                response.raise_for_status()
                version = response.json().get("version")
            if not isinstance(version, str) or not VERSION.fullmatch(version):
                raise ValueError("unsupported version format")
            return {"latest": version, "checked_at": time.time()}
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError("공식 패키지 버전을 조회할 수 없습니다.") from exc

    async def update(self, version: str, after_switch):
        if not VERSION.fullmatch(version):
            raise ProviderError("버전은 0.164.0 같은 정확한 숫자 버전이어야 합니다.", "invalid_version")
        if self.busy:
            raise ProviderError("다른 업데이트가 진행 중입니다.", "busy")
        if os.name == "nt" or not shutil.which("npm"):
            raise ProviderError("이 환경에서는 웹 업데이트를 지원하지 않습니다.", "unsupported")
        self.operation = {"status": "installing", "version": version, "started_at": time.time()}
        self.task = asyncio.create_task(self._install(version, after_switch))
        return dict(self.operation)

    async def _install(self, version: str, after_switch):
        async with self.lock:
            process = None
            stage = None
            created_destination = None
            previous_state = self.state()
            switched = False
            try:
                destination = self.root / f"codex-{version}"
                if not self.version_command(version):
                    stage = self.root / f"install-{uuid.uuid4().hex}"
                    reservation = "runtime:" + stage.name.removeprefix("install-")
                    if self.storage_budget is not None:
                        self.storage_budget.reserve(
                            reservation, "runtime", "system", "runtime", None,
                            RUNTIME_INSTALL_RESERVATION,
                        )
                    stage.mkdir(mode=0o700)
                    env = isolated_environment(stage / "installer-home")
                    env["npm_config_cache"] = str(stage / ".npm-cache")
                    # Fixed registry/package and argument-list execution; no install hooks or client commands.
                    process = await asyncio.create_subprocess_exec(shutil.which("npm"), "install", "--prefix", str(stage),
                        "--registry=https://registry.npmjs.org", "--ignore-scripts", "--no-audit", "--no-fund", "--omit=dev",
                        f"@openai/codex@{version}", stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL, env=env, cwd=stage)
                    await asyncio.wait_for(self._wait_for_install(process, stage), 300)
                    if process.returncode != 0:
                        raise ProviderError("공식 Codex 패키지 설치에 실패했습니다.")
                    if self._tree_size(stage) > RUNTIME_INSTALL_RESERVATION:
                        raise ProviderError("The Codex runtime package exceeded the safe installation size.")
                    if destination.exists():
                        raise ProviderError("기존 버전 디렉터리를 확인해야 합니다.")
                    stage.rename(destination)
                    created_destination = destination
                self.operation["status"] = "verifying"
                command = self.version_command(version)
                if not command:
                    raise ProviderError("설치된 실행 파일을 확인할 수 없습니다.")
                await self.verify(command, version=version)
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
                                  "message": "업데이트에 실패했습니다. 기존 선택 버전을 유지합니다."}
            finally:
                # Only directories generated by this operation, verified beneath runtime, are removable.
                try:
                    for cleanup in (stage, created_destination if self.operation["status"] != "completed" else None):
                        if (cleanup and cleanup.exists() and not cleanup.is_symlink()
                                and cleanup.resolve().parent == self.root.resolve()):
                            try:
                                shutil.rmtree(cleanup)
                            except OSError:
                                # The exact operation-owned path remains inert.
                                # Startup retries interrupted install stages;
                                # complete package trees may be reused by a
                                # later verified update to the same version.
                                pass
                finally:
                    # A completed subprocess no longer owns future capacity.
                    # Physical free-space checks still account for any tree
                    # whose best-effort cleanup failed.
                    if stage is not None and self.storage_budget is not None:
                        self.storage_budget.release("runtime:" + stage.name.removeprefix("install-"))

    async def verify(self, command, *, version: str | None = None):
        if version is not None:
            package_root = self.root / f"codex-{version}" / "node_modules" / "@openai" / "codex"
            native = native_codex_binary(package_root)
            if native is None:
                raise ProviderError(
                    "설치된 Codex에서 worker용 실행 파일을 찾을 수 없습니다.",
                    "native_runtime_unavailable",
                )
            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    str(native), "--version", stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=isolated_environment(self.root / "probe"), cwd=self.root,
                )
                output, _ = await asyncio.wait_for(process.communicate(), 10)
                if process.returncode != 0 or version.encode() not in output[:2048]:
                    raise ProviderError(
                        "설치된 Codex 실행 파일의 버전을 확인할 수 없습니다.",
                        "native_runtime_unavailable",
                    )
            except (OSError, TimeoutError) as exc:
                raise ProviderError(
                    "설치된 Codex 실행 파일을 실행할 수 없습니다.",
                    "native_runtime_unavailable",
                ) from exc
            finally:
                await stop_process(process)
        probe = CodexAccount(self.root / "probe-auth", command)
        try:
            await probe.start()
            await probe.request("account/read", {"refreshToken": False})
        finally:
            await probe.close()

    async def rollback(self, after_switch):
        if self.busy:
            raise ProviderError("업데이트가 진행 중입니다.", "busy")
        self.rolling_back = True
        try:
            async with self.lock:
                return await self._rollback(after_switch)
        finally:
            self.rolling_back = False

    async def _rollback(self, after_switch):
        current = self.state()
        if not current.get("selected"):
            raise ProviderError("복원할 이전 선택이 없습니다.", "unavailable")
        previous = current.get("previous")
        if previous and not self.version_command(previous):
            raise ProviderError("이전 버전 실행 파일이 없습니다.", "unavailable")
        fallback = shutil.which("codex")
        command = self.version_command(previous) if previous else [fallback] if fallback else []
        if not command:
            raise ProviderError("이전 기본 Codex 실행 파일이 없습니다.", "unavailable")
        await self.verify(command, version=previous)
        try:
            self.save({"selected": previous, "previous": current.get("selected"), "updated_at": time.time()})
            await after_switch()
        except BaseException:
            self.save(current)
            raise
        return await self.status()

    async def close(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
