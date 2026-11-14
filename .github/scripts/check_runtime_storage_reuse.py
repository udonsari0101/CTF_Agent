"""Bundled CLI releases must not keep duplicate published package trees."""

from __future__ import annotations

import sys
import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.db import Settings  # noqa: E402
from ctf_agent.main import create_app  # noqa: E402
from ctf_agent.providers.runtime import CodexRuntime  # noqa: E402
from ctf_agent.solver_worker import REQUIRED_CODEX_VERSION  # noqa: E402


class RuntimeStorageReuseTests(unittest.TestCase):
    def test_old_installs_are_removed_without_losing_rollback(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            runtime = CodexRuntime(root)
            runtime.save({"selected": None, "previous": "0.165.0"})
            for version in ("0.153.4", "0.164.0", "0.165.0"):
                package = root / f"codex-{version}"
                package.mkdir()
                (package / "cli").write_bytes(b"installed CLI")
            unrelated = root / "codex-invalid"
            unrelated.mkdir()
            CodexRuntime(root)
            self.assertFalse((root / "codex-0.153.4").exists())
            self.assertFalse((root / "codex-0.164.0").exists())
            self.assertTrue((root / "codex-0.165.0" / "cli").exists())
            self.assertTrue(unrelated.exists())

    def test_unknown_runtime_state_does_not_remove_installs(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            package = root / "codex-0.165.0"
            package.mkdir()
            CodexRuntime(root)
            self.assertTrue(package.exists())

    def test_old_installer_cache_is_removed_without_touching_package(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            package = root / f"codex-{REQUIRED_CODEX_VERSION}"
            native = package / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
            native.parent.mkdir(parents=True)
            native.write_text("official package", encoding="utf-8")
            for name in (".npm-cache", "installer-home"):
                disposable = package / name
                disposable.mkdir()
                (disposable / "archive").write_bytes(b"cache")
            CodexRuntime(root)
            self.assertTrue(native.exists())
            self.assertFalse((package / ".npm-cache").exists())
            self.assertFalse((package / "installer-home").exists())

    def test_bundled_version_reclaims_old_published_copy_when_idle(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                                storage_min_free_bytes=0, auth_mode="nologin")
            app = create_app(settings)
            service = app.state.solver
            self.assertIsNone(service._runtime_source(REQUIRED_CODEX_VERSION, REQUIRED_CODEX_VERSION))
            destination = service.coordinator.primary.exchange / "runtime" / f"codex-{REQUIRED_CODEX_VERSION}"
            destination.mkdir(parents=True)
            (destination / "old-package").write_bytes(b"derived copy")
            stale = destination.parent / "codex-0.165.0"
            stale.mkdir()
            (stale / "old-package").write_bytes(b"stale derived copy")
            claude = destination.parent / "claude-2.1.310"
            claude.mkdir()
            (claude / "package").write_bytes(b"other provider")
            result = service.coordinator.publish_runtime(REQUIRED_CODEX_VERSION, None)
            self.assertEqual(result, {"version": REQUIRED_CODEX_VERSION,
                                      "sha256": None, "source": "image"})
            self.assertFalse(destination.exists())
            self.assertFalse(stale.exists())
            self.assertTrue(claude.exists())

            destination.mkdir()
            (destination / "active-package").write_bytes(b"needed by a job")
            stale.mkdir()
            with patch.object(service.coordinator.primary, "has_open_jobs", return_value=True):
                result = service.coordinator.publish_runtime(REQUIRED_CODEX_VERSION, None)
            self.assertEqual(result["source"], "image")
            self.assertTrue((destination / "active-package").exists())
            self.assertTrue(stale.exists())

    @unittest.skipIf(os.name == "nt", "bundled executable check runs in the Linux image")
    def test_select_bundled_keeps_rollback_and_restores_failed_switch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "codex"
            executable.write_text(f"#!/bin/sh\necho codex-cli {REQUIRED_CODEX_VERSION}\n")
            executable.chmod(0o755)
            runtime = CodexRuntime(root / "runtime")
            old = {"selected": "0.165.0", "previous": "0.164.0"}
            runtime.save(old)
            with (patch("ctf_agent.providers.runtime.shutil.which", return_value=str(executable)),
                  patch.object(runtime, "verify", new=AsyncMock())):
                switched = AsyncMock()
                result = asyncio.run(runtime.select_bundled(REQUIRED_CODEX_VERSION, switched))
                self.assertIsNone(result["selected"])
                self.assertEqual(runtime.state()["previous"], "0.165.0")
                switched.assert_awaited_once()

                runtime.save(old)
                failed = AsyncMock(side_effect=RuntimeError("publish failed"))
                with self.assertRaisesRegex(RuntimeError, "publish failed"):
                    asyncio.run(runtime.select_bundled(REQUIRED_CODEX_VERSION, failed))
                self.assertEqual(runtime.state(), old)


if __name__ == "__main__":
    unittest.main(verbosity=2)
