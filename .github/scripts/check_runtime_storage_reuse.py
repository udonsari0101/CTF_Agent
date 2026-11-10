"""Bundled CLI releases must not keep duplicate published package trees."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.db import Settings  # noqa: E402
from ctf_agent.main import create_app  # noqa: E402
from ctf_agent.providers.runtime import CodexRuntime  # noqa: E402
from ctf_agent.solver_worker import REQUIRED_CODEX_VERSION  # noqa: E402


class RuntimeStorageReuseTests(unittest.TestCase):
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
            result = service.coordinator.publish_runtime(REQUIRED_CODEX_VERSION, None)
            self.assertEqual(result, {"version": REQUIRED_CODEX_VERSION,
                                      "sha256": None, "source": "image"})
            self.assertFalse(destination.exists())

            destination.mkdir()
            (destination / "active-package").write_bytes(b"needed by a job")
            with patch.object(service.coordinator.primary, "has_open_jobs", return_value=True):
                result = service.coordinator.publish_runtime(REQUIRED_CODEX_VERSION, None)
            self.assertEqual(result["source"], "image")
            self.assertTrue((destination / "active-package").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
