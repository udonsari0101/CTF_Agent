"""Regression for provider-scoped native CLI session compatibility."""

from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_exchange import _matching_provider_runtime  # noqa: E402


class ResumeRuntimeCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.source = self.db.execute(
            """SELECT ? AS codex_version, ? AS codex_runtime_sha256,
                      ? AS claude_version, ? AS claude_runtime_sha256""",
            ("1.2.3", "a" * 64, "4.5.6", "b" * 64),
        ).fetchone()

    def tearDown(self) -> None:
        self.db.close()

    def test_codex_session_survives_unrelated_claude_update(self) -> None:
        self.assertTrue(_matching_provider_runtime(
            self.source, "codex", codex_version="1.2.3",
            codex_runtime_sha256="a" * 64,
            claude_version="4.5.7", claude_runtime_sha256="c" * 64,
        ))

    def test_claude_session_survives_unrelated_codex_update(self) -> None:
        self.assertTrue(_matching_provider_runtime(
            self.source, "claude", codex_version="1.2.4",
            codex_runtime_sha256="d" * 64,
            claude_version="4.5.6", claude_runtime_sha256="b" * 64,
        ))

    def test_selected_runtime_change_still_blocks_native_resume(self) -> None:
        for provider, codex_version, claude_digest in (
            ("codex", "1.2.4", "b" * 64),
            ("claude", "1.2.3", "c" * 64),
        ):
            with self.subTest(provider=provider):
                self.assertFalse(_matching_provider_runtime(
                    self.source, provider, codex_version=codex_version,
                    codex_runtime_sha256="a" * 64,
                    claude_version="4.5.6", claude_runtime_sha256=claude_digest,
                ))


if __name__ == "__main__":
    unittest.main()
