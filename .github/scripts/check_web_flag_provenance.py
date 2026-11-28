"""Regression cases for source-literal flag handoff on remote web challenges."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.flag_provenance import literal_in_supplied_inputs


class WebFlagProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workdir = Path(temporary.name)
        (self.workdir / "attachments").mkdir()
        (self.workdir / "extracted" / "source").mkdir(parents=True)

    def test_source_literal_is_detected_across_read_chunks(self) -> None:
        candidate = "CTF{source_placeholder_not_remote}"
        (self.workdir / "extracted" / "source" / "bot.ts").write_bytes(
            b"x" * (64 * 1024 - 8) + candidate.encode() + b"\n"
        )
        self.assertTrue(literal_in_supplied_inputs(self.workdir, candidate))

    def test_remote_unique_value_does_not_match_local_source(self) -> None:
        (self.workdir / "extracted" / "source" / "bot.ts").write_text(
            'const FLAG="CTF{source_placeholder}";', encoding="utf-8"
        )
        self.assertFalse(
            literal_in_supplied_inputs(self.workdir, "CTF{remote_random_value}")
        )

    def test_model_generated_files_are_not_evidence_of_local_literal(self) -> None:
        (self.workdir / "solver.py").write_text('print("CTF{model_result}")')
        (self.workdir / "notes.md").write_text("CTF{model_result}")
        self.assertFalse(literal_in_supplied_inputs(self.workdir, "CTF{model_result}"))

    def test_description_literal_and_symlink_boundaries(self) -> None:
        candidate = "CTF{example_only}"
        self.assertTrue(
            literal_in_supplied_inputs(self.workdir, candidate, "Example: " + candidate)
        )
        outside = self.workdir / "outside"
        outside.write_text(candidate)
        try:
            (self.workdir / "attachments" / "outside-link").symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        self.assertFalse(literal_in_supplied_inputs(self.workdir, candidate))


if __name__ == "__main__":
    unittest.main()
