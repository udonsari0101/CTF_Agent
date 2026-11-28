"""Exercise the model-visible source candidate feedback and worker handoff."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.submit_flag import main


class SourceCandidateFeedbackTests(unittest.TestCase):
    def test_remote_placeholder_is_rejected_before_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            challenge = Path(name) / "competition/challenge"
            workdir = challenge / "codex-workdir"
            (workdir / "attachments").mkdir(parents=True)
            source_flag = "Layer7{source_example}"
            (workdir / "attachments/bot.ts").write_text(
                f'const FLAG = "{source_flag}";', encoding="utf-8"
            )
            brief = challenge / "chal_desc.md"
            brief.write_text("# Example\nRemote: http://example.invalid:3000\n", encoding="utf-8")
            previous = Path.cwd()
            try:
                os.chdir(workdir)
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(main([source_flag]), 65)
                self.assertIn("independent verification", stderr.getvalue())
                self.assertNotIn(source_flag, stderr.getvalue())
                self.assertFalse((workdir / ".flag-candidate").exists())

                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["Layer7{observed_remote_value}"]), 0)
                self.assertEqual(
                    (workdir / ".flag-candidate").read_text(encoding="utf-8"),
                    "Layer7{observed_remote_value}",
                )
                (workdir / ".flag-candidate").unlink()

                brief.write_text("# Example\nRemote: none (configured)\n", encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main([source_flag]), 0)
                self.assertEqual(
                    (workdir / ".flag-candidate").read_text(encoding="utf-8"),
                    source_flag,
                )
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
