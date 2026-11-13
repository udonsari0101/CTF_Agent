"""Catch silent short reads while staging a solve workspace."""

import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.agent_workspace import _copy_regular_tree  # noqa: E402


class WorkspaceCopyIntegrityTests(unittest.TestCase):
    def test_complete_input_is_staged(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "input"
            target = Path(root) / "workdir"
            source.mkdir()
            target.mkdir()
            content = b"a" * (1024 * 1024 + 7)
            (source / "handout.bin").write_bytes(content)

            staged = _copy_regular_tree(source, target)

            self.assertEqual((target / "handout.bin").read_bytes(), content)
            self.assertEqual(len(staged), 1)

    def test_short_read_is_rejected_before_the_solver_starts(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "input"
            target = Path(root) / "workdir"
            source.mkdir()
            target.mkdir()
            handout = source / "handout.bin"
            handout.write_bytes(b"nonempty original")
            original_open = Path.open

            def open_with_short_read(path, *args, **kwargs):
                if path == handout and args[0] == "rb":
                    return io.BytesIO(b"")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", open_with_short_read):
                with self.assertRaisesRegex(ValueError, "truncated"):
                    _copy_regular_tree(source, target)

            self.assertFalse((target / "handout.bin").exists())
            self.assertEqual(handout.read_bytes(), b"nonempty original")


if __name__ == "__main__":
    unittest.main()
