"""Offline contract for pinned CLI release monitoring."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import update_cli_versions  # noqa: E402


class VersionMonitorTests(unittest.TestCase):
    def test_update_keeps_image_and_provider_defaults_aligned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for locations in update_cli_versions.PINS.values():
                for filename, _ in locations:
                    source = ROOT / filename
                    target = root / filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            before = update_cli_versions.read_pins(root)
            target = {
                "codex": ".".join([*before["codex"].split(".")[:2],
                                      str(int(before["codex"].split(".")[2]) + 1)]),
                "claude": ".".join([*before["claude"].split(".")[:2],
                                       str(int(before["claude"].split(".")[2]) + 1)]),
            }
            self.assertTrue(update_cli_versions.update_pins(target, root))
            self.assertEqual(update_cli_versions.read_pins(root), target)
            self.assertFalse(update_cli_versions.update_pins(target, root))
            with self.assertRaisesRegex(ValueError, "Refusing to downgrade"):
                update_cli_versions.update_pins(before, root)

    def test_rejects_unpinned_or_divergent_release(self) -> None:
        for invalid in ("2.1.99-beta", "latest", "2.1", "2.1.4\nARG TEST=1"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                update_cli_versions._checked_version(invalid)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for locations in update_cli_versions.PINS.values():
                for filename, _ in locations:
                    source = ROOT / filename
                    target = root / filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            source = root / "ctf_agent/solver_worker.py"
            before = update_cli_versions.read_pins(root)
            text = source.read_text(encoding="utf-8")
            text = text.replace(
                f'CTF_IMAGE_CODEX_VERSION", "{before["codex"]}"',
                'CTF_IMAGE_CODEX_VERSION", "9.0.0"', 1,
            )
            source.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "versions disagree"):
                update_cli_versions.read_pins(root)


if __name__ == "__main__":
    unittest.main()
