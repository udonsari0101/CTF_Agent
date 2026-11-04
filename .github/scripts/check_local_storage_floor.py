"""Boundary checks for the managed Windows/WSL local storage policy."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent import release_updates  # noqa: E402
from scripts import package_local_release  # noqa: E402


def load_source(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load_source("storage_preflight", ROOT / "installer/installer/storage_preflight.py")
local_compose = load_source("local_compose", ROOT / "deploy/local-compose.py")
GIB = 1024**3


class LocalStoragePolicyTests(unittest.TestCase):
    @staticmethod
    def usage(free_by_path: dict[str, int]):
        return lambda path: SimpleNamespace(free=free_by_path[Path(path).name])

    def test_cold_and_cached_pull_estimates_leave_five_gib(self) -> None:
        self.assertEqual(preflight.required_free_bytes("before-pull", False), 15 * GIB)
        self.assertEqual(preflight.required_free_bytes("before-pull", True), 7 * GIB)
        self.assertEqual(preflight.required_free_bytes("after-pull", False), 5 * GIB)
        with self.assertRaises(ValueError):
            preflight.required_free_bytes("unknown", False)

    def test_application_and_separate_database_are_checked_independently(self) -> None:
        with mock.patch.object(preflight.shutil, "disk_usage", side_effect=self.usage({
            "app": 15 * GIB, "db": 5 * GIB,
        })):
            self.assertEqual(preflight.check_space(
                Path("/app"), Path("/db"), stage="before-pull", image_cached=False,
            ), (15 * GIB, 5 * GIB))
        for free in ({"app": 15 * GIB - 1, "db": 5 * GIB},
                     {"app": 15 * GIB, "db": 5 * GIB - 1}):
            with self.subTest(free=free), mock.patch.object(
                preflight.shutil, "disk_usage", side_effect=self.usage(free)
            ), self.assertRaises(RuntimeError):
                preflight.check_space(Path("/app"), Path("/db"),
                                      stage="before-pull", image_cached=False)

    def test_update_archive_and_extract_budget_is_separate_from_pull(self) -> None:
        required = (5 * GIB + release_updates.MAX_ARCHIVE_BYTES
                    + release_updates.MAX_UNPACKED_BYTES)
        with mock.patch.object(release_updates.shutil, "disk_usage", side_effect=self.usage({
            "app": required, "db": 5 * GIB,
        })):
            release_updates._require_local_update_staging_space(
                Path("/app"), Path("/db"), external_database=True,
            )
        for free in ({"app": required - 1, "db": 5 * GIB},
                     {"app": required, "db": 5 * GIB - 1}):
            with self.subTest(free=free), mock.patch.object(
                release_updates.shutil, "disk_usage", side_effect=self.usage(free)
            ), self.assertRaises(ValueError):
                release_updates._require_local_update_staging_space(
                    Path("/app"), Path("/db"), external_database=True,
                )

    def test_managed_runtime_sets_default_without_overwriting_operator_value(self) -> None:
        environment: dict[str, str] = {}
        local_compose.set_local_storage_floor(environment)
        self.assertEqual(environment["CTF_STORAGE_MIN_FREE_BYTES"], str(5 * GIB))
        environment["CTF_STORAGE_MIN_FREE_BYTES"] = str(6 * GIB)
        local_compose.set_local_storage_floor(environment)
        self.assertEqual(environment["CTF_STORAGE_MIN_FREE_BYTES"], str(6 * GIB))

    def test_release_zip_contains_preflight_used_by_installer(self) -> None:
        source = "installer/installer/storage_preflight.py"
        self.assertEqual(package_local_release.INSTALLER_FILES[source],
                         "installer/storage_preflight.py")
        tracked = package_local_release.tracked_files() | {
            source, "installer/DockerDisk.ps1",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            package_local_release, "tracked_files", return_value=tracked
        ):
            archive = Path(directory) / "local.zip"
            package_local_release.create_archive("v0.0.1", "a" * 40, archive)
            with zipfile.ZipFile(archive) as bundle:
                self.assertIn("CTF_Agent-v0.0.1/installer/storage_preflight.py",
                              bundle.namelist())
                self.assertEqual(bundle.read(
                    "CTF_Agent-v0.0.1/installer/storage_preflight.py"
                ), (ROOT / source).read_bytes())


if __name__ == "__main__":
    unittest.main()
