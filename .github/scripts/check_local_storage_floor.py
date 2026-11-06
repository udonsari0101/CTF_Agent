"""Boundary checks for the managed Windows/WSL local storage policy."""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent import release_updates  # noqa: E402
from ctf_agent.storage_budget import StorageBudget, StorageBudgetError  # noqa: E402
from ctf_agent.solver_exchange import _minimum_free_after_unreserved_stage  # noqa: E402
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

    def test_application_staging_does_not_duplicate_the_docker_pull(self) -> None:
        self.assertEqual(preflight.required_free_bytes("before-pull", False), 6 * GIB)
        self.assertEqual(preflight.required_free_bytes("before-pull", True), 6 * GIB)
        self.assertEqual(preflight.required_free_bytes("after-pull", False), 5 * GIB)
        with self.assertRaises(ValueError):
            preflight.required_free_bytes("unknown", False)

    def test_existing_service_restart_has_no_installation_space_preflight(self) -> None:
        restart = (ROOT / "installer/installer/start.sh").read_text(encoding="utf-8")
        install = (ROOT / "installer/installer/install.sh").read_text(encoding="utf-8")
        self.assertNotIn("storage_preflight.py", restart)
        self.assertIn("storage_preflight.py", install)

    def test_application_and_separate_database_are_checked_independently(self) -> None:
        with mock.patch.object(preflight.shutil, "disk_usage", side_effect=self.usage({
            "app": 6 * GIB, "db": 5 * GIB,
        })):
            self.assertEqual(preflight.check_space(
                Path("/app"), Path("/db"), stage="before-pull", image_cached=False,
            ), (6 * GIB, 5 * GIB))
        for free in ({"app": 6 * GIB - 1, "db": 5 * GIB},
                     {"app": 6 * GIB, "db": 5 * GIB - 1}):
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
        self.assertEqual(environment["CTF_SOLVER_MIN_FREE_BYTES"], str(5 * GIB))
        environment["CTF_STORAGE_MIN_FREE_BYTES"] = str(6 * GIB)
        environment["CTF_SOLVER_MIN_FREE_BYTES"] = str(7 * GIB)
        local_compose.set_local_storage_floor(environment)
        self.assertEqual(environment["CTF_STORAGE_MIN_FREE_BYTES"], str(6 * GIB))
        self.assertEqual(environment["CTF_SOLVER_MIN_FREE_BYTES"], str(7 * GIB))
        self.assertEqual(local_compose.set_local_storage_floor({}), None)

    def test_legacy_unreserved_copy_obeys_local_data_floor(self) -> None:
        with mock.patch.dict(os.environ, {"CTF_STORAGE_MIN_FREE_BYTES": str(5 * GIB)}):
            self.assertEqual(_minimum_free_after_unreserved_stage(), 5 * GIB)

    def test_direct_local_compose_has_the_same_default_floor(self) -> None:
        compose = (ROOT / "compose.local.yaml").read_text(encoding="utf-8")
        self.assertIn("CTF_STORAGE_MIN_FREE_BYTES:-5368709120", compose)
        self.assertIn("CTF_SOLVER_MIN_FREE_BYTES:-5368709120", compose)

    def test_large_concurrent_uploads_share_the_five_gib_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "storage.sqlite3"

            def connect():
                db = sqlite3.connect(path, timeout=15, check_same_thread=False)
                db.row_factory = sqlite3.Row
                return db

            budget = StorageBudget(Path(directory), connect, minimum_free_bytes=5 * GIB)
            budget._free = lambda: 8 * GIB
            start = threading.Barrier(2)
            outcomes: list[str] = []

            def claim(index: int) -> None:
                start.wait()
                try:
                    budget.reserve(f"upload-{index}", "attachment", "user",
                                   "workspace", "challenge", 2 * GIB)
                    outcomes.append("accepted")
                except StorageBudgetError as exc:
                    outcomes.append(exc.code)

            threads = [threading.Thread(target=claim, args=(index,))
                       for index in (1, 2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            self.assertCountEqual(outcomes, ["accepted", "insufficient_space"])
            self.assertEqual(sum(row["remaining_bytes"] for row in budget.snapshot()),
                             2 * GIB)

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
                self.assertEqual(bundle.read(
                    "CTF_Agent-v0.0.1/DockerDisk.ps1"
                ), (ROOT / "installer/DockerDisk.ps1").read_bytes())
                self.assertEqual(bundle.read(
                    "CTF_Agent-v0.0.1/Start.ps1"
                ), (ROOT / "installer/Start.ps1").read_bytes())


if __name__ == "__main__":
    unittest.main()
