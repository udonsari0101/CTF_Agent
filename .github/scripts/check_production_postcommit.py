"""A post-commit diagnostic failure must not misreport a healthy deployment."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("production_update", ROOT / "deploy" / "production-update.py")
assert SPEC is not None and SPEC.loader is not None
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
OLD = "a" * 40
NEW = "b" * 40
IMAGE = "ghcr.io/example/ctf-agent-public"
REF = IMAGE + "@sha256:" + "c" * 64
REPOSITORY = "example/CTF_Agent"


class PostCommitTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.release_root = self.root / "releases"
        self.release_root.mkdir()
        self.control = self.root / "update-control"
        self.control.mkdir()
        (self.release_root / "current").write_text(OLD + "\n", encoding="ascii")
        target = self.release_root / NEW
        target.mkdir()
        (target / "image-ref").write_text(REF + "\n", encoding="ascii")
        self.request = {"id": "f" * 32, "tag": "v1.2.3", "created_at": 1}

    def test_rollout_exit_failure_after_healthy_commit_is_success(self) -> None:
        def commit_then_fail(*_args: object, **_kwargs: object) -> bool:
            (self.release_root / "current").write_text(NEW + "\n", encoding="ascii")
            return False

        with (
            mock.patch.object(HELPER, "_current_version", return_value="v1.2.2"),
            mock.patch.object(HELPER, "_latest_release", return_value="v1.2.3"),
            mock.patch.object(HELPER, "_tag_revision", return_value=NEW),
            mock.patch.object(HELPER, "_image_ref", return_value=REF),
            mock.patch.object(HELPER, "_run_rollout", side_effect=commit_then_fail),
            mock.patch.object(HELPER, "_running_version", return_value="v1.2.3"),
            mock.patch.object(HELPER, "_ready_web", return_value=True),
            mock.patch.object(HELPER, "_restore_previous") as restore,
            mock.patch.object(HELPER, "_refresh_host_helper", return_value=False),
        ):
            self.assertFalse(HELPER._apply(
                self.control, self.release_root, self.root / "rollout.sh",
                REPOSITORY, IMAGE, self.request,
            ))
        restore.assert_not_called()
        self.assertEqual(json.loads((self.control / "status.json").read_text())["phase"], "completed")
        self.assertEqual(json.loads((self.control / "current-version.json").read_text())["revision"], NEW)

    def test_wrong_image_or_tag_never_counts_as_success(self) -> None:
        (self.release_root / "current").write_text(NEW + "\n", encoding="ascii")
        for saved_ref, version in ((REF, "v1.2.4"), (IMAGE + "@sha256:" + "d" * 64, "v1.2.3")):
            (self.release_root / NEW / "image-ref").write_text(saved_ref + "\n", encoding="ascii")
            with (
                self.subTest(saved_ref=saved_ref, version=version),
                mock.patch.object(HELPER, "_running_version", return_value=version),
                mock.patch.object(HELPER, "_ready_web", return_value=True),
                mock.patch.object(HELPER.time, "sleep"),
            ):
                self.assertFalse(HELPER._verified_target_release(
                    self.release_root, NEW, REF, REPOSITORY, IMAGE, "v1.2.3",
                ))

    def test_transient_inspect_failure_retries_committed_release(self) -> None:
        (self.release_root / "current").write_text(NEW + "\n", encoding="ascii")
        with (
            mock.patch.object(HELPER, "_running_version", side_effect=[OSError("Docker busy"), "v1.2.3"]) as inspect,
            mock.patch.object(HELPER, "_ready_web", return_value=True),
            mock.patch.object(HELPER.time, "sleep") as sleep,
        ):
            self.assertTrue(HELPER._verified_target_release(
                self.release_root, NEW, REF, REPOSITORY, IMAGE, "v1.2.3",
            ))
        self.assertEqual(inspect.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_uncommitted_rollout_cannot_be_marked_complete(self) -> None:
        with (
            mock.patch.object(HELPER, "_current_version", return_value="v1.2.2"),
            mock.patch.object(HELPER, "_latest_release", return_value="v1.2.3"),
            mock.patch.object(HELPER, "_tag_revision", return_value=NEW),
            mock.patch.object(HELPER, "_image_ref", return_value=REF),
            mock.patch.object(HELPER, "_run_rollout", return_value=False),
            mock.patch.object(HELPER, "_restore_previous", return_value=True) as restore,
        ):
            with self.assertRaisesRegex(RuntimeError, "previous release was restored"):
                HELPER._apply(
                    self.control, self.release_root, self.root / "rollout.sh",
                    REPOSITORY, IMAGE, self.request,
                )
        restore.assert_called_once()
        self.assertFalse((self.control / "current-version.json").exists())


if __name__ == "__main__":
    unittest.main()
