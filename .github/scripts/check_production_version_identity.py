"""The image, CI rollout, and host updater must agree on the running version."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("production_update", ROOT / "deploy" / "production-update.py")
assert SPEC is not None and SPEC.loader is not None
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
REVISION = "a" * 40
IMAGE = "ghcr.io/example/ctf-agent-public"
REF = IMAGE + "@sha256:" + "b" * 64
REPOSITORY = "example/CTF_Agent"
VERSION = "v1.2.3"


def container(*, revision: str = REVISION, image: str = REF, version: str | None = VERSION, health: str = "healthy") -> bytes:
    labels = {
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": "https://github.com/" + REPOSITORY,
    }
    if version is not None:
        labels["org.opencontainers.image.version"] = version
    return json.dumps([{
        "Config": {"Image": image, "Labels": labels},
        "State": {"Health": {"Status": health}},
    }]).encode()


def run_result(payload: bytes) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, payload, b"")


class VersionIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / "update-control"
        self.control.mkdir()
        self.releases = self.root / "releases"
        (self.releases / REVISION).mkdir(parents=True)
        (self.releases / REVISION / "image-ref").write_text(REF + "\n", encoding="ascii")

    def marker(self) -> dict:
        return json.loads((self.control / "current-version.json").read_text(encoding="utf-8"))

    def test_stale_marker_reconciles_from_exact_healthy_image(self) -> None:
        (self.control / "current-version.json").write_text(json.dumps({
            "tag": "v1.2.2", "revision": "c" * 40, "repository": REPOSITORY,
        }), encoding="utf-8")
        with mock.patch.object(HELPER.subprocess, "run", return_value=run_result(container())) as inspect:
            self.assertEqual(
                HELPER._current_version(self.control, self.releases, REVISION, REPOSITORY, IMAGE),
                VERSION,
            )
        self.assertEqual(inspect.call_args.args[0], ["docker", "inspect", "ctf_agent"])
        self.assertEqual(self.marker(), {"tag": VERSION, "revision": REVISION, "repository": REPOSITORY})

    def test_matching_marker_needs_no_docker(self) -> None:
        expected = {"tag": VERSION, "revision": REVISION, "repository": REPOSITORY}
        (self.control / "current-version.json").write_text(json.dumps(expected), encoding="utf-8")
        with mock.patch.object(HELPER.subprocess, "run") as inspect:
            self.assertEqual(
                HELPER._current_version(self.control, self.releases, REVISION, REPOSITORY, IMAGE),
                VERSION,
            )
        inspect.assert_not_called()
        self.assertEqual(self.marker(), expected)

    def test_mismatch_never_rewrites_marker(self) -> None:
        marker = self.control / "current-version.json"
        marker.write_text('stale', encoding="utf-8")
        for payload in (
            container(revision="c" * 40), container(image=IMAGE + "@sha256:" + "d" * 64),
            container(version="unknown"), container(health="starting"),
        ):
            with self.subTest(payload=payload), mock.patch.object(
                HELPER.subprocess, "run", return_value=run_result(payload),
            ):
                with self.assertRaises(ValueError):
                    HELPER._current_version(self.control, self.releases, REVISION, REPOSITORY, IMAGE)
                self.assertEqual(marker.read_text(encoding="utf-8"), "stale")

    def test_ci_rollout_writes_marker_only_after_validated_image(self) -> None:
        shell = (ROOT / ".github" / "scripts" / "remote-rollout.sh").read_text(encoding="utf-8")
        opening = 'python3 - "$release_root" "$revision" "$image_ref" "$source_repo" <<\'PY\'\n'
        code = shell.split(opening, 1)[1].split("\nPY", 1)[0]
        (self.releases / "current").write_text(REVISION + "\n", encoding="ascii")
        for payload, accepted in ((container(), True), (container(health="starting"), False)):
            (self.control / "current-version.json").unlink(missing_ok=True)
            arguments = ["rollout", str(self.releases), REVISION, REF, REPOSITORY]
            with self.subTest(accepted=accepted), mock.patch.object(sys, "argv", arguments), mock.patch(
                "subprocess.run", return_value=run_result(payload),
            ):
                if accepted:
                    exec(compile(code, "remote-rollout-marker", "exec"), {})
                    self.assertEqual(self.marker(), {
                        "tag": VERSION, "revision": REVISION, "repository": REPOSITORY,
                    })
                else:
                    with self.assertRaises(SystemExit):
                        exec(compile(code, "remote-rollout-marker", "exec"), {})
                    self.assertFalse((self.control / "current-version.json").exists())

    def test_legacy_image_rollout_preserves_missing_marker_without_failing(self) -> None:
        shell = (ROOT / ".github" / "scripts" / "remote-rollout.sh").read_text(encoding="utf-8")
        opening = 'python3 - "$release_root" "$revision" "$image_ref" "$source_repo" <<\'PY\'\n'
        code = shell.split(opening, 1)[1].split("\nPY", 1)[0]
        (self.releases / "current").write_text(REVISION + "\n", encoding="ascii")
        arguments = ["rollout", str(self.releases), REVISION, REF, REPOSITORY]
        with mock.patch.object(sys, "argv", arguments), mock.patch(
            "subprocess.run", return_value=run_result(container(version=None)),
        ):
            with self.assertRaises(SystemExit) as result:
                exec(compile(code, "remote-rollout-marker", "exec"), {})
        self.assertEqual(result.exception.code, 0)
        self.assertFalse((self.control / "current-version.json").exists())


if __name__ == "__main__":
    unittest.main()
