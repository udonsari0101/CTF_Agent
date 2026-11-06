"""Offline release wait checks; no registry, Actions API, or credentials required."""

from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.wait_release_image import (  # noqa: E402
    ReleaseImageWaitError,
    image_digest,
    wait_for_image,
)


REVISION = "a" * 40
IMAGE = "ghcr.io/example/ctf-agent-public"
REPOSITORY = "example/CTF_Agent"
TOKEN = "test-token"
DIGEST = "sha256:" + "b" * 64


def run(status: str, conclusion: str | None, number: int) -> dict:
    return {"id": number, "created_at": f"2026-11-06T00:{number:02d}:00Z",
            "status": status, "conclusion": conclusion, "head_sha": REVISION}


class ReleaseImageWaitTests(unittest.TestCase):
    def test_already_verified_image_needs_no_actions_lookup(self) -> None:
        def unexpected(*_args):
            raise AssertionError("Actions API should not be called")

        self.assertEqual(wait_for_image(
            REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=60,
            check_image=lambda *_: DIGEST, get_runs=unexpected,
        ), DIGEST)

    def test_pending_image_waits_for_exact_sha(self) -> None:
        clock = [0.0]
        attempts = [None, None, DIGEST]
        lookups = []

        def get_runs(_repo, workflow, sha, _token):
            lookups.append((workflow, sha))
            return [run("in_progress", None, 1)]

        def sleep(seconds):
            clock[0] += seconds

        self.assertEqual(wait_for_image(
            REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=120,
            poll_seconds=30, check_image=lambda *_: attempts.pop(0),
            get_runs=get_runs, monotonic=lambda: clock[0], sleep=sleep,
        ), DIGEST)
        self.assertEqual(clock[0], 60)
        self.assertEqual(lookups, [("image.yml", REVISION)] * 2)

    def test_image_failure_ends_wait_without_retry(self) -> None:
        with self.assertRaisesRegex(ReleaseImageWaitError, "Image workflow 4 ended as failure"):
            wait_for_image(
                REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=60,
                check_image=lambda *_: None,
                get_runs=lambda *_: [run("completed", "failure", 4)],
                sleep=lambda _: self.fail("Should fail before sleeping"),
            )

    def test_older_failure_does_not_override_new_running_attempt(self) -> None:
        clock = [0.0]
        results = [None, DIGEST]
        self.assertEqual(wait_for_image(
            REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=60,
            check_image=lambda *_: results.pop(0),
            get_runs=lambda *_: [run("completed", "failure", 1), run("in_progress", None, 2)],
            monotonic=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        ), DIGEST)

    def test_ci_failure_before_image_workflow_ends_wait(self) -> None:
        def get_runs(_repo, workflow, _sha, _token):
            return [] if workflow == "image.yml" else [run("completed", "failure", 5)]

        with self.assertRaisesRegex(ReleaseImageWaitError, "CI workflow 5 ended as failure"):
            wait_for_image(REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=60,
                           check_image=lambda *_: None, get_runs=get_runs,
                           sleep=lambda _: self.fail("Should fail before sleeping"))

    def test_pending_image_stops_at_deadline(self) -> None:
        clock = [0.0]
        with self.assertRaisesRegex(ReleaseImageWaitError, "Timed out"):
            wait_for_image(
                REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=45, poll_seconds=30,
                check_image=lambda *_: None, get_runs=lambda *_: [],
                monotonic=lambda: clock[0],
                sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            )
        self.assertEqual(clock[0], 45)

    def test_only_missing_sha_manifest_is_retryable(self) -> None:
        root = f"https://ghcr.io/v2/example/ctf-agent-public/manifests/{REVISION}"
        child = "https://ghcr.io/v2/example/ctf-agent-public/blobs/sha256:" + "c" * 64
        with patch("scripts.wait_release_image.ghcr_fetcher", return_value=lambda _: ({}, DIGEST)):
            with patch("scripts.wait_release_image.verify_image",
                       side_effect=urllib.error.HTTPError(root, 404, "missing", {}, None)):
                self.assertIsNone(image_digest(REVISION, IMAGE))
            with patch("scripts.wait_release_image.verify_image",
                       side_effect=urllib.error.HTTPError(child, 404, "missing", {}, None)):
                with self.assertRaises(urllib.error.HTTPError):
                    image_digest(REVISION, IMAGE)
            with patch("scripts.wait_release_image.verify_image",
                       side_effect=urllib.error.HTTPError(root, 401, "denied", {}, None)):
                with self.assertRaises(urllib.error.HTTPError):
                    image_digest(REVISION, IMAGE)
            with patch("scripts.wait_release_image.verify_image",
                       side_effect=urllib.error.HTTPError(
                           f"https://example.invalid/manifests/{REVISION}", 404, "missing", {}, None)):
                with self.assertRaises(urllib.error.HTTPError):
                    image_digest(REVISION, IMAGE)

    def test_bad_identity_is_not_retried(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            wait_for_image(REVISION, IMAGE, REPOSITORY, TOKEN, timeout_seconds=60,
                           check_image=lambda *_: (_ for _ in ()).throw(RuntimeError("identity mismatch")),
                           get_runs=lambda *_: self.fail("Should fail before Actions lookup"))


if __name__ == "__main__":
    unittest.main()
