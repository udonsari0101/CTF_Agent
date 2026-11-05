"""Offline checks for the release identity guard; no registry access."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.check_release_identity import (  # noqa: E402
    ReleaseIdentityError,
    verify_image,
    verify_tag_and_bundle,
)


REVISION = "a" * 40
SOURCE = "https://github.com/example/CTF_Agent"
CONFIG_DIGEST = "sha256:" + "c" * 64
ROOT_DIGEST = "sha256:" + "d" * 64


class ReleaseIdentityTests(unittest.TestCase):
    def test_matching_tag_and_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "release.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("CTF_Agent-v1.2.3/COMMIT", REVISION + "\n")
                bundle.writestr("CTF_Agent-v1.2.3/VERSION", "v1.2.3\n")
            result = subprocess.CompletedProcess([], 0, REVISION + "\n", "")
            with patch("scripts.check_release_identity.subprocess.run", return_value=result):
                verify_tag_and_bundle("v1.2.3", REVISION, archive)

    def test_mismatched_zip_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "release.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("CTF_Agent-v1.2.3/COMMIT", "b" * 40)
                bundle.writestr("CTF_Agent-v1.2.3/VERSION", "v1.2.3")
            result = subprocess.CompletedProcess([], 0, REVISION + "\n", "")
            with patch("scripts.check_release_identity.subprocess.run", return_value=result):
                with self.assertRaisesRegex(ReleaseIdentityError, "ZIP COMMIT"):
                    verify_tag_and_bundle("v1.2.3", REVISION, archive)

    def test_mismatched_tag_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "release.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("CTF_Agent-v1.2.3/COMMIT", REVISION)
                bundle.writestr("CTF_Agent-v1.2.3/VERSION", "v1.2.3")
            result = subprocess.CompletedProcess([], 0, "b" * 40 + "\n", "")
            with patch("scripts.check_release_identity.subprocess.run", return_value=result):
                with self.assertRaisesRegex(ReleaseIdentityError, "tag"):
                    verify_tag_and_bundle("v1.2.3", REVISION, archive)

    def test_matching_single_manifest_and_labels(self) -> None:
        payloads = {
            "manifests/" + REVISION: ({"config": {"digest": CONFIG_DIGEST}}, ROOT_DIGEST),
            "blobs/" + CONFIG_DIGEST: ({"config": {"Labels": {
                "org.opencontainers.image.revision": REVISION,
                "org.opencontainers.image.source": SOURCE,
            }}}, CONFIG_DIGEST),
        }
        self.assertEqual(verify_image(REVISION, SOURCE, payloads.__getitem__), ROOT_DIGEST)

    def test_wrong_oci_revision_is_rejected(self) -> None:
        payloads = {
            "manifests/" + REVISION: ({"config": {"digest": CONFIG_DIGEST}}, ROOT_DIGEST),
            "blobs/" + CONFIG_DIGEST: ({"config": {"Labels": {
                "org.opencontainers.image.revision": "b" * 40,
                "org.opencontainers.image.source": SOURCE,
            }}}, CONFIG_DIGEST),
        }
        with self.assertRaisesRegex(ReleaseIdentityError, "OCI identity"):
            verify_image(REVISION, SOURCE, payloads.__getitem__)

    def test_wrong_image_config_digest_is_rejected(self) -> None:
        payloads = {
            "manifests/" + REVISION: ({"config": {"digest": CONFIG_DIGEST}}, ROOT_DIGEST),
            "blobs/" + CONFIG_DIGEST: ({"config": {"Labels": {}}}, "sha256:" + "e" * 64),
        }
        with self.assertRaisesRegex(ReleaseIdentityError, "config digest"):
            verify_image(REVISION, SOURCE, payloads.__getitem__)

    def test_multiarch_manifest_uses_linux_amd64_child(self) -> None:
        child_digest = "sha256:" + "e" * 64
        payloads = {
            "manifests/" + REVISION: ({"manifests": [{
                "digest": child_digest,
                "platform": {"os": "linux", "architecture": "amd64"},
            }]}, ROOT_DIGEST),
            "manifests/" + child_digest: ({"config": {"digest": CONFIG_DIGEST}}, child_digest),
            "blobs/" + CONFIG_DIGEST: ({"config": {"Labels": {
                "org.opencontainers.image.revision": REVISION,
                "org.opencontainers.image.source": SOURCE,
            }}}, CONFIG_DIGEST),
        }
        self.assertEqual(verify_image(REVISION, SOURCE, payloads.__getitem__), ROOT_DIGEST)


if __name__ == "__main__":
    unittest.main()
