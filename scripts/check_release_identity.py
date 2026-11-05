"""Fail a release if its tag, ZIP revision, and published GHCR image diverge."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable


class ReleaseIdentityError(RuntimeError):
    pass


def verify_tag_and_bundle(tag: str, revision: str, archive: Path) -> None:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag):
        raise ReleaseIdentityError("Invalid release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ReleaseIdentityError("Invalid release revision")
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
        capture_output=True, text=True, check=True,
    )
    if result.stdout.strip() != revision:
        raise ReleaseIdentityError("Release tag does not point to the requested revision")
    prefix = f"CTF_Agent-{tag}/"
    with zipfile.ZipFile(archive) as bundle:
        if bundle.read(prefix + "COMMIT").decode("ascii").strip() != revision:
            raise ReleaseIdentityError("ZIP COMMIT does not match the release tag")
        if bundle.read(prefix + "VERSION").decode("ascii").strip() != tag:
            raise ReleaseIdentityError("ZIP VERSION does not match the release tag")


def verify_image(
    revision: str,
    expected_source: str,
    fetch_json: Callable[[str], tuple[dict, str]],
) -> str:
    manifest, digest = fetch_json("manifests/" + revision)
    if "manifests" in manifest:
        candidates = [entry for entry in manifest["manifests"]
                      if entry.get("platform", {}).get("os") == "linux"
                      and entry.get("platform", {}).get("architecture") == "amd64"]
        if len(candidates) != 1:
            raise ReleaseIdentityError("Expected one linux/amd64 image manifest")
        child, child_digest = fetch_json("manifests/" + candidates[0]["digest"])
        if child_digest != candidates[0]["digest"]:
            raise ReleaseIdentityError("Image index child digest does not match")
        manifest = child
    config_digest = manifest.get("config", {}).get("digest")
    if not isinstance(config_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest):
        raise ReleaseIdentityError("Image config digest is missing")
    config, resolved_config_digest = fetch_json("blobs/" + config_digest)
    if resolved_config_digest != config_digest:
        raise ReleaseIdentityError("Image config digest does not match")
    labels = config.get("config", {}).get("Labels", {})
    if (labels.get("org.opencontainers.image.revision") != revision
            or labels.get("org.opencontainers.image.source") != expected_source):
        raise ReleaseIdentityError("Published image OCI identity does not match the release")
    return digest


def ghcr_fetcher(image: str) -> Callable[[str], tuple[dict, str]]:
    match = re.fullmatch(r"ghcr\.io/([A-Za-z0-9-]+)/ctf-agent-public", image)
    if not match:
        raise ReleaseIdentityError("Expected the public CTF Agent GHCR repository")
    repository = match.group(1) + "/ctf-agent-public"
    token_url = "https://ghcr.io/token?" + urllib.parse.urlencode(
        {"scope": "repository:" + repository + ":pull"}
    )
    with urllib.request.urlopen(token_url, timeout=30) as response:
        token = json.load(response)["token"]

    def fetch(path: str) -> tuple[dict, str]:
        request = urllib.request.Request(
            "https://ghcr.io/v2/" + repository + "/" + path,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": ", ".join((
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )),
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            claimed_digest = response.headers.get("Docker-Content-Digest")
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        if claimed_digest and claimed_digest != digest:
            raise ReleaseIdentityError("Registry response digest does not match its body")
        return json.loads(body), digest

    return fetch


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    verify_tag_and_bundle(args.tag, args.revision, args.archive)
    owner = args.image.split("/")[1]
    source = f"https://github.com/{owner}/CTF_Agent"
    digest = verify_image(args.revision, source, ghcr_fetcher(args.image))
    print(digest)


if __name__ == "__main__":
    main()
