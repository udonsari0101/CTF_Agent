"""Wait for the exact release image without masking failed CI or image builds."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from scripts.check_release_identity import ghcr_fetcher, verify_image


class ReleaseImageWaitError(RuntimeError):
    pass


def image_digest(revision: str, image: str) -> str | None:
    owner = image.split("/")[1]
    source = f"https://github.com/{owner}/CTF_Agent"
    try:
        return verify_image(revision, source, ghcr_fetcher(image))
    except urllib.error.HTTPError as error:
        # Only the absent SHA manifest is expected while image.yml is building.
        # A missing child/config blob, authorization error, or bad OCI identity
        # must fail the release rather than being treated as publication lag.
        parsed = urllib.parse.urlparse(error.url)
        if (error.code == 404 and parsed.scheme == "https" and parsed.netloc == "ghcr.io"
                and parsed.path.endswith("/manifests/" + revision)):
            return None
        raise


def workflow_runs(repository: str, workflow: str, revision: str, token: str) -> list[dict]:
    query = urllib.parse.urlencode({"head_sha": revision, "per_page": 100})
    url = f"https://api.github.com/repos/{repository}/actions/workflows/{workflow}/runs?{query}"
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    return [run for run in payload["workflow_runs"] if run.get("head_sha") == revision]


def latest_run(runs: list[dict]) -> dict | None:
    return max(runs, key=lambda run: (run.get("created_at", ""), run.get("id", 0)), default=None)


def failed_run(run: dict | None) -> bool:
    return bool(run and run.get("status") == "completed"
                and run.get("conclusion") not in {"success", None})


def wait_for_image(
    revision: str,
    image: str,
    repository: str,
    token: str,
    *,
    timeout_seconds: int,
    poll_seconds: int = 30,
    check_image: Callable[[str, str], str | None] = image_digest,
    get_runs: Callable[[str, str, str, str], list[dict]] = workflow_runs,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ReleaseImageWaitError("Invalid release revision")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ReleaseImageWaitError("Invalid repository")
    if image != f"ghcr.io/{repository.split('/')[0].lower()}/ctf-agent-public":
        raise ReleaseImageWaitError("Image does not belong to the release repository")
    if not token:
        raise ReleaseImageWaitError("GitHub Actions token is unavailable")
    if timeout_seconds <= 0 or poll_seconds <= 0:
        raise ReleaseImageWaitError("Wait and polling limits must be positive")

    deadline = monotonic() + timeout_seconds
    while True:
        digest = check_image(revision, image)
        if digest is not None:
            return digest
        image_run = latest_run(get_runs(repository, "image.yml", revision, token))
        if failed_run(image_run):
            raise ReleaseImageWaitError(
                f"Image workflow {image_run['id']} ended as {image_run['conclusion']} for this commit"
            )
        if image_run is None:
            ci_run = latest_run(get_runs(repository, "ci.yml", revision, token))
            if failed_run(ci_run):
                raise ReleaseImageWaitError(
                    f"CI workflow {ci_run['id']} ended as {ci_run['conclusion']} for this commit"
                )
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ReleaseImageWaitError("Timed out waiting for the verified SHA image")
        sleep(min(poll_seconds, remaining))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10200)
    args = parser.parse_args()
    digest = wait_for_image(
        args.revision, args.image, args.repository, os.environ.get("GITHUB_TOKEN", ""),
        timeout_seconds=args.timeout_seconds,
    )
    print("Verified release image " + digest)


if __name__ == "__main__":
    try:
        main()
    except ReleaseImageWaitError as error:
        raise SystemExit(str(error)) from None
