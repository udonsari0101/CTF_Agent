"""Prepare a reviewed, pinned Codex/Claude toolchain update from npm dist-tags.

The image workflow still builds and publishes from the resulting Git commit.
This script never installs a package or moves a production image tag.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\Z")
SOURCES = {
    "codex": (
        "https://registry.npmjs.org/-/package/%40openai%2Fcodex/dist-tags",
        "latest",
    ),
    "claude": (
        "https://registry.npmjs.org/-/package/%40anthropic-ai%2Fclaude-code/dist-tags",
        "stable",
    ),
}
PINS = {
    "codex": (
        ("Dockerfile.toolchain", r"(?m)^(ARG CODEX_VERSION=)([0-9.]+)$"),
        ("ctf_agent/solver_worker.py", r'(CTF_IMAGE_CODEX_VERSION", ")([0-9.]+)("\))'),
    ),
    "claude": (
        ("Dockerfile.toolchain", r"(?m)^(ARG CLAUDE_VERSION=)([0-9.]+)$"),
        ("ctf_agent/solver_worker.py", r'(CTF_IMAGE_CLAUDE_VERSION", ")([0-9.]+)("\))'),
        ("ctf_agent/providers/claude_runtime.py", r'(CTF_IMAGE_CLAUDE_VERSION", ")([0-9.]+)("\))'),
    ),
}


def _checked_version(value: object) -> str:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError(f"Registry supplied an invalid stable version: {value!r}")
    return value


def registry_version(provider: str) -> str:
    url, tag = SOURCES[provider]
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "ctf-agent-cli-pin-monitor"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        document = json.load(response)
    if not isinstance(document, dict):
        raise ValueError("Registry dist-tags response is not an object")
    return _checked_version(document.get(tag))


def read_pins(root: Path = ROOT) -> dict[str, str]:
    pins = {}
    for provider, locations in PINS.items():
        versions = []
        for filename, pattern in locations:
            source = (root / filename).read_text(encoding="utf-8")
            matches = list(re.finditer(pattern, source))
            if len(matches) != 1:
                raise ValueError(f"Expected exactly one {provider} version in {filename}")
            versions.append(_checked_version(matches[0].group(2)))
        if len(set(versions)) != 1:
            raise ValueError(f"{provider} versions disagree across image and runtime")
        pins[provider] = versions[0]
    return pins


def update_pins(versions: dict[str, str], root: Path = ROOT) -> bool:
    current = read_pins(root)
    for provider, version in versions.items():
        if tuple(map(int, version.split("."))) < tuple(map(int, current[provider].split("."))):
            raise ValueError(f"Refusing to downgrade {provider} from {current[provider]} to {version}")
    changed = False
    staged: dict[Path, str] = {}
    for provider, locations in PINS.items():
        target = _checked_version(versions[provider])
        if target == current[provider]:
            continue
        changed = True
        for filename, pattern in locations:
            path = root / filename
            source = staged.get(path, path.read_text(encoding="utf-8"))
            source, count = re.subn(pattern, lambda match: match.group(1) + target + (match.group(3) if match.lastindex == 3 else ""), source)
            if count != 1:
                raise ValueError(f"Cannot update {provider} in {filename}")
            staged[path] = source
    if changed:
        for path, source in staged.items():
            path.write_text(source, encoding="utf-8")
        if read_pins(root) != versions:
            raise ValueError("Image and runtime pins did not remain aligned")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Update pins after a candidate image smoke test")
    args = parser.parse_args()
    current = read_pins()
    latest = {provider: registry_version(provider) for provider in SOURCES}
    if args.apply:
        update_pins(latest)
    print(json.dumps({"current": current, "stable": latest, "changed": current != latest}, sort_keys=True))


if __name__ == "__main__":
    main()
