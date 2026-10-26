"""Locate the platform-native Codex CLI in supported npm install layouts."""

from __future__ import annotations

import platform
import stat
from pathlib import Path


def native_codex_binary(package_root: Path) -> Path | None:
    architecture = {
        "x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64",
    }.get(platform.machine().lower())
    if architecture is None:
        return None
    package_name = f"codex-linux-{architecture}"
    # npm may nest optional dependencies or hoist them beside @openai/codex.
    candidates = sorted(
        set(package_root.glob(f"node_modules/@openai/{package_name}/vendor/*/bin/codex"))
        | set(package_root.parent.glob(f"{package_name}/vendor/*/bin/codex"))
    )
    if len(candidates) != 1:
        return None
    candidate = candidates[0]
    try:
        details = candidate.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        return None
    if not details.st_mode & stat.S_IXUSR:
        return None
    return candidate
