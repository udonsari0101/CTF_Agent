"""Application and database filesystem checks for the Windows/WSL installer.

The Windows launcher checks the separate Docker Desktop image disk and adds
planned writes when it shares a physical Windows drive with these filesystems.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


GIB = 1024**3
MINIMUM_REMAINING_BYTES = 5 * GIB
APPLICATION_STAGING_BYTES = GIB


def required_free_bytes(stage: str, image_cached: bool) -> int:
    if stage == "before-pull":
        # Docker Desktop stores image layers on its own disk. The application
        # filesystem needs room for the release/launcher staging, not a
        # duplicate copy of the entire image pull estimate.
        return MINIMUM_REMAINING_BYTES + APPLICATION_STAGING_BYTES
    if stage == "after-pull":
        return MINIMUM_REMAINING_BYTES
    raise ValueError("Invalid local storage preflight stage")


def check_space(home: Path, database: Path, *, stage: str,
                image_cached: bool) -> tuple[int, int]:
    """Fail before service drain if either data or database is too full."""

    needed = required_free_bytes(stage, image_cached)
    home_free = shutil.disk_usage(home).free
    database_free = shutil.disk_usage(database).free
    if home_free < needed:
        raise RuntimeError(
            f"Local application disk needs {needed / GIB:g} GiB available "
            f"at {stage} to leave 5 GiB free after the estimated writes"
        )
    if database_free < MINIMUM_REMAINING_BYTES:
        raise RuntimeError("Local database disk needs 5 GiB free")
    return home_free, database_free


def main(arguments: list[str]) -> int:
    if len(arguments) != 4 or arguments[3] not in {"cached", "cold"}:
        raise SystemExit(
            "usage: storage_preflight.py before-pull|after-pull HOME DATABASE cached|cold"
        )
    stage, home, database, cache_state = arguments
    try:
        check_space(Path(home), Path(database), stage=stage,
                    image_cached=cache_state == "cached")
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
