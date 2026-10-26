"""Record a solver's verified flag candidate without printing the flag.

This is the isolated-worker equivalent of the original ctf_agent
``submit-flag`` helper.  The coordinator reads the resulting file only after
the model turn has ended and validates it against the structured response.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Sequence


MAX_CANDIDATE_LENGTH = 4_000
_CANDIDATE_NAME = ".flag-candidate"


class InvalidCandidate(ValueError):
    """Raised when a candidate cannot be represented safely in one file."""


def validate_candidate(candidate: str) -> None:
    """Reject empty, oversized, or non-printable candidate values."""

    if not candidate or len(candidate) > MAX_CANDIDATE_LENGTH:
        raise InvalidCandidate("invalid candidate")
    if any(not character.isprintable() for character in candidate):
        raise InvalidCandidate("invalid candidate")
    try:
        candidate.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidCandidate("invalid candidate") from exc


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short candidate write")
        remaining = remaining[written:]


def record_candidate(candidate: str, directory: Path | None = None) -> Path:
    """Atomically replace ``.flag-candidate`` with a private regular file."""

    validate_candidate(candidate)
    workdir = Path.cwd() if directory is None else Path(directory)
    destination = workdir / _CANDIDATE_NAME
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f"{_CANDIDATE_NAME}.", suffix=".tmp", dir=workdir
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, candidate.encode("utf-8", errors="strict"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if not stat.S_ISREG(temporary.lstat().st_mode):
            raise OSError("candidate stage is not regular")
        os.replace(temporary, destination)
        temporary = None
        if not stat.S_ISREG(destination.lstat().st_mode):
            raise OSError("candidate destination is not regular")
        return destination
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point with fixed, candidate-free diagnostics."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        sys.stderr.write('usage: submit-flag "<FLAG>"\n')
        return 64
    try:
        record_candidate(arguments[0])
    except InvalidCandidate:
        sys.stderr.write("submit-flag: invalid candidate\n")
        return 65
    except Exception:
        sys.stderr.write("submit-flag: unable to record candidate\n")
        return 73
    sys.stdout.write("submit-flag: candidate recorded for verification\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["MAX_CANDIDATE_LENGTH", "InvalidCandidate", "main", "record_candidate", "validate_candidate"]
