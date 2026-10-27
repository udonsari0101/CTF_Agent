"""Request missing remote connection information from the web user.

The helper mirrors the original agent's ``request-remote`` handoff.  It writes
one private, bounded control file and never echoes the request text to stdout.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Sequence


MAX_REQUEST_BYTES = 800
REQUEST_NAME = ".remote-request"


class InvalidRemoteRequest(ValueError):
    pass


def validate_request(note: str) -> str:
    if not isinstance(note, str):
        raise InvalidRemoteRequest("invalid request")
    note = note.strip()
    try:
        raw = note.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidRemoteRequest("invalid request") from exc
    if not raw or len(raw) > MAX_REQUEST_BYTES or any(not char.isprintable() for char in note):
        raise InvalidRemoteRequest("invalid request")
    return note


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short request write")
        remaining = remaining[written:]


def record_request(note: str, directory: Path | None = None) -> Path:
    note = validate_request(note)
    workdir = Path.cwd() if directory is None else Path(directory)
    destination = workdir / REQUEST_NAME
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f"{REQUEST_NAME}.", suffix=".tmp", dir=workdir
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, note.encode("utf-8"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if not stat.S_ISREG(temporary.lstat().st_mode):
            raise OSError("request stage is not regular")
        os.replace(temporary, destination)
        temporary = None
        if not stat.S_ISREG(destination.lstat().st_mode):
            raise OSError("request destination is not regular")
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
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["-h"], ["--help"]):
        sys.stdout.write('usage: request-remote "<needed connection detail>"\n')
        return 0
    if len(arguments) != 1:
        sys.stderr.write('usage: request-remote "<needed connection detail>"\n')
        return 64
    try:
        record_request(arguments[0])
    except InvalidRemoteRequest:
        sys.stderr.write("request-remote: invalid request\n")
        return 65
    except Exception:
        sys.stderr.write("request-remote: unable to record request\n")
        return 73
    sys.stdout.write("request-remote: request recorded; stop this attempt now\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "InvalidRemoteRequest",
    "MAX_REQUEST_BYTES",
    "REQUEST_NAME",
    "main",
    "record_request",
    "validate_request",
]
