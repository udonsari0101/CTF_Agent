"""Installation-scoped browser access for a passwordless local server.

The secret lives in the web-only config bind. Solver containers receive only
their per-slot exchange and scratch binds, so a model cannot read this file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
import time
from pathlib import Path


KEY_NAME = "local-access.key"
COOKIE_NAME = "ctf_local_access"
COOKIE_SECONDS = 30 * 24 * 60 * 60
_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{64}\Z")
_COOKIE_PATTERN = re.compile(r"([0-9]{10,12})\.([A-Za-z0-9_-]{22})\.([0-9a-f]{64})\Z")


def ensure_key(config_dir: Path) -> bytes:
    """Create once, then read only a private regular file; never log its value."""

    if config_dir.is_symlink() or not config_dir.is_dir():
        raise RuntimeError("Local access config directory is invalid")
    path = config_dir / KEY_NAME
    if path.is_symlink():
        raise RuntimeError("Local access key must not be a symlink")
    if not path.exists() and not path.is_symlink():
        token = secrets.token_urlsafe(48)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        if os.name == "posix":
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            pass  # Another web/installer process created the same key first.
        else:
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
                os.write(descriptor, token.encode("ascii") + b"\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if os.name == "posix":
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        state = os.fstat(descriptor)
        if (not stat.S_ISREG(state.st_mode) or state.st_nlink != 1
                or (os.name == "posix" and stat.S_IMODE(state.st_mode) != 0o600)
                or state.st_size != 65):
            raise RuntimeError("Local access key has invalid permissions or format")
        raw = os.read(descriptor, 66)
    finally:
        os.close(descriptor)
    if len(raw) != 65 or raw[-1:] != b"\n":
        raise RuntimeError("Local access key has invalid permissions or format")
    token = raw[:-1].decode("ascii")
    if not _KEY_PATTERN.fullmatch(token):
        raise RuntimeError("Local access key has invalid permissions or format")
    return raw[:-1]


def issue_cookie(key: bytes, *, now: int | None = None) -> str:
    issued = int(time.time()) if now is None else now
    body = f"{issued}.{secrets.token_urlsafe(16)}"
    signature = hmac.new(key, b"local-browser-v1:" + body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def valid_cookie(key: bytes, value: str, *, now: int | None = None) -> bool:
    match = _COOKIE_PATTERN.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return False
    current = int(time.time()) if now is None else now
    issued = int(match.group(1))
    if issued > current + 60 or current - issued > COOKIE_SECONDS:
        return False
    body = f"{match.group(1)}.{match.group(2)}"
    expected = hmac.new(key, b"local-browser-v1:" + body.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, match.group(3))
