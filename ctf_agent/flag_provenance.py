"""Bounded check for a candidate copied verbatim from challenge inputs.

This cannot prove a candidate is correct. It only identifies the common case
where an endpoint-backed challenge ships a placeholder flag in its source.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


MAX_FILES = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
READ_BYTES = 64 * 1024


def _contains_literal(path: str, needle: bytes) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return False
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            return False
        overlap = b""
        while chunk := os.read(descriptor, READ_BYTES):
            if needle in overlap + chunk:
                return True
            overlap = chunk[-(len(needle) - 1):] if len(needle) > 1 else b""
        return False
    except OSError:
        return False
    finally:
        os.close(descriptor)


def literal_in_supplied_inputs(workdir: Path, candidate: str, description: str = "") -> bool:
    """Check immutable raw/extracted inputs, never model-created work files.

    The scan is deliberately bounded so a large disk image cannot delay a
    solver handoff. A negative result means only that no bounded literal was
    found; it is not evidence that the candidate is genuine.
    """

    needle = candidate.encode("utf-8")
    if not needle:
        return False
    if needle in description.encode("utf-8"):
        return True
    files = 0
    directories = 0
    total_bytes = 0
    for source in (workdir / "attachments", workdir / "extracted"):
        stack = [source]
        while (
            stack and files < MAX_FILES and directories < MAX_FILES
            and total_bytes < MAX_TOTAL_BYTES
        ):
            directory = stack.pop()
            directories += 1
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if directories + len(stack) < MAX_FILES:
                                    stack.append(Path(entry.path))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            size = entry.stat(follow_symlinks=False).st_size
                        except OSError:
                            continue
                        files += 1
                        if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
                            if files >= MAX_FILES:
                                break
                            continue
                        total_bytes += size
                        if _contains_literal(entry.path, needle):
                            return True
                        if files >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
                            break
            except OSError:
                continue
    return False


__all__ = ["literal_in_supplied_inputs"]
