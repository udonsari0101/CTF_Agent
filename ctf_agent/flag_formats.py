"""Canonical flag-format values shared by every challenge in a workspace."""

from __future__ import annotations

import re


# The suffix is five characters, so a shorthand can still satisfy the API's
# 500-character flag-format bound after expansion.
_PLAIN_PREFIX = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,494}\Z")


def normalize_flag_format(value: str | None) -> str | None:
    """Expand a plain flag prefix while preserving explicit format syntax.

    A workspace flag format is inherited by manually-created and CTFd-imported
    challenges alike.  Treat only a single identifier as shorthand so regular
    expressions, examples, and prose descriptions remain byte-for-byte intact.
    """

    if value is None or value == "":
        return value
    prefix = value.strip()
    if _PLAIN_PREFIX.fullmatch(prefix):
        return f"{prefix}{{...}}"
    return value
