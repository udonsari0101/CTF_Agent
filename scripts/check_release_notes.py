"""Reject private or credential-like content before publishing release notes."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
_URL = re.compile(r"https?://[^\s<>\])]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+"
    r"(?:com|net|org|io|ai|dev|co|kr|test|local|cloud|app|me)"
    r"(?::[0-9]+)?\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_CREDENTIAL = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|"
    r"ctfd_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"CF-Access-Client-Secret\s*[:=]|"
    r"Authorization\s*:\s*Bearer\s+\S+)",
    re.IGNORECASE,
)
_PRIVATE_PATH = re.compile(r"(?:[A-Za-z]:\\|/volume[0-9]+/|/home/)")


def validate_markdown(markdown: str, repository: str, tag: str) -> None:
    """Validate the same Markdown used for the release body and asset.

    Failure messages intentionally omit the offending text, which may be a secret.
    """

    if not _REPOSITORY.fullmatch(repository) or not _TAG.fullmatch(tag):
        raise ValueError("Invalid release identity")
    if len(markdown.encode("utf-8")) > 16_000 or not markdown.startswith("## Changes\n\n"):
        raise ValueError("Invalid release note structure or length")
    if not re.search(r"^- ", markdown, re.MULTILINE):
        raise ValueError("Release notes have no change entries")
    if _CREDENTIAL.search(markdown) or _EMAIL.search(markdown) or _IPV4.search(markdown):
        raise ValueError("Release notes contain private data")
    if _PRIVATE_PATH.search(markdown):
        raise ValueError("Release notes contain a local path")

    safe_compare = re.compile(
        rf"https://github\.com/{re.escape(repository)}/compare/"
        rf"v[0-9]+\.[0-9]+\.[0-9]+\.\.\.{re.escape(tag)}\Z"
    )
    other_text = markdown
    for match in _URL.finditer(markdown):
        if not safe_compare.fullmatch(match.group()):
            raise ValueError("Release notes contain an unexpected URL")
    other_text = _URL.sub("", other_text)
    if _DOMAIN.search(other_text):
        raise ValueError("Release notes contain an unexpected hostname")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("notes", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    validate_markdown(args.notes.read_text(encoding="utf-8"), args.repository, args.tag)


if __name__ == "__main__":
    main()
