"""Read-only inventory of published write-ups containing service operations.

Run against an explicitly selected SQLite database:

    python scripts/audit_existing_writeups.py --database /path/to/ctf_agent.sqlite3

The canonical ``challenge_writeups`` table is scanned without opening the
application or running its schema migration. Output contains counts and
challenge IDs only; it never prints Markdown, flags, or account details.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctf_agent.writeup_publication import contains_internal_operation


def audit(database_path: Path) -> dict[str, object]:
    """Inspect the canonical artifact without modifying the database."""

    path = database_path.expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("Database path is not a file.")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        columns = {
            row[1]
            for row in db.execute("PRAGMA table_info(challenge_writeups)")
        }
        if not {"challenge_id", "markdown"}.issubset(columns):
            raise ValueError("The database has no canonical write-up table.")
        total = 0
        flagged: list[str] = []
        for challenge_id, markdown in db.execute(
            "SELECT challenge_id,markdown FROM challenge_writeups ORDER BY challenge_id"
        ):
            total += 1
            if contains_internal_operation(markdown):
                flagged.append(str(challenge_id))
    return {
        "writeups_scanned": total,
        "writeups_flagged": len(flagged),
        "challenge_ids": flagged,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path,
                        help="Existing ctf_agent.sqlite3 path (read-only)")
    args = parser.parse_args(argv)
    try:
        result = audit(args.database)
    except (OSError, sqlite3.Error, ValueError) as exc:
        # Avoid echoing a database path or SQLite payload in error messages.
        print(f"Write-up audit failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
