"""Ensure startup backfill cannot replace a cleaned canonical write-up."""

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.writeups import WriteupStore


def main() -> None:
    with TemporaryDirectory() as directory:
        path = Path(directory) / "writeups.sqlite3"

        @contextmanager
        def database():
            connection = sqlite3.connect(path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            try:
                yield connection
                connection.commit()
            finally:
                connection.close()

        with database() as db:
            db.executescript(
                """
                CREATE TABLE challenges (
                    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
                    status TEXT NOT NULL, completion_source TEXT NOT NULL,
                    updated_at TEXT NOT NULL, notes TEXT NOT NULL
                );
                CREATE TABLE solver_jobs (
                    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL, writeup_markdown TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE challenge_writeups (
                    challenge_id TEXT PRIMARY KEY REFERENCES challenges(id),
                    markdown TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            db.executemany(
                "INSERT INTO challenges VALUES (?,?,?,?,?,?)",
                [
                    ("edited", "workspace", "solved", "agent", "2026-01-03", "Manual note"),
                    ("missing", "workspace", "solved", "agent", "2026-01-03", ""),
                ],
            )
            db.execute(
                "INSERT INTO challenge_writeups VALUES (?,?,?,?)",
                ("edited", "# Cleaned write-up\n\nReproducible analysis.", "2026-01-02", "2026-01-03"),
            )
            db.executemany(
                "INSERT INTO solver_jobs VALUES (?,?,?,?,?)",
                [
                    ("old-edited", "workspace", "edited", "# Old write-up\n\nsubmit-flag EXAMPLE", "2026-01-01"),
                    ("old-missing", "workspace", "missing", "# Old candidate", "2026-01-01"),
                    ("new-missing", "workspace", "missing", "# Latest candidate", "2026-01-02"),
                ],
            )

        WriteupStore(database)
        WriteupStore(database)  # Repeated startup must not restore legacy text.

        with database() as db:
            edited = db.execute(
                "SELECT markdown,updated_at FROM challenge_writeups WHERE challenge_id='edited'"
            ).fetchone()
            missing = db.execute(
                "SELECT markdown FROM challenge_writeups WHERE challenge_id='missing'"
            ).fetchone()
            notes = db.execute("SELECT notes FROM challenges WHERE id='edited'").fetchone()[0]

        assert edited["markdown"] == "# Cleaned write-up\n\nReproducible analysis."
        assert edited["updated_at"] == "2026-01-03"
        assert missing["markdown"] == "# Latest candidate"
        assert notes == "Manual note"


if __name__ == "__main__":
    main()
