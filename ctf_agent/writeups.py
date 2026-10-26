"""Durable storage for generated challenge write-ups.

``challenge_writeups`` remains the canonical artifact. A plain Markdown copy
is embedded in ``challenges.notes`` so files, downloads and the editor never
contain implementation comments.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Callable, ContextManager


GENERATED_WRITEUP_START = "<!-- ctf-agent:generated-writeup:start -->"
GENERATED_WRITEUP_END = "<!-- ctf-agent:generated-writeup:end -->"
_GENERATED_WRITEUP_BLOCK = re.compile(
    re.escape(GENERATED_WRITEUP_START)
    + r"\n.*?\n"
    + re.escape(GENERATED_WRITEUP_END),
    re.DOTALL,
)


def generated_writeup_block(markdown: str) -> str:
    """Return the plain Markdown used by the notes copy.

    The old HTML comments remain recognized for a one-way compatibility
    migration, but are never written again.
    """

    value = markdown.replace("\r\n", "\n").replace("\r", "\n").strip()
    value = value.replace(GENERATED_WRITEUP_START, "").replace(GENERATED_WRITEUP_END, "")
    return value.strip()


def merge_generated_writeup(
    notes: str,
    markdown: str,
    previous_markdown: str | None = None,
) -> str:
    """Insert or replace the known generated copy while preserving manual text."""

    current = notes if isinstance(notes, str) else ""
    block = generated_writeup_block(markdown)
    matches = list(_GENERATED_WRITEUP_BLOCK.finditer(current))
    if matches:
        first = matches[0]
        pieces = [current[: first.start()], block]
        cursor = first.end()
        for duplicate in matches[1:]:
            pieces.append(current[cursor : duplicate.start()])
            cursor = duplicate.end()
        pieces.append(current[cursor:])
        return "".join(pieces)

    previous = (
        generated_writeup_block(previous_markdown)
        if isinstance(previous_markdown, str) and previous_markdown
        else ""
    )
    if previous:
        position = current.rfind(previous)
        if position >= 0:
            return current[:position] + block + current[position + len(previous):]
    if block and current.rstrip().endswith(block):
        return current
    separator = "" if not current else ("\n" if current.endswith("\n") else "\n\n")
    return current + separator + block


def remove_generated_writeup(notes: str, previous_markdown: str | None = None) -> str:
    """Remove the known generated copy when a candidate Flag is rejected."""

    current = notes if isinstance(notes, str) else ""
    current = _GENERATED_WRITEUP_BLOCK.sub("", current)
    previous = (
        generated_writeup_block(previous_markdown)
        if isinstance(previous_markdown, str) and previous_markdown
        else ""
    )
    if not previous:
        return current
    position = current.rfind(previous)
    if position < 0:
        return current
    before, after = current[:position], current[position + len(previous):]
    if not after and before.endswith("\n\n"):
        before = before[:-2]
    elif not after and before.endswith("\n"):
        before = before[:-1]
    return before + after


class WriteupStore:
    """Own the additive write-up schema and its compatibility migration."""

    def __init__(self, database: Callable[[], ContextManager[sqlite3.Connection]]):
        self.database = database
        self.artifact_writer = None
        self._initialize()

    def set_artifact_writer(self, writer) -> None:
        self.artifact_writer = writer

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _initialize(self) -> None:
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """CREATE TABLE IF NOT EXISTS challenge_writeups (
                       challenge_id TEXT PRIMARY KEY
                           REFERENCES challenges(id) ON DELETE CASCADE,
                       markdown TEXT NOT NULL,
                       created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_challenge_writeups_updated "
                "ON challenge_writeups(updated_at,challenge_id)"
            )

            self._migrate_legacy_solver_results(db)
            rows = db.execute(
                """SELECT w.challenge_id,w.markdown,c.notes
                     FROM challenge_writeups w
                     JOIN challenges c ON c.id=w.challenge_id"""
            ).fetchall()
            for row in rows:
                clean_markdown = generated_writeup_block(row["markdown"])
                clean_notes = row["notes"]
                if _GENERATED_WRITEUP_BLOCK.search(clean_notes):
                    clean_notes = merge_generated_writeup(
                        clean_notes, clean_markdown, row["markdown"]
                    )
                if clean_markdown != row["markdown"]:
                    db.execute(
                        "UPDATE challenge_writeups SET markdown=? WHERE challenge_id=?",
                        (clean_markdown, row["challenge_id"]),
                    )
                if clean_notes != row["notes"]:
                    db.execute(
                        "UPDATE challenges SET notes=? WHERE id=?",
                        (clean_notes, row["challenge_id"]),
                    )

    @staticmethod
    def _migrate_legacy_solver_results(db: sqlite3.Connection) -> None:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_jobs'"
        ).fetchone()
        if not table:
            return
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(solver_jobs)").fetchall()
        }
        required = {
            "id",
            "workspace_id",
            "challenge_id",
            "writeup_markdown",
            "created_at",
        }
        if not required.issubset(columns):
            return

        # Keep the most recent durable result for each challenge.  Existing
        # notes are deliberately left untouched because an older release may
        # have stored either user text or a generated write-up there.
        db.execute(
            """WITH ranked AS (
                   SELECT challenge_id,workspace_id,writeup_markdown,
                          ROW_NUMBER() OVER (
                              PARTITION BY workspace_id,challenge_id
                              ORDER BY created_at DESC,id DESC
                          ) AS position
                   FROM solver_jobs
                   WHERE writeup_markdown IS NOT NULL
                     AND length(writeup_markdown)>0
               )
               INSERT INTO challenge_writeups(
                   challenge_id,markdown,created_at,updated_at
               )
               SELECT c.id,r.writeup_markdown,c.updated_at,c.updated_at
               FROM challenges c
               JOIN ranked r ON r.workspace_id=c.workspace_id
                            AND r.challenge_id=c.id
                            AND r.position=1
               WHERE c.status='solved' AND c.completion_source='agent'
               ON CONFLICT(challenge_id) DO UPDATE SET
                   markdown=excluded.markdown,
                   updated_at=excluded.updated_at
               WHERE challenge_writeups.markdown<>excluded.markdown"""
        )

    def fields(
        self,
        db: sqlite3.Connection,
        challenge_id: str,
        *,
        include_markdown: bool = True,
    ) -> dict:
        row = db.execute(
            "SELECT markdown,updated_at FROM challenge_writeups WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()
        result = {
            "has_writeup": row is not None,
            "writeup_updated_at": row["updated_at"] if row else None,
        }
        if include_markdown:
            result["writeup_markdown"] = row["markdown"] if row else None
        return result

    def record_agent_writeup(
        self,
        owner_user_id: str,
        workspace_id: str,
        challenge_id: str,
        markdown: str,
    ) -> bool:
        """Idempotently retain a committed result before notification fan-out."""

        if not isinstance(markdown, str) or not markdown:
            return False
        timestamp = self._timestamp()
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            owned = db.execute(
                """SELECT c.notes FROM challenges c
                   JOIN workspaces w ON w.id=c.workspace_id
                   WHERE c.id=? AND c.workspace_id=? AND w.owner_user_id=?
                      AND c.status='solved' AND c.completion_source='agent'""",
                (challenge_id, workspace_id, owner_user_id),
            ).fetchone()
            if not owned:
                return False
            prior = db.execute(
                "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            previous_markdown = prior["markdown"] if prior else None
            clean_markdown = generated_writeup_block(markdown)
            if not clean_markdown:
                return False
            db.execute(
                """INSERT INTO challenge_writeups(
                       challenge_id,markdown,created_at,updated_at
                   ) VALUES(?,?,?,?)
                   ON CONFLICT(challenge_id) DO UPDATE SET
                       markdown=excluded.markdown,
                       updated_at=excluded.updated_at
                   WHERE challenge_writeups.markdown<>excluded.markdown""",
                (challenge_id, clean_markdown, timestamp, timestamp),
            )
            merged_notes = merge_generated_writeup(
                owned["notes"], clean_markdown, previous_markdown
            )
            if merged_notes != owned["notes"]:
                db.execute(
                    """UPDATE challenges SET notes=?,updated_at=?
                       WHERE id=? AND workspace_id=?""",
                    (merged_notes, timestamp, challenge_id, workspace_id),
                )
        if self.artifact_writer is not None:
            self.artifact_writer(
                workspace_id, challenge_id, merged_notes, clean_markdown
            )
        return True


__all__ = [
    "GENERATED_WRITEUP_END",
    "GENERATED_WRITEUP_START",
    "WriteupStore",
    "generated_writeup_block",
    "merge_generated_writeup",
    "remove_generated_writeup",
]
