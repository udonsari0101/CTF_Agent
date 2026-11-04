"""Offline regression for the read-only published write-up audit CLI."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "audit_existing_writeups.py"


class ExistingWriteupAuditTests(unittest.TestCase):
    def test_reports_ids_only_and_preserves_database(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "ctf_agent.sqlite3"
            with closing(sqlite3.connect(database)) as db, db:
                db.execute(
                    "CREATE TABLE challenge_writeups "
                    "(challenge_id TEXT PRIMARY KEY, markdown TEXT NOT NULL)"
                )
                db.executemany(
                    "INSERT INTO challenge_writeups VALUES (?,?)",
                    [
                        ("safe-id", "# Solution\nPOST /api/v1/challenges/1/submit\n"),
                        ("flagged-id", "# Solution\n`submit-flag`\ntest{hidden-secret}\n"),
                    ],
                )
            before = database.read_bytes()
            completed = subprocess.run(
                [sys.executable, str(CLI), "--database", str(database)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                json.loads(completed.stdout),
                {
                    "challenge_ids": ["flagged-id"],
                    "writeups_flagged": 1,
                    "writeups_scanned": 2,
                },
            )
            self.assertNotIn("test{", completed.stdout + completed.stderr)
            self.assertNotIn("submit-flag", completed.stdout + completed.stderr)
            self.assertEqual(database.read_bytes(), before)

    def test_missing_table_fails_without_adding_schema(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "ctf_agent.sqlite3"
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("CREATE TABLE unrelated (id INTEGER)")
            before = database.read_bytes()
            completed = subprocess.run(
                [sys.executable, str(CLI), "--database", str(database)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, "")
            self.assertNotIn(str(database), completed.stderr)
            self.assertEqual(database.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
