"""Offline regression for exact, reversible historical write-up repair."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "repair_historical_writeups.py"
FLAG = "test{hidden-secret}"
SOURCE = (
    "# Example\n\n"
    "The solution uses this code:\n\n"
    "```python\nprint('solution')\n```\n\n"
    "```sh\npython solver.py\nsubmit-flag " + FLAG + "\n```\n"
)


class RepairTests(unittest.TestCase):
    def test_script_is_in_production_image_and_local_bundle(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        package = (ROOT / "scripts" / "package_local_release.py").read_text(encoding="utf-8")
        self.assertIn(
            "COPY --chown=0:0 --chmod=0444 scripts/repair_historical_writeups.py "
            "/app/scripts/repair_historical_writeups.py",
            dockerfile,
        )
        self.assertIn("!scripts/repair_historical_writeups.py", dockerignore)
        self.assertIn('"scripts/repair_historical_writeups.py",', package)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "ctf_agent.sqlite3"
        self.data = self.root / "data"
        self.challenge = self.data / "workspace_files" / "Workspace" / "Challenge"
        self.challenge.mkdir(parents=True)
        self.plan = self.root / "plan.json"
        self.backups = self.root / "backups"
        (self.challenge.parent / ".ctf-agent-id").write_text(
            json.dumps({"kind": "workspace", "id": "ws1"}), encoding="utf-8"
        )
        (self.challenge / ".ctf-agent-id").write_text(
            json.dumps({"kind": "challenge", "id": "ch1"}), encoding="utf-8"
        )
        self.notes = "Manual intro\n\n" + SOURCE
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE challenges (
                    id TEXT PRIMARY KEY, workspace_id TEXT, status TEXT,
                    completion_source TEXT, notes TEXT, updated_at TEXT
                );
                CREATE TABLE challenge_writeups (
                    challenge_id TEXT PRIMARY KEY, markdown TEXT, updated_at TEXT
                );
                CREATE TABLE solver_jobs (id TEXT, writeup_markdown TEXT);
                CREATE TABLE solver_slots (slot_id TEXT);
                CREATE TABLE readable_storage_paths (
                    kind TEXT, entity_id TEXT, parent_id TEXT, name TEXT
                );
                CREATE TABLE readable_text_state (
                    kind TEXT, challenge_id TEXT, content_sha256 TEXT, mtime_ns INTEGER,
                    PRIMARY KEY (kind,challenge_id)
                );
                """
            )
            db.execute(
                "INSERT INTO challenges VALUES (?,?,?,?,?,?)",
                ("ch1", "ws1", "solved", "agent", self.notes, "2026-01-01"),
            )
            db.execute(
                "INSERT INTO challenge_writeups VALUES (?,?,?)",
                ("ch1", SOURCE, "2026-01-01"),
            )
            db.execute("INSERT INTO solver_jobs VALUES (?,?)", ("job1", SOURCE))
            db.executemany(
                "INSERT INTO readable_storage_paths VALUES (?,?,?,?)",
                [("workspace", "ws1", "", "Workspace"),
                 ("challenge", "ch1", "ws1", "Challenge")],
            )
            for kind, content in (("writeup", SOURCE), ("notes", self.notes)):
                path = self.challenge / f"{kind}.md"
                path.write_bytes(content.encode("utf-8"))
                db.execute(
                    "INSERT INTO readable_text_state VALUES (?,?,?,?)",
                    (kind, "ch1", hashlib.sha256(content.encode()).hexdigest(), path.stat().st_mtime_ns),
                )

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(CLI), "--database", str(self.database),
             "--data-dir", str(self.data), "--expected-count", "1",
             "--plan", str(self.plan), *args],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertNotIn(FLAG, completed.stdout + completed.stderr)
        return completed

    def test_dry_run_apply_and_second_apply(self) -> None:
        before_db = self.database.read_bytes()
        before_notes = (self.challenge / "notes.md").read_bytes()
        before_ownership = {
            kind: (path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode))
            for kind in ("writeup", "notes")
            for path in (self.challenge / f"{kind}.md",)
        }
        dry = self.run_cli("--challenge-id", "ch1")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(json.loads(dry.stdout)["candidate_lines"], 1)
        self.assertNotIn(FLAG, self.plan.read_text(encoding="utf-8"))
        self.assertNotIn("submit-flag", self.plan.read_text(encoding="utf-8"))
        self.assertEqual(self.database.read_bytes(), before_db)
        self.assertEqual((self.challenge / "notes.md").read_bytes(), before_notes)

        apply = self.run_cli("--apply", "--confirm-stopped", "--backup-dir", str(self.backups))
        self.assertEqual(apply.returncode, 0, apply.stderr)
        result = json.loads(apply.stdout)
        self.assertEqual(result["updated"], 1)
        backup = Path(result["backup"])
        self.assertTrue((backup / "database.sqlite3").is_file())
        self.assertFalse((backup / "IN_PROGRESS").exists())
        with closing(sqlite3.connect(backup / "database.sqlite3")) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT markdown FROM challenge_writeups").fetchone()[0], SOURCE)

        with closing(sqlite3.connect(self.database)) as db:
            markdown = db.execute("SELECT markdown FROM challenge_writeups").fetchone()[0]
            notes = db.execute("SELECT notes FROM challenges").fetchone()[0]
            legacy = db.execute("SELECT writeup_markdown FROM solver_jobs").fetchone()[0]
            self.assertEqual(legacy, SOURCE)
            self.assertEqual(markdown, SOURCE.replace("submit-flag " + FLAG + "\n", ""))
            self.assertEqual(notes, self.notes.replace("submit-flag " + FLAG + "\n", ""))
            self.assertIn("print('solution')", markdown)
            for kind, content in (("writeup", markdown), ("notes", notes)):
                path = self.challenge / f"{kind}.md"
                self.assertEqual(path.read_text(encoding="utf-8"), content)
                digest, mtime = db.execute(
                    "SELECT content_sha256,mtime_ns FROM readable_text_state WHERE kind=?",
                    (kind,),
                ).fetchone()
                self.assertEqual(digest, hashlib.sha256(content.encode()).hexdigest())
                self.assertEqual(mtime, path.stat().st_mtime_ns)
                self.assertEqual(
                    (path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)),
                    before_ownership[kind],
                )

        repeat = self.run_cli("--apply", "--confirm-stopped", "--backup-dir", str(self.backups))
        self.assertEqual(repeat.returncode, 0, repeat.stderr)
        self.assertEqual(json.loads(repeat.stdout)["updated"], 0)
        self.assertEqual(len(list(self.backups.glob("writeup-repair-*"))), 1)

    def test_intervening_edit_blocks_apply(self) -> None:
        self.assertEqual(self.run_cli("--challenge-id", "ch1").returncode, 0)
        path = self.challenge / "notes.md"
        path.write_text(path.read_text(encoding="utf-8") + "manual edit\n", encoding="utf-8")
        failed = self.run_cli("--apply", "--confirm-stopped", "--backup-dir", str(self.backups))
        self.assertEqual(failed.returncode, 1)
        self.assertFalse(self.backups.exists())
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT markdown FROM challenge_writeups").fetchone()[0], SOURCE)

    def test_apply_requires_stopped_services_and_empty_slots(self) -> None:
        self.assertEqual(self.run_cli("--challenge-id", "ch1").returncode, 0)
        missing_confirmation = self.run_cli("--apply", "--backup-dir", str(self.backups))
        self.assertEqual(missing_confirmation.returncode, 1)
        self.assertFalse(self.backups.exists())
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("INSERT INTO solver_slots VALUES ('active')")
        active = self.run_cli("--apply", "--confirm-stopped", "--backup-dir", str(self.backups))
        self.assertEqual(active.returncode, 1)
        self.assertFalse(self.backups.exists())

    def test_non_standalone_operation_needs_manual_review(self) -> None:
        unsafe = SOURCE.replace("submit-flag " + FLAG, "python -c 'submit-flag " + FLAG + "'")
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE challenge_writeups SET markdown=?", (unsafe,))
            db.execute("UPDATE challenges SET notes=?", ("Manual intro\n\n" + unsafe,))
            for kind, content in (("writeup", unsafe), ("notes", "Manual intro\n\n" + unsafe)):
                path = self.challenge / f"{kind}.md"
                path.write_bytes(content.encode("utf-8"))
                db.execute(
                    "UPDATE readable_text_state SET content_sha256=?,mtime_ns=? WHERE kind=?",
                    (hashlib.sha256(content.encode()).hexdigest(), path.stat().st_mtime_ns, kind),
                )
        failed = self.run_cli("--challenge-id", "ch1")
        self.assertEqual(failed.returncode, 1)
        self.assertFalse(self.plan.exists())


if __name__ == "__main__":
    unittest.main()
