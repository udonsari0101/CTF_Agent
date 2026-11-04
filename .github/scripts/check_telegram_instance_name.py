"""Regression for per-user Telegram installation labels and notification rendering."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException

ROOT = Path(__file__).resolve().parents[2] if ".github" in Path(__file__).parts else Path.cwd()
sys.path.insert(0, str(ROOT))

from ctf_agent.telegram import register_telegram  # noqa: E402


class TelegramInstanceNameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        path = root / "state.sqlite3"

        @contextmanager
        def database():
            db = sqlite3.connect(path)
            db.row_factory = sqlite3.Row
            try:
                with db:
                    yield db
            finally:
                db.close()

        self.database = database
        with database() as db:
            db.execute("CREATE TABLE users(id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT)")
            db.executemany("INSERT INTO users(id) VALUES(?)", [("owner-a",), ("owner-b",)])
            # Simulate a pre-upgrade installation with existing per-user settings.
            db.execute("""CREATE TABLE telegram_settings(
                user_id TEXT PRIMARY KEY,chat_id INTEGER,enabled INTEGER NOT NULL DEFAULT 0,
                linked_at TEXT,last_success_at TEXT,last_failure_at TEXT,last_failure_code TEXT
            )""")
            db.execute("INSERT INTO telegram_settings(user_id,chat_id,enabled) VALUES('owner-a',123,1)")
        settings = SimpleNamespace(config_dir=root, public_origin="")
        self.service = register_telegram(FastAPI(), lambda: None, settings, database)

    def test_migration_and_owner_specific_setting(self) -> None:
        self.assertEqual(self.service.settings_for("owner-a")["instance_name"], "")
        self.service.set_instance_name("owner-a", "  Desktop <Lab>  ")
        self.assertEqual(self.service.settings_for("owner-a")["instance_name"], "Desktop <Lab>")
        self.assertEqual(self.service.settings_for("owner-b")["instance_name"], "")
        with self.database() as db:
            self.assertEqual(db.execute("SELECT chat_id,enabled FROM telegram_settings WHERE user_id='owner-a'").fetchone()[:], (None, 0))
            self.assertEqual(db.execute("SELECT instance_name FROM telegram_settings WHERE user_id='owner-b'").fetchone(), None)
        self.service.set_instance_name("owner-b", "Local")
        self.assertEqual(self.service.settings_for("owner-b")["instance_name"], "Local")

    def test_rejects_unbounded_or_multiline_names(self) -> None:
        for value in ("a" * 81, "bad\nname", "bad\x7fname"):
            with self.subTest(value=value), self.assertRaises(HTTPException):
                self.service.set_instance_name("owner-a", value)

    def test_every_notification_uses_escaped_instance_name(self) -> None:
        common = {
            "instance_name": "Lab <One>", "chat_id": 123, "workspace_id": "w", "challenge_id": "c",
            "workspace_name": "Demo", "challenge_name": "Question", "created_at": "2026-11-03",
            "solver_provider": None,
        }
        for event, additions in (
            ("flag_found", {"flag": "CTF{x}"}),
            ("writeup_ready", {"writeup_markdown": "# note"}),
            ("solver_alert", {"solver_status": "needs_input", "solver_error_code": "remote_input_required"}),
        ):
            with self.subTest(event=event):
                _, payload = self.service._notification({**common, "event_type": event, **additions})
                self.assertTrue(payload["text"].startswith("📍 <b>Lab &lt;One&gt;</b>\n"))
                self.assertNotIn("<One>", payload["text"])


if __name__ == "__main__":
    unittest.main()
