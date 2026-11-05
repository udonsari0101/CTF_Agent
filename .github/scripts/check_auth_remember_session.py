"""Offline checks for opt-in persistent login and current-device rotation."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.main import create_app


class RememberSessionTest(unittest.TestCase):
    def test_opt_in_cookie_rotation_and_legacy_table_migration(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            settings = Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="password", allow_web_bootstrap=True,
            )
            settings.db_dir.mkdir()
            with sqlite3.connect(settings.database_path) as db:
                db.execute(
                    "CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,csrf_token TEXT NOT NULL,expires_at INTEGER NOT NULL)"
                )
            app = create_app(settings)
            with TestClient(app) as browser:
                initial = browser.get("/api/auth/state").json()
                self.assertTrue(initial["setup_available"])
                setup = browser.post(
                    "/api/auth/setup", json={"username": "owner", "password": "pass1234"}
                )
                self.assertEqual(setup.status_code, 200, setup.text)
                self.assertFalse(browser.get("/api/auth/state").json()["session_persistent"])
                browser.headers.update({"x-csrf-token": setup.json()["csrf_token"]})
                self.assertEqual(browser.post("/api/auth/logout").status_code, 200)

                login = browser.post(
                    "/api/auth/login",
                    json={"username": "owner", "password": "pass1234", "remember": True},
                )
                self.assertEqual(login.status_code, 200, login.text)
                self.assertTrue(login.json()["session_persistent"])
                self.assertIn("Max-Age=2592000", login.headers["set-cookie"])
                old_cookie = browser.cookies.get("ctf_session")
                browser.headers["x-csrf-token"] = login.json()["csrf_token"]
                self.assertTrue(browser.get("/api/auth/state").json()["session_persistent"])

                refresh = browser.post("/api/auth/session/refresh", json={"remember": False})
                self.assertEqual(refresh.status_code, 200, refresh.text)
                self.assertFalse(refresh.json()["session_persistent"])
                self.assertIn("Max-Age=43200", refresh.headers["set-cookie"])
                self.assertNotEqual(old_cookie, browser.cookies.get("ctf_session"))
                with app.state.connect() as db:
                    columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
                    self.assertIn("persistent", columns)
                    self.assertIsNone(db.execute(
                        "SELECT 1 FROM sessions WHERE token_hash=?",
                        (hashlib.sha256(old_cookie.encode()).hexdigest(),),
                    ).fetchone())
                    self.assertEqual(db.execute(
                        "SELECT persistent FROM sessions WHERE token_hash=?",
                        (hashlib.sha256(browser.cookies.get("ctf_session").encode()).hexdigest(),),
                    ).fetchone()[0], 0)
                browser.headers["x-csrf-token"] = refresh.json()["csrf_token"]
                self.assertEqual(browser.post("/api/auth/logout").status_code, 200)
                self.assertFalse(browser.get("/api/auth/state").json()["authenticated"])

    def test_nologin_does_not_offer_session_rotation(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            app = create_app(Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            ))
            with TestClient(app) as browser:
                state = browser.get("/api/auth/state").json()
                self.assertFalse(state["session_persistent"])
                response = browser.post(
                    "/api/auth/session/refresh", json={"remember": True},
                    headers={"x-csrf-token": state["csrf_token"]},
                )
                self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
