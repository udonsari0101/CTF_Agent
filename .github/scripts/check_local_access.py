"""No-model regression for local passwordless browser access."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.local_access import COOKIE_NAME, KEY_NAME
from ctf_agent.main import create_app


class LocalAccessTest(unittest.TestCase):
    def _settings(self, root: Path, mode: str = "nologin") -> Settings:
        return Settings(root / "data", root / "db", root / "config", root / "logs",
                        storage_min_free_bytes=0, auth_mode=mode,
                        allow_web_bootstrap=True)

    def test_local_key_ticket_cookie_and_restart(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            settings = self._settings(Path(temporary))
            app = create_app(settings)
            key_path = settings.config_dir / KEY_NAME
            key = key_path.read_text(encoding="ascii").strip()
            self.assertEqual(len(key), 64)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

            with TestClient(app, base_url="http://host.docker.internal:5050") as untrusted:
                state = untrusted.get("/api/auth/state")
                self.assertEqual(state.status_code, 200)
                self.assertFalse(state.json()["authenticated"])
                self.assertIsNone(state.json()["csrf_token"])
                self.assertIsNone(state.json()["user"])
                self.assertNotIn(key, state.text)
                self.assertEqual(untrusted.get("/api/workspaces").status_code, 401)
                self.assertEqual(untrusted.post("/api/workspaces", json={}).status_code, 401)
                self.assertIn(untrusted.post("/api/auth/local/ticket", json={"token": "x" * 64}).status_code,
                              (403, 422))
                self.assertEqual(untrusted.post("/api/auth/local/ticket",
                                                json={"token": "\uD55C" * 64}).status_code, 422)
                self.assertEqual(untrusted.post("/api/auth/local/bootstrap",
                                                json={"ticket": "x" * 32}).status_code, 403)
                self.assertEqual(untrusted.get("/api/auth/local/ticket").status_code, 405)

            with TestClient(app) as browser:
                response = browser.post("/api/auth/local/ticket", json={"token": key})
                self.assertEqual(response.status_code, 200, response.text)
                ticket = response.json()["ticket"]
                self.assertEqual(len(ticket), 32)
                self.assertNotIn(key, response.text)
                self.assertEqual(response.headers["cache-control"], "no-store")
                response = browser.post("/api/auth/local/bootstrap", json={"ticket": ticket})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertIn("HttpOnly", response.headers["set-cookie"])
                self.assertIn("SameSite=strict", response.headers["set-cookie"])
                self.assertEqual(browser.post("/api/auth/local/bootstrap",
                                              json={"ticket": ticket}).status_code, 403)
                cookie = browser.cookies.get(COOKIE_NAME)
                self.assertIsNotNone(cookie)
                state = browser.get("/api/auth/state").json()
                self.assertTrue(state["authenticated"])
                self.assertTrue(state["csrf_token"])
                self.assertEqual(browser.get("/api/workspaces").status_code, 200)
                self.assertEqual(browser.post("/api/workspaces", json={"name": "test"}).status_code, 403)

            # Existing browser cookies survive an update or web restart, while
            # the key is stable and never recreated from a different value.
            second_app = create_app(settings)
            self.assertEqual(key_path.read_text(encoding="ascii").strip(), key)
            with TestClient(second_app) as browser:
                browser.cookies.set(COOKIE_NAME, cookie)
                self.assertTrue(browser.get("/api/auth/state").json()["authenticated"])
                self.assertEqual(browser.get("/api/workspaces").status_code, 200)

    def test_password_mode_has_no_local_ticket_endpoint(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            settings = self._settings(Path(temporary), "password")
            app = create_app(settings)
            with TestClient(app) as browser:
                self.assertEqual(browser.post("/api/auth/local/ticket",
                                              json={"token": "x" * 64}).status_code, 404)
                self.assertEqual(browser.post("/api/auth/local/bootstrap",
                                              json={"ticket": "x" * 32}).status_code, 404)
                self.assertTrue(browser.get("/api/auth/state").json()["setup_available"])
            self.assertFalse((settings.config_dir / KEY_NAME).exists())


if __name__ == "__main__":
    unittest.main()
