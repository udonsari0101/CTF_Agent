"""Public local-install access and bootstrap regression checks (no Docker)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings, allowed_origin
from ctf_agent.main import create_app


def local_compose_module():
    spec = importlib.util.spec_from_file_location(
        "ctf_local_compose_public_test", ROOT / "deploy" / "local-compose.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LocalPublicAccessTest(unittest.TestCase):
    def settings(self, root: Path, *, mode="nologin", access="link",
                 origins=(), setup_token="") -> Settings:
        return Settings(
            root / "data", root / "db", root / "config", root / "logs",
            public_origin="https://ctf.example.test" if origins else "",
            allowed_origins=origins, storage_min_free_bytes=0,
            auth_mode=mode, allow_web_bootstrap=True, local_access=access,
            first_admin_setup_token=setup_token,
        )

    def test_open_access_is_explicit_and_keeps_origin_csrf_checks(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            settings = self.settings(root, access="open", origins=("https://ctf.example.test",))
            with TestClient(create_app(settings), base_url="http://127.0.0.1:5050") as browser:
                state = browser.get("/api/auth/state").json()
                self.assertTrue(state["authenticated"])
                self.assertTrue(state["csrf_token"])
                self.assertEqual(browser.get("/api/workspaces").status_code, 200)
                endpoint = "/api/workspaces"
                body = {"name": "Public local test"}
                self.assertEqual(browser.post(endpoint, json=body).status_code, 403)
                headers = {"origin": "https://ctf.example.test",
                           "x-csrf-token": state["csrf_token"]}
                self.assertEqual(browser.post(endpoint, json=body, headers=headers).status_code, 201)
                self.assertEqual(browser.post(endpoint, json=body,
                                              headers={**headers, "origin": "https://other.test"}).status_code, 403)
                self.assertEqual(browser.post(endpoint, json=body,
                                              headers={**headers, "sec-fetch-site": "cross-site"}).status_code, 403)
                self.assertEqual(browser.post(endpoint, json=body,
                                              headers={"origin": "https://ctf.example.test"}).status_code, 403)
            with TestClient(create_app(self.settings(root)), base_url="http://127.0.0.1:5050") as browser:
                self.assertFalse(browser.get("/api/auth/state").json()["authenticated"])

    def test_public_first_admin_requires_token_and_https_cookie(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            with self.assertRaises(RuntimeError):
                create_app(self.settings(root, mode="password",
                                         origins=("https://ctf.example.test",)))
            token = "s" * 48
            settings = self.settings(root, mode="password",
                                     origins=("https://ctf.example.test",), setup_token=token)
            with TestClient(create_app(settings), base_url="http://internal:5050") as browser:
                state = browser.get("/api/auth/state").json()
                self.assertTrue(state["setup_available"])
                self.assertTrue(state["setup_token_required"])
                body = {"username": "owner", "password": "pass1234"}
                headers = {"origin": "https://ctf.example.test"}
                self.assertEqual(browser.post("/api/auth/setup", json=body,
                                              headers=headers).status_code, 403)
                self.assertEqual(browser.post("/api/auth/setup", json={**body, "setup_token": token},
                                              headers={"origin": "https://evil.test"}).status_code, 403)
                response = browser.post("/api/auth/setup", json={**body, "setup_token": token},
                                        headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertIn("Secure", response.headers["set-cookie"])
                self.assertIn("SameSite=strict", response.headers["set-cookie"])
                self.assertFalse(browser.get("/api/auth/state").json()["setup_available"])
            # The setup token is one-time. Removing it after administrator
            # creation must not prevent later service restarts.
            configured = self.settings(root, mode="password",
                                       origins=("https://ctf.example.test",))
            with TestClient(create_app(configured), base_url="http://127.0.0.1:5050") as local:
                response = local.post("/api/auth/login",
                                      json={"username": "owner", "password": "pass1234"},
                                      headers={"origin": "http://127.0.0.1:5050"})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertNotIn("Secure", response.headers["set-cookie"])

    def test_installed_config_applies_to_all_compose_calls(self):
        compose = local_compose_module()
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            home = Path(temporary)
            config = {
                "auth_mode": "password", "auto_start": False,
                "listen_address": "0.0.0.0", "access_mode": "link",
                "public_urls": ["http://192.0.2.10:5050", "https://ctf.example.test"],
                "first_admin_setup_token": "t" * 48,
            }
            (home / ".local-config.json").write_text(json.dumps(config), encoding="utf-8")
            environment = {"CTF_LOCAL_HOME": str(home), "CTF_LOCAL_PORT": "5050"}
            compose.apply_local_config(environment)
            self.assertEqual(environment["CTF_LOCAL_BIND"], "0.0.0.0")
            self.assertEqual(environment["CTF_LOCAL_ORIGIN"], "https://ctf.example.test")
            self.assertEqual(environment["CTF_ALLOWED_ORIGINS"],
                             "http://192.0.2.10:5050,https://ctf.example.test")
            self.assertEqual(environment["CTF_REQUIRE_FIRST_ADMIN_TOKEN"], "true")
            self.assertEqual(environment["CTF_FIRST_ADMIN_SETUP_TOKEN"], "t" * 48)
            self.assertEqual(environment["CTF_AUTH_MODE"], "password")
            self.assertEqual(environment["CTF_LOCAL_RESTART_POLICY"], "no")
            compose.apply_local_config(environment)
            self.assertEqual(environment["CTF_ALLOWED_ORIGINS"],
                             "http://192.0.2.10:5050,https://ctf.example.test")

            # During a reinstall, Compose runs before the new config is
            # committed. Its containers must receive the candidate settings,
            # while an ordinary restart still uses the installed settings.
            candidate = {
                **environment,
                "CTF_AUTH_MODE": "nologin",
                "CTF_LOCAL_BIND": "0.0.0.0",
                "CTF_LOCAL_PUBLIC_URLS": "",
                "CTF_LOCAL_ACCESS": "open",
                "CTF_LOCAL_AUTOSTART": "false",
                "CTF_FIRST_ADMIN_SETUP_TOKEN": "",
            }
            compose.apply_local_config(candidate, installer_override=True)
            self.assertEqual(candidate["CTF_AUTH_MODE"], "nologin")
            self.assertEqual(candidate["CTF_LOCAL_ACCESS"], "open")
            self.assertEqual(candidate["CTF_LOCAL_ORIGIN"], "")
            self.assertEqual(candidate["CTF_ALLOWED_ORIGINS"], "")
            self.assertNotIn("CTF_FIRST_ADMIN_SETUP_TOKEN", candidate)
            compose.apply_local_config(candidate)
            self.assertEqual(candidate["CTF_AUTH_MODE"], "password")
            self.assertEqual(candidate["CTF_LOCAL_ACCESS"], "link")
            with self.assertRaises(RuntimeError):
                compose.apply_local_config({"CTF_LOCAL_HOME": str(home)}, installer_override=True)

            config["access_mode"] = "open"
            (home / ".local-config.json").write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                compose.apply_local_config(environment)

            config.update(auth_mode="nologin", public_urls=[], access_mode="open")
            (home / ".local-config.json").write_text(json.dumps(config), encoding="utf-8")
            compose.apply_local_config(environment)
            self.assertEqual(environment["CTF_LOCAL_ORIGIN"], "")
            self.assertEqual(environment["CTF_ALLOWED_ORIGINS"], "")
            self.assertEqual(environment["CTF_LOCAL_ACCESS"], "open")

    def test_origin_parser_rejects_urls_that_are_not_origins(self):
        self.assertEqual(allowed_origin(" https://ctf.example.test/ "),
                         "https://ctf.example.test")
        for value in ("https://ctf.example.test/path", "https://user@ctf.example.test",
                      "https://ctf.example.test?x=1", "https://ctf.example.test:bad",
                      "file:///tmp/foo"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                allowed_origin(value)


if __name__ == "__main__":
    unittest.main()
