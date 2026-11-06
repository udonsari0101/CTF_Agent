"""Offline CTFd authentication and submission contract regression checks.

Run from the repository root with:
    python .github/scripts/check_ctfd_submission_contract.py

Every remote response is supplied by FakeTransport. No DNS lookup or network
connection is made, and no real CTFd flag is submitted.
"""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from local_test_client import TestClient

from ctf_agent.ctfd import CTFdClient, CTFdError, LoginForm, Response
from ctf_agent.db import Settings
from ctf_agent.main import create_app


SITE = "https://ctfd.example.test"
LOGIN_NONCE = "login-form-nonce"
SESSION_NONCE = "session-nonce-0123456789abcdef"
FLAG = "test{offline_contract_only}"


def fake_resolver(host: str, port: int, *, type: int):
    """Resolve only the synthetic test site to a public-looking IP in memory."""

    if host != "ctfd.example.test" or port != 443 or type != socket.SOCK_STREAM:
        raise AssertionError((host, port, type))
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


class FakeTransport:
    def __init__(self, mode: str):
        if mode not in {"token", "html", "html_late", "json", "json_redirect", "json_unsupported", "sso"}:
            raise ValueError(mode)
        self.mode = mode
        self.requests: list[dict] = []

    @staticmethod
    def _json(data: object, *, status: int = 200, cookies=()) -> Response:
        return Response(
            status, {"content-type": "application/json"},
            json.dumps({"success": True, "data": data}).encode("utf-8"), cookies,
        )

    def __call__(self, target, headers, maximum, timeout, deadline, **kwargs) -> Response:
        del maximum, timeout, deadline
        method = kwargs.get("method", "GET")
        body = kwargs.get("body")
        path = urlsplit(target.url).path
        self.requests.append({"method": method, "path": path, "headers": dict(headers), "body": body})

        # The transport also verifies what a real site would need in order to
        # accept a request; an in-memory success response alone proves little.
        if self.mode == "token":
            assert headers.get("Authorization") == "Token offline-token"
            assert "Cookie" not in headers
        else:
            assert "Authorization" not in headers

        if method == "GET" and path == "/login":
            if self.mode in {"html", "html_late"}:
                content = (
                    '<form action="/login" method="post">'
                    '<input name="name"><input name="password">'
                    f'<input name="nonce" value="{LOGIN_NONCE}"></form>'
                )
            elif self.mode == "json":
                content = (
                    '<script>window.__ctfdInitialRequests='
                    '{"/api/v2/auth/check/cookie":true}</script>'
                )
            elif self.mode in {"json_redirect", "json_unsupported"}:
                return Response(307, {"location": "/auth/login"}, b"")
            elif self.mode == "sso":
                content = '<form><input name="email"><input name="password"></form>'
            else:
                raise AssertionError("Token login must not request an HTML form")
            return Response(200, {"content-type": "text/html"}, content.encode("utf-8"))

        if method == "GET" and path == "/auth/login" and self.mode in {"json_redirect", "json_unsupported"}:
            content = '<form><input name="name"><input name="password"></form>'
            return Response(200, {"content-type": "text/html"}, content.encode("utf-8"))

        if method == "GET" and path == "/api/v2/auth/check/cookie":
            assert self.mode in {"json_redirect", "json_unsupported"}
            if self.mode == "json_unsupported":
                return Response(200, {"content-type": "text/html"}, b"<h1>Not a JSON session</h1>")
            return Response(401, {"content-type": "application/json"},
                            b'{"success":false,"authenticated":false}')

        if method == "POST" and path == "/login" and self.mode in {"html", "html_late"}:
            form = parse_qs((body or b"").decode("ascii"))
            assert form == {
                "name": ["offline-user"],
                "password": ["offline-password"],
                "nonce": [LOGIN_NONCE],
            }
            assert headers.get("Origin") == f"{urlsplit(target.url).scheme}://{urlsplit(target.url).netloc}"
            return Response(
                302, {"location": "/dashboard" if self.mode == "html_late" else "/challenges"}, b"",
                ("session=html-cookie; Path=/; Secure; HttpOnly",),
            )

        if method == "GET" and path == "/dashboard" and self.mode == "html_late":
            assert headers.get("Cookie") == "session=html-cookie"
            return Response(200, {"content-type": "text/html"}, b"<h1>Signed in</h1>")

        if method == "GET" and path == "/challenges" and self.mode in {"html", "html_late"}:
            assert headers.get("Cookie") == "session=html-cookie"
            html = f'<script>window.init={{"csrfNonce":"{SESSION_NONCE}"}}</script>'
            return Response(200, {"content-type": "text/html"}, html.encode("utf-8"))

        if method == "GET" and path == "/challenges" and self.mode in {"json", "json_redirect"}:
            assert headers.get("Cookie") == "session=json-cookie"
            return Response(200, {"content-type": "text/html"}, b"<h1>Challenges</h1>")

        if method == "POST" and path in {"/api/v2/auth/login/prepare", "/api/v2/auth/login"}:
            assert self.mode in {"json", "json_redirect"}
            assert json.loads(body) == {"name": "offline-user", "password": "offline-password"}
            assert headers.get("Content-Type") == "application/json"
            cookies = ("session=json-cookie; Path=/; Secure; HttpOnly",) if path.endswith("/login") else ()
            return self._json({"needs_consent": False} if path.endswith("/prepare") else {}, cookies=cookies)

        if method == "GET" and path == "/api/v1/users/me":
            if self.mode in {"html", "html_late"}:
                assert headers.get("Cookie") == "session=html-cookie"
            if self.mode in {"json", "json_redirect"}:
                assert headers.get("Cookie") == "session=json-cookie"
            return self._json({"id": 7, "name": "offline-user"})

        if method == "GET" and path == "/api/v1/challenges":
            # A JSON-session site can permit imports even when its login page
            # does not expose the CSRF nonce needed for CTFd's attempt API.
            return self._json([])

        if method == "POST" and path == "/api/v1/challenges/attempt":
            assert self.mode != "json", "Import-only JSON login must not submit"
            assert json.loads(body) == {"challenge_id": 17, "submission": FLAG}
            assert headers.get("Content-Type") == "application/json"
            if self.mode in {"html", "html_late"}:
                assert headers.get("Cookie") == "session=html-cookie"
                assert headers.get("CSRF-Token") == SESSION_NONCE
                assert headers["CSRF-Token"] != LOGIN_NONCE
            else:
                assert "CSRF-Token" not in headers
            return self._json({"status": "correct", "message": "Accepted"})

        raise AssertionError(f"Unexpected remote request: {method} {path}")


def client_for(mode: str) -> tuple[CTFdClient, FakeTransport]:
    transport = FakeTransport(mode)
    auth = {"token": {"auth_type": "token", "token": "offline-token"},
            "html": {"auth_type": "password", "username": "offline-user",
                     "password": "offline-password"},
            "html_late": {"auth_type": "password", "username": "offline-user",
                          "password": "offline-password"},
            "json": {"auth_type": "password", "username": "offline-user",
                     "password": "offline-password"},
            "json_redirect": {"auth_type": "password", "username": "offline-user",
                              "password": "offline-password"},
            "json_unsupported": {"auth_type": "password", "username": "offline-user",
                                 "password": "offline-password"},
            "sso": {"auth_type": "password", "username": "offline-user",
                    "password": "offline-password"}}[mode]
    return CTFdClient(SITE, resolver=fake_resolver, transport=transport, **auth), transport


class CTFdClientContract(unittest.TestCase):
    def test_token_connection_is_ready_and_submits_without_csrf(self):
        client, transport = client_for("token")
        client.validate()
        ready, reason = client.submission_readiness()
        self.assertIs(ready, True)
        self.assertIsInstance(reason, str)
        self.assertEqual(client.submit(17, FLAG)["status"], "correct")
        paths = [r["path"] for r in transport.requests]
        self.assertNotIn("/login", paths)
        self.assertIn("/api/v1/users/me", paths)
        self.assertIn("/api/v1/challenges", paths)
        self.assertEqual(paths.count("/api/v1/challenges/attempt"), 1)

    def test_html_password_uses_rotated_session_nonce_and_cookie(self):
        client, transport = client_for("html")
        client.validate()
        ready, reason = client.submission_readiness()
        self.assertIs(ready, True)
        self.assertIsInstance(reason, str)
        self.assertEqual(client.submit(17, FLAG)["status"], "correct")
        paths = [r["path"] for r in transport.requests]
        self.assertEqual(paths.count("/login"), 2)
        self.assertIn("/challenges", paths)
        self.assertIn("/api/v1/users/me", paths)
        self.assertIn("/api/v1/challenges", paths)
        self.assertEqual(paths.count("/api/v1/challenges/attempt"), 1)

    def test_json_password_is_import_only_without_session_nonce(self):
        client, transport = client_for("json")
        client.validate()
        self.assertEqual(client.preview()["challenges"], [])
        ready, reason = client.submission_readiness()
        self.assertIs(ready, False)
        self.assertIsInstance(reason, str)
        self.assertTrue(reason)
        with self.assertRaises(CTFdError):
            client.submit(17, FLAG)
        self.assertNotIn("/api/v1/challenges/attempt", [r["path"] for r in transport.requests])

    def test_redirected_js_login_uses_verified_same_origin_session_api(self):
        client, transport = client_for("json_redirect")
        client.validate()
        self.assertEqual(client.preview()["challenges"], [])
        paths = [(r["method"], r["path"]) for r in transport.requests]
        self.assertLess(paths.index(("GET", "/api/v2/auth/check/cookie")),
                        paths.index(("POST", "/api/v2/auth/login/prepare")))
        self.assertLess(paths.index(("POST", "/api/v2/auth/login/prepare")),
                        paths.index(("POST", "/api/v2/auth/login")))

    def test_unverified_login_pages_never_receive_credentials(self):
        for mode in ("json_unsupported", "sso"):
            with self.subTest(mode=mode):
                client, transport = client_for(mode)
                with self.assertRaises(CTFdError):
                    client.validate()
                self.assertFalse(any(r["method"] == "POST" for r in transport.requests))

    def test_json_login_form_rejects_external_action_or_unrelated_page(self):
        client, _ = client_for("json_redirect")
        parser = LoginForm()
        parser.feed('<form action="https://id.example.test/login">'
                    '<input name="name"><input name="password"></form>')
        self.assertFalse(client._has_json_login_form(parser, SITE + "/auth/login"))
        parser = LoginForm()
        parser.feed('<form><input name="name"><input name="password"></form>')
        self.assertFalse(client._has_json_login_form(parser, SITE + "/unrelated"))

    def test_html_password_fetches_rotated_nonce_after_nonce_free_landing(self):
        client, transport = client_for("html_late")
        client.validate()
        self.assertEqual(client.csrf_nonce, "")
        self.assertNotIn("/challenges", [r["path"] for r in transport.requests])
        ready, reason = client.submission_readiness()
        self.assertIs(ready, True)
        self.assertIsInstance(reason, str)
        self.assertEqual(client.csrf_nonce, SESSION_NONCE)
        self.assertIn("/challenges", [r["path"] for r in transport.requests])
        self.assertEqual(client.submit(17, FLAG)["status"], "correct")


class ConnectionReadinessContract(unittest.TestCase):
    @staticmethod
    def _browser():
        root = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        directory = Path(root.name)
        settings = Settings(
            directory / "data", directory / "db", directory / "config",
            directory / "logs", storage_min_free_bytes=0,
            auth_mode="nologin",
        )
        app = create_app(settings)

        def factory(**kwargs):
            mode = (
                "token" if kwargs["auth_type"] == "token" else
                kwargs["url"].split("//", 1)[1].split(".", 1)[0]
            )
            return CTFdClient(
                **kwargs,
                resolver=lambda _host, port, *, type: [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
                ],
                transport=FakeTransport(mode),
            )

        app.state.ctfd_client_factory = factory
        return root, TestClient(app)

    def test_replaced_saved_connection_rejects_older_preview(self):
        temporary, browser = self._browser()
        try:
            with browser:
                csrf = browser.get("/api/auth/state").json()["csrf_token"]
                browser.headers.update({"x-csrf-token": csrf})
                workspace = browser.post("/api/workspaces", json={"name": "stale preview"})
                self.assertEqual(workspace.status_code, 201, workspace.text)
                base = f'/api/workspaces/{workspace.json()["id"]}/ctfd'
                saved_body = {
                    "url": "https://token.example.test", "auth_type": "token",
                    "token": "offline-token",
                }
                saved = browser.put(base + "/connection", json=saved_body)
                self.assertEqual(saved.status_code, 200, saved.text)
                preview = browser.post(base + "/preview", json={"use_saved_connection": True})
                self.assertEqual(preview.status_code, 200, preview.text)
                self.assertNotIn("offline-token", preview.text)
                self.assertNotIn("connection_generation", preview.text)

                # Even a credential re-save to the same site creates a new
                # generation; an older preview must not import with it.
                replaced = browser.put(base + "/connection", json=saved_body)
                self.assertEqual(replaced.status_code, 200, replaced.text)
                stale = browser.post(
                    base + "/import", json={"preview_id": preview.json()["preview_id"]},
                )
                self.assertEqual(stale.status_code, 422, stale.text)
                self.assertIn("Preview again", stale.text)
                self.assertNotIn("offline-token", stale.text)
                self.assertEqual(browser.get(base + "/jobs").json()["jobs"], [])
        finally:
            temporary.cleanup()

    def test_one_time_connection_does_not_replace_saved_credentials(self):
        temporary, browser = self._browser()
        try:
            with browser:
                csrf = browser.get("/api/auth/state").json()["csrf_token"]
                browser.headers.update({"x-csrf-token": csrf})
                workspace = browser.post("/api/workspaces", json={"name": "one-time preview"})
                self.assertEqual(workspace.status_code, 201, workspace.text)
                base = f'/api/workspaces/{workspace.json()["id"]}/ctfd'
                saved = browser.put(base + "/connection", json={
                    "url": "https://token.example.test", "auth_type": "token",
                    "token": "offline-token",
                })
                self.assertEqual(saved.status_code, 200, saved.text)
                original = browser.get(base + "/connection").json()
                one_time = browser.post(base + "/preview", json={
                    "url": "https://html.example.test", "auth_type": "password",
                    "username": "offline-user", "password": "offline-password",
                })
                self.assertEqual(one_time.status_code, 200, one_time.text)
                self.assertEqual(one_time.json()["source_url"], "https://html.example.test")
                self.assertNotIn("offline-password", one_time.text)
                self.assertNotIn("offline-token", one_time.text)
                self.assertEqual(browser.get(base + "/connection").json(), original)
                imported = browser.post(
                    base + "/import", json={"preview_id": one_time.json()["preview_id"]},
                )
                self.assertEqual(imported.status_code, 202, imported.text)
                self.assertNotIn("offline-password", imported.text)
                self.assertNotIn("offline-token", imported.text)
                self.assertEqual(browser.get(base + "/connection").json(), original)

                # A fresh borrowed preview exercises the original token,
                # proving that one-time credentials were not persisted.
                borrowed = browser.post(base + "/preview", json={"use_saved_connection": True})
                self.assertEqual(borrowed.status_code, 200, borrowed.text)
                self.assertEqual(borrowed.json()["source_url"], original["url"])
                self.assertNotIn("offline-token", borrowed.text)
        finally:
            temporary.cleanup()

    def test_saved_connections_expose_readiness_and_gate_auto_submit(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            settings = Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            )
            app = create_app(settings)
            transports: list[FakeTransport] = []

            def factory(**kwargs):
                mode = "token" if kwargs["auth_type"] == "token" else kwargs["url"].split("//", 1)[1].split(".", 1)[0]
                transport = FakeTransport(mode)
                transports.append(transport)
                return CTFdClient(
                    **kwargs, resolver=lambda _host, port, *, type: [
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
                    ], transport=transport,
                )

            app.state.ctfd_client_factory = factory
            with TestClient(app) as browser:
                csrf = browser.get("/api/auth/state").json()["csrf_token"]
                browser.headers.update({"x-csrf-token": csrf})
                for mode in ("token", "html", "json"):
                    workspace = browser.post("/api/workspaces", json={"name": mode})
                    self.assertEqual(workspace.status_code, 201, workspace.text)
                    base = f'/api/workspaces/{workspace.json()["id"]}/ctfd'
                    credentials = (
                        {"auth_type": "token", "token": "offline-token"}
                        if mode == "token" else
                        {"auth_type": "password", "username": "offline-user",
                         "password": "offline-password"}
                    )
                    saved = browser.put(
                        base + "/connection",
                        json={"url": f"https://{mode}.example.test", **credentials},
                    )
                    self.assertEqual(saved.status_code, 200, saved.text)
                    data = saved.json()
                    self.assertEqual(data["submit_ready"], mode != "json")
                    self.assertIsInstance(data["submit_check_reason"], str)
                    if mode == "json":
                        self.assertTrue(data["submit_check_reason"])
                    self.assertNotIn("offline-token", saved.text)
                    self.assertNotIn("offline-password", saved.text)
                    current = browser.get(base + "/connection")
                    self.assertEqual(current.status_code, 200, current.text)
                    self.assertEqual(current.json()["submit_ready"], mode != "json")
                    if mode == "json":
                        preview = browser.post(
                            base + "/preview", json={"use_saved_connection": True},
                        )
                        self.assertEqual(preview.status_code, 200, preview.text)
                        self.assertEqual(preview.json()["source_url"], f"https://{mode}.example.test")
                    enabled = browser.put(base + "/settings", json={"auto_submit": True})
                    if mode == "json":
                        self.assertEqual(enabled.status_code, 409, enabled.text)
                        self.assertFalse(browser.get(base + "/connection").json()["auto_submit"])
                    else:
                        self.assertEqual(enabled.status_code, 200, enabled.text)
                        self.assertTrue(enabled.json()["auto_submit"])
                self.assertTrue(transports)
                for transport in transports:
                    self.assertNotIn(
                        "/api/v1/challenges/attempt",
                        [request["path"] for request in transport.requests],
                        "Connection readiness must never submit a flag",
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
