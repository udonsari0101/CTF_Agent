"""Offline checks for optional job-local Chromium profile persistence."""

from __future__ import annotations

import contextlib
import http.server
import importlib.machinery
import importlib.util
import io
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deploy" / "ctf-browser"
LOADER = importlib.machinery.SourceFileLoader("ctf_browser_session_check", str(SOURCE))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
browser = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(browser)


class BrowserSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name) / "solver-scratch"
        self.scratch.mkdir()
        self.workdir = self._job("ctf-job-abcdef")

    def _job(self, name: str) -> Path:
        workdir = self.scratch / name / "competition" / "challenge" / "codex-workdir"
        workdir.mkdir(parents=True)
        return workdir

    def test_session_option_is_wrapper_only_and_validated(self) -> None:
        self.assertEqual(
            browser.parse_options(["--session", "login_1", "--dump-dom", "https://example.invalid"]),
            (["--dump-dom", "https://example.invalid"], "login_1"),
        )
        self.assertEqual(browser.parse_options(["--session=a-1", "--dump-dom"]),
                         (["--dump-dom"], "a-1"))
        self.assertEqual(browser.parse_options(["--dump-dom"]), (["--dump-dom"], None))
        for arguments in (
            ["--session"], ["--session="], ["--session", "../escape"],
            ["--session", "a/b"], ["--session", "-bad"],
            ["--session", "a" * 49], ["--session", "one", "--session=two"],
            ["--session", "one", "--user-data-dir=/tmp/escape"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                browser.parse_options(arguments)

    def test_profile_reuse_and_job_isolation(self) -> None:
        self.assertEqual(browser.job_workdir(self.workdir, self.scratch), self.workdir)
        first = browser._persistent_runtime(self.workdir, "login")
        (first / "profile" / "cookie-marker").write_text("saved", encoding="ascii")
        self.assertEqual(browser._persistent_runtime(self.workdir, "login"), first)
        self.assertEqual((first / "profile" / "cookie-marker").read_text(encoding="ascii"), "saved")
        second = browser._persistent_runtime(self.workdir, "other")
        another_job = browser._persistent_runtime(self._job("ctf-job-ghijkl"), "login")
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, another_job)
        self.assertFalse((second / "profile" / "cookie-marker").exists())
        self.assertFalse((another_job / "profile" / "cookie-marker").exists())

    def test_unsafe_existing_session_path_is_rejected(self) -> None:
        sessions = self.workdir.parents[2] / ".b"
        sessions.mkdir()
        (sessions / browser._session_key("file")).write_text("unsafe", encoding="ascii")
        with self.assertRaises(ValueError):
            browser._persistent_runtime(self.workdir, "file")
        if os.name == "posix":
            outside = Path(self.temporary.name) / "outside"
            outside.mkdir()
            (sessions / browser._session_key("link")).symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                browser._persistent_runtime(self.workdir, "link")

    def test_default_cleans_only_its_profile_while_named_profile_survives(self) -> None:
        commands: list[list[str]] = []
        seen_markers: list[bool] = []

        class FakeProcess:
            def __init__(self, command, **_kwargs):
                commands.append(command)
                profile = Path(next(value.split("=", 1)[1] for value in command
                                    if value.startswith("--user-data-dir=")))
                seen_markers.append((profile / "marker").exists())
                (profile / "marker").write_text("saved", encoding="ascii")
                self.pid = 1

            def wait(self):
                return 0

            def poll(self):
                return 0

        with (
            patch.object(browser, "job_workdir", return_value=self.workdir),
            patch.object(browser.subprocess, "Popen", FakeProcess),
        ):
            self.assertEqual(browser.run(["--dump-dom", "https://example.invalid"]), 0)
            self.assertEqual(browser.run(["--session", "login", "--dump-dom", "https://example.invalid"]), 0)
            self.assertEqual(browser.run(["--session=login", "--dump-dom", "https://example.invalid"]), 0)
        profiles = [Path(next(value.split("=", 1)[1] for value in command
                              if value.startswith("--user-data-dir="))) for command in commands]
        self.assertFalse(profiles[0].exists())
        self.assertEqual(profiles[1], profiles[2])
        self.assertEqual(seen_markers, [False, False, True])
        self.assertTrue((profiles[1] / "marker").exists())
        self.assertTrue((self.workdir.parents[2] / ".b" / browser._session_key("login")).exists())

    @unittest.skipUnless(os.name == "posix", "flock is specific to the Linux worker")
    def test_same_session_is_locked_without_deleting_active_state(self) -> None:
        runtime = browser._persistent_runtime(self.workdir, "login")
        marker = runtime / "profile" / "marker"
        marker.write_text("saved", encoding="ascii")
        lock = browser._lock_session(runtime)
        self.assertIsInstance(lock, int)
        try:
            with self.assertRaisesRegex(ValueError, "already in use"):
                browser._lock_session(runtime)
            with (
                patch.object(browser, "job_workdir", return_value=self.workdir),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(browser.run(["--session", "login", "--dump-dom"]), 2)
            self.assertIn("already in use", stderr.getvalue())
            self.assertEqual(marker.read_text(encoding="ascii"), "saved")
        finally:
            os.close(lock)
        second = browser._lock_session(runtime)
        self.assertIsInstance(second, int)
        os.close(second)

    @unittest.skipUnless(
        os.environ.get("CTF_BROWSER_LIVE_TEST") == "1"
        and os.name == "posix"
        and Path(browser.CHROMIUM).is_file(),
        "requires explicit Chromium integration test in the toolchain image",
    )
    def test_chromium_cookie_persists_only_in_named_session(self) -> None:
        received: list[bool] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/test":
                    self.send_error(404)
                    return
                had_cookie = "ctf_browser_test=1" in self.headers.get("Cookie", "")
                received.append(had_cookie)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", "ctf_browser_test=1; Max-Age=3600; Path=/; SameSite=Lax")
                self.end_headers()
                self.wfile.write(b"<!doctype html><title>Browser session check</title>")

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/test"
            with tempfile.TemporaryDirectory(prefix="b", dir="/tmp") as short_root:
                workdir = Path(short_root) / "s" / "ctf-job-abcdef" / "competition" / "challenge" / "codex-workdir"
                workdir.mkdir(parents=True)
                with patch.object(browser, "job_workdir", return_value=workdir):
                    for arguments, expected in (
                        (["--session=login", "--dump-dom", url], False),
                        (["--session=login", "--dump-dom", url], True),
                        (["--dump-dom", url], False),
                    ):
                        start = len(received)
                        self.assertEqual(browser.run(arguments), 0)
                        self.assertGreater(len(received), start)
                        self.assertEqual(received[start], expected)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
