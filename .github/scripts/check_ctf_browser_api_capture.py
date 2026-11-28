"""Check opt-in browser API observations stay bounded and same-origin."""

from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import http.server
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from playwright.sync_api import sync_playwright


SOURCE = Path(__file__).resolve().parents[2] / "deploy" / "ctf-browser-act"
LOADER = SourceFileLoader("ctf_browser_api_capture_check", str(SOURCE))
SPEC = spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
browser = module_from_spec(SPEC)
LOADER.exec_module(browser)


class Response:
    def __init__(self, body: bytes, *, content_type: str = "application/json") -> None:
        self.status = 200
        self.headers = {"content-type": content_type, "content-length": str(len(body))}
        self.body_value = body
        self.body_reads = 0
        self.url = "https://target.test/api?token=private"

    def body(self) -> bytes:
        self.body_reads += 1
        return self.body_value


class Request:
    def __init__(self, response: Response, *, url: str | None = None,
                 resource_type: str = "fetch", size: int | None = None) -> None:
        self.url = url or response.url
        self.resource_type = resource_type
        self.method = "GET"
        self._response = response
        self._size = len(response.body_value) if size is None else size

    def response(self) -> Response:
        return self._response

    def sizes(self) -> dict[str, int]:
        return {"responseBodySize": self._size}


class ApiCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.observations = {"api_json": [], "api_json_dropped_events": 0}

    def test_response_cache_metadata_excludes_credentials(self) -> None:
        response = Response(b"ok")
        response.headers.update({
            "cache-control": "public, max-age=60", "vary": "Accept-Encoding",
            "etag": 'W/"example"', "set-cookie": "secret=do-not-log",
        })
        response.request = Request(response, resource_type="xhr")
        event = browser._response_event(response)
        self.assertEqual(event["cache"], {
            "cache-control": "public, max-age=60",
            "vary": "Accept-Encoding", "etag": 'W/"example"',
        })
        self.assertNotIn("do-not-log", str(event))

    def test_wait_accepts_short_ms_field_used_by_browser_steps(self) -> None:
        class Page:
            def __init__(self) -> None:
                self.waited = None

            def wait_for_timeout(self, milliseconds: int) -> None:
                self.waited = milliseconds

        page = Page()
        browser._execute(page, {"action": "wait", "ms": 1500}, Path("."), 5000)
        self.assertEqual(page.waited, 1500)
        browser._execute(page, {"action": "wait", "milliseconds": 1200}, Path("."), 5000)
        self.assertEqual(page.waited, 1200)

    def test_playwright_driver_uses_job_temp_and_restores_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            job_temp = Path(directory) / "job" / "tmp"
            job_temp.mkdir(parents=True)
            with patch.dict(os.environ, {"TMPDIR": "/private/provider/home/tmp",
                                        "TMP": "/private/provider/home/tmp",
                                        "TEMP": "/private/provider/home/tmp"}):
                with self.assertRaisesRegex(RuntimeError, "forced"):
                    with browser._playwright_driver_temp(job_temp):
                        self.assertEqual(
                            [os.environ[key] for key in ("TMPDIR", "TMP", "TEMP")],
                            [str(job_temp)] * 3,
                        )
                        raise RuntimeError("forced")
                self.assertEqual(os.environ["TMPDIR"], "/private/provider/home/tmp")

    def record(self, request: Request, page_url: str = "https://target.test/page") -> None:
        browser._record_api_json(self.observations, request, page_url)

    def test_small_same_origin_json_is_observed_with_redacted_query(self) -> None:
        response = Response(b'{"route":"/api","count":2}')
        self.record(Request(response, url="https://target.test:443/api?token=private"))
        self.assertEqual(self.observations["api_json"], [{
            "method": "GET", "status": 200,
            "url": "https://target.test/api?token=%3Credacted%3E",
            "body": {"route": "/api", "count": 2},
        }])
        self.assertEqual(response.body_reads, 1)

    def test_cross_origin_and_non_api_requests_never_read_body(self) -> None:
        for url, page, kind in (
            ("https://other.test/api", "https://target.test/page", "fetch"),
            ("https://target.test:444/api", "https://target.test/page", "xhr"),
            ("https://target.test/api", "about:blank", "xhr"),
            ("https://target.test/api", "https://target.test/page", "document"),
        ):
            response = Response(b'{"secret":"private"}')
            self.record(Request(response, url=url, resource_type=kind), page)
            self.assertEqual(response.body_reads, 0)
        self.assertEqual(self.observations["api_json"], [])

    def test_large_non_json_and_invalid_json_are_ignored(self) -> None:
        large = Response(b'"' + b"x" * 5000 + b'"')
        self.record(Request(large))
        self.assertEqual(large.body_reads, 0)
        non_json = Response(b"hello", content_type="text/html")
        self.record(Request(non_json))
        self.assertEqual(non_json.body_reads, 0)
        invalid = Response(b"not json")
        self.record(Request(invalid))
        self.assertEqual(self.observations["api_json"], [])

    def test_bootstrap_and_recent_bodies_are_retained_within_eight(self) -> None:
        for index in range(12):
            self.record(Request(Response(f'{{"n":{index}}}'.encode())))
        self.assertEqual(len(self.observations["api_json"]), 8)
        self.assertEqual([item["body"]["n"] for item in self.observations["api_json"]],
                         [0, 1, 6, 7, 8, 9, 10, 11])
        self.assertEqual(self.observations["api_json_dropped_events"], 4)

    def test_real_chromium_fetch_is_observed_after_request_finishes(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = (b"<html><body>ready</body></html>" if self.path == "/" else
                        b'{"answer":"observed"}')
                self.send_response(200)
                self.send_header("Content-Type", (
                    "text/html" if self.path == "/" else "application/json"
                ))
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                chrome = playwright.chromium.launch(headless=True, channel="chromium")
                try:
                    page = chrome.new_page()
                    browser._attach_api_capture(page.context, self.observations)
                    page.goto(f"http://127.0.0.1:{server.server_port}/")
                    result = page.evaluate("(async()=>{const r=await fetch('/api?token=private');"
                                           "return (await r.json()).answer})()")
                    page.wait_for_timeout(100)
                    self.assertEqual(result, "observed")
                    self.assertEqual(len(self.observations["api_json"]), 1)
                    self.assertEqual(self.observations["api_json"][0]["body"],
                                     {"answer": "observed"})
                finally:
                    chrome.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_delayed_origin_a_json_survives_origin_b_popup(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class OriginA(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path.startswith("/slow?"):
                    started.set()
                    release.wait(timeout=5)
                    body, mime = b'{"answer":"origin-a"}', "application/json"
                else:
                    body, mime = b"<html><body>origin-a</body></html>", "text/html"
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        class OriginB(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = b"<html><body>origin-b</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        first = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OriginA)
        second = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OriginB)
        threads = [threading.Thread(target=server.serve_forever, daemon=True)
                   for server in (first, second)]
        for thread in threads:
            thread.start()
        try:
            with sync_playwright() as playwright:
                chrome = playwright.chromium.launch(headless=True, channel="chromium")
                try:
                    context = chrome.new_context()
                    browser._attach_api_capture(context, self.observations)
                    page = context.new_page()
                    page.goto(f"http://127.0.0.1:{first.server_port}/")
                    page.evaluate("window.pending=fetch('/slow?token=private').then(r=>r.json())")
                    self.assertTrue(started.wait(timeout=5))
                    with page.expect_popup() as popup_info:
                        page.evaluate(f"window.open('http://127.0.0.1:{second.server_port}/')")
                    popup = popup_info.value
                    popup.wait_for_load_state()
                    release.set()
                    self.assertEqual(page.evaluate("window.pending"), {"answer": "origin-a"})
                    page.wait_for_timeout(100)
                    self.assertEqual(len(self.observations["api_json"]), 1)
                    self.assertEqual(self.observations["api_json"][0]["body"],
                                     {"answer": "origin-a"})
                finally:
                    release.set()
                    chrome.close()
        finally:
            release.set()
            for server in (first, second):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
