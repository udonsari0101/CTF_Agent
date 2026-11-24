"""Check that a browser call can inspect a popup and return to its opener."""

from __future__ import annotations

from argparse import Namespace
import contextlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from playwright.sync_api import sync_playwright


SOURCE = Path(__file__).resolve().parents[2] / "deploy" / "ctf-browser-act"
LOADER = SourceFileLoader("ctf_browser_tabs_check", str(SOURCE))
SPEC = spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
browser = module_from_spec(SPEC)
LOADER.exec_module(browser)


class BrowserTabTests(unittest.TestCase):
    def test_action_runner_switches_popup_and_opener(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_root = Path(temporary) / "ctf-job-test"
            workdir = job_root / "competition" / "challenge" / "codex-workdir"
            workdir.mkdir(parents=True)
            scratch = job_root / "tmp"
            scratch.mkdir()
            page = scratch / "opener.html"
            page.write_text(
                "<title>opener</title><button id=open>Open</button><script>"
                "document.querySelector('#open').onclick=()=>{"
                "const popup=window.open('about:blank');"
                "popup.document.write('<title>popup</title><p id=popup>popup</p>');"
                "}</script>", encoding="utf-8",
            )
            steps = scratch / "steps.json"
            steps.write_text(json.dumps([
                {"action": "click", "selector": "#open"},
                {"action": "wait_for", "selector": "#popup"},
                {"action": "list_pages"},
                {"action": "evaluate", "expression": "document.title"},
                {"action": "switch_page", "index": 0},
                {"action": "evaluate", "expression": "document.title"},
                {"action": "switch_page", "index": 1},
                {"action": "evaluate", "expression": "document.title"},
            ]), encoding="utf-8")
            with sync_playwright() as playwright:
                executable = playwright.chromium.executable_path
            guard = SimpleNamespace(
                job_workdir=lambda _cwd: workdir,
                _make_runtime=lambda _workdir: scratch / "runtime",
                _ensure_private_directory=lambda path: path.mkdir(parents=True, exist_ok=True),
                browser_environment=lambda _runtime: os.environ.copy(),
                CHROMIUM=executable,
            )
            output = io.StringIO()
            arguments = Namespace(url=page.as_uri(), session=None, steps=str(steps),
                                  output=None, html=None, screenshot=None,
                                  timeout=5000, capture_api_json=False)
            with patch.object(browser, "_load_browser_guard", return_value=guard):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(browser._run_browser(arguments), 0)
            result = json.loads(output.getvalue())
            self.assertEqual([item["active"] for item in result["actions"][3]["result"]],
                             [False, True])
            self.assertEqual([item["result"] for item in result["actions"]
                              if item["action"] == "evaluate"],
                             ["popup", "opener", "popup"])
            self.assertEqual(result["title"], "popup")

    def test_popup_can_be_selected_both_ways_in_one_call(self) -> None:
        with sync_playwright() as playwright:
            chromium = playwright.chromium.launch(headless=True, channel="chromium")
            try:
                context = chromium.new_context()
                opener = context.new_page()
                opener.goto("data:text/html,<title>opener</title><button id='open'>Open</button>")
                opener.locator("#open").evaluate(
                    "button => button.onclick = () => {"
                    "const popup = window.open('about:blank');"
                    "popup.document.write('<title>popup</title><p id=popup>popup</p>');"
                    "}"
                )
                active = [opener]
                context.on("page", lambda page: active.__setitem__(0, page))
                browser._execute(opener, {"action": "click", "selector": "#open"},
                                 Path.cwd(), 5000)
                browser._execute(active[0], {"action": "wait_for", "selector": "#popup"},
                                 Path.cwd(), 5000)
                pages = browser._page_inventory(context, active)
                self.assertEqual([item["index"] for item in pages], [0, 1])
                self.assertEqual([item["active"] for item in pages], [False, True])
                self.assertEqual(browser._select_page(context, active, {"index": 0})["index"], 0)
                self.assertEqual(active[0].title(), "opener")
                self.assertEqual(browser._select_page(context, active, {"index": 1})["index"], 1)
                self.assertEqual(active[0].title(), "popup")
                self.assertEqual(browser._select_page(context, active, {"index": 0})["index"], 0)
                context.pages[1].close()
                self.assertEqual(len(browser._page_inventory(context, active)), 1)
            finally:
                chromium.close()

    def test_invalid_page_indices_are_rejected(self) -> None:
        class Page:
            url = "https://example.test/?token=private"

            def is_closed(self) -> bool:
                return False

        class Context:
            pages = [Page()]

        context = Context()
        active = [context.pages[0]]
        for index in (None, False, -1, 1, "0"):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "list_pages"):
                browser._select_page(context, active, {"index": index})
        self.assertEqual(browser._page_inventory(context, active), [
            {"index": 0, "url": "https://example.test/?token=%3Credacted%3E", "active": True},
        ])


if __name__ == "__main__":
    unittest.main()
