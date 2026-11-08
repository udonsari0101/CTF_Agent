"""Smoke the post-contest admin controls in a real browser and local app."""

from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import socket
import shutil
import sys
import time

from playwright.sync_api import sync_playwright
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ctf_agent.db import Settings
from ctf_agent.main import create_app


def main() -> None:
    browser_name = (shutil.which("google-chrome") or shutil.which("chromium") or
                    shutil.which("chrome") or shutil.which("msedge"))
    browser_path = Path(browser_name) if browser_name else Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    with TemporaryDirectory(ignore_cleanup_errors=True) as temp:
        root = Path(temp)
        app = create_app(Settings(root / "data", root / "db", root / "config", root / "logs",
                                  storage_min_free_bytes=0, auth_mode="nologin", local_access="open"))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        worker = Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        worker.start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.1)
        assert server.started, "local test server did not start"
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path=str(browser_path) if browser_path.is_file() else None,
                    headless=True,
                )
                try:
                    for locale, width in (("ko", 390), ("en", 1440)):
                        page = browser.new_page(viewport={"width": width, "height": 844}, accept_downloads=True)
                        page.add_init_script(f"localStorage.setItem('ctf-language', '{locale}')")
                        errors = []
                        page.on("pageerror", lambda error: errors.append(str(error)))
                        page.goto(f"http://127.0.0.1:{port}/#admin", wait_until="domcontentloaded")
                        button = page.locator('[data-action="open-admin-log-export"]')
                        try:
                            button.wait_for(timeout=20000)
                        except Exception:
                            raise AssertionError(f"screen={page.locator('body').inner_text()[:800]!r}; errors={errors!r}")
                        assert "${tr(" not in page.locator("#app").inner_text()
                        button.click()
                        form = page.locator("#admin-log-export-form")
                        form.wait_for()
                        form.locator('button[type="submit"]').click()
                        try:
                            page.locator('[data-action="download-admin-logs"]:not([disabled])').wait_for(timeout=10000)
                        except Exception:
                            raise AssertionError(f"modal={form.inner_text()[:800]!r}; errors={errors!r}")
                        with page.expect_download() as download_info:
                            page.locator('[data-action="download-admin-logs"]').click()
                        assert download_info.value.suggested_filename.endswith(".zip")
                        page.goto(f"http://127.0.0.1:{port}/#settings", wait_until="domcontentloaded")
                        preferences = page.locator('#solver-preferences-form')
                        preferences.wait_for(timeout=20000)
                        preferences.locator('[name="ultra_escalation_default"]').select_option('auto')
                        with page.expect_response(lambda response: response.url.endswith('/api/auth/preferences')) as saved:
                            preferences.locator('button[type="submit"],button.primary').click()
                        assert saved.value.status == 200, saved.value.text()
                        before_avatar = page.locator('#profile-avatar-preview').inner_html()
                        with page.expect_response(lambda response: response.url.endswith('/api/auth/avatar/refresh')) as rotated:
                            page.locator('[data-action="refresh-profile-avatar"]').click()
                        assert rotated.value.status == 200, rotated.value.text()
                        assert page.locator('#profile-avatar-preview').inner_html() != before_avatar
                        assert page.request.get(f"http://127.0.0.1:{port}/api/auth/state").json()['user']['ultra_escalation_default'] == 'auto'
                        assert not errors, errors
                        page.close()
                finally:
                    browser.close()
        finally:
            server.should_exit = True
            worker.join(timeout=10)
            sock.close()
    print("PASS: diagnostic ZIP, Ultra default and avatar controls in Korean/mobile and English/desktop Chrome")


if __name__ == "__main__":
    main()
