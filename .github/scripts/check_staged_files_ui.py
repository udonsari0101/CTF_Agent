"""Browser regression for workspace pre-upload and challenge attachment."""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.local_access import KEY_NAME
from ctf_agent.main import create_app


def chrome_path():
    candidates = [
        os.environ.get("CTF_CHROME_PATH"), shutil.which("google-chrome"),
        shutil.which("chromium"), shutil.which("chrome"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    return next((path for path in candidates if path and Path(path).is_file()), None)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
        root = Path(temporary)
        settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        app = create_app(settings)
        with TestClient(app) as client:
            client.headers.update({
                "x-csrf-token": client.get("/api/auth/state").json()["csrf_token"],
            })
            created = client.post("/api/workspaces", json={"name": "Staged test"})
            assert created.status_code == 201, created.text
            workspace_id = created.json()["id"]

        port = free_port()
        server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error", access_log=False,
        ))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "test server did not start"
        try:
            with sync_playwright() as playwright:
                launch = {"headless": True}
                installed_chrome = chrome_path()
                if installed_chrome:
                    launch["executable_path"] = installed_chrome
                browser = playwright.chromium.launch(**launch)
                try:
                    origin = f"http://127.0.0.1:{port}"

                    def bootstrap(context):
                        token = (settings.config_dir / KEY_NAME).read_text(encoding="ascii").strip()
                        ticket = context.request.post(
                            origin + "/api/auth/local/ticket", data={"token": token},
                        )
                        assert ticket.ok, ticket.text()
                        response = context.request.post(
                            origin + "/api/auth/local/bootstrap",
                            data={"ticket": ticket.json()["ticket"]},
                        )
                        assert response.ok, response.text()

                    context = browser.new_context(locale="ko-KR")
                    bootstrap(context)
                    page = context.new_page()
                    page.goto(f"{origin}/#w/{workspace_id}")
                    page.locator('[data-action="show-staged-files"]').wait_for()
                    page.locator('[data-action="show-staged-files"]').click()
                    page.locator("#staged-files-input").set_input_files({
                        "name": "first.bin", "mimeType": "application/octet-stream",
                        "buffer": b"one",
                    })
                    page.get_by_text("first.bin", exact=True).wait_for()
                    page.locator('#staged-files-list a[download]').wait_for()
                    assert "workspaces/" in page.locator('#staged-files-list').inner_text()
                    page.evaluate("""() => {
                      const transfer = new DataTransfer();
                      transfer.items.add(new File([new Uint8Array([2,3])], 'second.bin',
                        {type:'application/octet-stream'}));
                      transfer.items.add(new File([new Uint8Array([4,5])], 'third.bin',
                        {type:'application/octet-stream'}));
                      document.dispatchEvent(new DragEvent('drop',
                        {bubbles:true,cancelable:true,dataTransfer:transfer}));
                    }""")
                    expect(page.locator('#staged-files-list .file-item')).to_have_count(3)
                    expect(page.locator('#staged-files-list a[download]')).to_have_count(3)
                    page.locator('#modal [data-action="close-modal"]').last.click()
                    page.locator('[data-action="new-challenge"]').first.click()
                    form = page.locator("#new-challenge-form")
                    form.wait_for()
                    assert form.locator('input[name="staged_file_ids"]').count() == 3
                    form.locator('input[name="name"]').fill("Unreleased challenge")
                    form.locator('.file-item').filter(has_text='first.bin').locator(
                        'input[name="staged_file_ids"]').check()
                    with page.expect_response(lambda response: (
                        "/staged-files/" in response.url and "/attach" in response.url
                    )) as attachment_response:
                        form.locator('button[type="submit"]').click()
                    assert attachment_response.value.status == 200, attachment_response.value.text()
                    page.locator('#modal').wait_for(state='hidden')
                    attachments = page.evaluate("""async workspaceId => {
                      const list = await (await fetch(`/api/workspaces/${workspaceId}/challenges`)).json();
                      const challenge = list.challenges.find(item => item.name === 'Unreleased challenge');
                      if (!challenge) return null;
                      const detail = await (await fetch(`/api/workspaces/${workspaceId}/challenges/${challenge.id}`)).json();
                      return detail.attachments;
                    }""", workspace_id)
                    assert attachments and len(attachments) == 1, attachments
                    assert attachments[0]["original_name"] == "first.bin"

                    english = browser.new_context(locale="en-US")
                    english.add_init_script("try { localStorage.setItem('ctf-language','en'); } catch {}")
                    bootstrap(english)
                    english_page = english.new_page()
                    english_page.goto(f"{origin}/#w/{workspace_id}")
                    english_page.get_by_role("button", name="Staged files").click()
                    assert "Drop files here" in english_page.locator("#modal").inner_text()
                    expect(english_page.locator("#staged-files-list")).to_contain_text("Stored path")
                    english.close()
                finally:
                    browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=10)
    print("staged-file browser flow: OK")


if __name__ == "__main__":
    main()
