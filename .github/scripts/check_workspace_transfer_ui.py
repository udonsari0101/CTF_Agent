import json
import mimetypes
import os
import shutil
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

web = Path(__file__).resolve().parents[2] / "ctf_agent" / "web"
w1 = "a" * 32
w2 = "b" * 32
c1 = "c" * 32
c2 = "d" * 32
workspace = {"id": w1, "name": "Demo workspace", "description": "", "flag_format": "", "challenge_count": 0, "solved_count": 0, "running_count": 0}
challenge = {"id": c1, "workspace_id": w1, "name": "Demo challenge", "category": "Web", "description": "", "remote_mode": "unknown", "remote": "", "status": "pending", "attachments": [], "notes": "", "flag": "", "related_challenges": [{"id":"e" * 32,"name":"Related","status":"solved","evidence_reapproval_required":True}]}
state = {"size": 0, "offset": 0, "status": "uploading", "puts": [], "chunk_lengths": [], "fail_second": True, "previews": 0, "creates": 0, "deletes": 0, "exports": [], "origin_error": True, "invite_creates": 0, "invite_requests": [], "invite_status": "issued", "direct_posts": []}

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.endswith("/transfer"):
            state["exports"].append(parse_qs(parsed.query))
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="demo.zip"')
            self.end_headers()
            self.wfile.write(b"PK\x03\x04")
            return
        super().do_GET()

def chrome_path():
    candidates = [os.environ.get("CTF_CHROME_PATH"), shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chrome"),
                  r"C:\Program Files\Google\Chrome\Application\chrome.exe"]
    return next((path for path in candidates if path and Path(path).is_file()), None)

def fulfill(route, payload, status=200):
    route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

def api(route):
    request = route.request
    parsed = urlparse(request.url)
    path = parsed.path
    method = request.method
    if path == "/api/auth/state":
        return fulfill(route, {"auth_mode":"password","authenticated":True,"csrf_token":"test","session_persistent":False,"user":{"id":"u1","username":"test","role":"user"}})
    if path == "/api/workspaces" and method == "GET":
        return fulfill(route, {"workspaces":[workspace]})
    if path == "/api/transfers/direct/invitations" and method == "POST":
        if state["origin_error"]:
            state["origin_error"] = False
            return fulfill(route, {"detail":{"code":"origin_unconfigured","message":"Public origin missing"}}, 503)
        state["invite_creates"] += 1
        state["invite_requests"].append(request.post_data_json)
        state["invite_status"] = "issued"
        return fulfill(route, {"invitation_id":"invite1","token":"one-time-secret","url":"https://destination.example/api/transfers/direct/invitations/invite1","scope":request.post_data_json["scope"],"workspace_id":request.post_data_json.get("workspace_id"),"max_size":request.post_data_json["max_size"],"expires_at":9999999999,"status":"issued"})
    if path == "/api/transfers/direct/invitations/invite1" and method == "GET":
        response = {"invitation_id":"invite1","scope":"workspace","workspace_id":None,"max_size":21474836480,"expires_at":9999999999,"status":state["invite_status"],"size":5}
        if state["invite_status"] == "completed":
            response["result"] = {"workspace_id":w2,"challenge_ids":[c2]}
        return fulfill(route, response)
    if path == "/api/transfers/direct/invitations/invite1" and method == "DELETE":
        state["invite_status"] = "revoked"
        return fulfill(route, {"revoked":True})
    if path.endswith("/transfer/direct") and method == "POST":
        state["direct_posts"].append(request.post_data_json)
        return fulfill(route, {"workspace_id":w2,"challenge_ids":[c2]})
    if path.startswith("/api/transfers/uploads"):
        parts = path.split("/")
        if path == "/api/transfers/uploads" and method == "POST":
            state["creates"] += 1
            state["size"] = request.post_data_json["size"]
            state["offset"] = 0
            state["status"] = "uploading"
            return fulfill(route, {"upload_id":"upload1","size":state["size"],"offset":0,"status":"uploading","sha256":None})
        if len(parts) == 5 and method == "GET":
            return fulfill(route, {"upload_id":"upload1","size":state["size"],"offset":state["offset"],"status":state["status"],"sha256":None})
        if path.endswith("/chunks") and method == "PUT":
            offset = int(parse_qs(parsed.query)["offset"][0])
            state["puts"].append(offset)
            state["chunk_lengths"].append(len(request.post_data_buffer))
            if offset > 0 and state["fail_second"]:
                state["fail_second"] = False
                return fulfill(route, {"detail":"temporary chunk failure"}, 503)
            state["offset"] = offset + len(request.post_data_buffer)
            return fulfill(route, {"offset":state["offset"]})
        if path.endswith("/finalize") and method == "POST":
            state["status"] = "ready"
            return fulfill(route, {"upload_id":"upload1","size":state["size"],"offset":state["offset"],"status":"ready"})
        if path.endswith("/preview") and method == "GET":
            state["previews"] += 1
            scope = "challenge" if parse_qs(parsed.query).get("workspace_id") else "workspace"
            return fulfill(route, {"scope":scope,"version":1,"name":"Imported sample","challenge_count":1,"attachment_count":1,"attachment_bytes":5,"archive_bytes":state["size"],"free_bytes":100000000,"sufficient_space":True,"name_collisions":[],"remote_endpoints_included":False,"structural_credentials_excluded":True,"free_text_may_contain_secrets":True,"integrity":"metadata_only","challenges":[{"name":"Imported challenge","category":"Web","attachment_count":1}]})
        if path.endswith("/import") and method == "POST":
            if request.post_data_json.get("workspace_id"):
                return fulfill(route, {"workspace_id":w1,"challenge_id":c2,"source_challenge_id":c1,"attachment_count":1})
            return fulfill(route, {"workspace_id":w2,"challenge_ids":[c2],"challenge_count":1,"attachment_count":1})
        if len(parts) == 5 and method == "DELETE":
            state["deletes"] += 1
            state["offset"] = 0
            return fulfill(route, {"deleted":True})
    if path.endswith("/transfer") and method == "GET":
        state["exports"].append(parse_qs(parsed.query))
        route.fulfill(status=200, content_type="application/zip", headers={"Content-Disposition":'attachment; filename="demo.zip"'}, body=b"PK\x03\x04")
        return
    if path.startswith(f"/api/workspaces/{w1}/challenges"):
        if path == f"/api/workspaces/{w1}/challenges":
            return fulfill(route, {"challenges":[],"categories":[],"counts":{"pending":0,"running":0,"stopped":0,"failed":0,"flag_found":0,"solved":0}})
        if path.endswith("/relations/candidates"):
            return fulfill(route, {"challenges":[]})
        if path.endswith("/uploads"):
            return fulfill(route, {"uploads":[]})
        if path.endswith("/solver"):
            return fulfill(route, {"job":{"job_id":"job1","phase":"completed","agents":[{"id":"child1","parent_id":"root","label":"Child 1"},{"id":"child2","parent_id":"root","label":"Child 2"}],"context_usage":[{"agent_id":"root","state":"measured","percent":42,"used_tokens":4200,"window_tokens":10000},{"agent_id":"child1","state":"compacting","percent":None}]},"events":[]})
        if path == f"/api/workspaces/{w1}/challenges/{c1}":
            return fulfill(route, challenge)
        if path == f"/api/workspaces/{w1}/challenges/{c2}":
            return fulfill(route, {**challenge,"id":c2,"name":"Imported challenge"})
    if path == "/api/accounts":
        return fulfill(route, {"accounts":[]})
    if path.startswith("/api/workspaces/") and method == "GET":
        wid = path.split("/")[3]
        return fulfill(route, {**workspace,"id":wid,"name":"Imported sample" if wid == w2 else workspace["name"]})
    return fulfill(route, {"detail":"unmocked "+path},404)

def run_dom_check():
    source = (web / "app.js").read_text(encoding="utf-8")
    export_code = source.split("async function downloadTransfer()", 1)[1].split("function showTransferImport", 1)[0]
    assert "response.blob(" not in export_code, "export must not buffer the entire archive in browser memory"
    assert "response.body.pipeTo" in export_code, "File System Access path must stream to disk"

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(web)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/index.html"
    try:
        with sync_playwright() as p:
            launch = {"headless": True}
            installed_chrome = chrome_path()
            if installed_chrome:
                launch["executable_path"] = installed_chrome
            browser = p.chromium.launch(**launch)
            try:
                context = browser.new_context(accept_downloads=True, locale="ko-KR")
                context.add_init_script("window.showSaveFilePicker = undefined")
                page = context.new_page()

                def asset(route):
                    relative = urlparse(route.request.url).path.removeprefix("/assets/")
                    target = (web / relative).resolve()
                    assert target.is_relative_to(web.resolve()), relative
                    route.fulfill(status=200, content_type=mimetypes.guess_type(relative)[0] or "application/octet-stream", body=target.read_bytes())

                page.route("**/assets/**", asset)
                page.route("**/api/**", api)
                page.goto(base)
                page.locator('[data-action="import-workspace-transfer"]').first.click()
                assert page.locator("#modal").evaluate("(el) => el.open")
                assert page.locator('[data-action="start-transfer-upload"]').is_disabled()
                payload = b"P" * (8 * 1024 * 1024 + 5)
                page.locator("#transfer-archive").set_input_files({"name":"sample.zip","mimeType":"application/zip","buffer":payload})
                page.locator('[data-action="start-transfer-upload"]').click()
                page.get_by_text("temporary chunk failure", exact=True).wait_for()
                assert state["puts"] == [0, 8 * 1024 * 1024], state["puts"]
                page.locator('[data-action="start-transfer-upload"]').click()
                page.get_by_text("가져오기 미리보기").wait_for()
                assert state["puts"] == [0, 8 * 1024 * 1024, 8 * 1024 * 1024], state["puts"]
                assert max(state["chunk_lengths"]) <= 8 * 1024 * 1024
                assert "제외됨" in page.locator("#transfer-preview").inner_text()
                page.locator('[data-action="confirm-transfer-import"]').click()
                page.wait_for_url("**#w/" + w2)
                page.locator('[data-action="export-workspace-transfer"]').click()
                assert not page.locator("#transfer-include-remote").is_checked()
                page.locator("#transfer-include-remote").check()
                with page.expect_download() as download:
                    page.locator('[data-action="download-transfer"]').click()
                assert download.value.suggested_filename.endswith(".zip")
                assert state["exports"][-1] == {"include_remote":["true"]}

                page.locator('[data-action="send-workspace-direct"]').click()
                page.locator("#direct-send-url").fill("https://destination.example/api/transfers/direct/invitations/invite1")
                page.locator("#direct-send-token").fill("one-time-secret")
                page.locator("#direct-include-remote").check()
                page.locator('[data-action="start-direct-send"]').click()
                page.get_by_text("전송을 마쳤습니다.", exact=False).first.wait_for()
                assert state["direct_posts"][-1] == {"invitation_url":"https://destination.example/api/transfers/direct/invitations/invite1","token":"one-time-secret","include_remote":True}
                page.locator('#modal [data-action="close-modal"]').last.click()

                page.locator('[data-action="receive-workspace-direct"]').click()
                page.locator('[data-action="create-direct-invitation"]').click()
                page.get_by_text("CTF_PUBLIC_ORIGIN", exact=False).first.wait_for()
                page.locator('[data-action="create-direct-invitation"]').click()
                page.locator("#direct-invite-token").wait_for(state="visible")
                assert page.locator("#direct-invite-token").input_value() == "one-time-secret"
                assert state["invite_requests"][-1]["scope"] == "workspace"
                assert "one-time-secret" not in page.evaluate("JSON.stringify(localStorage)")
                page.locator('#modal [data-action="close-modal"]').last.click()
                state["invite_status"] = "completed"
                page.locator('[data-action="receive-workspace-direct"]').click()
                page.locator('[data-action="open-direct-result"]').wait_for(state="visible")
                assert page.locator("#direct-invite-token").is_hidden()
                page.locator('#modal [data-action="close-modal"]').last.click()

                page.goto(base + "#w/" + w1 + "/c/" + c1)
                page.locator('#detail [data-action="import-challenge-transfer"]').wait_for()
                assert page.locator('#detail [data-action="export-challenge-transfer"]').is_visible()
                assert page.locator('#detail [data-action="receive-challenge-direct"]').is_visible()
                assert page.locator('#detail [data-action="send-challenge-direct"]').is_visible()
                assert "재확인 필요" in page.locator("#challenge-relations").inner_text()
                assert page.locator('#challenge-relations [data-action="edit-related-evidence"]').inner_text() == "재확인"
                page.locator(".solver-session-log > summary").click()
                page.locator(".solver-log-size-toggle").click()
                assert "42%" in page.locator(".solver-console-context").inner_text()
                page.locator('.solver-agent-select[data-agent-id="child1"]').click()
                assert "압축 중" in page.locator(".solver-console-context").inner_text()
                page.locator('.solver-agent-select[data-agent-id="child2"]').click()
                assert "알 수 없음" in page.locator(".solver-console-context").inner_text()
                page.locator('[data-action="close-solver-console"]').click()

                page.locator('#detail [data-action="receive-challenge-direct"]').click()
                page.locator('[data-action="create-direct-invitation"]').click()
                page.locator("#direct-invite-token").wait_for(state="visible")
                assert state["invite_requests"][-1]["scope"] == "challenge"
                assert state["invite_requests"][-1]["workspace_id"] == w1
                page.locator('[data-action="revoke-direct-invitation"]').click()
                page.locator('#modal [data-action="close-modal"]').last.click()

                page.locator('#detail [data-action="send-challenge-direct"]').click()
                page.locator("#direct-send-url").fill("https://destination.example/api/transfers/direct/invitations/invite1")
                page.locator("#direct-send-token").fill("one-time-secret")
                page.locator('[data-action="start-direct-send"]').click()
                page.get_by_text("전송을 마쳤습니다.", exact=False).first.wait_for()
                assert state["direct_posts"][-1]["include_remote"] is False
                page.locator('#modal [data-action="close-modal"]').last.click()

                page.locator('#detail [data-action="import-challenge-transfer"]').click()
                assert "문제 ZIP" in page.locator("#modal-title").inner_text()
                page.locator("#transfer-archive").set_input_files({"name":"challenge.zip","mimeType":"application/zip","buffer":b"PKzip"})
                page.locator('[data-action="start-transfer-upload"]').click()
                page.get_by_text("가져오기 미리보기").wait_for()
                assert page.locator('[data-action="confirm-transfer-import"]').is_enabled()
                page.locator('[data-action="cancel-transfer-upload"]').click()
                assert state["deletes"] == 1
                assert page.locator("#transfer-preview").is_hidden()
                assert page.evaluate("Object.keys(localStorage).filter(key => key.startsWith('ctf-transfer:')).length") == 0
                page.locator('[data-action="start-transfer-upload"]').click()
                page.get_by_text("가져오기 미리보기").wait_for()
                assert state["creates"] == 3
                page.locator('[data-action="confirm-transfer-import"]').click()
                page.locator("#challenge-title").get_by_text("Imported challenge").wait_for()

                english = browser.new_context(locale="en-US")
                en_page = english.new_page()
                en_page.route("**/assets/**", asset)
                en_page.route("**/api/**", api)
                en_page.goto(base)
                assert en_page.locator('[data-action="import-workspace-transfer"]').first.inner_text() == "Import ZIP"
                en_page.locator('[data-action="import-workspace-transfer"]').first.click()
                assert en_page.locator("#modal-title").inner_text() == "Import workspace ZIP"
                assert "Select a ZIP file." in en_page.locator("#transfer-upload-status").inner_text()
                english.close()
                print("PASS: ZIP and direct transfer DOM, resume/cancel, streamed export, context badges")
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    run_dom_check()



\n