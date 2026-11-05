"""Optional Docker Desktop HTTP smoke test for the local no-login boundary.

Uses disposable networks, a disposable web container, and a separate solver
network. It never touches the installed CTF Agent container or its data.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("CTF_LOCAL_ACCESS_TEST_IMAGE", "ctf-agent-local:latest")
TAG = "ctf_local_access_probe_" + secrets.token_hex(4)
WEB_NETWORK = TAG + "_web"
SOLVER_NETWORK = TAG + "_solver"
WEB_CONTAINER = TAG + "_web"


def docker(*arguments: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *arguments], check=True, text=True,
                          capture_output=capture, timeout=90)


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url: str, *, body: dict | None = None,
            opener=None) -> tuple[int, dict]:
    payload = json.dumps(body).encode("ascii") if body is not None else None
    req = urllib.request.Request(url, data=payload, method="POST" if payload else "GET")
    if payload:
        req.add_header("Content-Type", "application/json")
    try:
        open_request = opener.open if opener is not None else urllib.request.urlopen
        with open_request(req, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def browser_handoff_smoke(root: Path, key_path: Path, base: str, host_port: int) -> None:
    """Exercise the installed WSL fallback and a real headless Chromium browser."""
    from playwright.sync_api import sync_playwright

    distro = os.environ.get("CTF_LOCAL_ACCESS_TEST_WSL", "Ubuntu")

    def wsl_path(path: Path) -> str:
        return subprocess.run(
            ["wsl.exe", "-d", distro, "--exec", "wslpath", "-a", "-u", str(path)],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout.strip()

    launcher = (ROOT / "installer" / "installer" / "start.sh").read_text(encoding="utf-8")
    marker = '    python3 - "$home_dir/ctf_agent_data/config/local-access.key" <<\'PY\'\n'
    code = launcher.split(marker, 1)[1].split("\nPY\n", 1)[0]
    code = code.replace("127.0.0.1:5050", f"127.0.0.1:{host_port}")
    # This disposable web has no solver, so only its public /healthz can be
    # 200. The real launcher retains /readyz and waits for the actual worker.
    code = code.replace("/readyz", "/healthz")
    (root / "wsl-browser-code.py").write_text(code, encoding="utf-8")
    wrapper = root / "wsl-browser-wrapper.py"
    wrapper.write_text('''
import json,os,pathlib,sys,tempfile
code_path=sys.argv[1]
with tempfile.TemporaryDirectory(prefix="ctf-local-browser-") as temporary:
    root=pathlib.Path(temporary)
    key_path=root/"local-access.key"
    key_path.write_text(sys.stdin.read().strip()+"\\n")
    key_path.chmod(0o600)
    capture=root/"opened-url.txt"
    stub=root/"cmd.exe"
    stub.write_text("#!/usr/bin/env python3\\nimport os,pathlib,sys\\npathlib.Path(os.environ['CTF_CAPTURE_URL']).write_text(sys.argv[-1])\\n")
    stub.chmod(0o700)
    os.environ["CTF_CAPTURE_URL"]=str(capture)
    os.environ["PATH"]=str(root)+os.pathsep+os.environ["PATH"]
    sys.argv=[code_path,str(key_path)]
    exec(compile(pathlib.Path(code_path).read_text(),code_path,"exec"))
    print(json.dumps({"url":capture.read_text()}))
''', encoding="utf-8")
    launch = subprocess.run(
        ["wsl.exe", "-d", distro, "--exec", "python3", wsl_path(wrapper),
         wsl_path(root / "wsl-browser-code.py")],
        input=key_path.read_text(encoding="ascii").strip(), check=False,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90,
    )
    if launch.returncode:
        raise AssertionError("WSL launcher browser handoff failed: " + launch.stderr.strip())
    url = json.loads(launch.stdout.strip())["url"]
    assert url.startswith(base + "/#/local-access/") and len(url.rsplit("/", 1)[1]) == 32
    assert key_path.read_text(encoding="ascii").strip() not in url

    chrome = Path(os.environ.get("CTF_LOCAL_ACCESS_TEST_CHROME",
                                 r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=str(chrome), headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded")
        for _ in range(40):
            if context.request.get(base + "/api/auth/state").json()["authenticated"]:
                break
            time.sleep(0.25)
        else:
            raise AssertionError("Chromium did not exchange the WSL launcher ticket")
        assert page.evaluate("location.hash") == ""
        assert context.request.get(base + "/api/workspaces").status == 200
        page.reload(wait_until="domcontentloaded")
        assert context.request.get(base + "/api/auth/state").json()["authenticated"]
        second_tab = context.new_page()
        second_tab.goto(base, wait_until="domcontentloaded")
        assert context.request.get(base + "/api/auth/state").json()["authenticated"]
        separate_browser = browser.new_context()
        assert not separate_browser.request.get(base + "/api/auth/state").json()["authenticated"]
        separate_browser.close()

        docker("restart", WEB_CONTAINER)
        for _ in range(30):
            try:
                if request(base + "/healthz")[0] == 200:
                    break
            except (OSError, ValueError):
                time.sleep(1)
        else:
            raise AssertionError("Disposable web container did not restart")
        assert context.request.get(base + "/api/auth/state").json()["authenticated"]
        assert context.request.get(base + "/api/workspaces").status == 200
        page.reload(wait_until="domcontentloaded")
        assert context.request.get(base + "/api/auth/state").json()["authenticated"]
        context.close()
        browser.close()
    print("WSL legacy launcher handoff and Chromium cookie persistence: OK")


def main() -> None:
    docker("image", "inspect", IMAGE)
    host_port = port()
    created_networks: list[str] = []
    web_created = False
    try:
        with tempfile.TemporaryDirectory(prefix="ctf-local-access-http-") as temporary:
            root = Path(temporary)
            data, database = root / "data", root / "database"
            data.mkdir()
            database.mkdir()
            for network in (WEB_NETWORK, SOLVER_NETWORK):
                docker("network", "create", network)
                created_networks.append(network)
            docker(
                "run", "-d", "--name", WEB_CONTAINER,
                "--network", WEB_NETWORK, "--user", "0:0",
                "-p", f"127.0.0.1:{host_port}:5050",
                "-e", "CTF_AUTH_MODE=nologin",
                "-e", "CTF_STORAGE_MIN_FREE_BYTES=0",
                "-e", "CTF_ALLOW_WEB_BOOTSTRAP=true",
                "-v", f"{ROOT / 'ctf_agent'}:/app/ctf_agent:ro",
                "-v", f"{data}:/data", "-v", f"{database}:/database",
                IMAGE,
            )
            web_created = True
            base = f"http://127.0.0.1:{host_port}"
            for _ in range(30):
                try:
                    if request(base + "/healthz")[0] == 200:
                        break
                except (OSError, ValueError):
                    time.sleep(1)
            else:
                raise AssertionError("Disposable web container did not start")

            probe = r'''
import json,os,socket,urllib.error,urllib.request
base='http://host.docker.internal:PORT'
def call(path,body=None):
  data=json.dumps(body).encode() if body is not None else None
  req=urllib.request.Request(base+path,data=data,method='POST' if data else 'GET')
  if data: req.add_header('Content-Type','application/json')
  try:
    with urllib.request.urlopen(req,timeout=8) as r: return r.status,json.load(r)
  except urllib.error.HTTPError as e: return e.code,json.load(e)
try: socket.gethostbyname('WEB_CONTAINER'); direct=True
except socket.gaierror: direct=False
print(json.dumps({'direct_dns':direct,'key_mounted':os.path.exists('/data/config/local-access.key'),
  'state':call('/api/auth/state'),
  'workspaces':call('/api/workspaces'),
  'ticket':call('/api/auth/local/ticket',{'token':'x'*64}),
  'bootstrap':call('/api/auth/local/bootstrap',{'ticket':'x'*32})}))
'''.replace("PORT", str(host_port)).replace("WEB_CONTAINER", WEB_CONTAINER)
            output = docker("run", "--rm", "--network", SOLVER_NETWORK,
                            "--entrypoint", "python", IMAGE, "-c", probe).stdout
            result = json.loads(output.strip())
            assert not result["direct_dns"], result
            assert not result["key_mounted"], result
            assert result["state"][0] == 200, result
            assert result["state"][1]["authenticated"] is False, result
            assert result["state"][1]["csrf_token"] is None, result
            assert result["state"][1]["user"] is None, result
            assert result["workspaces"][0] == 401, result
            assert result["ticket"][0] == 403, result
            assert result["bootstrap"][0] == 403, result

            key = (data / "config" / "local-access.key").read_text(encoding="ascii").strip()
            assert len(key) == 64
            ticket_status, ticket_body = request(base + "/api/auth/local/ticket", body={"token": key})
            assert ticket_status == 200, ticket_body
            ticket = ticket_body["ticket"]
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            assert request(base + "/api/auth/local/bootstrap", body={"ticket": ticket}, opener=opener)[0] == 200
            assert request(base + "/api/workspaces", opener=opener)[0] == 200
            assert request(base + "/api/auth/local/bootstrap", body={"ticket": ticket})[0] == 403
            print("Docker Desktop host.docker.internal bypass blocked; browser ticket accepted once")
            if os.environ.get("CTF_LOCAL_ACCESS_BROWSER_SMOKE") == "1":
                browser_handoff_smoke(root, data / "config" / "local-access.key", base, host_port)
    finally:
        if web_created:
            subprocess.run(["docker", "rm", "-f", WEB_CONTAINER], capture_output=True, timeout=30)
        for network in reversed(created_networks):
            subprocess.run(["docker", "network", "rm", network], capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
