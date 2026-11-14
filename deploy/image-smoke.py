"""Exercise the packaged image with disposable data and no network access."""
import asyncio
import hashlib
import http.server
import importlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading

from fastapi.testclient import TestClient

from ctf_agent.main import create_app
from ctf_agent.codex_native import native_codex_binary
from ctf_agent.providers.codex import CodexAccount
from ctf_agent.solver_worker import REQUIRED_CLAUDE_VERSION, REQUIRED_CODEX_VERSION, resolve_codex_command
from ctf_agent.solver_exchange import _continuation_bundle


assert re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", os.environ.get("CTF_RELEASE_VERSION", ""))
assert re.fullmatch(r"[0-9a-f]{40}", os.environ.get("CTF_RELEASE_SHA", ""))


with tempfile.TemporaryDirectory(prefix="ctf-image-check-") as temporary:
    root = Path(temporary)
    # The CI container uses disposable tmpfs mounts for the solver's writable
    # paths. Ghidra resolves the image user's home from passwd, not $HOME.
    Path("/data/config/home").mkdir(parents=True, mode=0o700, exist_ok=True)
    data_root = root / "data"
    # Production's /data mount is root-owned and not writable at its top level
    # by the web UID. Seed only the writable directories created by storage
    # initialization, then make the root itself non-writable during app boot.
    for subdir in (
        "config", "workspaces", "workspace_files", "runtime",
        "claude-runtime", "solver-exchange", "solver-scratch",
    ):
        (data_root / subdir).mkdir(parents=True, exist_ok=True)
    (data_root / ".storage-budget.lock").touch()
    password = secrets.token_urlsafe(24)
    os.environ.update({
        "CTF_DATA_DIR": str(data_root),
        "CTF_DB_DIR": str(root / "database"),
        "CTF_CONFIG_DIR": str(data_root / "config"),
        "CTF_LOG_DIR": str(root / "logs"),
        "CTF_BOOTSTRAP_PASSWORD": password,
        "CTF_PUBLIC_ORIGIN": "https://testserver",
        "CTF_COOKIE_SECURE": "true",
    })
    data_root.chmod(0o500)
    try:
        app = create_app()
    finally:
        data_root.chmod(0o700)
    with TestClient(app, base_url="https://testserver") as client:
        # The disposable web-only smoke container has no solver worker. A
        # release must therefore refuse readiness while ordinary authenticated
        # routes remain testable; Compose readiness becomes 200 only after the
        # separate PID-1 worker publishes its isolation heartbeat.
        readiness = client.get("/readyz")
        assert readiness.status_code == 503
        assert readiness.json() == {"status": "unavailable"}
        assert client.get("/api/workspaces").status_code == 401
        response = client.post("/api/auth/login", json={"password": password})
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        client.headers["Origin"] = "https://testserver"
        workspace = client.post("/api/workspaces", json={"name": "Image check"})
        assert workspace.status_code == 201
        assert workspace.json()["flag_format"] is None
        base = "/api/workspaces/" + workspace.json()["id"]
        challenge = client.post(base + "/challenges", json={"name": "Sample"})
        assert challenge.status_code == 201
        path = base + "/challenges/" + challenge.json()["id"]
        assert client.post(path + "/complete").json()["completion_source"] == "manual"
        assert client.post(path + "/reopen").json()["status"] == "pending"
        assert client.put(path + "/notes", json={"content": "# Notes\n\nVerified."}).status_code == 200
        assert client.get(path + "/notes/download").text == "# Notes\n\nVerified."
        for asset in (
            "app.js", "accounts.js", "telegram.js", "style.css", "theme.css", "accounts.css", "icon.svg"
        ):
            result = client.get("/assets/" + asset)
            assert result.status_code == 200 and result.content
        assert client.delete(base).status_code == 200
    print("Packaged application auth, storage, status, notes and assets verified")

    # The release image must retain the bounded native-session handoff parser.
    continuation = root / "continuation-smoke"
    continuation.mkdir(mode=0o700)
    archive = b"offline continuation fixture"
    (continuation / "snapshot.tar.gz").write_bytes(archive)
    metadata = {
        "version": 1, "provider": "codex",
        "session_id": "11111111-2222-3333-4444-555555555555",
        "scratch_name": "ctf-job-smoke123456",
        "workdir_rel": "competition/challenge/codex-workdir",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "archive_size": len(archive), "input_sha256": "a" * 64,
    }
    (continuation / "meta.json").write_text(json.dumps(metadata), encoding="utf-8")
    assert _continuation_bundle(continuation, provider="codex") == (metadata, len(archive))
    print("Private solver continuation schema verified offline")

    for executable in ("node", "codex", "claude"):
        result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, executable + " failed its version check"
        if executable == "codex":
            assert REQUIRED_CODEX_VERSION in result.stdout
        if executable == "claude":
            assert REQUIRED_CLAUDE_VERSION in result.stdout
        print(result.stdout.strip())

    # The Playwright package supplies the one Node runtime shared by npm and
    # both provider launchers. Exercise a real browser with networking off so
    # the image-size optimization cannot silently break web challenges.
    playwright_node = Path("/usr/local/lib/python3.12/site-packages/playwright/driver/node")
    node_link = Path("/usr/local/bin/node")
    assert node_link.is_symlink() and node_link.samefile(playwright_node)
    npm_prefix = subprocess.run(
        ["npm", "prefix", "--global"], capture_output=True, text=True, timeout=15,
    )
    assert npm_prefix.returncode == 0 and npm_prefix.stdout.strip() == "/usr/local"
    assert not Path("/opt/jdk-21/lib/src.zip").exists()
    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path="/usr/bin/chromium", headless=True,
            args=["--no-sandbox"],
        )
        try:
            page = browser.new_page()
            page.goto("data:text/html,<title>offline-browser-smoke</title>")
            assert page.title() == "offline-browser-smoke"
        finally:
            browser.close()
    print("Shared Node runtime and offline Playwright browser verified")

    codex_native = native_codex_binary(Path("/usr/local/lib/node_modules/@openai/codex"))
    assert codex_native is not None
    assert codex_native.is_file() and not codex_native.is_symlink()
    os.environ["CTF_SOLVER_EXTERNAL_SANDBOX"] = "true"
    assert resolve_codex_command(Path("/unused"), REQUIRED_CODEX_VERSION) == [str(codex_native)]
    for layout in ("nested", "hoisted"):
        package_root = root / f"codex-{layout}" / "node_modules" / "@openai" / "codex"
        optional_root = (package_root / "node_modules" / "@openai"
                         if layout == "nested" else package_root.parent)
        candidate = optional_root / "codex-linux-x64" / "vendor" / "x86_64-unknown-linux-musl" / "bin" / "codex"
        candidate.parent.mkdir(parents=True)
        candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        candidate.chmod(0o700)
        assert native_codex_binary(package_root) == candidate
    code_mode_host = codex_native.with_name("codex-code-mode-host")
    host_details = code_mode_host.stat(follow_symlinks=False)
    assert stat.S_ISREG(host_details.st_mode) and not code_mode_host.is_symlink()
    assert stat.S_IMODE(host_details.st_mode) == 0o555
    assert host_details.st_uid == host_details.st_gid == 0
    assert not host_details.st_mode & (stat.S_ISUID | stat.S_ISGID)
    assert host_details.st_nlink == 1
    assert os.access(code_mode_host, os.X_OK)
    host_help = subprocess.run(
        [code_mode_host, "--help"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert host_help.returncode == 0
    assert "--listen" in host_help.stdout + host_help.stderr
    print("Pinned Codex code-mode host executable verified offline")

    claude_help = subprocess.run(
        ["claude", "--help"], capture_output=True, text=True, timeout=15
    )
    assert claude_help.returncode == 0
    for option in (
        "--restricted", "--output-format", "--include-partial-messages",
        "--json-schema", "--session-id", "--resume", "--model", "--effort",
        "--allowedTools", "--disallowedTools", "--permission-mode",
        "--permission-prompts", "--disable-slash-commands", "--settings",
    ):
        assert option in claude_help.stdout, option + " is missing from the pinned Claude CLI"
    print("Pinned Claude print/resume/tool-policy contract verified offline")

    # Production can use this parser through a tightly scoped, networkless
    # helper when an older Synology host parser cannot compile the policy.
    parser = Path("/usr/sbin/apparmor_parser")
    assert parser.is_file() and os.access(parser, os.X_OK)
    parser_version = subprocess.run(
        [parser, "--version"], capture_output=True, text=True, timeout=15
    )
    assert parser_version.returncode == 0
    assert "AppArmor parser version" in parser_version.stdout + parser_version.stderr
    print((parser_version.stdout + parser_version.stderr).splitlines()[0])
    parser_help = subprocess.run(
        [parser, "--help"], capture_output=True, text=True, timeout=15
    )
    assert parser_help.returncode == 0
    assert "--kernel-features" in parser_help.stdout + parser_help.stderr

    launchers = (
        Path("/usr/local/libexec/ctf-agent-codex-launcher"),
        Path("/usr/local/libexec/ctf-agent-claude-launcher"),
        Path("/usr/local/libexec/ctf-command/python"),
        Path("/usr/local/libexec/ctf-command/bash"),
        Path("/usr/local/libexec/ctf-command/submit-flag"),
        Path("/usr/local/libexec/ctf-command/request-remote"),
        Path("/usr/local/libexec/ctf-command/ctf-connect"),
        Path("/usr/local/libexec/ctf-command/ctf-browser"),
        Path("/usr/local/libexec/ctf-command/ctf-browser-act"),
    )
    launcher_inodes = set()
    for launcher in launchers:
        details = launcher.stat(follow_symlinks=False)
        assert stat.S_ISREG(details.st_mode) and not launcher.is_symlink()
        assert stat.S_IMODE(details.st_mode) == 0o555
        assert details.st_uid == details.st_gid == 0
        assert not details.st_mode & (stat.S_ISUID | stat.S_ISGID)
        assert details.st_nlink == 1
        launcher_inodes.add(details.st_ino)
    assert len(launcher_inodes) == len(launchers)
    account = pwd.getpwnam("ctf_agent")
    assert (account.pw_uid, account.pw_gid, account.pw_shell) == (
        10001,
        10001,
        "/usr/local/libexec/ctf-command/bash",
    )
    assert os.environ["SHELL"] == "/usr/local/libexec/ctf-command/bash"
    assert shutil.which("bwrap") is None
    submit_flag = Path("/usr/local/bin/submit-flag")
    assert submit_flag.is_symlink()
    assert submit_flag.resolve(strict=True) == Path("/usr/local/libexec/ctf-command/submit-flag")
    request_remote = Path("/usr/local/bin/request-remote")
    assert request_remote.is_symlink()
    assert request_remote.resolve(strict=True) == Path("/usr/local/libexec/ctf-command/request-remote")
    ctf_connect = Path("/usr/local/bin/ctf-connect")
    assert ctf_connect.is_symlink()
    assert ctf_connect.resolve(strict=True) == Path("/usr/local/libexec/ctf-command/ctf-connect")
    ctf_browser = Path("/usr/local/bin/ctf-browser")
    assert ctf_browser.is_symlink()
    assert ctf_browser.resolve(strict=True) == Path("/usr/local/libexec/ctf-command/ctf-browser")
    ctf_browser_act = Path("/usr/local/bin/ctf-browser-act")
    assert ctf_browser_act.is_symlink()
    assert ctf_browser_act.resolve(strict=True) == Path("/usr/local/libexec/ctf-command/ctf-browser-act")
    subprocess.run(
        [str(ctf_connect), "--help"],
        check=True,
        capture_output=True,
        timeout=10,
        cwd=temporary,
        env={
            "HOME": temporary,
            "LANG": "C.UTF-8",
            "PATH": os.environ.get("PATH", ""),
        },
    )
    print("Immutable AppArmor transition launchers verified")

    tool_home = root / "tool-home"
    tool_cache = root / "tool-cache"
    tool_tmp = root / "tool-tmp"
    for directory in (tool_home, tool_cache, tool_tmp):
        directory.mkdir(mode=0o700)
    tool_env = os.environ.copy()
    tool_env.update({
        "HOME": str(tool_home),
        "XDG_CONFIG_HOME": str(tool_home / "config"),
        "XDG_CACHE_HOME": str(tool_cache),
        "TMP": str(tool_tmp),
        "TEMP": str(tool_tmp),
        "TMPDIR": str(tool_tmp),
    })

    for executable in (
        "file", "objdump", "readelf", "gdb", "jq", "7z", "unzip", "xz",
        "nc", "openssl", "rg", "gcc", "binwalk", "foremost", "exiftool",
        "fls", "icat", "mmls", "steghide", "john", "ffmpeg", "ffprobe",
        "tesseract", "tshark", "qemu-x86_64", "qemu-system-x86_64", "tmux",
        "r2", "ffuf", "yara", "gdb-multiarch", "git", "strace", "ltrace",
        "patchelf", "cpio", "pngcheck", "pdfinfo", "pdftotext", "mediainfo",
        "sox", "chromium", "ctf-browser", "ctf-browser-act", "dig", "socat", "wasm2wat", "whois",
        "zbarimg", "apktool", "gdbserver", "nmap", "sqlmap", "testdisk", "photorec",
        "java", "javac", "ghidra_headless", "jadx", "gp", "stegseek", "multimon-ng",
        "pwndbg", "websocat", "xxd", "GoReSym", "seccomp-tools",
    ):
        assert shutil.which(executable), executable + " is missing from the CTF toolchain"
    ffuf = Path("/usr/local/bin/ffuf")
    ffuf_details = ffuf.stat(follow_symlinks=False)
    assert stat.S_ISREG(ffuf_details.st_mode) and not ffuf.is_symlink()
    assert stat.S_IMODE(ffuf_details.st_mode) == 0o555
    assert ffuf_details.st_uid == ffuf_details.st_gid == 0
    assert Path("/usr/share/doc/ffuf/copyright").is_file()
    for executable, arguments in (
        ("binwalk", ("--help",)),
        ("exiftool", ("-ver",)),
        ("ffmpeg", ("-version",)),
        ("fls", ("-V",)),
        ("qemu-system-x86_64", ("--version",)),
        ("qemu-x86_64", ("--version",)),
        ("steghide", ("--version",)),
        ("tesseract", ("--version",)),
        ("tmux", ("-V",)),
        ("tshark", ("--version",)),
        ("r2", ("-2", "-q", "-c", "iI;q", "/bin/true")),
        ("ffuf", ("-V",)),
        ("yara", ("--version",)),
        ("gdb-multiarch", ("--version",)),
        ("git", ("--version",)),
        ("strace", ("--version",)),
        ("ltrace", ("--version",)),
        ("patchelf", ("--version",)),
        ("cpio", ("--version",)),
        ("mediainfo", ("--Version",)),
        ("sox", ("--version",)),
        ("chromium", ("--version",)),
        ("ctf-browser", ("--version",)),
        ("ctf-browser-act", ("--help",)),
        ("seccomp-tools", ("--version",)),
        ("dig", ("-v",)),
        ("socat", ("-V",)),
        ("wasm2wat", ("--version",)),
        ("whois", ("--version",)),
        ("zbarimg", ("--version",)),
        ("apktool", ("--version",)),
        ("gdbserver", ("--version",)),
        ("nmap", ("--version",)),
        ("sqlmap", ("--version",)),
        ("java", ("-version",)),
        ("javac", ("-version",)),
        ("jadx", ("--version",)),
        ("websocat", ("--version",)),
    ):
        result = subprocess.run(
            [executable, *arguments], capture_output=True, text=True, timeout=15,
            cwd=temporary, env=tool_env,
        )
        assert result.returncode == 0, (
            executable + " failed its runtime check: " + result.stderr.strip()
        )
    apktool_version = subprocess.run(
        ["apktool", "--version"], capture_output=True, text=True,
        timeout=15, cwd=temporary, env=tool_env,
    )
    assert apktool_version.returncode == 0 and apktool_version.stdout.strip() == "2.12.1"
    assert not Path("/usr/lib/jvm/java-17-openjdk-amd64").exists()
    binary_fixture = b"\x00CTF\x01\xfe\xff\n"
    hex_dump = subprocess.run(
        ["xxd", "-p"], input=binary_fixture, capture_output=True,
        check=True, timeout=15, cwd=tool_tmp, env=tool_env,
    ).stdout
    restored = subprocess.run(
        ["xxd", "-r", "-p"], input=hex_dump, capture_output=True,
        check=True, timeout=15, cwd=tool_tmp, env=tool_env,
    ).stdout
    assert restored == binary_fixture
    java_source = tool_tmp / "CTFSmoke.java"
    java_source.write_text("public class CTFSmoke { public static int answer() { return 42; } }", encoding="utf-8")
    subprocess.run(
        ["javac", "--release", "11", str(java_source)], check=True,
        capture_output=True, text=True, timeout=30, cwd=tool_tmp, env=tool_env,
    )
    jadx_output = tool_tmp / "jadx-output"
    jadx_result = subprocess.run(
        ["jadx", "--no-res", "--output-dir", str(jadx_output), str(tool_tmp / "CTFSmoke.class")],
        capture_output=True, text=True, timeout=90, cwd=tool_tmp, env=tool_env,
    )
    assert jadx_result.returncode == 0, jadx_result.stderr.strip()
    assert any("answer()" in path.read_text(encoding="utf-8") for path in jadx_output.rglob("*.java"))
    native_source = tool_tmp / "ctf-smoke.c"
    native_source.write_text("int main(void) { return 42; }", encoding="utf-8")
    native_binary = tool_tmp / "ctf-smoke"
    subprocess.run(
        ["gcc", "-o", str(native_binary), str(native_source)], check=True,
        capture_output=True, text=True, timeout=30, cwd=tool_tmp, env=tool_env,
    )
    go_symbols = subprocess.run(
        ["GoReSym", "/usr/local/bin/GoReSym"],
        capture_output=True, text=True, timeout=30, cwd=tool_tmp, env=tool_env,
    )
    assert go_symbols.returncode == 0, go_symbols.stderr.strip()[-3000:]
    assert json.loads(go_symbols.stdout).get("Arch") == "amd64"
    ghidra_project = tool_tmp / "ghidra-project"
    ghidra_project.mkdir()
    ghidra_output = tool_tmp / "tmp" / "main.c"
    ghidra_result = subprocess.run(
        ["ghidra_headless", str(ghidra_project), "smoke-project", "-import", str(native_binary),
         "-analysisTimeoutPerFile", "60", "-max-cpu", "2",
         "-postScript", "DecompileFn.java", "main", str(ghidra_output)],
        capture_output=True, text=True, timeout=180, cwd=tool_tmp, env=tool_env,
    )
    assert ghidra_result.returncode == 0, (ghidra_result.stdout + ghidra_result.stderr)[-3000:]
    assert "main(" in ghidra_output.read_text(encoding="utf-8")
    reused_output = tool_tmp / "tmp" / "main-reused.c"
    reused_result = subprocess.run(
        ["ghidra_headless", str(ghidra_project), "smoke-project", "-process", native_binary.name,
         "-noanalysis", "-postScript", "DecompileFn.java", "main", str(reused_output)],
        capture_output=True, text=True, timeout=90, cwd=tool_tmp, env=tool_env,
    )
    assert reused_result.returncode == 0, (reused_result.stdout + reused_result.stderr)[-3000:]
    assert reused_output.read_text(encoding="utf-8") == ghidra_output.read_text(encoding="utf-8")
    gp_result = subprocess.run(
        ["gp", "-q", "-f"], input="factor(91)\n", capture_output=True,
        text=True, timeout=15, cwd=tool_tmp, env=tool_env,
    )
    assert gp_result.returncode == 0 and "7" in gp_result.stdout and "13" in gp_result.stdout
    stegseek_result = subprocess.run(
        ["stegseek", "--help"], capture_output=True, text=True,
        timeout=15, cwd=tool_tmp, env=tool_env,
    )
    assert "StegSeek" in stegseek_result.stdout + stegseek_result.stderr
    pwndbg_result = subprocess.run(
        ["pwndbg", "-q", "-batch", "-ex", "help vmmap", "/bin/true"],
        capture_output=True, text=True, timeout=30, cwd=tool_tmp, env=tool_env,
    )
    assert pwndbg_result.returncode == 0 and "vmmap" in pwndbg_result.stdout, pwndbg_result.stderr[-3000:]
    os.environ.update({key: tool_env[key] for key in (
        "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMP", "TEMP", "TMPDIR"
    )})
    for module in (
        "pwn", "capstone", "unicorn", "filebytes", "Crypto", "gmpy2", "sympy",
        "z3", "pyasn1", "requests", "jwt", "flask_unsign", "scapy", "PIL",
        "magic", "hashpumpy", "yaml", "angr", "claripy", "fpylll", "lief",
        "owiener", "pefile", "volatility3", "yara", "networkx",
    ):
        importlib.import_module(module)

    # Imports alone miss incompatible native wheels and broken tool APIs. Run
    # small deterministic operations representative of the restored playbooks.
    import angr
    import claripy
    from fpylll import IntegerMatrix, LLL
    import lief
    import owiener
    from volatility3.framework import constants as volatility_constants
    import yara

    project = angr.Project("/bin/true", auto_load_libs=False)
    assert project.arch.bits == 64
    symbolic = claripy.BVS("image_smoke", 8)
    solver = claripy.Solver()
    solver.add(symbolic == 42)
    assert solver.eval(symbolic, 1) == (42,)
    basis = IntegerMatrix.from_matrix([[4, 1], [1, 3]])
    LLL.reduction(basis)
    assert sum(int(basis[0, column]) ** 2 for column in range(2)) <= 10
    assert lief.parse("/bin/true") is not None
    assert owiener.attack(2621, 8927) == 5
    rule = yara.compile(source='rule image_smoke { strings: $a = "marker" condition: $a }')
    assert [match.rule for match in rule.match(data=b"marker")] == ["image_smoke"]
    assert volatility_constants.PACKAGE_VERSION == "2.28.0"
    interpreter = subprocess.run(
        ["patchelf", "--print-interpreter", "/bin/true"],
        check=True, capture_output=True, text=True, timeout=15,
        cwd=temporary, env=tool_env,
    ).stdout.strip()
    assert interpreter.startswith("/")
    browser_workdir = Path(
        "/solver-scratch/ctf-job-image-smoke/competition/challenge/codex-workdir"
    )
    (browser_workdir / "tmp").mkdir(parents=True, mode=0o700)
    browser_page = browser_workdir / "tmp" / "page.html"
    browser_png = browser_workdir / "tmp" / "page.png"
    browser_page.write_text(
        "<!doctype html><meta charset=utf-8><title>CTF browser smoke</title>"
        "<main>browser-ready</main>",
        encoding="utf-8",
    )
    browser_result = subprocess.run(
        [
            str(ctf_browser),
            "--hide-scrollbars",
            f"--screenshot={browser_png}",
            browser_page.as_uri(),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=browser_workdir,
        env=tool_env,
    )
    assert browser_result.returncode == 0, browser_result.stderr.strip()
    assert browser_png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert not list(browser_workdir.parents[2].glob(".ctf-browser-*"))

    browser_cookies_seen = []
    browser_submissions = []

    class BrowserSessionHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/action":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(
                    b"<!doctype html><title>CTF browser action check</title><body>"
                    b"<input id=user><input id=upload type=file><button id=send>Send</button>"
                    b"<div id=state></div><div id=result></div><script>"
                    b"console.log('browser-action-ready');"
                    b"document.querySelector('#state').textContent=localStorage.getItem('action_smoke')||'0';"
                    b"document.querySelector('#send').onclick=async()=>{"
                    b"const f=await document.querySelector('#upload').files[0].text();"
                    b"const r=await fetch('/submit?token=private',{method:'POST',"
                    b"headers:{'Content-Type':'application/json'},"
                    b"body:JSON.stringify({user:document.querySelector('#user').value,file:f})});"
                    b"const node=document.querySelector('#result');node.textContent=await r.text();"
                    b"node.className='done';localStorage.setItem('action_smoke','1');"
                    b"console.log('smoke-submitted')};</script>"
                )
                return
            if self.path != "/test":
                self.send_error(404)
                return
            browser_cookies_seen.append("ctf_browser_smoke=1" in self.headers.get("Cookie", ""))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie", "ctf_browser_smoke=1; Max-Age=3600; Path=/; SameSite=Lax")
            self.end_headers()
            self.wfile.write(
                b"<!doctype html><title>CTF browser session check</title><body>"
                b"<script>document.body.textContent='storage='+"
                b"(localStorage.getItem('ctf_browser_smoke')||'0');"
                b"localStorage.setItem('ctf_browser_smoke','1')</script>"
            )

        def do_POST(self):
            if self.path != "/submit?token=private":
                self.send_error(404)
                return
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            browser_submissions.append(payload)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"submitted:{payload['user']}:{payload['file']}".encode())

        def log_message(self, *_args):
            pass

    browser_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BrowserSessionHandler)
    browser_thread = threading.Thread(target=browser_server.serve_forever, daemon=True)
    browser_thread.start()
    try:
        browser_url = f"http://127.0.0.1:{browser_server.server_port}/test"
        for options, expected_cookie, expected_storage in (
            (["--session=smoke", "--dump-dom", browser_url], False, "storage=0"),
            (["--session=smoke", "--dump-dom", browser_url], True, "storage=1"),
            (["--dump-dom", browser_url], False, "storage=0"),
        ):
            previous_requests = len(browser_cookies_seen)
            result = subprocess.run(
                [str(ctf_browser), *options],
                capture_output=True, text=True, timeout=15,
                cwd=browser_workdir, env=tool_env,
            )
            assert result.returncode == 0, result.stderr.strip()[-3000:]
            assert len(browser_cookies_seen) > previous_requests
            assert browser_cookies_seen[previous_requests] is expected_cookie
            assert expected_storage in result.stdout

        upload_file = browser_workdir / "tmp" / "sample.txt"
        upload_file.write_text("sample-data", encoding="utf-8")
        steps_file = browser_workdir / "tmp" / "actions.json"
        steps_file.write_text(json.dumps([
            {"action": "fill", "selector": "#user", "value": "guest"},
            {"action": "upload", "selector": "#upload", "files": ["tmp/sample.txt"]},
            {"action": "click", "selector": "#send"},
            {"action": "wait_for", "selector": "#result.done"},
            {"action": "evaluate", "expression": "localStorage.getItem('action_smoke')"},
        ]), encoding="utf-8")
        action_html = browser_workdir / "tmp" / "action.html"
        action_png = browser_workdir / "tmp" / "action.png"
        action_json = browser_workdir / "tmp" / "action.json"
        result = subprocess.run(
            [str(ctf_browser_act), "--session=action", "--steps=tmp/actions.json",
             "--html=tmp/action.html", "--screenshot=tmp/action.png",
             "--output=tmp/action.json",
             f"http://127.0.0.1:{browser_server.server_port}/action"],
            capture_output=True, text=True, timeout=45,
            cwd=browser_workdir, env=tool_env,
        )
        assert result.returncode == 0, result.stderr.strip()[-3000:]
        action = json.loads(result.stdout)
        assert action["actions"][-1]["result"] == "1"
        assert "submitted:guest:sample-data" in action["body"]
        assert browser_submissions == [{"user": "guest", "file": "sample-data"}]
        assert any(event["text"] == "smoke-submitted" for event in action["console"])
        assert any(event.get("status") == 200 and event.get("method") == "POST"
                   for event in action["network"])
        assert "private" not in result.stdout and "private" not in action_json.read_text()
        assert "CTF browser action check" in action_html.read_text()
        assert action_png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        reused = subprocess.run(
            [str(ctf_browser_act), "--session=action",
             f"http://127.0.0.1:{browser_server.server_port}/action"],
            capture_output=True, text=True, timeout=30,
            cwd=browser_workdir, env=tool_env,
        )
        assert reused.returncode == 0, reused.stderr.strip()[-3000:]
        assert json.loads(reused.stdout)["body"].strip().splitlines()[-1] == "1"
    finally:
        browser_server.shutdown()
        browser_server.server_close()
        browser_thread.join(timeout=5)
    assert not list(browser_workdir.parents[2].glob(".ctf-browser-*"))
    print("Pinned ctf_agent CTF toolchain passed functional checks")

    async def protocol_check():
        account = CodexAccount(root / "isolated-codex", ["codex"])
        try:
            await account.start()
            result = await account.request("account/read", {"refreshToken": False})
            assert result["account"] is None
        finally:
            await account.close()

    asyncio.run(protocol_check())
    print("Isolated Codex account protocol verified without login or generation")
