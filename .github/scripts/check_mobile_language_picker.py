"""Check that the signed-in language picker remains usable at the mobile breakpoint."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def browser_path() -> str | None:
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        if found := shutil.which(name):
            return found
    for candidate in (
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def main() -> int:
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    source = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")
    shell = source[source.index("function shell("):source.index("\nasync function render(")]
    css = "\n".join((ROOT / f"ctf_agent/web/{name}").read_text(encoding="utf-8")
                    for name in ("style.css", "theme.css"))
    assert "</script" not in shell.lower() and "</style" not in css.lower()
    fixture = (
        '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<style>{css}</style></head><body><div id=\"app\"></div><pre id=\"result\">PENDING</pre>"
        "<script>"
        "const app=document.querySelector('#app');"
        "const sessionUser={username:'user',role:'admin'};"
        "const workspaces=[{id:'one'}],authMode='password';"
        "let sidebarCollapsed=false;"
        "const esc=value=>String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;');"
        "const avatarMarkup=()=>'<span>U</span>';"
        "const i18n={picker:()=>'<label class=\"language-picker\"><select data-language-picker "
        "aria-label=\"Language / 언어\"><option value=\"en\">English</option>"
        "<option value=\"ko\">한국어</option></select></label>'};"
        f"{shell}"
        "shell('workspaces','A very long workspace title that must truncate on a narrow screen');"
        "const picker=document.querySelector('.topbar [data-language-picker]');"
        "const box=picker?.getBoundingClientRect(),bar=document.querySelector('.topbar').getBoundingClientRect();"
        "const visible=picker&&box.width>0&&box.height>0&&getComputedStyle(picker).visibility==='visible';"
        "const within=visible&&box.left>=bar.left&&box.right<=bar.right+1;"
        "const noOverflow=document.documentElement.scrollWidth<=innerWidth+1;"
        "const choices=[...picker.options].map(option=>option.value).join(',')==='en,ko';"
        "const mobile=innerWidth<=500;"
        "const avatarHidden=getComputedStyle(document.querySelector('.topbar .avatar')).display==='none';"
        "document.querySelector('#result').textContent=mobile&&visible&&within&&noOverflow&&choices&&avatarHidden"
        "?'PASS':`FAIL width=${innerWidth} visible=${visible} within=${within} overflow=${document.documentElement.scrollWidth-innerWidth} choices=${choices} avatarHidden=${avatarHidden}`;"
        "</script></body></html>"
    )
    with tempfile.TemporaryDirectory(prefix="ctf-agent-mobile-language-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        command = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
                   "--disable-extensions", f"--user-data-dir={root / 'profile'}",
                   "--window-size=390,844", "--virtual-time-budget=1000", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        if result.returncode or '<pre id="result">PASS</pre>' not in result.stdout:
            marker = result.stdout.find('<pre id="result">')
            print(result.stdout[marker:marker + 250] if marker >= 0 else result.stdout[-500:])
            print(result.stderr[-500:])
            return 1
    print("PASS: signed-in language picker visible at mobile breakpoint without overflow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
