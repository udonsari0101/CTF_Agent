"""Browser regression for read-only, nonblocking admin CLI version lookup."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ctf_agent/web/admin_versions.js").read_text(encoding="utf-8")
APP = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")


def browser_path() -> str | None:
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in (
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def main() -> int:
    assert "import {renderAdminCliVersions} from './admin_versions.js'" in APP
    assert APP.count('renderAdminCliVersions(document.querySelector(\'#admin-cli-version-panel\')') == 2
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = SOURCE.replace("export function renderAdminCliVersions", "function renderAdminCliVersions")
    fixture = """<!doctype html><html><body><main id="root"><section id="versions"></section></main>
<pre id="result">PENDING</pre><script>
""" + implementation + """
const root=document.querySelector('#root');
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
let calls=[],offline=false,hold=false,resolvers=[];
const api=url=>{
 calls.push(url);
 if(hold && url.endsWith('/catalog')) return new Promise(resolve=>resolvers.push([url,resolve]));
 if(offline && url.endsWith('/catalog')) return Promise.reject(new Error('offline'));
 return Promise.resolve(url.endsWith('/catalog')?{latest:url.includes('/codex/')?'0.166.0':'2.1.310'}:
  {version:url.includes('/codex/')?'0.164.0':'2.1.300'});
};
(async()=>{
 const first=document.querySelector('#versions');
 renderAdminCliVersions(first,api,{scope:'admin-a'});
 const nonblocking=first.textContent.includes('조회 중')&&first.querySelector('button').disabled;
 await tick();await tick();
 const firstResult=first.textContent.includes('현재 0.164.0 · 최신 0.166.0')
  &&first.textContent.includes('현재 2.1.300 · 최신 2.1.310')&&calls.length===4;
 const second=document.createElement('section');root.replaceChildren(second);
 renderAdminCliVersions(second,api,{scope:'admin-a'});
 const cached=second.textContent.includes('최신 0.166.0')&&calls.length===4;
 offline=true;second.querySelector('button').click();await tick();await tick();
 const offlineResult=calls.length===8&&second.textContent.includes('최신 0.166.0')
  &&second.textContent.includes('조회 실패 · 이전 결과 표시')&&!second.querySelector('button').disabled;
 const third=document.createElement('section');root.replaceChildren(third);
 renderAdminCliVersions(third,api,{scope:'admin-a'});
 await tick();
 const backoff=calls.length===8&&third.textContent.includes('이전 결과 표시');
 offline=false;hold=true;
 const fourth=document.createElement('section');root.replaceChildren(fourth);
 renderAdminCliVersions(fourth,api,{scope:'admin-b',locale:'en'});
 await tick();
 const beforeReentry=calls.length===12&&fourth.textContent.includes('Checking');
 const fifth=document.createElement('section');root.replaceChildren(fifth);
 renderAdminCliVersions(fifth,api,{scope:'admin-b',locale:'en'});
 await tick();
 const deduplicated=calls.length===12;
 for(const [url,resolve] of resolvers) resolve({latest:url.includes('/codex/')?'0.166.0':'2.1.310'});
 await tick();await tick();
 const result=nonblocking&&firstResult&&cached&&offlineResult&&backoff&&beforeReentry&&deduplicated
  &&fifth.textContent.includes('Latest 0.166.0')&&!calls.some(url=>url.endsWith('/update'));
 document.querySelector('#result').textContent=result?'PASS':'FAIL '+JSON.stringify({nonblocking,firstResult,cached,offlineResult,backoff,beforeReentry,deduplicated,calls,text:fifth.textContent});
})().catch(error=>{document.querySelector('#result').textContent='ERROR '+error.stack});
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-admin-cli-versions-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
               "--disable-extensions", f"--user-data-dir={root / 'profile'}",
               "--virtual-time-budget=2000", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            cmd.append("--no-sandbox")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            print(result.stdout[-3500:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: admin CLI versions load without blocking; cache, retry and in-flight dedup preserve read-only state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
