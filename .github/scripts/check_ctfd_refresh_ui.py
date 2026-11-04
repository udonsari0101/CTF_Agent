"""Headless browser check for the single-challenge CTFd diff preview."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2] if ".github" in Path(__file__).parts else Path.cwd()
SOURCE = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")


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
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = SOURCE[
        SOURCE.index("function showCTFdRefreshPreview("):
        SOURCE.index("async function startAuthenticatedCTFdRefresh(")
    ]
    fixture = """<!doctype html><html><body><dialog id="modal"></dialog>
<pre id="result">PENDING</pre><script>
const modal=document.querySelector('#modal');
const currentWorkspace={id:'workspace'};
const currentChallenge={id:'challenge',workspace_id:'workspace',ctfd_id:7,ctfd_url:'https://ctf.example',name:'Old'};
let importPreview=null;
const calls=[];
const result={preview_id:'preview',field_diff:[
 {field:'name',current:'Old',incoming:'New',changed:true,local_override:false,selectable:true},
 {field:'description',current:'local notes',incoming:'remote notes',changed:true,local_override:true,selectable:false},
 {field:'remote',current:'old',incoming:'<img src=x onerror=alert(1)>',changed:true,local_override:false,selectable:true}
],challenges:[{files:[{name:'sample.zip'}]}],errors:[]};
const api=async (path,options)=>{calls.push({path,body:options.body});return result};
const esc=x=>String(x??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const importErrors=xs=>xs.map(x=>esc(x.message)).join(' ');
const formSnapshot=form=>JSON.stringify([...new FormData(form)]);
const openModal=(title,subtitle,body,footer,formId)=>{
 modal.innerHTML=`<form id="${formId}"><h2>${esc(title)}</h2><p>${esc(subtitle)}</p>${body}${footer}</form>`;
 if(!modal.open)modal.showModal();
};
const showCTFdRefreshConnectionFallback=()=>{throw Error('unexpected fallback')};
""" + implementation + """
(async()=>{
 await refreshCTFdChallenge();
 const name=modal.querySelector('input[name="field"][value="name"]');
 const description=modal.querySelector('input[name="field"][value="description"]');
 const remote=modal.querySelector('input[name="field"][value="remote"]');
 const parts={open:modal.open,name:name?.checked,description:description?.disabled,remote:remote?.checked,
  noImg:!modal.querySelector('img'),
  escaped:remote?.closest('.import-row')?.querySelectorAll('pre')[1]?.textContent.includes('<img'),
  mode:importPreview?.mode==='refresh',id:importPreview.result.preview_id==='preview',
  selected:new FormData(modal.querySelector('form')).getAll('field').join(',')==='name,remote',
  path:calls[0].path.endsWith('/ctfd/refresh/preview'),empty:Object.keys(calls[0].body).length===0};
 const correct=Object.values(parts).every(Boolean);
 await previewCTFdChallengeRefresh({url:'https://ctf.example',auth_type:'token',token:'one-off'});
 const manual=calls[1].body.token==='one-off'&&calls[1].body.auth_type==='token';
 document.querySelector('#result').textContent=correct&&manual?'PASS':'FAIL '+JSON.stringify({parts,manual,calls});
})().catch(error=>document.querySelector('#result').textContent='ERROR '+error.stack);
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-ctfd-refresh-ui-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        command = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run",
            "--disable-extensions", f"--user-data-dir={root / 'profile'}",
            "--virtual-time-budget=1000", "--dump-dom", page.as_uri(),
        ]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        if result.returncode or '<pre id="result">PASS</pre>' not in result.stdout:
            marker = result.stdout.find('<pre id="result">')
            print(result.stdout[marker:marker + 2500] if marker >= 0 else result.stdout[-3000:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: CTFd field preview, override lock, HTML escaping and one-off credentials")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
