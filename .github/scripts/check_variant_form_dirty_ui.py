"""Ensure solver variant edits participate in modal unsaved-change detection."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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

    dirty_start = SOURCE.index("function formDirty(")
    dirty_end = SOURCE.index("function fileIdentity(", dirty_start)
    staged_start = SOURCE.index("function stagedPickerRow(")
    staged_end = SOURCE.index("function challengeStatusMarkup(", staged_start)
    variants_start = SOURCE.index("function variantEditorMarkup(")
    variants_end = SOURCE.index("async function openSolverSession(", variants_start)
    implementation = (
        SOURCE[dirty_start:dirty_end]
        + SOURCE[staged_start:staged_end]
        + SOURCE[variants_start:variants_end]
    )

    fixture = """<!doctype html><html><body><dialog id="modal"></dialog><pre id="result">PENDING</pre><script>
const i18n={t:s=>s,format:(s,values)=>s.replace(/\\{(\\w+)\\}/g,(_,key)=>values[key]??'')};
const tr=s=>s,esc=s=>String(s??'').replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');
const size=n=>`${n} B`;
const modal=document.querySelector('#modal'),busyForms=new WeakSet(),MAX_SOLVER_VARIANTS=12;
let variantEditorGeneration=0,solverAccountId='account-a';
let sessionUser={solver_variant_defaults:[]};
let currentWorkspace={id:'ws',open_challenge_after_create:false},currentChallenge=null;
let challengeListing={result:{challenges:[{id:'source',name:'Source'}]}};
function selectedChallengeFiles(form){return form._challengeFiles||[]}
function fileIdentity(file){return `${file.name}:${file.size}`}
function path(id,ws){return `/api/workspaces/${ws}/challenges${id?'/'+id:''}`}
function renderChallengeFiles(form){form._challengeFiles||=[]}
function openModal(title,subtitle,body,footer,id){
 modal.dataset.kind='';modal.dataset.workspaceId='';
 modal.innerHTML=`<form id="${id}"><h2>${title}</h2><div>${body}</div><footer>${footer}</footer></form>`;
 const form=modal.querySelector('form');form.dataset.workspaceId=currentWorkspace.id;
 form.dataset.initial=formSnapshot(form);
 if(!modal.open)modal.showModal();
}
async function api(url){
 if(url==='/api/workspaces/ws/staged-files')return {files:[]};
 if(url==='/api/accounts')return {accounts:[
  {id:'account-a',label:'Account A',provider:'codex',selected:true,snapshot:{status:'authenticated'},model:'model-a'},
  {id:'account-b',label:'Account B',provider:'codex',snapshot:{status:'authenticated'},model:'model-b'}]};
 if(url==='/api/accounts/account-a/models')return {status:'available',models:[
  {model:'model-a',displayName:'Model A',serviceTiers:[],supportedReasoningEfforts:[{reasoningEffort:'low'},{reasoningEffort:'high'}]}]};
 if(url==='/api/accounts/account-b/models')return {status:'available',models:[
  {model:'model-b',displayName:'Model B',serviceTiers:[],supportedReasoningEfforts:[{reasoningEffort:'high'},{reasoningEffort:'max'}]}]};
 throw Error('Unexpected '+url);
}
""" + implementation + """
const result=document.querySelector('#result');
function assert(ok,label){if(!ok)throw Error(label)}
function tick(){return new Promise(resolve=>setTimeout(resolve,0))}
(async()=>{
 await showCloneReasoning('source');
 let form=modal.querySelector('#clone-reasoning-form');
 assert(variantRows(form).length===1,'clone default row loaded');
 assert(!formDirty(),'loading catalog and default row leaves clone clean');

 let row=variantRows(form)[0];
 row.querySelector('.variant-reasoning').value='low';
 row.querySelector('.variant-reasoning').dispatchEvent(new Event('change',{bubbles:true}));
 assert(formDirty(),'reasoning change marks clone dirty');

 await showCloneReasoning('source');form=modal.querySelector('#clone-reasoning-form');
 assert(!formDirty(),'reopening clone resets clean state');
 row=variantRows(form)[0];
 row.querySelector('.variant-account').value='account-b';
 row.querySelector('.variant-account').dispatchEvent(new Event('change',{bubbles:true}));
 await tick();
 assert(formDirty(),'account change marks clone dirty after model reload');

 await showCloneReasoning('source');form=modal.querySelector('#clone-reasoning-form');
 form.querySelector('[data-variant-add]').click();await tick();
 assert(variantRows(form).length===2&&formDirty(),'adding row marks clone dirty');

 await showCloneReasoning('source');form=modal.querySelector('#clone-reasoning-form');
 form.querySelector('[data-variant-remove]').click();
 assert(variantRows(form).length===0&&formDirty(),'removing default row marks clone dirty');

 await challengeForm(false);form=modal.querySelector('#new-challenge-form');
 assert(!formDirty(),'new challenge clean before user input');
 form.querySelector('[data-variant-add]').click();await tick();
 assert(variantRows(form).length===1&&formDirty(),'adding creation row marks new challenge dirty');
 result.textContent='PASS';
})().catch(error=>{result.textContent='ERROR '+error.stack});
</script></body></html>"""

    with tempfile.TemporaryDirectory(prefix="ctf-agent-variant-dirty-") as temporary:
        root = Path(temporary)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        command = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run",
            "--disable-extensions", "--disable-dev-shm-usage", "--virtual-time-budget=5000",
            "--dump-dom",
        ]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(
            [*command, f"--user-data-dir={root / 'profile'}", page.as_uri()],
            capture_output=True, text=True, timeout=45, encoding="utf-8", errors="replace",
        )
        if result.returncode or '<pre id="result">PASS</pre>' not in result.stdout:
            match = re.search(r'<pre id="result">.*?</pre>', result.stdout, re.DOTALL)
            print(match.group(0) if match else result.stdout[:3000])
            print(result.stderr[-1000:])
            return 1
    print("PASS: default clone clean; account, reasoning, add, remove, and create edits dirty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
