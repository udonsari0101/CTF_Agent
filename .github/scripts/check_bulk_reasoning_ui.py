"""Exercise range selection, bulk stop, and multi-reasoning clone UI in Chrome."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")


def section(start: str, end: str) -> str:
    return SOURCE[SOURCE.index(start):SOURCE.index(end)]


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
    implementation = section("function syncChallengeSelection()", "function writeupStamp(") + "\n" + section(
        "async function showCloneReasoning(", "async function openSolverSession("
    )
    fixture = """<!doctype html><html><body>
<div id="challenge-area"><span class="challenge-selection-count"></span>
<button data-action="stop-selected-challenges"></button><button data-action="clear-challenge-selection"></button>
<div class="challenge-card" data-challenge-id="a"><input data-action="select-challenge"></div>
<div class="challenge-card" data-challenge-id="b"><input data-action="select-challenge"></div>
<div class="challenge-card" data-challenge-id="c"><input data-action="select-challenge"></div></div>
<dialog id="modal"></dialog><pre id="result">PENDING</pre><script>
const i18n={t:s=>s,format:(s,values)=>s.replace(/\\{(\\w+)\\}/g,(_,key)=>values[key]??'')};
const tr=s=>s,esc=s=>String(s).replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');
const modal=document.querySelector('#modal');
let currentWorkspace={id:'ws'},currentChallenge=null,cloneReasoningAccounts=[],cloneReasoningModels=[],cloneReasoningGeneration=0;
let solverAccountId='',bulkStopBusy=false,selectionAnchorId='';
const selectedChallengeIds=new Set(),cancelled=[],toasts=[];
let submitted=null;
const challengeListing={result:{challenges:[
 {id:'a',name:'Alpha',status:'running',latest_solver:{status:'running'}},
 {id:'b',name:'Beta',status:'stopped',latest_solver:{status:'cancelled'}},
 {id:'c',name:'Gamma',status:'running',latest_solver:{status:'running'}},
]}};
function path(id,ws){return `/api/workspaces/${ws}/challenges/${id}`}
function normalizeSolverPayload(value){return value}
function solverJobId(value){return value?.job_id||''}
function solverIsActive(value){return value?.phase==='running'}
function toast(message){toasts.push(message)}
function siteConfirm(){return Promise.resolve(true)}
function refreshChallenges(){return Promise.resolve()}
function formSnapshot(form){return JSON.stringify([...new FormData(form)])}
function openModal(title,subtitle,body,footer,id){
 modal.innerHTML=`<form id="${id}"><h2>${title}</h2><div>${body}</div><footer>${footer}</footer></form>`;
 modal.querySelector('form').dataset.workspaceId=currentWorkspace.id;
 modal.showModal();
}
async function api(url,options={}){
 if(url==='/api/accounts')return {accounts:[{id:'acc',label:'Codex',provider:'codex',selected:true,service_tier:'fast',snapshot:{status:'authenticated'},model:'m'}]};
 if(url==='/api/accounts/acc/models')return {status:'available',models:[{model:'m',displayName:'Model',serviceTiers:[{id:'fast'}],supportedReasoningEfforts:[{reasoningEffort:'low'},{reasoningEffort:'high'},{reasoningEffort:'ultra'}]}]};
 if(url.endsWith('/clone-batch')){submitted=options.body;return {clones:[{},{}]}}
 if(url.endsWith('/solver'))return {job:{job_id:url.includes('/a/')?'job-a':'job-c',phase:'running'}};
 if(url.endsWith('/cancel')){cancelled.push(url);return {}}
 throw new Error('Unexpected '+url);
}
""" + implementation + """
(async()=>{
 selectChallenge('a',{toggle:false});selectChallenge('c',{range:true});
 const range=[...selectedChallengeIds].join(',')==='a,b,c';
 await stopSelectedChallenges();
 const stop=cancelled.length===2&&cancelled.some(x=>x.includes('job-a'))&&cancelled.some(x=>x.includes('job-c'))&&!cancelled.some(x=>x.includes('job-b'));
 await showCloneReasoning('a');
 const form=modal.querySelector('#clone-reasoning-form');
 const model=form.querySelector('#clone-reasoning-model').value;
 const levels=form.querySelectorAll('[name="reasoning_levels"]');
 for(const input of levels)if(['low','high'].includes(input.value))input.checked=true;
 form.elements.namedItem('subagents_high').checked=true;
 await submitCloneReasoning(form);
 const variants=submitted?.variants||[];
 const clone=model==='m'&&variants.length===2&&variants[0].reasoning_effort==='low'&&variants[0].subagents_enabled===false&&variants[1].reasoning_effort==='high'&&variants[1].subagents_enabled===true&&variants.every(x=>x.service_tier==='fast'&&x.ultra_escalation_mode==='off');
 document.querySelector('#result').textContent=range&&stop&&clone?'PASS':'FAIL '+JSON.stringify({range,stop,clone,variants,cancelled});
})().catch(error=>{document.querySelector('#result').textContent='ERROR '+error.stack});
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-bulk-ui-") as temporary:
        root = Path(temporary)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        command = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run",
            "--disable-extensions", "--disable-dev-shm-usage", "--virtual-time-budget=1200",
            "--dump-dom",
        ]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(
            [*command, f"--user-data-dir={root / 'profile'}", page.as_uri()],
            capture_output=True, text=True, timeout=45, encoding="utf-8", errors="replace",
        )
        if result.returncode or '<pre id="result">PASS</pre>' not in result.stdout:
            print(result.stdout[-3000:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: range selection, active-only stop, and per-level clone settings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
