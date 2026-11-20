"""Exercise independent Codex solver variants in the actual browser UI."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import re
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

    # Use the shipped UI functions; mock only the network and modal shell.
    start = SOURCE.index("function variantEditorMarkup(")
    end = SOURCE.index("async function openSolverSession(", start)
    implementation = SOURCE[start:end]
    fixture = """<!doctype html><html><body><dialog id="modal"></dialog><pre id="result">PENDING</pre><script>
const i18n={t:s=>s,format:(s,values)=>s.replace(/\\{(\\w+)\\}/g,(_,key)=>values[key]??'')};
const tr=s=>s,esc=s=>String(s).replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');
const modal=document.querySelector('#modal'),busyForms=new WeakSet();
const MAX_SOLVER_VARIANTS=12;
let variantEditorGeneration=0,solverAccountId='account-a';
let currentWorkspace={id:'ws'},currentChallenge=null,challengeListing={result:{challenges:[{id:'challenge',name:'Original'}]}};
let submitted=null,refreshed=0; const toasts=[];
function path(id,ws){return `/api/workspaces/${ws}/challenges/${id}`}
function toast(message){toasts.push(message)}
async function refreshChallenges(){refreshed++}
function openModal(title,subtitle,body,footer,id){
 modal.innerHTML=`<form id="${id}"><h2>${title}</h2><div>${body}</div><footer>${footer}</footer></form>`;
 modal.querySelector('form').dataset.workspaceId=currentWorkspace.id;
 modal.showModal();
}
async function api(url,options={}){
 if(url==='/api/accounts')return {accounts:[
  {id:'account-a',label:'Account A',provider:'codex',selected:true,service_tier:'fast',snapshot:{status:'authenticated'},model:'model-a'},
  {id:'account-b',label:'Account B',provider:'codex',snapshot:{status:'authenticated'},model:'model-b'}]};
 if(url==='/api/accounts/account-a/models')return {status:'available',models:[
  {model:'model-a',displayName:'Model A',serviceTiers:[{id:'fast'}],supportedReasoningEfforts:[{reasoningEffort:'low'},{reasoningEffort:'high'},{reasoningEffort:'ultra'}]}]};
 if(url==='/api/accounts/account-b/models')return {status:'available',models:[
  {model:'model-b',displayName:'Model B',serviceTiers:[],supportedReasoningEfforts:[{reasoningEffort:'high'},{reasoningEffort:'max'}]}]};
 if(url.endsWith('/clone-batch')){submitted=options.body;return {clones:options.body.variants.map(()=>({}))}}
 throw new Error('Unexpected '+url);
}
""" + implementation + """
const result=document.querySelector('#result');
function assert(ok,label){if(!ok)throw Error(label)}
function tick(){return new Promise(resolve=>setTimeout(resolve,0))}
(async()=>{
 await showCloneReasoning('challenge');
 const form=modal.querySelector('#clone-reasoning-form');
 await tick();
 assert(variantRows(form).length===1,'clone starts with one row');
 let first=variantRows(form)[0];
 assert(first.querySelector('.variant-model').value==='model-a','first account model');
 first.querySelector('.variant-reasoning').value='low';
 first.querySelector('.variant-reasoning').dispatchEvent(new Event('change',{bubbles:true}));
 first.querySelector('.variant-subagents').checked=false;
 addVariantRow(form); await tick();
 let second=variantRows(form)[1];
 second.querySelector('.variant-account').value='account-b';
 second.querySelector('.variant-account').dispatchEvent(new Event('change',{bubbles:true})); await tick();
 assert(second.querySelector('.variant-model').value==='model-b','second account model');
 second.querySelector('.variant-reasoning').value='high';
 second.querySelector('.variant-reasoning').dispatchEvent(new Event('change',{bubbles:true}));
 second.querySelector('.variant-subagents').checked=true;
 addVariantRow(form); await tick();
 let third=variantRows(form)[2];
 third.querySelector('.variant-reasoning').value='low';
 third.querySelector('.variant-reasoning').dispatchEvent(new Event('change',{bubbles:true}));
 assert(!form.querySelector('button[type="submit"]').disabled,'submit enabled');
 assert(variantRows(form).length===3,'three independent configurations');
 await submitCloneReasoning(form);
 const v=submitted?.variants||[];
 assert(v.length===3,'three clones submitted');
 assert(v[0].account_id==='account-a'&&v[0].model==='model-a'&&v[0].reasoning_effort==='low'&&v[0].subagents_enabled===false&&v[0].service_tier==='fast','first variant');
 assert(v[1].account_id==='account-b'&&v[1].model==='model-b'&&v[1].reasoning_effort==='high'&&v[1].subagents_enabled===true&&v[1].service_tier===null,'second variant');
 assert(v[2].account_id==='account-a'&&v[2].reasoning_effort==='low','same reasoning allowed in separate row');
 assert(refreshed===1,'list refreshed');
 result.textContent='PASS';
})().catch(error=>{result.textContent='ERROR '+error.stack});
</script></body></html>"""

    with tempfile.TemporaryDirectory(prefix="ctf-agent-bulk-ui-") as temporary:
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
    print("PASS: independent account, model, reasoning, service tier, and subagent clone rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
