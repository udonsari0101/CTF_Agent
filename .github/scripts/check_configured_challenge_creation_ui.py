"""Check multi-configuration challenge creation in a real browser."""

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

    snapshot_start = SOURCE.index("function formSnapshot(")
    snapshot_end = SOURCE.index("function renderChallengeFiles(", snapshot_start)
    staged_start = SOURCE.index("function stagedPickerRow(")
    staged_end = SOURCE.index("function challengeStatusMarkup(", staged_start)
    variants_start = SOURCE.index("function variantEditorMarkup(")
    variants_end = SOURCE.index("async function openSolverSession(", variants_start)
    implementation = (
        SOURCE[snapshot_start:snapshot_end]
        + SOURCE[staged_start:staged_end]
        + SOURCE[variants_start:variants_end]
    )

    fixture = """<!doctype html><html><body><dialog id="modal"></dialog><pre id="result">PENDING</pre><script>
const i18n={t:s=>s,format:(s,values)=>s.replace(/\\{(\\w+)\\}/g,(_,key)=>values[key]??'')};
const tr=s=>s,esc=s=>String(s??'').replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');
const size=n=>`${n} B`;
const modal=document.querySelector('#modal'),busyForms=new WeakSet();
const MAX_SOLVER_VARIANTS=12;
let variantEditorGeneration=0,solverAccountId='account-a',currentWorkspace={id:'ws',open_challenge_after_create:false};
let sessionUser={solver_variant_defaults:[]};
let currentChallenge=null,challengeListing={result:{challenges:[{id:'source',name:'Source'}]}};
let submitted=null,refreshed=0,uploadCalls=[],batchCalls=0,mockUploadFailure=false;const toasts=[];
function path(id,ws){return `/api/workspaces/${ws}/challenges${id?'/'+id:''}`}
function toast(message){toasts.push(message)}
async function refreshChallenges(){refreshed++}
function renderChallengeFiles(form){form._challengeFiles||=[]}
function openModal(title,subtitle,body,footer,id){
 modal.innerHTML=`<form id="${id}"><h2>${title}</h2><div>${body}</div><footer>${footer}</footer></form>`;
 modal.querySelector('form').dataset.workspaceId=currentWorkspace.id;
 if(!modal.open)modal.showModal();
}
async function uploadStagedFile(file,workspaceId){
 uploadCalls.push({name:file.name,workspaceId});
 if(mockUploadFailure)return {id:'uploaded-failed',status:'failed'};
 return {id:'uploaded-1',status:'ready'};
}
async function api(url,options={}){
 if(url==='/api/workspaces/ws/staged-files')return {files:[
  {id:'staged-1',name:'prior.zip',size:12,status:'ready',file_available:true,linked_count:0}]};
 if(url==='/api/accounts')return {accounts:[
  {id:'account-a',label:'Account A',provider:'codex',selected:true,service_tier:'fast',snapshot:{status:'authenticated'},model:'model-a'},
  {id:'account-b',label:'Account B',provider:'codex',snapshot:{status:'authenticated'},model:'model-b'}]};
 if(url==='/api/accounts/account-a/models')return {status:'available',models:[
  {model:'model-a',displayName:'Model A',serviceTiers:[{id:'fast'}],supportedReasoningEfforts:[{reasoningEffort:'low'},{reasoningEffort:'high'}]}]};
 if(url==='/api/accounts/account-b/models')return {status:'available',models:[
  {model:'model-b',displayName:'Model B',serviceTiers:[],supportedReasoningEfforts:[{reasoningEffort:'high'},{reasoningEffort:'max'}]}]};
 if(url==='/api/workspaces/ws/challenges/batch'){
  batchCalls++;submitted=options.body;
  return {challenges:options.body.variants.map((_,i)=>({id:`created-${i+1}`}))};
 }
 throw Error('Unexpected API '+url);
}
""" + implementation + """
const result=document.querySelector('#result');
function assert(ok,label){if(!ok)throw Error(label)}
(async()=>{
 await challengeForm(false);
 let form=modal.querySelector('#new-challenge-form');
 assert(form&&form.dataset.workspaceId==='ws','new challenge form opens');
 assert(variantRows(form).length===0,'ordinary create begins without variants');
 assert(form.querySelector('input[name="staged_file_ids"][value="staged-1"]'),'ready staged file can be selected');
 await addVariantRow(form);
 assert(variantRows(form).length===1,'first configuration added');
 let first=variantRows(form)[0];
 assert(first.querySelector('.variant-model').value==='model-a','first model loaded');
 first.querySelector('.variant-reasoning').value='low';
 first.querySelector('.variant-reasoning').dispatchEvent(new Event('change',{bubbles:true}));
 assert(first.querySelector('.variant-tier').value==='fast','first fast tier retained');
 await addVariantRow(form);
 let second=variantRows(form)[1];
 second.querySelector('.variant-account').value='account-b';
 second.querySelector('.variant-account').dispatchEvent(new Event('change',{bubbles:true}));
 await new Promise(resolve=>setTimeout(resolve,0));
 assert(second.querySelector('.variant-model').value==='model-b','second independent model loaded');
 second.querySelector('.variant-reasoning').value='max';
 second.querySelector('.variant-reasoning').dispatchEvent(new Event('change',{bubbles:true}));
 assert(!form.querySelector('button[type="submit"]').disabled,'complete variant rows permit submit');
 form.elements.name.value='Two settings';
 form.querySelector('input[name="staged_file_ids"][value="staged-1"]').checked=true;
 const local=new File([new Uint8Array([1,2,3])],'local.bin',{type:'application/octet-stream'});
 const stagedFiles=[...form.querySelectorAll('input[name="staged_file_ids"]:checked')].map(input=>({id:input.value,name:input.dataset.name,size:Number(input.dataset.size)}));
 await createConfiguredChallenges(form,{name:form.elements.name.value,category:'Web',description:'desc',remote_mode:'none',remote:''},stagedFiles,[local]);
 assert(uploadCalls.length===1&&uploadCalls[0].name==='local.bin','local file uploaded before creation');
 assert(batchCalls===1&&submitted?.challenge?.name==='Two settings','batch creation called');
 assert(submitted.staged_file_ids.length===2&&submitted.staged_file_ids[0]==='staged-1'&&submitted.staged_file_ids[1]==='uploaded-1','pre-uploaded and local files attached to batch');
 const v=submitted.variants;
 assert(v.length===2,'two problems configured');
 assert(v[0].account_id==='account-a'&&v[0].model==='model-a'&&v[0].reasoning_effort==='low'&&v[0].service_tier==='fast','first independent configuration');
 assert(v[1].account_id==='account-b'&&v[1].model==='model-b'&&v[1].reasoning_effort==='max'&&v[1].service_tier===null,'second independent configuration');
 assert(refreshed===1&&!modal.open,'creation refreshes and closes');

 mockUploadFailure=true;
 await challengeForm(false);
 form=modal.querySelector('#new-challenge-form');
 await addVariantRow(form);
 let failed=false;
 try{await createConfiguredChallenges(form,{name:'Should not exist'},[],[local])}catch(error){failed=true}
 assert(failed&&batchCalls===1&&modal.open,'failed local upload cannot create incomplete batch');
 result.textContent='PASS';
})().catch(error=>{result.textContent='ERROR '+error.stack});
</script></body></html>"""

    with tempfile.TemporaryDirectory(prefix="ctf-agent-create-variants-") as temporary:
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
    print("PASS: new challenge creates two independent solver variants with staged and local files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
