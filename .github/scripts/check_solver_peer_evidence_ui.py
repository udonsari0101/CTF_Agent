"""Browser regression for sharing a verified observation with a clone job."""

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
    implementation = "\n".join((
        section("function solverPeerEvidenceButton(", "function solverSessionMarkup("),
        section("async function openSolverPeerEvidence()", "async function rejectSolverFlag()"),
    ))
    fixture = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<dialog id="modal"></dialog><pre id="result">PENDING</pre><script>
const esc=value=>String(value??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const tr=value=>esc(value);
const i18n={t:value=>value};
const modal=document.querySelector('#modal');
let currentWorkspace={id:'workspace-1'};
let currentChallenge={id:'challenge-1',name:'Target challenge'};
let currentSolverJob={id:'target-job',phase:'running',provider:'codex'};
let solverRendering=1;
const posts=[],polls=[],toasts=[];
let pauseGet=false,releaseGet=null;
function solverJobId(job){return job?.job_id||job?.run_id||job?.id||'';}
function solverIsActive(job){return ['queued','staging','running'].includes(job?.phase);}
function openModal(title,subtitle,body,footer,formId){
  modal.innerHTML='<form id="'+formId+'">'+body+'<footer>'+footer+'</footer></form>';
  modal.showModal();
}
function scheduleSolverPoll(...args){polls.push(args);}
function toast(message){toasts.push(message);}
async function api(url,options){
  if(options?.method==='POST'){
    posts.push({url,body:options.body});
    return {share_id:'share-1',guidance_id:'guidance-1'};
  }
  if(pauseGet) await new Promise(resolve=>{releaseGet=resolve;});
  return {peers:[
    {job_id:'target-job',challenge_name:'Target challenge',model:'self'},
    {job_id:'source-1',challenge_name:'First clone',model:'gpt-6-sol',reasoning_effort:'xhigh',status:'completed'},
    {job_id:'source-2',challenge_name:'Second clone',model:'gpt-6-sol',reasoning_effort:'ultra',status:'running'}
  ],shares:[{observation:'Previously verified fact',delivery_status:'delivered'}]};
}
""" + implementation + """
(async()=>{
  const assert=(condition,message)=>{if(!condition)throw Error(message);};
  const button=solverPeerEvidenceButton(currentSolverJob,true);
  assert(button.includes('open-solver-peer-evidence'),'active job has no sharing button');
  assert(solverPeerEvidenceButton(currentSolverJob,false)==='','inactive view exposes sharing button');
  await openSolverPeerEvidence();
  const form=modal.querySelector('#solver-peer-evidence-form');
  const choices=[...form.querySelectorAll('select[name="source_job_id"] option')];
  assert(choices.length===2,'source selection did not render both clones');
  assert(choices.map(item=>item.value).join(',')==='source-1,source-2','self job included or source order changed');
  assert(choices[1].textContent.includes('ultra'),'source model details missing');
  assert(form.querySelector('.solver-peer-history').textContent.includes('Previously verified fact'),'share history missing');
  form.querySelector('select[name="source_job_id"]').value='source-2';
  form.querySelector('textarea[name="observation"]').value='Validated parser behavior';
  const body=Object.fromEntries(new FormData(form).entries());
  await sendSolverPeerEvidence(form,body);
  assert(posts.length===1,'expected one POST');
  assert(posts[0].url==='/api/solver/jobs/target-job/peer-evidence','POST targeted the wrong job');
  assert(posts[0].body.source_job_id==='source-2','selected source job was lost');
  assert(posts[0].body.observation==='Validated parser behavior','observation changed');
  assert(posts[0].body.requested_delivery==='same_turn','delivery option changed');
  assert(!modal.open&&polls.length===1,'success did not close modal or refresh job');

  await openSolverPeerEvidence();
  const staleForm=modal.querySelector('#solver-peer-evidence-form');
  currentSolverJob={id:'another-job',phase:'running',provider:'codex'};
  let refused=false;
  try {await sendSolverPeerEvidence(staleForm,{source_job_id:'source-1',observation:'stale',requested_delivery:'same_turn'});}
  catch {refused=true;}
  assert(refused&&posts.length===1,'stale job sent another POST');
  modal.close();

  currentSolverJob={id:'target-job',phase:'running',provider:'codex'};
  pauseGet=true;
  const pending=openSolverPeerEvidence();
  currentChallenge={id:'challenge-2',name:'Other challenge'};
  releaseGet();
  await pending;
  assert(!modal.open,'stale peer GET opened a modal for another challenge');
  document.querySelector('#result').textContent='PASS';
})().catch(error=>{document.querySelector('#result').textContent='FAIL '+error.message;});
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-peer-ui-", ignore_cleanup_errors=True) as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        command = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run",
            "--disable-extensions", "--disable-dev-shm-usage",
            "--virtual-time-budget=1000", "--dump-dom",
        ]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(
            [*command, f"--user-data-dir={root / 'profile'}", page.as_uri()],
            capture_output=True, text=True, timeout=45, encoding="utf-8", errors="replace",
        )
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            print(result.stdout[-3000:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: clone sources render, selection reaches the target job, stale jobs refuse sharing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
