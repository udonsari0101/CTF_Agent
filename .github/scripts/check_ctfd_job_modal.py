"""Browser regression for CTFd import history rendering and background polling."""

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
    assert '<div id="ctfd-job-area"></div><div id="challenge-area"></div>' not in SOURCE
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = "\n".join((
        section("function ctfdImportHistoryMarkup()", "async function importForm()"),
        section("const ctfdJobLabels =", "function reflectActiveCTFdRefreshes("),
        section("function updateCTFdImportButton(jobs, workspaceId)", "function updateCTFdJobs(area, jobs)"),
        section("async function pollCTFdJobs(workspaceId)", "async function retryCTFdJob(button)"),
        section("function showCTFdSyncPreview(result, workspaceId)", "async function startCTFdSync(form, challengeIds)"),
    ))
    fixture = """<!doctype html><html><body>
<main id="workspace"><div class="head-actions"><button data-action="ctfd-import">CTFd 가져오기 <span class="ctfd-import-badge" hidden></span></button></div><div id="challenge-area"></div></main>
<dialog id="modal" open></dialog><pre id="result">PENDING</pre><script>
const modal=document.querySelector('#modal');
const ctfdJobMarkupCache=new WeakMap();
let ctfdJobsPollTimer=null,ctfdJobsRequestGeneration=0,currentWorkspace={id:'w'};
let importPreview=null;
let refreshCount=0, jobs=[];
const esc=x=>String(x??'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
const size=x=>String(x)+' B';
const importErrors=xs=>xs.map(x=>esc(x.message)).join(' ');
const api=async()=>({jobs});
const reflectActiveCTFdRefreshes=()=>null;
const refreshChallenges=async()=>{refreshCount++};
const paintCTFdChallengeRefresh=()=>{};
const ctfdJobError=()=>'';
const toast=()=>{};
const detail={open:false};
const currentChallenge=null;
const rememberNotes=()=>{};
const openChallenge=async()=>{};
const formSnapshot=form=>JSON.stringify([...new FormData(form)]);
const openModal=(title,subtitle,body,footer,formId)=>{
 modal.innerHTML=`<form id="${formId||'no-form'}"><h2>${esc(title)}</h2><p>${esc(subtitle)}</p>${body}${footer}</form>`;
};
""" + implementation + """
(async()=>{
 modal.innerHTML='<label>URL<input id="url" value="draft"></label>'+ctfdImportHistoryMarkup();
 modal.dataset.kind='ctfd-import';modal.dataset.workspaceId='w';
 const input=modal.querySelector('#url');input.focus();
 jobs=[{id:'one',mode:'import',status:'running',imported:1,attachments:0,downloaded_bytes:5,errors:[]}];
 await pollCTFdJobs('w');
 const active=modal.querySelector('#ctfd-job-area').textContent.includes('1개')&&ctfdJobsPollTimer!==null
  &&!!modal.querySelector('[data-action="cancel-ctfd"]');
 const header=document.querySelector('.head-actions [data-action="ctfd-import"]');
 const badge=header.querySelector('.ctfd-import-badge');
 const runningBadge=!badge.hidden&&badge.textContent==='진행 중'&&header.getAttribute('aria-label').includes('진행 중');
 input.value='draft-changed';
 jobs=[{...jobs[0],imported:2}];
 await pollCTFdJobs('w');
 const preserved=input.isConnected&&document.activeElement===input&&input.value==='draft-changed'
  &&modal.querySelector('#ctfd-job-area').textContent.includes('2개');
 modal.removeAttribute('open');
 jobs=[{...jobs[0],status:'completed',imported:3}];
 await pollCTFdJobs('w');
 const background=refreshCount===1&&document.querySelector('#workspace #ctfd-job-area')===null;
 const completedBadge=badge.hidden&&!header.hasAttribute('aria-label');
 modal.setAttribute('open','');
 await pollCTFdJobs('w');
 const reopened=modal.querySelector('#ctfd-job-area').textContent.includes('3개');
 jobs=[{...jobs[0],status:'failed',errors:[{message:'retryable'}]}];
 await pollCTFdJobs('w');
 const retry=!!modal.querySelector('[data-action="retry-ctfd"]');
 const failedBadge=!badge.hidden&&badge.textContent==='실패'&&badge.classList.contains('is-failed')
  &&header.getAttribute('aria-label').includes('실패');
 const fresh=ctfdJobMarkup({...jobs[0],mode:'refresh',target_challenge_id:'c'})
  .includes('data-action="fresh-refresh-ctfd"');
 showCTFdSyncPreview({source_url:'https://ctf.example',challenges:[],new_count:0,existing_count:3,
  source_statuses:[{remote_id:7,challenge_id:'local-7',name:'<img src=x>',state:'hidden'},
   {remote_id:8,challenge_id:'local-8',name:'Other',state:'unlisted'},
   {remote_id:9,challenge_id:'local-9',name:'Visible',state:'visible'}],errors:[]},'w');
 const sourceStatus=modal.querySelectorAll('[data-action="open-ctfd-source-challenge"]').length===2
  &&modal.textContent.includes('원본에서 숨김')&&modal.textContent.includes('원본 목록에서 확인되지 않음')
  &&!modal.querySelector('img')&&modal.textContent.includes('<img src=x>')
  &&importPreview.mode==='sync';
 document.querySelector('#result').textContent=active&&preserved&&background&&reopened&&retry&&fresh
  &&runningBadge&&completedBadge&&failedBadge&&sourceStatus?'PASS':'FAIL '
  +JSON.stringify({active,preserved,background,reopened,retry,fresh,runningBadge,completedBadge,failedBadge,sourceStatus,refreshCount});
})().catch(error=>{document.querySelector('#result').textContent='ERROR '+error.stack});
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-ctfd-modal-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
               "--disable-extensions", f"--user-data-dir={root / 'profile'}",
               "--virtual-time-budget=1000", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            cmd.append("--no-sandbox")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            print(result.stdout[-3000:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: CTFd jobs stay in import dialog; form draft/focus and background completion survive polling")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
