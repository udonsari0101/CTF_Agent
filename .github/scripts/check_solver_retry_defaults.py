"""Browser regression for restoring the last solve's exact account and model settings."""

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
    assert SOURCE.count("loadSolverConfiguration(workspaceId,challengeId,generation,'',normalized.job)") == 3
    assert "solverConfigurationJobId !== solverJobId(normalized.job)" in SOURCE
    assert "'confirm-solver-retry-settings':" in SOURCE
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = "\n".join((
        section("function solverRetryConfiguration(job)", "function solverConfigurationMatchesVisibleForm()"),
        section("function solverConfigurationMatchesVisibleForm()", "function solverContinuationMarkup("),
        section("async function loadSolverConfiguration(", "async function loadSolver("),
    ))
    fixture = """<!doctype html><html><body><section id="solver-panel"></section>
<pre id="result">PENDING</pre><script>
const A='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', B='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', C='cccccccccccccccccccccccccccccccc';
let solverProvider='codex', solverAccounts=[], solverAccountId='', solverModels=[], solverModel='';
let solverReasoning='', solverServiceTier=null, solverUltracode=false, solverOptionsState='idle', solverOptionsError='';
let solverUltraEscalationMode='ask', solverRetryIssue='', solverRetryRequiresSelection=false;
let solverConfigurationJobId='', solverOptionsGeneration=0, currentSolverJob=null;
const esc=value=>String(value??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
const accounts=[
 {id:A,label:'same label',provider:'codex',selected:true,model:'base',reasoning_effort:'low',snapshot:{status:'authenticated'}},
 {id:B,label:'same label',provider:'codex',model:'base',reasoning_effort:'low',snapshot:{status:'authenticated'}},
 {id:C,label:'Claude',provider:'claude',model:'sonnet',reasoning_effort:'medium',snapshot:{status:'authenticated'}}
];
const catalog={
 [A]:[{model:'base',supportedReasoningEfforts:[{reasoningEffort:'low'}],serviceTiers:[]}],
 [B]:[{model:'base',supportedReasoningEfforts:[{reasoningEffort:'low'}],serviceTiers:[]},
      {model:'special',supportedReasoningEfforts:[{reasoningEffort:'xhigh'},{reasoningEffort:'ultra'}],serviceTiers:[{id:'fast'}]}],
 [C]:[{model:'sonnet',supportedReasoningEfforts:[{reasoningEffort:'medium'}],supportsUltracode:false}]
};
function solverJobId(job){return job?.id||''}
function solverContext(){return true}
function repaintSolverConfiguration(){document.querySelector('#solver-panel').innerHTML=solverProviderSelector()}
async function api(url){return url==='/api/accounts'?{accounts}:{status:'available',models:catalog[url.split('/')[3]]}}
""" + implementation + """
const codexJob={id:'job-1',job_mode:'solve',account_id:B,account_label:'same label',
 configuration:{provider:'codex',model:'special',reasoning_effort:'xhigh',service_tier:'fast'},
 ultra_escalation:{mode:'auto'}};
const claudeJob={id:'job-2',job_mode:'solve',account_id:C,account_label:'Claude',
 configuration:{provider:'claude',model:'opus-old',reasoning_effort:'xhigh',service_tier:null,ultracode:true},
 ultra_escalation:{mode:'off'}};
(async()=>{
 const checks={};
 currentSolverJob=codexJob;
 await loadSolverConfiguration('w','c',1,'',codexJob);
 checks.exact=solverAccountId===B&&solverModel==='special'&&solverReasoning==='xhigh'
  &&solverServiceTier==='fast'&&solverUltraEscalationMode==='auto'&&solverConfigurationReady();
 checks.form=document.querySelector('#solver-account-select').value===B
  &&document.querySelector('#solver-model-select').value==='special'
  &&document.querySelector('#solver-reasoning-select').value==='xhigh'
  &&document.querySelector('#solver-fast-toggle').checked;
 accounts.splice(1,1);
 await loadSolverConfiguration('w','c',1,'',codexJob);
 checks.missingAccount=solverAccountId===A&&solverRetryRequiresSelection&&!solverConfigurationReady()
  &&document.querySelector('.solver-retry-warning')?.textContent.includes('계정')
  &&!!document.querySelector('[data-action="confirm-solver-retry-settings"]');
 clearSolverRetryWarning();repaintSolverConfiguration();
 checks.confirm=solverConfigurationReady()&&!document.querySelector('.solver-retry-warning');
 accounts.splice(1,0,{id:B,label:'same label',provider:'codex',model:'base',reasoning_effort:'low',snapshot:{status:'signed_out'}});
 await loadSolverConfiguration('w','c',1,'',codexJob);
 checks.signedOut=solverRetryIssue.includes('다시 로그인')&&!solverConfigurationReady();
 accounts.splice(1,1,{id:B,label:'same label',provider:'codex',model:'base',reasoning_effort:'low',snapshot:{status:'authenticated'}});
 catalog[B]=catalog[B].slice(0,1);
 await loadSolverConfiguration('w','c',1,'',codexJob);
 checks.missingModel=solverRetryIssue.includes('이전 모델')&&solverRetryIssue.includes('이전 추론 수준')
  &&solverRetryIssue.includes('Fast')&&solverRetryIssue.includes('Ultra 전환')&&!solverConfigurationReady();
 currentSolverJob=claudeJob;
 await loadSolverConfiguration('w','c',1,'',claudeJob);
 checks.claude=solverProvider==='claude'&&solverAccountId===C&&solverRetryIssue.includes('Ultracode')
  &&!solverUltracode&&!solverConfigurationReady();
 solverProvider='codex';
 await loadSolverConfiguration('w','c',1,A);
 checks.manual=solverProvider==='codex'&&solverAccountId===A&&!solverRetryIssue&&solverConfigurationReady();
 document.querySelector('#result').textContent=Object.values(checks).every(Boolean)?'PASS':'FAIL '+JSON.stringify(checks);
})().catch(error=>document.querySelector('#result').textContent='ERROR '+error.stack);
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-retry-defaults-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
               "--disable-extensions", f"--user-data-dir={root / 'profile'}",
               "--virtual-time-budget=1500", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            cmd.append("--no-sandbox")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            print(result.stdout[-3500:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: exact retry defaults; unavailable settings require explicit reselection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
