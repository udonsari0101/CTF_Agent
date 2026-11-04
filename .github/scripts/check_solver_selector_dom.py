"""Browser regression: polling must not detach an open solver model selector."""

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
    implementation = "\n".join((
        section("function solverConfigurationMatchesVisibleForm()", "function solverUltraEscalationEligible()"),
        section("function replaceSolverPanelPreservingConfiguration(", "function paintSolver("),
        section("function repaintSolverConfiguration(", "async function loadSolverConfiguration("),
    ))
    fixture = """<!doctype html><html><body>
<input id="outside"><section id="solver-panel">
 <div class="solver-panel-head">old state</div>
 <div class="solver-configuration">
  <label>Provider<select id="solver-provider-select"><option value="codex">Codex</option></select></label>
  <label>Account<select id="solver-account-select"><option value="a1">a1</option></select></label>
  <label>Model<select id="solver-model-select"><option value="m1">m1</option><option value="m2" selected>m2</option></select></label>
  <label>Reasoning<select id="solver-reasoning-select"><option value="low">low</option></select></label>
 </div><button data-action="start-solver">Start</button>
</section><pre id="result">PENDING</pre><script>
let solverOptionsState='ready',solverProvider='codex',solverAccountId='a1';
let solverModel='m2',solverReasoning='low',solverServiceTier=null,solverUltracode=false;
let solverRetryRequiresSelection=false;
let solverUltraEscalationMode='ask',solverAccounts=[{id:'a1'}],solverModels=[{model:'m2'}];
let currentSolverJob=null,currentSolverEvents=[],nextConfig='';
function solverSelectedAccount(){return solverAccounts.find(x=>x.id===solverAccountId)}
function solverSelectedModel(){return solverModels.find(x=>x.model===solverModel)}
function solverContext(){return true}
function solverIsActive(){return false}
function solverProviderSelector(){return nextConfig}
function solverPanelMarkup(){return '<div>state</div>'+nextConfig+'<button data-action="start-solver">Start</button>'}
""" + implementation + """
const panel=document.querySelector('#solver-panel');
const model=panel.querySelector('#solver-model-select');model.focus();
const initial=solverConfigurationReady()&&document.activeElement===model;
replaceSolverPanelPreservingConfiguration(panel,
 '<div class="solver-panel-head">new state</div><div class="solver-configuration">'
 +'<label>Model<select id="solver-model-select"><option value="m1">m1</option></select></label>'
 +'</div><button data-action="start-solver">Start</button>');
const poll=panel.querySelector('#solver-model-select')===model&&model.isConnected
 &&document.activeElement===model&&model.value==='m2'
 &&panel.textContent.includes('new state');
solverModel='m3';solverReasoning='high';solverModels=[{model:'m3'}];
nextConfig='<div class="solver-configuration">'
 +'<label>Provider<select id="solver-provider-select"><option value="codex">Codex</option></select></label>'
 +'<label>Account<select id="solver-account-select"><option value="a1">a1</option></select></label>'
 +'<label>Model<select id="solver-model-select"><option value="m3">m3</option></select></label>'
 +'<label>Reasoning<select id="solver-reasoning-select"><option value="high">high</option></select></label>'
 +'</div>';
repaintSolverConfiguration('w','c',1);
const staleBlocked=panel.querySelector('#solver-model-select')===model&&model.isConnected
 &&document.activeElement===model&&!solverConfigurationReady()
 &&panel.querySelector('[data-action="start-solver"]').disabled;
document.querySelector('#outside').focus();repaintSolverConfiguration('w','c',1);
const aligned=panel.querySelector('#solver-model-select').value==='m3'
 &&solverConfigurationReady()&&!panel.querySelector('[data-action="start-solver"]').disabled;
const oldLog=document.createElement('details');oldLog.className='solver-session-log';
oldLog.innerHTML='<summary>Session</summary><div class="solver-live-console"><ol><li>first</li></ol></div>';
panel.append(oldLog);
replaceSolverPanelPreservingConfiguration(panel,
 '<div class="solver-panel-head">updated</div>'+nextConfig
 +'<details class="solver-session-log"><summary>Session</summary><div class="solver-live-console"></div></details>',true);
const logRetained=panel.querySelector('.solver-session-log')===oldLog
 &&panel.querySelector('.solver-live-console li')?.textContent==='first';
const activePanel=document.createElement('section');
activePanel.innerHTML='<div>running</div><details class="solver-session-log"><summary>Session</summary><div class="solver-live-console"><ol><li>running</li></ol></div></details>';
const activeLog=activePanel.querySelector('.solver-session-log');
replaceSolverPanelPreservingConfiguration(activePanel,
 '<div>still running</div><details class="solver-session-log"><summary>Session</summary><div class="solver-live-console"></div></details>',true);
const activeLogRetained=activePanel.querySelector('.solver-session-log')===activeLog
 &&activePanel.querySelector('.solver-live-console li')?.textContent==='running';
document.querySelector('#result').textContent=initial&&poll&&staleBlocked&&aligned&&logRetained&&activeLogRetained?'PASS':'FAIL '
 +JSON.stringify({initial,poll,staleBlocked,aligned,logRetained,activeLogRetained});
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-selector-") as temp:
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
    print("PASS: native selector remains connected; stale choice cannot start a job")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
