"""Browser regression for expanded solver log grouping and retained UI state."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")
CSS = (ROOT / "ctf_agent/web/theme.css").read_text(encoding="utf-8")


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
    assert "${solverEventMarkup(events)}" in section("function solverSessionMarkup(", "function toggleSolverLogSize(")
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = "\n".join((
        section("function solverEventLabel(", "function solverAgentNodes("),
        section("function solverAgentNodes(", "function solverGuidanceHistoryMarkup("),
        section("function toggleSolverLogSize(", "function solverWriteup("),
    ))
    fixture = """<!doctype html><html><head><meta charset="utf-8"><style>""" + CSS + """</style></head><body>
<dialog id="detail" open><button class="solver-log-size-toggle"></button></dialog><pre id="result">PENDING</pre><script>
const detail=document.querySelector('#detail');
const esc=x=>String(x??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const i18n={locale:'en',t:x=>x};
const tr=value=>esc(i18n.t(value));
const solverProgress={},solverPhases={};
const solverEventSequence=e=>Number(e.sequence)||0;
const solverIsActive=()=>true;
const solverJobId=j=>j?.id||'';
const solverCollapsedAgentIds=new Set(),solverConsoleCardStates=new Map();
let solverConsoleAgentId='root',solverConsoleFollowLatest=true,solverLogExpanded=false;
let solverConsoleDialog=null,solverGuidanceDraft='';
let currentChallenge={name:'Example'},currentSolverJob={id:'job-1',provider:'claude',phase:'running',agents:[]};
let currentSolverEvents=[
 {kind:'activity',sequence:1,activity_id:'a'.repeat(32),phase:'started',tool:'shell',summary:'Run solver',command:'python solver.py',created_at:1},
 {kind:'activity',sequence:2,activity_id:'a'.repeat(32),phase:'completed',tool:'shell',summary:'Run solver',output:'Flag found',exit_code:0,duration_ms:321,created_at:2},
 ...Array.from({length:35},(_,index)=>({kind:'progress',sequence:index+3,code:'step',created_at:index+3})),
];
""" + implementation + """
try {
  toggleSolverLogSize();
  const stream=solverConsoleDialog.querySelector('.solver-console-stream');
  const first=stream.querySelector('.solver-console-card');
  const initial=!!first&&first.querySelector('pre')?.textContent.includes('python solver.py')
    &&first.querySelector('.solver-console-field:last-child pre')?.textContent.includes('Flag found')
    &&stream.querySelectorAll('.solver-console-card').length===36
    &&first.matches('details')&&!first.open
    &&stream.querySelectorAll('details.solver-console-card').length===1
    &&solverConsoleDialog.querySelector('[name="requested_delivery"]').disabled;
  first.open=true;
  first.dispatchEvent(new Event('toggle'));
  currentSolverEvents.push({kind:'progress',sequence:38,code:'step',created_at:38});
  paintSolverConsole();
  const openRetained=first.open&&stream.querySelector('.solver-console-card')===first;
  first.open=false;
  first.dispatchEvent(new Event('toggle'));
  currentSolverEvents.push({kind:'progress',sequence:39,code:'step',created_at:39});
  paintSolverConsole();
  const stableCard=stream.querySelector('.solver-console-card');
  const retained=stableCard===first&&stableCard.open===false;
  stream.scrollTop=0;
  stream.dispatchEvent(new Event('scroll'));
  currentSolverEvents.push({kind:'progress',sequence:40,code:'step',created_at:40});
  paintSolverConsole();
  const retainedNode=stream.querySelector('.solver-console-card')===stableCard;
  const paused=!solverConsoleFollowLatest&&stream.scrollTop===0
    &&!solverConsoleDialog.querySelector('.solver-console-bottom').classList.contains('hidden');
  solverConsoleBottom();
  const resumed=solverConsoleFollowLatest&&solverConsoleAtBottom(stream)
    &&solverConsoleDialog.querySelector('.solver-console-bottom').classList.contains('hidden');
  const separate=document.createElement('div');
  separate.className='solver-console-stream'; document.body.append(separate);
  const source=[{kind:'progress',sequence:10,code:'step',created_at:10},
    {kind:'progress',sequence:11,code:'step',created_at:11}];
  reconcileSolverConsoleTimeline(separate,source);
  const oldCard=separate.querySelector('[data-log-key="event:10"]');
  source.unshift({kind:'progress',sequence:9,code:'step',created_at:9});
  reconcileSolverConsoleTimeline(separate,source);
  const backfill=separate.querySelector('.solver-console-card')?.dataset.logKey==='event:9'
    &&separate.querySelector('[data-log-key="event:10"]')===oldCard;
  const pending=document.createElement('div');
  pending.className='solver-console-stream'; document.body.append(pending);
  reconcileSolverConsoleTimeline(pending,[{kind:'activity',sequence:60,activity_id:'b'.repeat(32),
    phase:'started',tool:'shell',summary:'Working',command:'echo pending',message:'still running',created_at:60}]);
  const noEmptyExpand=pending.querySelectorAll('details').length===0;
  const compact=document.createElement('details');
  const compactEvents=[{kind:'progress',sequence:50,code:'step',created_at:50},
    {kind:'progress',sequence:51,code:'step',created_at:51}];
  compact.innerHTML='<summary><b>2</b><span class="solver-live-state live">LIVE</span></summary>'
    +'<div class="solver-live-console">'+solverEventMarkup(compactEvents)+'</div>';
  const compactFirst=compact.querySelector('li');
  compactEvents.push({kind:'progress',sequence:52,code:'step',created_at:52});
  reconcileCompactSolverLog(compact,compactEvents,false);
  const compactIncremental=compact.querySelector('li')===compactFirst
    &&compact.querySelectorAll('li').length===3
    &&compact.querySelector('summary b').textContent==='3'
    &&compact.querySelector('.solver-live-state').textContent==='END';
  currentSolverJob={id:'job-2',provider:'codex',phase:'running',agents:[]};
  currentSolverEvents=[];
  paintSolverConsole();
  const changed=solverConsoleDialog.querySelector('.solver-console-head small').textContent==='job-2'
    &&!solverConsoleDialog.querySelector('[name="requested_delivery"]').disabled
    &&!solverConsoleDialog.querySelector('.solver-console-card');
  document.querySelector('#result').textContent=initial&&openRetained&&retained&&retainedNode&&paused&&resumed&&backfill&&noEmptyExpand&&compactIncremental&&changed?'PASS'
    :'FAIL '+JSON.stringify({initial,openRetained,retained,retainedNode,paused,resumed,backfill,noEmptyExpand,compactIncremental,changed,count:stream.querySelectorAll('.solver-console-card').length});
} catch(error) { document.querySelector('#result').textContent='ERROR '+error.stack; }
</script></body></html>"""
    with tempfile.TemporaryDirectory(prefix="ctf-agent-solver-console-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        command = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
                   "--disable-extensions", f"--user-data-dir={root / 'profile'}",
                   "--virtual-time-budget=1000", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            print(result.stdout[-3000:])
            print(result.stderr[-1000:])
            return 1
    print("PASS: expanded timeline groups tool calls, retains cards and scroll; compact log unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
