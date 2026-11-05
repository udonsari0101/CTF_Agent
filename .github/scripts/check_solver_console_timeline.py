"""Browser regression for expanded solver log grouping and retained UI state."""

from __future__ import annotations

import json
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


REQUIRED_ENGLISH = {
    # Expanded session log and its steering composer.
    "모델 응답": "Model response", "내용": "Content", "결과": "Result", "명령": "Command",
    "일부만 표시": "Truncated", "↓ 맨 아래": "↓ Latest", "세션 로그 닫기": "Close session log",
    "메인 세션 추가 명령": "Instruction for the main session",
    "현재 턴에 개입": "Deliver in current turn", "다음 턴에 전달": "Deliver in next turn",
    "풀이 방향이나 확인할 내용을 입력": "Enter a direction or detail to check",
    # Account actions: the Korean and English labels must name the same action.
    "auth.json 업로드": "Upload auth.json", "auth.json 가져오기": "Import auth.json",
    "API 키 연결": "Connect API key", "모델 설정 저장": "Save model settings",
    "URL 또는 nc host port": "URL or nc host port", "남음": "remaining",
}


def check_i18n() -> None:
    duplicates: list[str] = []

    def reject_duplicates(items: list[tuple[str, object]]) -> dict[str, object]:
        seen: dict[str, object] = {}
        for key, value in items:
            if key in seen:
                duplicates.append(key)
            seen[key] = value
        return seen

    packs = {}
    for locale in ("en", "ko"):
        text = (ROOT / f"ctf_agent/web/i18n/{locale}.json").read_text(encoding="utf-8")
        packs[locale] = json.loads(text, object_pairs_hook=reject_duplicates)
        assert packs[locale]["locale"] == locale
    # A duplicate key silently lets the later value win, so conflicting
    # translations never reach the user as written.
    assert not duplicates, f"duplicate i18n keys: {sorted(set(duplicates))}"
    messages = packs["en"]["messages"]
    wrong = {key: messages.get(key) for key, value in REQUIRED_ENGLISH.items() if messages.get(key) != value}
    assert not wrong, f"missing or changed English labels: {wrong}"
    assert all(isinstance(value, str) and value.strip() for value in messages.values())
    assert all(isinstance(value, str) and value.strip() for value in packs["ko"]["messages"].values())


def main() -> int:
    assert "${solverEventMarkup(events)}" in section("function solverSessionMarkup(", "function toggleSolverLogSize(")
    check_i18n()
    browser = browser_path()
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = "\n".join((
        section("function solverEventLabel(", "function solverAgentNodes("),
        section("function solverAgentNodes(", "function solverGuidanceHistoryMarkup("),
        section("function toggleSolverLogSize(", "function solverWriteup("),
    ))
    english = json.loads((ROOT / "ctf_agent/web/i18n/en.json").read_text(encoding="utf-8"))["messages"]
    translations = json.dumps(english, ensure_ascii=False).replace("</", "<\\/")
    fixture = """<!doctype html><html><head><meta charset="utf-8"><style>""" + CSS + """</style></head><body>
<dialog id="detail" open><button class="solver-log-size-toggle"></button></dialog><pre id="result">PENDING</pre><script>
const detail=document.querySelector('#detail');
const esc=x=>String(x??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const translations=""" + translations + """;
const i18n={locale:'en',t:x=>translations[x]||x};
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
  const draftField=solverConsoleDialog.querySelector('#solver-console-message');
  draftField.value='keep this draft';
  currentSolverEvents.push({kind:'activity',sequence:70,phase:'completed',tool:'analysis',summary:'모델 응답',
    message:'Readable answer\\nsecond line',created_at:70});
  paintSolverConsole();
  const replyCard=stream.querySelector('[data-log-key="event:70"]');
  const reply=replyCard?.querySelector('.solver-console-reply');
  const readable=!!replyCard&&replyCard.classList.contains('message')&&!replyCard.matches('details')
    &&!replyCard.querySelector('details,pre')&&reply.textContent.includes('Readable answer')
    &&reply.textContent.includes('second line')&&reply.getBoundingClientRect().height>0;
  const englishLabels=replyCard.querySelector('.solver-console-card-title strong')?.textContent==='Model response'
    &&solverConsoleDialog.querySelector('.solver-console-head .solver-console-bottom')?.textContent==='↓ Latest'
    &&solverConsoleDialog.querySelector('#solver-console-guidance-form label')?.textContent==='Instruction for the main session'
    &&solverConsoleDialog.querySelector('#solver-console-message')?.placeholder==='Enter a direction or detail to check'
    &&first.querySelector('.solver-console-field-head strong')?.textContent==='Command';
  const draftKept=solverConsoleDialog.querySelector('#solver-console-message')===draftField
    &&draftField.value==='keep this draft';
  const expandableCard=stream.querySelector('details.solver-console-card');
  const plainCard=stream.querySelector('.solver-console-card.static:not(.message)');
  const distinct=!!expandableCard&&!!plainCard
    &&getComputedStyle(expandableCard.querySelector('summary'),'::after').content.includes('▸')
    &&getComputedStyle(expandableCard).borderLeftWidth!=='0px'
    &&getComputedStyle(plainCard).borderLeftWidth==='0px';
  currentSolverJob.agents=[{id:'agent-a',parent_id:'root',label:'Worker',status:'running'}];
  currentSolverEvents.push({kind:'activity',sequence:71,agent_id:'agent-a',phase:'completed',tool:'analysis',
    summary:'모델 응답',message:'Worker answer',created_at:71});
  paintSolverConsole();
  selectSolverAgent({dataset:{agentId:'agent-a'}});
  currentSolverEvents.push({kind:'activity',sequence:72,agent_id:'agent-a',phase:'completed',tool:'analysis',
    summary:'모델 응답',message:'Second worker answer',created_at:72});
  paintSolverConsole();
  const agentKept=solverConsoleAgentId==='agent-a'
    &&!!solverConsoleDialog.querySelector('.solver-agent-select.selected[data-agent-id="agent-a"]')
    &&stream.querySelectorAll('.solver-console-card').length===2
    &&solverConsoleDialog.querySelector('#solver-console-message')===draftField
    &&draftField.value==='keep this draft';
  solverConsoleAgentId='root'; paintSolverConsole();
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
  document.querySelector('#result').textContent=initial&&openRetained&&retained&&retainedNode&&paused&&resumed&&readable&&englishLabels&&draftKept&&distinct&&agentKept&&backfill&&noEmptyExpand&&compactIncremental&&changed?'PASS'
    :'FAIL '+JSON.stringify({initial,openRetained,retained,retainedNode,paused,resumed,readable,englishLabels,draftKept,distinct,agentKept,backfill,noEmptyExpand,compactIncremental,changed,count:stream.querySelectorAll('.solver-console-card').length});
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
    print("PASS: expanded timeline shows model replies inline, marks only real details as expandable, "
          "retains cards, drafts, subagent and scroll; compact log unchanged; i18n labels aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
