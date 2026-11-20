"""Verify challenge card Ctrl/Cmd and Shift selection in a real browser."""

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

    start = SOURCE.index("function challengeSelectionStats(")
    end = SOURCE.index("async function stopSelectedChallenges(", start)
    implementation = SOURCE[start:end]
    fixture = """<!doctype html><html><body>
<main id="challenge-area">
 <div class="challenge-bulk-toolbar">
  <span class="challenge-selection-count"></span>
  <button data-action="select-visible-challenges">Select all</button>
  <button data-action="stop-selected-challenges">Stop selected</button>
  <button data-action="trash-selected-challenges">Trash selected</button>
  <button data-action="clear-challenge-selection">Clear selection</button>
 </div>
 <div class="challenge-card-grid">
  <article class="challenge-card" data-challenge-id="a"><input type="checkbox" data-action="select-challenge"><h3>A</h3><div class="challenge-card-actions"><button>Action</button></div></article>
  <article class="challenge-card" data-challenge-id="b"><input type="checkbox" data-action="select-challenge"><h3>B</h3></article>
  <article class="challenge-card" data-challenge-id="c"><input type="checkbox" data-action="select-challenge"><h3>C</h3></article>
  <article class="challenge-card" data-challenge-id="d"><input type="checkbox" data-action="select-challenge"><h3>D</h3></article>
 </div>
</main><pre id="result">PENDING</pre><script>
const i18n={t:s=>s,format:(s,values)=>s.replace(/\\{(\\w+)\\}/g,(_,key)=>values[key]??'')};
const tr=s=>s,esc=s=>String(s??'').replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');
const selectedChallengeIds=new Set();let selectionAnchorId='',bulkStopBusy=false;
let selectedStatus='',selectedCategory='',selectedSort='added_desc',search='';
const statuses={running:'Running',pending:'Pending'},solverTerminalPhases=new Set(['completed','failed']);
const challengeListing={result:{challenges:[
  {id:'a',name:'A',status:'pending'},{id:'b',name:'B',status:'pending'},
  {id:'c',name:'C',status:'running'},{id:'d',name:'D',status:'pending'}
]}};
function challengeHasActiveSolve(challenge){return challenge.status==='running'}
""" + implementation + """
const result=document.querySelector('#result');
function assert(ok,label){if(!ok)throw Error(label)}
function selected(){return [...selectedChallengeIds].sort().join(',')}
function card(id){return document.querySelector(`[data-challenge-id="${id}"]`)}
function click(id,opts={},target='h3'){
 const event=new MouseEvent('click',{bubbles:true,cancelable:true,...opts});
 card(id).querySelector(target).dispatchEvent(event);
 return event;
}
document.querySelector('#challenge-area').addEventListener('click',event=>selectChallengeFromModifiedClick(event));
try{
 syncChallengeSelection();
 assert(selected()===''&&document.querySelector('[data-action="stop-selected-challenges"]').disabled,'initial toolbar disables bulk stop');
 click('a',{ctrlKey:true});
 assert(selected()==='a'&&card('a').classList.contains('is-selected')&&card('a').querySelector('input').checked,'Ctrl selects card');
 click('c',{shiftKey:true});
 assert(selected()==='a,b,c','Shift selects contiguous range from anchor');
 assert(!document.querySelector('[data-action="stop-selected-challenges"]').disabled,'active selected can stop');
 click('c',{metaKey:true});
 assert(selected()==='a,b','Cmd toggles selected card off');
 click('d',{ctrlKey:true});
 assert(selected()==='a,b,d','Ctrl adds another card');
 click('b',{shiftKey:true});
 assert(selected()==='a,b,c,d','Shift range uses latest unmodified anchor');
 selectChallenge('c');
 assert(selected()==='a,b,d','checkbox toggles selected card');
 const before=selected();
 click('a',{ctrlKey:true},'.challenge-card-actions button');
 assert(selected()===before,'action buttons do not change selection');
 click('c');
 assert(selected()===before,'ordinary card click leaves selection unchanged');
 assert(document.querySelector('.challenge-selection-count').textContent.includes('3'),'selection count updates');
 selectedChallengeIds.clear();selectionAnchorId='';syncChallengeSelection();
 assert(selected()===''&&document.querySelector('[data-action="clear-challenge-selection"]').disabled,'clear selection updates toolbar');
 result.textContent='PASS';
}catch(error){result.textContent='ERROR '+error.stack}
</script></body></html>"""

    with tempfile.TemporaryDirectory(prefix="ctf-agent-challenge-selection-") as temporary:
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
    print("PASS: Ctrl/Cmd toggle, Shift range, action exclusion, and bulk toolbar state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
