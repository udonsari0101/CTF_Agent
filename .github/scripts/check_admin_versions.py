"""Browser regression for administrator-only provider CLI updates."""
import shutil
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ctf_agent/web/admin_versions.js").read_text(encoding="utf-8")
APP = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")
ACCOUNTS = (ROOT / "ctf_agent/web/accounts.js").read_text(encoding="utf-8")


def main():
    assert APP.count("renderAdminCliVersions(document.querySelector('#admin-cli-version-panel')") == 2
    assert 'class="settings-card account-runtime"' in APP
    assert "runtimeControls(" not in ACCOUNTS
    browser = next((shutil.which(n) for n in ("chrome", "msedge", "chromium", "google-chrome")
                    if shutil.which(n)), None)
    if not browser:
        for candidate in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                          r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"):
            if Path(candidate).exists():
                browser = candidate
                break
    if not browser:
        print("SKIP: Chrome/Chromium is not installed")
        return 0
    implementation = SOURCE.replace("export function renderAdminCliVersions", "function renderAdminCliVersions")
    fixture = """<!doctype html><meta charset="utf-8"><body><section id="versions"></section>
<pre id="result">PENDING</pre><script>""" + implementation + """
const root=document.querySelector('#versions'),tick=()=>new Promise(r=>setTimeout(r,0));
let calls=[],version='0.164.0',operation={status:'idle'},holdCatalog=false;
const api=(url,options={})=>{
  calls.push({url,options});
  if(holdCatalog&&url.endsWith('/catalog')) return new Promise(()=>{});
  if(url.endsWith('/catalog')) return Promise.resolve({latest:url.includes('/codex/')?'0.166.0':'2.1.310'});
  if(url.endsWith('/update')) {
    if(url.includes('/codex/')) {version=options.body.version;operation={status:'completed',version};}
    return Promise.resolve(operation);
  }
  return Promise.resolve({version:url.includes('/codex/')?version:'2.1.300',
    operation:url.includes('/codex/')?operation:{status:'idle'},
    can_manage:true,update_supported:true,selected:url.includes('/codex/')});
};
const settle=async()=>{for(let i=0;i<8;i++) await tick()};
(async()=>{
  renderAdminCliVersions(root,api,{scope:'admin-a'});await settle();
  const rows=[...root.querySelectorAll('.runtime-provider')],codex=rows[0];
  const button=(row,name)=>[...row.querySelectorAll('button')].find(b=>b.textContent===name);
  const initial=rows.length===2&&root.textContent.includes('현재 0.164.0 · 최신 0.166.0')
    &&root.textContent.includes('현재 2.1.300 · 최신 2.1.310')
    &&button(codex,'최신 버전으로 업데이트')&&button(rows[1],'버전 설치')
    &&button(codex,'이전 버전으로 복원');
  codex.querySelector('input').value='bad';button(codex,'버전 설치').click();await settle();
  const invalid=!calls.some(c=>c.url.endsWith('/update'))&&codex.textContent.includes('정확한 숫자 버전');
  button(codex,'최신 버전으로 업데이트').click();await settle();
  const updates=calls.filter(c=>c.url.endsWith('/update'));
  const installed=updates.length===1&&updates[0].options.body.version==='0.166.0'
    &&codex.textContent.includes('현재 0.166.0')&&codex.textContent.includes('업데이트 완료');
  const next=document.createElement('section');root.replaceWith(next);
  renderAdminCliVersions(next,api,{scope:'admin-a'});await settle();
  const reentry=next.textContent.includes('현재 0.166.0');
  holdCatalog=true;
  const third=document.createElement('section');next.replaceWith(third);
  renderAdminCliVersions(third,api,{scope:'admin-b'});await settle();
  const direct=third.querySelector('.runtime-provider');
  const manual=button(direct,'버전 설치');
  const independent=!manual.disabled;
  direct.querySelector('input').value='0.165.0';manual.click();await settle();
  const installWithoutCatalog=independent&&calls.filter(c=>c.url.endsWith('/update')).length===2
    &&version==='0.165.0';
  document.querySelector('#result').textContent=initial&&invalid&&installed&&reentry&&installWithoutCatalog?'PASS':
    'FAIL '+JSON.stringify({initial:!!initial,invalid,installed,reentry,installWithoutCatalog,calls,text:third.textContent});
})().catch(e=>document.querySelector('#result').textContent='ERROR '+e.stack);
</script></body>"""
    with tempfile.TemporaryDirectory(prefix="ctf-admin-cli-updates-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
               f"--user-data-dir={root / 'profile'}", "--virtual-time-budget=2500", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            cmd.append("--no-sandbox")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            state = re.search(r'<pre id="result">([^<]*)</pre>', result.stdout)
            print(state.group(1) if state else "Browser result not rendered")
            print(result.stderr[-1000:])
            return 1
    print("PASS: admin CLI install controls, validation, update status, and re-entry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
