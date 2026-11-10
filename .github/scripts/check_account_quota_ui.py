"""Browser regression for account quota state and auth.json upload layout."""

from __future__ import annotations

import shutil
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
    source = (ROOT / "ctf_agent/web/accounts.js").read_text(encoding="utf-8")
    css = "\n".join((ROOT / f"ctf_agent/web/{name}").read_text(encoding="utf-8")
                    for name in ("style.css", "theme.css", "accounts.css"))
    assert "</script" not in source.lower() and "</style" not in css.lower()
    probe = r"""
const windowOf = (label, used) => ({label, used_percent:used, resets_at:null});
const quotaOf = (limited, windows, extra={}) => ({
  status:limited ? 'quota_exceeded' : 'available', limited,
  buckets:[{id:'main',name:'Main',limited,windows}], ...extra,
});
const account = (id, provider, quota, stale=false) => ({
  id,label:id,provider,selected:false,auth_kind:'oauth',checked_at:Date.now()/1000,
  stale,snapshot:{status:'authenticated',identity:{},quota},
});
const items = [
  account('codex-zero-week', 'codex', quotaOf(false,
    [windowOf('5시간',0),windowOf('7일',100)])),
  account('claude-zero-week', 'claude', quotaOf(true,
    [windowOf('5시간',0),windowOf('7일',100)])),
  account('cached-limit', 'claude', quotaOf(true,
    [windowOf('5시간',0),windowOf('7일',100)],{stale:true})),
  account('aged-limit', 'codex', quotaOf(true,
    [windowOf('5시간',0),windowOf('7일',100)]), true),
  account('missing-usage', 'codex', quotaOf(false,
    [windowOf('5시간',null),windowOf('7일',null)])),
];
const api = async path => {
  if (path === '/api/accounts') return {accounts:items};
  if (path.endsWith('/refresh')) return {};
  if (path.endsWith('/models')) return {status:'available',models:[{model:'gpt-6-sol',displayName:'GPT-6 Sol',supportedReasoningEfforts:[{reasoningEffort:'high'}]}]};
  if (path === '/api/providers/codex/runtime' || path === '/api/providers/claude/runtime')
    return {operation:{status:'idle'},can_manage:true,update_supported:true};
  throw new Error('Unexpected API route: '+path);
};
const check = (condition, message) => {if (!condition) throw new Error(message)};
try {
  const state = quotaDisplayState(items[0]);
  check(!state.blocked && state.exhausted, 'Codex zero window must be red, not provider-blocked');
  check(state.buckets[0].windows[0].remaining === 100, 'five-hour 100% remaining');
  check(state.buckets[0].windows[1].remaining === 0, 'weekly 0% remaining');
  check(quotaDisplayState(items[1]).blocked, 'Claude quota-exceeded is blocked');
  const cached = quotaDisplayState(items[2]);
  check(cached.stale && !cached.blocked && !cached.exhausted, 'cached limit is historical');
  const aged = quotaDisplayState(items[3]);
  check(aged.stale && !aged.blocked && !aged.exhausted, 'aged limit is historical');
  check(!quotaDisplayState(items[4]).exhausted, 'unknown usage is not exhausted');
  await renderAccounts(document.querySelector('#root'), api);
  check(!document.querySelector('.runtime-provider'), 'CLI updates are in administrator settings only');
  const card = id => document.querySelector(`.account-list [data-account-id="${id}"]`);
  const codex = card('codex-zero-week');
  check(codex.classList.contains('quota-exhausted') && !codex.classList.contains('quota-limited'),
    'Codex card exhausted styling');
  check(!codex.querySelector('.quota-alert'), 'inferred exhaustion must not say provider-blocked');
  check(codex.querySelectorAll('progress')[0].value === 100, 'five-hour meter');
  check(codex.querySelectorAll('progress')[1].classList.contains('quota-window-exhausted'),
    'weekly meter exhausted');
  const claude = card('claude-zero-week');
  check(claude.classList.contains('quota-limited') && claude.querySelector('.quota-alert'),
    'fresh provider refusal must be explicit');
  const old = card('cached-limit');
  check(old.classList.contains('quota-stale') && !old.classList.contains('quota-limited')
    && !old.querySelector('.quota-alert,.quota-window-exhausted'),
    'cached values must not look like current refusal');
  check(card('aged-limit').classList.contains('quota-stale')
    && !card('aged-limit').querySelector('.quota-alert,.quota-window-exhausted'),
    'aged values must not look like current refusal');
  check(!card('missing-usage').classList.contains('quota-exhausted'), 'unknown usage card');
  const uploadButton = [...codex.querySelectorAll('button')]
    .find(button => button.textContent === 'auth.json 업로드');
  uploadButton.click();
  const form = codex.querySelector('form.auth-upload');
  const button = form?.querySelector('button');
  const file = form?.querySelector('input[type="file"]');
  check(form && button && file, 'upload controls accessible');
  const actionButtons = label => [...codex.querySelectorAll('.actions button')]
    .find(item => item.textContent === label);
  actionButtons('API 키 연결').click();
  const keyForm = codex.querySelector('form.account-api-key');
  const keyInput = keyForm?.querySelector('input');
  check(keyForm && keyInput, 'API key form opens from the action button');
  actionButtons('모델·속도 설정').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  const modelSelect = codex.querySelector('.model-fields select');
  check(modelSelect, 'model form opens from the action button');
  modelSelect.value = 'gpt-6-sol';
  modelSelect.dispatchEvent(new Event('change'));
  const expectedHeight = parseFloat(getComputedStyle(document.querySelector('.account-management'))
    .getPropertyValue('--account-control-height'));
  check(expectedHeight >= 36, 'shared account control height is defined: '+expectedHeight);
  const heights = [...codex.querySelectorAll('.actions button'), button,
    keyForm.querySelector('button'), document.querySelector('.account-create button')]
    .map(item => Math.round(item.getBoundingClientRect().height));
  check(heights.every(item => item === expectedHeight), 'account buttons share one height: '+heights);
  button.focus();
  check(document.activeElement === button, 'upload button keyboard focus');
  document.querySelector('#root').style.width = '320px';
  await new Promise(resolve => requestAnimationFrame(resolve));
  const labelRect = form.querySelector('label').getBoundingClientRect();
  const buttonRect = button.getBoundingClientRect();
  check(Math.round(buttonRect.height) === expectedHeight,
    'compact upload button on narrow view');
  check(buttonRect.top >= labelRect.bottom || buttonRect.left >= labelRect.right,
    'narrow upload controls must not overlap');
  // A background usage refresh rebuilds the card, but open forms and their
  // drafts must stay connected so typing and native pickers are not reset.
  keyInput.value = 'draft-value-for-layout-test';
  actionButtons('사용량 새로고침').click();
  await new Promise(resolve => setTimeout(resolve, 50));
  check(card('codex-zero-week') === codex, 'refresh updates the account card in place');
  check(codex.querySelector('form.account-api-key input') === keyInput
    && keyInput.value === 'draft-value-for-layout-test', 'API key draft survives usage refresh');
  check(codex.querySelector('form.auth-upload') === form, 'auth.json form survives usage refresh');
  check(codex.querySelector('.model-fields select') === modelSelect
    && modelSelect.value === 'gpt-6-sol', 'model dropdown and unsaved selection survive usage refresh');
  check([...codex.querySelectorAll('.actions button')].every(item => item.isConnected)
    && codex.querySelectorAll('.actions button').length >= 6, 'action buttons rebuilt after refresh');
  document.querySelector('#result').textContent='PASS';
} catch (error) {
  document.querySelector('#result').textContent='FAIL '+error.message;
}
"""
    fixture = (
        '<!doctype html><html><meta charset="utf-8"><style>'
        '#root{width:520px;max-width:100%;}'+css+'</style><body>'
        '<div id="root"></div><pre id="result">PENDING</pre>'
        '<script type="module">'+source+'\n'+probe+'</script></body></html>'
    )
    with tempfile.TemporaryDirectory(prefix="ctf-agent-account-quota-") as temp:
        root = Path(temp)
        page = root / "index.html"
        page.write_text(fixture, encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
               "--disable-extensions", "--disable-dev-shm-usage",
               "--virtual-time-budget=5000", "--dump-dom"]
        if sys.platform != "win32":
            cmd.append("--no-sandbox")
        for attempt in range(2):
            result = subprocess.run(
                [*cmd, f"--user-data-dir={root / f'profile-{attempt}'}", page.as_uri()],
                capture_output=True, text=True, timeout=45,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0 and '<pre id="result">PASS</pre>' in result.stdout:
                break
            result_text = re.search(r'<pre id="result">([^<]*)</pre>', result.stdout)
            if result_text and result_text.group(1).startswith("FAIL"):
                break
        else:
            result_text = re.search(r'<pre id="result">([^<]*)</pre>', result.stdout)
        if result.returncode != 0 or '<pre id="result">PASS</pre>' not in result.stdout:
            print("Browser result:", result_text.group(1) if result_text else "not rendered")
            print(result.stderr[-500:])
            return 1
    print("PASS: quota windows, stale state, shared button height, and forms kept across refresh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
