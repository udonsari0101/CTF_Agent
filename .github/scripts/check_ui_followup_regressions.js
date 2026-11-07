// Focused regressions for the UI follow-up review. No external server or browser is needed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', '..', 'ctf_agent/web/app.js'), 'utf8');
const section = (start, end) => {
  const first = source.indexOf(start), last = source.indexOf(end, first + start.length);
  assert(first >= 0 && last > first, `missing section: ${start}`);
  return source.slice(first, last);
};
const evaluate = (code, value, globals = {}) => vm.runInNewContext(`${code}\n${value}`, {URL, ...globals});
const esc = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const tests = [];
const test = (name, callback) => tests.push([name, callback]);

test('slow list polling accepts a response within the first-page limit', () => {
  const first = Number(source.match(/const PAGE_LOAD_LIMIT_MS = (\d+)/)?.[1]);
  const slow = Number(source.match(/CHALLENGE_LIST_SLOW_TIMEOUT = ([A-Z_0-9]+)/)?.[1]) ||
    (source.includes('CHALLENGE_LIST_SLOW_TIMEOUT = PAGE_LOAD_LIMIT_MS') ? first : 0);
  assert(first >= 12000);
  assert(slow >= first, `slow polling ${slow} ms is shorter than initial load ${first} ms`);
});

test('backticks inside a link URL stay in the URL while code spans remain code', () => {
  const markdownInline = evaluate(section('function markdownInline(', 'function safeMarkdown('), 'markdownInline', {esc});
  const html = markdownInline('[t](http://x/?cmd=`id`) and `http://x`');
  assert(html.includes('<a href="http://x/?cmd=`id`"'), html);
  assert(html.includes('<code>http://x</code>'), html);
  assert(!html.includes('<a href="http://x"'), html);
});

test('stale list freezes card time but keeps the open solver panel ticking', () => {
  const now = Date.now();
  const workspace = {listStaleAt: now - 5000, gone: false};
  const elapsedClock = evaluate(section('function elapsedClock(', 'function challengeInputMarkup('), 'elapsedClock', {
    currentWorkspace: workspace, i18n: {t: value => value}, challengeElapsedText: ({elapsed_seconds}) => String(elapsed_seconds), esc,
  });
  assert(Math.abs(elapsedClock() * 1000 - now) < 2000, 'open panel time stopped on a list error');
  assert(Math.abs(elapsedClock(true) * 1000 - workspace.listStaleAt) < 2000, 'list card time did not freeze');
  workspace.gone = true;
  assert(Math.abs(elapsedClock() * 1000 - workspace.listStaleAt) < 2000, 'deleted workspace time did not freeze');
  assert(source.includes('solverElapsedMarkup(latestRun,true)'), 'list card does not opt into stale-list clock');
});

test('setup failures focus the token or username field, not password', async () => {
  const submitCredentials = evaluate(section('async function submitCredentials(', 'function showLogin('), 'submitCredentials', {
    runForm: async callback => callback(), toast: () => {}, transferErrorText: error => error.message,
  });
  for (const [status, expected] of [[403, 'setup_token'], [409, 'username']]) {
    let focused = '', selected = '';
    const fields = Object.fromEntries(['password', 'setup_token', 'username'].map(name => [name, {
      focus() { focused = name; }, select() { selected = name; },
    }]));
    const notice = {textContent: '', scrollIntoView() {}};
    const form = {id: 'setup-form', isConnected: true,
      querySelector(selector) { return selector === '.login-error' ? notice : fields[selector.match(/name="([^"]+)"/)?.[1]]; }};
    await submitCredentials(form, async () => { throw Object.assign(new Error('failed'), {status}); });
    assert.equal(focused, expected);
    assert.equal(selected, expected);
  }
});

test('workspace 404 preserves an active direct-send modal', () => {
  const workspace = {id: 'a'.repeat(32)};
  const modal = {open: true, dataset: {kind: 'direct-send'}, close() { this.open = false; }};
  const directSendState = {status: 'sending'};
  evaluate(section('function renderWorkspaceNotFound(', 'function leaveGoneWorkspace('), 'renderWorkspaceNotFound()', {
    currentWorkspace: workspace, modal, directSendState, detail: {open: false}, solverConsoleDialog: null,
    rememberNotes() {}, modalInputAtRisk() { return false; },
    leaveWorkspacePage() {}, shell() {}, showPageNotice() {}, workspaceNotFoundMarkup() {},
    paintLiveNotices() {}, toast() {}, i18n: {t: value => value}, directSendActive: state => state.status === 'sending',
  });
  assert(modal.open, 'active transfer modal was closed');
});

test('empty challenge-list response keeps a source-language error for later translation', () => {
  const challengeListResult = evaluate(section('function challengeListResult(', 'function challengeListUpdated('), 'challengeListResult', {
    i18n: {t: () => 'Please reload the challenges.'},
  });
  assert.throws(() => challengeListResult({}), error =>
    error.message === '문제 목록을 다시 불러와 주세요.');
});

test('non-JSON auth state shows the boot failure rather than a login form', async () => {
  let login = false, failure = false;
  const boot = evaluate(section('async function boot()', 'async function bootstrapLocalBrowser()'), 'boot', {
    bootAttempt: 0, signedOut: false, i18n: {init: () => Promise.resolve()},
    bootstrapLocalBrowser: async () => {}, pageRequest: async () => ({}),
    showLogin() { login = true; }, showBootFailure() { failure = true; }, unanswered: error => error,
  });
  await boot();
  assert.equal(login, false);
  assert.equal(failure, true);
});

test('an already authenticated local browser skips the unnecessary ticket exchange', async () => {
  let exchanges = 0, cleared = 0, renders = 0;
  const window = {location: {hash: '#/local-access/' + 'a'.repeat(32), pathname: '/', search: ''},
    history: {replaceState() { cleared++; }}};
  const boot = evaluate(section('async function boot()', 'async function bootstrapLocalBrowser()'), 'boot', {
    bootAttempt: 0, signedOut: false, pendingLocalTicket: '', window,
    i18n: {init: () => Promise.resolve()},
    bootstrapLocalBrowser: async () => { exchanges++; return true; },
    pageRequest: async () => ({auth_mode: 'nologin', authenticated: true, csrf_token: 'ok', user: {username: 'local'}}),
    sessionStarted() {}, render: async () => { renders++; }, showBootFailure(error) { throw error; },
  });
  await boot();
  assert.equal(exchanges, 0);
  assert.equal(cleared, 1);
  assert.equal(renders, 1);
});

test('Telegram module follows the versioned app asset namespace', () => {
  assert(source.includes("import(new URL('./telegram.js', import.meta.url))"));
  assert.equal(new URL('./telegram.js', 'https://example.test/assets/abc123/app.js').pathname,
    '/assets/abc123/telegram.js');
});

(async () => {
  let failed = 0;
  for (const [name, callback] of tests) {
    try { await callback(); console.log(`OK ${name}`); }
    catch (error) { failed++; console.error(`DEFECT ${name}: ${error.message}`); }
  }
  if (failed) process.exitCode = 1;
  console.log(`RESULT: ${tests.length - failed} OK, ${failed} DEFECT`);
})().catch(error => { console.error(error); process.exitCode = 1; });
