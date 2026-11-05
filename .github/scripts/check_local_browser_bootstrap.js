// Verify that a one-use local ticket leaves browser history before the POST.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const app = fs.readFileSync(path.join(__dirname, '..', '..', 'ctf_agent', 'web', 'app.js'), 'utf8');
const start = app.indexOf('async function bootstrapLocalBrowser() {');
const end = app.indexOf('\n\nrun(async () =>', start);
assert(start >= 0 && end > start);
const method = app.slice(start, end);

(async () => {
  const ticket = 'a'.repeat(32);
  const events = [];
  const window = {
    location: {hash: '#/local-access/' + ticket, pathname: '/', search: ''},
    history: {replaceState(...args) { events.push(['replace', ...args]); }},
  };
  const fetch = async (url, options) => {
    events.push(['fetch', url, options]);
    return {ok: true};
  };
  const bootstrap = vm.runInNewContext(method + '\nbootstrapLocalBrowser', {window, fetch});
  await bootstrap();
  assert.equal(events[0][0], 'replace');
  assert.equal(events[0][3], '/');
  assert.equal(events[1][0], 'fetch');
  assert.equal(events[1][1], '/api/auth/local/bootstrap');
  assert.equal(events[1][2].credentials, 'same-origin');
  assert.deepEqual(JSON.parse(events[1][2].body), {ticket});
  assert(!events[1][2].body.includes('local-access/'));
  console.log('PASS: local browser ticket cleared before exchange');
})().catch(error => { console.error(error); process.exitCode = 1; });
