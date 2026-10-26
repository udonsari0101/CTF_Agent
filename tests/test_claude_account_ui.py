"""Exercise the browser login handoff with a late Claude OAuth URL."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_claude_login_link_arrives_without_erasing_entered_code():
    if not shutil.which("node"):
        pytest.skip("node is required for the account UI test")
    source = (Path(__file__).resolve().parents[1] / "ctf_agent/web/accounts.js").read_text(encoding="utf-8")
    source = source.replace("export async function renderAccounts", "async function renderAccounts")
    harness = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Node {
  constructor(tag) {
    this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {};
    this.textContent = ''; this.className = ''; this.value = ''; this.hidden = false;
  }
  append(...items) { for (const item of items) { this.children.push(item); item.parent = this; } }
  prepend(item) { this.children.unshift(item); item.parent = this; }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  contains(item) { return this === item || this.children.some(child => child.contains(item)); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  walk() { return [this, ...this.children.flatMap(child => child.walk())]; }
  querySelector(selector) { return this.walk().find(node => node.tag === selector) || null; }
}
const document = {createElement: tag => new Node(tag)};
const container = new Node('main');
const timers = [];
const copied = [];
const sent = [];
const url = 'https://claude.ai/oauth/authorize?state=test';
const account = {id: 'one', label: 'Claude', provider: 'claude', selected: true,
  snapshot: {status: 'signed_out'}, login: {status: 'pending'}};
let polls = 0;
let failCode = true;
let releaseCode;
const api = async (path, options = {}) => {
  if (path === '/api/accounts') return {accounts: [account]};
  if (path === '/api/providers/codex/runtime') return {operation: {}, can_manage: false};
  if (path === '/api/providers/claude/runtime') return {version: '2.1.263', can_manage: false};
  if (path === '/api/accounts/one/login' && !options.method) {
    return {status: 'pending', accepts_code: true, ...(polls++ ? {verification_url: url} : {})};
  }
  if (path === '/api/accounts/one/login/code') {
    sent.push(options.body.code);
    await new Promise(resolve => { releaseCode = resolve; });
    if (failCode) throw new Error('try again');
    return {status: 'pending'};
  }
  throw new Error(`unexpected ${path}`);
};
const context = {document, container, api, console,
  window: {setTimeout: callback => timers.push(callback), confirm: () => true},
  navigator: {clipboard: {writeText: async text => copied.push(text)}}};
vm.createContext(context);
vm.runInContext(fs.readFileSync(0, 'utf8'), context);
const flush = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  await vm.runInContext('renderAccounts(container, api)', context);
  const text = () => container.walk().map(node => node.textContent);
  assert.ok(text().some(value => value.includes('브라우저의 로그인 완료 화면')));
  const code = container.walk().find(node => node.attributes['aria-label'] === 'Claude 인증 코드');
  assert.ok(code);
  code.value = 'browser-code#state';
  assert.equal(container.walk().find(node => node.textContent === 'Claude 로그인 페이지 열기'), undefined);
  await timers.shift()();
  assert.equal(code.value, 'browser-code#state');
  const link = container.walk().find(node => node.textContent === 'Claude 로그인 페이지 열기');
  assert.equal(link.href, url);
  const copy = container.walk().find(node => node.textContent === '링크 복사');
  copy.listeners.click(); await flush();
  assert.deepEqual(copied, [url]);
  const form = container.walk().find(node => node.tag === 'form' && node.children.includes(code));
  const send = form.children.find(node => node.tag === 'button');
  form.listeners.submit({preventDefault() {}}); await flush();
  assert.equal(send.disabled, true);
  assert.equal(code.disabled, true);
  assert.equal(form.attributes['aria-busy'], 'true');
  assert.ok(form.walk().some(node => node.className === 'account-login-spinner'));
  form.listeners.submit({preventDefault() {}}); await flush();
  assert.deepEqual(sent, ['browser-code#state']);
  releaseCode(); await flush();
  assert.equal(send.disabled, false);
  assert.equal(code.disabled, false);
  assert.equal(code.value, 'browser-code#state');
  failCode = false;
  form.listeners.submit({preventDefault() {}}); await flush();
  assert.deepEqual(sent, ['browser-code#state', 'browser-code#state']);
  assert.equal(send.disabled, true);
  releaseCode(); await flush();
  assert.equal(code.value, '');
  assert.equal(send.disabled, true);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run(
        ["node", "-e", harness],
        input=source,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
