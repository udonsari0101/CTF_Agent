"""Keep provider update controls grouped and locked while an update runs."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_runtime_sections_and_busy_controls():
    if not shutil.which("node"):
        pytest.skip("node is required for the account UI test")

    root = Path(__file__).resolve().parents[1]
    source = (root / "ctf_agent/web/accounts.js").read_text(encoding="utf-8")
    source = source.replace("export async function renderAccounts", "async function renderAccounts")
    harness = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Node {
  constructor(tag) {
    this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {};
    this.textContent = ''; this.className = ''; this.value = ''; this.disabled = false;
  }
  append(...items) { for (const item of items) { this.children.push(item); item.parent = this; } }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  contains(item) { return this === item || this.children.some(child => child.contains(item)); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  walk() { return [this, ...this.children.flatMap(child => child.walk())]; }
}
const container = new Node('main');
const timers = [];
let codexStatus = 'installing';
let claudeStatus = 'verifying';
const api = async path => {
  if (path === '/api/accounts') return {accounts: []};
  if (path === '/api/providers/codex/runtime') return {
    version: '0.164.0', can_manage: true, update_supported: true,
    operation: {status: codexStatus, version: '0.165.0'},
  };
  if (path === '/api/providers/claude/runtime') return {
    version: '2.1.310', can_manage: true, update_supported: true,
    operation: {status: claudeStatus, version: '2.1.311'},
  };
  throw new Error(`unexpected ${path}`);
};
const context = {document: {createElement: tag => new Node(tag)}, container, api,
  window: {setTimeout: callback => timers.push(callback)}, console};
vm.createContext(context);
vm.runInContext(fs.readFileSync(0, 'utf8'), context);
const sections = () => container.walk().filter(node => node.className === 'runtime-provider');
const controls = section => section.walk().filter(node => node.tag === 'input' || node.tag === 'button');
const flush = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  await vm.runInContext('renderAccounts(container, api)', context);
  assert.equal(sections().length, 2);
  assert.equal(sections()[0].children[0].textContent, 'Codex 업데이트');
  assert.equal(sections()[1].children[0].textContent, 'Claude Code 업데이트');
  assert.equal(controls(sections()[0])[0].attributes['aria-label'], '설치할 Codex 버전');
  assert.equal(controls(sections()[1])[0].attributes['aria-label'], '설치할 Claude Code 버전');
  assert.ok(sections().every(section => controls(section).some(control => control.tag === 'button' && control.textContent === '버전 설치')));
  for (const section of sections()) {
    assert.ok(controls(section).every(control => control.disabled));
    assert.ok(section.walk().some(node => node.tag === 'progress' && !('value' in node.attributes)));
    assert.ok(section.walk().some(node => node.className === 'runtime-progress' && node.attributes.role === 'status'));
  }
  assert.equal(timers.length, 1);
  codexStatus = 'completed'; claudeStatus = 'idle';
  timers.shift()(); await flush(); await flush();
  assert.equal(sections().length, 2);
  assert.ok(sections().every(section => controls(section).every(control => !control.disabled)));
  assert.ok(sections().every(section => !section.walk().some(node => node.tag === 'progress')));
  assert.equal(timers.length, 0);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run(
        ["node", "-e", harness], input=source, text=True, encoding="utf-8",
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
