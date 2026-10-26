import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_account_quota_ui_shows_remaining_percent_and_clamps_progress():
    if not shutil.which("node"):
        pytest.skip("node is required for the browser JavaScript regression test")

    source = (ROOT / "ctf_agent" / "web" / "accounts.js").read_text(encoding="utf-8")
    styles = (ROOT / "ctf_agent" / "web" / "accounts.css").read_text(encoding="utf-8")
    assert "iconButton(" not in source
    assert "button('사용량 새로고침'" in source
    assert "button('계정 삭제'" in source
    assert "button('최신 버전 조회'" in source
    assert ".account-list .account-model-summary + .actions" in styles
    source = source.replace("export async function renderAccounts", "async function renderAccounts")
    harness = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(0, 'utf8');

class Node {
  constructor(tag = 'div') {
    this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {};
    this.textContent = ''; this.className = ''; this.hidden = false; this.value = '';
    this.disabled = false;
  }
  append(...items) {
    for (const item of items) {
      if (item == null) continue;
      this.children.push(item); item.parent = this;
      if (item.selected) this.value = item.value;
    }
  }
  prepend(item) { this.children.unshift(item); item.parent = this; }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  contains(item) { return this === item || this.children.some(child => child.contains?.(item)); }
  addEventListener(kind, listener) { this.listeners[kind] = listener; }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelector(selector) {
    return selector === 'a' ? this.walk().find(node => node.tag === 'a') || null : null;
  }
  walk() { return [this, ...this.children.flatMap(child => child.walk?.() || [])]; }
}

const document = {createElement: tag => new Node(tag)};
const container = new Node('main');
const windows = [
  {label: '5시간', used_percent: 0, resets_at: 2},
  {label: '7일', used_percent: 32, resets_at: 3},
  {label: '상한 초과', used_percent: 140, resets_at: 4},
  {label: '하한 미만', used_percent: -20, resets_at: 5},
  {label: '미확정', used_percent: null, resets_at: 6},
];
const account = {id: 'one', label: 'Codex', provider: 'codex', selected: false,
  checked_at: 1, stale: true, login: {status: 'idle'}, snapshot: {
    status: 'auth_required', identity: {}, quota: {stale: true, buckets: [{id: 'codex', windows}]}
  }};
const api = async url => {
  if (url === '/api/accounts') return {accounts: [account]};
  if (url === '/api/providers/codex/runtime') {
    return {version: 'test', operation: {status: 'idle'}, can_manage: false, update_supported: false};
  }
  if (url === '/api/providers/claude/runtime') return {version: '2.1.263', can_manage: false};
  throw new Error(`unexpected ${url}`);
};

const context = {document, window: {setTimeout() {}, confirm: () => true}, navigator: {},
  FormData: class {}, console, container, api};
vm.createContext(context);
vm.runInContext(source, context);

(async () => {
  await vm.runInContext('renderAccounts(container, api)', context);
  const nodes = container.walk();
  const text = nodes.filter(node => node.tag === 'p').map(node => node.textContent);
  const small = nodes.filter(node => node.tag === 'small').map(node => node.textContent);
  assert.ok(text.some(value => value.includes('\uB85C\uADF8\uC778 \uD544\uC694')));
  assert.ok(small.some(value => value.includes('새로고침 필요')));
  assert.ok(text.includes('최근 조회 실패: 아래 사용량은 이전 조회 값입니다.'));
  assert.ok(text.some(value => value.startsWith('5시간: 100% 남음 · 초기화 ')));
  assert.ok(text.some(value => value.startsWith('7일: 68% 남음 · 초기화 ')));
  assert.ok(text.some(value => value.startsWith('상한 초과: 0% 남음 · 초기화 ')));
  assert.ok(text.some(value => value.startsWith('하한 미만: 100% 남음 · 초기화 ')));
  assert.ok(text.some(value => value.startsWith('미확정: 남은 사용량 미제공 · 초기화 ')));

  const meters = nodes.filter(node => node.tag === 'progress');
  assert.deepEqual(meters.map(node => node.value), [100, 68, 0, 100]);
  assert.deepEqual(meters.map(node => node.attributes['aria-label']), [
    '5시간 남은 사용량', '7일 남은 사용량', '상한 초과 남은 사용량', '하한 미만 남은 사용량'
  ]);
  assert.deepEqual(meters.map(node => node.attributes['aria-valuetext']), [
    '100% 남음', '68% 남음', '0% 남음', '100% 남음'
  ]);
  const card = nodes.find(node => node.tag === 'section' && node.className === 'card');
  const bucket = card.children.find(node => node.className === 'quota-bucket');
  const summary = card.children.find(node => node.className === 'account-model-summary');
  const actions = card.children.find(node => node.className === 'actions');
  assert.ok(card.children.indexOf(summary) > card.children.indexOf(bucket));
  assert.ok(card.children.indexOf(summary) < card.children.indexOf(actions));
  assert.equal(summary.textContent, '모델: 계정 기본 · 추론: 계정 기본 · 속도: 기본');
  assert.equal(summary.attributes['aria-label'], '기본 풀이 설정');
  const buttons = nodes.filter(node => node.tag === 'button');
  assert.ok(buttons.some(node => node.textContent === '사용량 새로고침'));
  assert.ok(buttons.some(node => node.textContent === '계정 삭제'));
  assert.ok(!buttons.some(node => ['↻', '⌫'].includes(node.textContent)));
  assert.ok(!buttons.some(node => node.className === 'icon-action'));
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
