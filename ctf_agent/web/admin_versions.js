// Read-only CLI version overview. Installing a version requires the explicit
// controls in the Agent page.
const SUCCESS_TTL_MS = 5 * 60 * 1000;
const FAILURE_RETRY_MS = 30 * 1000;
const SOURCES = [{name:'Codex',key:'codex'}, {name:'Claude Code',key:'claude'}];
let cacheScope = '';
const cache = new Map();

function entry(key) {
  if (!cache.has(key)) cache.set(key,{value:'',checkedAt:0,attemptedAt:0,error:'',pending:null});
  return cache.get(key);
}

function fetchVersion(api,key,kind,force=false) {
  const state = entry(`${key}:${kind}`);
  if (state.pending) return state.pending;
  const now = Date.now();
  if (!force && state.attemptedAt && now - state.attemptedAt < (state.error ? FAILURE_RETRY_MS : SUCCESS_TTL_MS)) return Promise.resolve();
  const endpoint = `/api/providers/${key}/${kind === 'current' ? 'runtime' : 'catalog'}`;
  state.attemptedAt = now;
  state.pending = Promise.resolve().then(() => api(endpoint)).then(result => {
    const version = kind === 'current' ? result?.version : result?.latest;
    // An absent runtime is valid; a malformed catalog must not replace the
    // most recent successful lookup.
    if (kind === 'latest' && (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version))) throw new Error('최신 버전 응답을 확인할 수 없습니다.');
    state.value = typeof version === 'string' ? version : '';
    state.checkedAt = Date.now();
    state.error = '';
  }).catch(error => {
    state.error = error?.message || '버전 조회에 실패했습니다.';
  }).finally(() => { state.pending = null; });
  return state.pending;
}

export function renderAdminCliVersions(container,api,{scope='',locale='ko'}={}) {
  if (cacheScope !== scope) { cache.clear(); cacheScope = scope; }
  const en = locale === 'en';
  const heading = document.createElement('div');
  heading.className = 'release-update-head';
  const title = document.createElement('h2');
  title.textContent = en ? 'Agent CLI versions' : '에이전트 CLI 버전';
  const refresh = document.createElement('button');
  refresh.type = 'button';
  refresh.className = 'small ghost';
  refresh.textContent = en ? 'Refresh' : '새로고침';
  const manage = document.createElement('a');
  manage.href = '#accounts';
  manage.className = 'button-link small';
  manage.textContent = en ? 'Update agent CLI' : '에이전트 CLI 업데이트';
  heading.append(title,manage,refresh);
  container.replaceChildren(heading);
  const rows = new Map();
  for (const source of SOURCES) {
    const row = document.createElement('div');
    row.className = 'admin-cli-version-row';
    const name = document.createElement('strong');
    name.textContent = source.name;
    const versions = document.createElement('p');
    const status = document.createElement('small');
    status.setAttribute('role','status');
    status.setAttribute('aria-live','polite');
    row.append(name,versions,status);
    container.append(row);
    rows.set(source.key,{versions,status});
  }

  function paint() {
    if (!container.isConnected) return;
    for (const source of SOURCES) {
      const current = entry(`${source.key}:current`);
      const latest = entry(`${source.key}:latest`);
      const row = rows.get(source.key);
      row.versions.textContent = en
        ? `Current ${current.value || 'Unavailable'} · Latest ${latest.value || 'Unavailable'}`
        : `현재 ${current.value || '확인 불가'} · 최신 ${latest.value || '조회 불가'}`;
      const failures = [current,latest].filter(item => item.error);
      const busy = current.pending || latest.pending;
      row.status.textContent = busy ? (en ? 'Checking…' : '조회 중…')
        : failures.length ? (en ? 'Lookup failed' : '조회 실패') +
          (current.checkedAt || latest.checkedAt ? (en ? ' · showing previous result' : ' · 이전 결과 표시') : '')
        : current.checkedAt || latest.checkedAt ? (en ? 'Checked' : '조회 완료') : (en ? 'Waiting' : '대기');
      row.status.title = failures.map(item => item.error).join(' / ');
    }
    refresh.disabled = SOURCES.some(source => entry(`${source.key}:current`).pending || entry(`${source.key}:latest`).pending);
    refresh.setAttribute('aria-busy',String(refresh.disabled));
  }

  function load(force=false) {
    const requests = SOURCES.flatMap(source => [fetchVersion(api,source.key,'current',force),fetchVersion(api,source.key,'latest',force)]);
    paint();
    for (const request of requests) request.then(paint);
  }
  refresh.addEventListener('click',() => load(true));
  paint();
  // Slow/offline registries never block the administrator page.
  load();
}
