// Administrator-only CLI version lookup and installation controls.
// The TTL covers the registry lookup only; the runtime is read on every entry.
const SUCCESS_TTL_MS = 5 * 60 * 1000;
const FAILURE_RETRY_MS = 30 * 1000;
const VERSION_FORMAT = /^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$/;
const SOURCES = [
  {name:'Codex',key:'codex',example:'0.164.0'},
  {name:'Claude Code',key:'claude',example:'2.1.310'},
];
let cacheScope = '';
let activeLanguageListener = null;
let activeTimer = null;
let activeRender = 0;
const cache = new Map();

function entry(key) {
  if (!cache.has(key)) cache.set(key,{value:'',runtime:null,checkedAt:0,attemptedAt:0,error:'',pending:null});
  return cache.get(key);
}

function fetchVersion(api,key,kind,force=false) {
  const state = entry(`${key}:${kind}`);
  if (state.pending) return state.pending;
  const now = Date.now();
  if (kind === 'latest' && !force && state.attemptedAt &&
      now - state.attemptedAt < (state.error ? FAILURE_RETRY_MS : SUCCESS_TTL_MS)) return Promise.resolve();
  const endpoint = `/api/providers/${key}/${kind === 'current' ? 'runtime' : 'catalog'}`;
  state.attemptedAt = now;
  state.pending = Promise.resolve().then(() => api(endpoint)).then(result => {
    const version = kind === 'current' ? result?.version : result?.latest;
    // An absent runtime is valid; a malformed catalog must not replace the
    // most recent successful lookup.
    if (kind === 'latest' && (typeof version !== 'string' || !VERSION_FORMAT.test(version))) throw new Error('최신 버전 응답을 확인할 수 없습니다.');
    if (kind === 'current') state.runtime = result;
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
  clearTimeout(activeTimer);
  const renderId = ++activeRender;
  const live = () => container.isConnected && renderId === activeRender;
  const english = () => (globalThis.ctfI18n?.locale || locale) === 'en';
  const label = (ko,en) => english() ? en : ko;
  const heading = document.createElement('div');
  heading.className = 'release-update-head';
  const title = document.createElement('h2');
  const refresh = document.createElement('button');
  refresh.type = 'button';
  refresh.className = 'small ghost';
  heading.append(title,refresh);
  container.replaceChildren(heading);
  const rows = new Map();
  for (const source of SOURCES) {
    const row = document.createElement('section');
    row.className = 'runtime-provider';
    const name = document.createElement('h3');
    name.textContent = source.name;
    const versions = document.createElement('p');
    const status = document.createElement('p');
    status.setAttribute('role','status');
    status.setAttribute('aria-live','polite');
    const progress = document.createElement('progress');
    progress.hidden = true;
    const controls = document.createElement('div');
    controls.className = 'runtime-controls';
    const version = document.createElement('input');
    version.setAttribute('aria-label',label(`${source.name} 설치 버전`,`${source.name} version to install`));
    const check = document.createElement('button');
    const latest = document.createElement('button');
    const install = document.createElement('button');
    const rollback = document.createElement('button');
    const bundled = document.createElement('button');
    for (const button of [check,latest,install,rollback,bundled]) button.type = 'button';
    controls.append(version,check,latest,install,rollback);
    if (source.key === 'codex') controls.append(bundled);
    row.append(name,versions,status,progress,controls);
    container.append(row);
    rows.set(source.key,{versions,status,progress,version,check,latest,install,rollback,bundled,actionBusy:false,actionError:''});
  }

  function paint() {
    if (!live()) return;
    title.textContent = label('에이전트 CLI 업데이트','Agent CLI updates');
    refresh.textContent = label('새로고침','Refresh');
    let anyBusy = false;
    for (const source of SOURCES) {
      const current = entry(`${source.key}:current`);
      const catalog = entry(`${source.key}:latest`);
      const row = rows.get(source.key);
      const operation = current.runtime?.operation || {};
      const installing = ['installing','verifying'].includes(operation.status);
      const busy = Boolean(current.pending || row.actionBusy || installing);
      anyBusy ||= busy || Boolean(catalog.pending);
      row.versions.textContent = label(
        `현재 ${current.value || '확인 불가'} · 최신 ${catalog.value || '조회 불가'}`,
        `Current ${current.value || 'Unavailable'} · Latest ${catalog.value || 'Unavailable'}`);
      const operationLabel = {
        installing:label('설치 중','Installing'), verifying:label('검증 중','Verifying'),
        completed:label('업데이트 완료','Update completed'), failed:label('업데이트 실패','Update failed'),
        interrupted:label('업데이트 중단','Update interrupted')
      }[operation.status];
      const failures = [current.error,catalog.error,row.actionError].filter(Boolean);
      row.status.textContent = failures.length && !installing
        ? `${label('확인 실패','Lookup failed')}: ${failures.join(' / ')}`
        : operationLabel
          ? `${operationLabel}${operation.version ? ` · ${operation.version}` : ''}${operation.message ? ` · ${operation.message}` : ''}`
        : busy || catalog.pending ? label('조회 중…','Checking…')
        : current.runtime?.update_supported === false ? label('이 환경에서는 웹 업데이트를 지원하지 않습니다.','Web updates are unavailable in this environment.')
        : current.checkedAt || catalog.checkedAt ? label('조회 완료','Checked') : label('대기','Waiting');
      row.status.classList.toggle('error-text',Boolean(failures.length || ['failed','interrupted'].includes(operation.status)));
      row.status.classList.toggle('runtime-progress',installing);
      row.progress.hidden = !installing;
      row.progress.setAttribute('aria-label',`${source.name} ${operationLabel || ''}`);
      row.check.textContent = label('최신 버전 조회','Check latest');
      row.latest.textContent = label('최신 버전으로 업데이트','Update to latest');
      row.install.textContent = label('버전 설치','Install version');
      row.rollback.textContent = label('이전 버전으로 복원','Restore previous version');
      row.rollback.hidden = !current.runtime?.selected;
      if (source.key === 'codex') {
        row.bundled.textContent = label('이미지에 포함된 Codex 사용','Use bundled Codex');
        row.bundled.hidden = !current.runtime?.selected;
        row.bundled.disabled = busy || current.runtime?.can_manage !== true;
      }
      const canManage = current.runtime?.can_manage === true && current.runtime?.update_supported !== false;
      for (const button of [row.check,row.latest]) button.disabled = busy || Boolean(catalog.pending) || !canManage;
      for (const button of [row.install,row.rollback]) button.disabled = busy || !canManage;
      row.version.disabled = installing || row.actionBusy || !canManage;
      row.version.placeholder = label(`버전 (예: ${source.example})`,`Version (e.g. ${source.example})`);
      row.version.setAttribute('aria-label',label(`${source.name} 설치 버전`,`${source.name} version to install`));
    }
    refresh.disabled = anyBusy;
    refresh.setAttribute('aria-busy',String(anyBusy));
  }

  function schedulePoll() {
    clearTimeout(activeTimer);
    if (!live()) return;
    if (SOURCES.some(source => ['installing','verifying'].includes(entry(`${source.key}:current`).runtime?.operation?.status))) {
      activeTimer = setTimeout(() => { if (live()) loadCurrent(); },3000);
    }
  }

  function loadCurrent() {
    const requests = SOURCES.map(source => fetchVersion(api,source.key,'current',true));
    paint();
    Promise.all(requests).then(() => { paint(); schedulePoll(); });
  }

  function load(force=false) {
    const currentRequests = SOURCES.map(source => fetchVersion(api,source.key,'current',true));
    const catalogRequests = SOURCES.map(source => fetchVersion(api,source.key,'latest',force));
    paint();
    for (const request of [...currentRequests,...catalogRequests]) request.then(paint);
    Promise.all(currentRequests).then(schedulePoll);
  }

  async function action(source,task) {
    const row = rows.get(source.key);
    if (row.actionBusy) return;
    row.actionBusy = true;
    row.actionError = '';
    paint();
    try {
      await task();
      await fetchVersion(api,source.key,'current',true);
    } catch (error) {
      row.actionError = error?.message || label('요청에 실패했습니다.','Request failed.');
    } finally {
      row.actionBusy = false;
      paint();
      schedulePoll();
    }
  }

  for (const source of SOURCES) {
    const row = rows.get(source.key);
    row.check.addEventListener('click',() => action(source,async () => {
      await fetchVersion(api,source.key,'latest',true);
      if (entry(`${source.key}:latest`).error) throw new Error(entry(`${source.key}:latest`).error);
      row.version.value = entry(`${source.key}:latest`).value;
    }));
    const update = value => {
      if (!VERSION_FORMAT.test(value)) throw new Error(label('정확한 숫자 버전을 입력해 주세요.','Enter an exact numeric version.'));
      return api(`/api/providers/${source.key}/update`,{method:'POST',body:{version:value}});
    };
    row.latest.addEventListener('click',() => action(source,async () => {
      await fetchVersion(api,source.key,'latest',true);
      const catalog = entry(`${source.key}:latest`);
      if (catalog.error || !catalog.value) throw new Error(catalog.error || label('최신 버전을 확인하지 못했습니다.','Latest version unavailable.'));
      row.version.value = catalog.value;
      const operation = await update(catalog.value);
      entry(`${source.key}:current`).runtime = {...entry(`${source.key}:current`).runtime,operation};
    }));
    row.install.addEventListener('click',() => action(source,async () => {
      const operation = await update(row.version.value.trim());
      entry(`${source.key}:current`).runtime = {...entry(`${source.key}:current`).runtime,operation};
    }));
    row.rollback.addEventListener('click',() => action(source,async () => {
      await api(`/api/providers/${source.key}/rollback`,{method:'POST'});
    }));
    if (source.key === 'codex') row.bundled.addEventListener('click',() => action(source,async () => {
      await api('/api/providers/codex/use-bundled',{method:'POST'});
    }));
  }
  refresh.addEventListener('click',() => load(true));
  const onLanguageChanged = () => {
    if (live()) paint();
    else {
      document.removeEventListener('ctf-language-changed',onLanguageChanged);
      if (activeLanguageListener === onLanguageChanged) activeLanguageListener = null;
    }
  };
  if (activeLanguageListener) document.removeEventListener('ctf-language-changed',activeLanguageListener);
  activeLanguageListener = onLanguageChanged;
  document.addEventListener('ctf-language-changed',onLanguageChanged);
  paint();
  // Slow/offline registries never block the administrator page.
  load();
}
