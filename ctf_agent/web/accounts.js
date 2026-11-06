const i18n = globalThis.ctfI18n || {locale:'ko',t:value=>value,format:(value,values) => value.replace(/\{(\w+)\}/g,(hole,name) => values[name] ?? hole)};
const localized = (ko, en) => i18n.locale === 'en' ? en : ko;

const el = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};

// Names, models and account details: the page translator must not treat them as labels.
const dataEl = (tag, text, className) => {
  const node = el(tag, text, className);
  node.setAttribute('data-i18n-ignore', '');
  return node;
};

function createNotice() {
  const node = el('p', '', 'notice');
  node.setAttribute('role', 'status');
  node.setAttribute('aria-live', 'polite');
  node.hidden = true;
  return {node, set(text, isError = false) {
    node.textContent = text;
    node.hidden = !text.trim();
    node.classList.toggle('error-notice', isError && !node.hidden);
  }};
}

async function copyText(value) {
  const text = String(value ?? '');
  if (window.isSecureContext !== false && typeof navigator.clipboard?.writeText === 'function') {
    let timeout;
    try {
      // Invoke while the click still has transient user activation.
      const writing = navigator.clipboard.writeText(text);
      await Promise.race([
        writing,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error(i18n.t('클립보드 응답이 지연되었습니다.'))), 1200); }),
      ]);
      return 'unverified';
    } catch { /* The text remains available for manual copying. */ }
    finally { clearTimeout(timeout); }
  }
  showManualCopy(text);
  return 'manual';
}

function showManualCopy(text) {
  const dialog = el('dialog', undefined, 'modal copy-select-dialog');
  const heading = el('h2', i18n.t('직접 복사'));
  const guidance = el('p', i18n.t('내용을 선택한 상태입니다. Ctrl+C를 누르세요.'));
  const area = el('textarea');
  area.readOnly = true;
  area.value = text;
  area.setAttribute('aria-label', i18n.t('복사할 내용'));
  const close = el('button', i18n.t('닫기'));
  close.type = 'button';
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => dialog.remove(), {once:true});
  dialog.append(heading,guidance,area,close);
  document.body.append(dialog);
  dialog.showModal();
  area.focus(); area.select();
}

const date = seconds => seconds != null ? new Date(seconds * 1000).toLocaleString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US', {timeZone: 'Asia/Seoul'}) + ' KST' : i18n.t('미제공');
const labels = {authenticated: '로그인됨', signed_out: '로그아웃됨', cli_missing: 'CLI 미설치', provider_error: '조회 실패',
  provider_unavailable: '연결 불가', pending: '인증 대기', completed: '로그인 완료', failed: '로그인 실패', expired: '로그인 만료',
  cancelled: '로그인 취소', starting: '로그인 준비 중', idle: '로그인 전', timeout: '응답 시간 초과', unsupported: '지원되지 않음', unavailable: '정보 없음'};
labels.auth_required = '\uB85C\uADF8\uC778 \uD544\uC694';
const quotaLimitLabels = {
  rate_limit_reached: '사용량 구간 한도에 도달했습니다.',
  workspace_owner_credits_depleted: '워크스페이스 소유자 크레딧이 소진되었습니다.',
  workspace_member_credits_depleted: '워크스페이스 사용자 크레딧이 소진되었습니다.',
  workspace_owner_usage_limit_reached: '워크스페이스 소유자 사용 한도에 도달했습니다.',
  workspace_member_usage_limit_reached: '워크스페이스 사용자 사용 한도에 도달했습니다.',
};

// Providers report computed windows such as 90분 or Opus 7일, so the language
// pack cannot list every label.
const windowUnits = {일:'day', 시간:'hour', 분:'minute'};
function quotaWindowLabel(label) {
  const text = String(label ?? '');
  const translated = i18n.t(text);
  const match = i18n.locale === 'en' && translated === text && /^(.*?)([\d.]+)(일|시간|분)$/.exec(text);
  return match ? `${match[1]}${match[2]} ${windowUnits[match[3]]}${match[2] === '1' ? '' : 's'}` : translated;
}

const VERSION_FORMAT = /^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$/;
const runtimeStatusLabels = {installing:'설치 중', verifying:'검증 중', completed:'업데이트 완료', failed:'업데이트 실패', interrupted:'업데이트 중단'};
const runtimeBusy = info => ['installing', 'verifying'].includes(info?.operation?.status);
const runtimeSources = [
  {key:'codex', name:'Codex', title:'Codex 업데이트', adminOnly:'Codex 업데이트는 관리자만 실행할 수 있습니다.',
    placeholder:'버전 (예: 0.164.0)', versionLabel:'설치할 Codex 버전', latestMissing:'최신 Codex 버전을 확인하지 못했습니다.'},
  {key:'claude', name:'Claude Code', title:'Claude Code 업데이트', adminOnly:'Claude Code 업데이트는 관리자만 실행할 수 있습니다.',
    placeholder:'버전 (예: 2.1.310)', versionLabel:'설치할 Claude Code 버전', latestMissing:'최신 Claude Code 버전을 확인하지 못했습니다.'},
];

const proIdentity = identity => [identity?.planType,identity?.subscriptionType]
  .some(value => String(value || '').toLowerCase().split(/[^a-z0-9]+/).includes('pro'));

function orderedQuotaBuckets(quota, identity) {
  const buckets = Array.isArray(quota?.buckets) ? quota.buckets : [];
  if (!proIdentity(identity)) return buckets;
  const priority = bucket => {
    const id = String(bucket?.id || '').toLowerCase();
    const name = String(bucket?.name || '').toLowerCase();
    const combined = `${id} ${name}`;
    if (combined.includes('spark')) return 2;
    if (id === 'codex' || /(^|[^a-z0-9])codex([^a-z0-9]|$)/.test(combined)) return 0;
    return 1;
  };
  return buckets.map((bucket,index) => ({bucket,index})).sort((left,right) =>
    priority(left.bucket) - priority(right.bucket) || left.index - right.index).map(item => item.bucket);
}

function quotaRemaining(used) {
  return typeof used === 'number' && Number.isFinite(used)
    ? Math.max(0, Math.min(100, 100 - used)) : null;
}

// A zero-remaining window deserves a visible warning, but only a current
// provider limit/status can say that execution is blocked. Cached snapshots
// from a failed refresh are historical readings, not a live refusal.
export function quotaDisplayState(account) {
  const quota = account?.snapshot?.quota || {};
  const stale = account?.stale === true || quota.stale === true;
  const readable = quota.status === 'available' || quota.status === 'quota_exceeded';
  const buckets = orderedQuotaBuckets(quota, account?.snapshot?.identity)
    .filter(bucket => bucket && typeof bucket === 'object').map(bucket => {
      const windows = (Array.isArray(bucket.windows) ? bucket.windows : [])
        .filter(window => window && typeof window === 'object').map(window => {
        const remaining = quotaRemaining(window.used_percent);
        return {window, remaining, exhausted: !stale && readable && remaining === 0};
      });
      return {bucket, windows, blocked: !stale && bucket.limited === true,
        exhausted: windows.some(item => item.exhausted)};
    });
  return {stale, buckets,
    blocked: !stale && (quota.limited === true || quota.status === 'quota_exceeded'),
    exhausted: buckets.some(item => item.exhausted)};
}

export async function renderAccounts(container, api, options = {}) {
  // Set by the #admin 'Update agent CLI' link: land on the update controls.
  const revealRuntime = globalThis.ctfAccountsTarget === 'runtime';
  delete globalThis.ctfAccountsTarget;
  container.replaceChildren();
  const shell = el('section', undefined, 'account-management');
  container.append(shell);
  const pageHead = el('div', undefined, 'page-head');
  const titleGroup = el('div');
  const eyebrow = el('div', 'AGENTS', 'eyebrow');
  const heading = el('h1', '에이전트');
  titleGroup.append(eyebrow, heading);
  pageHead.append(titleGroup);
  heading.setAttribute('tabindex', '-1');
  const returnActions = typeof options.onReturnToChallenge === 'function' ? el('div', undefined, 'actions') : null;
  if (returnActions) {
    const returnButton = el('button', '문제로 돌아가기', 'primary');
    returnButton.type = 'button';
    returnButton.addEventListener('click', options.onReturnToChallenge);
    returnActions.append(returnButton);
  }
  // Background usage status stays apart from the action notices, so neither
  // can erase the other. Action results appear beside the control that failed.
  const usageStatus = createNotice();
  const feedback = createNotice();
  const errorText = error => {
    const providerCode = String(error.provider_code || '').toUpperCase();
    const policy = error.code === 'policy_security' || error.category === 'policy_security' || /^(TAC|CVP)(?:[-_]|$)/.test(providerCode);
    const httpFailure = /^요청에 실패했습니다 \((\d+)\)\.$/.exec(error.message || '');
    return [httpFailure ? localized(error.message, `Request failed (${httpFailure[1]}).`) : i18n.t(error.message || '요청에 실패했습니다.'), providerCode,
      error.stage && `${i18n.t('단계')}: ${error.stage}`, error.retryable === false && i18n.t('자동 재시도하지 않습니다.'),
      policy && i18n.t('보안 작업 정책 제한입니다. 다른 모델을 선택하거나 계정 권한을 확인하세요.')].filter(Boolean).join(' · ');
  };
  const accounts = el('div', undefined, 'account-list');
  const runtime = el('section', undefined, 'card account-runtime');
  const form = el('form', undefined, 'card account-create');
  const provider = el('select');
  provider.setAttribute('aria-label', '계정 제공자');
  for (const [value, name] of [['codex', 'Codex'], ['claude', 'Claude Code']]) {
    const option = el('option', name); option.value = value; provider.append(option);
  }
  const authKind = el('select');
  authKind.setAttribute('aria-label', '계정 연결 방식');
  for (const [value, name] of [['oauth', '브라우저 로그인'], ['api_key', 'API 키']]) {
    const option = el('option', name); option.value = value; authKind.append(option);
  }
  const label = el('input');
  label.placeholder = '계정 이름 (예: 개인 Plus)'; label.required = true; label.maxLength = 100;
  label.setAttribute('aria-label', '계정 이름');
  const submit = el('button', '계정 추가'); submit.type = 'submit';
  form.append(provider, authKind, label, submit);
  if (returnActions) pageHead.append(returnActions);
  shell.append(pageHead);
  shell.append(form, usageStatus.node, feedback.node, accounts, runtime);
  heading.focus?.();
  let stopped = false;
  let loadGeneration = 0;
  let runtimeLoadGeneration = 0;
  let runtimePollFailures = 0;
  let runtimeTimer = null;
  let buttonCount = 0;
  const runtimeStates = new Map(runtimeSources.map(source => [source.key, {info:null, error:'', notice:createNotice()}]));
  const loginGeneration = new WeakMap();
  const modelTargets = new Map();
  const formTargets = new Map();
  const active = () => !stopped && container.contains(accounts);
  async function quietly(task, notice) {
    try { return await task(); }
    catch (error) { notice.set(errorText(error), true); }
  }
  async function action(task, notice = feedback) {
    notice.set('');
    try { return await task(); }
    catch (error) {
      notice.set(errorText(error), true);
      notice.node.scrollIntoView({block:'nearest'});
    }
  }
  // Refreshes rebuild the action rows and a busy button loses focus. Return
  // focus to the matching control unless the user already moved elsewhere.
  function restoreFocus(key) {
    if (!key || (document.activeElement && document.activeElement !== document.body)) return;
    const target = shell.querySelector(`[data-focus-key="${CSS.escape(key)}"]`);
    (target?.disabled ? target.parentElement.querySelector('button:not(:disabled)') : target)?.focus({preventScroll:true});
  }
  function button(text, task, notice = feedback, focusKey = `button-${++buttonCount}`) {
    const node = el('button', text); node.type = 'button';
    node.dataset.focusKey = focusKey;
    node.addEventListener('click', () => action(async () => {
      const focused = document.activeElement === node;
      // Invoke first so clipboard writes retain the click's user activation.
      const pending = task();
      node.disabled = true;
      try { return await pending; } finally {
        node.disabled = false;
        if (focused) restoreFocus(focusKey);
      }
    }, notice));
    return node;
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    action(async () => {
      submit.disabled = true;
      try { await api('/api/accounts', {method: 'POST', body: {provider: provider.value, auth_kind: authKind.value, label: label.value}}); label.value = ''; await load(); }
      finally { submit.disabled = false; }
    });
  });

  async function showLogin(account, target, start) {
    const generation = (loginGeneration.get(target) || 0) + 1;
    loginGeneration.set(target, generation);
    const current = () => active() && container.contains(target) && loginGeneration.get(target) === generation;
    const {notice} = formTargets.get(account.id);
    let result = await api(`/api/accounts/${account.id}/login`, start ? {method: 'POST'} : {});
    if (!current()) return;
    target.replaceChildren();
    target.append(el('p', labels[result.status] || result.status));
    if (result.message) target.append(el('p', result.message));
    if (result.error) target.append(el('p', errorText(result.error), 'error-text'));
    const isClaudeLogin = account.provider === 'claude' && ['starting', 'pending'].includes(result.status);
    let claudeLink = null;
    const renderClaudeLink = state => {
      if (!claudeLink) return;
      claudeLink.replaceChildren();
      if (!state.verification_url) {
        claudeLink.append(el('p', 'Claude 인증 링크를 준비 중입니다.'));
        return;
      }
      const link = el('a', 'Claude 로그인 페이지 열기');
      link.href = state.verification_url; link.target = '_blank'; link.rel = 'noopener noreferrer';
      claudeLink.append(link, button('링크 복사', async () => {
        const result = await copyText(state.verification_url);
        notice.set(result === 'manual' ? '링크를 선택했습니다. Ctrl+C를 눌러 복사하세요.' : '복사를 시도했습니다. 링크가 필요하면 직접 열어 주소를 복사하세요.');
      }, notice));
    };
    if (isClaudeLogin) {
      const guide = el('div', undefined, 'claude-login-guide');
      claudeLink = el('div', undefined, 'claude-login-link');
      guide.append(
        el('p', '1. 아래 링크를 열어 Claude 계정으로 로그인하세요.'),
        claudeLink,
        el('p', '2. 브라우저의 로그인 완료 화면에 코드가 표시되면 복사해 아래에 붙여넣으세요. 코드 없이 자동 완료되면 기다리면 됩니다.'),
      );
      target.append(guide);
      renderClaudeLink(result);
    } else if (result.verification_url) {
      const link = el('a', '공식 사이트에서 로그인');
      link.href = result.verification_url; link.target = '_blank'; link.rel = 'noopener noreferrer';
      target.append(link);
    }
    if (result.user_code) target.append(el('pre', result.user_code));
    if (result.accepts_code && result.status === 'pending') {
      const codeForm = el('form');
      const code = el('input'); code.type = 'password'; code.autocomplete = 'off'; code.placeholder = 'Claude 로그인 완료 화면의 코드';
      code.setAttribute('aria-label', 'Claude 인증 코드'); code.maxLength = 4096; code.required = true;
      const send = el('button', '인증 코드 전달'); send.type = 'submit';
      const progress = el('p', '', 'claude-login-progress');
      progress.setAttribute('role', 'status'); progress.setAttribute('aria-live', 'polite'); progress.hidden = true;
      let submitted = false;
      const setSubmitting = (busy, message = '') => {
        send.disabled = busy; code.disabled = busy;
        codeForm.setAttribute('aria-busy', busy ? 'true' : 'false');
        send.replaceChildren();
        if (busy) {
          const spinner = el('span', undefined, 'account-login-spinner');
          spinner.setAttribute('aria-hidden', 'true');
          send.append(spinner, el('span', '인증 중...'));
        } else send.textContent = '인증 코드 전달';
        progress.textContent = message; progress.hidden = !message;
      };
      codeForm.append(code, send, progress);
      codeForm.addEventListener('submit', async event => {
        event.preventDefault();
        if (submitted || !code.value.trim()) return;
        submitted = true;
        notice.set('');
        setSubmitting(true, '인증 코드를 전송하고 로그인 완료를 확인 중입니다.');
        try {
          await api(`/api/accounts/${account.id}/login/code`, {method: 'POST', body: {code: code.value.trim()}});
          if (current()) code.value = '';
        } catch (error) {
          if (current()) {
            submitted = false;
            setSubmitting(false);
            notice.set(errorText(error), true);
          }
        }
      });
      target.append(codeForm);
    }
    if (['starting', 'pending'].includes(result.status)) {
      target.append(button('로그인 취소', async () => {
        await api(`/api/accounts/${account.id}/login/cancel`, {method: 'POST'});
        await showLogin(account, target, false);
      }, notice));
      // Poll status without replacing an in-progress code input.
      const poll = async () => {
        if (!current()) return;
        try {
          const previousStatus = result.status;
          result = await api(`/api/accounts/${account.id}/login`);
          if (!current()) return;
          if (previousStatus === 'starting' && result.status === 'pending') {
            await showLogin(account, target, false);
            return;
          }
          if (['starting', 'pending'].includes(result.status)) {
            if (isClaudeLogin) {
              renderClaudeLink(result);
            } else if (!target.querySelector('a') && result.verification_url) {
              const link = el('a', '공식 사이트에서 로그인'); link.href = result.verification_url;
              link.target = '_blank'; link.rel = 'noopener noreferrer'; target.prepend(link);
            }
            window.setTimeout(poll, 2500);
          } else {
            target.replaceChildren(el('p', labels[result.status] || result.status));
            if (result.message) target.append(el('p', result.message));
            if (result.error) target.append(el('p', errorText(result.error), 'error-text'));
            if (result.status === 'completed') { modelTargets.delete(account.id); await api(`/api/accounts/${account.id}/refresh`, {method: 'POST'}); await load(); target.replaceChildren(); }
          }
        } catch (error) {
          if (current()) {
            notice.set(errorText(error), true);
            if (error.retryable !== false) window.setTimeout(poll, 5000);
          }
        }
      };
      window.setTimeout(poll, 2500);
    } else if (result.status === 'completed' && start) {
      modelTargets.delete(account.id);
      await api(`/api/accounts/${account.id}/refresh`, {method: 'POST'});
      await load();
      target.replaceChildren();
    }
  }

  async function showModels(account, target) {
    const data = await api(`/api/accounts/${account.id}/models`);
    if (!active() || !container.contains(target)) return;
    target.replaceChildren();
    if (data.status !== 'available') { target.append(el('p', data.message || '모델 목록을 제공하지 않습니다.')); return; }
    const model = el('select'); model.setAttribute('aria-label', '모델');
    const effort = el('select'); effort.setAttribute('aria-label', '추론 수준');
    const tier = el('select'); tier.setAttribute('aria-label', '응답 속도');
    const ultracode = el('input'); ultracode.type = 'checkbox'; ultracode.setAttribute('aria-label', 'Ultracode');
    const help = el('div', undefined, 'model-help');
    model.append(Object.assign(el('option', '계정 기본 모델'), {value: ''}));
    for (const item of data.models) {
      const option = dataEl('option', item.displayName || item.model || item.id); option.value = item.model || item.id;
      option.selected = option.value === account.model; model.append(option);
    }
    const setEfforts = () => {
      effort.replaceChildren(Object.assign(el('option', '기본 추론 수준'), {value: ''}));
      const selected = data.models.find(item => (item.model || item.id) === model.value);
      const efforts = selected?.supportedReasoningEfforts || [];
      const desiredEffort = model.value === account.model ? account.reasoning_effort : selected?.defaultReasoningEffort;
      for (const value of efforts) {
        const option = dataEl('option', value.reasoningEffort); option.value = value.reasoningEffort;
        option.selected = value.reasoningEffort === desiredEffort; effort.append(option);
      }
      effort.disabled = !selected;
      ultracode.disabled = account.provider !== 'claude' || selected?.supportsUltracode !== true;
      ultracode.checked = !ultracode.disabled && model.value === account.model && account.ultracode === true;
      tier.replaceChildren(Object.assign(el('option', '기본 속도'), {value: ''}));
      const fast = selected?.serviceTiers?.find(item => item.id === 'fast');
      if (fast) tier.append(Object.assign(el('option', fast.name || '1.5배 Fast'), {value: 'fast', selected: model.value === account.model && account.service_tier === 'fast'}));
      tier.disabled = !fast;
      help.replaceChildren();
      if (fast) {
        const source = el('a', 'Fast 안내'); source.href = 'https://learn.chatgpt.com/docs/agent-configuration/speed';
        source.target = '_blank'; source.rel = 'noopener noreferrer'; help.append(source);
      }
      const id = selected?.model || selected?.id;
      if (id === 'gpt-daybreak-blue-latest') {
        const source = el('a', 'Daybreak Blue'); source.href = 'https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest';
        source.target = '_blank'; source.rel = 'noopener noreferrer'; help.append(source);
      } else if (id === 'gpt-5.6-sol') {
        const source = el('a', 'GPT-5.6 Sol'); source.href = 'https://developers.openai.com/api/docs/models/gpt-5.6-sol';
        source.target = '_blank'; source.rel = 'noopener noreferrer'; help.append(source);
      }
    };
    model.addEventListener('change', setEfforts); setEfforts();
    const modelField = el('label', '모델'); modelField.append(model);
    const effortField = el('label', '추론 수준'); effortField.append(effort);
    const tierField = el('label', '응답 속도'); tierField.append(tier);
    const fields = el('div', undefined, 'model-fields'); fields.append(modelField,effortField,tierField);
    if (account.provider === 'claude') {
      const ultracodeField = el('label', undefined, 'model-ultracode-toggle');
      ultracodeField.append(ultracode, el('span', 'Ultracode'));
      fields.append(ultracodeField);
    }
    const notice = createNotice();
    const save = button('모델 설정 저장', async () => {
      await api(`/api/accounts/${account.id}`, {method: 'PATCH', body: {model: model.value || null,
        reasoning_effort: model.value && effort.value || null, service_tier: model.value && tier.value || null,
        ultracode: account.provider === 'claude' && ultracode.checked}});
      modelTargets.delete(account.id);
      await load();
    }, notice);
    save.className = 'model-save';
    target.append(fields, help, save, notice.node);
  }

  function authUpload(account, target) {
    target.replaceChildren();
    const form = el('form', undefined, 'auth-upload');
    const input = el('input'); input.type = 'file'; input.accept = '.json,application/json'; input.required = true;
    input.setAttribute('aria-label', 'Codex auth.json 파일');
    const submit = el('button', 'auth.json 가져오기'); submit.type = 'submit';
    target.append(el('p', 'auth.json · 최대 2 MiB'));
    const fileField = el('label', 'auth.json 파일'); fileField.append(input);
    const notice = createNotice();
    form.append(fileField, submit); target.append(form, notice.node);
    form.addEventListener('submit', event => {
      event.preventDefault();
      action(async () => {
        const file = input.files[0];
        if (!file || file.name !== 'auth.json' || file.size > 2 * 1024 * 1024) throw new Error(i18n.t('2MiB 이하의 auth.json 파일을 선택해 주세요.'));
        submit.disabled = true;
        try {
          const body = new FormData(); body.append('file', file);
          await api(`/api/accounts/${account.id}/auth-file`, {method: 'POST', body});
          modelTargets.delete(account.id);
          await load(); notice.set('auth.json을 가져오고 Codex 계정 정보를 확인했습니다.');
        } finally { input.value = ''; submit.disabled = false; }
      }, notice);
    });
  }

  function showApiKey(account, target) {
    target.replaceChildren();
    const form = el('form', undefined, 'account-api-key');
    const field = el('label', 'API 키');
    const input = el('input');
    input.type = 'password'; input.autocomplete = 'off'; input.required = true;
    input.minLength = 20; input.maxLength = 8192;
    input.setAttribute('aria-label', 'API 키');
    field.append(input);
    const submit = el('button', 'API 키 연결'); submit.type = 'submit';
    const notice = createNotice();
    form.append(field, submit);
    target.append(form, notice.node);
    form.addEventListener('submit', event => {
      event.preventDefault();
      action(async () => {
        submit.disabled = true;
        try {
          await api(`/api/accounts/${account.id}/api-key`, {method: 'POST', body: {key: input.value}});
          input.value = '';
          target.replaceChildren();
          modelTargets.delete(account.id);
          await load();
          formTargets.get(account.id)?.notice.set('API 키가 연결되었습니다.');
        } finally { input.value = ''; submit.disabled = false; }
      }, notice);
    });
  }

  async function load() {
    const generation = ++loadGeneration;
    const data = await api('/api/accounts');
    if (!active() || generation !== loadGeneration) return;
    const focusKey = document.activeElement?.dataset?.focusKey;
    const pendingLogins = [];
    const liveAccountIds = new Set(data.accounts.map(account => account.id));
    for (const id of modelTargets.keys()) if (!liveAccountIds.has(id)) modelTargets.delete(id);
    for (const id of formTargets.keys()) if (!liveAccountIds.has(id)) formTargets.delete(id);
    const existingCards = new Map([...accounts.children]
      .filter(child => child.dataset.accountId)
      .map(child => [child.dataset.accountId, child]));
    for (const child of [...accounts.children]) if (!child.dataset.accountId) child.remove();
    for (const account of data.accounts) {
      const card = el('section', undefined, 'card');
      card.dataset.accountId = account.id;
      const snapshot = account.snapshot || {};
      card.append(dataEl('h3', `${account.label} · ${account.provider}${account.selected ? ` · ${i18n.t('현재 선택')}` : ''}`));
      const identity = snapshot.identity || {};
      const modelSummary = [`${i18n.t('모델')}: ${account.model || i18n.t('계정 기본')}`, `${i18n.t('추론')}: ${account.reasoning_effort || i18n.t('계정 기본')}`,
        `${i18n.t('속도')}: ${account.service_tier === 'fast' ? 'Fast 1.5×' : i18n.t('기본')}`];
      if (account.provider === 'claude') modelSummary.push(`Ultracode: ${account.ultracode ? (i18n.locale === 'en' ? 'On' : '켜짐') : (i18n.locale === 'en' ? 'Off' : '꺼짐')}`);
      card.append(dataEl('p', [i18n.t(labels[snapshot.status] || '아직 조회하지 않음'),
        account.auth_kind === 'api_key' ? i18n.t('API 키') : null, identity.email,
        identity.planType || identity.subscriptionType].filter(Boolean).join(' · ')));
      if (snapshot.message) card.append(el('p', snapshot.message));
      if (snapshot.auth_refresh_unconfirmed) card.append(el('p', i18n.t('현재 인증은 확인됐지만 자동 갱신을 확인하지 못했습니다. 만료 후 재로그인이 필요할 수 있습니다.'), 'auth-refresh-warning'));
      if (snapshot.error) card.append(el('p', errorText({...snapshot.error,message:snapshot.error.message || '계정 정보를 조회하지 못했습니다.'}), 'error-text'));
      card.append(el('small', `${i18n.t('마지막 조회')}: ${date(account.checked_at)}${account.stale ? ` · ${i18n.t('새로고침 필요')}` : ''}`));
      const quota = snapshot.quota;
      if (quota) {
        const quotaView = quotaDisplayState(account);
        if (quota.stale) card.append(el('p', '최근 조회 실패: 아래 사용량은 이전 조회 값입니다.'));
        if (quota.message) card.append(el('p', quota.message));
        if (quota.error) card.append(el('p', errorText({...quota.error,message:quota.error.message || '사용량을 조회하지 못했습니다.'}), 'error-text'));
        if (quotaView.stale) card.className += ' quota-stale';
        else if (quotaView.blocked) {
          card.className += ' quota-limited';
          card.append(el('p', '현재 계정의 사용량 제한에 도달했습니다. 초기화 뒤 새로고침하거나 다른 등록 계정을 선택해 주세요.', 'quota-alert'));
        } else if (quotaView.exhausted) card.className += ' quota-exhausted';
        for (const bucketState of quotaView.buckets) {
          const {bucket} = bucketState;
          const list = el('div', undefined, `quota-bucket${bucketState.blocked ? ' quota-limited' : ''}${bucketState.exhausted ? ' quota-exhausted' : ''}${quotaView.stale ? ' quota-stale' : ''}`);
          list.setAttribute('aria-label', `${bucket.name || bucket.id || 'Codex'} ${i18n.t('사용량')}`);
          list.append(dataEl('strong', bucket.name || bucket.id));
          if (bucketState.blocked) {
            const reason = quotaLimitLabels[bucket.reached_type] || (bucket.spend_control_reached ? '설정된 지출 한도에 도달했습니다.' : quotaLimitLabels.rate_limit_reached);
            list.append(el('p', reason, 'quota-reason'));
          }
          if (!bucketState.windows.length) list.append(el('p', '사용량 구간이 제공되지 않았습니다.'));
          for (const {window,remaining,exhausted:windowExhausted} of bucketState.windows) {
            list.append(el('p', `${quotaWindowLabel(window.label)}: ${remaining == null ? i18n.t('남은 사용량 미제공') : `${remaining}% ${i18n.t('남음')}`} · ${i18n.t('초기화')} ${date(window.resets_at)}`, windowExhausted ? 'quota-window-exhausted' : undefined));
            if (remaining != null) {
              const meter = el('progress'); meter.max = 100; meter.value = remaining;
              if (windowExhausted) meter.className = 'quota-window-exhausted';
              meter.setAttribute('aria-label', `${quotaWindowLabel(window.label)} ${i18n.t('남은 사용량')}`);
              meter.setAttribute('aria-valuetext', `${remaining}% ${i18n.t('남음')}`); list.append(meter);
            }
          }
          if (bucket.individual_limit) {
            const remaining = bucket.individual_limit.remaining_percent;
            list.append(el('p', `${i18n.t('개인 사용 한도')}: ${remaining == null ? i18n.t('잔여량 미제공') : `${remaining}% ${i18n.t('남음')}`} · ${i18n.t('초기화')} ${date(bucket.individual_limit.resets_at)}`));
          }
          if (bucket.credits?.unlimited === true) list.append(el('p', '워크스페이스 크레딧: 무제한'));
          else if (bucket.credits?.has_credits === false) list.append(el('p', '워크스페이스 추가 크레딧: 없음'));
          card.append(list);
        }
        if (quota.reset_credits?.available_count > 0) {
          card.append(el('p', `${i18n.t('사용 가능한 Codex 한도 초기화 크레딧')}: ${quota.reset_credits.available_count}${i18n.locale === 'ko' ? '개' : ''}`, 'quota-reset-credits'));
        }
        if (!quota.buckets?.length && !quota.message) card.append(el('p', '조회 가능한 사용량 정보가 없습니다.'));
      }
      const summary = el('p', modelSummary.join(' · '), 'account-model-summary');
      summary.setAttribute('aria-label', '기본 풀이 설정');
      card.append(summary);
      const forms = formTargets.get(account.id) || {notice: createNotice(), login: el('div'), upload: el('div'), apiKey: el('div')};
      formTargets.set(account.id, forms);
      const {notice, login, upload, apiKey} = forms;
      const models = modelTargets.get(account.id) || el('div');
      modelTargets.set(account.id, models);
      // Build the refreshed card without moving an open form. Removing even the
      // same <select> for one render closes its native dropdown, and a rebuilt
      // API-key or file field would drop what the user already entered.
      const keep = [notice.node, login, models, upload, apiKey];
      const slots = keep.map(() => el('div'));
      const controls = el('div', undefined, 'actions');
      const accountButton = (key, text, task) => button(text, task, notice, `${account.id}:${key}`);
      const select = accountButton('select', account.selected ? '선택됨' : '이 계정 선택', async () => { await api(`/api/accounts/${account.id}/select`, {method: 'POST'}); await load(); });
      select.disabled = account.selected;
      controls.append(select, accountButton('refresh', '사용량 새로고침', async () => { await api(`/api/accounts/${account.id}/refresh`, {method: 'POST'}); await load(); }));
      if (account.auth_kind !== 'api_key') controls.append(accountButton('login', snapshot.status === 'authenticated' ? '다시 로그인' : '로그인', () => showLogin(account, login, true)));
      controls.append(accountButton('api-key', 'API 키 연결', () => showApiKey(account, apiKey)), accountButton('models', '모델·속도 설정', () => showModels(account, models)),
        accountButton('logout', '로그아웃', async () => { await api(`/api/accounts/${account.id}/logout`, {method: 'POST'}); modelTargets.delete(account.id); login.replaceChildren(); await load(); }),
        accountButton('delete', '계정 삭제', async () => {
          if (!window.confirm(localized(`${account.label} 계정 등록과 서버에 저장된 로그인 정보를 삭제할까요?`, `Remove ${account.label} and the sign-in saved on the server?`))) return;
          await api(`/api/accounts/${account.id}`, {method: 'DELETE'});
          await load();
        }));
      if (account.provider === 'codex') controls.append(accountButton('upload', 'auth.json 업로드', () => authUpload(account, upload)));
      card.append(controls, ...slots);
      const existing = existingCards.get(account.id);
      existingCards.delete(account.id);
      if (existing && keep.every(node => existing.contains(node))) {
        // Update quotas and account metadata in place while the form slots
        // and their ancestors stay connected, preserving focus and drafts.
        existing.className = card.className;
        const volatile = [...card.childNodes].filter(child => !slots.includes(child));
        for (const child of [...existing.childNodes]) if (!keep.includes(child)) child.remove();
        for (const child of volatile) existing.insertBefore(child, notice.node);
      } else {
        slots.forEach((slot, index) => slot.replaceWith(keep[index]));
        if (existing) existing.replaceWith(card);
        else accounts.append(card);
      }
      if (['starting', 'pending'].includes(account.login?.status) && !login.hasChildNodes()) {
        pendingLogins.push(quietly(() => showLogin(account, login, false), notice));
      }
    }
    for (const stale of existingCards.values()) stale.remove();
    if (!data.accounts.length) accounts.append(el('p', '등록된 계정이 없습니다.'));
    restoreFocus(focusKey);
    await Promise.all(pendingLogins);
    return data;
  }

  async function refreshUsageOnEnter(data) {
    const eligible = (data?.accounts || []).filter(account => account?.snapshot?.status === 'authenticated');
    if (!eligible.length || !active()) return;
    usageStatus.set('사용량 새로고침 중');
    const results = await Promise.allSettled(eligible.map(account =>
      api(`/api/accounts/${account.id}/refresh`, {method: 'POST'})
    ));
    if (!active()) return;
    try { await load(); }
    catch (error) { usageStatus.set(errorText(error), true); return; }
    const failed = results.filter(result => result.status === 'rejected').length;
    usageStatus.set(failed ? localized(`${failed}개 계정의 사용량을 새로고침하지 못했습니다.`, `Could not refresh usage for ${failed} account(s).`) : '', failed > 0);
  }

  function runtimeControls(source, state, disabled) {
    const path = `/api/providers/${source.key}`;
    const version = el('input');
    version.placeholder = source.placeholder;
    version.dataset.focusKey = `runtime:${source.key}:version`;
    version.setAttribute('aria-label', source.versionLabel);
    const runtimeButton = (name, text, task) => button(text, task, state.notice, `runtime:${source.key}:${name}`);
    const fillLatest = async () => {
      const data = await api(`${path}/catalog`);
      if (!data.latest) throw new Error(source.latestMissing);
      version.value = data.latest;
      return data.latest;
    };
    const install = async value => {
      const operation = await api(`${path}/update`, {method: 'POST', body: {version: value}});
      // The install is running now, so polling must start even if the next status read fails.
      state.info = {...state.info, operation};
      await loadRuntime();
    };
    const controls = el('div', undefined, 'runtime-controls');
    controls.append(version, runtimeButton('check', '최신 버전 조회', fillLatest),
      runtimeButton('update', '최신 버전으로 업데이트', async () => install(await fillLatest())),
      runtimeButton('install', '버전 설치', async () => {
        const value = version.value.trim();
        if (!VERSION_FORMAT.test(value)) throw new Error(i18n.t('버전은 0.164.0 같은 정확한 숫자 버전이어야 합니다.'));
        await install(value);
      }));
    if (state.info.selected) controls.append(runtimeButton('rollback', '이전 버전으로 복원', async () => {
      await api(`${path}/rollback`, {method: 'POST'}); await loadRuntime();
    }));
    if (disabled) for (const control of controls.children) control.disabled = true;
    return controls;
  }

  function runtimeSection(source, polling) {
    const state = runtimeStates.get(source.key);
    const {info} = state;
    const operation = info?.operation || {};
    const section = el('section', undefined, 'runtime-provider');
    section.append(el('h3', source.title), el('p', `${i18n.t('현재 버전')}: ${info?.version || i18n.t(info ? '설치 확인 불가' : '확인 불가')}`));
    if (info) {
      const label = !operation.status || operation.status === 'idle' ? localized('대기', 'Idle') : i18n.t(runtimeStatusLabels[operation.status] || operation.status);
      const busy = runtimeBusy(info);
      const status = el('p', `${i18n.t('상태')}: ${label}${operation.version ? ` · ${operation.version}` : ''}`,
        busy ? 'runtime-progress' : ['failed', 'interrupted'].includes(operation.status) ? 'runtime-status error-text' : 'runtime-status');
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      section.append(status);
      if (busy) {
        const progress = el('progress');
        progress.setAttribute('aria-label', `${source.name} ${label}`);
        section.append(progress);
      }
      if (operation.message) section.append(el('p', operation.message, 'error-text'));
    }
    if (state.error && polling) section.append(el('p', '상태 확인에 실패해 다시 시도합니다.', 'error-text'));
    else if (state.error) section.append(el('p', `${i18n.t('상태를 확인하지 못했습니다.')} ${state.error}`, 'error-text'),
      button('다시 조회', loadRuntime, state.notice, `runtime:${source.key}:retry`));
    if (info && !info.can_manage) section.append(el('p', source.adminOnly));
    else if (info && !info.update_supported) section.append(el('p', '이 환경에서는 웹 업데이트를 지원하지 않습니다.'));
    else if (info) section.append(runtimeControls(source, state, polling));
    section.append(state.notice.node);
    return section;
  }

  async function loadRuntime() {
    const generation = ++runtimeLoadGeneration;
    window.clearTimeout(runtimeTimer);
    const results = await Promise.allSettled(runtimeSources.map(source => api(`/api/providers/${source.key}/runtime`)));
    if (!active() || generation !== runtimeLoadGeneration) return;
    runtimeSources.forEach((source, index) => {
      const state = runtimeStates.get(source.key);
      const {status, value, reason} = results[index];
      if (status === 'fulfilled') { state.info = value; state.error = ''; }
      else state.error = errorText(reason);
    });
    // A failed read says nothing about the install, so keep following the last known state.
    const polling = [...runtimeStates.values()].some(state => runtimeBusy(state.info));
    runtimePollFailures = results.some(item => item.status === 'rejected') ? runtimePollFailures + 1 : 0;
    const focusKey = document.activeElement?.dataset?.focusKey;
    const versions = [...runtime.querySelectorAll('input[data-focus-key]')].map(input => [input.dataset.focusKey, input.value]);
    runtime.replaceChildren(...runtimeSources.map(source => runtimeSection(source, polling)));
    for (const [key, value] of versions) {
      const input = runtime.querySelector(`input[data-focus-key="${CSS.escape(key)}"]`);
      if (input) input.value = value;
    }
    restoreFocus(focusKey);
    if (polling) runtimeTimer = window.setTimeout(() => { if (active()) loadRuntime(); }, Math.min(3000 * 2 ** runtimePollFailures, 30000));
  }

  const onLanguageChanged = () => {
    if (!active()) return;
    quietly(load, feedback);
    loadRuntime();
  };
  document.addEventListener('ctf-language-changed', onLanguageChanged);
  const data = await quietly(load, feedback);
  await loadRuntime();
  if (revealRuntime && active()) {
    runtime.tabIndex = -1;
    runtime.focus({preventScroll:true});
    runtime.scrollIntoView({block:'start'});
  }
  await refreshUsageOnEnter(data);
  return () => {
    stopped = true;
    window.clearTimeout(runtimeTimer);
    document.removeEventListener('ctf-language-changed', onLanguageChanged);
  };
}
