const i18n = globalThis.ctfI18n || {locale:'ko',t:value=>value};

const el = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};

async function copyText(value) {
  const text = String(value ?? '');
  if (window.isSecureContext !== false && typeof navigator.clipboard?.writeText === 'function') {
    let timeout;
    try {
      // Invoke while the click still has transient user activation.
      const writing = navigator.clipboard.writeText(text);
      await Promise.race([
        writing,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('클립보드 응답이 지연되었습니다.')), 1200); }),
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

export async function renderAccounts(container, api, options = {}) {
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
  const feedback = el('p', '', 'notice');
  feedback.setAttribute('role', 'status');
  feedback.setAttribute('aria-live', 'polite');
  feedback.hidden = true;
  const setFeedback = text => { feedback.textContent = text; feedback.hidden = !text.trim(); };
  const errorText = error => {
    const providerCode = String(error.provider_code || '').toUpperCase();
    const policy = error.code === 'policy_security' || error.category === 'policy_security' || /^(TAC|CVP)(?:[-_]|$)/.test(providerCode);
    return [error.message || '요청에 실패했습니다.', providerCode,
      error.stage && `단계: ${error.stage}`, error.retryable === false && '자동 재시도하지 않습니다.',
      policy && '보안 작업 정책 제한입니다. 다른 모델을 선택하거나 계정 권한을 확인하세요.'].filter(Boolean).join(' · ');
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
    const option = el('option', i18n.t(name)); option.value = value; authKind.append(option);
  }
  const label = el('input');
  label.placeholder = '계정 이름 (예: 개인 Plus)'; label.required = true; label.maxLength = 100;
  label.setAttribute('aria-label', '계정 이름');
  const submit = el('button', '계정 추가'); submit.type = 'submit';
  form.append(provider, authKind, label, submit);
  if (returnActions) pageHead.append(returnActions);
  shell.append(pageHead);
  shell.append(form, feedback, accounts, runtime);
  heading.focus?.();
  let stopped = false;
  let loadGeneration = 0;
  let runtimeLoadGeneration = 0;
  const loginGeneration = new WeakMap();
  const modelTargets = new Map();
  const active = () => !stopped && container.contains(accounts);
  async function action(task) {
    setFeedback('');
    try { return await task(); }
    catch (error) { setFeedback(errorText(error)); }
  }
  function button(text, task) {
    const node = el('button', text); node.type = 'button';
    node.addEventListener('click', () => action(async () => {
      // Invoke first so clipboard writes retain the click's user activation.
      const pending = task();
      node.disabled = true;
      try { return await pending; } finally { node.disabled = false; }
    }));
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
        setFeedback(i18n.t(result === 'manual' ? '링크를 선택했습니다. Ctrl+C를 눌러 복사하세요.' : '복사를 시도했습니다. 링크가 필요하면 직접 열어 주소를 복사하세요.'));
      }));
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
        setFeedback('');
        setSubmitting(true, '인증 코드를 전송하고 로그인 완료를 확인 중입니다.');
        try {
          await api(`/api/accounts/${account.id}/login/code`, {method: 'POST', body: {code: code.value.trim()}});
          if (current()) code.value = '';
        } catch (error) {
          if (current()) {
            submitted = false;
            setSubmitting(false);
            setFeedback(errorText(error));
          }
        }
      });
      target.append(codeForm);
    }
    if (['starting', 'pending'].includes(result.status)) {
      target.append(button('로그인 취소', async () => {
        await api(`/api/accounts/${account.id}/login/cancel`, {method: 'POST'});
        await showLogin(account, target, false);
      }));
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
            if (result.status === 'completed') { modelTargets.delete(account.id); await api(`/api/accounts/${account.id}/refresh`, {method: 'POST'}); await load(); }
          }
        } catch (error) {
          if (current()) {
            setFeedback(errorText(error));
            if (error.retryable !== false) window.setTimeout(poll, 5000);
          }
        }
      };
      window.setTimeout(poll, 2500);
    } else if (result.status === 'completed' && start) {
      modelTargets.delete(account.id);
      await api(`/api/accounts/${account.id}/refresh`, {method: 'POST'});
      await load();
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
      const option = el('option', item.displayName || item.model || item.id); option.value = item.model || item.id;
      option.selected = option.value === account.model; model.append(option);
    }
    const setEfforts = () => {
      effort.replaceChildren(Object.assign(el('option', '기본 추론 수준'), {value: ''}));
      const selected = data.models.find(item => (item.model || item.id) === model.value);
      const efforts = selected?.supportedReasoningEfforts || [];
      const desiredEffort = model.value === account.model ? account.reasoning_effort : selected?.defaultReasoningEffort;
      for (const value of efforts) {
        const option = el('option', value.reasoningEffort); option.value = value.reasoningEffort;
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
    const save = button('모델 설정 저장', async () => {
      await api(`/api/accounts/${account.id}`, {method: 'PATCH', body: {model: model.value || null,
        reasoning_effort: model.value && effort.value || null, service_tier: model.value && tier.value || null,
        ultracode: account.provider === 'claude' && ultracode.checked}});
      modelTargets.delete(account.id);
      await load();
    });
    save.className = 'model-save';
    target.append(fields, help, save);
  }

  function authUpload(account, target) {
    target.replaceChildren();
    const form = el('form', undefined, 'auth-upload');
    const input = el('input'); input.type = 'file'; input.accept = '.json,application/json'; input.required = true;
    input.setAttribute('aria-label', 'Codex auth.json 파일');
    const submit = el('button', 'auth.json 가져오기'); submit.type = 'submit';
    target.append(el('p', 'auth.json · 최대 2 MiB'));
    const fileField = el('label', 'auth.json 파일'); fileField.append(input);
    form.append(fileField, submit); target.append(form);
    form.addEventListener('submit', event => {
      event.preventDefault();
      action(async () => {
        const file = input.files[0];
        if (!file || file.name !== 'auth.json' || file.size > 2 * 1024 * 1024) throw new Error('2MiB 이하의 auth.json 파일을 선택해 주세요.');
        submit.disabled = true;
        try {
          const body = new FormData(); body.append('file', file);
          await api(`/api/accounts/${account.id}/auth-file`, {method: 'POST', body});
          modelTargets.delete(account.id);
          await load(); setFeedback('auth.json을 가져오고 Codex 계정 정보를 확인했습니다.');
        } finally { input.value = ''; submit.disabled = false; }
      });
    });
  }

  function showApiKey(account, target) {
    target.replaceChildren();
    const form = el('form', undefined, 'account-api-key');
    const field = el('label', i18n.t('API 키'));
    const input = el('input');
    input.type = 'password'; input.autocomplete = 'off'; input.required = true;
    input.minLength = 20; input.maxLength = 8192;
    input.setAttribute('aria-label', i18n.t('API 키'));
    field.append(input);
    const submit = el('button', i18n.t('API 키 연결')); submit.type = 'submit';
    form.append(field, submit);
    target.append(form);
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
          setFeedback(i18n.t('API 키가 연결되었습니다.'));
        } finally { input.value = ''; submit.disabled = false; }
      });
    });
  }

  async function load() {
    const generation = ++loadGeneration;
    const data = await api('/api/accounts');
    if (!active() || generation !== loadGeneration) return;
    const pendingLogins = [];
    const liveAccountIds = new Set(data.accounts.map(account => account.id));
    for (const id of modelTargets.keys()) if (!liveAccountIds.has(id)) modelTargets.delete(id);
    accounts.replaceChildren();
    if (!data.accounts.length) accounts.append(el('p', '등록된 계정이 없습니다.'));
    for (const account of data.accounts) {
      const card = el('section', undefined, 'card');
      const snapshot = account.snapshot || {};
      card.append(el('h3', `${account.label} · ${account.provider}${account.selected ? ` · ${i18n.t('현재 선택')}` : ''}`));
      const identity = snapshot.identity || {};
      const modelSummary = [`${i18n.t('모델')}: ${account.model || i18n.t('계정 기본')}`, `${i18n.t('추론')}: ${account.reasoning_effort || i18n.t('계정 기본')}`,
        `${i18n.t('속도')}: ${account.service_tier === 'fast' ? 'Fast 1.5×' : i18n.t('기본')}`];
      if (account.provider === 'claude') modelSummary.push(`Ultracode: ${account.ultracode ? (i18n.locale === 'en' ? 'On' : '켜짐') : (i18n.locale === 'en' ? 'Off' : '꺼짐')}`);
      card.append(el('p', [i18n.t(labels[snapshot.status] || '아직 조회하지 않음'),
        account.auth_kind === 'api_key' ? i18n.t('API 키') : null, identity.email,
        identity.planType || identity.subscriptionType].filter(Boolean).join(' · ')));
      if (snapshot.message) card.append(el('p', snapshot.message));
      if (snapshot.auth_refresh_unconfirmed) card.append(el('p', i18n.t('현재 인증은 확인됐지만 자동 갱신을 확인하지 못했습니다. 만료 후 재로그인이 필요할 수 있습니다.'), 'auth-refresh-warning'));
      if (snapshot.error) card.append(el('p', errorText({...snapshot.error,message:snapshot.error.message || '계정 정보를 조회하지 못했습니다.'}), 'error-text'));
      card.append(el('small', `${i18n.t('마지막 조회')}: ${date(account.checked_at)}${account.stale ? ` · ${i18n.t('새로고침 필요')}` : ''}`));
      const quota = snapshot.quota;
      if (quota) {
        const exhaustedClaudeWindow = account.provider === 'claude' && ['available', 'quota_exceeded'].includes(quota.status)
          && Array.isArray(quota.buckets) && quota.buckets.some(bucket => Array.isArray(bucket.windows) && bucket.windows.some(window =>
            typeof window.used_percent === 'number' && Number.isFinite(window.used_percent) && window.used_percent >= 100));
        if (quota.stale) card.append(el('p', '최근 조회 실패: 아래 사용량은 이전 조회 값입니다.'));
        if (quota.message) card.append(el('p', quota.message));
        if (quota.error) card.append(el('p', errorText({...quota.error,message:quota.error.message || '사용량을 조회하지 못했습니다.'}), 'error-text'));
        if (quota.limited || exhaustedClaudeWindow) {
          card.className += ' quota-limited';
          card.append(el('p', '현재 계정의 사용량 제한에 도달했습니다. 초기화 뒤 새로고침하거나 다른 등록 계정을 선택해 주세요.', 'quota-alert'));
        }
        for (const bucket of orderedQuotaBuckets(quota,identity)) {
          const exhaustedWindows = account.provider === 'claude' && ['available', 'quota_exceeded'].includes(quota.status)
            && Array.isArray(bucket.windows) && bucket.windows.some(window =>
              typeof window.used_percent === 'number' && Number.isFinite(window.used_percent) && window.used_percent >= 100);
          const bucketLimited = bucket.limited || exhaustedWindows;
          const list = el('div', undefined, `quota-bucket${bucketLimited ? ' quota-limited' : ''}`);
          list.setAttribute('aria-label', `${bucket.name || bucket.id || 'Codex'} 사용량`);
          list.append(el('strong', bucket.name || bucket.id));
          if (bucketLimited) {
            const reason = quotaLimitLabels[bucket.reached_type] || (bucket.spend_control_reached ? '설정된 지출 한도에 도달했습니다.' : quotaLimitLabels.rate_limit_reached);
            list.append(el('p', reason, 'quota-reason'));
          }
          if (!bucket.windows.length) list.append(el('p', '사용량 구간이 제공되지 않았습니다.'));
          for (const window of bucket.windows) {
            const used = window.used_percent;
            const remaining = typeof used === 'number' && Number.isFinite(used) ? Math.max(0, Math.min(100, 100 - used)) : null;
            const windowExhausted = exhaustedWindows && remaining === 0;
            list.append(el('p', `${i18n.t(window.label)}: ${remaining == null ? i18n.t('남은 사용량 미제공') : `${remaining}% ${i18n.t('남음')}`} · ${i18n.t('초기화')} ${date(window.resets_at)}`, windowExhausted ? 'quota-window-exhausted' : undefined));
            if (remaining != null) {
              const meter = el('progress'); meter.max = 100; meter.value = remaining;
              if (windowExhausted) meter.className = 'quota-window-exhausted';
              meter.setAttribute('aria-label', `${window.label} 남은 사용량`);
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
      const login = el('div');
      const models = modelTargets.get(account.id) || el('div');
      modelTargets.set(account.id, models);
      const controls = el('div', undefined, 'actions');
      const upload = el('div');
      const apiKey = el('div');
      const select = button(account.selected ? '선택됨' : '이 계정 선택', async () => { await api(`/api/accounts/${account.id}/select`, {method: 'POST'}); await load(); });
      select.disabled = account.selected;
      controls.append(select, button('사용량 새로고침', async () => { await api(`/api/accounts/${account.id}/refresh`, {method: 'POST'}); await load(); }));
      if (account.auth_kind !== 'api_key') controls.append(button(snapshot.status === 'authenticated' ? '다시 로그인' : '로그인', () => showLogin(account, login, true)));
      controls.append(button('API 키 연결', () => showApiKey(account, apiKey)), button('모델·속도 설정', () => showModels(account, models)),
        button('로그아웃', async () => { await api(`/api/accounts/${account.id}/logout`, {method: 'POST'}); modelTargets.delete(account.id); await load(); }),
        button('계정 삭제', async () => {
          if (!window.confirm(`${account.label} 계정 등록과 서버에 저장된 로그인 정보를 삭제할까요?`)) return;
          await api(`/api/accounts/${account.id}`, {method: 'DELETE'});
          await load();
        }));
      if (account.provider === 'codex') controls.append(button('auth.json 업로드', () => authUpload(account, upload)));
      card.append(controls, login, models, upload, apiKey); accounts.append(card);
      if (['starting', 'pending'].includes(account.login?.status)) {
        pendingLogins.push(action(() => showLogin(account, login, false)));
      }
    }
    await Promise.all(pendingLogins);
    return data;
  }

  async function refreshUsageOnEnter(data) {
    const eligible = (data?.accounts || []).filter(account => account?.snapshot?.status === 'authenticated');
    if (!eligible.length || !active()) return;
    setFeedback('사용량 새로고침 중');
    const results = await Promise.allSettled(eligible.map(account =>
      api(`/api/accounts/${account.id}/refresh`, {method: 'POST'})
    ));
    if (!active()) return;
    await load();
    const failed = results.filter(result => result.status === 'rejected').length;
    setFeedback(failed ? `${failed}개 계정의 사용량을 새로고침하지 못했습니다.` : '');
  }

  async function loadRuntime() {
    const generation = ++runtimeLoadGeneration;
    const [info, claude] = await Promise.all([
      api('/api/providers/codex/runtime'),
      api('/api/providers/claude/runtime'),
    ]);
    if (!active() || generation !== runtimeLoadGeneration) return;
    const operation = info.operation || {};
    const claudeOperation = claude.operation || {};
    const busy = status => ['installing', 'verifying'].includes(status);
    const anyBusy = busy(operation.status) || busy(claudeOperation.status);
    const operationLabels = {idle: '대기', installing: '설치 중', verifying: '검증 중', completed: '업데이트 완료', failed: '업데이트 실패', interrupted: '업데이트 중단'};
    const claudeStatus = {idle: '대기', installing: '설치 중', verifying: '검증 중', completed: '업데이트 완료', failed: '업데이트 실패', interrupted: '중단'};
    const addStatus = (section, state, labels, name) => {
      const status = el('p', `상태: ${labels[state.status] || state.status || '대기'}${state.version ? ` · ${state.version}` : ''}`,
        busy(state.status) ? 'runtime-progress' : 'runtime-status');
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      section.append(status);
      if (busy(state.status)) {
        const progress = el('progress');
        progress.setAttribute('aria-label', `${name} ${labels[state.status]}`);
        section.append(progress);
      }
      if (state.message) section.append(el('p', state.message, 'error-text'));
    };
    const disableControls = controls => {
      if (anyBusy) for (const control of controls.children) control.disabled = true;
    };
    const codexSection = el('section', undefined, 'runtime-provider');
    codexSection.append(el('h3', 'Codex 업데이트'), el('p', `현재 버전: ${info.version || '설치 확인 불가'}`));
    addStatus(codexSection, operation, operationLabels, 'Codex');
    if (!info.can_manage) codexSection.append(el('p', 'Codex 업데이트는 관리자만 실행할 수 있습니다.'));
    else if (!info.update_supported) codexSection.append(el('p', '이 환경에서는 웹 업데이트를 지원하지 않습니다.'));
    else {
      const version = el('input'); version.placeholder = '버전 (예: 0.164.0)'; version.setAttribute('aria-label', '설치할 Codex 버전');
      const controls = el('div', undefined, 'runtime-controls');
      controls.append(version, button('최신 버전 조회', async () => { const data = await api('/api/providers/codex/catalog'); version.value = data.latest; }),
        button('버전 설치', async () => {
          await api('/api/providers/codex/update', {method: 'POST', body: {version: version.value.trim()}}); await loadRuntime();
        }));
      if (info.selected) controls.append(button('이전 버전으로 복원', async () => {
        await api('/api/providers/codex/rollback', {method: 'POST'}); await loadRuntime();
      }));
      disableControls(controls);
      codexSection.append(controls);
    }
    const claudeSection = el('section', undefined, 'runtime-provider');
    claudeSection.append(el('h3', 'Claude Code 업데이트'), el('p', `현재 버전: ${claude.version || '확인 불가'}`));
    addStatus(claudeSection, claudeOperation, claudeStatus, 'Claude Code');
    if (claude.can_manage && claude.update_supported) {
      const claudeVersion = el('input');
      claudeVersion.placeholder = '버전 (예: 2.1.310)';
      claudeVersion.setAttribute('aria-label', '설치할 Claude Code 버전');
      const claudeActions = el('div', undefined, 'runtime-controls');
      claudeActions.append(
        claudeVersion,
        button('최신 버전 조회', async () => { const data = await api('/api/providers/claude/catalog'); claudeVersion.value = data.latest; }),
        button('버전 설치', async () => { await api('/api/providers/claude/update', {method: 'POST', body: {version: claudeVersion.value.trim()}}); await loadRuntime(); })
      );
      if (claude.selected) claudeActions.append(button('이전 버전으로 복원', async () => {
        await api('/api/providers/claude/rollback', {method: 'POST'}); await loadRuntime();
      }));
      disableControls(claudeActions);
      claudeSection.append(claudeActions);
    }
    runtime.replaceChildren(codexSection, claudeSection);
    if (anyBusy) window.setTimeout(() => {
      if (active() && generation === runtimeLoadGeneration) action(loadRuntime);
    }, 3000);
  }
  await action(async () => {
    const data = await load();
    await loadRuntime();
    await refreshUsageOnEnter(data);
  });
  return () => { stopped = true; };
}
