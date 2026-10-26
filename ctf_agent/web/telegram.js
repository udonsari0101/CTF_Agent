const i18n = globalThis.ctfI18n || {locale:'ko',t:value=>value};

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
}

async function copyText(value) {
  const text = String(value ?? '');
  if (window.isSecureContext !== false && typeof navigator.clipboard?.writeText === 'function') {
    let timeout;
    try {
      // The request must start inside the original button click.
      const writing = navigator.clipboard.writeText(text);
      await Promise.race([
        writing,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('클립보드 응답이 지연되었습니다.')), 1200); }),
      ]);
      return 'unverified';
    } catch { /* The link remains available for manual copying. */ }
    finally { clearTimeout(timeout); }
  }
  showManualCopy(text);
  return 'manual';
}

function showManualCopy(text) {
  const dialog = document.createElement('dialog');
  dialog.className = 'modal copy-select-dialog';
  const heading = document.createElement('h2'); heading.textContent = i18n.t('직접 복사');
  const guidance = document.createElement('p'); guidance.textContent = i18n.t('내용을 선택한 상태입니다. Ctrl+C를 누르세요.');
  const area = document.createElement('textarea');
  area.readOnly = true; area.value = text; area.setAttribute('aria-label',i18n.t('복사할 내용'));
  const close = document.createElement('button'); close.type = 'button'; close.textContent = i18n.t('닫기');
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => dialog.remove(), {once:true});
  dialog.append(heading,guidance,area,close);
  document.body.append(dialog);
  dialog.showModal(); area.focus(); area.select();
}

function dateText(value) {
  if (!value) return i18n.t('기록 없음');
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? i18n.t('기록 없음') : date.toLocaleString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US');
}

export async function renderTelegram(container, api) {
  let active = true;
  let link = null;
  let pollTimer = null;

  const stopPolling = () => {
    if (pollTimer) window.clearTimeout(pollTimer);
    pollTimer = null;
  };

  const message = (text = '', error = false) => {
    const node = container.querySelector('[data-telegram-notice]');
    if (!node) return;
    node.textContent = text;
    node.classList.toggle('error-notice', Boolean(text && error));
    node.hidden = !text;
  };

  const load = async (quiet = false) => {
    try {
      const state = await api('/api/telegram');
      if (!active || !container.isConnected) return null;
      paint(state);
      return state;
    } catch (error) {
      if (!quiet) message(error.message || 'Telegram 상태를 불러오지 못했습니다.', true);
      return null;
    }
  };

  const schedulePoll = () => {
    stopPolling();
    const tick = async () => {
      if (!active || !container.isConnected || !link) return;
      const state = await load(true);
      if (state?.linked) {
        link = null;
        paint(state);
        message('Telegram 연결을 확인했습니다. 아래에서 알림을 켤 수 있습니다.');
        return;
      }
      pollTimer = window.setTimeout(tick, 3000);
    };
    pollTimer = window.setTimeout(tick, 3000);
  };

  const paint = state => {
    const configured = state.configured;
    const linked = state.linked;
    const unavailable = state.configuration_error
      ? 'Telegram 봇 상태를 확인하지 못했습니다. 토큰을 확인해 주세요.'
      : 'BotFather에서 발급한 봇 토큰을 등록하세요.';
    const linkPanel = link ? `
      <div class="telegram-link-box">
        <p>일회용 링크에서 <code>/start</code>를 누르세요.</p>
        <div class="line-actions">
          <a class="button-link primary" href="${escapeHtml(link.deep_link)}" target="_blank" rel="noopener noreferrer">Telegram 봇 열기</a>
          <button type="button" class="small ghost icon-action" data-telegram-action="copy-link" aria-label="Telegram 연결 링크 복사" title="Telegram 연결 링크 복사">⧉</button>
          <button type="button" class="small ghost icon-action" data-telegram-action="refresh" aria-label="Telegram 연결 확인" title="Telegram 연결 확인">↻</button>
        </div>
        <small>${escapeHtml(dateText(link.expires_at))}까지 유효</small>
      </div>` : '';
    container.innerHTML = `
      <div class="section-head"><div><h2>Telegram 알림</h2></div><span class="connection-state ${linked ? 'connected' : ''}">${i18n.t(linked ? '연결됨' : '연결 안 됨')}</span></div>
      <form class="telegram-bot-form" data-telegram-bot-form autocomplete="off">
        <label for="telegram-bot-token">봇 토큰</label>
        <div class="line-actions">
          <input id="telegram-bot-token" name="token" type="password" required autocomplete="new-password" spellcheck="false" placeholder="BotFather token" aria-label="Telegram 봇 토큰">
          <button type="submit" class="small primary" data-telegram-save>${configured ? '토큰 교체' : '토큰 등록'}</button>
          ${configured ? '<button type="button" class="small danger" data-telegram-action="delete-bot">토큰 삭제</button>' : ''}
        </div>
        ${configured ? `<small>@${escapeHtml(state.bot_username)} · ${i18n.t('토큰은 다시 표시되지 않습니다.')}</small>` : '<small><a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer">BotFather</a>에서 봇 토큰을 발급받으세요.</small>'}
      </form>
      ${state.configuration_error ? `<p class="notice error-notice">${unavailable}</p>` : ''}
      ${configured && !linked ? '<p>Chat ID는 일회용 링크로 연결합니다.</p>' : ''}
      ${configured && !linked ? '<button type="button" class="primary" data-telegram-action="link">일회용 연결 링크 발급</button>' : ''}
      ${linkPanel}
      ${linked ? `
        <label class="telegram-toggle"><input type="checkbox" data-telegram-action="toggle" ${state.enabled ? 'checked' : ''}> Flag·write-up 알림 받기</label>
        <div class="telegram-meta"><span>${i18n.t('연결 시각')} ${escapeHtml(dateText(state.linked_at))}</span><span>${i18n.t('최근 전송')} ${escapeHtml(dateText(state.last_success_at))}</span>${state.last_failure_at ? `<span class="error-text">${i18n.t('최근 실패')} ${escapeHtml(dateText(state.last_failure_at))} · ${escapeHtml(state.last_failure_code || i18n.t('전송 오류'))}</span>` : ''}</div>
        <button type="button" class="small danger" data-telegram-action="unlink">Telegram 연결 해제</button>` : ''}
      <p class="notice" data-telegram-notice hidden></p>`;
  };

  container.addEventListener('click', async event => {
    const control = event.target.closest('[data-telegram-action]');
    if (!control || control.dataset.telegramAction === 'toggle') return;
    const action = control.dataset.telegramAction;
    // Preserve transient activation until a clipboard write has started.
    if (action !== 'copy-link') control.disabled = true;
    message();
    try {
      if (action === 'link') {
        link = await api('/api/telegram/link', {method:'POST'});
        const state = await api('/api/telegram');
        paint(state);
        schedulePoll();
      } else if (action === 'copy-link' && link) {
        const copying = copyText(link.deep_link);
        control.disabled = true;
        const result = await copying;
        message(i18n.t(result === 'manual' ? '링크를 선택했습니다. Ctrl+C를 눌러 복사하세요.' : '복사를 시도했습니다. 링크를 직접 열어 주소를 복사할 수도 있습니다.'));
      } else if (action === 'refresh') {
        const state = await load();
        if (state && !state.linked) message('아직 봇 인증을 기다리고 있습니다.');
      } else if (action === 'delete-bot') {
        if (!window.confirm('이 봇과 Telegram 연결, 대기 중인 알림을 삭제할까요?')) return;
        stopPolling();
        link = null;
        const state = await api('/api/telegram/bot', {method:'DELETE'});
        paint(state);
        message('봇 토큰을 삭제했습니다.');
      } else if (action === 'unlink') {
        if (!window.confirm('이 Telegram 연결과 대기 중인 알림을 해제할까요?')) return;
        stopPolling();
        link = null;
        const state = await api('/api/telegram', {method:'DELETE'});
        paint(state);
        message('Telegram 연결을 해제했습니다.');
      }
    } catch (error) {
      message(error.message || '요청을 처리하지 못했습니다.', true);
    } finally {
      if (control.isConnected) control.disabled = false;
    }
  });

  container.addEventListener('submit', async event => {
    const form = event.target.closest('[data-telegram-bot-form]');
    if (!form) return;
    event.preventDefault();
    const input = form.querySelector('[name="token"]');
    const button = form.querySelector('[data-telegram-save]');
    const token = input.value.trim();
    if (!token) return;
    button.disabled = true;
    message();
    try {
      const state = await api('/api/telegram/bot', {method:'PUT', body:{token}});
      input.value = '';
      stopPolling();
      link = null;
      paint(state);
      message('봇 토큰을 확인하고 저장했습니다. 연결 링크를 발급해 주세요.');
    } catch (error) {
      message(error.message || '봇 토큰을 저장하지 못했습니다.', true);
    } finally {
      if (button.isConnected) button.disabled = false;
    }
  });

  container.addEventListener('change', async event => {
    const control = event.target.closest('[data-telegram-action="toggle"]');
    if (!control) return;
    control.disabled = true;
    try {
      const state = await api('/api/telegram', {method:'PATCH', body:{enabled: control.checked}});
      paint(state);
      message(state.enabled ? 'Telegram 알림을 켰습니다.' : 'Telegram 알림을 껐습니다.');
    } catch (error) {
      control.checked = !control.checked;
      message(error.message || '알림 설정을 변경하지 못했습니다.', true);
    } finally {
      if (control.isConnected) control.disabled = false;
    }
  });

  container.innerHTML = '<p class="muted">Telegram 설정을 불러오는 중입니다…</p>';
  await load();
  return () => {
    active = false;
    stopPolling();
  };
}
