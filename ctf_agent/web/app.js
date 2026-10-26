// A relative import inherits the release-specific asset directory emitted by
// the server, preventing a new app.js from loading a cached older dependency.
import {renderAccounts} from './accounts.js';
const i18n = globalThis.ctfI18n || {locale:'ko',t:value=>value,picker:()=>'',init:async()=>{}};

const app = document.querySelector('#app');
const modal = document.querySelector('#modal');
const detail = document.querySelector('#detail');
const statuses = {pending:'시작 전',running:'작업 중',stopped:'중단',failed:'실패',flag_found:'Flag 발견',solved:'완료'};
let csrf = '', workspaces = [], currentWorkspace = null, currentChallenge = null;
let sessionUser = null;
let authMode = 'password';
const activeUploads = new Map();
const uploadViews = new Map();
const startingListSolvers = new Set();
let challengeFlags = new Map();
let selectedStatus = '', selectedCategory = '', selectedSort = 'added_desc', search = '', disposeAccounts = null, importPreview = null;
let disposeTelegram = null;
let ctfdRetryId = null;
const activeCTFdChallengeRefreshes = new Map();
const watchedCTFdRefreshJobs = new Set();
let rendering = 0, challengeRendering = 0, listRendering = 0, detailBusy = false;
let modalRendering = 0, ctfdSubmitRendering = 0;
let challengeFileDragDepth = 0;
let solverRendering = 0, solverPollTimer = null, currentSolverJob = null;
let resourcePollTimer = null, resourceRequestGeneration = 0;
let challengeListPollTimer = null, challengeListPollGeneration = 0, challengeListSignatures = new Map(), challengeListCategories = '';
let currentSolverEvents = [], currentSolverGuidance = [], solverEventCursor = 0, solverListedFlag = '', solverSyncedWriteup = '', solverGuidanceDraft = '';
let writeupRefineJob = null, writeupRefineEvents = [], writeupRefineTimer = null;
let writeupRefineError = null, writeupRefineInstruction = '';
let relatedCandidates = [];
let releaseUpdateTimer = null, releaseUpdateRequestGeneration = 0;
let solverProvider = (() => { try { return localStorage.getItem('ctf-solver-provider') === 'claude' ? 'claude' : 'codex'; } catch { return 'codex'; } })();
let solverAccounts = [], solverAccountId = '', solverModels = [], solverModel = '';
let solverReasoning = '', solverServiceTier = null, solverUltracode = false, solverOptionsState = 'idle', solverOptionsError = '';
let solverUltraEscalationMode = 'ask';
let solverOptionsGeneration = 0;
let sidebarCollapsed = (() => { try { return localStorage.getItem('ctf-sidebar-collapsed') === 'true'; } catch { return false; } })();
let solverLogExpanded = false, solverConsoleDialog = null;
let solverConsoleAgentId = 'root', solverConsoleFollowLatest = true;
const solverCollapsedAgentIds = new Set();
const noteDrafts = new Map();
const busyForms = new WeakSet();
const ctfdJobMarkupCache = new WeakMap();
const challengeReturnRoute = /^w\/[0-9a-f]{32}\/c\/[0-9a-f]{32}$/;
let accountsReturnTarget = null, accountsReturnPending = false;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date = value => new Date(value).toLocaleDateString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US', {month:'short',day:'numeric',timeZone:'Asia/Seoul'});
const size = value => value < 1024 ? `${value} B` : value < 1024**2 ? `${(value/1024).toFixed(1)} KB` : value < 1024**3 ? `${(value/1024**2).toFixed(1)} MB` : value < 1024**4 ? `${(value/1024**3).toFixed(2)} GB` : `${(value/1024**4).toFixed(2)} TB`;
const badge = status => `<span class="status status-${esc(status)}">${esc(statuses[status] || status)}</span>`;
const importErrors = errors => errors.map(error => esc(typeof error === 'string' ? error : `${error.challenge_id ? `문제 ${error.challenge_id}: ` : ''}${error.message || '가져오기 오류'}`)).join('<br>');
const path = (challenge, workspace = currentWorkspace?.id) => `/api/workspaces/${workspace}/challenges${challenge ? `/${challenge}` : ''}`;
const noteKey = c => `${c.workspace_id}:${c.id}`;
const conditional = token => token ? {'If-Match': token} : {};

function resourcePreferenceKey() {
  return `ctf-resource-meter-hidden:${sessionUser?.id || 'local'}`;
}

function resourceMeterHidden() {
  try { return localStorage.getItem(resourcePreferenceKey()) === 'true'; } catch { return false; }
}

function formatMemory(value) {
  if (!Number.isFinite(value) || value < 0) return '—';
  const gib = value / 1024 ** 3;
  return `${gib >= 10 ? gib.toFixed(1) : gib.toFixed(2)} GB`;
}

function resourceMeterMarkup(hidden = resourceMeterHidden()) {
  return `<div class="workspace-resource-zone"><div id="workspace-resource-meter" class="workspace-resource-meter${hidden ? ' hidden' : ''}" aria-label="시스템 리소스 사용률"><span><small>CPU</small><strong data-resource="cpu">—</strong></span><span><small>RAM</small><strong data-resource="memory">—</strong></span></div><button type="button" class="small ghost resource-toggle" data-action="toggle-resource-meter" aria-pressed="${hidden}" aria-controls="workspace-resource-meter">${hidden ? '리소스 보기' : '리소스 숨기기'}</button></div>`;
}

function stopResourcePolling() {
  if (resourcePollTimer !== null) clearTimeout(resourcePollTimer);
  resourcePollTimer = null;
  resourceRequestGeneration++;
}

function stopChallengeListPolling() {
  if (challengeListPollTimer !== null) clearTimeout(challengeListPollTimer);
  challengeListPollTimer = null;
  challengeListPollGeneration++;
}

function paintResourceMeter(snapshot) {
  const meter = document.querySelector('#workspace-resource-meter');
  if (!meter || meter.classList.contains('hidden')) return;
  const cpu = meter.querySelector('[data-resource="cpu"]');
  const memory = meter.querySelector('[data-resource="memory"]');
  const cpuValue = typeof snapshot?.cpu_percent === 'number' ? snapshot.cpu_percent : NaN;
  const memoryValue = typeof snapshot?.memory_percent === 'number' ? snapshot.memory_percent : NaN;
  if (cpu) cpu.textContent = Number.isFinite(cpuValue) ? `${cpuValue.toFixed(1)}%` : '측정 중';
  if (memory) memory.textContent = Number.isFinite(memoryValue)
    ? `${formatMemory(Number(snapshot.memory_used_bytes))} / ${formatMemory(Number(snapshot.memory_total_bytes))} · ${memoryValue.toFixed(1)}%`
    : '사용 불가';
}

async function pollWorkspaceResources(workspaceId, generation = resourceRequestGeneration) {
  if (document.visibilityState === 'hidden' || resourceMeterHidden() || currentWorkspace?.id !== workspaceId) return;
  try {
    const snapshot = await api(`/api/workspaces/${workspaceId}/resources`);
    if (generation !== resourceRequestGeneration || currentWorkspace?.id !== workspaceId) return;
    paintResourceMeter(snapshot);
  } catch {
    if (generation === resourceRequestGeneration && currentWorkspace?.id === workspaceId) paintResourceMeter(null);
  }
  if (generation === resourceRequestGeneration && document.visibilityState !== 'hidden' && !resourceMeterHidden() && currentWorkspace?.id === workspaceId) {
    resourcePollTimer = setTimeout(() => pollWorkspaceResources(workspaceId,generation),5000);
  }
}

function startResourcePolling(workspaceId) {
  stopResourcePolling();
  if (!resourceMeterHidden() && document.visibilityState !== 'hidden') pollWorkspaceResources(workspaceId,resourceRequestGeneration);
}

function toggleResourceMeter(button) {
  const meter = document.querySelector('#workspace-resource-meter');
  const hidden = !meter?.classList.contains('hidden');
  try { localStorage.setItem(resourcePreferenceKey(),String(hidden)); } catch {}
  meter?.classList.toggle('hidden',hidden);
  button.textContent = hidden ? '리소스 보기' : '리소스 숨기기';
  button.setAttribute('aria-pressed',String(hidden));
  stopResourcePolling();
  if (!hidden && currentWorkspace?.id) {
    paintResourceMeter({});
    pollWorkspaceResources(currentWorkspace.id,resourceRequestGeneration);
  }
}

function markdownInline(value) {
  const source = String(value ?? '');
  const format = segment => esc(segment)
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/__([^_\n]+)__/g, '<strong>$1</strong>');
  let result = '', cursor = 0;
  const link = /\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s<>()]+)/g;
  for (const match of source.matchAll(link)) {
    result += format(source.slice(cursor, match.index));
    const raw = match[2] || match[3];
    const suffix = match[3] ? (raw.match(/[.,;:!?]+$/)?.[0] || '') : '';
    const url = suffix ? raw.slice(0, -suffix.length) : raw;
    let safe = false;
    try { safe = ['http:', 'https:'].includes(new URL(url).protocol); } catch {}
    result += safe
      ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${format(match[1] || url)}</a>${format(suffix)}`
      : format(match[0]);
    cursor = match.index + match[0].length;
  }
  return result + format(source.slice(cursor));
}

function safeMarkdown(markdown) {
  const lines = String(markdown || '').replace(/\r\n?/g,'\n').split('\n');
  const output = [];
  let code = false, codeLines = [], list = '';
  const closeList = () => { if (list) { output.push(`</${list}>`); list = ''; } };
  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      closeList();
      if (code) { output.push(`<pre><code>${esc(codeLines.join('\n'))}</code></pre>`); codeLines = []; }
      code = !code;
      continue;
    }
    if (code) { codeLines.push(line); continue; }
    const heading = /^(#{1,4})\s+(.+)$/.exec(line);
    if (heading) { closeList(); const level = heading[1].length; output.push(`<h${level}>${markdownInline(heading[2])}</h${level}>`); continue; }
    const unordered = /^\s*[-*+]\s+(.+)$/.exec(line);
    const ordered = /^\s*\d+[.)]\s+(.+)$/.exec(line);
    if (unordered || ordered) {
      const kind = unordered ? 'ul' : 'ol';
      if (list !== kind) { closeList(); list = kind; output.push(`<${kind}>`); }
      output.push(`<li>${markdownInline((unordered || ordered)[1])}</li>`);
      continue;
    }
    closeList();
    const quote = /^\s*>\s?(.*)$/.exec(line);
    if (quote) { output.push(`<blockquote>${markdownInline(quote[1])}</blockquote>`); continue; }
    if (/^\s*(?:---+|\*\*\*+)\s*$/.test(line)) { output.push('<hr>'); continue; }
    if (line.trim()) output.push(`<p>${markdownInline(line)}</p>`);
  }
  closeList();
  if (codeLines.length || code) output.push(`<pre><code>${esc(codeLines.join('\n'))}</code></pre>`);
  return output.join('');
}

const generatedWriteupStart = '<!-- ctf-agent:generated-writeup:start -->';
const generatedWriteupEnd = '<!-- ctf-agent:generated-writeup:end -->';

function removeGeneratedWriteupCopy(value) {
  let result = String(value ?? '');
  while (true) {
    const start = result.indexOf(generatedWriteupStart);
    if (start < 0) return result;
    const end = result.indexOf(generatedWriteupEnd,start + generatedWriteupStart.length);
    if (end < 0) return result;
    result = result.slice(0,start) + result.slice(end + generatedWriteupEnd.length);
  }
}
const solverPhases = {
  queued:'대기열',staging:'문제 준비',awaiting_credential:'계정 연결 대기',validating:'실행 환경 확인',
  running:'문제 풀이 중',flag_found:'Flag 발견',writing:'write-up 작성 중',completed:'완료',cancelled:'취소됨',
  failed:'실패',refused:'실행 거부',needs_input:'원격 정보 필요',cleanup_blocked:'격리 정리 실패',
};
const solverProgress = {
  preparing:'문제 자료 준비',analyzing:'문제 분석',waiting_for_model:'모델 응답 대기',inspecting_files:'첨부파일 확인',executing:'풀이 실행',
  validating_flag:'Flag 검증',drafting_writeup:'write-up 작성',provider_auth_retry:'계정 인증 재확인',provider_access_check:'모델 사용 권한 확인',
  provider_quota_retry:'계정 사용량 제한 확인',provider_rate_limit_retry:'공급자 요청 제한 재시도',
  provider_overloaded_retry:'공급자 과부하 재시도',provider_connection_retry:'공급자 연결 재시도',
  provider_retrying:'공급자 응답 재시도',reasoning_escalated:'추론 max 자동 승격',
};
const solverTerminalPhases = new Set(['completed','cancelled','failed','refused','needs_input']);
const writeupRefinementInstructionLimit = 12 * 1024;
const solverErrorFields = ['code','category','stage','retryable','provider_code','quota','requirements'];

function solverErrorDetails(error, fallback) {
  const details = {message: typeof error?.message === 'string' && error.message ? error.message : fallback};
  if (error && typeof error === 'object') {
    for (const key of solverErrorFields) if (error[key] !== undefined) details[key] = error[key];
  }
  return details;
}

function solverErrorException(details) {
  return Object.assign(new Error(details.message),details);
}

function writeupRefinementEligible(challenge = currentChallenge) {
  const flag = challenge?.flag;
  return Boolean(challenge && challenge.status === 'solved' && challenge.completion_source === 'agent' &&
    typeof flag === 'string' && flag && flag.length <= 4000 && !/[\r\n\u0000-\u001f\u007f-\u009f]/.test(flag) &&
    typeof challenge.writeup_markdown === 'string' && challenge.writeup_markdown);
}

function normalizeWriteupRefinementInstruction(value) {
  return String(value ?? '').replace(/\r\n?/g,'\n').trim();
}

function writeupRefinementInstructionBytes(value) {
  return new TextEncoder().encode(value).byteLength;
}

function clearAccountsReturnTarget() {
  accountsReturnTarget = null;
  accountsReturnPending = false;
}

function accountsReturnRoute() {
  const target = accountsReturnTarget;
  if (!target || target.userId !== String(sessionUser?.id || '') || !challengeReturnRoute.test(target.route)) {
    clearAccountsReturnTarget();
    return '';
  }
  return target.route;
}

function openSolverAccounts() {
  const workspaceId = String(currentWorkspace?.id || '');
  const challengeWorkspaceId = String(currentChallenge?.workspace_id || '');
  const route = `w/${workspaceId}/c/${String(currentChallenge?.id || '')}`;
  if (sessionUser?.id && workspaceId === challengeWorkspaceId && challengeReturnRoute.test(route)) {
    // Module memory is scoped to this browser tab and never crosses a login boundary.
    accountsReturnTarget = {userId: String(sessionUser.id), route};
    accountsReturnPending = true;
  } else clearAccountsReturnTarget();
  location.hash = '#accounts';
}

function returnFromAccounts() {
  const route = accountsReturnRoute();
  clearAccountsReturnTarget();
  if (route) location.hash = `#${route}`;
}

function stopSolverPolling() {
  ++solverRendering;
  ++solverOptionsGeneration;
  if (solverPollTimer) clearTimeout(solverPollTimer);
  if (writeupRefineTimer) clearTimeout(writeupRefineTimer);
  solverPollTimer = null;
  writeupRefineTimer = null;
  currentSolverJob = null;
  currentSolverEvents = [];
  currentSolverGuidance = [];
  solverEventCursor = 0;
  solverGuidanceDraft = '';
  solverConsoleAgentId = 'root'; solverConsoleFollowLatest = true; solverCollapsedAgentIds.clear();
  solverListedFlag = '';
  solverSyncedWriteup = '';
  solverAccounts = []; solverAccountId = ''; solverModels = []; solverModel = '';
  solverReasoning = ''; solverServiceTier = null; solverUltracode = false; solverOptionsState = 'idle'; solverOptionsError = '';
  solverUltraEscalationMode = 'ask';
  writeupRefineJob = null; writeupRefineEvents = []; writeupRefineError = null; writeupRefineInstruction = '';
}

function solverJobId(job) { return job?.job_id || job?.run_id || job?.id || '';
}

function normalizeSolverPayload(payload) {
  const candidate = payload?.job ?? payload?.snapshot ?? payload?.solver ?? payload;
  const phase = candidate?.phase || candidate?.status;
  const job = candidate && typeof candidate === 'object' && phase
    ? {...candidate,phase,model:candidate.model || candidate.configuration} : null;
  const events = Array.isArray(payload?.events) ? payload.events : Array.isArray(job?.events) ? job.events : [];
  const guidance = [];
  for (const raw of [job?.guidance,payload?.guidance]) {
    if (Array.isArray(raw)) guidance.push(...raw);
    else if (raw && typeof raw === 'object') guidance.push(raw);
  }
  return {job, events:[...events].sort((a,b) => Number(a.sequence || 0) - Number(b.sequence || 0)),guidance:mergeSolverGuidance([],guidance)};
}

function solverEventSequence(event) {
  const sequence = Number(event?.sequence);
  return Number.isInteger(sequence) && sequence > 0 ? sequence : 0;
}

function mergeSolverEvents(current, incoming) {
  const merged = [], positions = new Map();
  for (const event of [...(Array.isArray(current) ? current : []),...(Array.isArray(incoming) ? incoming : [])]) {
    if (!event || typeof event !== 'object') continue;
    const sequence = solverEventSequence(event);
    const key = sequence ? `sequence:${sequence}` : `fallback:${event.kind || ''}:${event.created_at || event.occurred_at || ''}:${event.code || event.progress_code || ''}`;
    if (positions.has(key)) merged[positions.get(key)] = event;
    else { positions.set(key,merged.length); merged.push(event); }
  }
  merged.sort((a,b) => solverEventSequence(a) - solverEventSequence(b));
  return merged.slice(-2500);
}

function mergeSolverGuidance(current, incoming) {
  const items = new Map();
  for (const guidance of [...(Array.isArray(current) ? current : []),...(Array.isArray(incoming) ? incoming : [])]) {
    if (!guidance || typeof guidance !== 'object' || typeof guidance.id !== 'string') continue;
    items.set(guidance.id,guidance);
  }
  return [...items.values()].sort((a,b) => Number(a.created_at || 0) - Number(b.created_at || 0)).slice(-100);
}

function solverIsActive(job) {
  if (!job) return false;
  if (job.terminal === true || job.released_at != null) return false;
  return !solverTerminalPhases.has(job.phase);
}

function solverHasMoreEvents(job) {
  const last = Number(job?.last_event_sequence);
  return Number.isInteger(last) && last > solverEventCursor;
}

function solverContext(workspaceId, challengeId, generation) {
  const panel = document.querySelector('#solver-panel');
  return Boolean(panel?.isConnected && detail.open && solverRendering === generation &&
    currentWorkspace?.id === workspaceId && currentChallenge?.id === challengeId);
}

const solverQuotaLimitLabels = {
  rate_limit_reached:'사용량 구간 한도에 도달했습니다.',
  workspace_owner_credits_depleted:'워크스페이스 소유자 크레딧이 소진되었습니다.',
  workspace_member_credits_depleted:'워크스페이스 사용자 크레딧이 소진되었습니다.',
  workspace_owner_usage_limit_reached:'워크스페이스 소유자 사용 한도에 도달했습니다.',
  workspace_member_usage_limit_reached:'워크스페이스 사용자 사용 한도에 도달했습니다.',
};

function solverQuotaWindowLabel(minutes) {
  if (!Number.isInteger(minutes) || minutes <= 0 || minutes > 525600) return '사용량 구간';
  if (minutes % 1440 === 0) return `${minutes / 1440}일`;
  if (minutes % 60 === 0) return `${minutes / 60}시간`;
  return `${minutes}분`;
}

function solverQuotaReset(seconds) {
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 4102444800) return i18n.t('초기화 시각 미제공');
  return `${i18n.t('초기화')} ${new Date(seconds * 1000).toLocaleString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US',{timeZone:'Asia/Seoul'})} KST`;
}

function solverQuotaMarkup(quota) {
  if (!quota || typeof quota !== 'object' || Array.isArray(quota)) return '';
  const safeName = typeof quota.limit_name === 'string' && /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$/.test(quota.limit_name)
    ? quota.limit_name : (typeof quota.limit_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(quota.limit_id) ? quota.limit_id : 'Codex');
  const reached = solverQuotaLimitLabels[quota.reached_type];
  const reasons = [];
  if (reached) reasons.push(reached);
  if (quota.spend_control_reached === true) reasons.push('설정된 지출 한도에 도달했습니다.');
  const seen = new Set();
  const windows = Array.isArray(quota.windows) ? quota.windows.slice(0,2).flatMap(window => {
    if (!window || typeof window !== 'object' || !['primary','secondary'].includes(window.kind) || seen.has(window.kind)) return [];
    seen.add(window.kind);
    const used = typeof window.used_percent === 'number' && Number.isFinite(window.used_percent)
      ? Math.max(0, Math.min(100, window.used_percent)) : null;
    const remaining = used == null ? '남은 사용량 미제공' : `${100 - used}% 남음`;
    return [`<li><strong>${esc(solverQuotaWindowLabel(window.window_minutes))}</strong><span>${esc(remaining)} · ${esc(solverQuotaReset(window.resets_at))}</span></li>`];
  }) : [];
  if (!reasons.length && !windows.length) return '';
  return `<div class="solver-quota" aria-label="Codex 사용량 제한"><strong>제한 항목 · ${esc(safeName)}</strong>${reasons.map(reason => `<p>${esc(reason)}</p>`).join('')}${windows.length ? `<ul>${windows.join('')}</ul>` : '<p>초기화 구간 정보는 공급자가 제공하지 않았습니다.</p>'}</div>`;
}

function solverErrorMarkup(error, defaultTitle = '풀이 실행 오류') {
  if (!error) return '';
  if (error.code === 'ultra_escalation_requested') {
    return `<div class="notice muted solver-ultra-request" role="status"><strong>Ultra 전환 제안</strong><p>${esc(error.message || '분석을 이어받아 Ultra로 계속할 수 있습니다.')}</p></div>`;
  }
  const providerCode = String(error.provider_code || '').toUpperCase();
  const needsRemote = error.code === 'remote_input_required';
  const toolsUnavailable = error.code === 'provider_tools_unavailable';
  const authRequired = error.code === 'auth_required';
  const accessDenied = error.code === 'access_denied';
  const daybreakAccess = error.code === 'daybreak_route_rejected';
  const attestationUnavailable = error.code === 'codex_attestation_unavailable';
  const policy = error.code === 'policy_security' || error.category === 'policy_security' || /^(TAC|CVP)(?:[-_]|$)/.test(providerCode);
  const quotaTitles = {usage_limit_exceeded:'계정 사용량 한도',session_budget_exceeded:'세션 사용 예산',rate_limit_exceeded:'공급자 요청 제한',quota_exceeded:'계정 사용량 제한'};
  const quotaGuidance = {
    usage_limit_exceeded:'표시된 초기화 시각 뒤 다시 시도하거나 다른 등록 계정을 선택해 주세요.',
    session_budget_exceeded:'새 풀이 세션으로 다시 시도하거나 다른 등록 계정을 선택해 주세요.',
    rate_limit_exceeded:'잠시 뒤 다시 시도해 주세요.',
    quota_exceeded:'표시된 제한 상태를 확인한 뒤 다시 시도해 주세요.',
  };
  let title = quotaTitles[error.code] || defaultTitle;
  let guidance = quotaGuidance[error.code]
    || (error.retryable ? '잠시 후 다시 시도하세요.' : '설정과 실행 환경을 확인하세요.');
  if (needsRemote) {
    title = '원격 접속 정보가 필요합니다';
    guidance = '문제 수정에서 원격 대상을 설정하세요.';
  } else if (daybreakAccess) {
    title = 'Daybreak 실행 경로 확인 필요';
    guidance = '계정 로그인, Daybreak 권한과 서버 실행 경로를 확인하세요.';
  } else if (attestationUnavailable) {
    title = 'Codex 실행 방식 확인 필요';
    guidance = '모델을 바꾸거나 서버 실행 환경을 확인하세요.';
  } else if (authRequired) {
    title = '계정 다시 로그인 필요';
    guidance = '계정 관리에서 다시 로그인하세요.';
  } else if (accessDenied) {
    title = '모델 사용 권한 없음';
    guidance = '계정 권한이나 모델을 변경하세요.';
  } else if (policy) {
    title = `보안 작업 정책 제한${providerCode ? ` · ${providerCode}` : ''}`;
    guidance = '다른 모델이나 권한을 확인하세요.';
  } else if (toolsUnavailable) {
    title = '로컬 풀이 도구 사용 불가';
    guidance = 'shell·terminal·command를 지원하는 모델을 선택하세요.';
  }
  const requirements = Array.isArray(error.requirements) && error.requirements.length
    ? `<small>필요 조건: ${error.requirements.map(esc).join(', ')}</small>` : '';
  let actions = '';
  if (authRequired) {
    actions = '<div class="actions solver-error-actions"><a class="button-link primary" href="#accounts" data-action="open-solver-accounts">계정 다시 로그인</a></div>';
  } else if (daybreakAccess) {
    actions = '<div class="actions solver-error-actions"><a class="button-link primary" href="#accounts" data-action="open-solver-accounts">계정·모델 확인</a><a class="button-link" href="https://openai.com/daybreak/" target="_blank" rel="noopener noreferrer">Daybreak 공식 안내</a></div>';
  } else if (attestationUnavailable) {
    actions = '<div class="actions solver-error-actions"><a class="button-link primary" href="#accounts" data-action="open-solver-accounts">모델 변경</a></div>';
  } else if (accessDenied) {
    actions = '<div class="actions solver-error-actions"><a class="button-link primary" href="#accounts" data-action="open-solver-accounts">계정·모델 설정</a></div>';
  }
  return `<div class="notice error-notice solver-error${policy ? ' policy-error' : ''}" role="alert"><strong>${esc(title)}</strong><p>${esc(error.message || '풀이를 계속할 수 없습니다.')}</p><small>${esc(guidance)}</small>${solverQuotaMarkup(error.quota)}${requirements}${actions}</div>`;
}

function solverEventLabel(event) {
  const code = event.progress?.code || event.progress_code || event.code;
  const phase = event.phase || event.status;
  if (event.kind === 'agent') {
    return i18n.t({running:'하위 에이전트 시작',completed:'하위 에이전트 완료',failed:'하위 에이전트 실패',interrupted:'하위 에이전트 중단'}[event.status] || '하위 에이전트');
  }
  const kinds = {flag:'Flag 발견',writeup:'write-up 완성',error:'오류',cancelled:'취소됨',released:'격리 정리 완료',activity:'도구 실행',guidance:'추가 명령'};
  return i18n.t(code ? (solverProgress[code] || code) : (kinds[event.kind] || solverPhases[phase] || phase || event.kind || '상태 변경'));
}

function solverEventTime(event) {
  const timestamp = Number(event?.occurred_at || event?.created_at);
  return Number.isFinite(timestamp) && timestamp > 0
    ? new Date(timestamp * 1000).toLocaleTimeString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US',{timeZone:'Asia/Seoul'}) : '';
}

function solverEventDetail(event) {
  const parts = [];
  const toolLabels = {shell:'shell',web_search:'web',file:'file',analysis:'analysis',agent:'하위 에이전트'};
  if (event.kind === 'agent') {
    if (typeof event.label === 'string' && event.label) parts.push(event.label.slice(0,120));
    if (typeof event.model === 'string' && event.model) parts.push(event.model.slice(0,120));
  }
  if (event.kind === 'activity' && event.tool) parts.push(toolLabels[event.tool] || event.tool);
  if (event.kind === 'activity' && event.phase) parts.push(event.phase === 'started' ? '시작' : event.phase === 'completed' ? '완료' : event.phase);
  for (const key of ['summary','command','message','output']) {
    const value = typeof event[key] === 'string' ? event[key].replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g,'').trim() : '';
    if (value && !parts.includes(value)) parts.push(value.slice(0,4096));
  }
  if (event.kind === 'activity' && Number.isInteger(event.exit_code)) parts.push(`exit ${event.exit_code}`);
  if (event.kind === 'activity' && Number.isInteger(event.duration_ms) && event.duration_ms >= 0) {
    parts.push(event.duration_ms >= 1000 ? `${(event.duration_ms / 1000).toFixed(1)}s` : `${event.duration_ms}ms`);
  }
  if (event.kind === 'guidance' && event.state) parts.push(event.state === 'delivered' ? '전달됨' : event.state === 'rejected' ? '거부됨' : event.state);
  if (event.kind === 'guidance' && event.provider_delivery) parts.push(event.provider_delivery === 'same_turn' ? '현재 턴' : event.provider_delivery === 'next_turn' ? '다음 턴' : event.provider_delivery);
  if (event.kind === 'guidance' && typeof event.error_code === 'string' && event.error_code) parts.push(event.error_code);
  return parts.join(' · ');
}

function solverEventMarkup(events, job = null) {
  if (!events.length) return '<p class="solver-log-empty">아직 기록이 없습니다.</p>';
  const agentLabels = new Map((Array.isArray(job?.agents) ? job.agents : [])
    .filter(agent => agent && typeof agent.id === 'string' && agent.id !== 'root')
    .map(agent => [agent.id,String(agent.label || agent.id)]));
  return `<ol class="solver-events" aria-label="풀이 진행 기록">${events.map(event => {
    const code = event.progress?.code || event.progress_code || event.code;
    const label = solverEventLabel(event);
    const detailText = solverEventDetail(event);
    const percent = Number(event.progress?.percent ?? event.percent);
    const percentSuffix = Number.isFinite(percent) ? ` · ${Math.max(0,Math.min(100,percent))}%` : '';
    const escalationSuffix = code === 'reasoning_escalated'
      ? ` · ${esc(event.from_effort || '')} → max · MAX_REQUIRED + 작업 근거 확인`
      : '';
    const agentLabel = event.kind === 'agent' ? null : agentLabels.get(event.agent_id);
    return `<li class="solver-event solver-event-${esc(event.kind || 'status')}"><span><strong>${agentLabel ? `<span class="solver-event-agent">${esc(agentLabel)}</span>` : ''}${esc(label)}${percentSuffix}${escalationSuffix}</strong>${detailText ? `<code>${esc(detailText)}</code>` : ''}</span><small>${esc(solverEventTime(event))}</small></li>`;
  }).join('')}</ol>`;
}

function solverAgentNodes(job) {
  const nodes = [{id:'root',parent_id:null,label:'전체 세션'}], seen = new Set(['root']);
  for (const agent of Array.isArray(job?.agents) ? job.agents : []) {
    if (!agent || typeof agent.id !== 'string' || !agent.id || seen.has(agent.id)) continue;
    seen.add(agent.id);
    nodes.push(agent);
  }
  return nodes;
}

function solverConsoleEvents(job, events) {
  if (solverConsoleAgentId === 'root') return events;
  if (!solverAgentNodes(job).some(agent => agent.id === solverConsoleAgentId)) {
    solverConsoleAgentId = 'root';
    return events;
  }
  return events.filter(event => event.kind === 'activity' && event.agent_id === solverConsoleAgentId);
}

function solverAgentTreeMarkup(job, events) {
  const agents = solverAgentNodes(job);
  if (agents.length < 2) return '';
  const ids = new Set(agents.map(agent => agent.id));
  if (!ids.has(solverConsoleAgentId)) solverConsoleAgentId = 'root';
  const children = new Map(), counts = new Map();
  for (const agent of agents.slice(1)) {
    const parentId = ids.has(agent.parent_id) && agent.parent_id !== agent.id ? agent.parent_id : 'root';
    if (!children.has(parentId)) children.set(parentId,[]);
    children.get(parentId).push(agent);
  }
  for (const event of events) {
    if (event.kind === 'activity' && typeof event.agent_id === 'string') counts.set(event.agent_id,(counts.get(event.agent_id) || 0) + 1);
  }
  const visited = new Set();
  function branch(agent) {
    if (visited.has(agent.id)) return '';
    visited.add(agent.id);
    const descendants = (children.get(agent.id) || []).filter(child => !visited.has(child.id));
    const expandable = descendants.length > 0;
    const collapsed = solverCollapsedAgentIds.has(agent.id);
    const status = typeof agent.status === 'string' ? agent.status : '';
    const safeStatus = ['queued','running','completed','failed','cancelled','stopped','interrupted'].includes(status) ? status : '';
    const statusLabel = {queued:'대기',running:'작업 중',completed:'완료',failed:'실패',cancelled:'취소',stopped:'중단',interrupted:'중단'}[status] || status;
    const meta = [agent.provider,agent.model,statusLabel].filter(Boolean).map(esc).join(' · ');
    const count = agent.id === 'root' ? events.length : counts.get(agent.id) || 0;
    return `<li class="solver-agent-node"><div class="solver-agent-row">${expandable
      ? `<button type="button" class="solver-agent-expand" data-action="toggle-solver-agent-branch" data-agent-id="${esc(agent.id)}" aria-label="${esc(agent.label || agent.id)} ${collapsed ? '펼치기' : '접기'}" aria-expanded="${!collapsed}">${collapsed ? '▸' : '▾'}</button>`
      : '<span class="solver-agent-expand-spacer" aria-hidden="true"></span>'}
      <button type="button" class="solver-agent-select${solverConsoleAgentId === agent.id ? ' selected' : ''}" data-action="select-solver-agent" data-agent-id="${esc(agent.id)}" aria-pressed="${solverConsoleAgentId === agent.id}"><span class="solver-agent-name">${esc(agent.id === 'root' ? '전체 세션' : agent.label || agent.id)}</span><span class="solver-agent-count">${count}</span>${safeStatus ? `<span class="solver-agent-status ${safeStatus}" title="${esc(status)}"></span>` : ''}${meta ? `<small>${meta}</small>` : ''}</button></div>${expandable ? `<ul class="solver-agent-children${collapsed ? ' hidden' : ''}">${descendants.map(branch).join('')}</ul>` : ''}</li>`;
  }
  let content = branch(agents[0]);
  for (const agent of agents.slice(1)) if (!visited.has(agent.id)) content += branch(agent);
  return `<h3>에이전트</h3><ul class="solver-agent-list">${content}</ul>`;
}

function solverGuidanceHistoryMarkup() {
  const recent = currentSolverGuidance.slice(-3);
  const stateLabels = {queued:'대기',staged:'전달 준비',delivered:'전달됨',rejected:'거부됨'};
  return recent.length ? `<ol class="solver-guidance-history">${recent.map(item => `<li><span>${esc(item.message || '')}</span><small>${esc([stateLabels[item.status] || item.status,item.error_code].filter(Boolean).join(' · '))}</small></li>`).join('')}</ol>` : '';
}

function solverGuidanceMarkup(job, active) {
  const allowed = job?.guidance_allowed === true || (job?.guidance_allowed === undefined && ['queued','staging','awaiting_credential','running'].includes(job?.phase));
  if (!active || !allowed) return '';
  return `<form id="solver-guidance-form" class="solver-guidance" data-job-id="${esc(solverJobId(job))}">
    <label for="solver-guidance-message">추가 명령<textarea id="solver-guidance-message" name="message" rows="2" maxlength="16384" placeholder="${esc(i18n.t('풀이 방향이나 확인할 내용을 입력'))}" required>${esc(solverGuidanceDraft)}</textarea></label>
    <button type="submit" class="small">전송</button>
    <div class="solver-guidance-history-slot">${solverGuidanceHistoryMarkup()}</div>
  </form>`;
}

function solverSessionMarkup(job, events, active) {
  const jobId = solverJobId(job);
  return `<details class="solver-event-log solver-session-log" ${active ? 'open' : ''}>
    <summary><span>세션 로그 <b>${events.length}</b></span><span class="solver-live-state${active ? ' live' : ''}">${active ? 'LIVE' : 'END'}</span></summary>
    <div class="solver-session-toolbar">${jobId ? `<div class="solver-session-id"><span>SESSION</span><code>${esc(jobId)}</code></div>` : '<span></span>'}<button type="button" class="small ghost icon-action solver-log-size-toggle" data-action="toggle-solver-log-size" aria-label="${solverLogExpanded ? '세션 로그 축소' : '세션 로그 확대'}" title="${solverLogExpanded ? '세션 로그 축소' : '세션 로그 확대'}" aria-pressed="${solverLogExpanded}">${solverLogExpanded ? '↙' : '⛶'}</button></div>
    <div class="solver-live-console" role="log" aria-live="polite" aria-relevant="additions text">${solverEventMarkup(events)}</div>
  </details>`;
}

function toggleSolverLogSize(button) {
  if (solverConsoleDialog?.open) { solverConsoleDialog.close(); return; }
  if (!currentSolverJob) return;
  if (!solverConsoleDialog) {
    solverConsoleDialog = document.createElement('dialog');
    solverConsoleDialog.className = 'solver-console-dialog';
    solverConsoleDialog.setAttribute('aria-label','세션 로그');
    document.body.append(solverConsoleDialog);
    solverConsoleDialog.addEventListener('close', () => {
      solverLogExpanded = false;
      const toggle = detail.querySelector('.solver-log-size-toggle');
      if (toggle) {
        toggle.textContent = '⛶';
        toggle.setAttribute('aria-label','세션 로그 확대');
        toggle.setAttribute('title','세션 로그 확대');
        toggle.setAttribute('aria-pressed','false');
      }
    });
  }
  const provider = (currentSolverJob.model || currentSolverJob.configuration || {}).provider;
  const active = solverIsActive(currentSolverJob) && currentSolverJob.guidance_allowed !== false;
  const agentTree = solverAgentTreeMarkup(currentSolverJob,currentSolverEvents);
  solverConsoleDialog.innerHTML = `<header class="solver-console-head"><div><strong>${esc(currentChallenge?.name || '세션 로그')}</strong><small>${esc(solverJobId(currentSolverJob))}</small></div><div class="solver-console-head-actions"><button type="button" class="small ghost solver-console-bottom hidden" data-action="solver-console-bottom" aria-label="맨 아래로 이동">↓ 맨 아래</button><button type="button" class="small ghost" data-action="close-solver-console" aria-label="세션 로그 닫기">닫기</button></div></header>
    <div class="solver-console-body"><aside class="solver-agent-tree${agentTree ? '' : ' hidden'}" aria-label="에이전트 활동">${agentTree}</aside><div class="solver-console-stream" role="log" aria-live="polite">${solverEventMarkup(solverConsoleEvents(currentSolverJob,currentSolverEvents),solverConsoleAgentId === 'root' ? currentSolverJob : null)}</div></div>
    <div class="solver-console-controls"><form id="solver-console-guidance-form" class="solver-console-guidance${active ? '' : ' hidden'}">
      <label for="solver-console-message">메인 세션 추가 명령</label><textarea id="solver-console-message" name="message" maxlength="16384" rows="3" placeholder="풀이 방향이나 확인할 내용을 입력" required>${esc(solverGuidanceDraft)}</textarea>
      <div class="solver-console-send"><select name="requested_delivery" aria-label="명령 전달 방식" ${provider === 'claude' ? 'disabled' : ''}><option value="same_turn">현재 턴에 개입</option><option value="next_turn" ${provider === 'claude' ? 'selected' : ''}>다음 턴에 전달</option></select><button type="submit" class="primary">전송</button></div>
    </form><label class="solver-console-upload">문제 파일 추가<input id="solver-console-files" type="file" multiple></label><small>업로드가 끝난 파일은 진행 중인 풀이의 attachments/에 추가됩니다.</small></div>`;
  solverConsoleDialog.showModal();
  solverLogExpanded = true;
  const toggle = detail.querySelector('.solver-log-size-toggle');
  if (toggle) {
    toggle.textContent = '↙';
    toggle.setAttribute('aria-label','세션 로그 축소');
    toggle.setAttribute('title','세션 로그 축소');
    toggle.setAttribute('aria-pressed','true');
  }
  const stream = solverConsoleDialog.querySelector('.solver-console-stream');
  solverConsoleFollowLatest = true;
  if (stream) {
    stream.addEventListener('scroll', () => {
      solverConsoleFollowLatest = solverConsoleAtBottom(stream);
      paintSolverConsoleBottomButton();
    });
    stream.scrollTop = stream.scrollHeight;
  }
}

function solverConsoleAtBottom(stream) {
  return stream.scrollHeight - stream.scrollTop - stream.clientHeight <= 36;
}

function paintSolverConsoleBottomButton() {
  solverConsoleDialog?.querySelector('.solver-console-bottom')?.classList.toggle('hidden',solverConsoleFollowLatest);
}

function solverConsoleBottom() {
  const stream = solverConsoleDialog?.querySelector('.solver-console-stream');
  if (!stream) return;
  solverConsoleFollowLatest = true;
  stream.scrollTop = stream.scrollHeight;
  paintSolverConsoleBottomButton();
}

function selectSolverAgent(button) {
  const id = button.dataset.agentId;
  if (!solverAgentNodes(currentSolverJob).some(agent => agent.id === id)) return;
  solverConsoleAgentId = id;
  solverConsoleFollowLatest = true;
  paintSolverConsole();
}

function toggleSolverAgentBranch(button) {
  const id = button.dataset.agentId;
  const agents = solverAgentNodes(currentSolverJob);
  if (!agents.some(agent => agent.id === id)) return;
  if (solverCollapsedAgentIds.has(id)) solverCollapsedAgentIds.delete(id);
  else {
    solverCollapsedAgentIds.add(id);
    const parents = new Map(agents.map(agent => [agent.id,agent.parent_id]));
    const visited = new Set();
    for (let selected = solverConsoleAgentId; selected && !visited.has(selected); selected = parents.get(selected)) {
      if (selected === id) { solverConsoleAgentId = id; break; }
      visited.add(selected);
    }
  }
  paintSolverConsole();
}

function paintSolverConsole() {
  if (!solverConsoleDialog?.open) return;
  const stream = solverConsoleDialog.querySelector('.solver-console-stream');
  if (!stream) return;
  const tree = solverConsoleDialog.querySelector('.solver-agent-tree');
  if (tree) {
    const markup = solverAgentTreeMarkup(currentSolverJob,currentSolverEvents);
    tree.classList.toggle('hidden',!markup);
    if (tree.innerHTML !== markup) tree.innerHTML = markup;
  }
  const scrollTop = stream.scrollTop;
  const markup = solverEventMarkup(solverConsoleEvents(currentSolverJob,currentSolverEvents),solverConsoleAgentId === 'root' ? currentSolverJob : null);
  if (stream.innerHTML !== markup) {
    stream.innerHTML = markup;
    stream.scrollTop = solverConsoleFollowLatest ? stream.scrollHeight : scrollTop;
  } else if (solverConsoleFollowLatest) stream.scrollTop = stream.scrollHeight;
  paintSolverConsoleBottomButton();
  const form = solverConsoleDialog.querySelector('#solver-console-guidance-form');
  if (form) form.classList.toggle('hidden', !solverIsActive(currentSolverJob) || currentSolverJob.guidance_allowed === false);
}

function solverWriteup(job = currentSolverJob) {
  const canonical = writeupRefinementEligible() ? currentChallenge.writeup_markdown : '';
  for (const value of [canonical,job?.writeup_markdown,currentChallenge?.writeup_markdown]) {
    if (typeof value === 'string' && value) return value;
  }
  return '';
}

function writeupRefinementMarkup() {
  const active = solverIsActive(writeupRefineJob);
  const eligible = writeupRefinementEligible();
  if (!eligible && !active) return '';
  const phase = writeupRefineJob?.phase;
  const progress = writeupRefineJob?.progress || {};
  const progressCode = progress.code || writeupRefineJob?.progress_code;
  const status = active
    ? (progressCode ? solverProgress[progressCode] || progressCode : solverPhases[phase] || phase || '보완 중')
    : phase === 'cancelled' ? '보완을 중단했습니다.'
      : phase === 'completed' ? '보완 완료' : '';
  const ready = eligible && solverConfigurationReady() && !active;
  return `<details class="writeup-refinement" ${active || writeupRefineError ? 'open' : ''}><summary>write-up 보완</summary>
    <label for="writeup-refine-instruction">추가 요청 <span class="optional">선택</span></label>
    <textarea id="writeup-refine-instruction" rows="3" maxlength="${writeupRefinementInstructionLimit}" placeholder="예: 익스플로잇 코드 설명을 더 구체적으로 작성" ${active ? 'disabled' : ''}>${esc(writeupRefineInstruction)}</textarea>
    <div class="actions"><button type="button" data-action="refine-writeup" ${ready ? '' : 'disabled'}>${active ? '보완 중…' : '보완 요청'}</button>${active ? `<button type="button" class="small danger ghost icon-action" data-action="cancel-writeup-refine" aria-label="write-up 보완 중단" title="write-up 보완 중단" ${writeupRefineJob?.cancel_requested ? 'disabled' : ''}>■</button>` : ''}</div>
    ${status || !solverConfigurationReady() ? `<p id="writeup-refine-status" class="form-hint" role="status">${esc(status || '계정·모델·추론 수준을 선택하세요.')}</p>` : ''}
    ${writeupRefineError ? solverErrorMarkup(writeupRefineError,'write-up 보완 오류') : ''}
  </details>`;
}

function solverWriteupArtifact(writeup) {
  if (!writeup) return '';
  return `<div class="solver-artifact solver-writeup-artifact"><strong>write-up</strong><div class="actions"><button type="button" class="small ghost icon-action" data-action="copy-solver-writeup" aria-label="write-up 복사" title="write-up 복사">▤</button><button type="button" class="small ghost icon-action" data-action="download-solver-writeup" aria-label="write-up Markdown 다운로드" title="write-up Markdown 다운로드">⇩</button></div><details class="writeup-preview"><summary>미리보기</summary><div class="markdown-preview">${safeMarkdown(writeup)}</div></details><div id="writeup-refine-container">${writeupRefinementMarkup()}</div></div>`;
}

function solverSelectedAccount() {
  return solverAccounts.find(account => account.id === solverAccountId && account.provider === solverProvider) || null;
}

function solverSelectedModel() {
  return solverModels.find(item => solverModel && solverModel === (item.model || item.id)) || null;
}

function solverConfigurationReady() {
  return solverOptionsState === 'ready' && Boolean(solverSelectedAccount() && solverSelectedModel() && solverReasoning);
}

function solverUltraEscalationEligible() {
  const model = solverSelectedModel();
  return solverProvider === 'codex' && ['high','xhigh'].includes(solverReasoning)
    && Array.isArray(model?.supportedReasoningEfforts)
    && model.supportedReasoningEfforts.some(item => item?.reasoningEffort === 'ultra');
}

function solverProviderSelector() {
  const provider = `<label>공급자<select id="solver-provider-select" aria-label="문제 풀이 공급자"><option value="codex" ${solverProvider === 'codex' ? 'selected' : ''}>Codex</option><option value="claude" ${solverProvider === 'claude' ? 'selected' : ''}>Claude Code</option></select></label>`;
  const available = solverAccounts.filter(account => account.provider === solverProvider && account.snapshot?.status === 'authenticated');
  if (solverOptionsState === 'loading' || solverOptionsState === 'idle') {
    return `<div class="solver-configuration solver-configuration-loading">${provider}
      <label>실행 계정<select disabled><option>불러오는 중…</option></select></label>
      <label>모델<select disabled><option>불러오는 중…</option></select></label>
      <label>추론 수준<select disabled><option>불러오는 중…</option></select></label>
      <span class="solver-fast-placeholder" aria-hidden="true"></span>
      <span class="form-hint solver-config-help" role="status">계정 설정을 불러오는 중</span></div>`;
  }
  if (solverOptionsState === 'error') {
    return `<div class="solver-configuration">${provider}<p class="notice error-notice solver-config-state">${esc(solverOptionsError || '계정 설정을 불러오지 못했습니다.')}</p><a class="button-link" href="#accounts" data-action="open-solver-accounts">계정 관리</a></div>`;
  }
  if (!available.length) {
    return `<div class="solver-configuration">${provider}<p class="notice muted solver-config-state">이 공급자에 로그인된 계정이 없습니다.</p><a class="button-link" href="#accounts" data-action="open-solver-accounts">계정 연결하기</a></div>`;
  }
  const accountOptions = available.map(account => `<option value="${esc(account.id)}" ${account.id === solverAccountId ? 'selected' : ''}>${esc(account.label)}${account.selected ? ' · 기본' : ''}</option>`).join('');
  const modelOptions = solverModels.map(item => { const value = item.model || item.id; return value ? `<option value="${esc(value)}" ${value === solverModel ? 'selected' : ''}>${esc(item.displayName || value)}</option>` : ''; }).join('');
  const chosen = solverSelectedModel();
  const efforts = Array.isArray(chosen?.supportedReasoningEfforts) ? chosen.supportedReasoningEfforts.map(item => item?.reasoningEffort).filter(Boolean) : [];
  const effortOptions = efforts.map(value => `<option value="${esc(value)}" ${value === solverReasoning ? 'selected' : ''}>${esc(value)}</option>`).join('');
  const supportsFast = solverProvider === 'codex' && Array.isArray(chosen?.serviceTiers) && chosen.serviceTiers.some(item => item?.id === 'fast');
  const supportsUltracode = solverProvider === 'claude' && chosen?.supportsUltracode === true;
  const ultraChoice = solverUltraEscalationEligible() ? `<label class="solver-ultra-escalation"><span>막히면 Ultra</span><select id="solver-ultra-escalation" aria-label="Ultra 전환 방식"><option value="ask" ${solverUltraEscalationMode === 'ask' ? 'selected' : ''}>전환 전 묻기</option><option value="auto" ${solverUltraEscalationMode === 'auto' ? 'selected' : ''}>조건 충족 시 자동</option><option value="off" ${solverUltraEscalationMode === 'off' ? 'selected' : ''}>사용 안 함</option></select></label>` : '';
  return `<div class="solver-configuration">${provider}
    <label>실행 계정<select id="solver-account-select" aria-label="문제 풀이 계정">${accountOptions}</select></label>
    <label>모델<select id="solver-model-select" aria-label="문제 풀이 모델" ${modelOptions ? '' : 'disabled'}>${modelOptions || '<option>사용 가능한 모델 없음</option>'}</select></label>
    <label>추론 수준<select id="solver-reasoning-select" aria-label="문제 풀이 추론 수준" ${effortOptions ? '' : 'disabled'}>${effortOptions || '<option>지원 정보 없음</option>'}</select></label>
    ${supportsFast ? `<label class="solver-fast-choice"><input id="solver-fast-toggle" type="checkbox" ${solverServiceTier === 'fast' ? 'checked' : ''}>1.5배 Fast 실행</label>` : supportsUltracode ? `<label class="solver-ultracode-choice"><input id="solver-ultracode-toggle" type="checkbox" ${solverUltracode ? 'checked' : ''}>Ultracode</label>` : '<span class="solver-fast-placeholder" aria-hidden="true"></span>'}
    ${ultraChoice}
    <span class="form-hint solver-config-help">이번 실행에만 적용</span>
  </div>`;
}

function solverPanelMarkup(job, events = [], loading = false) {
  if (loading) return '<div class="solver-panel-head"><h3>문제 풀이</h3><span class="connection-state">확인 중</span></div>';
  const writeup = job?.flag_rejected ? '' : solverWriteup(job);
  if (!job) return `<div class="solver-panel-head"><h3>문제 풀이</h3><span class="connection-state">실행 전</span></div>
    ${solverWriteupArtifact(writeup)}
    ${solverProviderSelector()}
    <button class="primary" data-action="start-solver" ${solverConfigurationReady() ? '' : 'disabled'}>풀이 시작</button>`;
  const active = solverIsActive(job), model = job.model || job.configuration || {};
  const progress = job.progress || {};
  const progressCode = progress.code || job.progress_code;
  const percent = Number(progress.percent ?? job.percent);
  const progressText = progressCode ? (solverProgress[progressCode] || progressCode) : '';
  const modelText = [job.account_label, model.provider, model.model, model.reasoning_effort && `${i18n.t('추론')} ${model.reasoning_effort}`, model.ultracode ? 'Ultracode' : null, model.service_tier === 'fast' ? 'Fast 1.5×' : null].filter(Boolean).join(' · ');
  const flag = typeof job.flag === 'string' && job.flag ? job.flag : '';
  const usableFlag = flag && !job.flag_rejected;
  const retryCount = Number(job.retry_checkpoint?.rejected_count || 0);
  const checkpointReason = job.retry_checkpoint?.reason;
  const checkpointLabels = {rejected_flag:'오답',needs_remote:'원격 정보 요청',timeout:'시간 제한',cancelled:'사용자 중단',provider_failure:'모델 오류',turn_limit:'풀이 회차 종료',ultra_escalation:'Ultra 전환'};
  const controls = active
    ? `<button class="danger" data-action="cancel-solver" ${job.cancel_requested ? 'disabled' : ''}>${job.cancel_requested ? '중단 처리 중' : '풀이 중단'}</button>`
    : job.error?.code === 'ultra_escalation_requested'
      ? `${job.ultra_escalation?.started_job_id ? '<span class="form-hint">Ultra 작업으로 이어가는 중</span>' : job.ultra_escalation?.auto_pending ? '<span class="form-hint">Ultra 전환 준비 중</span>' : job.ultra_escalation?.eligible ? '<button class="primary" data-action="approve-ultra-escalation">Ultra로 이어가기</button>' : ''}<button data-action="start-solver" ${solverConfigurationReady() ? '' : 'disabled'}>현재 설정으로 다시 풀기</button>`
    : job.phase === 'needs_input'
      ? `<button data-action="edit-challenge">원격 접속 정보 입력</button>${currentChallenge?.remote_mode !== 'unknown' ? `<button class="primary" data-action="start-solver" ${solverConfigurationReady() ? '' : 'disabled'}>새 작업으로 계속 풀기</button>` : ''}`
      : job.flag_rejected
      ? `<button class="primary" data-action="start-solver" ${solverConfigurationReady() ? '' : 'disabled'}>오답을 제외하고 다시 풀기</button>`
      : job.phase === 'completed'
      ? '<p class="form-hint">다시 실행하려면 먼저 위의 완료 취소를 눌러 미완료 상태로 되돌리세요.</p>'
      : `<button class="primary" data-action="start-solver" ${solverConfigurationReady() ? '' : 'disabled'}>다시 풀기</button>`;
  return `<div class="solver-panel-head"><h3>문제 풀이</h3><span class="solver-phase solver-phase-${esc(job.phase)}">${esc(active && job.cancel_requested ? '중단 요청 중' : (solverPhases[job.phase] || job.phase))}</span></div>
    ${modelText ? `<p class="solver-model">${esc(modelText)}</p>` : ''}
    ${job.network_policy === 'general_internet' ? '<p class="form-hint solver-limit">인터넷 사용 가능</p>' : ''}
    ${job.retry_checkpoint ? `<p class="notice muted solver-retry-context">체크포인트 · ${esc(checkpointLabels[checkpointReason] || '이전 작업')}${retryCount ? ` · 오답 ${retryCount}개` : ''}</p>` : ''}
    ${job.phase === 'queued' && Number.isFinite(Number(job.queue_position)) ? `<p class="form-hint">대기 순서 ${Math.max(1,Number(job.queue_position))}번째</p>` : ''}
    ${progressText ? `<div class="solver-progress"><span>${esc(progressText)}</span>${Number.isFinite(percent) ? `<progress max="100" value="${Math.max(0,Math.min(100,percent))}" aria-label="${esc(progressText)} 진행률"></progress>` : ''}</div>` : ''}
    ${usableFlag ? `<div class="solver-artifact solver-flag-found" role="status" aria-live="assertive"><strong>Flag를 발견했습니다</strong><code>${esc(flag)}</code><div class="actions"><button type="button" class="small ghost icon-action" data-action="copy-solver-flag" aria-label="Flag 복사" title="Flag 복사">⚑</button>${!active && currentChallenge?.completion_source !== 'manual' ? '<button type="button" class="small danger ghost" data-action="reject-solver-flag">오답으로 제외</button>' : ''}</div></div>` : ''}
    ${job.flag_rejected ? `<div class="solver-artifact solver-flag-rejected" role="status"><strong>제외한 Flag</strong><code>${esc(flag)}</code></div>` : ''}
    ${solverWriteupArtifact(writeup)}
    ${solverErrorMarkup(job.error)}
    ${solverSessionMarkup(job,events,active)}
    ${solverGuidanceMarkup(job,active)}
    ${active ? '' : solverProviderSelector()}
    <div class="actions solver-actions">${controls}</div>`;
}

function rememberNotes() {
  const editor = document.querySelector('#notes-editor');
  if (!detail.open || !currentChallenge || !editor) return;
  const key = noteKey(currentChallenge);
  if (editor.value !== currentChallenge.notes) {
    noteDrafts.set(key, {content:editor.value, baseline:currentChallenge.notes, token:currentChallenge.notes_token});
  } else noteDrafts.delete(key);
}

function notesDirty() {
  return detail.open && currentChallenge && document.querySelector('#notes-editor')?.value !== currentChallenge.notes;
}

function formDirty() {
  if (!modal.open) return false;
  const form = modal.querySelector('form');
  return Boolean(form && form.dataset.initial && form.dataset.initial !== formSnapshot(form));
}

function formSnapshot(form) {
  const values = [...new FormData(form)].map(([key,value]) => [key,value instanceof File ? (value.name ? `${value.name}:${value.size}:${value.lastModified}` : '') : value]);
  if (form?.id === 'new-challenge-form') values.push(['__selected_files__',selectedChallengeFiles(form).map(fileIdentity)]);
  return JSON.stringify(values);
}

function fileIdentity(file) {
  return `${file.name}\u0000${file.size}\u0000${file.lastModified || 0}`;
}

function selectedChallengeFiles(form) {
  return Array.isArray(form?._challengeFiles) ? form._challengeFiles : [];
}

function renderChallengeFiles(form) {
  if (!form) return;
  const files = selectedChallengeFiles(form);
  const zone = form.querySelector('[data-file-drop-zone]');
  const list = form.querySelector('#challenge-file-list');
  const summary = form.querySelector('#challenge-file-summary');
  zone?.classList.toggle('has-files',Boolean(files.length));
  if (summary) summary.textContent = files.length
    ? `${files.length}개 · ${size(files.reduce((total,file) => total + Number(file.size || 0),0))}`
    : '여러 파일 · 용량 제한 없음';
  if (!list) return;
  list.hidden = !files.length;
  list.innerHTML = files.map((file,index) => `<div class="challenge-file-row"><span class="challenge-file-type" aria-hidden="true">FILE</span><span><strong>${esc(file.name)}</strong><small>${size(Number(file.size || 0))}</small></span><button type="button" class="small danger" data-action="remove-challenge-file" data-index="${index}" aria-label="${esc(file.name)} 선택 취소" title="선택 취소">×</button></div>`).join('');
}

function addChallengeFiles(form, incoming) {
  if (!form || form.id !== 'new-challenge-form') return 0;
  const files = selectedChallengeFiles(form), known = new Set(files.map(fileIdentity));
  let added = 0;
  for (const file of Array.from(incoming || [])) {
    if (!file?.name || known.has(fileIdentity(file))) continue;
    files.push(file); known.add(fileIdentity(file)); added++;
  }
  form._challengeFiles = files;
  renderChallengeFiles(form);
  return added;
}

function activeChallengeUploadForm() {
  if (!modal.open) return null;
  const form = modal.querySelector('#new-challenge-form');
  return form && !busyForms.has(form) ? form : null;
}

function fileDrag(dataTransfer) {
  const types = Array.from(dataTransfer?.types || []);
  return types.includes('Files') || Boolean(dataTransfer?.files?.length);
}

function setChallengeFileDrag(active) {
  modal.classList?.toggle('file-drag-active',active);
  const overlay = modal.querySelector?.('.challenge-drop-screen');
  overlay?.setAttribute('aria-hidden',String(!active));
}

function resetChallengeFileDrag() {
  challengeFileDragDepth = 0;
  setChallengeFileDrag(false);
}

async function detailAction(task, button) {
  if (detailBusy) return;
  detailBusy = true;
  detail.setAttribute('aria-busy','true');
  const controls = [...detail.querySelectorAll('button,input,select')].filter(node => !['copy-notes','download-notes'].includes(node.dataset.action));
  const previous = controls.map(node => node.disabled);
  controls.forEach(node => { node.disabled = true; });
  try { await run(task, button); }
  finally {
    controls.forEach((node,index) => { node.disabled = previous[index]; });
    detailBusy = false; detail.removeAttribute('aria-busy');
  }
}

async function api(url, options = {}) {
  const headers = {...options.headers};
  if (csrf) headers['X-CSRF-Token'] = csrf;
  let body = options.body;
  if (body !== undefined && !(body instanceof FormData) && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(url, {...options, headers, body, credentials:'same-origin'});
  let result;
  try { result = await response.json(); } catch { result = {}; }
  if (!response.ok) {
    if (response.status === 401 && authMode === 'password' && !url.endsWith('/login')) { csrf = ''; showLogin(true); }
    const detail = result.detail;
    const payload = detail && typeof detail === 'object' && !Array.isArray(detail) ? detail : result;
    const message = Array.isArray(detail)
      ? detail.map(e => e.msg).join(' / ')
      : (typeof detail === 'string' ? detail : payload.message);
    const error = new Error(message || `요청에 실패했습니다 (${response.status}).`);
    error.status = response.status;
    for (const key of ['code','category','stage','retryable','provider_code','quota','requirements']) if (payload[key] !== undefined) error[key] = payload[key];
    throw error;
  }
  return result;
}

function toast(message, error = false) {
  const node = document.createElement('div');
  node.className = `toast${error ? ' error' : ''}`;
  node.textContent = message;
  node.setAttribute('role',error ? 'alert' : 'status');
  const topDialog = modal.open ? modal : detail.open ? detail : null;
  let target = topDialog ? topDialog.querySelector('.toasts') : document.querySelector('#toasts');
  if (!target) {
    target = document.createElement('div'); target.className = 'toasts'; target.setAttribute('aria-live','polite');
    topDialog.append(target);
  }
  target.append(node);
  setTimeout(() => node.remove(), error ? 8000 : 4000);
}

async function run(task, button) {
  // Start the action while the click still owns its transient user activation.
  // Clipboard writes can be rejected if the clicked control is disabled first.
  try {
    const pending = task();
    if (button) button.disabled = true;
    return await pending;
  } catch (error) { toast(error.message, true); }
  finally { if (button) button.disabled = false; }
}

async function runForm(task, form, button) {
  if (busyForms.has(form)) return;
  busyForms.add(form); form.setAttribute('aria-busy','true');
  const controls = [...form.querySelectorAll('input,select,textarea,button')], previous = controls.map(node => node.disabled);
  controls.forEach(node => { node.disabled = true; });
  try { await run(task,button); }
  finally { controls.forEach((node,index) => { node.disabled = previous[index]; }); busyForms.delete(form); form.removeAttribute('aria-busy'); }
}

function showLogin(expired = false, configured = true, setupAvailable = false) {
  if (solverConsoleDialog?.open) solverConsoleDialog.close();
  clearAccountsReturnTarget();
  ++modalRendering; ++ctfdSubmitRendering; challengeFlags.clear();
  stopSolverPolling();
  stopResourcePolling();
  stopChallengeListPolling();
  for (const upload of activeUploads.values()) upload.controller?.abort();
  activeUploads.clear(); uploadViews.clear();
  rememberNotes();
  disposeTelegram?.(); disposeTelegram = null;
  disposeAccounts?.(); disposeAccounts = null;
  modal.close(); detail.close();
  if (!configured && setupAvailable) {
    app.innerHTML = `<main class="login-shell"><div class="login-card">${i18n.picker()}
      <div class="brand"><img src="/assets/icon.svg" alt=""><div>CTF Workspace</div></div>
      <h1>관리자 계정 만들기</h1>
      <form id="setup-form"><label>아이디<input name="username" autocomplete="username" maxlength="100" required autofocus></label><label>비밀번호<input type="password" name="password" autocomplete="new-password" minlength="4" maxlength="1024" required></label><label>비밀번호 확인<input type="password" name="confirmation" autocomplete="new-password" minlength="4" maxlength="1024" required></label><button class="primary">관리자 계정 만들기 <span aria-hidden="true">→</span></button></form>
    </div></main>`;
    return;
  }
  app.innerHTML = `<main class="login-shell"><div class="login-card">${i18n.picker()}
    <div class="brand"><img src="/assets/icon.svg" alt=""><div>CTF Workspace</div></div>
    <h1>로그인</h1>
    ${!configured ? '<p>관리자 초기 비밀번호가 설정되지 않았습니다.</p>' : expired ? '<p>세션이 만료되었습니다.</p>' : ''}
    <form id="login-form"><label>아이디<input name="username" autocomplete="username" value="${esc(sessionUser?.username || '')}" maxlength="100" required autofocus></label><label>비밀번호<input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label><button class="primary" ${configured ? '' : 'disabled'}>로그인 <span aria-hidden="true">→</span></button></form>
  </div></main>`;
}

function toggleSidebar(button) {
  sidebarCollapsed = !sidebarCollapsed;
  try { localStorage.setItem('ctf-sidebar-collapsed', String(sidebarCollapsed)); } catch {}
  const layout = document.querySelector('.shell');
  layout?.classList.toggle('sidebar-collapsed',sidebarCollapsed);
  if (button) {
    button.setAttribute('aria-expanded',String(!sidebarCollapsed));
    button.setAttribute('aria-label',sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기');
    button.title = sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기';
    const icon = button.querySelector('[aria-hidden="true"]');
    if (icon) icon.textContent = sidebarCollapsed ? '»' : '«';
  }
}

function shell(active, breadcrumb = '모든 작업공간') {
  app.innerHTML = `<div class="shell ${sidebarCollapsed ? 'sidebar-collapsed' : ''}"><aside id="app-sidebar" class="sidebar">
    <div class="sidebar-head"><a class="brand" href="#" aria-label="CTF Workspace 홈"><img src="/assets/icon.svg" alt=""><div class="brand-copy">CTF Workspace</div></a><button type="button" class="sidebar-toggle icon-action" data-action="toggle-sidebar" aria-controls="app-sidebar" aria-expanded="${!sidebarCollapsed}" aria-label="${sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기'}" title="${sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기'}"><span aria-hidden="true">${sidebarCollapsed ? '»' : '«'}</span></button></div>
    <div class="nav-label">WORKSPACE</div><nav aria-label="기본 메뉴">
    <a class="nav-item ${active === 'workspaces' ? 'active' : ''}" href="#" aria-label="작업공간" ${active === 'workspaces' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">▦</span><span class="nav-text">작업공간</span><span class="nav-count">${workspaces.length}</span></a>
    <a class="nav-item ${active === 'accounts' ? 'active' : ''}" href="#accounts" aria-label="에이전트" ${active === 'accounts' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">◎</span><span class="nav-text">에이전트</span></a>
    <a class="nav-item ${active === 'settings' ? 'active' : ''}" href="#settings" aria-label="개인 설정" ${active === 'settings' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">⚙</span><span class="nav-text">개인 설정</span></a>
    ${sessionUser?.role === 'admin' ? `<a class="nav-item ${active === 'admin' ? 'active' : ''}" href="#admin" aria-label="관리자 설정" ${active === 'admin' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">◇</span><span class="nav-text">관리자 설정</span></a>` : ''}</nav>
    ${authMode === 'password' ? '<div class="sidebar-foot"><button class="ghost small" data-action="logout">로그아웃</button></div>' : ''}
    </aside><main class="main"><header class="topbar"><div class="breadcrumb"><a href="#">Workspace</a><span>/</span><span>${esc(breadcrumb)}</span></div><div class="topbar-meta">${i18n.picker()}<span>${esc(sessionUser?.username || '')}</span><div class="avatar" title="${esc(sessionUser?.username || '')}">${esc((sessionUser?.username || 'U').slice(0,1).toUpperCase())}</div></div></header><div id="content" class="content"></div></main></div>`;
  return document.querySelector('#content');
}

async function render() {
  const ticket = ++rendering;
  stopResourcePolling();
  stopChallengeListPolling();
  disposeAccounts?.(); disposeAccounts = null;
  disposeTelegram?.(); disposeTelegram = null;
  const listing = await api('/api/workspaces');
  if (ticket !== rendering) return;
  workspaces = listing.workspaces;
  const hash = location.hash.slice(1);
  if (hash === 'accounts') {
    currentWorkspace = null;
    const container = shell('accounts', '에이전트');
    const returnRoute = accountsReturnRoute();
    const dispose = await renderAccounts(container, api, {
      onReturnToChallenge: returnRoute ? returnFromAccounts : null,
    });
    if (ticket === rendering) disposeAccounts = dispose; else dispose?.();
    return;
  }
  if (hash === 'settings') { currentWorkspace = null; renderSettings(); return; }
  if (hash === 'admin') { currentWorkspace = null; await renderAdmin(); return; }
  const match = /^w\/([0-9a-f]{32})(?:\/c\/([0-9a-f]{32}))?$/.exec(hash);
  if (match) {
    const workspace = await api(`/api/workspaces/${match[1]}`);
    if (ticket !== rendering) return;
    currentWorkspace = workspace;
    await renderWorkspace();
    if (match[2] && ticket === rendering) await openChallenge(match[2]);
  } else { currentWorkspace = null; renderOverview(); }
}

function renderOverview() {
  const content = shell('workspaces');
  const total = workspaces.reduce((sum, w) => sum + w.challenge_count, 0);
  const solved = workspaces.reduce((sum, w) => sum + w.solved_count, 0);
  const running = workspaces.reduce((sum, w) => sum + w.running_count, 0);
  content.innerHTML = `<div class="page-head"><div><div class="eyebrow">WORKSPACES</div><h1>작업공간</h1></div><button class="primary" data-action="new-workspace">＋ 작업공간 만들기</button></div>
    <div class="stats"><div class="stat"><div class="stat-label">전체 작업공간</div><div class="stat-value">${workspaces.length}</div></div><div class="stat"><div class="stat-label">등록된 문제</div><div class="stat-value">${total}</div></div><div class="stat"><div class="stat-label">작업 중</div><div class="stat-value">${running}</div></div><div class="stat"><div class="stat-label">완료한 문제</div><div class="stat-value accent">${solved}</div><div class="stat-note">${total ? Math.round(solved / total * 100) : 0}%</div></div></div>
    <div class="section-head"><h2>내 작업공간 <span class="muted">${workspaces.length}</span></h2></div>
    ${workspaces.length ? `<div class="cards">${workspaces.map(w => `<a class="workspace-card" href="#w/${w.id}"><div class="card-top"><span class="folder-icon">⚑</span><span class="tag ${w.running_count ? '' : 'muted'}">${w.running_count ? `${w.running_count} ${i18n.t('작업 중')}` : 'WORKSPACE'}</span></div><h3>${esc(w.name)}</h3>${w.description ? `<p>${esc(w.description)}</p>` : ''}<div class="card-bottom"><span>${i18n.t('문제')} ${w.challenge_count}</span><span>${i18n.t('완료')} ${w.solved_count}</span><span class="card-arrow">↗</span></div></a>`).join('')}</div>` : `<div class="empty"><div class="empty-icon">⚑</div><h2>작업공간이 없습니다.</h2><button class="primary" data-action="new-workspace">＋ 새 작업공간</button></div>`}`;
}

async function renderWorkspace() {
  const w = currentWorkspace;
  stopChallengeListPolling();
  const content = shell('workspaces', w.name);
  content.innerHTML = `<div class="page-head"><div><div class="eyebrow">CTF WORKSPACE</div><h1>${esc(w.name)}</h1>${w.description ? `<p>${esc(w.description)}</p>` : ''}</div><div class="head-actions"><button class="ghost icon-action" data-action="edit-workspace" aria-label="작업공간 설정" title="작업공간 설정">⚙</button><button data-action="ctfd-submit-settings">자동 제출 설정</button><button data-action="ctfd-import">CTFd 가져오기</button><button data-action="ctfd-sync" title="저장된 CTFd 연결에서 새로 추가된 문제만 확인합니다.">새 문제 동기화</button><button class="primary" data-action="new-challenge">＋ 문제 추가</button></div></div>
    <div class="workspace-summary"><div class="workspace-summary-meta"><span>⚑ Flag 형식 <code>${esc(w.flag_format || '미설정')}</code></span><span>문제 <b data-workspace-challenge-count>${w.challenge_count ?? ''}</b></span></div>${resourceMeterMarkup()}</div>
    <div id="ctfd-job-area"></div><div id="challenge-area"></div>`;
  startResourcePolling(w.id);
  await refreshChallenges();
  startChallengeListPolling(w.id);
  pollCTFdJobs(w.id);
}

function challengeRunSummary(challenge) {
  const run = challenge.latest_solver || challenge.solver || challenge.latest_run || null;
  const configuration = run?.configuration || challenge.solver_configuration || null;
  if (!configuration || typeof configuration !== 'object') return '';
  const phase = run?.phase || run?.status;
  const parts = [run?.account_label, configuration.provider, configuration.model,
    configuration.reasoning_effort && `${i18n.t('추론')} ${configuration.reasoning_effort}`,
    configuration.ultracode ? 'Ultracode' : null,
    configuration.service_tier === 'fast' ? 'Fast 1.5×' : null,
    phase && (solverPhases[phase] || statuses[phase] || phase)];
  return parts.filter(Boolean).map(esc).join('<span aria-hidden="true">/</span>');
}

function challengeElapsedText(run) {
  const value = run?.elapsed_seconds;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '';
  const seconds = Math.floor(value);
  if (i18n.locale === 'en') {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m${seconds % 60 ? ` ${seconds % 60}s` : ''}`;
    return `${Math.floor(seconds / 3600)}h${Math.floor(seconds % 3600 / 60) ? ` ${Math.floor(seconds % 3600 / 60)}m` : ''}`;
  }
  if (seconds < 60) return `${seconds}초`;
  const minutes = Math.floor(seconds / 60), remainder = seconds % 60;
  if (minutes < 60) return remainder ? `${minutes}분 ${remainder}초` : `${minutes}분`;
  const hours = Math.floor(minutes / 60), minuteRemainder = minutes % 60;
  return minuteRemainder ? `${hours}시간 ${minuteRemainder}분` : `${hours}시간`;
}

function challengeInputMarkup(challenge, workspaceId) {
  const mode = challenge.remote_mode === 'none' ? 'none' : 'endpoint';
  return `<form class="challenge-inline-input" data-workspace-id="${esc(workspaceId)}" data-challenge-id="${esc(challenge.id)}" data-edit-token="${esc(challenge.edit_token || '')}" data-name="${esc(challenge.name)}">
    <div><strong>추가 입력 필요</strong><small>접속 정보를 입력하면 이어서 풉니다.</small></div>
    <label><span class="sr-only">원격 대상</span><select name="remote_mode" aria-label="원격 대상"><option value="endpoint" ${mode === 'endpoint' ? 'selected' : ''}>접속 정보</option><option value="none" ${mode === 'none' ? 'selected' : ''}>원격 대상 없음</option></select></label>
    <label class="challenge-inline-remote${mode === 'none' ? ' is-disabled' : ''}"><span class="sr-only">원격 접속 정보</span><input name="remote" value="${esc(challenge.remote || '')}" maxlength="2000" placeholder="URL 또는 nc host port" aria-label="원격 접속 정보" ${mode === 'endpoint' ? 'required' : 'disabled'}></label>
    <button type="submit" class="small primary">계속 풀기</button>
  </form>`;
}

function challengeCardMarkup(challenge, workspaceId) {
  const category = challenge.category || '미분류';
  const statusLabel = statuses[challenge.status] || challenge.status;
  const manual = challenge.completion_source === 'manual';
  const canCopyWriteup = challenge.has_writeup === true && !manual;
  const latestRun = challenge.latest_solver || challenge.solver || challenge.latest_run || null;
  const elapsed = challenge.status === 'solved' && !manual ? challengeElapsedText(latestRun) : '';
  const runSummary = challengeRunSummary(challenge);
  const runPhase = latestRun?.phase || latestRun?.status;
  const liveSession = latestRun && !solverTerminalPhases.has(runPhase);
  const needsInput = runPhase === 'needs_input';
  const canStart = !needsInput && ['pending','stopped','failed'].includes(challenge.status);
  const startKey = `${workspaceId}:${challenge.id}`;
  const starting = canStart && startingListSolvers.has(startKey);
  const openLabel = challenge.status === 'solved' ? '결과 보기' : challenge.status === 'running' ? '진행 보기' : challenge.status === 'flag_found' ? 'Flag 확인' : '풀이 설정';
  return `<article class="challenge-card challenge-card-${esc(challenge.status)}" data-challenge-id="${esc(challenge.id)}" role="listitem">
    <div class="challenge-card-top"><span class="challenge-category">${esc(category)}</span><span class="challenge-card-status"><span class="status-dot" aria-hidden="true"></span>${esc(statusLabel)}${elapsed ? `<small title="${latestRun.elapsed_includes_queue ? '대기 포함 소요 시간' : '풀이 시간'}">· ${esc(elapsed)}</small>` : ''}</span></div>
    <button type="button" class="challenge-card-title" data-action="open-challenge" data-id="${esc(challenge.id)}" aria-label="${esc(challenge.name)} 문제 열기">${esc(challenge.name)}</button>
    ${challenge.description ? `<p class="challenge-card-description">${esc(challenge.description)}</p>` : ''}
    ${runSummary ? `<div class="challenge-run-summary" aria-label="최근 실행 설정">${runSummary}</div>` : ''}
    ${challenge.flag ? `<div class="challenge-card-flag"><code>${esc(challenge.flag)}</code><span>FLAG READY</span></div>` : manual ? '<div class="challenge-card-note">수동 완료</div>' : ''}
    ${needsInput ? challengeInputMarkup(challenge,workspaceId) : ''}
    <footer class="challenge-card-footer"><span class="challenge-updated">${esc(date(challenge.updated_at))}</span><div class="challenge-card-actions">
      ${challenge.flag ? `<button type="button" class="small ghost icon-action flag-action" data-action="copy-list-flag" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" aria-label="${esc(challenge.name)} Flag 복사" title="Flag 복사">⚑</button>` : ''}
      ${canCopyWriteup ? `<button type="button" class="small ghost icon-action writeup-action" data-action="copy-list-writeup" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" aria-label="${esc(challenge.name)} write-up 복사" title="write-up 복사">▤</button>` : ''}
      ${latestRun ? `<button type="button" class="small ghost session-action${liveSession ? ' live' : ''}" data-action="open-solver-session" data-id="${esc(challenge.id)}" data-live="${liveSession}" aria-label="${esc(challenge.name)} ${liveSession ? '실시간 풀이 터미널' : '이전 풀이 터미널'} 보기" title="${liveSession ? '실시간 풀이 터미널' : '이전 풀이 터미널'}">${liveSession ? '<span class="session-live-dot" aria-hidden="true"></span>LIVE' : '<span aria-hidden="true">&gt;_</span>'}</button>` : ''}
      ${canStart ? `<button type="button" class="small ghost complete-action" data-action="complete-list-challenge" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" data-name="${esc(challenge.name)}" aria-label="${esc(challenge.name)} 수동 완료">수동 완료</button>` : ''}
      ${canStart ? `<button type="button" class="small primary solve-action" data-action="start-list-solver" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" data-name="${esc(challenge.name)}" aria-label="${esc(challenge.name)} 기본 설정으로 풀이 시작" title="기본 설정으로 풀이 시작" ${starting ? 'disabled aria-busy="true"' : ''}>${starting ? '시작 중' : '▶ 풀이 시작'}</button>` : ''}
      <button type="button" class="small challenge-open-action" data-action="open-challenge" data-id="${esc(challenge.id)}">${openLabel} <span aria-hidden="true">↗</span></button>
    </div></footer>
  </article>`;
}

function challengeCardSignature(challenge) {
  return JSON.stringify({
    id:challenge.id,name:challenge.name,category:challenge.category,description:challenge.description,
    status:challenge.status,flag:challenge.flag,completion_source:challenge.completion_source,
    has_writeup:challenge.has_writeup,updated_at:challenge.updated_at,
    latest_solver:challenge.latest_solver || challenge.solver || challenge.latest_run || null,
  });
}

function challengeListParams() {
  const params = new URLSearchParams();
  if (selectedStatus) params.set('status',selectedStatus);
  if (selectedCategory) params.set('category',selectedCategory);
  if (search) params.set('q',search);
  if (selectedSort !== 'added_desc') params.set('sort',selectedSort);
  return params;
}

function challengeListingMarkup(result, workspaceId) {
  const total = Object.values(result.counts).reduce((a,b) => a+b,0);
  return `<div class="toolbar"><div class="filters challenge-status-strip" aria-label="상태 필터"><button class="filter ${!selectedStatus ? 'active' : ''}" data-action="filter" data-status="" aria-pressed="${!selectedStatus}">전체<span>${total}</span></button>${Object.entries(statuses).map(([key,label]) => `<button class="filter status-filter-${key} ${selectedStatus === key ? 'active' : ''}" data-action="filter" data-status="${key}" aria-pressed="${selectedStatus === key}"><i aria-hidden="true"></i>${label}<span>${result.counts[key]}</span></button>`).join('')}</div>
    <form id="search-form" class="search-wrap"><label class="sr-only" for="search-input">문제 검색</label><input id="search-input" name="q" value="${esc(search)}" placeholder="문제 이름, 설명 검색"><label class="sr-only" for="category-filter">분류</label><select id="category-filter"><option value="">모든 분류</option>${result.categories.map(c => `<option ${c === selectedCategory ? 'selected' : ''} value="${esc(c)}">${esc(c)}</option>`).join('')}</select><label class="sr-only" for="sort-order">정렬</label><select id="sort-order" name="sort"><option value="added_desc" ${selectedSort === 'added_desc' ? 'selected' : ''}>최근 추가순</option><option value="added_asc" ${selectedSort === 'added_asc' ? 'selected' : ''}>오래된 추가순</option><option value="name_asc" ${selectedSort === 'name_asc' ? 'selected' : ''}>이름 오름차순</option><option value="name_desc" ${selectedSort === 'name_desc' ? 'selected' : ''}>이름 내림차순</option><option value="solver_desc" ${selectedSort === 'solver_desc' ? 'selected' : ''}>최근 풀이 시작순</option><option value="solver_asc" ${selectedSort === 'solver_asc' ? 'selected' : ''}>오래된 풀이 시작순</option></select><button class="small" type="submit">검색</button></form></div>
    ${result.challenges.length ? `<div class="challenge-card-grid" role="list" aria-label="문제 목록" aria-live="polite">${result.challenges.map(c => challengeCardMarkup(c,workspaceId)).join('')}</div><div class="table-footer">${result.challenges.length}개 문제</div>` : `<div class="empty"><div class="empty-icon">▤</div><h2>${total ? '조건에 맞는 문제가 없습니다.' : '등록된 문제가 없습니다.'}</h2>${total ? '<button data-action="clear-filter">필터 초기화</button>' : '<button class="primary" data-action="new-challenge">＋ 문제 추가</button>'}</div>`}<p id="challenge-live-state" class="sr-only" role="status" aria-live="polite"></p>`;
}

function paintChallengeListing(result, workspaceId, patchOnly = false) {
  const area = document.querySelector('#challenge-area');
  if (!area || currentWorkspace?.id !== workspaceId) return false;
  const challenges = Array.isArray(result?.challenges) ? result.challenges : [];
  const counts = result?.counts && typeof result.counts === 'object' ? result.counts : {};
  const categories = Array.isArray(result?.categories) ? result.categories : [];
  const total = Object.values(counts).reduce((sum,value) => sum + Number(value || 0),0);
  challengeFlags = new Map(challenges.filter(challenge => challenge.flag).map(challenge => [challenge.id,challenge.flag]));
  if (currentWorkspace) {
    currentWorkspace.challenge_count = total;
    currentWorkspace.solved_count = Number(counts.solved || 0);
    currentWorkspace.running_count = Number(counts.running || 0);
  }
  const countNode = document.querySelector('[data-workspace-challenge-count]');
  if (countNode) countNode.textContent = String(total);
  const signatures = new Map(challenges.map(challenge => [challenge.id,challengeCardSignature(challenge)]));
  const categoryKey = JSON.stringify(categories);
  const grid = area.querySelector?.('.challenge-card-grid');
  const cards = grid ? [...grid.querySelectorAll('[data-challenge-id]')] : [];
  const sameCards = cards.length === challenges.length && cards.every((card,index) => card.dataset.challengeId === challenges[index]?.id);
  if (!patchOnly || !grid || !sameCards || categoryKey !== challengeListCategories) {
    area.innerHTML = challengeListingMarkup({challenges,counts,categories},workspaceId);
    challengeListSignatures = signatures;
    challengeListCategories = categoryKey;
    return true;
  }
  let changed = 0;
  for (let index = 0; index < challenges.length; index++) {
    const challenge = challenges[index], card = cards[index], signature = signatures.get(challenge.id);
    if (challengeListSignatures.get(challenge.id) === signature) continue;
    const template = document.createElement('template');
    template.innerHTML = challengeCardMarkup(challenge,workspaceId).trim();
    const replacement = template.content?.firstElementChild;
    if (!replacement) return false;
    card.replaceWith(replacement);
    changed++;
  }
  for (const button of area.querySelectorAll?.('[data-action="filter"]') || []) {
    const key = button.dataset.status;
    const value = key ? Number(counts[key] || 0) : total;
    const number = button.querySelector('span');
    if (number) number.textContent = String(value);
  }
  const footer = area.querySelector?.('.table-footer');
  if (footer) footer.textContent = `${challenges.length}개 문제`;
  challengeListSignatures = signatures;
  challengeListCategories = categoryKey;
  if (changed) {
    const live = document.querySelector('#challenge-live-state');
    if (live) live.textContent = `문제 ${changed}개의 상태가 갱신되었습니다.`;
  }
  return true;
}

async function copyChallengeWriteup(button) {
  const workspaceId = button.dataset.workspaceId, challengeId = button.dataset.id;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error('문제 목록을 다시 불러와 주세요.');
  button.disabled = true; button.setAttribute('aria-busy','true');
  try {
    const artifact = await api(`${path(challengeId,workspaceId)}/writeup`);
    if (!currentWorkspace || currentWorkspace.id !== workspaceId || typeof artifact?.markdown !== 'string' || !artifact.markdown) throw new Error('write-up을 다시 불러와 주세요.');
    await copyText(artifact.markdown); toast('write-up을 복사했습니다.');
  } finally {
    if (button.isConnected) { button.disabled = false; button.removeAttribute('aria-busy'); }
  }
}

async function completeListChallenge(button) {
  const workspaceId = button.dataset.workspaceId, challengeId = button.dataset.id;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error('문제 목록을 다시 불러와 주세요.');
  if (!confirm(`“${button.dataset.name || '이 문제'}”를 수동 완료로 기록할까요?`)) return;
  await api(`${path(challengeId,workspaceId)}/complete`,{method:'POST'});
  if (currentWorkspace?.id === workspaceId) await refreshChallenges();
  toast('수동 완료로 기록했습니다.');
}

async function startListSolver(button) {
  const workspaceId = button.dataset.workspaceId, challengeId = button.dataset.id;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error('문제 목록을 다시 불러와 주세요.');
  const key = `${workspaceId}:${challengeId}`;
  if (startingListSolvers.has(key)) return;
  startingListSolvers.add(key);
  button.disabled = true;
  button.setAttribute('aria-busy','true');
  const previousText = button.textContent;
  button.textContent = '시작 중';
  let started = false;
  try {
    const payload = await api(`${path(challengeId,workspaceId)}/solver`,{
      method:'POST',body:{provider:solverProvider,writeup_locale:i18n.locale},
    });
    started = true;
    if (payload.capacity?.warning && payload.capacity.warning_message) toast(payload.capacity.warning_message);
    if (currentWorkspace?.id === workspaceId) await refreshChallenges().catch(() => {});
    toast(`“${button.dataset.name || '문제'}” 풀이를 시작했습니다.`);
  } finally {
    startingListSolvers.delete(key);
    if (!started && currentWorkspace?.id === workspaceId) refreshChallenges().catch(() => {});
    if (button.isConnected) {
      button.disabled = false;
      button.removeAttribute('aria-busy');
      button.textContent = previousText;
    }
  }
}

async function continueListSolver(form, data) {
  const workspaceId = form.dataset.workspaceId, challengeId = form.dataset.challengeId;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error('문제 목록을 다시 불러와 주세요.');
  const remoteMode = data.remote_mode === 'none' ? 'none' : 'endpoint';
  const remote = remoteMode === 'endpoint' ? String(data.remote || '').trim() : '';
  if (remoteMode === 'endpoint' && !remote) throw new Error('원격 접속 정보를 입력하세요.');
  const updated = await api(path(challengeId,workspaceId),{
    method:'PATCH',headers:conditional(form.dataset.editToken),body:{remote_mode:remoteMode,remote},
  });
  form.dataset.editToken = updated.edit_token || '';
  const button = form.querySelector('button[type="submit"]');
  button.dataset.id = challengeId; button.dataset.workspaceId = workspaceId; button.dataset.name = form.dataset.name;
  await startListSolver(button);
}

async function refreshChallenges() {
  if (!currentWorkspace || !document.querySelector('#challenge-area')) return;
  const ticket = ++listRendering, workspaceId = currentWorkspace.id;
  const params = challengeListParams();
  const result = await api(`${path(null,workspaceId)}?${params}`);
  if (ticket !== listRendering || currentWorkspace?.id !== workspaceId) return;
  paintChallengeListing(result,workspaceId);
}

function scheduleChallengeListPoll(workspaceId, generation, delay = 2000) {
  if (generation !== challengeListPollGeneration || currentWorkspace?.id !== workspaceId || document.visibilityState === 'hidden') return;
  if (challengeListPollTimer !== null) clearTimeout(challengeListPollTimer);
  challengeListPollTimer = setTimeout(() => pollChallengeList(workspaceId,generation),delay);
}

async function pollChallengeList(workspaceId, generation) {
  challengeListPollTimer = null;
  if (generation !== challengeListPollGeneration || currentWorkspace?.id !== workspaceId || document.visibilityState === 'hidden') return;
  const ticket = listRendering, query = challengeListParams().toString();
  try {
    const result = await api(`${path(null,workspaceId)}?${query}`);
    if (generation !== challengeListPollGeneration || ticket !== listRendering || currentWorkspace?.id !== workspaceId) return;
    if (!paintChallengeListing(result,workspaceId,true)) await refreshChallenges();
  } catch { /* Keep the last visible state and retry. */ }
  scheduleChallengeListPoll(workspaceId,generation);
}

function startChallengeListPolling(workspaceId) {
  stopChallengeListPolling();
  scheduleChallengeListPoll(workspaceId,challengeListPollGeneration);
}

function openModal(title, subtitle, body, footer, formId) {
  ++modalRendering;
  resetChallengeFileDrag();
  modal.removeAttribute('aria-busy');
  modal.dataset.kind = ''; modal.dataset.workspaceId = '';
  modal.innerHTML = `${formId ? `<form id="${formId}">` : ''}<div class="dialog-head"><div><h2 id="modal-title">${esc(title)}</h2>${subtitle ? `<p>${esc(subtitle)}</p>` : ''}</div><button type="button" class="icon-btn icon-action" data-action="close-modal" aria-label="닫기" title="닫기">×</button></div><div class="dialog-body">${body}</div><div class="dialog-foot">${footer || '<button type="button" class="icon-action" data-action="close-modal" aria-label="닫기" title="닫기">×</button>'}</div>${formId ? '</form>' : ''}`;
  modal.setAttribute('aria-labelledby','modal-title');
  const form = modal.querySelector('form');
  if (form) { form.dataset.initial = formSnapshot(form); form.dataset.workspaceId = currentWorkspace?.id || ''; }
  if (!modal.open) modal.showModal();
}

function workspaceForm(edit = false) {
  const w = edit ? currentWorkspace : {};
  openModal(edit ? '작업공간 설정' : '새 작업공간 만들기', '', `
    <label>작업공간 이름<input name="name" value="${esc(w.name)}" placeholder="예: 2026 가을 CTF" maxlength="160" required autofocus></label>
    <label>설명 <span class="optional">선택</span><textarea name="description" rows="3" placeholder="대회 일정이나 기억할 내용을 적어 주세요.">${esc(w.description)}</textarea></label>
    <label>Flag 형식 <span class="optional">선택</span><input name="flag_format" value="${esc(w.flag_format)}" maxlength="500"><span class="form-hint">접두어만 입력하면 {…} 형식을 적용합니다.</span></label>
    <label class="workspace-option"><input type="checkbox" name="open_challenge_after_create" ${w.open_challenge_after_create ? 'checked' : ''}><span>문제 등록 후 상세창 열기</span></label>
    ${edit ? '<div class="danger-zone"><button class="danger small icon-action" type="button" data-action="delete-workspace" aria-label="작업공간 삭제" title="작업공간 삭제">⌫</button></div>' : ''}`, `<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">${edit ? '변경 저장' : '작업공간 만들기'}</button>`, edit ? 'edit-workspace-form' : 'new-workspace-form');
  if (edit) modal.querySelector('form').dataset.editToken = w.edit_token || '';
}

function challengeForm(edit = false) {
  const c = edit ? currentChallenge : {};
  const remoteMode = c.remote_mode || (c.remote ? 'endpoint' : 'unknown');
  openModal(edit ? '문제 수정' : '문제 추가', '', `
    <label>문제 이름<input name="name" value="${esc(c.name)}" placeholder="문제 이름을 입력하세요" maxlength="200" required autofocus></label>
    <label>분류 <span class="optional">선택</span><input name="category" value="${esc(c.category)}" placeholder="예: Web, Crypto, Reversing" maxlength="100"></label>
    <label>문제 설명<textarea name="description" rows="5" placeholder="문제 설명, 접속 정보, 참고 내용을 붙여 넣으세요.">${esc(c.description)}</textarea></label>
    <label>원격 대상<select name="remote_mode"><option value="unknown" ${remoteMode === 'unknown' ? 'selected' : ''}>아직 모름 · 풀이 중 요청 가능</option><option value="endpoint" ${remoteMode === 'endpoint' ? 'selected' : ''}>원격 대상 있음</option><option value="none" ${remoteMode === 'none' ? 'selected' : ''}>원격 대상 없음</option></select></label>
    <label data-remote-endpoint>원격 접속 정보<textarea name="remote" rows="2" maxlength="2000" placeholder="예: nc challenge.example 31337 또는 https://challenge.example/">${esc(c.remote)}</textarea></label>
    <label>Flag <span class="optional">선택</span><input name="flag" value="${esc(c.flag)}" placeholder="찾은 Flag를 기록하세요" maxlength="4000"></label>
    ${edit ? '' : `<section class="challenge-file-picker" data-file-drop-zone>
      <div class="challenge-file-heading"><span>문제 파일 <span class="optional">선택</span></span><strong id="challenge-file-summary">여러 파일 · 용량 제한 없음</strong></div>
      <input id="challenge-files" class="sr-only" type="file" name="files" multiple>
      <label class="challenge-file-target" for="challenge-files">
        <span class="challenge-file-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/></svg></span>
        <span><strong>파일을 끌어놓거나 선택</strong><small>여러 파일을 한 번에 추가할 수 있습니다.</small></span>
      </label>
      <div id="challenge-file-list" class="challenge-file-list" hidden></div>
    </section>
    <div class="challenge-drop-screen" aria-hidden="true"><div><span class="challenge-file-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/></svg></span><strong>여기에 놓아 문제 파일 추가</strong><small>여러 파일을 함께 놓을 수 있습니다.</small></div></div>`}`, '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">저장</button>', edit ? 'edit-challenge-form' : 'new-challenge-form');
  const form = modal.querySelector('form');
  const mode = form.elements.remote_mode, endpoint = form.querySelector('[data-remote-endpoint]'), remote = form.elements.remote;
  const syncRemoteMode = () => {
    const enabled = mode.value === 'endpoint';
    endpoint.classList.toggle('hidden', !enabled);
    remote.disabled = !enabled;
    remote.required = enabled;
  };
  mode.addEventListener('change', syncRemoteMode);
  syncRemoteMode();
  if (!edit) { form._challengeFiles = []; renderChallengeFiles(form); }
  if (edit) { form.dataset.editToken = c.edit_token || ''; form.dataset.challengeId = c.id; }
}

function challengeStatusMarkup(challenge) {
  return `<div id="challenge-status-badge">${badge(challenge.status)}</div>${challenge.completion_source === 'manual' ? '<span class="tag muted">수동 완료</span>' : ''}
    ${challenge.status === 'solved' ? '<button data-action="reopen" class="primary">완료 취소</button>' : `<label class="sr-only" for="status-select">기록할 상태</label><select id="status-select">${Object.entries(statuses).filter(([key]) => key !== 'solved').map(([key,label]) => `<option value="${key}" ${challenge.status === key ? 'selected' : ''}>${label}</option>`).join('')}</select><button data-action="complete" class="primary">✓ 수동 완료</button>`}`;
}

function relatedChallengeLabel(challenge) {
  const source = challenge.ctfd_id != null ? `CTFd #${challenge.ctfd_id}` : challenge.id.slice(0,8);
  return `${challenge.name} · ${challenge.category || i18n.t('분야 미지정')} · ${source}`;
}

function relatedChallengeMarkup(challenge) {
  const linked = challenge.related_challenges || challenge.prerequisites || [];
  const linkedIds = new Set(linked.map(item => item.id));
  const available = relatedCandidates.filter(item => item.id !== challenge.id && !linkedIds.has(item.id));
  return `<h3>연결된 문제</h3><div class="related-challenge-list">${linked.length ? linked.map(item =>
    `<div class="file-item"><div><button type="button" class="small ghost" data-action="open-related-challenge" data-id="${esc(item.id)}">${esc(relatedChallengeLabel(item))}</button><small>${esc(statuses[item.status] || item.status)}</small></div><button type="button" class="small danger icon-action" data-action="remove-relation" data-id="${esc(item.id)}" aria-label="문제 연결 해제" title="문제 연결 해제">×</button></div>`).join('') : '<p class="muted">없음</p>'}</div>
    ${available.length ? `<div class="related-add"><label class="sr-only" for="related-challenge-select">연결할 문제 선택</label><select id="related-challenge-select"><option value="">문제 선택</option>${available.map(item => `<option value="${esc(item.id)}">${esc(relatedChallengeLabel(item))}</option>`).join('')}</select><button type="button" class="small ghost" data-action="add-relation">연결</button></div>` : ''}`;
}

async function loadRelatedChallenges(challenge) {
  relatedCandidates = [];
  const area = detail.querySelector('#challenge-relations');
  if (area) area.innerHTML = relatedChallengeMarkup(challenge);
  const result = await api(`${path(challenge.id,challenge.workspace_id)}/relations/candidates`);
  if (currentChallenge !== challenge || !detail.open) return;
  relatedCandidates = result.challenges || [];
  const current = detail.querySelector('#challenge-relations');
  if (current) current.innerHTML = relatedChallengeMarkup(challenge);
}

async function changeRelation(removeId = null) {
  const challenge = currentChallenge;
  const relatedId = removeId || detail.querySelector('#related-challenge-select')?.value;
  if (!challenge || !relatedId) return;
  const endpoint = `${path(challenge.id,challenge.workspace_id)}/relations`;
  const result = await api(removeId ? `${endpoint}/${encodeURIComponent(relatedId)}` : endpoint,
    removeId ? {method:'DELETE'} : {method:'POST',body:{related_id:relatedId}});
  if (currentChallenge !== challenge) return;
  challenge.related_challenges = result.related_challenges || [];
  const area = detail.querySelector('#challenge-relations');
  if (area) area.innerHTML = relatedChallengeMarkup(challenge);
}

async function openChallenge(id, focusSolverSession = false, expandSolverSession = false) {
  rememberNotes();
  stopSolverPolling();
  if (solverConsoleDialog?.open) solverConsoleDialog.close();
  const ticket = ++challengeRendering, workspaceId = currentWorkspace.id;
  const c = await api(path(id,workspaceId));
  if (ticket !== challengeRendering || currentWorkspace?.id !== workspaceId) return;
  rememberNotes();
  const draft = noteDrafts.get(noteKey(c));
  const displayedNotes = draft ? draft.content : c.notes;
  if (draft) { c.notes = draft.baseline; c.notes_token = draft.token; }
  currentChallenge = c;
  detail.setAttribute('aria-labelledby','challenge-title');
  const refreshKey = `${c.workspace_id}:${c.id}`;
  const refreshingFromCTFd = activeCTFdChallengeRefreshes.has(refreshKey);
  const ctfdRefreshButton = c.ctfd_id !== null && c.ctfd_id !== undefined && c.ctfd_url
    ? `<button class="small ghost icon-action" data-action="refresh-ctfd-challenge" aria-label="CTFd 원본에서 문제 새로고침" title="CTFd 원본에서 문제 새로고침" aria-describedby="ctfd-refresh-help" ${refreshingFromCTFd ? 'disabled aria-busy="true"' : ''}>${refreshingFromCTFd ? '…' : '↻'}</button>` : '';
  detail.innerHTML = `<div class="dialog-head"><div><div class="eyebrow">${esc(c.category || 'CHALLENGE')}</div><h2 id="challenge-title">${esc(c.name)}</h2><p>${esc(currentWorkspace.name)}</p></div><div class="line-actions">${ctfdRefreshButton}<button class="small icon-action" data-action="clone-challenge" aria-label="문제 복제" title="문제 복제">⧉</button><button class="small icon-action" data-action="edit-challenge" aria-label="문제 수정" title="문제 수정">✎</button><button class="icon-btn icon-action" data-action="close-detail" aria-label="문제 닫기" title="문제 닫기">×</button></div></div>
    <div class="detail-grid"><div class="detail-main">${c.description ? `<h3>문제 설명</h3><div class="description">${esc(c.description)}</div>` : ''}
    ${c.remote_mode === 'endpoint' && c.remote ? `<h3>원격 접속 정보</h3><div class="description"><code>${esc(c.remote)}</code></div>` : c.remote_mode === 'none' ? '<span class="tag muted">원격 대상 없음</span>' : '<span class="tag muted">원격 정보 미등록</span>'}
    <div class="section-head"><h3>풀이 노트</h3><span class="tag muted">MARKDOWN</span></div>
    <label class="sr-only" for="notes-editor">Markdown 풀이 노트</label><textarea id="notes-editor" class="notes-editor" spellcheck="false" placeholder="# 문제 이름\n\n## 풀이 과정\n\n확인한 내용과 풀이 과정을 기록하세요.">${esc(displayedNotes)}</textarea>
    <div class="notes-tools"><div class="actions"><button class="icon-action" data-action="upload-notes" aria-label="Markdown 노트 불러오기" title="Markdown 노트 불러오기">⇧</button><button class="icon-action" data-action="copy-notes" aria-label="풀이 노트 복사" title="풀이 노트 복사">⧉</button><button class="icon-action" data-action="download-notes" aria-label="풀이 노트 다운로드" title="풀이 노트 다운로드">⇩</button><button class="icon-action" data-action="reload-notes" aria-label="저장된 풀이 노트 새로고침" title="저장된 풀이 노트 새로고침">↻</button></div><button class="primary" data-action="save-notes">노트 저장</button></div><div class="form-hint${draft ? '' : ' hidden'}" id="notes-save-state" role="status">${draft ? '저장하지 않은 작성 내용을 복원했습니다.' : ''}</div><input id="notes-file" type="file" accept=".md,.markdown,.txt" hidden>
    </div><aside class="detail-side"><section><h3>진행 상태</h3><div id="challenge-status-controls">${challengeStatusMarkup(c)}</div></section>
    <section id="solver-panel" class="solver-panel" aria-live="polite" tabindex="-1">${solverPanelMarkup(null,[],true)}</section>
    <section><div class="section-head"><h3>Flag</h3><div class="actions"><button id="copy-flag-button" class="small ghost icon-action" data-action="copy-flag" aria-label="Flag 복사" title="Flag 복사" ${c.flag ? '' : 'disabled'}>⧉</button><button class="small ghost icon-action" data-action="edit-challenge" aria-label="Flag 편집" title="Flag 편집">✎</button></div></div><div id="challenge-flag-box" class="flag-box" role="status" aria-live="assertive" tabindex="0">${esc(c.flag || '미등록')}</div></section>
    ${ctfdRefreshButton ? `<section class="ctfd-source-tools"><div class="section-head"><h3>CTFd 원본</h3></div><p id="ctfd-refresh-help" class="form-hint">CTFd 내용·첨부 갱신 · 로컬 기록 유지</p><div class="actions"><button type="button" class="small ghost" data-action="ctfd-refresh-auth">다시 인증</button><button type="button" class="small ghost" data-action="ctfd-submit-settings">연결 설정</button></div><p id="ctfd-refresh-state" class="form-hint ${refreshingFromCTFd ? '' : 'hidden'}" role="status">${refreshingFromCTFd ? 'CTFd 문제 갱신 중…' : ''}</p></section>` : ''}
    <section><h3>첨부파일 <span class="muted">${c.attachments.length}</span></h3><div class="file-list">${c.attachments.map(f => `<div class="file-item"><div><a href="${path(c.id,c.workspace_id)}/attachments/${f.id}" target="_blank" rel="noopener" download>${esc(f.original_name)}</a><small>${size(f.size)}</small></div><button class="small danger icon-action" data-action="delete-attachment" data-id="${f.id}" aria-label="${esc(f.original_name)} 삭제" title="${esc(f.original_name)} 삭제">×</button></div>`).join('')}</div><div id="upload-progress"></div><label class="sr-only" for="attachment-files">첨부파일 추가</label><input id="attachment-files" class="file-input" type="file" multiple title="대용량 파일 이어 올리기 지원"></section>
    <section><button class="danger small ghost icon-action" data-action="delete-challenge" aria-label="문제 삭제" title="문제 삭제">⌫</button></section></aside></div>`;
  const relationsSection = document.createElement('section');
  relationsSection.id = 'challenge-relations';
  relationsSection.innerHTML = relatedChallengeMarkup(c);
  detail.querySelector('.file-list')?.closest('section')?.before(relationsSection);
  if (!detail.open) detail.showModal();
  detail.scrollTop = 0;
  refreshUploads(c.workspace_id,c.id).catch(error => toast(error.message,true));
  loadRelatedChallenges(c).catch(error => toast(error.message,true));
  const solverLoad = loadSolver(c.workspace_id,c.id);
  if (focusSolverSession) {
    await solverLoad;
    if (ticket !== challengeRendering || currentWorkspace?.id !== workspaceId || currentChallenge?.id !== c.id || !detail.open) return;
    const session = detail.querySelector('.solver-session-log');
    if (session) session.open = true;
    if (expandSolverSession && session) toggleSolverLogSize();
    const panel = detail.querySelector('#solver-panel');
    panel?.focus?.({preventScroll:true});
    panel?.scrollIntoView?.({behavior:'smooth',block:'start'});
  }
}

async function cloneChallenge() {
  const source = currentChallenge;
  if (!source || !currentWorkspace) throw new Error('복제할 문제를 다시 불러와 주세요.');
  const workspaceId = source.workspace_id;
  const cloned = await api(`${path(source.id,workspaceId)}/clone`, {method:'POST'});
  if (currentWorkspace?.id !== workspaceId || currentChallenge !== source) return;
  rememberNotes();
  stopSolverPolling();
  ++challengeRendering;
  detail.close();
  await refreshChallenges();
  toast(`“${cloned.name}” 문제를 만들었습니다.`);
  if (currentWorkspace?.id === workspaceId && currentWorkspace.open_challenge_after_create) {
    await openChallenge(cloned.id);
  }
}

async function openSolverSession(button) {
  if (!currentWorkspace || !button.dataset.id) throw new Error('풀이 세션을 다시 불러와 주세요.');
  if (button.dataset.live === 'true') await openChallenge(button.dataset.id,true,true);
  else await openChallenge(button.dataset.id,true);
}

async function saveNotes(silent = false) {
  const c = currentChallenge, editor = document.querySelector('#notes-editor');
  const content = editor.value;
  if (content === c.notes) { if (!silent) toast('변경된 내용이 없습니다.'); return; }
  const result = await api(`${path(c.id,c.workspace_id)}/notes`, {method:'PUT', headers:conditional(c.notes_token), body:{content}});
  const persisted = typeof result.notes === 'string' ? result.notes : content;
  c.notes = persisted; c.notes_token = result.notes_token;
  if (currentChallenge === c) {
    // Do not overwrite text typed while the request was in flight.  When the
    // server restored the generated write-up block, reflect that canonical
    // value immediately if this editor still contains the submitted text.
    if (editor.value === content && persisted !== content) editor.value = persisted;
    rememberNotes();
    const status = document.querySelector('#notes-save-state');
    if (status) { status.classList?.remove('hidden'); status.textContent = editor.value === persisted ? '노트를 저장했습니다.' : '저장 요청 후 추가로 입력한 내용은 아직 저장되지 않았습니다.'; }
  }
  if (!silent) toast(editor.value === persisted ? '풀이 노트를 저장했습니다.' : '이전 내용은 저장했습니다. 새로 입력한 내용은 한 번 더 저장해 주세요.');
}

async function copyText(text) {
  const value = String(text ?? '');
  if (window.isSecureContext !== false && typeof navigator.clipboard?.writeText === 'function') {
    try { await navigator.clipboard.writeText(value); return; } catch { /* Try selection-based copy if permission was denied. */ }
  }
  const focused = document.activeElement;
  const selection = focused && typeof focused.selectionStart === 'number' ? [focused.selectionStart,focused.selectionEnd] : null;
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly','');
  textarea.setAttribute('aria-hidden','true');
  // Safari can refuse execCommand('copy') for a fully clipped .sr-only field.
  textarea.className = 'clipboard-proxy';
  (modal.open ? modal : detail.open ? detail : document.body).append(textarea); textarea.focus(); textarea.select();
  textarea.setSelectionRange?.(0,textarea.value.length);
  let success = false;
  try { success = typeof document.execCommand === 'function' && document.execCommand('copy'); }
  catch { success = false; }
  finally {
    textarea.remove();
    if (focused?.isConnected !== false) focused?.focus?.();
    if (selection && focused?.isConnected !== false && typeof focused?.setSelectionRange === 'function') focused.setSelectionRange(...selection);
  }
  if (!success) throw new Error('자동 복사를 지원하지 않는 브라우저입니다. 클립보드 권한을 허용하거나 표시된 내용을 직접 선택해 복사하세요.');
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = filename;
  (detail.open ? detail : document.body).append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

function downloadNotes() {
  const filename = (currentChallenge.name.replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').replace(/^[ .]+|[ .]+$/g,'').slice(0,100) || 'challenge') + '-notes.md';
  downloadBlob(new Blob([document.querySelector('#notes-editor').value],{type:'text/markdown;charset=utf-8'}),filename);
}

function solverFilename() {
  return (currentChallenge.name.replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').replace(/^[ .]+|[ .]+$/g,'').slice(0,100) || 'challenge') + '-writeup.md';
}

function paintSolver(job, events, workspaceId, challengeId, generation, guidance = []) {
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const panel = document.querySelector('#solver-panel');
  const previousJobId = solverJobId(currentSolverJob);
  const nextJobId = solverJobId(job);
  if (previousJobId && nextJobId && previousJobId !== nextJobId) {
    currentSolverEvents = [];
    currentSolverGuidance = [];
    solverEventCursor = 0;
    solverGuidanceDraft = '';
    solverConsoleAgentId = 'root'; solverConsoleFollowLatest = true; solverCollapsedAgentIds.clear();
  }
  currentSolverJob = job;
  currentSolverEvents = mergeSolverEvents(currentSolverEvents,events);
  currentSolverGuidance = mergeSolverGuidance(currentSolverGuidance,guidance);
  solverEventCursor = Math.max(solverEventCursor,...currentSolverEvents.map(solverEventSequence));
  const previousConsole = panel.querySelector('.solver-live-console');
  const previousLog = panel.querySelector('.solver-session-log');
  const previousLogOpen = previousLog?.open;
  const previousScroll = Number(previousConsole?.scrollTop || 0);
  const followLatest = !previousConsole || Number(previousConsole.scrollHeight || 0) - previousScroll - Number(previousConsole.clientHeight || 0) < 32;
  const guidanceFocused = document.activeElement?.id === 'solver-guidance-message' && solverIsActive(job);
  if (!guidanceFocused) panel.innerHTML = solverPanelMarkup(job,currentSolverEvents);
  else {
    const console = panel.querySelector('.solver-live-console');
    if (console) console.innerHTML = solverEventMarkup(currentSolverEvents);
    const count = panel.querySelector('.solver-session-log summary b');
    if (count) count.textContent = String(currentSolverEvents.length);
    const guidanceHistory = panel.querySelector('.solver-guidance-history-slot');
    if (guidanceHistory) guidanceHistory.innerHTML = solverGuidanceHistoryMarkup();
  }
  const nextConsole = panel.querySelector('.solver-live-console');
  const nextLog = panel.querySelector('.solver-session-log');
  if (nextLog && previousLog && previousJobId === nextJobId) nextLog.open = previousLogOpen;
  if (nextConsole) nextConsole.scrollTop = followLatest ? nextConsole.scrollHeight : previousScroll;
  paintSolverConsole();
  if (!job) return;

  if (typeof job.flag === 'string' && job.flag && !job.flag_rejected) {
    currentChallenge.flag = job.flag;
    challengeFlags.set(challengeId,job.flag);
    const box = document.querySelector('#challenge-flag-box'), copy = document.querySelector('#copy-flag-button');
    if (box) box.textContent = job.flag;
    if (copy) copy.disabled = false;
    const listed = `${solverJobId(job)}:${job.flag}`;
    if (solverListedFlag !== listed) {
      solverListedFlag = listed;
      refreshChallenges().catch(() => {});
    }
  }

  const completedStatus = currentChallenge.status === 'solved' || currentChallenge.completion_source === 'agent'
    ? 'solved' : job.flag ? 'flag_found' : null;
  const status = job.flag_rejected ? null : job.phase === 'completed' ? completedStatus : job.flag ? 'flag_found'
    : ['cancelled','needs_input'].includes(job.phase) ? 'stopped' : ['failed','refused'].includes(job.phase) ? 'failed'
      : ['queued','staging','awaiting_credential','validating','running','writing','cleanup_blocked'].includes(job.phase) ? 'running' : null;
  if (status) {
    const changed = currentChallenge.status !== status;
    currentChallenge.status = status;
    const controls = document.querySelector('#challenge-status-controls');
    if (changed && controls) controls.innerHTML = challengeStatusMarkup(currentChallenge);
    else {
      const holder = document.querySelector('#challenge-status-badge');
      if (holder) holder.innerHTML = badge(status);
    }
  }

  if (!job.flag_rejected && job.writeup_markdown && solverSyncedWriteup !== solverJobId(job)) {
    solverSyncedWriteup = solverJobId(job);
    syncSolverWriteup(job,workspaceId,challengeId,generation).catch(() => {
      if (solverContext(workspaceId,challengeId,generation)) solverSyncedWriteup = '';
    });
  }
}

async function syncSolverWriteup(job, workspaceId, challengeId, generation) {
  const challenge = currentChallenge;
  const editor = document.querySelector('#notes-editor');
  const savedNotes = challenge?.notes;
  const latest = await api(path(challengeId,workspaceId));
  if (!solverContext(workspaceId,challengeId,generation) || currentChallenge !== challenge) return;
  const editorWasSaved = Boolean(editor && editor.value === savedNotes);
  currentChallenge.flag = latest.flag;
  currentChallenge.status = latest.status;
  currentChallenge.completion_source = latest.completion_source;
  if (typeof latest.notes === 'string') currentChallenge.notes = latest.notes;
  if (typeof latest.notes_token === 'string') currentChallenge.notes_token = latest.notes_token;
  currentChallenge.writeup_markdown = latest.writeup_markdown || job.writeup_markdown;
  currentChallenge.writeup_updated_at = latest.writeup_updated_at || currentChallenge.writeup_updated_at;
  currentChallenge.has_writeup = Boolean(currentChallenge.writeup_markdown);
  if (editorWasSaved && editor && typeof latest.notes === 'string') editor.value = latest.notes;
  rememberNotes();
  const state = document.querySelector('#notes-save-state');
  if (state) {
    state.classList?.remove('hidden');
    state.textContent = editorWasSaved
      ? 'write-up을 풀이 노트에 반영했습니다.'
      : 'write-up을 저장했습니다. 작성 중인 노트는 유지됩니다.';
  }
  await refreshChallenges();
}

function solverPollWarning(message) {
  const panel = document.querySelector('#solver-panel');
  if (!panel) return;
  let warning = panel.querySelector('.solver-poll-warning');
  if (!warning) {
    warning = document.createElement('p'); warning.className = 'notice error-notice solver-poll-warning'; warning.setAttribute('role','status'); panel.append(warning);
  }
  warning.textContent = message;
}

function scheduleSolverPoll(job, workspaceId, challengeId, generation, delay = 1500) {
  if ((!solverIsActive(job) && !solverHasMoreEvents(job) && job?.ultra_escalation?.auto_pending !== true) || !solverContext(workspaceId,challengeId,generation)) return;
  const id = solverJobId(job);
  if (!id) return;
  if (solverPollTimer) clearTimeout(solverPollTimer);
  solverPollTimer = setTimeout(() => pollSolverJob(id,workspaceId,challengeId,generation),delay);
}

async function pollSolverJob(jobId, workspaceId, challengeId, generation) {
  if (!solverContext(workspaceId,challengeId,generation)) return;
  try {
    const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}?after=${solverEventCursor}`);
    if (!solverContext(workspaceId,challengeId,generation)) return;
    const normalized = normalizeSolverPayload(payload);
    if (!normalized.job) throw new Error('풀이 실행 상태 응답을 확인할 수 없습니다.');
    const linkedUltraJob = normalized.job.ultra_escalation?.started_job_id;
    const selectedJobId = solverJobId(currentSolverJob);
    if (selectedJobId && selectedJobId !== jobId
        && selectedJobId !== linkedUltraJob
        && selectedJobId !== normalized.job.ultra_escalation?.source_job_id) return;
    if (typeof linkedUltraJob === 'string' && linkedUltraJob && linkedUltraJob !== jobId) {
      solverEventCursor = 0;
      await pollSolverJob(linkedUltraJob,workspaceId,challengeId,generation);
      return;
    }
    const events = normalized.events.length ? normalized.events : currentSolverEvents;
    paintSolver(normalized.job,events,workspaceId,challengeId,generation,normalized.guidance);
    // Opening a challenge while its job is already active skips account/model
    // loading.  Load it as soon as that polled job becomes terminal so retry
    // controls do not remain permanently disabled in the "확인 중" state.
    if (!solverIsActive(normalized.job) && solverOptionsState !== 'ready') {
      await loadSolverConfiguration(workspaceId,challengeId,generation);
    }
    scheduleSolverPoll(normalized.job,workspaceId,challengeId,generation);
  } catch (error) {
    if (!solverContext(workspaceId,challengeId,generation)) return;
    solverPollWarning(error.message || '풀이 상태를 불러오지 못했습니다. 잠시 후 다시 확인합니다.');
    scheduleSolverPoll(currentSolverJob,workspaceId,challengeId,generation,5000);
  }
}

function repaintSolverConfiguration(workspaceId, challengeId, generation) {
  if (!solverContext(workspaceId,challengeId,generation) || solverIsActive(currentSolverJob)) return;
  const panel = document.querySelector('#solver-panel');
  if (panel) panel.innerHTML = solverPanelMarkup(currentSolverJob,currentSolverEvents);
}

async function loadSolverConfiguration(workspaceId, challengeId, generation, preferredAccountId = '') {
  const ticket = ++solverOptionsGeneration;
  solverOptionsState = 'loading'; solverOptionsError = '';
  repaintSolverConfiguration(workspaceId,challengeId,generation);
  try {
    const payload = await api('/api/accounts');
    if (!solverContext(workspaceId,challengeId,generation) || ticket !== solverOptionsGeneration) return;
    solverAccounts = Array.isArray(payload?.accounts) ? payload.accounts.filter(account => account && typeof account.id === 'string') : [];
    const available = solverAccounts.filter(account => account.provider === solverProvider && account.snapshot?.status === 'authenticated');
    const preferred = preferredAccountId || solverAccountId;
    const account = available.find(item => item.id === preferred)
      || available.find(item => item.selected === true)
      || available[0]
      || null;
    solverAccountId = account?.id || '';
    solverModels = []; solverModel = ''; solverReasoning = ''; solverServiceTier = null; solverUltracode = false;
    if (!account) {
      solverOptionsState = 'ready';
      repaintSolverConfiguration(workspaceId,challengeId,generation);
      return;
    }
    const catalog = await api(`/api/accounts/${encodeURIComponent(account.id)}/models`);
    if (!solverContext(workspaceId,challengeId,generation) || ticket !== solverOptionsGeneration) return;
    if (catalog?.status !== 'available' || !Array.isArray(catalog.models)) throw new Error('선택한 계정의 모델 목록을 사용할 수 없습니다.');
    solverModels = catalog.models.filter(item => item && typeof (item.model || item.id) === 'string');
    const chosen = solverModels.find(item => (item.model || item.id) === account.model)
      || solverModels.find(item => item.isDefault === true || item.default === true)
      || solverModels[0]
      || null;
    solverModel = chosen ? (chosen.model || chosen.id) : '';
    const efforts = Array.isArray(chosen?.supportedReasoningEfforts)
      ? chosen.supportedReasoningEfforts.map(item => item?.reasoningEffort).filter(Boolean) : [];
    solverReasoning = efforts.includes(account.reasoning_effort) ? account.reasoning_effort
      : efforts.includes(chosen?.defaultReasoningEffort) ? chosen.defaultReasoningEffort
      : efforts[0] || '';
    const tiers = Array.isArray(chosen?.serviceTiers) ? chosen.serviceTiers.map(item => item?.id).filter(Boolean) : [];
    solverServiceTier = account.service_tier === 'fast' && tiers.includes('fast') ? 'fast' : null;
    solverUltracode = solverProvider === 'claude' && chosen?.supportsUltracode === true
      && (chosen.model || chosen.id) === account.model && account.ultracode === true;
    solverOptionsState = 'ready';
  } catch (error) {
    if (!solverContext(workspaceId,challengeId,generation) || ticket !== solverOptionsGeneration) return;
    solverModels = []; solverModel = ''; solverReasoning = ''; solverServiceTier = null; solverUltracode = false;
    solverOptionsState = 'error';
    solverOptionsError = error.message || '계정 설정을 불러오지 못했습니다.';
  }
  repaintSolverConfiguration(workspaceId,challengeId,generation);
}

async function loadSolver(workspaceId, challengeId) {
  const generation = solverRendering;
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const panel = document.querySelector('#solver-panel');
  panel.innerHTML = solverPanelMarkup(null,[],true);
  try {
    const payload = await api(`/api/workspaces/${workspaceId}/challenges/${challengeId}/solver`);
    if (!solverContext(workspaceId,challengeId,generation)) return;
    const normalized = normalizeSolverPayload(payload);
    const linkedUltraJob = normalized.job?.ultra_escalation?.started_job_id;
    if (typeof linkedUltraJob === 'string' && linkedUltraJob) {
      solverEventCursor = 0;
      await pollSolverJob(linkedUltraJob,workspaceId,challengeId,generation);
    } else {
      paintSolver(normalized.job,normalized.events,workspaceId,challengeId,generation,normalized.guidance);
      if (!solverIsActive(normalized.job)) await loadSolverConfiguration(workspaceId,challengeId,generation);
      scheduleSolverPoll(normalized.job,workspaceId,challengeId,generation);
    }
  } catch (error) {
    if (!solverContext(workspaceId,challengeId,generation)) return;
    if (error.status === 404) {
      paintSolver(null,[],workspaceId,challengeId,generation);
      await loadSolverConfiguration(workspaceId,challengeId,generation);
    }
    else {
      panel.innerHTML = `${solverPanelMarkup(null)}${solverErrorMarkup(error)}`;
      currentSolverJob = null; currentSolverEvents = []; currentSolverGuidance = []; solverEventCursor = 0;
    }
  }
  await loadWriteupRefinement(workspaceId,challengeId,generation);
}

async function startSolver() {
  const challenge = currentChallenge, workspaceId = challenge.workspace_id, challengeId = challenge.id;
  if (!solverConfigurationReady()) throw new Error('로그인된 계정과 모델·추론 수준을 선택해 주세요.');
  if (solverPollTimer) clearTimeout(solverPollTimer);
  const generation = ++solverRendering;
  solverPollTimer = null; currentSolverJob = null; currentSolverEvents = []; currentSolverGuidance = []; solverEventCursor = 0; solverGuidanceDraft = ''; solverListedFlag = ''; solverSyncedWriteup = '';
  solverConsoleAgentId = 'root'; solverConsoleFollowLatest = true; solverCollapsedAgentIds.clear();
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const panel = document.querySelector('#solver-panel');
  panel.innerHTML = solverPanelMarkup(null,[],true);
  try {
    const payload = await api(`/api/workspaces/${workspaceId}/challenges/${challengeId}/solver`,{method:'POST',body:{
      provider:solverProvider, account_id:solverAccountId, model:solverModel,
      reasoning_effort:solverReasoning, service_tier:solverServiceTier, ultracode:solverUltracode,
      ultra_escalation_mode:solverUltraEscalationEligible() ? solverUltraEscalationMode : 'off',
      writeup_locale:i18n.locale,
    }});
    if (payload.capacity?.warning && payload.capacity.warning_message) {
      toast(payload.capacity.warning_message);
    }
    if (!solverContext(workspaceId,challengeId,generation)) return;
    const normalized = normalizeSolverPayload(payload);
    if (!normalized.job) throw new Error('풀이 실행을 시작했지만 상태 응답을 확인할 수 없습니다.');
    paintSolver(normalized.job,normalized.events,workspaceId,challengeId,generation,normalized.guidance);
    const id = solverJobId(normalized.job);
    if (id && solverIsActive(normalized.job)) await pollSolverJob(id,workspaceId,challengeId,generation);
  } catch (error) {
    if (solverContext(workspaceId,challengeId,generation)) panel.innerHTML = `${solverPanelMarkup(null)}${solverErrorMarkup(error)}`;
    throw error;
  }
}

async function approveUltraEscalation() {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || job?.error?.code !== 'ultra_escalation_requested' || !job?.ultra_escalation?.eligible) return;
  const workspaceId = currentWorkspace?.id, challengeId = currentChallenge?.id, generation = solverRendering;
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/ultra-escalate`,{method:'POST'});
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const normalized = normalizeSolverPayload(payload);
  if (!normalized.job) throw new Error('Ultra 작업 상태를 확인할 수 없습니다.');
  // A source-job poll may still be in flight. Retire its rendering generation
  // before showing the linked job so a late response cannot paint over it.
  if (solverPollTimer) clearTimeout(solverPollTimer);
  solverPollTimer = null;
  const nextGeneration = ++solverRendering;
  paintSolver(normalized.job,normalized.events,workspaceId,challengeId,nextGeneration,normalized.guidance);
  scheduleSolverPoll(normalized.job,workspaceId,challengeId,nextGeneration,250);
}

function paintWriteupRefinement() {
  const container = document.querySelector('#writeup-refine-container');
  if (container) container.innerHTML = writeupRefinementMarkup();
}

async function loadWriteupRefinement(workspaceId, challengeId, generation) {
  const challenge = currentChallenge;
  if (!writeupRefinementEligible(challenge) || !solverContext(workspaceId,challengeId,generation)) return;
  try {
    const payload = await api(`${path(challengeId,workspaceId)}/writeup/refine`);
    if (!solverContext(workspaceId,challengeId,generation) || currentChallenge !== challenge) return;
    await acceptWriteupRefinement(payload,workspaceId,challengeId,generation);
  } catch (error) {
    if (error.status === 404 || !solverContext(workspaceId,challengeId,generation) || currentChallenge !== challenge) return;
    writeupRefineError = writeupRefineError || solverErrorDetails(error,'write-up 보완 상태를 불러오지 못했습니다.');
    paintWriteupRefinement();
  }
}

async function applyRefinedWriteup(workspaceId, challengeId, generation) {
  const challenge = currentChallenge;
  const editor = document.querySelector('#notes-editor');
  const savedNotes = challenge?.notes;
  const latest = await api(path(challengeId,workspaceId));
  if (!solverContext(workspaceId,challengeId,generation) || currentChallenge !== challenge) return false;
  if (typeof latest.writeup_markdown !== 'string' || !latest.writeup_markdown) throw new Error('보완된 write-up을 확인할 수 없습니다. 기존 write-up은 유지했습니다.');
  const editorWasSaved = Boolean(editor && editor.value === savedNotes);
  currentChallenge.writeup_markdown = latest.writeup_markdown;
  currentChallenge.writeup_updated_at = latest.writeup_updated_at;
  currentChallenge.has_writeup = true;
  if (typeof latest.notes === 'string') currentChallenge.notes = latest.notes;
  if (typeof latest.notes_token === 'string') currentChallenge.notes_token = latest.notes_token;
  if (editorWasSaved && editor && typeof latest.notes === 'string') editor.value = latest.notes;
  if (currentSolverJob) currentSolverJob = {...currentSolverJob,writeup_markdown:latest.writeup_markdown};
  rememberNotes();
  const state = document.querySelector('#notes-save-state');
  if (state) {
    state.classList?.remove('hidden');
    state.textContent = editorWasSaved
      ? '보완한 write-up을 풀이 노트에 반영했습니다.'
      : '보완한 write-up을 저장했습니다. 작성 중인 노트는 유지됩니다.';
  }
  const panel = document.querySelector('#solver-panel');
  if (panel) panel.innerHTML = solverPanelMarkup(currentSolverJob,currentSolverEvents);
  await refreshChallenges();
  return true;
}

async function acceptWriteupRefinement(payload, workspaceId, challengeId, generation) {
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const normalized = normalizeSolverPayload(payload);
  if (!normalized.job) throw new Error('write-up 보완 작업 상태를 확인할 수 없습니다.');
  writeupRefineJob = normalized.job;
  writeupRefineEvents = normalized.events.length ? normalized.events : writeupRefineEvents;
  writeupRefineError = null;
  paintWriteupRefinement();
  if (solverIsActive(writeupRefineJob)) {
    if (writeupRefineTimer) clearTimeout(writeupRefineTimer);
    writeupRefineTimer = setTimeout(() => pollWriteupRefinement(
      solverJobId(writeupRefineJob),workspaceId,challengeId,generation
    ),1500);
    return;
  }
  if (writeupRefineJob.phase === 'cancelled') {
    writeupRefineError = null;
    paintWriteupRefinement();
    return;
  }
  if (writeupRefineJob.phase !== 'completed') {
    writeupRefineError = solverErrorDetails(
      writeupRefineJob.error,
      'write-up 보완 작업을 완료하지 못했습니다. 기존 write-up은 유지했습니다.'
    );
    paintWriteupRefinement();
    throw solverErrorException(writeupRefineError);
  }
  if (await applyRefinedWriteup(workspaceId,challengeId,generation)) {
    writeupRefineInstruction = '';
    writeupRefineError = null;
    paintWriteupRefinement();
    toast('write-up 보완을 완료하고 풀이 노트에 반영했습니다.');
  }
}

async function pollWriteupRefinement(jobId, workspaceId, challengeId, generation) {
  writeupRefineTimer = null;
  if (!jobId || !solverContext(workspaceId,challengeId,generation)) return;
  try {
    const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}`);
    await acceptWriteupRefinement(payload,workspaceId,challengeId,generation);
  } catch (error) {
    if (!solverContext(workspaceId,challengeId,generation)) return;
    writeupRefineError = solverErrorDetails(error,'write-up 보완 상태를 확인하지 못했습니다.');
    paintWriteupRefinement();
    if (solverIsActive(writeupRefineJob)) writeupRefineTimer = setTimeout(() =>
      pollWriteupRefinement(jobId,workspaceId,challengeId,generation),5000);
  }
}

async function startWriteupRefinement() {
  const challenge = currentChallenge;
  if (!writeupRefinementEligible(challenge)) throw new Error('완료된 write-up만 보완할 수 있습니다.');
  if (!solverConfigurationReady()) throw new Error('계정·모델·추론 수준을 선택해 주세요.');
  if (solverIsActive(writeupRefineJob)) return;
  const workspaceId = challenge.workspace_id, challengeId = challenge.id, generation = solverRendering;
  const input = document.querySelector('#writeup-refine-instruction');
  writeupRefineInstruction = normalizeWriteupRefinementInstruction(input ? input.value : writeupRefineInstruction);
  writeupRefineError = null;
  const body = {provider:solverProvider,account_id:solverAccountId,model:solverModel,reasoning_effort:solverReasoning,service_tier:solverServiceTier,ultracode:solverUltracode,writeup_locale:i18n.locale};
  try {
    if (writeupRefinementInstructionBytes(writeupRefineInstruction) > writeupRefinementInstructionLimit) {
      const error = new Error('추가 요청은 UTF-8 기준 12 KiB 이하로 입력하세요.');
      error.code = 'invalid_writeup_instruction';
      throw error;
    }
    if (writeupRefineInstruction) body.instruction = writeupRefineInstruction;
    const payload = await api(`${path(challengeId,workspaceId)}/writeup/refine`,{method:'POST',body});
    if (!solverContext(workspaceId,challengeId,generation)) return;
    await acceptWriteupRefinement(payload,workspaceId,challengeId,generation);
  } catch (error) {
    if (solverContext(workspaceId,challengeId,generation)) {
      writeupRefineError = solverErrorDetails(error,'write-up 보완을 시작하지 못했습니다.');
      paintWriteupRefinement();
    }
    throw error;
  }
}

async function cancelWriteupRefinement() {
  const job = writeupRefineJob, jobId = solverJobId(job);
  if (!jobId || !solverIsActive(job)) return;
  if (!confirm('write-up 보완을 중단할까요?')) return;
  const workspaceId = currentWorkspace.id, challengeId = currentChallenge.id, generation = solverRendering;
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/cancel`,{method:'POST'});
  if (!solverContext(workspaceId,challengeId,generation)) return;
  await acceptWriteupRefinement(payload,workspaceId,challengeId,generation);
  if (writeupRefineJob?.phase !== 'completed') toast(writeupRefineJob?.phase === 'cancelled' ? 'write-up 보완을 중단했습니다.' : 'write-up 보완 중단을 요청했습니다.');
}

async function cancelSolver() {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || !solverIsActive(job)) return;
  if (!confirm('현재 풀이를 중단할까요? 발견한 Flag와 저장된 결과는 유지됩니다.')) return;
  const workspaceId = currentWorkspace.id, challengeId = currentChallenge.id, generation = solverRendering;
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/cancel`,{method:'POST'});
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const normalized = normalizeSolverPayload(payload);
  paintSolver(normalized.job || {...job,phase:'cancelled',terminal:true},normalized.events.length ? normalized.events : currentSolverEvents,workspaceId,challengeId,generation,normalized.guidance);
  if (normalized.job && solverIsActive(normalized.job)) scheduleSolverPoll(normalized.job,workspaceId,challengeId,generation);
  toast('풀이 중단을 요청했습니다.');
}

async function sendSolverGuidance(value, requestedDelivery = 'same_turn') {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || !solverIsActive(job)) throw new Error('진행 중인 풀이 세션이 없습니다.');
  if (job.guidance_allowed === false) throw new Error('현재 풀이 단계에는 추가 명령을 보낼 수 없습니다.');
  const message = String(value ?? '').replace(/\r\n?/g,'\n').trim();
  if (!message) throw new Error('추가 명령을 입력하세요.');
  if (new TextEncoder().encode(message).byteLength > 16 * 1024) throw new Error('추가 명령은 UTF-8 기준 16 KiB 이하여야 합니다.');
  const workspaceId = currentWorkspace?.id, challengeId = currentChallenge?.id, generation = solverRendering;
  if (!workspaceId || !challengeId || !solverContext(workspaceId,challengeId,generation)) throw new Error('풀이 화면을 다시 열어 주세요.');
  solverGuidanceDraft = message;
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/guidance`,{method:'POST',body:{message,requested_delivery:requestedDelivery}});
  if (!solverContext(workspaceId,challengeId,generation) || solverJobId(currentSolverJob) !== jobId) return;
  solverGuidanceDraft = '';
  const consoleInput = solverConsoleDialog?.querySelector('#solver-console-message');
  if (consoleInput) consoleInput.value = '';
  const normalized = normalizeSolverPayload(payload);
  if (normalized.job) paintSolver(normalized.job,normalized.events,workspaceId,challengeId,generation,normalized.guidance);
  else {
    currentSolverGuidance = mergeSolverGuidance(currentSolverGuidance,normalized.guidance);
    const panel = document.querySelector('#solver-panel');
    if (panel) panel.innerHTML = solverPanelMarkup(currentSolverJob,currentSolverEvents);
  }
  scheduleSolverPoll(currentSolverJob,workspaceId,challengeId,generation,100);
  toast('추가 명령을 전달했습니다.');
}

async function rejectSolverFlag() {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || !job?.flag || job.flag_rejected || solverIsActive(job)) return;
  if (!confirm('이 Flag를 오답으로 제외할까요? 기존 write-up 원본은 실행 기록에 보존되고, 문제는 미완료 상태로 돌아갑니다.')) return;
  const workspaceId = currentWorkspace.id, challengeId = currentChallenge.id, generation = solverRendering;
  const challenge = currentChallenge, notesBefore = currentChallenge.notes;
  const editor = document.querySelector('#notes-editor');
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/reject-flag`,{method:'POST'});
  if (!solverContext(workspaceId,challengeId,generation)) return;
  // The rejection transaction removes both the canonical write-up and its
  // notes copy. Reload that committed snapshot while preserving manual text
  // typed during either request. Legacy marked copies are also removed from
  // stale drafts so they cannot be restored as user-owned notes.
  const latest = await api(path(challengeId,workspaceId));
  if (!solverContext(workspaceId,challengeId,generation) || currentChallenge !== challenge) return;
  const editorValue = editor?.value;
  const normalized = normalizeSolverPayload(payload);
  currentChallenge.flag = '';
  currentChallenge.status = 'pending';
  currentChallenge.previous_status = null;
  currentChallenge.completion_source = null;
  currentChallenge.has_writeup = false;
  currentChallenge.writeup_markdown = '';
  currentChallenge.writeup_updated_at = null;
  if (typeof latest.notes === 'string') currentChallenge.notes = latest.notes;
  if (typeof latest.notes_token === 'string') currentChallenge.notes_token = latest.notes_token;
  if (editor && typeof latest.notes === 'string') {
    editor.value = editorValue === notesBefore
      ? latest.notes
      : removeGeneratedWriteupCopy(editorValue);
    rememberNotes();
  }
  challengeFlags.delete(challengeId);
  solverListedFlag = '';
  solverSyncedWriteup = '';
  const box = document.querySelector('#challenge-flag-box'), copy = document.querySelector('#copy-flag-button');
  if (box) box.textContent = '미등록';
  if (copy) copy.disabled = true;
  const controls = document.querySelector('#challenge-status-controls');
  if (controls) controls.innerHTML = challengeStatusMarkup(currentChallenge);
  paintSolver(normalized.job || {...job,flag_rejected:true,writeup_markdown:null},normalized.events.length ? normalized.events : currentSolverEvents,workspaceId,challengeId,generation,normalized.guidance);
  await refreshChallenges();
  toast('오답 Flag를 제외했습니다. 다음 풀이가 이전 분석에서 계속됩니다.');
}

function uploadETA(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  if (seconds < 60) return `${Math.max(1,Math.ceil(seconds))}초`;
  if (seconds < 3600) return `${Math.ceil(seconds/60)}분`;
  const hours = Math.floor(seconds/3600), minutes = Math.ceil((seconds%3600)/60);
  return `${hours}시간${minutes ? ` ${minutes}분` : ''}`;
}

function paintUploads(uploads, workspaceId, challengeId, replace = false) {
  if (currentWorkspace?.id !== workspaceId || currentChallenge?.id !== challengeId) return;
  const area = document.querySelector('#upload-progress');
  if (!area) return;
  const incoming = new Set(uploads.map(upload => upload.id));
  if (replace) for (const [id,item] of uploadViews) {
    if (item.workspaceId === workspaceId && item.challengeId === challengeId && !incoming.has(id) && !activeUploads.has(id)) uploadViews.delete(id);
  }
  for (const upload of uploads) {
    const previous = uploadViews.get(upload.id) || {};
    uploadViews.set(upload.id,{...previous,...upload,workspaceId,challengeId});
  }
  const visible = [...uploadViews.values()].filter(upload => upload.workspaceId === workspaceId && upload.challengeId === challengeId);
  area.innerHTML = visible.map(upload => {
    const active = activeUploads.get(upload.id), amount = active?.offset ?? upload.offset;
    const telemetry = active?.running && active.message === '전송 중' && active.bytesPerSecond > 0
      ? ` · ${size(active.bytesPerSecond)}/s · 남은 시간 ${uploadETA((upload.size-amount)/active.bytesPerSecond)}` : '';
    return `<div class="file-item upload-item"><div><strong>${esc(upload.name)}</strong><small>${size(amount)} / ${size(upload.size)} · ${esc(active?.message || '같은 원본 파일을 다시 선택하면 이어서 올립니다.')}${esc(telemetry)}</small><progress max="${Math.max(1,upload.size)}" value="${amount}" aria-label="${esc(upload.name)} 업로드 진행"></progress><div class="actions">${active?.running ? `<button class="small" data-action="pause-upload" data-id="${upload.id}">일시 중지</button>` : active?.file ? `<button class="small" data-action="resume-upload" data-id="${upload.id}">이어서 올리기</button>` : ''}<button class="small danger" data-action="cancel-upload" data-id="${upload.id}">업로드 취소</button></div></div></div>`;
  }).join('');
}

async function refreshUploads(workspaceId, challengeId) {
  const result = await api(`${path(challengeId,workspaceId)}/uploads`);
  paintUploads(result.uploads,workspaceId,challengeId,true);
  return result.uploads;
}

async function refreshChallengeAttachmentsInPlace(workspaceId, challengeId) {
  const latest = await api(path(challengeId,workspaceId));
  if (currentChallenge?.workspace_id !== workspaceId || currentChallenge?.id !== challengeId) return;
  currentChallenge.attachments = latest.attachments || [];
  const list = detail.querySelector('.file-list');
  if (list) list.innerHTML = currentChallenge.attachments.map(file => `<div class="file-item"><div><a href="${path(challengeId,workspaceId)}/attachments/${file.id}" target="_blank" rel="noopener" download>${esc(file.original_name)}</a><small>${size(file.size)}</small></div><button class="small danger icon-action" data-action="delete-attachment" data-id="${esc(file.id)}" aria-label="${esc(file.original_name)} 삭제" title="${esc(file.original_name)} 삭제">×</button></div>`).join('');
  const heading = list?.closest('section')?.querySelector('h3 .muted');
  if (heading) heading.textContent = String(currentChallenge.attachments.length);
}

async function uploadFile(file, workspaceId, challengeId, resumeId) {
  const endpoint = path(challengeId,workspaceId);
  let upload;
  if (resumeId) upload = await api(`/api/uploads/${resumeId}`);
  else {
    const pending = await api(`${endpoint}/uploads`);
    paintUploads(pending.uploads,workspaceId,challengeId,true);
    upload = pending.uploads.find(item => item.name === file.name && item.size === file.size && item.last_modified === file.lastModified);
    if (!upload) upload = await api(`${endpoint}/uploads`,{method:'POST',body:{name:file.name,size:file.size,last_modified:file.lastModified}});
  }
  if (upload.status === 'completed') return true;
  if (activeUploads.get(upload.id)?.running) throw new Error('이 파일은 이미 업로드 중입니다.');
  const startedAt = Date.now();
  const active = {file,workspaceId,challengeId,offset:upload.offset,running:true,paused:false,controller:new AbortController(),message:'전송 준비 중',
    startedAt,sampleAt:startedAt,sampleOffset:upload.offset,bytesPerSecond:0};
  activeUploads.set(upload.id,active);
  const paint = () => paintUploads([upload],workspaceId,challengeId);
  paint();
  try {
    // Read/hash only already committed chunks to ensure the selected resume file
    // really matches; previously uploaded bytes are not retransmitted.
    if (upload.offset) {
      active.message = '기존 파일 조각 확인 중'; paint();
      let start = 0;
      do {
        const manifest = await api(`/api/uploads/${upload.id}/chunks?start=${start}`);
        for (const chunk of manifest.chunks) {
          if (active.paused) return false;
          if (!crypto.subtle) throw new Error('이어 올리기 검증에는 HTTPS 연결이 필요합니다.');
          const bytes = await file.slice(chunk.offset,chunk.offset + chunk.size).arrayBuffer();
          const checksum = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),value => value.toString(16).padStart(2,'0')).join('');
          if (checksum !== chunk.sha256) throw new Error('선택한 파일이 이전 원본과 다릅니다. 원본을 선택하거나 이 업로드를 취소하세요.');
        }
        start = manifest.next_offset;
      } while (start !== null);
    }
    while (upload.offset < file.size) {
      if (active.paused) return false;
      active.message = '전송 중'; paint();
      const chunk = file.slice(upload.offset,Math.min(file.size,upload.offset + 8 * 1024 * 1024));
      upload = await api(`/api/uploads/${upload.id}/chunks?offset=${upload.offset}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:chunk,signal:active.controller.signal});
      const sampledAt = Date.now(), elapsed = (sampledAt-active.sampleAt)/1000, transferred = upload.offset-active.sampleOffset;
      if (elapsed > 0 && transferred > 0) {
        const sample = transferred/elapsed;
        active.bytesPerSecond = active.bytesPerSecond ? active.bytesPerSecond*.65 + sample*.35 : sample;
        active.sampleAt = sampledAt; active.sampleOffset = upload.offset;
      }
      active.offset = upload.offset; paint();
    }
    if (active.paused) return false;
    active.message = '전체 파일 검증 및 저장 중'; paint();
    await api(`/api/uploads/${upload.id}/finalize`,{method:'POST',signal:active.controller.signal});
    activeUploads.delete(upload.id);
    uploadViews.delete(upload.id);
    paintUploads([],workspaceId,challengeId);
    return true;
  } catch (error) {
    if (error.name !== 'AbortError') { active.message = error.message; throw error; }
    return false;
  } finally {
    active.running = false;
    if (active.paused) active.message = '일시 중지됨 · 이어서 올릴 수 있습니다.';
    if (activeUploads.has(upload.id)) paint();
  }
}

async function reloadNotes() {
  if (notesDirty() && !confirm('작성 중인 내용을 저장본으로 바꿀까요? 필요한 내용은 먼저 복사하거나 다운로드해 주세요.')) return;
  const c = currentChallenge;
  const previous = document.querySelector('#notes-editor').value;
  const latest = await api(path(c.id,c.workspace_id));
  if (currentChallenge !== c) return;
  if (document.querySelector('#notes-editor').value !== previous) throw new Error('불러오는 동안 추가로 입력한 내용이 있어 변경하지 않았습니다.');
  c.notes = latest.notes; c.notes_token = latest.notes_token;
  document.querySelector('#notes-editor').value = latest.notes;
  noteDrafts.delete(noteKey(c));
  const state = document.querySelector('#notes-save-state');
  if (state) { state.classList?.remove('hidden'); state.textContent = '최신 저장본을 불러왔습니다.'; }
}

async function changeCompletion(action) {
  const c = currentChallenge;
  await saveNotes(true);
  await api(`${path(c.id,c.workspace_id)}/${action}`,{method:'POST'});
  if (currentWorkspace?.id === c.workspace_id && currentChallenge?.id === c.id) await openChallenge(c.id);
  await refreshChallenges();
  toast(action === 'complete' ? '수동 완료로 기록했습니다.' : '완료 전 상태로 되돌렸습니다.');
}

function renderSettings() {
  const content = shell('settings', '개인 설정');
  const credentialSettings = authMode === 'password' ? `
    <section class="settings-card"><h2>로그인 아이디 변경</h2><form id="username-form"><label>아이디<input name="new_username" value="${esc(sessionUser?.username)}" autocomplete="username" maxlength="100" required></label><label>현재 비밀번호<input type="password" name="current_password" autocomplete="current-password" maxlength="1024" required></label><div><button class="primary">아이디 변경</button></div></form></section>
    <div class="divider"></div><section class="settings-card"><h2>비밀번호 변경</h2><form id="password-form"><label>현재 비밀번호<input type="password" name="current_password" autocomplete="current-password" maxlength="1024" required></label><label>새 비밀번호<input type="password" name="new_password" autocomplete="new-password" minlength="4" maxlength="1024" required><span class="form-hint">최소 4자</span></label><label>새 비밀번호 확인<input type="password" name="confirmation" autocomplete="new-password" minlength="4" maxlength="1024" required></label><div><button class="primary">비밀번호 변경</button></div></form><div class="divider"></div><button class="ghost" data-action="logout">로그아웃</button></section><div class="divider"></div>` : '';
  content.innerHTML = `<div class="page-head"><div><div class="eyebrow">PERSONAL SETTINGS</div><h1>개인 설정</h1></div></div>
    ${credentialSettings}<section id="telegram-settings"></section>`;
  const container = document.querySelector('#telegram-settings');
  import('/assets/telegram.js').then(async module => { const dispose = await module.renderTelegram(container,api,{user:sessionUser}); if (container.isConnected) disposeTelegram = dispose; else dispose?.(); }).catch(() => { if (container.isConnected) container.textContent = '알림 설정을 불러올 수 없습니다. 잠시 후 다시 시도하세요.'; });
}

async function refreshReleaseUpdatePanel(force = false) {
  const area = document.querySelector('#release-update-panel');
  if (!area) return;
  const notesOpen = area.querySelector('details')?.open === true;
  if (releaseUpdateTimer) clearTimeout(releaseUpdateTimer);
  releaseUpdateTimer = null;
  const requestGeneration = ++releaseUpdateRequestGeneration;
  const refreshButton = area.querySelector('[data-action="refresh-release-update"]');
  if (refreshButton) {
    refreshButton.disabled = true;
    refreshButton.setAttribute('aria-busy','true');
  }
  try {
    const info = await api(force ? '/api/admin/updates?refresh=true' : '/api/admin/updates');
    if (!area.isConnected || requestGeneration !== releaseUpdateRequestGeneration) return;
    const phase = info.status?.phase || 'idle';
    const active = ['queued','downloading','verifying','installing','health_check','rolling_back'].includes(phase);
    const labels = {idle:'대기',queued:'대기 중',downloading:'다운로드 중',verifying:'검증 중',installing:'설치 중',health_check:'상태 확인 중',rolling_back:'이전 버전 복구 중',completed:'완료',failed:'실패'};
    area.innerHTML = `<div class="release-update-head"><h2>서비스 업데이트</h2><button type="button" class="small ghost" data-action="refresh-release-update">새로고침</button></div><p>${i18n.locale === 'en' ? 'Current' : '현재'} ${esc(info.current)} · ${i18n.locale === 'en' ? 'Latest' : '최신'} ${esc(info.latest?.tag || i18n.t('조회 불가'))}</p>
      ${info.latest?.notes ? `<details><summary>업데이트 내역</summary><div class="release-notes markdown-preview" data-i18n-ignore>${safeMarkdown(info.latest.notes)}</div></details>` : ''}
      ${info.error ? `<p class="form-hint" role="status">${esc(info.error)}</p>` : ''}
      ${!info.helper_ready ? '<p class="form-hint">이 설치 방식에는 웹 업데이트 실행기가 연결되어 있지 않습니다.</p>' : ''}
      ${phase !== 'idle' ? `<p class="form-hint" role="status">${esc(i18n.t(labels[phase] || phase))}${info.status?.message ? ` · ${esc(info.status.message)}` : ''}</p>` : ''}
      <button type="button" class="primary" data-action="install-release-update" ${info.available && info.helper_ready && !active ? '' : 'disabled'}>업데이트</button>`;
    if (notesOpen) {
      const notes = area.querySelector('details');
      if (notes) notes.open = true;
    }
    if (active) releaseUpdateTimer = setTimeout(() => refreshReleaseUpdatePanel(),5000);
  } catch (error) {
    if (area.isConnected && requestGeneration === releaseUpdateRequestGeneration) {
      area.innerHTML = `<div class="release-update-head"><h2>서비스 업데이트</h2><button type="button" class="small ghost" data-action="refresh-release-update">새로고침</button></div><p class="form-hint" role="status">${esc(error.message || '업데이트 상태를 불러오지 못했습니다.')}</p>`;
      releaseUpdateTimer = setTimeout(() => refreshReleaseUpdatePanel(),5000);
    }
  }
}

async function installReleaseUpdate(button) {
  button.disabled = true;
  button.setAttribute('aria-busy','true');
  try {
    const result = await api('/api/admin/updates',{method:'POST'});
    toast(`${result.tag} 업데이트를 시작했습니다.`);
  } finally {
    await refreshReleaseUpdatePanel();
  }
}

function adminUserActiveButton(user, activeAdminCount) {
  const reason = user.role === 'admin' && user.active && activeAdminCount <= 1
    ? '마지막 활성 관리자는 비활성화할 수 없습니다.'
    : user.id === sessionUser?.id ? '현재 로그인한 계정은 비활성화할 수 없습니다.' : '';
  const reasonId = `user-active-reason-${esc(user.id)}`;
  const disabled = reason ? `disabled title="${esc(reason)}" aria-label="${esc(user.username)}: ${esc(reason)}" aria-describedby="${reasonId}"` : '';
  return `<span class="admin-active-control"><button class="small" data-action="user-active" data-id="${esc(user.id)}" data-active="${user.active ? 'false' : 'true'}" ${disabled}>${user.active ? '비활성화' : '활성화'}</button>${reason ? `<small id="${reasonId}" class="admin-disabled-reason">${esc(reason)}</small>` : ''}</span>`;
}

function solverCapacityAdminMarkup(capacity) {
  const maximum = capacity.admin_max || '';
  const limit = capacity.hard_max ? `${capacity.hard_max}개` : '제한 없음';
  const warning = capacity.warning
    ? `<p class="notice error-notice" role="status">${esc(capacity.warning_message)}</p>`
    : '';
  const summary = i18n.locale === 'en'
    ? `Running ${esc(capacity.configured)} · jobs ${esc(capacity.open_jobs)} · recommended ${esc(capacity.recommended)} · maximum ${esc(i18n.t(limit))} · estimated web PIDs ${esc(capacity.estimated_web_pids)} / ${capacity.web_pids_limit ? esc(capacity.web_pids_limit) : i18n.t('제한 없음')}`
    : `실행 ${esc(capacity.configured)} · 작업 ${esc(capacity.open_jobs)} · 권장 ${esc(capacity.recommended)} · 최대 ${esc(limit)} · 웹 PID 예상 ${esc(capacity.estimated_web_pids)} / ${capacity.web_pids_limit ? esc(capacity.web_pids_limit) : '제한 없음'}`;
  return `<section class="settings-card"><h2>솔버 자동 확장</h2>
    <p class="form-hint">${summary}</p>
    ${warning}
    <form id="solver-capacity-form"><label>최대 솔버 수 <span class="optional">비우면 제한 없음</span><input name="maximum" type="number" min="${esc(capacity.baseline)}" step="1" value="${esc(maximum)}" placeholder="제한 없음"></label><div><button class="primary">저장</button></div></form>
  </section>`;
}

async function renderAdmin() {
  if (sessionUser?.role !== 'admin') { location.hash = 'settings'; toast('관리자 권한이 필요합니다.',true); return; }
  const capacity = await api('/api/admin/solver-capacity');
  if (authMode === 'nologin') {
    const content = shell('admin','관리자 설정');
    content.innerHTML = `<div class="page-head"><div><div class="eyebrow">ADMIN SETTINGS</div><h1>관리자 설정</h1></div></div>
      ${solverCapacityAdminMarkup(capacity)}<div class="divider"></div>
      <section class="settings-card"><h2>미완료 업로드 정리</h2><p class="form-hint">7일 이상 진행하지 않은 미완료 임시 파일만 정리합니다. 완료된 첨부파일은 유지됩니다.</p><button data-action="cleanup-uploads">만료된 업로드 정리</button></section><div class="divider"></div><section id="release-update-panel" class="settings-card"></section>`;
    refreshReleaseUpdatePanel();
    return;
  }
  const result = await api('/api/admin/users');
  const activeAdminCount = result.users.filter(user => user.role === 'admin' && user.active).length;
  const content = shell('admin','관리자 설정');
  content.innerHTML = `<div class="page-head"><div><div class="eyebrow">ADMIN SETTINGS</div><h1>사용자 관리</h1></div><button class="primary" data-action="new-user">＋ 사용자 추가</button></div>
    <div class="table-wrap"><table class="challenge-table"><thead><tr><th>아이디</th><th>권한</th><th>상태</th><th>최근 로그인</th><th>작업공간 / 계정</th><th>Telegram</th><th>관리</th></tr></thead><tbody>${result.users.map(user => `<tr><td class="challenge-title">${esc(user.username)}${user.id === sessionUser.id ? ' <span class="tag">나</span>' : ''}</td><td><select data-action="user-role" data-id="${user.id}" aria-label="${esc(user.username)} 권한"><option value="user" ${user.role === 'user' ? 'selected' : ''}>일반 사용자</option><option value="admin" ${user.role === 'admin' ? 'selected' : ''}>관리자</option></select></td><td>${user.active ? '활성' : '비활성'}</td><td>${user.last_login_at ? date(user.last_login_at) : '기록 없음'}</td><td>${user.workspace_count} / ${user.account_count}</td><td>${user.telegram_linked ? (user.telegram_enabled ? '알림 켜짐' : '연결됨 · 알림 꺼짐') : '미연결'}${user.telegram_last_failure_at ? '<br><small>최근 전송 오류 기록</small>' : ''}</td><td><div class="actions">${adminUserActiveButton(user,activeAdminCount)}<button class="small" data-action="user-password" data-id="${user.id}" data-name="${esc(user.username)}">비밀번호 초기화</button></div></td></tr>`).join('')}</tbody></table></div>
    <div class="divider"></div>${solverCapacityAdminMarkup(capacity)}
    <div class="divider"></div><section class="settings-card"><h2>미완료 업로드 정리</h2><p class="form-hint">7일 이상 진행하지 않은 미완료 임시 파일만 정리합니다. 완료된 첨부파일은 유지됩니다.</p><button data-action="cleanup-uploads">만료된 업로드 정리</button></section><div class="divider"></div><section id="release-update-panel" class="settings-card"></section>`;
  refreshReleaseUpdatePanel();
}

function newUserForm() {
  openModal('사용자 추가','', '<label>아이디<input name="username" autocomplete="off" maxlength="100" required></label><label>초기 비밀번호<input type="password" name="password" autocomplete="new-password" minlength="4" maxlength="1024" required><span class="form-hint">4자 이상 · 조합 조건 없음</span></label><label>권한<select name="role"><option value="user">일반 사용자</option><option value="admin">관리자</option></select></label>','<button type="button" data-action="close-modal">취소</button><button type="submit" class="primary">사용자 만들기</button>','new-user-form');
}

function importForm() {
  importPreview = null;
  openModal('CTFd 문제 가져오기', '', '<label>CTFd 사이트 주소<input name="url" inputmode="url" placeholder="ctf.example.com" required autofocus><span class="form-hint">https://를 생략하면 자동으로 붙입니다.</span></label><label>인증 방식<select id="ctfd-auth-type" name="auth_type"><option value="none">로그인 없이 가져오기</option><option value="token">API 토큰</option><option value="password">아이디와 비밀번호</option></select></label><div id="ctfd-token-fields" hidden><label>API 토큰<input name="token" type="password" autocomplete="off" disabled></label></div><div id="ctfd-password-fields" hidden><label>CTFd 아이디<input name="username" autocomplete="off" disabled></label><label>CTFd 비밀번호<input name="password" type="password" autocomplete="off" disabled></label></div><div class="notice">인증값은 가져오기 중에만 사용합니다.</div>', '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">문제 목록 확인</button>', 'ctfd-preview-form');
}

function ctfdRefreshAuthForm() {
  const challenge = currentChallenge;
  if (!challenge?.ctfd_url || challenge.ctfd_id === null || challenge.ctfd_id === undefined) throw new Error('CTFd에서 가져온 문제만 다시 인증할 수 있습니다.');
  openModal('CTFd 다시 인증', '', `
    <label>CTFd 사이트 주소<input name="url" inputmode="url" value="${esc(challenge.ctfd_url)}" readonly required><span class="form-hint">문제를 가져온 원본 사이트와 일치해야 합니다.</span></label>
    <label>인증 방식<select id="ctfd-refresh-auth-type" name="auth_type"><option value="none">로그인 없이 연결</option><option value="token">API 토큰</option><option value="password">아이디와 비밀번호</option></select></label>
    <div id="ctfd-refresh-token-fields" hidden><label>API 토큰<input name="token" type="password" autocomplete="off" disabled></label></div>
    <div id="ctfd-refresh-password-fields" hidden><label>CTFd 아이디<input name="username" autocomplete="off" disabled></label><label>CTFd 비밀번호<input name="password" type="password" autocomplete="off" disabled></label></div>
    <div class="notice">인증값은 요청 후 제거합니다. 로컬 풀이 자료는 유지됩니다.</div>`,
    '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">인증하고 새로고침</button>',
    'ctfd-refresh-auth-form');
  const form = modal.querySelector('#ctfd-refresh-auth-form') || modal.querySelector('form');
  if (form) {
    form.dataset.workspaceId = challenge.workspace_id;
    form.dataset.challengeId = challenge.id;
    form.dataset.initial = formSnapshot(form);
  }
  modal.dataset.kind = 'ctfd-refresh-auth'; modal.dataset.workspaceId = challenge.workspace_id;
}

function ctfdSyncViewCurrent(workspaceId, generation, page, hash, kind) {
  return modal.open && modal.dataset.kind === kind && modal.dataset.workspaceId === workspaceId &&
    modalRendering === generation && rendering === page && location.hash === hash && currentWorkspace?.id === workspaceId;
}

async function previewCTFdSync() {
  if (!currentWorkspace) return;
  const workspaceId = currentWorkspace.id, page = rendering, hash = location.hash;
  importPreview = null;
  openModal('새 문제 동기화', '',
    '<div class="ctfd-sync-loading" role="status"><span class="status status-running">새 문제 확인 중</span></div>',
    '<button type="button" data-action="close-modal">닫기</button>');
  modal.dataset.kind = 'ctfd-sync-loading'; modal.dataset.workspaceId = workspaceId;
  const generation = modalRendering;
  try {
    const result = await api(`/api/workspaces/${workspaceId}/ctfd/sync/preview`,{method:'POST',body:{}});
    if (!ctfdSyncViewCurrent(workspaceId,generation,page,hash,'ctfd-sync-loading')) return;
    showCTFdSyncPreview(result,workspaceId);
  } catch (error) {
    if (!ctfdSyncViewCurrent(workspaceId,generation,page,hash,'ctfd-sync-loading')) return;
    openModal('새 문제 동기화 실패', '',
      `<div class="notice error-notice" role="alert">${esc(error.message)}</div><p class="form-hint">저장된 CTFd 연결이 필요합니다. 로컬 풀이 자료는 유지됩니다.</p>`,
      '<button type="button" data-action="close-modal">닫기</button><button type="button" data-action="ctfd-submit-settings">연결 설정</button><button type="button" class="primary" data-action="ctfd-sync-retry">다시 확인</button>');
    modal.dataset.kind = 'ctfd-sync-error'; modal.dataset.workspaceId = workspaceId;
  }
}

function ctfdSubmissionRows(history) {
  const submissionLabels = {
    queued:'대기',running:'제출 중',retry:'재시도 대기',correct:'정답',already_solved:'이미 해결됨',
    incorrect:'오답',rate_limited:'제한됨',auth_error:'인증 오류',network_error:'연결 오류',
    paused:'대회 일시 중지',partial:'부분 처리',failed:'실패',superseded:'새 Flag로 대체됨',disabled:'전송 안 함',
  };
  return history.submissions.map(job => `<div class="submission-row"><div><strong>${esc(job.challenge_name || `문제 ${job.ctfd_id}`)}</strong><small>CTFd #${esc(job.ctfd_id)} · ${esc(submissionLabels[job.status] || job.status)} · 시도 ${esc(job.attempts)}</small>${job.display_message ? `<p>${esc(job.display_message)}</p>` : ''}</div><span class="status ${['correct','already_solved'].includes(job.status) ? 'status-solved' : job.status === 'incorrect' ? 'status-failed' : ''}">${esc(submissionLabels[job.status] || job.status)}</span></div>`).join('') || '<p class="form-hint">자동 제출 기록이 없습니다.</p>';
}

function ctfdConnectionState(state) {
  return `<div class="section-head"><h3>제출 연결</h3><span class="connection-state ${state.connected ? 'connected' : ''}">${state.connected ? '검증됨' : '연결 안 됨'}</span></div>
      ${state.connected ? `<p class="ctfd-connection-meta"><strong>${esc(state.url)}</strong><small>${state.auth_type === 'password' ? '아이디·비밀번호' : 'API 토큰'}</small></p>` : '<p class="form-hint">제출 계정을 연결하세요.</p>'}
      <div class="ctfd-submit-toggle-row"><label class="ctfd-submit-toggle"><input id="ctfd-auto-submit-toggle" type="checkbox" data-saved="${Boolean(state.auto_submit)}" aria-describedby="ctfd-auto-submit-help" ${state.auto_submit ? 'checked' : ''} ${state.connected ? '' : 'disabled'}><span>Flag 자동 제출</span></label></div>
      <p id="ctfd-auto-submit-help" class="notice ctfd-submit-help ${state.auto_submit ? '' : 'muted'}">기본 OFF · CTFd 오답 패널티가 적용될 수 있습니다.</p>
      ${state.connected ? '<div class="ctfd-submit-actions"><button type="button" class="small danger ghost" data-action="disconnect-ctfd-submit">연결 해제</button></div>' : ''}`;
}

function ctfdSubmitScope() {
  const form = modal.querySelector('#ctfd-submit-connection-form');
  if (!modal.open || modal.dataset.kind !== 'ctfd-submit' || !form || currentWorkspace?.id !== modal.dataset.workspaceId) return null;
  return {form, workspaceId:modal.dataset.workspaceId, workspaceName:currentWorkspace.name, generation:modalRendering, page:rendering, hash:location.hash};
}

function ctfdSubmitCurrent(scope) {
  return modal.open && modal.dataset.kind === 'ctfd-submit' && modalRendering === scope.generation && rendering === scope.page && location.hash === scope.hash && currentWorkspace?.id === scope.workspaceId && modal.querySelector('#ctfd-submit-connection-form') === scope.form;
}

// Refresh only the saved connection and history; credentials being edited stay in the form.
async function ctfdSubmitAction(task) {
  const scope = ctfdSubmitScope();
  if (!scope || busyForms.has(scope.form)) return;
  const controls = [...modal.querySelectorAll('input,select,textarea,button')];
  const previous = controls.map(node => node.disabled), focused = document.activeElement;
  busyForms.add(scope.form); scope.form.setAttribute('aria-busy','true'); modal.setAttribute('aria-busy','true');
  controls.forEach(node => { node.disabled = true; });
  try { await task(scope); }
  finally {
    controls.forEach((node,index) => { node.disabled = previous[index]; });
    busyForms.delete(scope.form); scope.form.removeAttribute('aria-busy');
    if (ctfdSubmitCurrent(scope)) {
      modal.removeAttribute('aria-busy');
      if (scope.state) {
        modal.querySelector('#ctfd-connection-state').innerHTML = ctfdConnectionState(scope.state);
        modal.querySelector('#ctfd-connection-summary').textContent = scope.state.connected ? '연결 바꾸기' : '제출 계정 연결';
      }
      if (scope.history) modal.querySelector('#ctfd-submission-history').innerHTML = ctfdSubmissionRows(scope.history);
      if (scope.saved) scope.form.dataset.initial = formSnapshot(scope.form);
      const focus = scope.focusSelector ? modal.querySelector(scope.focusSelector) : focused;
      if (focus?.isConnected && !focus.disabled) focus.focus();
    }
  }
}

async function refreshCTFdSubmit() {
  await ctfdSubmitAction(async scope => {
    const [state, history] = await Promise.all([
      api(`/api/workspaces/${scope.workspaceId}/ctfd/connection`),
      api(`/api/workspaces/${scope.workspaceId}/ctfd/submissions`),
    ]);
    scope.state = state; scope.history = history;
  });
}

async function toggleCTFdSubmit(input) {
  const desired = input.checked;
  input.checked = input.dataset.saved === 'true';
  await ctfdSubmitAction(async scope => {
    if (desired && !confirm(`자동 제출을 켜면 ${scope.workspaceName}에서 발견한 CTFd Flag를 즉시 전송합니다. 오답 패널티가 적용될 수 있습니다. 켤까요?`)) return;
    scope.state = await api(`/api/workspaces/${scope.workspaceId}/ctfd/settings`,{method:'PUT',body:{auto_submit:desired}});
    scope.focusSelector = '#ctfd-auto-submit-toggle';
    if (ctfdSubmitCurrent(scope)) toast(desired ? 'CTFd 자동 제출을 켰습니다.' : 'CTFd 자동 제출을 껐습니다.');
  });
}

async function disconnectCTFdSubmit() {
  await ctfdSubmitAction(async scope => {
    if (!confirm('저장된 제출용 인증과 대기 중인 자동 제출을 해제할까요?')) return;
    scope.state = await api(`/api/workspaces/${scope.workspaceId}/ctfd/connection`,{method:'DELETE'});
    if (ctfdSubmitCurrent(scope)) {
      modal.querySelector('#ctfd-connection-details').open = true;
      scope.focusSelector = 'input[name="url"]';
      toast('CTFd 제출 연결을 해제했습니다.');
    }
  });
}

async function saveCTFdSubmitConnection(form, body) {
  await ctfdSubmitAction(async scope => {
    if (scope.form !== form) return;
    body.url = body.url.trim(); if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(body.url)) body.url = `https://${body.url}`;
    if (body.auth_type === 'token') { delete body.username; delete body.password; }
    else delete body.token;
    scope.state = await api(`/api/workspaces/${scope.workspaceId}/ctfd/connection`,{method:'PUT',body});
    if (!ctfdSubmitCurrent(scope)) return;
    for (const input of form.querySelectorAll('input[name="token"],input[name="username"],input[name="password"]')) input.value = '';
    form.querySelector('input[name="url"]').value = scope.state.url || body.url;
    scope.saved = true; scope.focusSelector = '#ctfd-auto-submit-toggle';
    modal.querySelector('#ctfd-connection-details').open = false;
    toast('CTFd 제출 계정을 검증해 저장했습니다. 자동 제출은 직접 켜야 합니다.');
  });
}

async function ctfdSubmitSettings() {
  if (!currentWorkspace) return;
  const workspaceId = currentWorkspace.id, generation = modalRendering, page = rendering, hash = location.hash, ticket = ++ctfdSubmitRendering;
  const [state, history] = await Promise.all([
    api(`/api/workspaces/${workspaceId}/ctfd/connection`),
    api(`/api/workspaces/${workspaceId}/ctfd/submissions`),
  ]);
  if (ticket !== ctfdSubmitRendering || generation !== modalRendering || page !== rendering || hash !== location.hash || currentWorkspace?.id !== workspaceId) return;
  const authType = state.auth_type === 'password' ? 'password' : 'token';
  openModal('CTFd 자동 제출', '', `<div class="ctfd-submit-panel">
    <section id="ctfd-connection-state" class="ctfd-connection-state">${ctfdConnectionState(state)}</section>
    <div class="divider"></div>
    <details id="ctfd-connection-details" class="ctfd-submit-connection-details" ${state.connected ? '' : 'open'}><summary id="ctfd-connection-summary">${state.connected ? '연결 바꾸기' : '제출 계정 연결'}</summary>
      <form id="ctfd-submit-connection-form">
        <label>CTFd 사이트 주소<input name="url" inputmode="url" value="${esc(state.url || '')}" placeholder="ctf.example.com" required><span class="form-hint">https://를 생략하면 자동으로 붙입니다.</span></label>
        <label>인증 방식<select id="ctfd-submit-auth-type" name="auth_type"><option value="token" ${authType === 'token' ? 'selected' : ''}>API 토큰</option><option value="password" ${authType === 'password' ? 'selected' : ''}>아이디와 비밀번호</option></select></label>
        <div id="ctfd-submit-token-fields" ${authType === 'token' ? '' : 'hidden'}><label>API 토큰<input name="token" type="password" autocomplete="off" ${authType === 'token' ? 'required' : 'disabled'}></label></div>
        <div id="ctfd-submit-password-fields" ${authType === 'password' ? '' : 'hidden'}><label>CTFd 아이디<input name="username" autocomplete="off" ${authType === 'password' ? 'required' : 'disabled'}></label><label>CTFd 비밀번호<input name="password" type="password" autocomplete="off" ${authType === 'password' ? 'required' : 'disabled'}></label></div>
        <button type="submit" class="primary">연결 검증·저장</button>
      </form>
    </details>
    <div class="divider"></div><div class="section-head ctfd-submit-history-head"><h3>최근 자동 제출</h3><button type="button" class="small ghost icon-action" data-action="refresh-ctfd-submit" aria-label="최근 자동 제출 새로고침" title="최근 자동 제출 새로고침">↻</button></div>
    <div id="ctfd-submission-history" class="submission-history" role="region" tabindex="0" aria-label="최근 자동 제출 기록">${ctfdSubmissionRows(history)}</div></div>`,
    '<button type="button" data-action="close-modal">닫기</button>');
  modal.dataset.kind = 'ctfd-submit'; modal.dataset.workspaceId = workspaceId;
}

function showImportPreview(result, credentials) {
  importPreview = {mode:'import', workspaceId:currentWorkspace?.id, result, credentials: result.preview_id ? null : credentials};
  openModal('가져올 문제 선택', `${result.challenges.length}개 · ${result.source_url}`, `<div class="import-preview">${result.challenges.map(c => `<label class="import-row"><input type="checkbox" name="challenge" value="${c.id}" checked><span>${esc(c.name)} <small>${esc(c.category || '미분류')} · 첨부 ${result.details_pending ? '가져올 때 확인' : (c.files || []).length}</small></span></label>`).join('') || '<p>가져올 문제가 없습니다.</p>'}</div>${result.errors.length ? `<div class="notice error-notice">${importErrors(result.errors)}</div>` : ''}<p class="form-hint">기존 문제는 변경하지 않습니다.</p>`, '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">선택한 문제 가져오기</button>', 'ctfd-import-form');
}

function showCTFdSyncPreview(result, workspaceId) {
  const challenges = Array.isArray(result?.challenges) ? result.challenges : [];
  const existingCount = Number.isInteger(result?.existing_count) && result.existing_count >= 0 ? result.existing_count : 0;
  const newCount = Number.isInteger(result?.new_count) && result.new_count >= 0 ? result.new_count : challenges.length;
  const errors = Array.isArray(result?.errors) ? result.errors : [];
  importPreview = {mode:'sync', workspaceId, result};
  const rows = challenges.map(c => `<label class="import-row"><input type="checkbox" name="challenge" value="${esc(c.id)}" checked><span>${esc(c.name)} <small>${esc(c.category || '미분류')} · 첨부 ${result.details_pending ? '동기화할 때 확인' : (c.files || []).length}</small></span></label>`).join('');
  const body = `<div class="ctfd-sync-counts"><span><strong>${newCount}</strong> 신규</span><span><strong>${existingCount}</strong> 기존 유지</span></div>
    <div class="import-preview">${rows || '<p>새로 추가된 문제가 없습니다.</p>'}</div>
    ${errors.length ? `<div class="notice error-notice">${importErrors(errors)}</div>` : ''}
    <p class="notice muted">기존 상태, Flag, 풀이 노트, write-up, 첨부파일은 변경하지 않습니다.</p>`;
  const footer = challenges.length
    ? '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">선택한 새 문제 동기화</button>'
    : '<button type="button" data-action="close-modal" class="primary">확인</button>';
  openModal('새 문제 동기화', `${newCount}개 신규 · ${result?.source_url || '연결된 CTFd'}`, body, footer,
    challenges.length ? 'ctfd-sync-form' : undefined);
  const form = modal.querySelector('#ctfd-sync-form') || (challenges.length ? modal.querySelector('form') : null);
  if (form) { form.dataset.workspaceId = workspaceId; form.dataset.initial = formSnapshot(form); }
  modal.dataset.kind = 'ctfd-sync-preview'; modal.dataset.workspaceId = workspaceId;
}

async function startCTFdSync(form, challengeIds) {
  const preview = importPreview;
  const workspaceId = form.dataset.workspaceId;
  if (!preview || preview.mode !== 'sync' || preview.workspaceId !== workspaceId || currentWorkspace?.id !== workspaceId ||
      !preview.result?.preview_id) throw new Error('동기화 목록이 만료되었습니다. 새 문제를 다시 확인하세요.');
  if (!challengeIds.length) throw new Error('동기화할 새 문제를 선택하세요.');
  await api(`/api/workspaces/${workspaceId}/ctfd/sync`,{
    method:'POST', body:{preview_id:preview.result.preview_id,challenge_ids:challengeIds},
  });
  importPreview = null; modal.close();
  if (currentWorkspace?.id === workspaceId) {
    await refreshChallenges();
    await pollCTFdJobs(workspaceId);
  }
  toast(`새 문제 ${challengeIds.length}개 동기화를 시작했습니다.`);
}

function paintCTFdChallengeRefresh(message, error = false) {
  const state = document.querySelector('#ctfd-refresh-state');
  if (!state) return;
  state.textContent = message;
  state.className = `form-hint${error ? ' error-text' : ''}`;
  state.setAttribute('role',error ? 'alert' : 'status');
}

function ctfdJobError(job) {
  const first = Array.isArray(job?.errors) ? job.errors[0] : null;
  if (typeof first === 'string') return first;
  return first?.message || 'CTFd에서 문제를 갱신하지 못했습니다.';
}

async function watchCTFdChallengeRefresh(initialJob, workspaceId, challengeId, key) {
  let job = initialJob;
  while (ctfdActiveJobStatuses.has(job?.status)) {
    const detailText = job.current_file ? ` · ${job.current_file}` : '';
    paintCTFdChallengeRefresh(`CTFd에서 최신 문제 정보와 첨부파일을 가져오는 중입니다${detailText}`);
    await new Promise(resolve => setTimeout(resolve,2000));
    if (currentWorkspace?.id !== workspaceId) { activeCTFdChallengeRefreshes.delete(key); return; }
    const result = await api(`/api/workspaces/${workspaceId}/ctfd/jobs/${job.id}`);
    job = result?.job || result;
  }
  activeCTFdChallengeRefreshes.delete(key);
  const changed = job?.status === 'completed' || (job?.status === 'partial' && Number(job?.refreshed || 0) > 0);
  if (changed) {
    rememberNotes();
    if (currentWorkspace?.id === workspaceId && currentChallenge?.id === challengeId && detail.open) await openChallenge(challengeId);
    else if (currentWorkspace?.id === workspaceId) await refreshChallenges();
  }
  if (job?.status === 'completed' && Number(job?.refreshed || 0) > 0) {
    toast('CTFd 최신 내용으로 문제를 갱신했습니다. 로컬 풀이 자료는 유지했습니다.');
    return;
  }
  const message = ctfdJobError(job);
  paintCTFdChallengeRefresh(message,true);
  throw new Error(message);
}

async function launchCTFdChallengeRefresh(credentials = {}) {
  const challenge = currentChallenge, workspace = currentWorkspace;
  if (!challenge || !workspace || challenge.workspace_id !== workspace.id || challenge.ctfd_id === null ||
      challenge.ctfd_id === undefined || !challenge.ctfd_url) throw new Error('CTFd에서 가져온 문제만 새로고침할 수 있습니다.');
  const workspaceId = workspace.id, challengeId = challenge.id, key = `${workspaceId}:${challengeId}`;
  if (activeCTFdChallengeRefreshes.has(key)) return;
  rememberNotes();
  activeCTFdChallengeRefreshes.set(key,'starting');
  paintCTFdChallengeRefresh('CTFd 연결과 원본 문제를 확인하고 있습니다.');
  try {
    const result = await api(`/api/workspaces/${workspaceId}/challenges/${challengeId}/ctfd/refresh`,{method:'POST',body:credentials});
    const job = result?.job || result;
    if (!job?.id) throw new Error('CTFd 새로고침 작업 정보를 받지 못했습니다.');
    activeCTFdChallengeRefreshes.set(key,job.id);
    pollCTFdJobs(workspaceId).catch(() => {});
    watchedCTFdRefreshJobs.add(job.id);
    watchCTFdChallengeRefresh(job,workspaceId,challengeId,key)
      .catch(error => { if (currentWorkspace?.id === workspaceId) toast(error.message,true); })
      .finally(() => watchedCTFdRefreshJobs.delete(job.id));
    toast('CTFd 문제 새로고침을 시작했습니다.');
    return job;
  } catch (error) {
    activeCTFdChallengeRefreshes.delete(key);
    paintCTFdChallengeRefresh(error.message,true);
    throw error;
  }
}

function showCTFdRefreshConnectionFallback(error, challenge) {
  if (!challenge || currentWorkspace?.id !== challenge.workspace_id || currentChallenge?.id !== challenge.id) return;
  openModal('CTFd 연결 확인', '',
    `<div class="notice error-notice" role="alert">${esc(error?.message || '저장된 CTFd 연결을 사용할 수 없습니다.')}</div><p class="form-hint">다시 인증하거나 연결 설정을 갱신하세요. 로컬 풀이 자료는 유지됩니다.</p>`,
    '<button type="button" data-action="ctfd-submit-settings">연결 설정</button><button type="button" class="primary" data-action="ctfd-refresh-auth">다시 인증</button>');
  modal.dataset.kind = 'ctfd-refresh-fallback';
  modal.dataset.workspaceId = challenge.workspace_id;
}

async function refreshCTFdChallenge() {
  const challenge = currentChallenge;
  try { return await launchCTFdChallengeRefresh({}); }
  catch (error) {
    const imported = challenge?.ctfd_id !== null && challenge?.ctfd_id !== undefined && challenge?.ctfd_url;
    if (imported && currentChallenge === challenge && currentWorkspace?.id === challenge.workspace_id) {
      showCTFdRefreshConnectionFallback(error,challenge);
      return null;
    }
    throw error;
  }
}

async function startAuthenticatedCTFdRefresh(form, body) {
  const workspaceId = form.dataset.workspaceId, challengeId = form.dataset.challengeId;
  if (currentWorkspace?.id !== workspaceId || currentChallenge?.id !== challengeId) throw new Error('문제를 다시 연 뒤 인증해 주세요.');
  body.url = String(body.url || '').trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(body.url)) body.url = `https://${body.url}`;
  if (body.auth_type === 'token') { delete body.username; delete body.password; }
  else if (body.auth_type === 'password') delete body.token;
  else { delete body.token; delete body.username; delete body.password; }
  let started = false;
  try {
    await launchCTFdChallengeRefresh(body);
    started = true;
  } finally {
    for (const key of ['token','username','password']) if (Object.hasOwn(body,key)) body[key] = '';
    for (const input of form.querySelectorAll('input[name="token"],input[name="username"],input[name="password"]')) input.value = '';
  }
  if (started) modal.close();
}

const ctfdJobLabels = {queued:'대기',running:'가져오는 중',completed:'완료',partial:'일부 실패',failed:'실패',cancelled:'취소',interrupted:'중단'};
const ctfdActiveJobStatuses = new Set(['queued','running']);
const ctfdVisibleHistoryLimit = 2;

function ctfdJobMarkup(job) {
  const operation = job.mode === 'new' ? 'CTFd 새 문제 동기화' : job.mode === 'refresh' ? 'CTFd 문제 새로고침' : 'CTFd 가져오기';
  const progress = job.mode === 'refresh' ? `업데이트 ${job.refreshed || 0}개` : job.mode === 'new' ? `신규 ${job.imported || 0}개` : `문제 ${job.imported || 0}개`;
  let controls = '';
  if (ctfdActiveJobStatuses.has(job.status)) controls = `<button class="small" data-action="cancel-ctfd" data-id="${esc(job.id)}">작업 중단</button>`;
  else if (['partial','failed','cancelled','interrupted'].includes(job.status)) {
    if (job.mode === 'refresh' && job.target_challenge_id) {
      controls += `<button class="small" data-action="fresh-refresh-ctfd" data-challenge-id="${esc(job.target_challenge_id)}">최신 원본으로 새 작업</button>`;
    } else {
      const retryLabel = job.mode === 'new' ? '같은 연결로 다시 시도' : '다시 인증하고 이어 받기';
      controls = `<button class="small" data-action="retry-ctfd" data-id="${esc(job.id)}" data-mode="${esc(job.mode || 'import')}">${retryLabel}</button>`;
    }
  }
  return `<section class="workspace-summary" data-job-id="${esc(job.id)}"><div><strong>${esc(operation)} · ${esc(ctfdJobLabels[job.status] || job.status)}</strong><div class="form-hint">${esc(progress)} · 첨부 ${esc(job.attachments || 0)}개 · ${size(job.downloaded_bytes || 0)}${job.current_file ? ` · ${esc(job.current_file)}` : ''}</div>${job.errors?.length ? `<div class="notice error-notice">${importErrors(job.errors)}</div>` : ''}</div><div class="actions">${controls}</div></section>`;
}

function ctfdJobsMarkup(jobs) {
  const active = jobs.filter(job => ctfdActiveJobStatuses.has(job.status));
  const history = jobs.filter(job => !ctfdActiveJobStatuses.has(job.status));
  const recent = history.slice(0,ctfdVisibleHistoryLimit);
  const older = history.slice(ctfdVisibleHistoryLimit);
  const folded = older.length ? `<details class="ctfd-job-history"><summary>이전 CTFd 가져오기 기록 ${older.length}개 보기</summary><div class="ctfd-job-history-list">${older.map(ctfdJobMarkup).join('')}</div></details>` : '';
  return `${active.map(ctfdJobMarkup).join('')}${recent.map(ctfdJobMarkup).join('')}${folded}`;
}

function updateCTFdJobs(area, jobs) {
  const markup = ctfdJobsMarkup(jobs);
  if (ctfdJobMarkupCache.get(area) === markup) return;
  const previousHistory = area.querySelector('.ctfd-job-history');
  const historyWasOpen = previousHistory?.open === true;
  const focused = document.activeElement;
  const historySummaryWasFocused = focused?.tagName === 'SUMMARY' && focused.closest?.('.ctfd-job-history') === previousHistory;
  const focusedJob = focused?.closest?.('[data-job-id]');
  const focusedJobId = focusedJob && area.contains(focusedJob) ? focusedJob.dataset.jobId : '';
  const focusedAction = focusedJobId ? focused.dataset.action : '';
  area.innerHTML = markup;
  ctfdJobMarkupCache.set(area,markup);
  const history = area.querySelector('.ctfd-job-history');
  if (history && historyWasOpen) history.open = true;
  if (historySummaryWasFocused) history?.querySelector('summary')?.focus();
  else if (focusedJobId && focusedAction) {
    const job = [...area.querySelectorAll('[data-job-id]')].find(node => node.dataset.jobId === focusedJobId);
    [...(job?.querySelectorAll('[data-action]') || [])].find(node => node.dataset.action === focusedAction)?.focus();
  }
}

function reflectActiveCTFdRefreshes(jobs, workspaceId) {
  const prefix = `${workspaceId}:`;
  const previous = new Map([...activeCTFdChallengeRefreshes].filter(([key]) => key.startsWith(prefix)));
  const active = jobs.filter(job => job.mode === 'refresh' && ctfdActiveJobStatuses.has(job.status) &&
    typeof job.target_challenge_id === 'string' && job.target_challenge_id);
  const activeKeys = new Set(active.map(job => `${workspaceId}:${job.target_challenge_id}`));
  for (const key of previous.keys()) if (!activeKeys.has(key)) activeCTFdChallengeRefreshes.delete(key);
  for (const job of active) activeCTFdChallengeRefreshes.set(`${workspaceId}:${job.target_challenge_id}`,job.id);

  const challengeId = currentChallenge?.workspace_id === workspaceId ? currentChallenge.id : '';
  if (!challengeId || !detail.open) return null;
  const key = `${workspaceId}:${challengeId}`, activeJob = active.find(job => job.target_challenge_id === challengeId);
  for (const button of detail.querySelectorAll('[data-action="refresh-ctfd-challenge"],[data-action="ctfd-refresh-auth"]')) {
    button.disabled = Boolean(activeJob);
    if (button.dataset.action === 'refresh-ctfd-challenge') {
      button.textContent = activeJob ? '…' : '↻';
      button.setAttribute('aria-label',activeJob ? 'CTFd 문제 새로고침 진행 중' : 'CTFd 원본에서 문제 새로고침');
      button.title = activeJob ? 'CTFd 문제 새로고침 진행 중' : 'CTFd 원본에서 문제 새로고침';
      if (activeJob) button.setAttribute('aria-busy','true'); else button.removeAttribute('aria-busy');
    }
  }
  if (activeJob) {
    paintCTFdChallengeRefresh(activeJob.current_file
      ? `CTFd 첨부파일을 갱신하는 중입니다 · ${activeJob.current_file}`
      : 'CTFd에서 최신 문제 정보를 가져오는 중입니다.');
    return null;
  }
  const previousJobId = previous.get(key);
  if (!previousJobId || watchedCTFdRefreshJobs.has(previousJobId)) return null;
  return jobs.find(job => job.id === previousJobId && job.mode === 'refresh' && job.target_challenge_id === challengeId) || null;
}

async function pollCTFdJobs(workspaceId) {
  const area = document.querySelector('#ctfd-job-area');
  if (!area || currentWorkspace?.id !== workspaceId) return;
  try {
    const result = await api(`/api/workspaces/${workspaceId}/ctfd/jobs`);
    if (!area.isConnected || currentWorkspace?.id !== workspaceId) return;
    const completedRefresh = reflectActiveCTFdRefreshes(result.jobs,workspaceId);
    updateCTFdJobs(area,result.jobs);
    if (result.jobs.some(job => ['queued','running'].includes(job.status))) setTimeout(() => { if (area.isConnected) pollCTFdJobs(workspaceId); },2000);
    else {
      if (completedRefresh?.status === 'completed' && Number(completedRefresh.refreshed || 0) > 0 && currentChallenge?.id === completedRefresh.target_challenge_id && detail.open) {
        rememberNotes();
        await openChallenge(completedRefresh.target_challenge_id);
        toast('CTFd 문제 새로고침이 완료되었습니다. 로컬 풀이 자료는 유지했습니다.');
      } else if (completedRefresh) paintCTFdChallengeRefresh(ctfdJobError(completedRefresh),true);
      await refreshChallenges();
    }
  } catch (error) {
    if (area.isConnected && currentWorkspace?.id === workspaceId) {
      ctfdJobMarkupCache.delete(area);
      area.textContent = error.message;
      setTimeout(() => { if (area.isConnected && currentWorkspace?.id === workspaceId) pollCTFdJobs(workspaceId); },2000);
    }
  }
}

async function retryCTFdJob(button) {
  const workspaceId = currentWorkspace?.id;
  if (!workspaceId) return;
  if (button.dataset.mode === 'new') {
    await api(`/api/workspaces/${workspaceId}/ctfd/jobs/${button.dataset.id}/retry`,{method:'POST',body:{}});
    await pollCTFdJobs(workspaceId);
    toast('저장된 CTFd 연결로 작업을 다시 시작했습니다.');
    return;
  }
  ctfdRetryId = button.dataset.id;
  importForm();
}

async function freshCTFdRefreshFromJob(button) {
  const workspaceId = currentWorkspace?.id, challengeId = button.dataset.challengeId;
  if (!workspaceId || !challengeId) throw new Error('새로고침할 문제를 다시 선택하세요.');
  await openChallenge(challengeId);
  if (currentWorkspace?.id !== workspaceId || currentChallenge?.id !== challengeId) throw new Error('문제를 다시 연 뒤 새로고침해 주세요.');
  try { await refreshCTFdChallenge(); }
  catch (error) {
    paintCTFdChallengeRefresh(error.message,true);
    throw error;
  }
}

document.addEventListener('click', event => {
  const button = event.target.closest('[data-action]');
  if (!button || button.disabled) return;
  const action = button.dataset.action;
  const actions = {
    'logout': async () => { if (authMode !== 'password') return; await api('/api/auth/logout',{method:'POST'}); csrf = ''; showLogin(); noteDrafts.clear(); detail.innerHTML = ''; modal.innerHTML = ''; },
    'toggle-sidebar': () => toggleSidebar(button),
    'toggle-resource-meter': () => toggleResourceMeter(button),
    'toggle-solver-log-size': () => toggleSolverLogSize(button),
    'select-solver-agent': () => selectSolverAgent(button),
    'toggle-solver-agent-branch': () => toggleSolverAgentBranch(button),
    'solver-console-bottom': () => solverConsoleBottom(),
    'close-solver-console': () => solverConsoleDialog?.close(),
    'open-solver-accounts': () => openSolverAccounts(),
    'new-workspace': () => workspaceForm(), 'edit-workspace': () => workspaceForm(true),
    'new-challenge': () => challengeForm(), 'edit-challenge': async () => { const c = currentChallenge; await saveNotes(true); if (currentChallenge === c && currentWorkspace?.id === c.workspace_id) challengeForm(true); },
    'clone-challenge': () => cloneChallenge(),
    'add-relation': () => changeRelation(),
    'install-release-update': () => installReleaseUpdate(button),
    'refresh-release-update': () => refreshReleaseUpdatePanel(true),
    'remove-relation': () => changeRelation(button.dataset.id),
    'open-related-challenge': () => openChallenge(button.dataset.id),
    'remove-challenge-file': () => {
      const form = activeChallengeUploadForm(), index = Number(button.dataset.index);
      if (!form || !Number.isInteger(index)) return;
      selectedChallengeFiles(form).splice(index,1); renderChallengeFiles(form);
    },
    'close-modal': () => { if (busyForms.has(modal.querySelector('form'))) return; if (formDirty() && !confirm('작성 중인 변경 내용을 버리고 닫을까요?')) return; ++modalRendering; modal.close(); importPreview = null; },
    'close-detail': () => {
      if (detailBusy) return;
      if (notesDirty() && !confirm('저장하지 않은 노트가 있습니다. 닫을까요?')) return;
      rememberNotes(); stopSolverPolling(); ++challengeRendering;
      if (solverConsoleDialog?.open) solverConsoleDialog.close();
      detail.close();
    },
    'open-challenge': () => openChallenge(button.dataset.id),
    'open-solver-session': () => openSolverSession(button),
    'copy-list-flag': async () => { const flag = challengeFlags.get(button.dataset.id); if (!flag || currentWorkspace?.id !== button.dataset.workspaceId) throw new Error('Flag를 다시 불러와 주세요.'); await copyText(flag); toast('Flag를 복사했습니다.'); },
    'copy-list-writeup': () => copyChallengeWriteup(button),
    'complete-list-challenge': () => completeListChallenge(button),
    'start-list-solver': () => startListSolver(button),
    'filter': async () => { selectedStatus = button.dataset.status; await refreshChallenges(); },
    'clear-filter': async () => { selectedStatus = ''; selectedCategory = ''; search = ''; await refreshChallenges(); },
    'save-notes': () => saveNotes(),
    'copy-notes': async () => { await copyText(document.querySelector('#notes-editor').value); toast('클립보드에 복사했습니다.'); },
    'copy-flag': async () => { await copyText(currentChallenge.flag || ''); toast('Flag를 복사했습니다.'); },
    'start-solver': () => startSolver(),
    'approve-ultra-escalation': () => approveUltraEscalation(),
    'cancel-solver': () => cancelSolver(),
    'reject-solver-flag': () => rejectSolverFlag(),
    'copy-solver-flag': async () => { if (!currentSolverJob?.flag) throw new Error('발견된 Flag가 없습니다.'); await copyText(currentSolverJob.flag); toast('Flag를 복사했습니다.'); },
    'copy-solver-writeup': async () => { const writeup = solverWriteup(); if (!writeup) throw new Error('완성된 write-up이 없습니다.'); await copyText(writeup); toast('write-up을 복사했습니다.'); },
    'download-solver-writeup': () => { const writeup = solverWriteup(); if (!writeup) throw new Error('완성된 write-up이 없습니다.'); downloadBlob(new Blob([writeup],{type:'text/markdown;charset=utf-8'}),solverFilename()); },
    'refine-writeup': () => startWriteupRefinement(),
    'cancel-writeup-refine': () => cancelWriteupRefinement(),
    'download-notes': () => downloadNotes(),
    'reload-notes': () => reloadNotes(),
    'upload-notes': () => document.querySelector('#notes-file').click(),
    'complete': () => changeCompletion('complete'),
    'reopen': () => changeCompletion('reopen'),
    'delete-challenge': async () => { const c = currentChallenge; if (!confirm(`“${c.name}” 문제와 첨부파일, 노트를 삭제할까요? 되돌릴 수 없습니다.`)) return; await api(path(c.id,c.workspace_id),{method:'DELETE'}); noteDrafts.delete(noteKey(c)); if (currentChallenge === c) { stopSolverPolling(); detail.close(); } await refreshChallenges(); toast('문제를 삭제했습니다.'); },
    'delete-workspace': async () => { const w = currentWorkspace; if (!confirm(`“${w.name}” 작업공간의 모든 문제와 자료를 삭제할까요? 되돌릴 수 없습니다.`)) return; await api(`/api/workspaces/${w.id}`,{method:'DELETE'}); if (currentWorkspace?.id === w.id) { modal.close(); location.hash = ''; } toast('작업공간을 삭제했습니다.'); },
    'delete-attachment': async () => { const c = currentChallenge; if (!confirm('첨부파일을 삭제할까요?')) return; await saveNotes(true); await api(`${path(c.id,c.workspace_id)}/attachments/${button.dataset.id}`,{method:'DELETE'}); if (currentChallenge === c) await openChallenge(c.id); },
    'ctfd-import': () => { ctfdRetryId = null; importForm(); },
    'ctfd-sync': () => previewCTFdSync(),
    'ctfd-sync-retry': () => previewCTFdSync(),
    'refresh-ctfd-challenge': () => refreshCTFdChallenge(),
    'ctfd-refresh-auth': () => ctfdRefreshAuthForm(),
    'ctfd-submit-settings': () => ctfdSubmitSettings(),
    'refresh-ctfd-submit': () => refreshCTFdSubmit(),
    'disconnect-ctfd-submit': () => disconnectCTFdSubmit(),
    'cancel-ctfd': async () => { await api(`/api/workspaces/${currentWorkspace.id}/ctfd/jobs/${button.dataset.id}/cancel`,{method:'POST'}); await pollCTFdJobs(currentWorkspace.id); },
    'retry-ctfd': () => retryCTFdJob(button),
    'fresh-refresh-ctfd': () => freshCTFdRefreshFromJob(button),
    'new-user': () => newUserForm(),
    'user-active': async () => { if (!confirm('사용자 활성 상태를 변경할까요? 비활성 사용자는 기존 세션으로도 접근할 수 없습니다.')) return; await api(`/api/admin/users/${button.dataset.id}`,{method:'PATCH',body:{active:button.dataset.active === 'true'}}); await renderAdmin(); },
    'user-password': () => { openModal('비밀번호 초기화',`${button.dataset.name} 사용자의 로그인 비밀번호를 바꿉니다.`,'<label>새 비밀번호<input type="password" name="password" autocomplete="new-password" minlength="4" maxlength="1024" required><span class="form-hint">4자 이상 · 조합 조건 없음</span></label>','<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">비밀번호 변경</button>','reset-user-form'); modal.querySelector('form').dataset.userId = button.dataset.id; },
    'cleanup-uploads': async () => { const result = await api('/api/admin/uploads/cleanup',{method:'POST'}); toast(`만료된 업로드 ${result.removed}개를 정리했습니다.`); },
    'pause-upload': () => { const active = activeUploads.get(button.dataset.id); if (active) { active.paused = true; active.controller.abort(); } },
    'resume-upload': async () => { const active = activeUploads.get(button.dataset.id); if (active) { await uploadFile(active.file,active.workspaceId,active.challengeId,button.dataset.id); if (currentChallenge?.id === active.challengeId) await openChallenge(active.challengeId); } },
    'cancel-upload': async () => { if (!confirm('이 미완료 업로드와 임시 파일을 삭제할까요?')) return; const active = activeUploads.get(button.dataset.id); if (active) { active.paused = true; active.controller.abort(); } await api(`/api/uploads/${button.dataset.id}`,{method:'DELETE'}); activeUploads.delete(button.dataset.id); await refreshUploads(currentWorkspace.id,currentChallenge.id); },
  };
  if (actions[action]) {
    event.preventDefault();
    if (['save-notes','reload-notes','complete','reopen','reject-solver-flag','delete-challenge','delete-attachment','edit-challenge','clone-challenge'].includes(action)) detailAction(actions[action],button);
    else if (['refresh-ctfd-submit','disconnect-ctfd-submit'].includes(action)) run(actions[action]);
    else run(actions[action], button);
  }
});

document.addEventListener('submit', event => {
  const form = event.target;
  if (form.matches?.('.challenge-inline-input')) {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    runForm(() => continueListSolver(form,body),form,form.querySelector('button[type="submit"]'));
    return;
  }
  if (!form.id) return;
  const known = ['login-form','setup-form','new-workspace-form','edit-workspace-form','new-challenge-form','edit-challenge-form','search-form','password-form','username-form','new-user-form','reset-user-form','solver-capacity-form','solver-guidance-form','solver-console-guidance-form','ctfd-preview-form','ctfd-import-form','ctfd-sync-form','ctfd-refresh-auth-form','ctfd-submit-connection-form'];
  if (!known.includes(form.id)) return;
  event.preventDefault();
  const challengeFiles = form.id === 'new-challenge-form' ? [...selectedChallengeFiles(form)] : [];
  const data = new FormData(form);
  const body = Object.fromEntries(data);
  if (form.id === 'ctfd-submit-connection-form') { run(() => saveCTFdSubmitConnection(form,body)); return; }
  runForm(async () => {
    if (form.id === 'setup-form') {
      if (body.password !== body.confirmation) throw new Error('비밀번호 확인이 일치하지 않습니다.');
      const result = await api('/api/auth/setup',{method:'POST',body:{username:body.username,password:body.password}});
      csrf = result.csrf_token; sessionUser = result.user; form.reset(); await render();
    } else if (form.id === 'login-form') {
      const result = await api('/api/auth/login',{method:'POST',body:{username:body.username,password:body.password}}); csrf = result.csrf_token; if (sessionUser && sessionUser.id !== result.user.id) { noteDrafts.clear(); clearAccountsReturnTarget(); } sessionUser = result.user; form.reset(); await render();
    } else if (form.id === 'new-workspace-form' || form.id === 'edit-workspace-form') {
      const edit = form.id === 'edit-workspace-form';
      body.open_challenge_after_create = data.has('open_challenge_after_create');
      const w = await api(edit ? `/api/workspaces/${form.dataset.workspaceId}` : '/api/workspaces',{method:edit?'PATCH':'POST',headers:edit ? conditional(form.dataset.editToken) : {},body}); modal.close();
      if (location.hash === `#w/${w.id}`) { currentWorkspace = w; await renderWorkspace(); } else { selectedStatus='';selectedCategory='';selectedSort='added_desc';search='';location.hash = `w/${w.id}`; }
      toast(edit ? '작업공간 설정을 저장했습니다.' : '작업공간을 만들었습니다.');
    } else if (form.id === 'new-challenge-form' || form.id === 'edit-challenge-form') {
      const edit = form.id === 'edit-challenge-form'; delete body.files;
      if (body.remote_mode !== 'endpoint') body.remote = '';
      const workspaceId = form.dataset.workspaceId;
      const c = await api(edit ? path(form.dataset.challengeId,workspaceId) : path(null,workspaceId),{method:edit?'PATCH':'POST',headers:edit ? conditional(form.dataset.editToken) : {},body});
      let failures = [];
      modal.close();
      if (currentWorkspace?.id === workspaceId) {
        await refreshChallenges();
        if (edit || currentWorkspace.open_challenge_after_create) await openChallenge(c.id);
      }
      toast('문제를 저장했습니다.');
      let uploaded = 0;
      if (!edit) for (const file of challengeFiles) { try { if (await uploadFile(file,workspaceId,c.id)) uploaded++; } catch (error) { failures.push(`${file.name}: ${error.message}`); } }
      if (!edit && currentWorkspace?.id === workspaceId && challengeFiles.length) await refreshChallenges();
      if (uploaded) toast(`첨부파일 ${uploaded}개를 저장했습니다.`);
      if (failures.length) toast(failures.join(' / '),true);
    } else if (form.id === 'search-form') { search = body.q; selectedCategory = document.querySelector('#category-filter').value; selectedSort = document.querySelector('#sort-order').value; await refreshChallenges(); }
    else if (form.id === 'password-form') { if (body.new_password !== body.confirmation) throw new Error('새 비밀번호 확인이 일치하지 않습니다.'); delete body.confirmation; const result = await api('/api/auth/password',{method:'POST',body}); csrf = result.csrf_token; form.reset(); toast('비밀번호를 변경했습니다.'); }
    else if (form.id === 'username-form') { const result = await api('/api/auth/username',{method:'POST',body}); sessionUser.username = result.username; csrf = result.csrf_token; renderSettings(); toast('아이디를 변경했습니다.'); }
    else if (form.id === 'new-user-form') { await api('/api/admin/users',{method:'POST',body}); form.reset(); modal.close(); await renderAdmin(); toast('사용자를 추가했습니다.'); }
    else if (form.id === 'reset-user-form') { await api(`/api/admin/users/${form.dataset.userId}/password`,{method:'POST',body}); form.reset(); modal.close(); toast('비밀번호를 변경했습니다.'); }
    else if (form.id === 'solver-capacity-form') { const maximum = String(body.maximum || '').trim(); await api('/api/admin/solver-capacity',{method:'PUT',body:{maximum:maximum ? Number(maximum) : null}}); await renderAdmin(); toast('솔버 최대 수를 저장했습니다.'); }
    else if (form.id === 'solver-guidance-form') { await sendSolverGuidance(body.message); }
    else if (form.id === 'solver-console-guidance-form') { await sendSolverGuidance(body.message,body.requested_delivery || 'next_turn'); }
    else if (form.id === 'ctfd-preview-form') {
      if (!body.token) delete body.token;
      body.url = body.url.trim(); if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(body.url)) body.url = `https://${body.url}`;
      const result = await api(`/api/workspaces/${currentWorkspace.id}/ctfd/preview`,{method:'POST',body}); form.reset(); showImportPreview(result,body);
    } else if (form.id === 'ctfd-import-form') {
      const ids = data.getAll('challenge').map(Number); if (!ids.length) throw new Error('가져올 문제를 선택하세요.');
      const workspaceId = currentWorkspace.id;
      const endpoint = ctfdRetryId ? `/api/workspaces/${workspaceId}/ctfd/jobs/${ctfdRetryId}/retry` : `/api/workspaces/${workspaceId}/ctfd/import`;
      const payload = importPreview.result.preview_id ? {preview_id:importPreview.result.preview_id,challenge_ids:ids} : {...importPreview.credentials,challenge_ids:ids};
      await api(endpoint,{method:'POST',body:payload});
      importPreview = null; ctfdRetryId = null; modal.close(); await refreshChallenges(); await pollCTFdJobs(workspaceId); toast('CTFd 가져오기를 시작했습니다.');
    } else if (form.id === 'ctfd-sync-form') {
      const ids = data.getAll('challenge').map(Number).filter(id => Number.isInteger(id) && id > 0);
      await startCTFdSync(form,ids);
    } else if (form.id === 'ctfd-refresh-auth-form') {
      await startAuthenticatedCTFdRefresh(form,body);
    }
  }, form, form.querySelector('button[type="submit"],button:not([type])'));
});

document.addEventListener('change', event => {
  const input = event.target;
  if (input.id === 'challenge-files') {
    addChallengeFiles(input.closest('form'),input.files);
    input.value = '';
  }
  if (input.matches?.('.challenge-inline-input select[name="remote_mode"]')) {
    const remote = input.closest('form')?.querySelector('input[name="remote"]');
    if (remote) {
      const enabled = input.value === 'endpoint';
      remote.disabled = !enabled; remote.required = enabled;
      remote.closest('label')?.classList.toggle('is-disabled',!enabled);
    }
  }
  if (input.id === 'solver-provider-select') {
    solverProvider = input.value === 'claude' ? 'claude' : 'codex';
    try { localStorage.setItem('ctf-solver-provider',solverProvider); } catch {}
    solverAccountId = '';
    if (currentWorkspace && currentChallenge) run(() => loadSolverConfiguration(
      currentWorkspace.id,currentChallenge.id,solverRendering
    ));
  }
  if (input.id === 'solver-account-select') {
    solverAccountId = input.value;
    if (currentWorkspace && currentChallenge) run(() => loadSolverConfiguration(
      currentWorkspace.id,currentChallenge.id,solverRendering,solverAccountId
    ));
  }
  if (input.id === 'solver-model-select') {
    solverModel = input.value;
    const chosen = solverSelectedModel();
    const efforts = Array.isArray(chosen?.supportedReasoningEfforts)
      ? chosen.supportedReasoningEfforts.map(item => item?.reasoningEffort).filter(Boolean) : [];
    solverReasoning = efforts.includes(solverReasoning) ? solverReasoning
      : efforts.includes(chosen?.defaultReasoningEffort) ? chosen.defaultReasoningEffort
      : efforts[0] || '';
    const supportsFast = Array.isArray(chosen?.serviceTiers) && chosen.serviceTiers.some(item => item?.id === 'fast');
    if (!supportsFast) solverServiceTier = null;
    if (solverProvider !== 'claude' || chosen?.supportsUltracode !== true) solverUltracode = false;
    repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
  }
  if (input.id === 'solver-reasoning-select') {
    solverReasoning = input.value;
    repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
  }
  if (input.id === 'solver-fast-toggle') {
    solverServiceTier = input.checked ? 'fast' : null;
  }
  if (input.id === 'solver-ultracode-toggle') {
    solverUltracode = input.checked;
  }
  if (input.id === 'solver-ultra-escalation') {
    solverUltraEscalationMode = ['ask','auto','off'].includes(input.value) ? input.value : 'ask';
  }
  if (input.id === 'category-filter') run(async () => { selectedCategory = input.value; await refreshChallenges(); });
  if (input.id === 'sort-order') run(async () => { selectedSort = input.value; await refreshChallenges(); });
  if (input.id === 'ctfd-auth-type') {
    for (const [id,type] of [['ctfd-token-fields','token'],['ctfd-password-fields','password']]) {
      const fields = document.getElementById(id), enabled = input.value === type;
      fields.hidden = !enabled;
      fields.querySelectorAll('input').forEach(node => { node.disabled = !enabled; node.required = enabled; if (!enabled) node.value = ''; });
    }
  }
  if (input.id === 'ctfd-refresh-auth-type') {
    for (const [id,type] of [['ctfd-refresh-token-fields','token'],['ctfd-refresh-password-fields','password']]) {
      const fields = document.getElementById(id), enabled = input.value === type;
      fields.hidden = !enabled;
      fields.querySelectorAll('input').forEach(node => { node.disabled = !enabled; node.required = enabled; if (!enabled) node.value = ''; });
    }
  }
  if (input.id === 'ctfd-submit-auth-type') {
    for (const [id,type] of [['ctfd-submit-token-fields','token'],['ctfd-submit-password-fields','password']]) {
      const fields = document.getElementById(id), enabled = input.value === type;
      fields.hidden = !enabled;
      fields.querySelectorAll('input').forEach(node => { node.disabled = !enabled; node.required = enabled; if (!enabled) node.value = ''; });
    }
  }
  if (input.id === 'ctfd-auto-submit-toggle') run(() => toggleCTFdSubmit(input));
  if (input.dataset.action === 'user-role') run(async () => {
    try { const user = await api(`/api/admin/users/${input.dataset.id}`,{method:'PATCH',body:{role:input.value}}); if (user.id === sessionUser.id) sessionUser = user; }
    finally { await renderAdmin(); }
  },input);
  if (input.id === 'status-select') detailAction(async () => {
    const c = currentChallenge, status = input.value;
    try { await saveNotes(true); await api(`${path(c.id,c.workspace_id)}/status`,{method:'PATCH',body:{status}}); if (currentChallenge?.id === c.id) await openChallenge(c.id); await refreshChallenges(); }
    catch (error) { input.value = c.status; throw error; }
  });
  if (input.id === 'attachment-files') run(async () => {
    const c = currentChallenge, failures = [];
    let completed = 0;
    for (const file of input.files) { try { if (await uploadFile(file,c.workspace_id,c.id)) completed++; } catch(error) { failures.push(`${file.name}: ${error.message}`); } }
    if (currentChallenge?.id === c.id) await openChallenge(c.id); input.value = '';
    if (failures.length) throw new Error(failures.join(' / ')); if (completed) toast(`첨부파일 ${completed}개를 저장했습니다.`);
  },input);
  if (input.id === 'solver-console-files') run(async () => {
    const challenge = currentChallenge, files = [...input.files], failures = [];
    if (!challenge) return;
    let completed = 0;
    try {
      for (const file of files) {
        try { if (await uploadFile(file,challenge.workspace_id,challenge.id)) completed++; }
        catch (error) { failures.push(`${file.name}: ${error.message}`); }
      }
      await refreshChallengeAttachmentsInPlace(challenge.workspace_id,challenge.id);
      if (completed && currentChallenge?.id === challenge.id && solverIsActive(currentSolverJob) && currentSolverJob.guidance_allowed !== false) {
        const names = files.filter(file => file?.name).map(file => file.name).slice(0, 20);
        try {
          await sendSolverGuidance(`새 문제 파일 ${completed}개를 업로드했습니다. attachments/에서 새로 추가된 파일을 확인하고 풀이를 이어가세요.${names.length ? ` 파일: ${names.join(', ')}` : ''}`.slice(0, 4000),
            (currentSolverJob.model || currentSolverJob.configuration || {}).provider === 'claude' ? 'next_turn' : 'same_turn');
        } catch (error) { toast(`파일은 저장됐습니다. 추가 명령 전달: ${error.message}`, true); }
      }
      if (completed) toast(`첨부파일 ${completed}개를 저장했습니다.`);
      if (failures.length) throw new Error(failures.join(' / '));
    } finally { input.value = ''; }
  },input);
  if (input.id === 'notes-file' && input.files.length) detailAction(async () => {
    const c = currentChallenge, editor = document.querySelector('#notes-editor'), previous = editor.value;
    try {
      if (previous && !confirm('현재 노트를 선택한 파일의 내용으로 바꿀까요?')) return;
      const body = new FormData(); body.append('file',input.files[0]);
      await api(`${path(c.id,c.workspace_id)}/notes/upload`,{method:'POST',headers:conditional(c.notes_token),body});
      const latest = await api(path(c.id,c.workspace_id));
      if (currentChallenge !== c) return;
      c.notes = latest.notes; c.notes_token = latest.notes_token;
      if (editor.value === previous) editor.value = latest.notes;
      rememberNotes(); await openChallenge(c.id); toast('Markdown 노트를 불러왔습니다.');
    } finally { input.value = ''; }
  },input);
});

document.addEventListener('input', event => {
  if (event.target.id === 'notes-editor') { rememberNotes(); const state = document.querySelector('#notes-save-state'); if (state) { state.classList?.remove('hidden'); state.textContent = '저장하지 않은 변경 사항'; } }
  if (event.target.id === 'writeup-refine-instruction') writeupRefineInstruction = event.target.value;
  if (event.target.id === 'solver-guidance-message') solverGuidanceDraft = event.target.value;
  if (event.target.id === 'solver-console-message') solverGuidanceDraft = event.target.value;
});

document.addEventListener('dragenter', event => {
  if (!fileDrag(event.dataTransfer) || !activeChallengeUploadForm()) return;
  event.preventDefault(); challengeFileDragDepth++; setChallengeFileDrag(true);
});
document.addEventListener('dragover', event => {
  if (!fileDrag(event.dataTransfer) || !activeChallengeUploadForm()) return;
  event.preventDefault();
  try { event.dataTransfer.dropEffect = 'copy'; } catch {}
  setChallengeFileDrag(true);
});
document.addEventListener('dragleave', event => {
  if (!activeChallengeUploadForm()) { resetChallengeFileDrag(); return; }
  challengeFileDragDepth = Math.max(0,challengeFileDragDepth - 1);
  if (!challengeFileDragDepth || !event.relatedTarget) resetChallengeFileDrag();
});
document.addEventListener('drop', event => {
  const form = activeChallengeUploadForm();
  if (!form || !fileDrag(event.dataTransfer)) return;
  event.preventDefault(); resetChallengeFileDrag(); addChallengeFiles(form,event.dataTransfer.files);
});
window.addEventListener('dragend',resetChallengeFileDrag);
window.addEventListener('blur',resetChallengeFileDrag);

document.addEventListener('keydown', event => {
  if (['Enter',' '].includes(event.key) && event.target.matches('tr[data-action]')) { event.preventDefault(); event.target.click(); }
});
detail.addEventListener('cancel', event => {
  if (detailBusy || (notesDirty() && !confirm('저장하지 않은 노트가 있습니다. 닫을까요?'))) event.preventDefault();
  else { rememberNotes(); stopSolverPolling(); ++challengeRendering; }
});
detail.addEventListener('close', () => { if (!detail.open) stopSolverPolling(); });
modal.addEventListener('cancel', event => { if (busyForms.has(modal.querySelector('form')) || (formDirty() && !confirm('작성 중인 변경 내용을 버리고 닫을까요?'))) event.preventDefault(); else ++modalRendering; });
modal.addEventListener('close', () => { resetChallengeFileDrag(); if (!modal.open) { ++modalRendering; modal.removeAttribute('aria-busy'); modal.dataset.kind = ''; } importPreview = null; });
window.addEventListener('hashchange', event => {
  if ((formDirty() || notesDirty() || detailBusy || (modal.open && busyForms.has(modal.querySelector('form')))) && !confirm('저장하지 않은 내용이나 진행 중인 요청이 있습니다. 다른 화면으로 이동할까요?')) { if (accountsReturnPending) clearAccountsReturnTarget(); history.replaceState(null,'',event.oldURL); return; }
  accountsReturnPending = false;
  const returnRoute = accountsReturnRoute();
  if (returnRoute && location.hash === `#${returnRoute}`) clearAccountsReturnTarget();
  rememberNotes(); stopSolverPolling(); stopResourcePolling(); stopChallengeListPolling(); ++challengeRendering; ++listRendering; ++modalRendering; challengeFlags.clear(); selectedStatus=''; selectedCategory=''; selectedSort='added_desc'; search=''; if (solverConsoleDialog?.open) solverConsoleDialog.close(); detail.close(); modal.close(); if (csrf) run(render);
});
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') { stopResourcePolling(); stopChallengeListPolling(); }
  else if (currentWorkspace?.id) {
    if (document.querySelector('#workspace-resource-meter') && !resourceMeterHidden()) startResourcePolling(currentWorkspace.id);
    if (document.querySelector('#challenge-area')) startChallengeListPolling(currentWorkspace.id);
  }
});
window.addEventListener('beforeunload', event => { if (notesDirty() || formDirty() || [...activeUploads.values()].some(upload => upload.running)) { event.preventDefault(); event.returnValue = ''; } });
run(async () => { const state = await api('/api/auth/state'); await i18n.init(); authMode = state.auth_mode || 'password'; if (state.authenticated) { csrf = state.csrf_token; sessionUser = state.user; await render(); } else if (authMode === 'password') showLogin(false,state.configured,state.setup_available); else app.innerHTML = '<main class="login-shell"><div class="login-card"><h1>서비스 연결 오류</h1></div></main>'; });
