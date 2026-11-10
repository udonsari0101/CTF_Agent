// A relative import inherits the release-specific asset directory emitted by
// the server, preventing a new app.js from loading a cached older dependency.
import {renderAccounts} from './accounts.js';
import {renderAdminCliVersions} from './admin_versions.js';
const i18n = globalThis.ctfI18n || {locale:'ko',t:value=>value,format:(value,values) => value.replace(/\{(\w+)\}/g,(hole,name) => values[name] ?? hole),picker:()=>'',init:async()=>{}};

const app = document.querySelector('#app');
const modal = document.querySelector('#modal');
const detail = document.querySelector('#detail');
const statuses = {pending:'시작 전',running:'작업 중',stopped:'중단',failed:'실패',flag_found:'Flag 발견',solved:'완료'};
let csrf = '', workspaces = [], currentWorkspace = null, currentChallenge = null;
let sessionUser = null;
let sessionPersistent = false;
let authMode = 'password';
const activeUploads = new Map();
const uploadViews = new Map();
const stagedActiveUploads = new Map();
const stagedFilesCache = new Map();
const stagedWaiting = new Map();
const stagedBatches = new Map();
let stagedRefreshTimer = null;
const startingListSolvers = new Set();
let challengeFlags = new Map();
const writeupCopyCache = new Map();
const WRITEUP_COPY_CACHE_BYTES = 512 * 1024;
const writeupCopyEpoch = new Map();
const writeupCurrentStamp = new Map();
let writeupCopyCacheBytes = 0;
let writeupPrefetchObserver = null;
let writeupPrefetchWorkspace = '';
let writeupPrefetchQueue = [];
let writeupPrefetchRequested = new Set();
let writeupPrefetchActive = 0;
let writeupPrefetchGeneration = 0;
let selectedStatus = '', selectedCategory = '', selectedSort = 'added_desc', search = '', disposeAccounts = null, importPreview = null;
let disposeTelegram = null;
let ctfdRetryId = null;
// Per-workspace CTFd import drafts. In memory only, and never holds a token or password.
const ctfdDrafts = new Map();
let ctfdJobsPollTimer = null, ctfdJobsRequestGeneration = 0;
const activeCTFdChallengeRefreshes = new Map();
const watchedCTFdRefreshJobs = new Set();
let rendering = 0, challengeRendering = 0, listRendering = 0, detailBusy = false;
let modalRendering = 0, ctfdSubmitRendering = 0;
// Bumped whenever a session ends or starts. Work that began under an older epoch belongs
// to a session that is gone: its 401 means nothing and its errors have nobody to reach.
let authEpoch = 0, signedOut = false, signingOut = false;
// How long the first screen waits for one answer. A slow server still gets through; a request
// that never answers ends in the failure page with Retry. The language files use the same limit.
const PAGE_LOAD_LIMIT_MS = 25000;
// The last failure or not-found page: its markup for a language change, and what Retry runs.
let pageNotice = null, pageRetry = null;
let workspacesListed = false;
// Only the newest boot may act on its answers. A language switch re-arms a running Retry.
let bootAttempt = 0;
let challengeFileDragDepth = 0;
let transferState = null;
let transferExportController = null;
let directInviteState = null, directInviteTimer = null;
let directSendState = null, directSendTimer = null, directSendBusy = false;
const TRANSFER_CHUNK_BYTES = 8 * 1024 * 1024;
let solverRendering = 0, solverPollTimer = null, currentSolverJob = null;
let resourcePollTimer = null, resourceRequestGeneration = 0;
let challengeListPollTimer = null, challengeListPollGeneration = 0, challengeListSignatures = new Map(), challengeListCategories = '';
// A healthy server answers the list long before the short limit, and three misses in a row show the notice within 20 s of
// a hang. A slower server is not a dead one: after the notice, or after an answer that took that long, the long limit
// applies, so aborting cannot turn slow into never. The rest of this state lives on currentWorkspace (listFailures,
// listUpdatedAt, listStaleAt, gone), so a new page starts clean.
const CHALLENGE_LIST_FAILURES_SHOWN = 3, CHALLENGE_LIST_TIMEOUT = 4000, CHALLENGE_LIST_SLOW_TIMEOUT = PAGE_LOAD_LIMIT_MS;
let challengeListSlow = false;
let currentSolverEvents = [], currentSolverGuidance = [], solverEventCursor = 0, solverListedFlag = '', solverSyncedWriteup = '', solverGuidanceDraft = '';
let writeupRefineJob = null, writeupRefineEvents = [], writeupRefineTimer = null;
let writeupRefineError = null, writeupRefineInstruction = '';
let relatedCandidates = [];
let releaseUpdateTimer = null, releaseUpdateRequestGeneration = 0;
let solverProvider = (() => { try { return localStorage.getItem('ctf-solver-provider') === 'claude' ? 'claude' : 'codex'; } catch { return 'codex'; } })();
let solverAccounts = [], solverAccountId = '', solverModels = [], solverModel = '';
let solverReasoning = '', solverServiceTier = null, solverUltracode = false, solverOptionsState = 'idle', solverOptionsError = '';
let solverUltraEscalationMode = 'ask';
let solverRetryIssues = [], solverRetryRequiresSelection = false;
let solverConfigurationJobId = '';
let solverOptionsGeneration = 0;
let sidebarCollapsed = (() => { try { return localStorage.getItem('ctf-sidebar-collapsed') === 'true'; } catch { return false; } })();
let solverLogExpanded = false, solverConsoleDialog = null;
let solverConfirmDialog = null;
let solverConsoleAgentId = 'root', solverConsoleFollowLatest = true;
const solverCollapsedAgentIds = new Set();
const solverConsoleCardStates = new Map();
const noteDrafts = new Map();
let challengeListing = null, adminView = null, resourceMeterSnapshot = null;
const busyForms = new WeakSet();
const ctfdJobMarkupCache = new WeakMap();
const challengeReturnRoute = /^w\/[0-9a-f]{32}\/c\/[0-9a-f]{32}$/;
let accountsReturnTarget = null, accountsReturnPending = false;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function avatarMarkup(user) {
  const seed = String(user?.avatar_seed || user?.id || 'local');
  let state = 2166136261;
  for (const char of seed) state = Math.imul(state ^ char.charCodeAt(0), 16777619) >>> 0;
  const hue = state % 360;
  let cells = '';
  for (let row = 0; row < 5; row++) for (let column = 0; column < 3; column++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    if ((state & 0x80000000) || (row === 2 && column === 2)) {
      cells += `<rect x="${column}" y="${row}" width="1" height="1"/>`;
      if (column !== 2) cells += `<rect x="${4-column}" y="${row}" width="1" height="1"/>`;
    }
  }
  return `<svg viewBox="0 0 5 5" width="32" height="32" role="img" aria-label="${tr('Profile image')}"><rect width="5" height="5" fill="hsl(${hue} 35% 94%)"/><g fill="hsl(${hue} 65% 36%)">${cells}</g></svg>`;
}
const tr = value => esc(i18n.t(value));
const date = value => new Date(value).toLocaleDateString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US', {month:'short',day:'numeric',timeZone:'Asia/Seoul'});
const size = value => value < 1024 ? `${value} B` : value < 1024**2 ? `${(value/1024).toFixed(1)} KB` : value < 1024**3 ? `${(value/1024**2).toFixed(1)} MB` : value < 1024**4 ? `${(value/1024**3).toFixed(2)} GB` : `${(value/1024**4).toFixed(2)} TB`;
const badge = status => `<span class="status status-${esc(status)}">${esc(statuses[status] || status)}</span>`;
const importErrors = errors => errors.map(error => {
  if (typeof error === 'string') return esc(i18n.t(error));
  const message = i18n.t(error.message || '가져오기 오류');
  return esc(error.challenge_id ? i18n.t('문제 {id}: {message}').replace('{id}',error.challenge_id).replace('{message}',() => message) : message);
}).join('<br>');
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

function stopCTFdJobsPolling() {
  if (ctfdJobsPollTimer) clearTimeout(ctfdJobsPollTimer);
  ctfdJobsPollTimer = null;
  ctfdJobsRequestGeneration++;
}

function stopReleaseUpdatePolling() {
  if (releaseUpdateTimer) clearTimeout(releaseUpdateTimer);
  releaseUpdateTimer = null;
  releaseUpdateRequestGeneration++;
}

// The polls re-check currentWorkspace, so nothing of a page that is gone can come back.
function leaveWorkspacePage(keepDetail = false) {
  if (keepDetail) pauseSolverPolling(); else stopSolverPolling();
  stopResourcePolling();
  stopChallengeListPolling();
  stopCTFdJobsPolling();
  ++listRendering; ++challengeRendering;
  currentWorkspace = null;
}

function paintResourceMeter(snapshot) {
  resourceMeterSnapshot = snapshot;
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
  // Nothing inside a code span is Markdown, so each one waits behind a placeholder while
  // links and bold run over the text around it. A literal marker character is held the
  // same way: it stays in the text and cannot pose as a placeholder.
  const held = [];
  const hold = html => `\uE000${held.push(html) - 1}\uE001`;
  // Shield backticks in URL targets before recognizing code spans. A URL can contain
  // literal backticks, while a standalone `https://...` must still be rendered as code.
  const source = String(value ?? '')
    .replace(/[\uE000\uE001\uE002]/g,match => hold(match))
    .replace(/\]\(https?:\/\/[^\s)\uE000\uE001]+/g,match => match.replace(/`/g,'\uE002'))
    .replace(/`([^`\n]+)`/g,(_,code) => hold(`<code>${esc(code)}</code>`));
  const format = segment => esc(segment)
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/__([^_\n]+)__/g, '<strong>$1</strong>');
  let result = '', cursor = 0;
  const link = /\[([^\]\n]+)\]\((https?:\/\/[^\s)\uE000\uE001]+)\)|(https?:\/\/[^\s<>()\uE000\uE001]+)/g;
  for (const match of source.matchAll(link)) {
    result += format(source.slice(cursor, match.index));
    const raw = match[2] || match[3];
    const suffix = match[3] ? (raw.match(/[.,;:!?]+$/)?.[0] || '') : '';
    const url = (suffix ? raw.slice(0, -suffix.length) : raw).replace(/\uE002/g,'`');
    let safe = false;
    try { safe = ['http:', 'https:'].includes(new URL(url).protocol); } catch {}
    result += safe
      ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${format(match[1] || url)}</a>${format(suffix)}`
      : format(match[0]);
    cursor = match.index + match[0].length;
  }
  return (result + format(source.slice(cursor))).replace(/\uE000(\d+)\uE001/g,(_,index) => held[index]);
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
  failed:'실패',refused:'실행 거부',needs_input:'추가 입력 필요',cleanup_blocked:'격리 정리 실패',interrupted:'중단됨',
  releasing:'격리 정리 중',
};
const solverProgress = {
  preparing:'문제 자료 준비',analyzing:'문제 분석',waiting_for_model:'모델 응답 대기',inspecting_files:'첨부파일 확인',researching:'자료 조사',executing:'풀이 실행',
  validating_flag:'Flag 검증',drafting_writeup:'write-up 작성',provider_auth_retry:'계정 인증 재확인',provider_access_check:'모델 사용 권한 확인',
  provider_quota_retry:'계정 사용량 제한 확인',provider_rate_limit_retry:'공급자 요청 제한 재시도',
  provider_overloaded_retry:'공급자 과부하 재시도',provider_connection_retry:'공급자 연결 재시도',
  provider_retrying:'공급자 응답 재시도',reasoning_escalated:'추론 max 자동 승격',
  continuation_restored:'이전 작업 파일 복원',session_resumed:'이전 세션 재개',
  workspace_restored:'이전 작업 파일 복원',continuation_fallback:'이전 분석으로 전환',
};
const solverActivityPhases = {started:'시작',completed:'완료',attachment_added:'첨부 추가',attachment_sync_failed:'첨부 동기화 실패'};
const solverGuidanceStates = {queued:'대기',staged:'전달 준비',delivered:'전달됨',rejected:'거부됨'};
const solverGuidanceErrors = {job_finished:'풀이 종료',solve_finished:'풀이 종료'};
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

// Polls in flight see the new generation and end. What the panel shows, and copies, stays.
function pauseSolverPolling() {
  ++solverRendering;
  ++solverOptionsGeneration;
  if (solverPollTimer) clearTimeout(solverPollTimer);
  if (writeupRefineTimer) clearTimeout(writeupRefineTimer);
  solverPollTimer = null;
  writeupRefineTimer = null;
}

function stopSolverPolling() {
  pauseSolverPolling();
  currentSolverJob = null;
  currentSolverEvents = [];
  currentSolverGuidance = [];
  solverEventCursor = 0;
  solverGuidanceDraft = '';
  solverConsoleAgentId = 'root'; solverConsoleFollowLatest = true; solverCollapsedAgentIds.clear(); solverConsoleCardStates.clear();
  solverListedFlag = '';
  solverSyncedWriteup = '';
  solverAccounts = []; solverAccountId = ''; solverModels = []; solverModel = '';
  solverReasoning = ''; solverServiceTier = null; solverUltracode = false; solverOptionsState = 'idle'; solverOptionsError = '';
  solverUltraEscalationMode = ['ask','auto','off'].includes(sessionUser?.ultra_escalation_default)
    ? sessionUser.ultra_escalation_default : 'ask';
  solverRetryIssues = []; solverRetryRequiresSelection = false;
  solverConfigurationJobId = '';
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

const solverEventCap = 2500, solverHeldEventCap = 12000;

function mergeSolverEvents(current, incoming, cap = solverEventCap) {
  const merged = [], positions = new Map();
  for (const event of [...(Array.isArray(current) ? current : []),...(Array.isArray(incoming) ? incoming : [])]) {
    if (!event || typeof event !== 'object') continue;
    const sequence = solverEventSequence(event);
    const key = sequence ? `sequence:${sequence}` : `fallback:${event.kind || ''}:${event.created_at || event.occurred_at || ''}:${event.code || event.progress_code || ''}`;
    if (positions.has(key)) merged[positions.get(key)] = event;
    else { positions.set(key,merged.length); merged.push(event); }
  }
  merged.sort((a,b) => solverEventSequence(a) - solverEventSequence(b));
  return merged.slice(-cap);
}

// Older events are dropped only once nobody is reading them: eviction under a
// scrolled-up reader destroys the cards and open details they are looking at.
function solverEventLimit(panel, incoming) {
  if (currentSolverEvents.length + incoming < solverEventCap) return solverEventCap;
  if (solverConsoleDialog?.open && !solverConsoleFollowLatest) return solverHeldEventCap;
  const compact = panel?.querySelector('.solver-live-console');
  return compact?.clientHeight && compact.scrollHeight - compact.scrollTop - compact.clientHeight >= 32
    ? solverHeldEventCap : solverEventCap;
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
    const remaining = used == null ? i18n.t('남은 사용량 미제공') : `${100 - used}% ${i18n.t('남음')}`;
    return [`<li><strong>${esc(solverQuotaWindowLabel(window.window_minutes))}</strong><span>${esc(remaining)} · ${esc(solverQuotaReset(window.resets_at))}</span></li>`];
  }) : [];
  if (!reasons.length && !windows.length) return '';
  return `<div class="solver-quota" aria-label="Codex 사용량 제한"><strong>${tr('제한 항목')} · ${esc(safeName)}</strong>${reasons.map(reason => `<p>${esc(reason)}</p>`).join('')}${windows.length ? `<ul>${windows.join('')}</ul>` : '<p>초기화 구간 정보는 공급자가 제공하지 않았습니다.</p>'}</div>`;
}

function solverErrorMarkup(error, defaultTitle = '풀이 실행 오류') {
  if (!error) return '';
  if (error.code === 'ultra_escalation_requested') {
    return `<div class="notice muted solver-ultra-request" role="status"><strong>Ultra 전환 제안</strong><p>${esc(error.message || '분석을 이어받아 Ultra로 계속할 수 있습니다.')}</p></div>`;
  }
  const providerCode = String(error.provider_code || '').toUpperCase();
  const needsRemote = error.code === 'remote_input_required';
  const serviceUpdating = error.code === 'service_updating';
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
  if (serviceUpdating) {
    title = i18n.t('서비스 업데이트 중');
    guidance = i18n.t('새 풀이 작업은 등록되지 않았습니다. 업데이트 완료 후 다시 시작해 주세요.');
  } else if (needsRemote) {
    title = '추가 입력이 필요합니다';
    guidance = '요청된 원격 접속 정보나 누락된 파일을 문제에 추가한 뒤 다시 시작하세요.';
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
    title = `${i18n.t('보안 작업 정책 제한')}${providerCode ? ` · ${providerCode}` : ''}`;
    guidance = '다른 모델이나 권한을 확인하세요.';
  } else if (toolsUnavailable) {
    title = '로컬 풀이 도구 사용 불가';
    guidance = 'shell·terminal·command를 지원하는 모델을 선택하세요.';
  }
  const requirements = Array.isArray(error.requirements) && error.requirements.length
    ? `<small>${tr('필요 조건')}: <span data-i18n-ignore>${error.requirements.map(esc).join(', ')}</span></small>` : '';
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
  return i18n.t(solverProgress[code] || kinds[event.kind] || solverPhases[phase] || '상태 변경');
}

let solverTimeFormat = null, solverTimeFormatLocale = '';

function clockText(milliseconds) {
  const locale = i18n.locale === 'ko' ? 'ko-KR' : 'en-US';
  if (solverTimeFormatLocale !== locale) {
    solverTimeFormat = new Intl.DateTimeFormat(locale,{hour:'numeric',minute:'numeric',second:'numeric',timeZone:'Asia/Seoul'});
    solverTimeFormatLocale = locale;
  }
  return solverTimeFormat.format(new Date(milliseconds));
}

function solverEventTime(event) {
  const timestamp = Number(event?.occurred_at || event?.created_at);
  if (!Number.isFinite(timestamp) || timestamp <= 0) return '';
  return clockText(timestamp * 1000);
}

function solverEventDetail(event) {
  const parts = [];
  const toolLabels = {shell:'shell',web_search:'web',file:'file',analysis:'analysis',agent:'하위 에이전트'};
  if (event.kind === 'agent') {
    if (typeof event.label === 'string' && event.label) parts.push(event.label.slice(0,120));
    if (typeof event.model === 'string' && event.model) parts.push(event.model.slice(0,120));
  }
  if (event.kind === 'activity' && event.tool) parts.push(toolLabels[event.tool] ? i18n.t(toolLabels[event.tool]) : event.tool);
  if (event.kind === 'activity' && solverActivityPhases[event.phase]) parts.push(i18n.t(solverActivityPhases[event.phase]));
  for (const key of ['summary','command','message','output']) {
    const value = typeof event[key] === 'string' ? event[key].replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g,'').trim() : '';
    // Summaries are worker labels. Commands, messages and output stay verbatim.
    const shown = key === 'summary' ? i18n.t(value) : value;
    if (shown && !parts.includes(shown)) parts.push(shown.slice(0,4096));
  }
  if (event.kind === 'activity' && Number.isInteger(event.exit_code)) parts.push(`exit ${event.exit_code}`);
  if (event.kind === 'activity' && Number.isInteger(event.duration_ms) && event.duration_ms >= 0) {
    parts.push(event.duration_ms >= 1000 ? `${(event.duration_ms / 1000).toFixed(1)}s` : `${event.duration_ms}ms`);
  }
  if (event.kind === 'guidance' && solverGuidanceStates[event.state]) parts.push(i18n.t(solverGuidanceStates[event.state]));
  if (event.kind === 'guidance' && event.provider_delivery) parts.push(i18n.t({same_turn:'현재 턴',next_turn:'다음 턴'}[event.provider_delivery] || event.provider_delivery));
  if (event.kind === 'guidance' && event.error_code) parts.push(solverGuidanceErrorLabel(event.error_code));
  return parts.join(' · ');
}

function solverGuidanceErrorLabel(code) {
  return i18n.t(solverGuidanceErrors[code] || '전달 실패');
}

function solverEventMarkup(events, job = null) {
  if (!events.length) return '<p class="solver-log-empty">아직 기록이 없습니다.</p>';
  const agentLabels = new Map((Array.isArray(job?.agents) ? job.agents : [])
    .filter(agent => agent && typeof agent.id === 'string' && agent.id !== 'root')
    .map(agent => [agent.id,String(agent.label || agent.id)]));
  return `<ol class="solver-events" aria-label="풀이 진행 기록">${events.map((event,index) => {
    const code = event.progress?.code || event.progress_code || event.code;
    const label = solverEventLabel(event);
    const detailText = solverEventDetail(event);
    const percent = Number(event.progress?.percent ?? event.percent);
    const percentSuffix = Number.isFinite(percent) ? ` · ${Math.max(0,Math.min(100,percent))}%` : '';
    const escalationSuffix = code === 'reasoning_escalated'
      ? ` · ${esc(event.from_effort || '')} → max · MAX_REQUIRED + ${tr('작업 근거 확인')}`
      : '';
    const agentLabel = event.kind === 'agent' ? null : agentLabels.get(event.agent_id);
    return `<li class="solver-event solver-event-${esc(event.kind || 'status')}" data-event-sequence="${solverEventSequence(event) || index + 1}" data-event-locale="${esc(i18n.locale)}"><span><strong>${agentLabel ? `<span class="solver-event-agent" data-i18n-ignore>${esc(agentLabel)}</span>` : ''}${esc(label)}${percentSuffix}${escalationSuffix}</strong>${detailText ? `<code>${esc(detailText)}</code>` : ''}</span><small>${esc(solverEventTime(event))}</small></li>`;
  }).join('')}</ol>`;
}

function reconcileCompactSolverLog(log, events, active) {
  const count = log?.querySelector('summary b');
  if (count) count.textContent = String(events.length);
  const state = log?.querySelector('.solver-live-state');
  if (state) {
    state.textContent = active ? 'LIVE' : 'END';
    state.classList.toggle('live',active);
  }
  const console = log?.querySelector('.solver-live-console');
  if (!console) return;
  if (!events.length) {
    if (!console.querySelector('.solver-log-empty')) console.innerHTML = solverEventMarkup(events);
    return;
  }
  let list = console.querySelector(':scope > .solver-events');
  if (!list) {
    console.innerHTML = solverEventMarkup(events);
    return;
  }
  const existing = new Map([...list.children].filter(item => item.dataset?.eventSequence)
    .map(item => [item.dataset.eventSequence,item]));
  const keep = new Set(events.map((event,index) => String(solverEventSequence(event) || index + 1)));
  // Remove first: a stale head would otherwise make every kept row move.
  for (const [key,item] of existing) if (!keep.has(key)) item.remove();
  for (const [index,event] of events.entries()) {
    const key = String(solverEventSequence(event) || index + 1);
    let item = existing.get(key);
    // A row is kept across polls, so one painted in the previous language is rebuilt in place.
    if (item?.dataset.eventLocale !== i18n.locale) {
      const template = document.createElement('template');
      template.innerHTML = solverEventMarkup([event]);
      const fresh = template.content.querySelector('li');
      fresh.dataset.eventSequence = key;
      item?.replaceWith(fresh);
      item = fresh;
    }
    if (list.children[index] !== item) list.insertBefore(item,list.children[index] || null);
  }
}

// Routine markers name the job's current step. The fullscreen log shows only the
// newest one as a live line; a finished-looking card for each would misread as done.
const solverRoutineProgress = new Set(['preparing','analyzing','waiting_for_model','inspecting_files','researching','executing','validating_flag','drafting_writeup']);

function solverEventCode(event) {
  return event?.progress?.code || event?.progress_code || event?.code;
}

function solverConsoleHiddenEvent(event) {
  return event.kind === 'context_usage'
    || (event.kind === 'progress' && solverRoutineProgress.has(solverEventCode(event)));
}

function solverConsoleActivityId(event) {
  return typeof event.activity_id === 'string' && /^[0-9a-f]{32}$/.test(event.activity_id) ? event.activity_id : '';
}

// Reasoning starts have no completion event and no text.
function solverConsoleBareAnalysis(entry) {
  const first = entry.events[0];
  return first.kind === 'activity' && first.tool === 'analysis' && first.phase === 'started' && !solverConsoleActivityId(first);
}

function solverConsoleEntries(events) {
  const entries = [], paired = new Map(), newest = new Map();
  for (const [index,event] of events.entries()) {
    if (!event || typeof event !== 'object' || solverConsoleHiddenEvent(event)) continue;
    const activityId = solverConsoleActivityId(event);
    const agentId = typeof event.agent_id === 'string' ? event.agent_id : 'root';
    // Codex reports a child's lifecycle as one-shot activities with no completion
    // partner. They describe the child, so they fold into its card.
    const lifecycle = event.kind === 'activity' && event.tool === 'agent' && !activityId;
    const groupKey = event.kind === 'activity' && activityId
      ? `activity:${agentId}:${activityId}`
      : (event.kind === 'agent' || lifecycle) && agentId !== 'root' ? `agent:${agentId}` : '';
    let entry = groupKey ? paired.get(groupKey) : null;
    if (entry) entry.events.push(event);
    else {
      entry = {key:groupKey || `event:${solverEventSequence(event) || index + 1}`,events:[event]};
      entries.push(entry);
      if (groupKey) paired.set(groupKey,entry);
    }
    newest.set(agentId,entry);
  }
  // A reasoning start means something only while it is that agent's newest step.
  return entries.filter(entry => !solverConsoleBareAnalysis(entry) || (solverIsActive(currentSolverJob)
    && newest.get(typeof entry.events[0].agent_id === 'string' ? entry.events[0].agent_id : 'root') === entry));
}

function solverConsoleText(value) {
  return typeof value === 'string'
    ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g,'').trim()
    : '';
}

function solverConsoleField(label, value, truncated = false) {
  const content = solverConsoleText(value);
  if (!content) return '';
  return `<div class="solver-console-field"><div class="solver-console-field-head"><strong>${tr(label)}</strong>${truncated ? `<small>${tr('일부만 표시')}</small>` : ''}</div><pre>${esc(content)}</pre></div>`;
}

function solverConsoleAgentStatus(events) {
  let status = '';
  for (const event of events) {
    if (event.kind === 'agent' && event.status) status = event.status;
    else if (event.summary === 'Subagent completed') status = 'completed';
    else if (event.summary === 'Subagent interrupted') status = 'interrupted';
  }
  return status;
}

function solverConsoleEntryState(entry) {
  const events = entry.events, first = events[0], latest = events[events.length - 1];
  const live = solverIsActive(currentSolverJob);
  if (entry.key.startsWith('agent:')) {
    // A child's own view has no agent events, so the job's record decides there.
    const reported = (Array.isArray(currentSolverJob?.agents) ? currentSolverJob.agents : []).find(agent => agent?.id === first.agent_id)?.status;
    const status = solverConsoleAgentStatus(events) || reported;
    if (status === 'failed') return 'failed';
    if (status === 'completed') return 'done';
    return !live || ['interrupted','cancelled','stopped'].includes(status) ? 'stopped' : 'running';
  }
  if (first.kind === 'activity') {
    if (events.some(event => event.phase === 'attachment_sync_failed'
      || (Number.isInteger(event.exit_code) && event.exit_code !== 0))) return 'failed';
    if (events.some(event => event.phase === 'completed')) return 'done';
    if (first.phase !== 'started' || (!solverConsoleActivityId(first) && !solverConsoleBareAnalysis(entry))) return 'info';
    return live ? 'running' : 'stopped';
  }
  const phase = latest.phase || latest.status;
  if (latest.kind === 'error' || (latest.kind === 'guidance' && latest.state === 'rejected')
    || (latest.kind === 'status' && ['failed','refused'].includes(phase))) return 'failed';
  if (latest.kind === 'cancelled' || (latest.kind === 'status' && ['cancelled','interrupted'].includes(phase))) return 'stopped';
  if (['flag','writeup'].includes(latest.kind) || (latest.kind === 'guidance' && latest.state === 'delivered')) return 'done';
  return 'info';
}

function solverConsoleEntryRevision(entry, agentLabels) {
  const first = entry.events[0];
  return `${i18n.locale}:${entry.events.map(event => solverEventSequence(event)).join(',')}:${entry.events.map(event => event.phase || event.status || '').join(',')}:${agentLabels.get(first.agent_id) || ''}:${solverConsoleEntryState(entry)}`;
}

// Worker summaries are fixed literals. A title follows the card's state, so a
// finished card never keeps a "started" title.
const solverActivityTitles = {
  shell:['명령 실행 중','명령 실행'],web_search:['웹 검색 중','웹 검색'],file:['파일 작업 중','파일 작업'],
  file_change:['파일 변경 중','파일 변경'],file_read:['파일 확인 중','파일 확인'],tool:['도구 실행 중','도구 실행'],
  analysis:['분석 중','분석'],agent:['하위 에이전트 위임 중','하위 에이전트 위임'],
};
const solverActivitySummaries = new Set(['명령 실행','웹 검색','파일 변경','파일 검사','분석 중','Subagent tool','Subagent dispatch started','Subagent started']);

function solverConsoleActivityTitle(first, state) {
  const summary = solverConsoleText(first.summary);
  const family = summary === '파일 변경' ? 'file_change' : summary === '파일 검사' ? 'file_read' : first.tool;
  const titles = solverActivitySummaries.has(summary) ? solverActivityTitles[family] : null;
  return titles ? titles[state === 'running' ? 0 : 1] : summary || solverEventLabel(first);
}

function solverConsoleDuration(events) {
  let duration = events.findLast?.(event => Number.isInteger(event.duration_ms) && event.duration_ms >= 0)?.duration_ms;
  if (duration === undefined && events.length > 1) {
    const elapsed = Number(events[events.length - 1].created_at) - Number(events[0].created_at);
    if (Number.isFinite(elapsed) && elapsed > 0) duration = Math.round(elapsed * 1000);
  }
  return Number.isInteger(duration) ? duration >= 1000 ? `${(duration / 1000).toFixed(1)}s` : `${duration}ms` : '';
}

function solverConsoleFirstLine(value) {
  return (solverConsoleText(value).split('\n').find(line => line.trim()) || '').trim().slice(0,240);
}

function solverConsoleEntryMarkup(entry, agentLabels) {
  const events = entry.events;
  const first = events[0], latest = events[events.length - 1];
  const agent = entry.key.startsWith('agent:');
  const activity = !agent && first.kind === 'activity';
  const state = solverConsoleEntryState(entry);
  const running = state === 'running', failed = state === 'failed', stopped = state === 'stopped';
  const delegation = agent || (activity && first.tool === 'agent');
  const agentLabel = agentLabels.get(first.agent_id) || '';
  const agentName = agent ? agentLabel || events.findLast?.(event => event.kind === 'agent' && event.label)?.label || i18n.t('하위 에이전트') : '';
  const title = agent ? agentName : activity ? solverConsoleActivityTitle(first,state) : solverEventLabel(latest);
  const toolLabel = activity ? ({shell:'명령',web_search:'검색',file:'파일',analysis:'분석',tool:'도구',agent:'하위 에이전트'}[first.tool] || first.tool || '도구')
    : agent ? '하위 에이전트' : '진행';
  const stateLabel = failed ? '실패' : running ? '진행 중' : !activity && !agent ? ''
    : stopped ? agent ? '중단' : '결과 없음' : state === 'done' ? '완료' : '';
  const durationText = activity ? solverConsoleDuration(events) : '';
  const exitCode = events.findLast?.(event => Number.isInteger(event.exit_code))?.exit_code;
  // Time and exit code first: on a narrow card they outrank the agent's name.
  const meta = [durationText,Number.isInteger(exitCode) ? `exit ${exitCode}` : '',agentLabel && !agent ? agentLabel : ''].filter(Boolean);
  const command = events.find(event => solverConsoleText(event.command));
  const output = [...events].reverse().find(event => solverConsoleText(event.output));
  const messages = events.filter(event => event.phase === 'completed' || delegation)
    .map(event => solverConsoleText(event.message)).filter(Boolean);
  const distinctMessages = [...new Set(messages)];
  const detail = !activity && !agent && ['error','flag','writeup','guidance'].includes(latest.kind)
    ? solverConsoleText(latest.error?.message || solverEventDetail(latest)) : '';
  // A completed model response carries only text. Show it in the timeline
  // instead of hiding it behind a disclosure that has nothing else to reveal.
  const reply = activity && first.tool === 'analysis' && !command && !output && distinctMessages.length > 0;
  const previewSource = command?.command || (delegation ? distinctMessages[0] : '') || (latest.kind === 'error' ? detail : '');
  const previewLine = reply ? '' : solverConsoleFirstLine(previewSource);
  // A short command or task is fully readable on the card and needs no disclosure.
  const previewComplete = solverConsoleText(previewSource) === previewLine && previewLine.length <= 120;
  // A child named after its task would only repeat the title.
  const preview = agent && previewLine.startsWith(title) ? '' : previewLine;
  const expandable = !reply && (agent || activity
    ? Boolean(output || (delegation ? distinctMessages.length && !previewComplete : distinctMessages.length)
      || (command && !running && !previewComplete))
    : Boolean(detail && !previewComplete));
  const body = agent || activity
    ? `${solverConsoleField(first.tool === 'web_search' ? '검색어' : '명령',command?.command,events.some(event => event.command_truncated))}
       ${solverConsoleField('결과',output?.output,events.some(event => event.output_truncated))}
       ${distinctMessages.map(message => solverConsoleField(delegation ? '위임 내용' : '내용',message)).join('')}`
    : solverConsoleField('내용',detail);
  const classes = `solver-console-card${running ? ' running' : ''}${failed ? ' failed' : ''}${stopped ? ' stopped' : ''}${state === 'info' ? ' info' : ''}${expandable ? '' : ' static'}${reply ? ' message' : ''}`;
  const attributes = `class="${classes}" data-log-key="${esc(entry.key)}" data-log-revision="${esc(solverConsoleEntryRevision(entry,agentLabels))}"`;
  const icon = reply ? '›' : {running:'◌',failed:'×',stopped:'■',info:'·'}[state] || '✓';
  const heading = `<span class="solver-console-card-icon" aria-hidden="true">${icon}</span><span class="solver-console-card-title"><strong${agent ? ' data-i18n-ignore' : ''}>${agent ? esc(title) : tr(title)}</strong><small data-i18n-ignore>${esc([i18n.t(toolLabel),...meta].join(' · '))}</small>${preview ? `<code class="solver-console-card-preview" title="${esc(preview)}">${esc(preview)}</code>` : ''}</span><span class="solver-console-card-state">${reply ? '' : tr(stateLabel)}</span><time>${esc(solverEventTime(latest))}</time>`;
  if (reply) return `<div ${attributes}><div class="solver-console-card-summary">${heading}</div><div class="solver-console-reply" data-i18n-ignore>${distinctMessages.map(message => `<p>${esc(message)}</p>`).join('')}</div></div>`;
  if (!expandable) return `<div ${attributes}><div class="solver-console-card-summary">${heading}</div></div>`;
  return `<details ${attributes}${solverConsoleCardStates.get(entry.key) === true ? ' open' : ''}>
    <summary>${heading}</summary><div class="solver-console-card-body">${body}</div>
  </details>`;
}

function solverConsoleTimelineMarkup(events, job = null) {
  if (!events.length) return `<p class="solver-log-empty">${tr('아직 기록이 없습니다.')}</p>`;
  const agentLabels = solverAgentDisplayNames(job,currentSolverEvents);
  return `<div class="solver-console-timeline">${solverConsoleEntries(events).map(entry => solverConsoleEntryMarkup(entry,agentLabels)).join('')}</div>`;
}

function reconcileSolverConsoleTimeline(stream, events, job = null) {
  const entries = solverConsoleEntries(events);
  if (!entries.length) {
    if (!stream.querySelector('.solver-log-empty')) stream.innerHTML = `<p class="solver-log-empty">${tr('아직 기록이 없습니다.')}</p>`;
    return;
  }
  stream.querySelector('.solver-log-empty')?.remove();
  let timeline = stream.querySelector(':scope > .solver-console-timeline');
  if (!timeline) {
    timeline = document.createElement('div');
    timeline.className = 'solver-console-timeline';
    stream.replaceChildren(timeline);
  }
  const agentLabels = solverAgentDisplayNames(job,currentSolverEvents);
  const existing = new Map([...timeline.children].filter(card => card.dataset?.logKey)
    .map(card => [card.dataset.logKey,card]));
  const keep = new Set(entries.map(entry => entry.key));
  // Remove first: a stale head would otherwise make every kept card move and blur.
  for (const [key,card] of existing) if (!keep.has(key)) card.remove();
  for (const [index, entry] of entries.entries()) {
    const revision = solverConsoleEntryRevision(entry,agentLabels);
    let card = existing.get(entry.key);
    if (!card || card.dataset.logRevision !== revision) {
      const template = document.createElement('template');
      template.innerHTML = solverConsoleEntryMarkup(entry,agentLabels);
      const replacement = template.content.firstElementChild;
      replacement.dataset.logRevision = revision;
      if (card) {
        const focused = card.contains(document.activeElement);
        if (card.matches('details')) solverConsoleCardStates.set(entry.key,card.open);
        if (replacement.matches('details')) replacement.open = solverConsoleCardStates.get(entry.key) === true;
        card.replaceWith(replacement);
        if (focused) replacement.querySelector('summary')?.focus({preventScroll:true});
      }
      card = replacement;
    }
    if (timeline.children[index] !== card) timeline.insertBefore(card,timeline.children[index] || null);
  }
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

const solverAgentPromptNames = new Map();

function solverAgentPromptName(job, agentId, events) {
  const key = `${solverJobId(job)}:${agentId}`;
  if (!solverAgentPromptNames.has(key)) {
    const assigned = events.find(event => event.agent_id === agentId && event.tool === 'agent' && solverConsoleText(event.message));
    if (!assigned) return '';
    solverAgentPromptNames.set(key,solverConsoleFirstLine(assigned.message).slice(0,48));
  }
  return solverAgentPromptNames.get(key);
}

// Display names without the root node. Identical labels are told apart by the
// child's task, or by an ordinal when the task is not known.
function solverAgentDisplayNames(job, events = []) {
  const agents = (Array.isArray(job?.agents) ? job.agents : [])
    .filter(agent => agent && typeof agent.id === 'string' && agent.id !== 'root');
  const names = new Map(), counts = new Map();
  for (const agent of agents) {
    const label = String(agent.label || agent.id);
    names.set(agent.id,label);
    counts.set(label,(counts.get(label) || 0) + 1);
  }
  const ordinals = new Map(), seen = new Set();
  for (const agent of agents) {
    const label = String(agent.label || agent.id);
    if (counts.get(label) < 2) continue;
    const ordinal = (ordinals.get(label) || 0) + 1;
    ordinals.set(label,ordinal);
    let name = solverAgentPromptName(job,agent.id,events) || `${label} #${ordinal}`;
    if (seen.has(name)) name = `${name} #${ordinal}`;
    seen.add(name);
    names.set(agent.id,name);
  }
  return names;
}

function solverConsoleEvents(job, events) {
  if (solverConsoleAgentId === 'root') return events;
  if (!solverAgentNodes(job).some(agent => agent.id === solverConsoleAgentId)) {
    solverConsoleAgentId = 'root';
    return events;
  }
  return events.filter(event => event.kind === 'activity' && event.agent_id === solverConsoleAgentId);
}

function solverContextUsageMarkup(job, agentId = solverConsoleAgentId) {
  const usage = (Array.isArray(job?.context_usage) ? job.context_usage : [])
    .find(item => item && item.agent_id === agentId);
  const compacting = usage?.state === 'compacting' || usage?.state === 'compaction';
  const hasPercent = typeof usage?.percent === 'number' && Number.isFinite(usage.percent)
    && usage.percent >= 0 && usage.percent <= 100;
  const label = compacting ? i18n.t('압축 중') : hasPercent ? `${Math.round(usage.percent)}%` : i18n.t('알 수 없음');
  const agent = agentId === 'root' ? i18n.t('메인 에이전트') : solverAgentDisplayNames(job,currentSolverEvents).get(agentId) || agentId;
  const title = `${agent} · ${i18n.t('컨텍스트 사용량')}: ${label}`;
  return `<span class="solver-console-context${compacting ? ' compacting' : hasPercent ? ' measured' : ' unknown'}" title="${esc(title)}" aria-label="${esc(title)}">${tr('컨텍스트')} ${esc(label)}</span>`;
}

function solverAgentTreeMarkup(job, events) {
  const agents = solverAgentNodes(job);
  if (agents.length < 2) return '';
  const ids = new Set(agents.map(agent => agent.id));
  if (!ids.has(solverConsoleAgentId)) solverConsoleAgentId = 'root';
  const children = new Map(), counts = new Map(), names = solverAgentDisplayNames(job,events), live = solverIsActive(job);
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
    const reported = typeof agent.status === 'string' ? agent.status : '';
    const status = !live && ['queued','running'].includes(reported) ? 'stopped' : reported;
    const name = agent.id === 'root' ? i18n.t('전체 세션') : names.get(agent.id) || agent.label || agent.id;
    const safeStatus = ['queued','running','completed','failed','cancelled','stopped','interrupted'].includes(status) ? status : '';
    const statusLabel = i18n.t({queued:'대기',running:'작업 중',completed:'완료',failed:'실패',cancelled:'취소됨',stopped:'중단',interrupted:'중단'}[status] || '');
    const meta = [agent.provider,agent.model,statusLabel].filter(Boolean).map(esc).join(' · ');
    const count = agent.id === 'root' ? events.length : counts.get(agent.id) || 0;
    return `<li class="solver-agent-node" data-agent-node="${esc(agent.id)}"><div class="solver-agent-row">${expandable
      ? `<button type="button" class="solver-agent-expand" data-action="toggle-solver-agent-branch" data-agent-id="${esc(agent.id)}" aria-label="${esc(name)} ${tr(collapsed ? '펼치기' : '접기')}" aria-expanded="${!collapsed}">${collapsed ? '▸' : '▾'}</button>`
      : '<span class="solver-agent-expand-spacer" aria-hidden="true"></span>'}
      <button type="button" class="solver-agent-select${solverConsoleAgentId === agent.id ? ' selected' : ''}" data-action="select-solver-agent" data-agent-id="${esc(agent.id)}" aria-pressed="${solverConsoleAgentId === agent.id}"><span class="solver-agent-name"${agent.id === 'root' ? '' : ' data-i18n-ignore'}>${esc(name)}</span><span class="solver-agent-count">${count}</span>${safeStatus ? `<span class="solver-agent-status ${safeStatus}" title="${esc(statusLabel)}"></span>` : ''}${meta ? `<small data-i18n-ignore>${meta}</small>` : ''}</button></div>${expandable ? `<ul class="solver-agent-children${collapsed ? ' hidden' : ''}">${descendants.map(branch).join('')}</ul>` : ''}</li>`;
  }
  let content = branch(agents[0]);
  for (const agent of agents.slice(1)) if (!visited.has(agent.id)) content += branch(agent);
  return `<h3>${tr('에이전트')}</h3><ul class="solver-agent-list">${content}</ul>`;
}

// Patching in place keeps buttons, forms and open disclosures alive across polls:
// a replaced node loses keyboard focus and swallows a click spanning the poll.
function solverMorphKey(node) {
  return [node.tagName,node.id,node.getAttribute('class')?.split(' ')[0] || '',node.getAttribute('data-job-id') || '',node.getAttribute('data-agent-node') || '',node.getAttribute('data-challenge-id') || '',node.getAttribute('data-action') || ''].join('|');
}

function solverMorphNode(current, next) {
  if (current.matches('.solver-configuration,.solver-session-log,[data-morph-keep]')) return;
  for (const {name} of [...current.attributes]) if (name !== 'open' && !next.hasAttribute(name)) current.removeAttribute(name);
  for (const {name,value} of [...next.attributes]) if (name !== 'open' && current.getAttribute(name) !== value) current.setAttribute(name,value);
  if (!current.matches('textarea')) solverMorphChildren(current,next);
}

function solverMorphChildren(parent, next) {
  const available = [...parent.children], nodes = [...next.childNodes], matches = new Map();
  for (const node of nodes) {
    if (node.nodeType !== 1) continue;
    const key = solverMorphKey(node), index = available.findIndex(item => solverMorphKey(item) === key);
    if (index >= 0) matches.set(node,available.splice(index,1)[0]);
  }
  // Remove first: a stale element would otherwise make every kept element move.
  for (const stale of available) if (!stale.matches('.toasts')) stale.remove();
  let cursor = parent.firstChild;
  for (const node of nodes) {
    if (node.nodeType !== 1) {
      // Text has no state, so it adapts to the elements and never displaces one.
      if (cursor?.nodeType === node.nodeType) {
        if (cursor.nodeValue !== node.nodeValue) cursor.nodeValue = node.nodeValue;
        cursor = cursor.nextSibling;
      } else parent.insertBefore(node,cursor);
      continue;
    }
    const current = matches.get(node);
    if (!current) { parent.insertBefore(node,cursor); continue; }
    solverMorphNode(current,node);
    while (cursor && cursor !== current && cursor.nodeType !== 1) {
      const text = cursor;
      cursor = cursor.nextSibling;
      text.remove();
    }
    if (cursor === current) cursor = cursor.nextSibling;
    else if (current.contains(document.activeElement)) {
      // Moving a node drops its focus and any IME composition, so the others step over it.
      const after = current.nextSibling;
      while (cursor && cursor !== current) {
        const passed = cursor;
        cursor = cursor.nextSibling;
        parent.insertBefore(passed,after);
      }
      cursor = current.nextSibling;
    } else parent.insertBefore(current,cursor);
  }
  while (cursor) {
    const leftover = cursor;
    cursor = cursor.nextSibling;
    if (!leftover.matches?.('.toasts')) leftover.remove();
  }
}

function morphMarkup(root, markup) {
  const template = document.createElement('template');
  template.innerHTML = markup;
  solverMorphChildren(root,template.content);
}

function solverGuidanceHistoryMarkup() {
  const recent = currentSolverGuidance.slice(-3);
  return recent.length ? `<ol class="solver-guidance-history">${recent.map(item => `<li><span data-i18n-ignore>${esc(item.message || '')}</span><small>${esc([i18n.t(solverGuidanceStates[item.status] || ''),item.error_code ? solverGuidanceErrorLabel(item.error_code) : ''].filter(Boolean).join(' · '))}</small></li>`).join('')}</ol>` : '';
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

function solverPeerEvidenceButton(job, active) {
  if (!active || !solverJobId(job) || job?.guidance_allowed === false) return '';
  return `<button type="button" class="small ghost solver-peer-evidence-button" data-action="open-solver-peer-evidence">${tr('공동 풀이 자료')}</button>`;
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
    solverConsoleDialog.addEventListener('toggle', event => {
      const card = event.target;
      if (card?.matches?.('details.solver-console-card') && card.dataset.logKey) {
        solverConsoleCardStates.set(card.dataset.logKey,card.open);
        // Expanding grows the stream without a scroll event, and the reader is
        // on that card now: the next poll must not pull them back down.
        const stream = solverConsoleDialog.querySelector('.solver-console-stream');
        if (card.open && stream && !solverConsoleAtBottom(stream)) {
          solverConsoleFollowLatest = false;
          paintSolverConsoleBottomButton();
        }
      }
    }, true);
  }
  const agentTree = solverAgentTreeMarkup(currentSolverJob,currentSolverEvents);
  solverConsoleDialog.innerHTML = solverConsoleMarkup(agentTree,solverConsoleTimelineMarkup(solverConsoleEvents(currentSolverJob,currentSolverEvents),solverConsoleAgentId === 'root' ? currentSolverJob : null));
  solverConsolePaintKey = '';
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
    paintSolverConsoleCurrentStep(stream);
    stream.scrollTop = stream.scrollHeight;
  }
  paintSolverConsoleControls();
  if (currentWorkspace?.id && currentChallenge?.id) paintUploads([],currentWorkspace.id,currentChallenge.id);
}

// The tree, stream and upload mirror have their own painters, so a language repaint keeps them.
// The page, the detail and the solver console each carry this notice: a dialog sits in the top layer and hides what is under it.
function liveNoticeBody() {
  const workspace = currentWorkspace;
  if (workspace?.gone) return tr('작업공간을 찾을 수 없습니다. 노트를 저장할 수 없으니 닫기 전에 복사하세요.');
  if (!workspace?.listStaleAt) return '';
  return `<strong>${tr('실시간 갱신이 멈췄습니다.')}</strong> ${esc(i18n.format('마지막 갱신 {time} KST. 서버가 응답하면 자동으로 이어집니다.',{time:clockText(workspace.listUpdatedAt || workspace.listStaleAt)}))}`;
}

function liveNoticeMarkup() {
  return `<div class="live-notice notice error-notice" role="status">${liveNoticeBody()}</div>`;
}

function paintLiveNotices() {
  for (const notice of document.querySelectorAll('.live-notice')) notice.innerHTML = liveNoticeBody();
  updateSolverElapsedLabels();
}

function solverConsoleMarkup(agentTree, timeline) {
  const provider = currentSolverJob.provider || currentSolverJob.configuration?.provider;
  const active = solverIsActive(currentSolverJob) && currentSolverJob.guidance_allowed !== false;
  return `<header class="solver-console-head"><div><strong data-i18n-ignore>${esc(currentChallenge?.name || i18n.t('세션 로그'))}</strong><small data-i18n-ignore>${esc(solverConsoleSubtitle(currentSolverJob))}</small>${solverContextUsageMarkup(currentSolverJob)}</div><div class="solver-console-head-actions"><button type="button" class="small ghost solver-console-bottom hidden" data-action="solver-console-bottom" aria-label="${tr('맨 아래로 이동')}">${tr('↓ 맨 아래')}</button><button type="button" class="small ghost" data-action="close-solver-console" aria-label="${tr('세션 로그 닫기')}">${tr('닫기')}</button></div></header>
    ${liveNoticeMarkup()}
    <div class="solver-console-body"><aside class="solver-agent-tree${agentTree ? '' : ' hidden'}" aria-label="에이전트 활동" data-morph-keep>${agentTree}</aside><div class="solver-console-stream" role="log" aria-live="polite" data-morph-keep>${timeline}</div></div>
    <div class="solver-console-controls"><form id="solver-console-guidance-form" class="solver-console-guidance${active ? '' : ' hidden'}" data-job-id="${esc(solverJobId(currentSolverJob))}">
      <label for="solver-console-message">${tr('메인 세션 추가 명령')}</label><textarea id="solver-console-message" name="message" maxlength="16384" rows="3" placeholder="${tr('풀이 방향이나 확인할 내용을 입력')}" required>${esc(solverGuidanceDraft)}</textarea>
      <div class="solver-console-send"><select name="requested_delivery" aria-label="${tr('명령 전달 방식')}" ${provider === 'claude' ? 'disabled' : ''}><option value="same_turn">${tr('현재 턴에 개입')}</option><option value="next_turn" ${provider === 'claude' ? 'selected' : ''}>${tr('다음 턴에 전달')}</option></select><button type="submit" class="primary">${tr('전송')}</button></div>
    </form><div class="solver-console-upload-row"><label class="solver-console-upload">${tr('문제 파일 추가')}<input id="solver-console-files" type="file" multiple></label><small></small></div><div class="solver-console-uploads file-list" data-morph-keep></div></div>`;
}

function solverConsoleSubtitle(job) {
  return `${solverJobId(job)}${job?.read_only_history ? ` · ${i18n.t('가져온 기록 · 읽기 전용')}` : ''}`;
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

let solverConsolePaintKey = '';

function solverConsoleCurrentStep(job) {
  if (!solverIsActive(job) || solverConsoleAgentId !== 'root') return '';
  if (job.cancel_requested) return '중단 요청 중';
  const code = solverEventCode(currentSolverEvents.findLast?.(event => event.kind === 'progress' && solverRoutineProgress.has(solverEventCode(event))));
  return solverProgress[code] || solverPhases[job.phase] || '';
}

function paintSolverConsoleCurrentStep(stream) {
  let line = stream.querySelector(':scope > .solver-console-current');
  const text = solverConsoleCurrentStep(currentSolverJob);
  if (!text) { line?.remove(); return; }
  if (!line) {
    line = document.createElement('p');
    line.className = 'solver-console-current';
    line.setAttribute('aria-busy','true');
    line.innerHTML = '<span class="solver-console-card-icon" aria-hidden="true">◌</span><span></span>';
  }
  if (stream.lastElementChild !== line) stream.append(line);
  const label = i18n.t(text), target = line.lastElementChild;
  if (target.textContent !== label) target.textContent = label;
}

function paintSolverConsoleControls() {
  const job = currentSolverJob, active = solverIsActive(job);
  const form = solverConsoleDialog?.querySelector('#solver-console-guidance-form');
  if (form) {
    form.classList.toggle('hidden', !active || job?.guidance_allowed === false);
    form.dataset.jobId = solverJobId(job);
    const delivery = form.querySelector('select[name="requested_delivery"]');
    if (delivery) {
      delivery.disabled = (job?.provider || job?.configuration?.provider || job?.model?.provider) === 'claude';
      if (delivery.disabled) delivery.value = 'next_turn';
    }
  }
  const row = solverConsoleDialog?.querySelector('.solver-console-upload-row');
  if (row) {
    // The server refuses new attachments while a run is open; imported history is read-only.
    row.classList.toggle('hidden',job?.read_only_history === true);
    row.querySelector('.solver-console-upload')?.classList.toggle('hidden',active);
    const hint = row.querySelector('small');
    const text = i18n.t(active ? '첨부는 풀이가 끝난 뒤 추가할 수 있습니다.' : '추가한 파일은 다음 실행부터 attachments/에 포함됩니다.');
    if (hint && hint.textContent !== text) hint.textContent = text;
  }
}

function solverReadingAnchors(container, selector, keyOf) {
  const items = container.querySelectorAll(selector);
  const top = container.getBoundingClientRect().top;
  let low = 0, high = items.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (items[middle].getBoundingClientRect().bottom > top) high = middle;
    else low = middle + 1;
  }
  return Array.prototype.slice.call(items,low,low + 12)
    .map(item => ({key:keyOf(item),offset:item.getBoundingClientRect().top - top}));
}

// Restores the first surviving anchor. If they were all evicted, the top of the
// list is the nearest content that is left.
function restoreSolverReadingAnchors(container, selector, attribute, anchors) {
  const top = container.getBoundingClientRect().top;
  for (const anchor of anchors) {
    const item = container.querySelector(`${selector}[${attribute}="${CSS.escape(anchor.key)}"]`);
    if (!item) continue;
    container.scrollTop += item.getBoundingClientRect().top - top - anchor.offset;
    return;
  }
  if (anchors.length) container.scrollTop = 0;
}

function paintSolverConsole() {
  if (!solverConsoleDialog?.open) return;
  const heading = solverConsoleDialog.querySelector('.solver-console-head > div:first-child');
  if (heading) {
    const title = heading.querySelector('strong'), id = heading.querySelector('small');
    if (title) title.textContent = currentChallenge?.name || i18n.t('세션 로그');
    if (id) id.textContent = solverConsoleSubtitle(currentSolverJob);
    const badge = heading.querySelector('.solver-console-context');
    if (badge) badge.outerHTML = solverContextUsageMarkup(currentSolverJob);
  }
  paintSolverConsoleControls();
  const stream = solverConsoleDialog.querySelector('.solver-console-stream');
  if (!stream) return;
  const lastEvent = currentSolverEvents[currentSolverEvents.length - 1];
  // An idle poll must not touch the DOM: everything below depends only on these.
  const paintKey = [solverJobId(currentSolverJob),solverConsoleAgentId,[...solverCollapsedAgentIds].join(),currentSolverEvents.length,lastEvent ? solverEventSequence(lastEvent) : 0,solverIsActive(currentSolverJob),JSON.stringify(currentSolverJob?.agents ?? null)].join('|');
  if (paintKey === solverConsolePaintKey) { paintSolverConsoleCurrentStep(stream); return; }
  solverConsolePaintKey = paintKey;
  const tree = solverConsoleDialog.querySelector('.solver-agent-tree');
  if (tree) {
    const markup = solverAgentTreeMarkup(currentSolverJob,currentSolverEvents);
    tree.classList.toggle('hidden',!markup);
    const template = document.createElement('template');
    template.innerHTML = markup;
    solverMorphChildren(tree,template.content);
  }
  const cardSelector = '.solver-console-card[data-log-key]';
  const anchors = solverConsoleFollowLatest ? [] : solverReadingAnchors(stream,cardSelector,card => card.dataset.logKey);
  for (const card of stream.querySelectorAll('details.solver-console-card[data-log-key]')) {
    solverConsoleCardStates.set(card.dataset.logKey,card.open);
  }
  reconcileSolverConsoleTimeline(stream,solverConsoleEvents(currentSolverJob,currentSolverEvents),solverConsoleAgentId === 'root' ? currentSolverJob : null);
  paintSolverConsoleCurrentStep(stream);
  if (solverConsoleFollowLatest) stream.scrollTop = stream.scrollHeight;
  else restoreSolverReadingAnchors(stream,cardSelector,'data-log-key',anchors);
  paintSolverConsoleBottomButton();
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
    ? solverProgress[progressCode] || solverPhases[phase] || '보완 중'
    : phase === 'cancelled' ? '보완을 중단했습니다.'
      : phase === 'completed' ? '보완 완료' : '';
  const ready = eligible && solverConfigurationReady() && !active;
  return `<details class="writeup-refinement" ${active || writeupRefineError ? 'open' : ''}><summary>write-up 보완</summary>
    <label for="writeup-refine-instruction">추가 요청 <span class="optional">선택 입력</span></label>
    <textarea id="writeup-refine-instruction" rows="3" maxlength="${writeupRefinementInstructionLimit}" placeholder="${tr('예: 익스플로잇 코드 설명을 더 구체적으로 작성')}" ${active ? 'disabled' : ''}>${esc(writeupRefineInstruction)}</textarea>
    <div class="actions"><button type="button" data-action="refine-writeup" ${ready ? '' : 'disabled'}>${active ? '보완 중…' : '보완 요청'}</button>${active ? `<button type="button" class="small danger ghost icon-action" data-action="cancel-writeup-refine" aria-label="write-up 보완 중단" title="write-up 보완 중단" ${writeupRefineJob?.cancel_requested ? 'disabled' : ''}>■</button>` : ''}</div>
    ${status || !solverConfigurationReady() ? `<p id="writeup-refine-status" class="form-hint" role="status">${esc(status || '계정·모델·추론 수준을 선택하세요.')}</p>` : ''}
    ${writeupRefineError ? solverErrorMarkup(writeupRefineError,'write-up 보완 오류') : ''}
  </details>`;
}

function solverWriteupArtifact(writeup) {
  if (!writeup) return '';
  return `<div class="solver-artifact solver-writeup-artifact"><strong>write-up</strong><div class="actions"><button type="button" class="small ghost icon-action" data-action="copy-solver-writeup" aria-label="write-up 복사" title="write-up 복사">▤</button><button type="button" class="small ghost icon-action" data-action="download-solver-writeup" aria-label="write-up Markdown 다운로드" title="write-up Markdown 다운로드">⇩</button></div><details class="writeup-preview"><summary>미리보기</summary><div class="markdown-preview">${safeMarkdown(writeup)}</div></details><div id="writeup-refine-container">${writeupRefinementMarkup()}</div></div>`;
}

function solverRetryConfiguration(job) {
  const config = job?.configuration;
  if (job?.job_mode !== 'solve' || !config || !['codex','claude'].includes(config.provider)) return null;
  return {
    provider:config.provider, accountId:job.account_id || '', accountLabel:job.account_label || '',
    model:config.model || '', reasoning:config.reasoning_effort || '',
    serviceTier:config.service_tier || null, ultracode:config.ultracode === true,
    ultraEscalationMode:job.ultra_escalation?.mode || 'off',
  };
}

function solverSelectedAccount() {
  return solverAccounts.find(account => account.id === solverAccountId && account.provider === solverProvider) || null;
}

function solverSelectedModel() {
  return solverModels.find(item => solverModel && solverModel === (item.model || item.id)) || null;
}

function solverRetryWarningMarkup() {
  if (!solverRetryIssues.length) return '';
  const canConfirm = solverOptionsState === 'ready' && Boolean(solverSelectedAccount() && solverSelectedModel() && solverReasoning);
  const issues = solverRetryIssues.map(([key,values]) => i18n.format(key,values)).join(' ');
  return `<div class="notice error-notice solver-retry-warning" role="status"><p data-i18n-ignore>${esc(issues)} ${tr('아래 설정을 확인해 주세요.')}</p>${canConfirm ? '<div class="actions"><button type="button" class="small" data-action="confirm-solver-retry-settings">현재 설정으로 계속</button></div>' : ''}</div>`;
}

function clearSolverRetryWarning() {
  solverRetryIssues = [];
  solverRetryRequiresSelection = false;
}

function solverConfigurationMatchesVisibleForm() {
  const form = document.querySelector('#solver-panel > .solver-configuration');
  if (!form) return true;
  for (const [id, expected] of [
    ['solver-provider-select',solverProvider],
    ['solver-account-select',solverAccountId],
    ['solver-model-select',solverModel],
    ['solver-reasoning-select',solverReasoning],
    ['solver-ultra-escalation',solverUltraEscalationMode],
  ]) {
    const field = form.querySelector(`#${id}`);
    if (field && field.value !== expected) return false;
  }
  const fast = form.querySelector('#solver-fast-toggle');
  if (fast && fast.checked !== (solverServiceTier === 'fast')) return false;
  const ultracode = form.querySelector('#solver-ultracode-toggle');
  if (ultracode && ultracode.checked !== solverUltracode) return false;
  return true;
}

function solverConfigurationReady() {
  return solverOptionsState === 'ready'
    && !solverRetryRequiresSelection
    && Boolean(solverSelectedAccount() && solverSelectedModel() && solverReasoning)
    && solverConfigurationMatchesVisibleForm();
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
    return `<div class="solver-configuration">${provider}<p class="notice error-notice solver-config-state">${esc(solverOptionsError || '계정 설정을 불러오지 못했습니다.')}</p>${solverRetryWarningMarkup()}<a class="button-link" href="#accounts" data-action="open-solver-accounts">계정 관리</a></div>`;
  }
  if (!available.length) {
    return `<div class="solver-configuration">${provider}<p class="notice muted solver-config-state">이 공급자에 로그인된 계정이 없습니다.</p>${solverRetryWarningMarkup()}<a class="button-link" href="#accounts" data-action="open-solver-accounts">계정 연결하기</a></div>`;
  }
  const accountOptions = available.map(account => `<option value="${esc(account.id)}" data-i18n-ignore ${account.id === solverAccountId ? 'selected' : ''}>${esc(account.label)}${account.selected ? ` · ${tr('기본')}` : ''}</option>`).join('');
  const modelOptions = solverModels.map(item => { const value = item.model || item.id; return value ? `<option value="${esc(value)}" data-i18n-ignore ${value === solverModel ? 'selected' : ''}>${esc(item.displayName || value)}</option>` : ''; }).join('');
  const chosen = solverSelectedModel();
  const efforts = Array.isArray(chosen?.supportedReasoningEfforts) ? chosen.supportedReasoningEfforts.map(item => item?.reasoningEffort).filter(Boolean) : [];
  const effortOptions = efforts.map(value => `<option value="${esc(value)}" data-i18n-ignore ${value === solverReasoning ? 'selected' : ''}>${esc(value)}</option>`).join('');
  const supportsFast = solverProvider === 'codex' && Array.isArray(chosen?.serviceTiers) && chosen.serviceTiers.some(item => item?.id === 'fast');
  const supportsUltracode = solverProvider === 'claude' && chosen?.supportsUltracode === true;
  const ultraChoice = solverUltraEscalationEligible() ? `<label class="solver-ultra-escalation"><span>막히면 Ultra</span><select id="solver-ultra-escalation" aria-label="Ultra 전환 방식"><option value="ask" ${solverUltraEscalationMode === 'ask' ? 'selected' : ''}>전환 전 묻기</option><option value="auto" ${solverUltraEscalationMode === 'auto' ? 'selected' : ''}>조건 충족 시 자동</option><option value="off" ${solverUltraEscalationMode === 'off' ? 'selected' : ''}>사용 안 함</option></select></label>` : '';
  return `<div class="solver-configuration">${provider}
    <label>실행 계정<select id="solver-account-select" aria-label="문제 풀이 계정">${accountOptions}</select></label>
    <label>모델<select id="solver-model-select" aria-label="문제 풀이 모델" ${modelOptions ? '' : 'disabled'}>${modelOptions || '<option>사용 가능한 모델 없음</option>'}</select></label>
    <label>추론 수준<select id="solver-reasoning-select" aria-label="문제 풀이 추론 수준" ${effortOptions ? '' : 'disabled'}>${effortOptions || '<option>지원 정보 없음</option>'}</select></label>
    ${supportsFast ? `<label class="solver-fast-choice"><input id="solver-fast-toggle" type="checkbox" ${solverServiceTier === 'fast' ? 'checked' : ''}>1.5배 Fast 실행</label>` : supportsUltracode ? `<label class="solver-ultracode-choice"><input id="solver-ultracode-toggle" type="checkbox" ${solverUltracode ? 'checked' : ''}>Ultracode</label>` : '<span class="solver-fast-placeholder" aria-hidden="true"></span>'}
    ${ultraChoice}
    ${solverRetryWarningMarkup()}
    <span class="form-hint solver-config-help">이번 실행에만 적용</span>
  </div>`;
}

function solverContinuationMarkup(job) {
  if (!job) return '';
  const mode = job.continuation_mode;
  const retryCount = Number(job.retry_checkpoint?.rejected_count || 0);
  const checkpointReason = job.retry_checkpoint?.reason;
  const checkpointLabels = {rejected_flag:'오답',needs_remote:'원격 정보 요청',timeout:'시간 제한',cancelled:'사용자 중단',provider_failure:'모델 오류',turn_limit:'풀이 회차 종료',ultra_escalation:'Ultra 전환'};
  const legacy = job.retry_checkpoint
    ? `${i18n.t('체크포인트')} · ${i18n.t(checkpointLabels[checkpointReason] || '이전 작업')}${retryCount ? ` · ${i18n.locale === 'en' ? `${retryCount} incorrect flags` : `오답 ${retryCount}개`}` : ''}`
    : '';
  if (!['fresh','checkpoint','workspace','session'].includes(mode)) {
    return legacy ? `<p class="notice muted solver-retry-context">${esc(legacy)}</p>` : '';
  }
  if (mode === 'fresh' && !job.retry_checkpoint && !job.continuation_source_job_id) return '';
  const waiting = ['queued','staging','awaiting_credential','validating'].includes(job.phase);
  let label = '새 세션';
  if (mode === 'checkpoint') label = waiting ? '이전 분석 복원 준비 중' : '이전 분석으로 이어감';
  if (mode === 'workspace') label = waiting ? '이전 작업 파일 복원 준비 중' : '이전 작업 파일로 이어감';
  if (mode === 'session') label = (job.continuation_confirmed === true || job.continuation_confirmed === 1)
    ? '동일 세션 이어감'
    : waiting ? '동일 세션 재개 준비 중' : solverTerminalPhases.has(job.phase) ? '동일 세션 재개 미확인' : '동일 세션 재개 확인 중';
  const details = legacy ? `<span>${esc(legacy)}</span>` : '';
  return `<p class="solver-continuation solver-continuation-${mode}"><strong>${esc(i18n.t(label))}</strong>${details}</p>`;
}

function solverQueueMarkup(job) {
  if (job?.phase !== 'queued') return '';
  const position = Number(job.queue_position);
  const hasPosition = job.queue_position != null && Number.isFinite(position);
  const updating = job.queue_block_reason === 'service_update';
  if (!hasPosition && !updating) return '';
  const order = hasPosition
    ? (i18n.locale === 'en' ? `Queue position ${Math.max(1,position)}` : `대기 순서 ${Math.max(1,position)}번째`)
    : '';
  const reason = updating ? i18n.t('서비스 업데이트 중 · 완료 후 시작') : '';
  return `<p class="form-hint solver-queue-state${updating ? ' solver-queue-state-update' : ''}" role="status">${esc([order,reason].filter(Boolean).join(' · '))}</p>`;
}

function solverAttachmentHold() {
  return attachmentsPending(currentChallenge?.workspace_id,currentChallenge?.id);
}

function solverAttachmentHoldMarkup() {
  return `<p class="solver-attachment-hold form-hint" role="status">${tr(attachmentHoldReason)}</p>`;
}

function solverStartAttributes() {
  return solverAttachmentHold() ? 'data-attachment-hold disabled' : solverConfigurationReady() ? '' : 'disabled';
}

function solverPanelMarkup(job, events = [], loading = false) {
  if (loading) return '<div class="solver-panel-head"><h3>문제 풀이</h3><span class="connection-state">확인 중</span></div>';
  const writeup = job?.flag_rejected ? '' : solverWriteup(job);
  if (!job) return `<div class="solver-panel-head"><h3>문제 풀이</h3><span class="connection-state">실행 전</span></div>
    ${solverWriteupArtifact(writeup)}
    ${solverProviderSelector()}
    <button class="primary" data-action="start-solver" ${solverStartAttributes()}>풀이 시작</button>
    ${solverAttachmentHold() ? solverAttachmentHoldMarkup() : ''}`;
  const active = solverIsActive(job), model = job.model || job.configuration || {};
  const progress = job.progress || {};
  const progressCode = progress.code || job.progress_code;
  const percent = Number(progress.percent ?? job.percent);
  const progressText = i18n.t(solverProgress[progressCode] || (progressCode ? '상태 변경' : ''));
  const modelText = [job.account_label, model.provider, model.model, model.reasoning_effort && `${i18n.t('추론')} ${model.reasoning_effort}`, model.ultracode ? 'Ultracode' : null, model.service_tier === 'fast' ? 'Fast 1.5×' : null].filter(Boolean).join(' · ');
  const flag = typeof job.flag === 'string' && job.flag ? job.flag : '';
  const usableFlag = flag && !job.flag_rejected;
  const controls = active
    ? `<button class="danger" data-action="cancel-solver" ${job.cancel_requested ? 'disabled' : ''}>${job.cancel_requested ? '중단 처리 중' : '풀이 중단'}</button>`
    : job.error?.code === 'ultra_escalation_requested'
      ? `${job.ultra_escalation?.started_job_id ? '<span class="form-hint">Ultra 작업으로 이어가는 중</span>' : job.ultra_escalation?.auto_pending ? '<span class="form-hint">Ultra 전환 준비 중</span>' : job.ultra_escalation?.eligible ? `<button class="primary" data-action="approve-ultra-escalation" ${solverAttachmentHold() ? 'data-attachment-hold disabled' : ''}>Ultra로 이어가기</button>` : '<span class="form-hint">이전 Ultra 요청이 만료됐습니다. 현재 설정으로 다시 풀 수 있습니다.</span>'}<button data-action="start-solver" ${solverStartAttributes()}>현재 설정으로 다시 풀기</button>`
    : job.phase === 'needs_input'
      ? `<button data-action="edit-challenge">문제 입력 수정</button>${currentChallenge?.remote_mode === 'endpoint' || job.input_ready_to_retry === true ? `<button class="primary" data-action="start-solver" ${solverStartAttributes()}>계속 풀기</button>` : '<span class="form-hint">요청된 접속 정보나 파일을 먼저 추가하세요.</span>'}`
      : job.flag_rejected
      ? `<button class="primary" data-action="start-solver" ${solverStartAttributes()}>오답을 제외하고 다시 풀기</button>`
      : job.phase === 'completed'
      ? '<p class="form-hint">다시 실행하려면 먼저 위의 완료 취소를 눌러 미완료 상태로 되돌리세요.</p>'
      : `<button class="primary" data-action="start-solver" ${solverStartAttributes()}>다시 풀기</button>`;
  const elapsed = active ? solverElapsedMarkup(job) : '';
  return `<div class="solver-panel-head"><h3>문제 풀이</h3><div class="solver-panel-state"><span class="solver-phase solver-phase-${esc(job.phase)}">${esc(active && job.cancel_requested ? '중단 요청 중' : (solverPhases[job.phase] || '상태 변경'))}</span>${elapsed}</div></div>
    ${modelText ? `<p class="solver-model" data-i18n-ignore>${esc(modelText)}</p>` : ''}
    ${job.network_policy === 'general_internet' ? '<p class="form-hint solver-limit">인터넷 사용 가능</p>' : ''}
    ${solverContinuationMarkup(job)}
    ${solverQueueMarkup(job)}
    ${progressText ? `<div class="solver-progress"><span>${esc(progressText)}</span>${Number.isFinite(percent) ? `<progress max="100" value="${Math.max(0,Math.min(100,percent))}" aria-label="${esc(i18n.format('{label} 진행률',{label:progressText}))}"></progress>` : ''}</div>` : ''}
    ${usableFlag ? `<div class="solver-artifact solver-flag-found" role="status" aria-live="assertive"><strong>Flag를 발견했습니다</strong><code>${esc(flag)}</code><div class="actions"><button type="button" class="small ghost icon-action" data-action="copy-solver-flag" aria-label="Flag 복사" title="Flag 복사">⚑</button>${currentChallenge?.completion_source !== 'manual' ? '<button type="button" class="small danger ghost" data-action="reject-solver-flag">오답으로 제외</button>' : ''}</div></div>` : ''}
    ${job.flag_rejected ? `<div class="solver-artifact solver-flag-rejected" role="status"><strong>제외한 Flag</strong><code>${esc(flag)}</code></div>` : ''}
    ${solverWriteupArtifact(writeup)}
    ${solverErrorMarkup(job.error)}
    ${solverSessionMarkup(job,events,active)}
    ${solverGuidanceMarkup(job,active)}
    ${solverPeerEvidenceButton(job,active)}
    ${active ? '' : solverProviderSelector()}
    <div class="actions solver-actions">${controls}</div>
    ${controls.includes('data-attachment-hold') ? solverAttachmentHoldMarkup() : ''}`;
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

// CTFd import drafts survive closing, so those forms have nothing to discard.
function modalInputAtRisk() {
  return formDirty() && !['ctfd-preview-form','ctfd-import-form','ctfd-sync-form'].includes(modal.querySelector('form')?.id);
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
    ? `${i18n.format('파일 {n}개',{n:files.length})} · ${size(files.reduce((total,file) => total + Number(file.size || 0),0))}`
    : '여러 파일 · 용량 제한 없음';
  if (!list) return;
  list.hidden = !files.length;
  list.innerHTML = files.map((file,index) => `<div class="challenge-file-row"><span class="challenge-file-type" aria-hidden="true">FILE</span><span><strong data-i18n-ignore>${esc(file.name)}</strong><small>${size(Number(file.size || 0))}</small></span><button type="button" class="small danger" data-action="remove-challenge-file" data-index="${index}" aria-label="${esc(i18n.format('{name} 선택 취소',{name:file.name}))}" title="선택 취소">×</button></div>`).join('');
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
    paintSolverStartHold();
  }
}

async function api(url, options = {}) {
  // Once a session has ended only the sign-in requests leave the page.
  if (signedOut && !url.startsWith('/api/auth/')) throw Object.assign(new Error(i18n.t('로그인이 필요합니다.')),{status:401});
  const epoch = authEpoch;
  const headers = {...options.headers};
  if (csrf) headers['X-CSRF-Token'] = csrf;
  let body = options.body;
  if (body !== undefined && !(body instanceof FormData) && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(url, {...options, headers, body, credentials:'same-origin'});
  if (response.ok && options.responseType === 'blob') return response.blob();
  let result;
  // A request given up on has no answer to read. An unreadable answer is an empty one.
  try { result = await response.json(); } catch (error) { if (options.signal?.aborted) throw error; result = {}; }
  if (!response.ok) {
    if (response.status === 401 && authMode === 'password' && url !== '/api/auth/login' && !signedOut && epoch === authEpoch) showLogin(!signingOut);
    const detail = result.detail;
    const payload = detail && typeof detail === 'object' && !Array.isArray(detail) ? detail : result;
    const message = Array.isArray(detail)
      ? detail.map(e => e.msg).join(' / ')
      : (typeof detail === 'string' ? detail : payload.message);
    const error = new Error(message || `요청에 실패했습니다 (${response.status}).`);
    error.status = response.status;
    for (const key of ['code','category','stage','retryable','provider_code','quota','requirements']) if (payload[key] !== undefined) error[key] = payload[key];
    if (error.code === 'service_updating') error.message = i18n.t('서비스 업데이트 중입니다. 완료 후 다시 시도하세요.');
    throw error;
  }
  return result;
}

// A request limit fails with the browser's own English text.
function unanswered(error, signal) {
  const gaveUp = signal?.aborted || ['TimeoutError','AbortError'].includes(error?.name);
  return gaveUp ? new Error('서버가 응답하지 않습니다. 잠시 후 다시 시도하세요.') : error;
}

// What a page needs before it can show anything. It may take long, but not for ever.
async function pageRequest(url) {
  const signal = pageLoadSignal();
  try { return await api(url,{signal}); }
  catch (error) { throw unanswered(error,signal); }
}

function toast(message, error = false, duration = error ? 8000 : 4000) {
  const node = document.createElement('div');
  node.className = `toast${error ? ' error' : ''}`;
  node.textContent = message;
  node.setAttribute('role',error ? 'alert' : 'status');
  const topDialog = modal.open ? modal : solverConsoleDialog?.open ? solverConsoleDialog : detail.open ? detail : null;
  let target = topDialog ? topDialog.querySelector('.toasts') : document.querySelector('#toasts');
  if (!target) {
    target = document.createElement('div'); target.className = 'toasts'; target.setAttribute('aria-live','polite');
    (topDialog || document.body).append(target);
  }
  target.append(node);
  setTimeout(() => node.remove(), duration);
  return node;
}

function siteConfirm(message, heading = '확인', actionLabel = '확인') {
  if (solverConfirmDialog?.open) return Promise.resolve(false);
  const restoreFocus = document.activeElement;
  const dialog = document.createElement('dialog');
  solverConfirmDialog = dialog;
  dialog.className = 'solver-confirm-dialog';
  dialog.setAttribute('aria-labelledby','solver-confirm-title');
  dialog.innerHTML = '<div class="solver-confirm-content"><h2 id="solver-confirm-title"></h2><p class="solver-confirm-message"></p><div class="solver-confirm-actions"><button type="button" data-confirm-cancel>취소</button><button type="button" class="danger" data-confirm-accept></button></div></div>';
  dialog.querySelector('#solver-confirm-title').textContent = i18n.t(heading);
  dialog.querySelector('.solver-confirm-message').textContent = i18n.t(message);
  const cancel = dialog.querySelector('[data-confirm-cancel]');
  const accept = dialog.querySelector('[data-confirm-accept]');
  cancel.textContent = i18n.t('취소');
  accept.textContent = i18n.t(actionLabel);
  document.body.append(dialog);
  return new Promise((resolve,reject) => {
    let settled = false;
    const finish = confirmed => {
      if (settled) return;
      settled = true;
      if (dialog.open) dialog.close();
      dialog.remove();
      if (solverConfirmDialog === dialog) solverConfirmDialog = null;
      if (restoreFocus?.isConnected) restoreFocus.focus();
      resolve(confirmed);
    };
    cancel.addEventListener('click',() => finish(false));
    accept.addEventListener('click',() => finish(true));
    dialog.addEventListener('cancel',event => { event.preventDefault(); finish(false); });
    dialog.addEventListener('close',() => finish(false));
    try { dialog.showModal(); cancel.focus(); }
    catch (error) { dialog.remove(); solverConfirmDialog = null; reject(error); }
  });
}

function showManualCopy(value) {
  const previous = document.querySelector('.copy-select-dialog');
  if (previous?.open) {
    const textarea = previous.querySelector('textarea');
    if (textarea) { textarea.value = value; textarea.focus(); textarea.select(); }
    return;
  }
  const restoreFocus = document.activeElement;
  const dialog = document.createElement('dialog');
  dialog.className = 'modal copy-select-dialog';
  const heading = document.createElement('h2');
  heading.textContent = i18n.t('직접 복사');
  const guidance = document.createElement('p');
  guidance.textContent = i18n.t('내용을 선택한 상태입니다. Ctrl+C를 누르세요.');
  const textarea = document.createElement('textarea');
  textarea.readOnly = true;
  textarea.value = value;
  textarea.setAttribute('aria-label', i18n.t('복사할 내용'));
  const close = document.createElement('button');
  close.type = 'button'; close.textContent = i18n.t('닫기');
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => {
    dialog.remove();
    if (restoreFocus?.isConnected) restoreFocus.focus?.();
  }, {once:true});
  dialog.append(heading, guidance, textarea, close);
  document.body.append(dialog);
  dialog.showModal();
  textarea.focus(); textarea.select();
}

function copyToast(result, value) {
  if (result === 'manual') return;
  const node = toast('복사를 시도했습니다. 붙여넣기를 확인하세요.', false, 10000);
  const manual = document.createElement('button');
  manual.type = 'button'; manual.className = 'small ghost copy-select-action';
  manual.textContent = '직접 선택';
  manual.addEventListener('click', () => { showManualCopy(value); node.remove(); });
  node.append(manual);
}

async function run(task, button) {
  // Start the action while the click still owns its transient user activation.
  // Clipboard writes can be rejected if the clicked control is disabled first.
  const epoch = authEpoch;
  try {
    const pending = task();
    if (button) button.disabled = true;
    return await pending;
  } catch (error) { if (epoch === authEpoch) toast(error.message, true); }
  finally { if (button) button.disabled = button.hasAttribute('data-attachment-hold'); }
}

async function runForm(task, form, button) {
  if (busyForms.has(form)) return;
  busyForms.add(form); form.setAttribute('aria-busy','true');
  const controls = [...form.querySelectorAll('input,select,textarea,button')], previous = controls.map(node => node.disabled);
  controls.forEach(node => { node.disabled = true; });
  try { await run(task,button); }
  finally {
    controls.forEach((node,index) => { node.disabled = previous[index]; });
    if (form.id === 'admin-log-export-form' && form.dataset.previewReady === 'true') {
      form.querySelector('[data-action="download-admin-logs"]').disabled = false;
    }
    busyForms.delete(form); form.removeAttribute('aria-busy');
  }
}

function sessionStarted() {
  authEpoch++;
  signedOut = false;
}

// A sign-in failure stays in the card: on a phone a toast can sit under the keyboard. The
// notice takes source text, so the page observer translates it now and on a language
// change. runForm disabled the focused control, so focus returns only after it finishes.
async function submitCredentials(form, task, button) {
  const notice = form.querySelector('.login-error');
  notice.textContent = '';
  let failure = null;
  await runForm(async () => { try { await task(); } catch (error) { failure = error; } },form,button);
  if (!failure) return;
  if (!form.isConnected) { toast(transferErrorText(failure),true); return; }
  notice.textContent = failure instanceof TypeError ? '서버에 연결할 수 없습니다. 연결을 확인하세요.' : failure.message;
  const focusName = form.id === 'setup-form' && failure.status === 403 ? 'setup_token'
    : form.id === 'setup-form' && failure.status === 409 ? 'username' : 'password';
  const field = form.querySelector(`[name="${focusName}"]`) || form.querySelector('[name="password"]');
  field?.focus();
  field?.select();
  notice.scrollIntoView({block:'nearest'});
}

function showLogin(expired = false, configured = true, setupAvailable = false, setupTokenRequired = false) {
  authEpoch++;
  signedOut = true;
  csrf = '';
  workspacesListed = false;
  if (solverConsoleDialog?.open) solverConsoleDialog.close();
  clearAccountsReturnTarget();
  ++rendering; ++modalRendering; ++ctfdSubmitRendering; challengeFlags.clear();
  writeupPrefetchGeneration++;
  writeupPrefetchObserver?.disconnect(); writeupPrefetchObserver = null;
  writeupPrefetchQueue = []; writeupPrefetchRequested.clear(); writeupPrefetchWorkspace = ''; writeupPrefetchActive = 0;
  writeupCopyCache.clear(); writeupCopyCacheBytes = 0;
  writeupCopyEpoch.clear(); writeupCurrentStamp.clear();
  leaveWorkspacePage();
  stopReleaseUpdatePolling();
  pauseStagedUploads();
  for (const upload of activeUploads.values()) { upload.paused = true; upload.controller?.abort(); }
  activeUploads.clear(); uploadViews.clear();
  stopAttachmentWork();
  rememberNotes();
  disposeTelegram?.(); disposeTelegram = null;
  disposeAccounts?.(); disposeAccounts = null;
  // Any dialog left open would keep the login form inert.
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  if (!configured && setupAvailable) {
    app.innerHTML = `<main class="login-shell"><div class="login-card">${i18n.picker()}
      <div class="brand"><img src="/assets/icon.svg" alt=""><div>CTF Workspace</div></div>
      <h1>관리자 계정 만들기</h1>
      <form id="setup-form"><label>아이디<input name="username" autocomplete="username" maxlength="100" required autofocus></label><label>비밀번호<input type="password" name="password" autocomplete="new-password" minlength="4" maxlength="1024" required></label><label>비밀번호 확인<input type="password" name="confirmation" autocomplete="new-password" minlength="4" maxlength="1024" required></label>${setupTokenRequired ? '<label>설치 확인 코드<input type="password" name="setup_token" autocomplete="off" maxlength="256" required></label>' : ''}<div class="notice error-notice login-error" role="alert"></div><button class="primary">관리자 계정 만들기 <span aria-hidden="true">→</span></button></form>
    </div></main>`;
    return;
  }
  app.innerHTML = `<main class="login-shell"><div class="login-card">${i18n.picker()}
    <div class="brand"><img src="/assets/icon.svg" alt=""><div>CTF Workspace</div></div>
    <h1>로그인</h1>
    ${!configured ? '<p>관리자 초기 비밀번호가 설정되지 않았습니다.</p>' : expired ? '<p>세션이 만료되었습니다.</p>' : ''}
    <form id="login-form"><label>아이디<input name="username" autocomplete="username" value="${esc(sessionUser?.username || '')}" maxlength="100" required autofocus></label><label>비밀번호<input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label><div class="notice error-notice login-error" role="alert"></div><label class="login-remember"><input type="checkbox" name="remember" value="true">이 기기에서 30일 로그인 유지</label><button class="primary" ${configured ? '' : 'disabled'}>로그인 <span aria-hidden="true">→</span></button></form>
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

function shell(active, breadcrumb = '모든 작업공간', named = false) {
  app.innerHTML = `<div class="shell ${sidebarCollapsed ? 'sidebar-collapsed' : ''}"><aside id="app-sidebar" class="sidebar">
    <div class="sidebar-head"><a class="brand" href="#" aria-label="CTF Workspace 홈"><img src="/assets/icon.svg" alt=""><div class="brand-copy">CTF Workspace</div></a><button type="button" class="sidebar-toggle icon-action" data-action="toggle-sidebar" aria-controls="app-sidebar" aria-expanded="${!sidebarCollapsed}" aria-label="${sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기'}" title="${sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기'}"><span aria-hidden="true">${sidebarCollapsed ? '»' : '«'}</span></button></div>
    <div class="nav-label">WORKSPACE</div><nav aria-label="기본 메뉴">
    <a class="nav-item ${active === 'workspaces' ? 'active' : ''}" href="#" aria-label="작업공간" ${active === 'workspaces' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">▦</span><span class="nav-text">작업공간</span><span class="nav-count">${workspaces.length}</span></a>
    <a class="nav-item ${active === 'accounts' ? 'active' : ''}" href="#accounts" aria-label="에이전트" ${active === 'accounts' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">◎</span><span class="nav-text">에이전트</span></a>
    <a class="nav-item ${active === 'settings' ? 'active' : ''}" href="#settings" aria-label="개인 설정" ${active === 'settings' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">⚙</span><span class="nav-text">개인 설정</span></a>
    ${sessionUser?.role === 'admin' ? `<a class="nav-item ${active === 'admin' ? 'active' : ''}" href="#admin" aria-label="관리자 설정" ${active === 'admin' ? 'aria-current="page"' : ''}><span class="nav-icon" aria-hidden="true">◇</span><span class="nav-text">관리자 설정</span></a>` : ''}</nav>
    ${authMode === 'password' ? '<div class="sidebar-foot"><button class="ghost small" data-action="logout">로그아웃</button></div>' : ''}
    </aside><main class="main"><header class="topbar"><div class="breadcrumb"><a href="#">작업공간</a><span>/</span><span${named ? ' data-i18n-ignore' : ''}>${esc(breadcrumb)}</span></div><div class="topbar-meta">${i18n.picker()}<span data-i18n-ignore>${esc(sessionUser?.username || '')}</span><div class="avatar" data-i18n-ignore title="${esc(sessionUser?.username || '')}">${avatarMarkup(sessionUser)}</div></div></header><div id="content" class="content"></div></main></div>`;
  return document.querySelector('#content');
}

async function render() {
  // Until a session starts the login form is the whole page.
  if (signedOut) return;
  const ticket = ++rendering;
  stopResourcePolling();
  stopChallengeListPolling();
  disposeAccounts?.(); disposeAccounts = null;
  disposeTelegram?.(); disposeTelegram = null;
  try { await renderRoute(ticket); }
  catch (error) {
    // In password mode a 401 has already opened the login form. Only no-login mode gets
    // here with one: it has no form, so Retry goes back through the boot path.
    if (ticket === rendering) showPageFailure(error,error.status === 401 ? boot : retryRender);
  }
}

// A language pack lost in the same outage comes back with the page.
async function retryRender() {
  await i18n.init().catch(() => {});
  await render();
}

async function renderRoute(ticket) {
  const listing = await pageRequest('/api/workspaces');
  if (ticket !== rendering) return;
  // A proxy or portal can answer 200 with a page of its own.
  if (!Array.isArray(listing?.workspaces)) throw new Error('서버 응답을 확인할 수 없습니다. 잠시 후 다시 시도하세요.');
  workspaces = listing.workspaces;
  workspacesListed = true;
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
  if (hash === 'admin') { currentWorkspace = null; await renderAdmin(ticket); return; }
  const match = /^w\/([0-9a-f]{32})(?:\/c\/([0-9a-f]{32}))?$/.exec(hash);
  if (match) {
    let workspace;
    try { workspace = await pageRequest(`/api/workspaces/${match[1]}`); }
    catch (error) {
      if (error.status !== 404) throw error;
      if (ticket === rendering) renderWorkspaceNotFound();
      return;
    }
    if (ticket !== rendering) return;
    currentWorkspace = workspace;
    await renderWorkspace();
    // The workspace page works without this challenge, so it stays and only a toast reports it.
    if (match[2] && ticket === rendering) await openChallenge(match[2]).catch(error => { if (ticket === rendering) toast(transferErrorText(error),true); });
  } else { currentWorkspace = null; renderOverview(); }
}

function pageFailureMarkup(error) {
  return `<div class="empty page-failure" role="alert"><div class="empty-icon" aria-hidden="true">!</div><h2>${tr('화면을 불러오지 못했습니다.')}</h2><p>${esc(transferErrorText(error))}</p><button type="button" class="primary" data-action="retry-page">${tr('다시 시도')}</button></div>`;
}

function workspaceNotFoundMarkup() {
  return `<div class="empty page-failure" role="alert"><div class="empty-icon" aria-hidden="true">⚑</div><h2>${tr('작업공간을 찾을 수 없습니다.')}</h2><p>${tr('삭제되었거나 이 계정으로 볼 수 없는 작업공간입니다.')}</p><a class="button-link primary" href="#">${tr('모든 작업공간')}</a></div>`;
}

function repaintPageNotice() {
  const root = document.querySelector('#content') || app.querySelector('.page-failure-shell');
  if (root && pageNotice) morphMarkup(root,pageNotice());
}

function showPageNotice(markup, retry = null) {
  pageNotice = markup;
  pageRetry = retry;
  repaintPageNotice();
}

const pageTitles = new Map([['accounts','에이전트'],['settings','개인 설정'],['admin','관리자 설정']]);

function showPageFailure(error, retry) {
  leaveWorkspacePage();
  const hash = location.hash.slice(1);
  const title = pageTitles.get(hash);
  shell(title ? hash : 'workspaces',title);
  if (!workspacesListed) document.querySelector('.nav-count')?.remove();
  showPageNotice(() => pageFailureMarkup(error),retry);
}

// Before a session is known there is no shell, so this one fills #app.
function showBootFailure(error) {
  app.innerHTML = '<main class="page-failure-shell"></main>';
  showPageNotice(() => `${i18n.picker()}${pageFailureMarkup(error)}`,boot);
}

// Also for a workspace that disappears while it is on screen. The detail stays open, and so
// does a form with typed input: either may hold the only copy of something. Both sit above
// the notice, so they say it themselves, and closing the last one finishes leaving the page.
function renderWorkspaceNotFound() {
  const workspace = currentWorkspace;
  rememberNotes();
  if (solverConsoleDialog?.open) solverConsoleDialog.close();
  if (modal.open && !modalInputAtRisk() && !(modal.dataset.kind === 'direct-send' && directSendState && directSendActive(directSendState))) modal.close();
  leaveWorkspacePage(detail.open);
  if (workspace && (detail.open || modal.open)) {
    currentWorkspace = workspace;
    workspace.gone = true;
    workspace.listStaleAt ||= Date.now();
  }
  shell('workspaces');
  showPageNotice(workspaceNotFoundMarkup);
  paintLiveNotices();
  if (modal.open) toast(i18n.t('작업공간을 찾을 수 없습니다.'),true);
}

function leaveGoneWorkspace() {
  if (!currentWorkspace?.gone || detail.open || modal.open) return;
  currentWorkspace = null;
  document.querySelector('.page-failure a')?.focus();
}

function renderOverview() {
  shell('workspaces').innerHTML = overviewMarkup();
}

function overviewMarkup() {
  const total = workspaces.reduce((sum, w) => sum + w.challenge_count, 0);
  const solved = workspaces.reduce((sum, w) => sum + w.solved_count, 0);
  const running = workspaces.reduce((sum, w) => sum + w.running_count, 0);
  return `<div class="page-head"><div><div class="eyebrow">WORKSPACES</div><h1>작업공간</h1></div><div class="head-actions"><button data-action="receive-workspace-direct">${tr('직접 받기')}</button><button data-action="import-workspace-transfer">${tr('ZIP 가져오기')}</button><button class="primary" data-action="new-workspace">＋ 작업공간 만들기</button></div></div>
    <div class="stats"><div class="stat"><div class="stat-label">전체 작업공간</div><div class="stat-value">${workspaces.length}</div></div><div class="stat"><div class="stat-label">등록된 문제</div><div class="stat-value">${total}</div></div><div class="stat"><div class="stat-label">작업 중</div><div class="stat-value">${running}</div></div><div class="stat"><div class="stat-label">완료한 문제</div><div class="stat-value accent">${solved}</div><div class="stat-note">${total ? Math.round(solved / total * 100) : 0}%</div></div></div>
    <div class="section-head"><h2>내 작업공간 <span class="muted">${workspaces.length}</span></h2></div>
    ${workspaces.length ? `<div class="cards">${workspaces.map(w => `<a class="workspace-card" href="#w/${w.id}"><div class="card-top"><span class="folder-icon">⚑</span><span class="tag ${w.running_count ? '' : 'muted'}">${w.running_count ? i18n.format('{n}개 작업 중',{n:w.running_count}) : 'WORKSPACE'}</span></div><h3 data-i18n-ignore>${esc(w.name)}</h3>${w.description ? `<p data-i18n-ignore>${esc(w.description)}</p>` : ''}<div class="card-bottom"><span>${i18n.format('문제 {n}',{n:w.challenge_count})}</span><span>${i18n.t('완료')} ${w.solved_count}</span><span class="card-arrow">↗</span></div></a>`).join('')}</div>` : `<div class="empty"><div class="empty-icon">⚑</div><h2>작업공간이 없습니다.</h2><button class="primary" data-action="new-workspace">＋ 새 작업공간</button></div>`}`;
}

async function showChallengeTrash() {
  const workspaceId = currentWorkspace?.id;
  if (!workspaceId) return;
  const result = await api(`/api/workspaces/${workspaceId}/trash`);
  if (currentWorkspace?.id !== workspaceId) return;
  const rows = result.challenges || [];
  const body = rows.length ? `<div class="file-list">${rows.map(item => `<div class="file-item"><div><strong data-i18n-ignore>${esc(item.name)}</strong><small>${esc(item.category || '')} · ${esc(item.deleted_at || '')}</small></div><div class="actions"><button type="button" class="small" data-action="restore-trash-challenge" data-id="${esc(item.id)}">${tr('Restore')}</button><button type="button" class="small danger" data-action="purge-trash-challenge" data-id="${esc(item.id)}">${tr('Delete permanently')}</button></div></div>`).join('')}</div>` : `<p class="muted">${tr('The trash is empty.')}</p>`;
  openModal(tr('Trash'), '', body, `<button type="button" data-action="close-modal">${tr('Close')}</button>`);
  modal.dataset.kind = 'challenge-trash';
  modal.dataset.workspaceId = workspaceId;
}

async function showCloneGroups() {
  const workspaceId = currentWorkspace?.id;
  if (!workspaceId) return;
  const [groupResult, listResult] = await Promise.all([
    api(`/api/workspaces/${workspaceId}/clone-groups`),
    api(`/api/workspaces/${workspaceId}/challenges`),
  ]);
  if (currentWorkspace?.id !== workspaceId) return;
  const groups = groupResult.groups || [];
  const active = listResult.challenges || [];
  const grouped = new Set(groups.flatMap(group => group.members.map(member => member.id)));
  const standalone = active.filter(item => !grouped.has(item.id));
  const options = id => active.filter(item => item.id !== id).map(item =>
    `<option value="${esc(item.id)}" data-i18n-ignore>${esc(item.name)}</option>`).join('');
  const member = item => `<div class="file-item clone-member"><div><strong data-i18n-ignore>${esc(item.name)}</strong><small>${esc(item.status)}${item.deleted_at ? ` · ${tr('Trash')}` : ''}</small></div>${item.deleted_at ? '' : `<div class="actions"><select aria-label="${tr('Group with challenge')}" data-member-id="${esc(item.id)}"><option value="">${tr('Group with challenge')}</option>${options(item.id)}</select><button type="button" class="small" data-action="move-clone-group" data-id="${esc(item.id)}">${tr('Group')}</button><button type="button" class="small ghost" data-action="split-clone-group" data-id="${esc(item.id)}">${tr('Separate')}</button></div>`}</div>`;
  const body = `${groups.map(group => {
    const label = group.members.find(item => item.id === group.id)?.name || group.members[0]?.canonical_name || group.members[0]?.name || '';
    return `<section class="clone-group"><h3 data-i18n-ignore>${esc(label)} · ${group.members.length}</h3><div class="file-list">${group.members.map(member).join('')}</div></section>`;
  }).join('')}${standalone.length ? `<section class="clone-group"><h3>${tr('Ungrouped')}</h3><div class="file-list">${standalone.map(member).join('')}</div></section>` : ''}${!groups.length && !standalone.length ? `<p class="muted">${tr('No challenges.')}</p>` : ''}`;
  openModal(tr('Clone groups'), '', body, `<button type="button" data-action="close-modal">${tr('Close')}</button>`);
  modal.dataset.kind = 'clone-groups';
  modal.dataset.workspaceId = workspaceId;
}

async function changeCloneGroup(button, split = false) {
  const workspaceId = modal.dataset.workspaceId, challengeId = button.dataset.id;
  if (!workspaceId || currentWorkspace?.id !== workspaceId) return;
  const target = split ? null : button.closest('.clone-member')?.querySelector('select')?.value;
  if (!split && !target) throw new Error(i18n.t('Choose a challenge to group with.'));
  await api(`/api/workspaces/${workspaceId}/challenges/${challengeId}/clone-group`,
    {method:'PUT',body:{target_challenge_id:target}});
  await showCloneGroups();
}

async function renderWorkspace() {
  const w = currentWorkspace;
  stopChallengeListPolling();
  shell('workspaces', w.name, true).innerHTML = workspaceMarkup(w);
  startResourcePolling(w.id);
  await refreshChallenges(pageRequest);
  startChallengeListPolling(w.id);
  pollCTFdJobs(w.id);
}

function workspaceMarkup(w) {
  return `<div class="page-head"><div><div class="eyebrow">CTF WORKSPACE</div><h1 data-i18n-ignore>${esc(w.name)}</h1>${w.description ? `<p data-i18n-ignore>${esc(w.description)}</p>` : ''}</div><div class="head-actions"><button class="ghost icon-action" data-action="edit-workspace" aria-label="작업공간 설정" title="작업공간 설정">⚙</button><button data-action="show-challenge-trash">${tr("Trash")}</button><button data-action="show-clone-groups">${tr("Clone groups")}</button><button data-action="show-staged-files">${tr('사전 파일')}</button><button data-action="receive-workspace-direct">${tr('직접 받기')}</button><button data-action="import-workspace-transfer">${tr('ZIP 가져오기')}</button><button data-action="ctfd-submit-settings">CTFd 연결</button><button data-action="ctfd-import">CTFd 가져오기 <span class="ctfd-import-badge" hidden></span></button><button data-action="ctfd-sync" title="저장된 CTFd 연결에서 새로 추가된 문제만 확인합니다.">새 문제 동기화</button><button class="primary" data-action="new-challenge">＋ 문제 추가</button></div></div>
    <div class="workspace-summary"><div class="workspace-summary-meta"><span>⚑ Flag 형식 <code>${esc(w.flag_format || i18n.t('미설정'))}</code></span><span>문제 수 <b data-workspace-challenge-count>${w.challenge_count ?? ''}</b></span></div>${resourceMeterMarkup()}</div>
    <div id="challenge-area" data-morph-keep></div>${liveNoticeMarkup()}`;
}

function challengeRunSummary(challenge) {
  const run = challenge.latest_solver || challenge.solver || challenge.latest_run || null;
  const configuration = run?.configuration || challenge.solver_configuration || null;
  if (!configuration || typeof configuration !== 'object') return '';
  const phase = run?.phase || run?.status;
  const phaseLabel = phase === 'needs_input' && run?.input_request_kind === 'ultra_escalation'
    ? i18n.t('Ultra 전환 제안')
    : phase === 'needs_input' && run?.input_request_kind === 'remote_input'
      ? i18n.t('원격 정보 요청') : phase && i18n.t(solverPhases[phase] || statuses[phase] || '상태 변경');
  const parts = [run?.account_label, configuration.provider, configuration.model,
    configuration.reasoning_effort && `${i18n.t('추론')} ${configuration.reasoning_effort}`,
    configuration.ultracode ? 'Ultracode' : null,
    configuration.service_tier === 'fast' ? 'Fast 1.5×' : null,
    phaseLabel,
    phase === 'queued' && run?.queue_block_reason === 'service_update' ? i18n.t('서비스 업데이트 중') : null];
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

// These labels count on the client, so they stop with the data behind them.
function elapsedClock(freezeOnListStale = false) {
  return ((currentWorkspace?.gone || freezeOnListStale) && currentWorkspace?.listStaleAt || Date.now()) / 1000;
}

function solverElapsedMarkup(run, freezeOnListStale = false) {
  const base = run?.solve_elapsed_seconds;
  if (typeof base !== 'number' || !Number.isFinite(base) || base < 0) return '';
  const runningSince = run.solve_elapsed_running_since;
  const ticking = typeof runningSince === 'number' && Number.isFinite(runningSince) && runningSince > 0;
  const label = i18n.t(run.solve_elapsed_includes_queue ? '대기 포함 경과 시간' : '풀이 경과 시간');
  const elapsed = challengeElapsedText({elapsed_seconds:base + (ticking ? Math.max(0,elapsedClock(freezeOnListStale) - runningSince) : 0)});
  return `<small class="solver-elapsed" data-elapsed-base="${base}" ${ticking ? `data-running-since="${runningSince}" ` : ''}${freezeOnListStale ? 'data-freeze-list-stale ' : ''}title="${label}" aria-label="${label} ${esc(elapsed)}">· ${esc(elapsed)}</small>`;
}

function updateSolverElapsedLabels() {
  for (const label of document.querySelectorAll('.solver-elapsed[data-elapsed-base]')) {
    const base = Number(label.dataset.elapsedBase);
    if (!Number.isFinite(base) || base < 0) continue;
    const runningSince = Number(label.dataset.runningSince);
    const ticking = Number.isFinite(runningSince) && runningSince > 0;
    const elapsed = challengeElapsedText({elapsed_seconds:base + (ticking ? Math.max(0,elapsedClock(label.hasAttribute('data-freeze-list-stale')) - runningSince) : 0)});
    label.textContent = `· ${elapsed}`;
    label.setAttribute('aria-label',`${label.title} ${elapsed}`);
  }
}

function challengeInputMarkup(challenge, workspaceId) {
  const mode = challenge.remote_mode === 'none' ? 'none' : 'endpoint';
  const inputReady = challenge.latest_solver?.input_ready_to_retry === true;
  const waitingForCorrection = mode === 'none' && !inputReady;
  const held = attachmentsPending(workspaceId,challenge.id);
  return `<form class="challenge-inline-input" data-workspace-id="${esc(workspaceId)}" data-challenge-id="${esc(challenge.id)}" data-edit-token="${esc(challenge.edit_token || '')}" data-name="${esc(challenge.name)}" data-input-ready="${inputReady}" data-original-remote-mode="${esc(challenge.remote_mode || 'unknown')}">
    <div><strong>추가 입력 필요</strong><small>요청된 접속 정보나 파일을 추가한 뒤 이어서 풉니다.</small></div>
    <label><span class="sr-only">원격 대상</span><select name="remote_mode" aria-label="원격 대상"><option value="endpoint" ${mode === 'endpoint' ? 'selected' : ''}>접속 정보</option><option value="none" ${mode === 'none' ? 'selected' : ''}>원격 대상 없음</option></select></label>
    <label class="challenge-inline-remote${mode === 'none' ? ' is-disabled' : ''}"><span class="sr-only">원격 접속 정보</span><input name="remote" value="${esc(challenge.remote || '')}" maxlength="2000" placeholder="URL 또는 nc host port" aria-label="원격 접속 정보" ${mode === 'endpoint' ? 'required' : 'disabled'}></label>
    <button type="submit" class="small primary" ${held ? 'data-attachment-hold ' : ''}${held || waitingForCorrection ? 'disabled' : ''}>계속 풀기</button>
  </form>`;
}

function challengeAttentionMarkup(challenge, kind) {
  const ultra = kind === 'ultra_escalation';
  return `<div class="challenge-inline-attention" role="status">
    <div><strong>${esc(i18n.t(ultra ? 'Ultra 전환 제안' : '추가 입력 필요'))}</strong><small>${esc(i18n.t(ultra ? '이전 분석을 이어받아 Ultra로 계속할 수 있는지 확인하세요.' : '필요한 내용을 문제 상세에서 확인하세요.'))}</small></div>
    <button type="button" class="small primary" data-action="open-challenge" data-id="${esc(challenge.id)}">${esc(i18n.t(ultra ? '전환 확인' : '요청 확인'))}</button>
  </div>`;
}

function challengeLabel(template, challenge) {
  return esc(i18n.t(template).replace('{name}',() => challenge.name));
}

// Attachment work per challenge, in memory. POST .../solver stages the attachment set at enqueue, so a
// solve started now would run without these files and the next upload would get a 409. Start waits.
// A record exists only while something still has to arrive; paused and failed files leave it.
const attachmentWork = new Map();
const attachmentHoldReason = '첨부파일 업로드가 끝나면 시작할 수 있습니다.';
const attachmentWorkKey = (workspaceId, challengeId) => `${workspaceId}:${challengeId}`;

function attachmentsPending(workspaceId, challengeId) {
  return attachmentWork.has(attachmentWorkKey(workspaceId,challengeId));
}

function attachmentWorkBody(work, startable) {
  const current = work.items.find(item => !item.done) || work.items.at(-1);
  const total = work.items.reduce((sum,item) => sum + item.size,0);
  const sent = work.items.reduce((sum,item) => sum + item.offset,0);
  const percent = total ? Math.floor(sent / total * 100) : 0;
  const count = work.items.length > 1 ? `${i18n.format('파일 {current}/{total}',{current:work.items.indexOf(current) + 1,total:work.items.length})} · ` : '';
  return `<div class="challenge-card-upload-head"><strong data-i18n-ignore title="${esc(current.name)}">${esc(count + current.name)}</strong><span data-i18n-ignore>${size(sent)} / ${size(total)} · ${percent}%</span></div><progress max="${Math.max(1,total)}" value="${sent}" aria-label="${esc(i18n.format('{name} 업로드 진행',{name:current.name}))}"></progress>${startable ? `<small>${tr(attachmentHoldReason)}</small>` : ''}`;
}

function attachmentWorkMarkup(work, startable) {
  return `<div class="challenge-card-upload" role="status">${attachmentWorkBody(work,startable)}</div>`;
}

function challengeCardMarkup(challenge, workspaceId) {
  const category = challenge.category || i18n.t('미분류');
  const statusLabel = statuses[challenge.status] || challenge.status;
  const manual = challenge.completion_source === 'manual';
  const canCopyWriteup = challenge.has_writeup === true && !manual;
  const latestRun = challenge.latest_solver || challenge.solver || challenge.latest_run || null;
  const elapsed = challenge.status === 'solved' && !manual ? challengeElapsedText(latestRun) : '';
  const runSummary = challengeRunSummary(challenge);
  const runPhase = latestRun?.phase || latestRun?.status;
  const liveSession = latestRun && !solverTerminalPhases.has(runPhase);
  const liveElapsed = liveSession && challenge.status === 'running'
    ? solverElapsedMarkup(latestRun,true) : '';
  const needsInput = runPhase === 'needs_input';
  const inputRequestKind = latestRun?.input_request_kind;
  const canStart = !needsInput && ['pending','stopped','failed'].includes(challenge.status);
  const startKey = `${workspaceId}:${challenge.id}`;
  const starting = canStart && startingListSolvers.has(startKey);
  const work = attachmentWork.get(startKey);
  const openLabel = challenge.status === 'solved' ? '결과 보기' : challenge.status === 'running' ? '진행 보기' : challenge.status === 'flag_found' ? 'Flag 확인' : '풀이 설정';
  return `<article class="challenge-card challenge-card-${esc(challenge.status)}" data-challenge-id="${esc(challenge.id)}" role="listitem">
    <div class="challenge-card-top"><span class="challenge-category" data-i18n-ignore>${esc(category)}</span><span class="challenge-card-status"><span class="status-dot" aria-hidden="true"></span>${esc(statusLabel)}${liveElapsed || (elapsed ? `<small title="${latestRun.elapsed_includes_queue ? '대기 포함 소요 시간' : '풀이 시간'}">· ${esc(elapsed)}</small>` : '')}</span></div>
    <button type="button" class="challenge-card-title" data-i18n-ignore data-action="open-challenge" data-id="${esc(challenge.id)}" aria-label="${challengeLabel('{name} 문제 열기',challenge)}">${esc(challenge.name)}</button>
    ${challenge.description ? `<p class="challenge-card-description" data-i18n-ignore>${esc(challenge.description)}</p>` : ''}
    ${runSummary ? `<div class="challenge-run-summary" data-i18n-ignore aria-label="${esc(i18n.t('최근 실행 설정'))}">${runSummary}</div>` : ''}
    ${challenge.flag ? `<div class="challenge-card-flag"><code>${esc(challenge.flag)}</code><span>FLAG READY</span></div>` : manual ? '<div class="challenge-card-note">수동 완료됨</div>' : ''}
    ${needsInput ? inputRequestKind === 'remote_input'
      ? challengeInputMarkup(challenge,workspaceId)
      : challengeAttentionMarkup(challenge,inputRequestKind) : ''}
    ${work ? attachmentWorkMarkup(work,canStart || (needsInput && inputRequestKind === 'remote_input')) : ''}
    <footer class="challenge-card-footer"><span class="challenge-updated">${esc(date(challenge.updated_at))}</span><div class="challenge-card-actions">
      ${challenge.flag ? `<button type="button" class="small ghost icon-action flag-action" data-action="copy-list-flag" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" aria-label="${challengeLabel('{name} Flag 복사',challenge)}" title="Flag 복사">⚑</button>` : ''}
      ${canCopyWriteup ? `<button type="button" class="small ghost icon-action writeup-action" data-action="copy-list-writeup" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" data-writeup-stamp="${esc(writeupStamp(challenge))}" aria-label="${challengeLabel('{name} write-up 복사',challenge)}" title="write-up 복사">▤</button>` : ''}
      ${latestRun ? `<button type="button" class="small ghost session-action${liveSession ? ' live' : ''}" data-action="open-solver-session" data-id="${esc(challenge.id)}" data-live="${liveSession}" aria-label="${challengeLabel(liveSession ? '{name} 실시간 풀이 터미널 보기' : '{name} 이전 풀이 터미널 보기',challenge)}" title="${liveSession ? '실시간 풀이 터미널' : '이전 풀이 터미널'}">${liveSession ? '<span class="session-live-dot" aria-hidden="true"></span>LIVE' : '<span aria-hidden="true">&gt;_</span>'}</button>` : ''}
      ${canStart ? `<button type="button" class="small ghost complete-action" data-action="complete-list-challenge" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" data-name="${esc(challenge.name)}" aria-label="${challengeLabel('{name} 수동 완료',challenge)}">수동 완료</button>` : ''}
      ${canStart ? `<button type="button" class="small primary solve-action" data-action="start-list-solver" data-id="${esc(challenge.id)}" data-workspace-id="${esc(workspaceId)}" data-name="${esc(challenge.name)}" aria-label="${challengeLabel('{name} 기본 설정으로 풀이 시작',challenge)}" title="기본 설정으로 풀이 시작" ${work ? 'data-attachment-hold ' : ''}${starting ? 'disabled aria-busy="true"' : work ? 'disabled' : ''}>${starting ? '시작 중' : '▶ 풀이 시작'}</button>` : ''}
      <button type="button" class="small challenge-open-action" data-action="open-challenge" data-id="${esc(challenge.id)}">${openLabel} <span aria-hidden="true">↗</span></button>
    </div></footer>
  </article>`;
}

function challengeCardSignature(challenge) {
  return JSON.stringify({
    id:challenge.id,name:challenge.name,category:challenge.category,description:challenge.description,
    status:challenge.status,flag:challenge.flag,completion_source:challenge.completion_source,
    has_writeup:challenge.has_writeup,updated_at:challenge.updated_at,edit_token:challenge.edit_token,
    writeup_updated_at:challenge.writeup_updated_at,notes_token:challenge.notes_token,
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
    <form id="search-form" class="search-wrap"><label class="sr-only" for="search-input">문제 검색</label><input id="search-input" name="q" value="${esc(search)}" placeholder="문제 이름, 설명 검색"><label class="sr-only" for="category-filter">분류</label><select id="category-filter"><option value="">모든 분류</option>${result.categories.map(c => `<option data-i18n-ignore ${c === selectedCategory ? 'selected' : ''} value="${esc(c)}">${esc(c)}</option>`).join('')}</select><label class="sr-only" for="sort-order">정렬</label><select id="sort-order" name="sort"><option value="added_desc" ${selectedSort === 'added_desc' ? 'selected' : ''}>최근 추가순</option><option value="added_asc" ${selectedSort === 'added_asc' ? 'selected' : ''}>오래된 추가순</option><option value="name_asc" ${selectedSort === 'name_asc' ? 'selected' : ''}>이름 오름차순</option><option value="name_desc" ${selectedSort === 'name_desc' ? 'selected' : ''}>이름 내림차순</option><option value="solver_desc" ${selectedSort === 'solver_desc' ? 'selected' : ''}>최근 풀이 시작순</option><option value="solver_asc" ${selectedSort === 'solver_asc' ? 'selected' : ''}>오래된 풀이 시작순</option><option value="solve_time_asc" ${selectedSort === 'solve_time_asc' ? 'selected' : ''}>풀이 시간 짧은 순</option><option value="solve_time_desc" ${selectedSort === 'solve_time_desc' ? 'selected' : ''}>풀이 시간 긴 순</option></select><button class="small" type="submit">검색</button></form></div>
    ${result.challenges.length ? `<div class="challenge-card-grid" role="list" aria-label="문제 목록" aria-live="polite">${result.challenges.map(c => challengeCardMarkup(c,workspaceId)).join('')}</div><div class="table-footer">${result.challenges.length}개 문제</div>` : `<div class="empty"><div class="empty-icon">▤</div><h2>${total ? '조건에 맞는 문제가 없습니다.' : '등록된 문제가 없습니다.'}</h2>${total ? '<button data-action="clear-filter">필터 초기화</button>' : '<button class="primary" data-action="new-challenge">＋ 문제 추가</button>'}</div>`}<p id="challenge-live-state" class="sr-only" role="status" aria-live="polite"></p>`;
}

function writeupStamp(challenge) {
  return JSON.stringify([challenge.writeup_updated_at || challenge.updated_at || '',challenge.notes_token || '']);
}

function writeupIdentity(workspaceId, challengeId) {
  return `${workspaceId}/${challengeId}`;
}

function writeupCopyKey(workspaceId, challengeId, stamp) {
  return `${workspaceId}/${challengeId}/${stamp}`;
}

function invalidateWriteupCopy(workspaceId, challengeId) {
  const identity = writeupIdentity(workspaceId,challengeId);
  writeupCopyEpoch.set(identity,(writeupCopyEpoch.get(identity) || 0) + 1);
  for (const [key,entry] of writeupCopyCache) {
    if (entry.workspaceId !== workspaceId || entry.challengeId !== challengeId) continue;
    writeupCopyCacheBytes -= entry.bytes;
    writeupCopyCache.delete(key);
  }
  const prefix = `${identity}/`;
  for (const key of writeupPrefetchRequested) if (key.startsWith(prefix)) writeupPrefetchRequested.delete(key);
  writeupPrefetchQueue = writeupPrefetchQueue.filter(item => item.workspaceId !== workspaceId || item.challengeId !== challengeId);
}

function reconcileWriteupCopies(challenges, workspaceId) {
  for (const challenge of challenges) {
    const identity = writeupIdentity(workspaceId,challenge.id);
    const stamp = challenge.has_writeup ? writeupStamp(challenge) : null;
    const prior = writeupCurrentStamp.get(identity);
    const staleCached = [...writeupCopyCache.values()].some(entry =>
      entry.workspaceId === workspaceId && entry.challengeId === challenge.id && entry.stamp !== stamp);
    if ((prior !== undefined && prior !== stamp) || staleCached) invalidateWriteupCopy(workspaceId,challenge.id);
    writeupCurrentStamp.set(identity,stamp);
  }
}

function cachedWriteup(workspaceId, challengeId, stamp) {
  const key = writeupCopyKey(workspaceId,challengeId,stamp);
  const entry = writeupCopyCache.get(key);
  if (!entry) return null;
  writeupCopyCache.delete(key);
  writeupCopyCache.set(key,entry);
  return entry.markdown;
}

function rememberWriteup(workspaceId, challengeId, stamp, markdown) {
  const key = writeupCopyKey(workspaceId,challengeId,stamp);
  const bytes = markdown.length * 2;
  if (bytes > WRITEUP_COPY_CACHE_BYTES) return;
  const previous = writeupCopyCache.get(key);
  if (previous) writeupCopyCacheBytes -= previous.bytes;
  writeupCopyCache.delete(key);
  while (writeupCopyCacheBytes + bytes > WRITEUP_COPY_CACHE_BYTES) {
    const oldest = writeupCopyCache.keys().next().value;
    if (oldest === undefined) break;
    writeupCopyCacheBytes -= writeupCopyCache.get(oldest).bytes;
    writeupCopyCache.delete(oldest);
  }
  writeupCopyCache.set(key,{workspaceId,challengeId,stamp,markdown,bytes});
  writeupCopyCacheBytes += bytes;
}

function replaceKnownWriteup(challenge) {
  if (!challenge?.workspace_id || !challenge?.id) return;
  invalidateWriteupCopy(challenge.workspace_id,challenge.id);
  if (challenge.has_writeup && typeof challenge.writeup_markdown === 'string' && challenge.writeup_markdown) {
    rememberWriteup(challenge.workspace_id,challenge.id,writeupStamp(challenge),challenge.writeup_markdown);
  }
}

function pumpWriteupPrefetch() {
  while (writeupPrefetchActive < 2 && writeupPrefetchQueue.length) {
    const item = writeupPrefetchQueue.shift();
    if (item.generation !== writeupPrefetchGeneration || currentWorkspace?.id !== item.workspaceId ||
        item.epoch !== (writeupCopyEpoch.get(writeupIdentity(item.workspaceId,item.challengeId)) || 0)) continue;
    writeupPrefetchActive++;
    api(`${path(item.challengeId,item.workspaceId)}/writeup`).then(artifact => {
      if (item.generation === writeupPrefetchGeneration && currentWorkspace?.id === item.workspaceId &&
          item.epoch === (writeupCopyEpoch.get(writeupIdentity(item.workspaceId,item.challengeId)) || 0) &&
          writeupCurrentStamp.get(writeupIdentity(item.workspaceId,item.challengeId)) === item.stamp &&
          typeof artifact?.markdown === 'string' && artifact.markdown) {
        rememberWriteup(item.workspaceId,item.challengeId,item.stamp,artifact.markdown);
      }
    }).catch(() => {}).finally(() => {
      if (item.generation !== writeupPrefetchGeneration) return;
      writeupPrefetchActive--;
      pumpWriteupPrefetch();
    });
  }
}

function observeVisibleWriteups(area, workspaceId) {
  if (typeof IntersectionObserver !== 'function') return;
  if (writeupPrefetchWorkspace !== workspaceId) {
    writeupPrefetchGeneration++;
    writeupPrefetchWorkspace = workspaceId;
    writeupPrefetchQueue = [];
    writeupPrefetchRequested.clear();
    writeupPrefetchActive = 0;
  }
  writeupPrefetchObserver?.disconnect();
  writeupPrefetchObserver = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      writeupPrefetchObserver?.unobserve(entry.target);
      const button = entry.target;
      const challengeId = button.dataset.id, stamp = button.dataset.writeupStamp || '';
      const key = writeupCopyKey(workspaceId,challengeId,stamp);
      if (!challengeId || writeupCopyCache.has(key) || writeupPrefetchRequested.has(key)) continue;
      writeupPrefetchRequested.add(key);
      writeupPrefetchQueue.push({workspaceId,challengeId,stamp,generation:writeupPrefetchGeneration,
        epoch:writeupCopyEpoch.get(writeupIdentity(workspaceId,challengeId)) || 0});
    }
    pumpWriteupPrefetch();
  },{rootMargin:'160px'});
  for (const button of area.querySelectorAll('[data-action="copy-list-writeup"]')) writeupPrefetchObserver.observe(button);
}

// A dirty control ignores the value and selected attributes a morph writes. The morph also
// writes the server's disabled state over a form whose select still shows the user's choice.
function syncChallengeListControls(area) {
  const category = area.querySelector('#category-filter');
  category.value = selectedCategory;
  if (category.selectedIndex < 0) category.selectedIndex = 0;
  area.querySelector('#sort-order').value = selectedSort;
  for (const form of area.querySelectorAll('.challenge-inline-input')) syncInlineInput(form);
}

function morphChallengeListing(area, listing, workspaceId) {
  morphMarkup(area,challengeListingMarkup(listing,workspaceId));
  syncChallengeListControls(area);
}

function clearChallengeFilters() {
  selectedStatus = ''; selectedCategory = ''; selectedSort = 'added_desc'; search = '';
  const area = document.querySelector('#challenge-area');
  area.querySelector('#search-input').value = '';
  syncChallengeListControls(area);
  return refreshChallenges();
}

function paintChallengeListing(result, workspaceId, patchOnly = false) {
  const area = document.querySelector('#challenge-area');
  if (!area || currentWorkspace?.id !== workspaceId) return false;
  const challenges = Array.isArray(result?.challenges) ? result.challenges : [];
  const counts = result?.counts && typeof result.counts === 'object' ? result.counts : {};
  const categories = Array.isArray(result?.categories) ? result.categories : [];
  const total = Object.values(counts).reduce((sum,value) => sum + Number(value || 0),0);
  challengeListing = {workspaceId,result:{challenges,counts,categories}};
  reconcileWriteupCopies(challenges,workspaceId);
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
  // Only the cards: the inline input form inside one carries the same attribute.
  const cards = grid ? [...grid.querySelectorAll(':scope > .challenge-card')] : [];
  const sameCards = cards.length === challenges.length && cards.every((card,index) => card.dataset.challengeId === challenges[index]?.id);
  // An empty state that stays the same is patched too: a morph would rewrite translated text on every poll.
  const emptyState = area.querySelector(':scope > .empty');
  const sameEmpty = emptyState && !challenges.length && Boolean(emptyState.querySelector('[data-action="clear-filter"]')) === total > 0;
  if (!patchOnly || !(grid || sameEmpty) || !sameCards || categoryKey !== challengeListCategories) {
    morphChallengeListing(area,{challenges,counts,categories},workspaceId);
    challengeListSignatures = signatures;
    challengeListCategories = categoryKey;
    observeVisibleWriteups(area,workspaceId);
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
    solverMorphNode(card,replacement);
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
    syncChallengeListControls(area);
    observeVisibleWriteups(area,workspaceId);
    const live = document.querySelector('#challenge-live-state');
    if (live) live.textContent = `문제 ${changed}개의 상태가 갱신되었습니다.`;
  }
  return true;
}

async function copyChallengeWriteup(button) {
  const workspaceId = button.dataset.workspaceId, challengeId = button.dataset.id;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error(i18n.t('문제 목록을 다시 불러와 주세요.'));
  const stamp = button.dataset.writeupStamp || '';
  const identity = writeupIdentity(workspaceId,challengeId);
  const epoch = writeupCopyEpoch.get(identity) || 0;
  const ready = cachedWriteup(workspaceId,challengeId,stamp);
  if (ready !== null) {
    const result = await copyText(ready); copyToast(result,ready);
    return;
  }
  button.disabled = true; button.setAttribute('aria-busy','true');
  try {
    const artifact = await api(`${path(challengeId,workspaceId)}/writeup`);
    if (!currentWorkspace || currentWorkspace.id !== workspaceId || typeof artifact?.markdown !== 'string' || !artifact.markdown) throw new Error(i18n.t('write-up을 다시 불러와 주세요.'));
    if (epoch !== (writeupCopyEpoch.get(identity) || 0)) throw new Error(i18n.t('write-up이 갱신되었습니다. 다시 눌러 주세요.'));
    let expectedUpdatedAt = '';
    try { expectedUpdatedAt = JSON.parse(stamp)[0] || ''; } catch {}
    if (artifact.updated_at && expectedUpdatedAt && artifact.updated_at !== expectedUpdatedAt) {
      invalidateWriteupCopy(workspaceId,challengeId);
      refreshChallenges().catch(() => {});
      showManualCopy(artifact.markdown);
      return;
    }
    rememberWriteup(workspaceId,challengeId,stamp,artifact.markdown);
    // Loading Markdown may outlive the click's clipboard permission. First
    // fetch still presents the exact text; the next click can copy immediately.
    showManualCopy(artifact.markdown);
  } finally {
    if (button.isConnected) { button.disabled = false; button.removeAttribute('aria-busy'); }
  }
}

async function completeListChallenge(button) {
  const workspaceId = button.dataset.workspaceId, challengeId = button.dataset.id;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error(i18n.t('문제 목록을 다시 불러와 주세요.'));
  if (!confirm(i18n.t('“{name}”를 수동 완료로 기록할까요?').replace('{name}',() => button.dataset.name || i18n.t('이 문제')))) return;
  await api(`${path(challengeId,workspaceId)}/complete`,{method:'POST'});
  if (currentWorkspace?.id === workspaceId) await refreshChallenges();
  toast('수동 완료로 기록했습니다.');
}

async function startListSolver(button) {
  const workspaceId = button.dataset.workspaceId, challengeId = button.dataset.id;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error(i18n.t('문제 목록을 다시 불러와 주세요.'));
  requireNoAttachmentWork(workspaceId,challengeId);
  const key = `${workspaceId}:${challengeId}`, name = button.dataset.name;
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
    toast(i18n.t('“{name}” 풀이를 시작했습니다.').replace('{name}',() => name || i18n.t('문제')));
  } finally {
    startingListSolvers.delete(key);
    if (!started && currentWorkspace?.id === workspaceId) refreshChallenges().catch(() => {});
    if (button.isConnected) {
      button.disabled = button.hasAttribute('data-attachment-hold');
      button.removeAttribute('aria-busy');
      button.textContent = previousText;
    }
  }
}

async function continueListSolver(form, data) {
  const workspaceId = form.dataset.workspaceId, challengeId = form.dataset.challengeId;
  if (!currentWorkspace || currentWorkspace.id !== workspaceId) throw new Error(i18n.t('문제 목록을 다시 불러와 주세요.'));
  requireNoAttachmentWork(workspaceId,challengeId);
  const remoteMode = data.remote_mode === 'none' ? 'none' : 'endpoint';
  const remote = remoteMode === 'endpoint' ? String(data.remote || '').trim() : '';
  if (remoteMode === 'none' && form.dataset.originalRemoteMode === 'none' && form.dataset.inputReady !== 'true') {
    throw new Error(i18n.t('요청된 접속 정보나 파일을 먼저 추가하세요.'));
  }
  if (remoteMode === 'endpoint' && !remote) throw new Error(i18n.t('원격 접속 정보를 입력하세요.'));
  const updated = await api(path(challengeId,workspaceId),{
    method:'PATCH',headers:conditional(form.dataset.editToken),body:{remote_mode:remoteMode,remote},
  });
  form.dataset.editToken = updated.edit_token || '';
  const button = form.querySelector('button[type="submit"]');
  button.dataset.id = challengeId; button.dataset.workspaceId = workspaceId; button.dataset.name = form.dataset.name;
  await startListSolver(button);
}

async function refreshChallenges(request = api) {
  if (!currentWorkspace || !document.querySelector('#challenge-area')) return;
  const ticket = ++listRendering, workspaceId = currentWorkspace.id, startedAt = Date.now();
  const params = challengeListParams();
  const result = challengeListResult(await request(`${path(null,workspaceId)}?${params}`));
  if (ticket !== listRendering || currentWorkspace?.id !== workspaceId) return;
  paintChallengeListing(result,workspaceId);
  challengeListUpdated(startedAt);
}

// api() answers {} when a body breaks off, and a timeout does exactly that. It is not an empty list.
function challengeListResult(result) {
  if (!Object.keys(result).length) throw new Error('문제 목록을 다시 불러와 주세요.');
  return result;
}

function challengeListUpdated(startedAt) {
  const workspace = currentWorkspace, now = Date.now();
  workspace.listUpdatedAt = now;
  workspace.listFailures = 0;
  challengeListSlow = now - startedAt >= CHALLENGE_LIST_TIMEOUT;
  if (!workspace.listStaleAt) return;
  workspace.listStaleAt = 0;
  paintLiveNotices();
}

function challengeListFailed() {
  const workspace = currentWorkspace;
  workspace.listFailures = (workspace.listFailures || 0) + 1;
  if (workspace.listFailures < CHALLENGE_LIST_FAILURES_SHOWN || workspace.listStaleAt) return;
  workspace.listStaleAt = Date.now();
  challengeListSlow = true;
  paintLiveNotices();
  // A form has no notice of its own.
  if (modal.open) toast(i18n.t('실시간 갱신이 멈췄습니다.'),true);
}

function scheduleChallengeListPoll(workspaceId, generation, delay = 2000) {
  if (generation !== challengeListPollGeneration || currentWorkspace?.id !== workspaceId || document.visibilityState === 'hidden') return;
  if (challengeListPollTimer !== null) clearTimeout(challengeListPollTimer);
  challengeListPollTimer = setTimeout(() => pollChallengeList(workspaceId,generation),delay);
}

async function pollChallengeList(workspaceId, generation) {
  challengeListPollTimer = null;
  if (generation !== challengeListPollGeneration || currentWorkspace?.id !== workspaceId || document.visibilityState === 'hidden') return;
  const ticket = listRendering, query = challengeListParams().toString(), startedAt = Date.now();
  try {
    // A request that hangs never rejects, so only the timeout lets it count.
    const signal = AbortSignal.timeout?.(challengeListSlow ? CHALLENGE_LIST_SLOW_TIMEOUT : CHALLENGE_LIST_TIMEOUT);
    const result = challengeListResult(await api(`${path(null,workspaceId)}?${query}`,{signal}));
    if (generation !== challengeListPollGeneration || ticket !== listRendering || currentWorkspace?.id !== workspaceId) return;
    if (paintChallengeListing(result,workspaceId,true)) challengeListUpdated(startedAt);
    else await refreshChallenges();
  } catch (error) {
    // A 401 has already opened the login form, and a hidden tab or a new page bumped the generation.
    if (generation !== challengeListPollGeneration || currentWorkspace?.id !== workspaceId) return;
    if (error.status === 404) {
      workspaces = workspaces.filter(workspace => workspace.id !== workspaceId);
      renderWorkspaceNotFound();
    } else challengeListFailed();
  } finally { scheduleChallengeListPoll(workspaceId,generation); }
}

function startChallengeListPolling(workspaceId) {
  stopChallengeListPolling();
  scheduleChallengeListPoll(workspaceId,challengeListPollGeneration);
}

function openModal(title, subtitle, body, footer, formId) {
  pauseStagedUploads();
  if (transferState?.running) { transferState.paused = true; transferState.controller?.abort(); }
  transferState = null;
  transferExportController?.abort(); transferExportController = null;
  if (directInviteTimer !== null) clearTimeout(directInviteTimer);
  directInviteTimer = null; directInviteState = null;
  if (directSendTimer !== null) clearTimeout(directSendTimer);
  directSendTimer = null; directSendState = null;
  ++modalRendering;
  resetChallengeFileDrag();
  modal.removeAttribute('aria-busy');
  modal.dataset.kind = ''; modal.dataset.workspaceId = '';
  modal.innerHTML = `${formId ? `<form id="${formId}">` : ''}<div class="dialog-head"><div><h2 id="modal-title">${esc(title)}</h2>${subtitle ? `<p data-i18n-ignore>${esc(subtitle)}</p>` : ''}</div><button type="button" class="icon-btn icon-action" data-action="close-modal" aria-label="닫기" title="닫기">×</button></div><div class="dialog-body">${body}</div><div class="dialog-foot">${footer || '<button type="button" class="icon-action" data-action="close-modal" aria-label="닫기" title="닫기">×</button>'}</div>${formId ? '</form>' : ''}`;
  modal.setAttribute('aria-labelledby','modal-title');
  const form = modal.querySelector('form');
  if (form) { form.dataset.initial = formSnapshot(form); form.dataset.workspaceId = currentWorkspace?.id || ''; }
  if (!modal.open) modal.showModal();
}

function transferErrorText(error) {
  // fetch() rejects with a browser-specific English TypeError.
  if (error instanceof TypeError) return i18n.t('서버에 연결할 수 없습니다. 연결을 확인하세요.');
  return i18n.t(String(error?.message ?? error ?? ''));
}

function pauseStagedUploads() {
  if (stagedRefreshTimer !== null) clearTimeout(stagedRefreshTimer);
  stagedRefreshTimer = null;
  for (const active of stagedActiveUploads.values()) {
    if (!active.running) continue;
    active.paused = true;
    active.controller.abort();
  }
}

async function showStagedFiles() {
  const workspaceId = currentWorkspace?.id;
  if (!workspaceId) return;
  openModal(i18n.t('사전 파일'), i18n.t('문제 정보가 나오기 전에 파일을 올려두고, 나중에 문제에 연결할 수 있습니다. 사전 파일은 현재 작업공간 ZIP 내보내기·직접 받기에 포함되지 않습니다.'),
    `<div class="staged-files"><label class="challenge-file-target" for="staged-files-input"><span class="challenge-file-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/></svg></span><span><strong>${tr('파일을 여기로 끌어오거나 선택하세요')}</strong><small>${tr('여러 파일을 한 번에 추가할 수 있습니다.')}</small></span></label><input id="staged-files-input" class="sr-only" type="file" multiple><div id="staged-files-summary" class="staged-summary" role="status" aria-live="polite" hidden></div><div id="staged-files-list" class="file-list"></div></div>`,
    `<button type="button" data-action="close-modal">${tr('닫기')}</button>`);
  modal.dataset.kind = 'staged-files';
  modal.dataset.workspaceId = workspaceId;
  await refreshStagedFiles(workspaceId);
}

function addStagedFiles(files, workspaceId) {
  stagedWaiting.set(workspaceId,(stagedWaiting.get(workspaceId) || 0) + files.length);
  // The server takes a non-blocking workspace lock per request, so a second
  // batch dropped during an upload must wait instead of colliding with it.
  const batch = (stagedBatches.get(workspaceId) || Promise.resolve()).catch(() => {}).then(() => uploadStagedBatch(files,workspaceId));
  stagedBatches.set(workspaceId,batch);
  return batch;
}

async function uploadStagedBatch(files, workspaceId) {
  const errors = [];
  let remaining = files.length;
  const leave = count => { remaining -= count; stagedWaiting.set(workspaceId,Math.max(0,(stagedWaiting.get(workspaceId) || 0) - count)); };
  for (const file of files) {
    if (!modal.open || modal.dataset.kind !== 'staged-files' || modal.dataset.workspaceId !== workspaceId) break;
    leave(1);
    try { await uploadStagedFile(file,workspaceId); }
    catch (error) { errors.push(`${file.name}: ${transferErrorText(error)}`); }
  }
  const skipped = remaining;
  leave(skipped);
  await refreshStagedFiles(workspaceId);
  if (skipped) errors.push(i18n.t('대기 중이던 파일 {count}개는 올리지 않았습니다. 사전 파일을 열고 다시 선택하세요.').replace('{count}',skipped));
  if (errors.length) throw new Error(errors.join(' / '));
}

function stagedFileInfo(file, active) {
  const offset = active?.offset ?? file.offset;
  const ready = file.status === 'ready' && file.file_available !== false;
  let body;
  if (file.status === 'verifying') {
    body = `<small>${size(file.size)} · ${tr('전체 파일 SHA-256 확인 중')}</small><progress aria-label="${tr('전체 파일 SHA-256 확인 중')}"></progress>`;
  } else if (file.status === 'uploading') {
    const speed = active?.running && active.speed ? ` · ${size(active.speed)}/s` : '';
    body = `<small>${size(offset)} / ${size(file.size)}${speed} · ${tr(file.verification_error || active?.message || '원본 파일을 다시 선택하면 이어 올립니다.')}</small><progress aria-label="${tr('업로드 진행률')}" max="${Math.max(1,file.size)}" value="${offset}"></progress>`;
  } else {
    body = `<small>${size(file.size)} · ${ready ? tr('준비됨') : tr('원본 파일 확인 필요')} · ${tr('문제 연결')} ${Number(file.linked_count || 0)}</small>`;
    if (file.sha256) body += `<small>${tr('SHA-256 확인됨')}: <code>${esc(file.sha256)}</code></small>`;
    if (ready && file.storage_path) body += `<small>${tr('보관 경로')}: <code>${esc(file.storage_path)}</code></small>`;
  }
  return `<strong data-i18n-ignore>${esc(file.name)}</strong>${body}`;
}

function stagedFileControls(file, workspaceId, active) {
  const id = esc(file.id);
  if (file.status === 'verifying') return '';
  if (file.status !== 'uploading') {
    const ready = file.status === 'ready' && file.file_available !== false;
    return `${ready ? `<a class="button-link" href="/api/workspaces/${encodeURIComponent(workspaceId)}/staged-files/${encodeURIComponent(file.id)}/content" download>${tr('다운로드')}</a>` : ''}<button type="button" class="small danger" data-action="delete-staged-file" data-id="${id}">${tr('삭제')}</button>`;
  }
  const cancel = `<button type="button" class="small danger" data-action="delete-staged-file" data-id="${id}" data-unfinished="true">${tr('업로드 취소')}</button>`;
  if (active?.running) return `<button type="button" class="small" data-action="pause-staged-upload" data-id="${id}">${tr('일시 중지')}</button>${cancel}`;
  const resume = active?.file ? `<button type="button" class="small" data-action="resume-staged-upload" data-id="${id}">${tr('이어 올리기')}</button>` : '';
  const verify = file.size === file.offset ? `<button type="button" class="small" data-action="retry-staged-verification" data-id="${id}">${tr('검증 다시 시도')}</button>` : '';
  return `${resume}${verify}<label class="button-link">${tr('원본 재선택')}<input type="file" data-staged-resume="${id}" class="sr-only"></label>${cancel}`;
}

// Rows are updated in place: rebuilding them on every chunk swaps the button
// under the pointer, so a click on Pause or Cancel could land on nothing.
function paintStagedFiles(list, files, workspaceId) {
  if (!files.length) {
    list.innerHTML = `<p class="muted">${tr('사전 파일이 없습니다.')}</p>`;
    return;
  }
  const rows = files.map(file => {
    let row = list.querySelector(`[data-staged-id="${CSS.escape(file.id)}"]`);
    if (!row) {
      row = document.createElement('div');
      row.className = 'file-item staged-file';
      row.dataset.stagedId = file.id;
      row.innerHTML = '<div class="staged-file-info"></div><div class="actions"></div>';
    }
    const active = stagedActiveUploads.get(file.id);
    const info = stagedFileInfo(file,active), controls = stagedFileControls(file,workspaceId,active);
    if (row._stagedInfo !== info) { row._stagedInfo = info; row.firstElementChild.innerHTML = info; }
    if (row._stagedControls !== controls) { row._stagedControls = controls; row.lastElementChild.innerHTML = controls; }
    return row;
  });
  rows.forEach((row,index) => { if (list.children[index] !== row) list.insertBefore(row,list.children[index] || null); });
  while (list.children.length > rows.length) list.lastElementChild.remove();
}

function paintStagedSummary(workspaceId) {
  const summary = modal.querySelector('#staged-files-summary');
  if (!summary) return;
  const running = [...stagedActiveUploads.values()].filter(active => active.workspaceId === workspaceId && active.running).length;
  const waiting = stagedWaiting.get(workspaceId) || 0;
  const text = [running ? `${i18n.t('업로드 중')} ${running}` : '',waiting ? `${i18n.t('대기 중')} ${waiting}` : ''].filter(Boolean).join(' · ');
  summary.hidden = !text;
  if (summary.textContent !== text) summary.textContent = text;
}

async function refreshStagedFiles(workspaceId, cachedFiles = null) {
  const files = cachedFiles || (await api(`/api/workspaces/${workspaceId}/staged-files`)).files || [];
  stagedFilesCache.set(workspaceId,files);
  if (!modal.open || modal.dataset.kind !== 'staged-files' || modal.dataset.workspaceId !== workspaceId) return files;
  const list = modal.querySelector('#staged-files-list');
  if (!list) return files;
  paintStagedFiles(list,files,workspaceId);
  paintStagedSummary(workspaceId);
  if (stagedRefreshTimer !== null) clearTimeout(stagedRefreshTimer);
  stagedRefreshTimer = files.some(file => file.status === 'verifying')
    ? setTimeout(() => refreshStagedFiles(workspaceId).catch(() => {}), 2000) : null;
  return files;
}

async function stagedRequest(url, options) {
  // Other writers can briefly hold the non-blocking workspace lock.
  for (let attempt = 0; ; attempt++) {
    try { return await api(url,options); }
    catch (error) {
      if (error.status !== 409 || attempt === 3 || options?.signal?.aborted) throw error;
      await new Promise(resolve => setTimeout(resolve,300 * (attempt + 1)));
    }
  }
}

async function uploadStagedFile(file, workspaceId, resumeId = '') {
  if ((!file && !resumeId) || !workspaceId) return false;
  const base = `/api/workspaces/${workspaceId}/staged-files`;
  // The server stores the NFC form of a name; macOS hands the browser NFD.
  const sameSource = item => item.name.normalize('NFC') === file.name.normalize('NFC') && item.size === file.size && item.last_modified === file.lastModified;
  let upload;
  if (resumeId) upload = await api(`${base}/${resumeId}`);
  else {
    const files = await refreshStagedFiles(workspaceId);
    upload = files.find(item => item.status === 'uploading' && sameSource(item));
    if (!upload) upload = await stagedRequest(base,{method:'POST',body:{name:file.name,size:file.size,last_modified:file.lastModified}});
  }
  if (file && !sameSource(upload)) throw new Error(i18n.t('이어 올릴 원본 파일이 다릅니다.'));
  if (upload.status === 'ready') return true;
  const previous = stagedActiveUploads.get(upload.id);
  if (previous?.running) throw new Error(i18n.t('이 파일은 이미 업로드 중입니다.'));
  const source = file || previous?.file || null;
  const active = {file:source,offset:upload.offset,workspaceId,controller:new AbortController(),running:true,paused:false,deleted:false,speed:0,message:'준비 중'};
  stagedActiveUploads.set(upload.id,active);
  let completed = false;
  const paint = () => {
    if (active.deleted) return Promise.resolve();
    const cache = stagedFilesCache.get(workspaceId) || [];
    const index = cache.findIndex(item => item.id === upload.id);
    if (index >= 0) cache[index] = {...cache[index],...upload};
    else cache.push(upload);
    return refreshStagedFiles(workspaceId,cache).catch(() => {});
  };
  await paint();
  try {
    // A paused upload still holds the same File, so only a reselected source needs hashing.
    if (file && upload.offset && previous?.file !== file) {
      active.message = '기존 파일 검증 중'; await paint();
      let start = 0;
      do {
        const manifest = await api(`${base}/${upload.id}/chunks?start=${start}`);
        for (const chunk of manifest.chunks) {
          if (active.paused) return false;
          if (!crypto.subtle) throw new Error(i18n.t('이어 올리기 검증에는 HTTPS가 필요합니다.'));
          const bytes = await file.slice(chunk.offset,chunk.offset + chunk.size).arrayBuffer();
          const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),value => value.toString(16).padStart(2,'0')).join('');
          if (digest !== chunk.sha256) throw new Error(i18n.t('이전 업로드의 원본과 파일 내용이 다릅니다.'));
        }
        start = manifest.next_offset;
      } while (start !== null);
    }
    let sampled = performance.now();
    while (file && upload.offset < file.size) {
      if (active.paused) return false;
      active.message = '전송 중';
      const before = upload.offset;
      const part = file.slice(upload.offset,Math.min(file.size,upload.offset + 8 * 1024 * 1024));
      upload = await stagedRequest(`${base}/${upload.id}/chunks?offset=${upload.offset}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:part,signal:active.controller.signal});
      const now = performance.now(), rate = (upload.offset - before) / Math.max((now - sampled) / 1000,.001);
      active.speed = active.speed ? active.speed * .7 + rate * .3 : rate;
      sampled = now;
      active.offset = upload.offset;
      await paint();
    }
    active.speed = 0;
    active.message = '전체 파일 검증 중'; await paint();
    try { upload = await stagedRequest(`${base}/${upload.id}/finalize`,{method:'POST',signal:active.controller.signal}); }
    catch (error) {
      if (active.paused) return false;
      // A gateway timeout does not necessarily stop the server-side hash.
      upload = await api(`${base}/${upload.id}`);
      if (upload.status !== 'verifying' && upload.status !== 'ready') throw error;
    }
    while (upload.status === 'verifying') {
      if (active.paused) return false;
      active.message = '전체 파일 SHA-256 확인 중'; await paint();
      await new Promise(resolve => setTimeout(resolve, 2000));
      upload = await api(`${base}/${upload.id}`);
    }
    if (upload.status !== 'ready') throw new Error(i18n.t(upload.verification_error || '파일 확인을 마치지 못했습니다. 다시 시도하세요.'));
    completed = true;
    stagedActiveUploads.delete(upload.id);
    await refreshStagedFiles(workspaceId);
    return true;
  } catch (error) {
    if (error.name !== 'AbortError') { active.message = transferErrorText(error); throw error; }
    return false;
  } finally {
    active.running = false;
    active.speed = 0;
    if (active.paused) active.message = '일시 중지됨';
    if (!completed) await paint();
  }
}

function transferFilename(name, scope) {
  const cleaned = String(name || scope).replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').replace(/^[ .]+|[ .]+$/g,'').slice(0,100);
  return `${cleaned || scope}-${scope}.zip`;
}

function showTransferExport(scope) {
  const workspace = currentWorkspace;
  const challenge = scope === 'challenge' ? currentChallenge : null;
  if (!workspace || (scope === 'challenge' && (!challenge || challenge.workspace_id !== workspace.id))) throw new Error(i18n.t('내보낼 자료를 다시 선택하세요.'));
  const name = challenge?.name || workspace.name;
  openModal(i18n.t(scope === 'challenge' ? '문제 ZIP 내보내기' : '작업공간 ZIP 내보내기'), name,
    `<div class="transfer-explainer"><p>${tr('문제 기록, 첨부파일과 읽기 전용 풀이 세션 로그를 ZIP으로 다운로드합니다. 계정, 인증 정보, CTFd 연결과 실행 가능한 세션은 제외됩니다.')}</p><label class="transfer-remote-option"><input id="transfer-include-remote" type="checkbox"><span><strong>${tr('원격 접속 정보 포함')}</strong><small>${tr('서버 주소, URL, 접속 명령을 ZIP에 넣습니다. 필요한 경우에만 선택하세요.')}</small></span></label><p class="form-hint">${tr('설명, 노트와 로그에는 민감한 내용이 있을 수 있습니다. 공유 전에 확인하세요.')}</p><p id="transfer-export-status" class="form-hint" role="status"></p></div>`,
    `<button type="button" data-action="close-modal">${tr('취소')}</button><button type="button" class="primary" data-action="download-transfer">${tr('ZIP 다운로드')}</button>`);
  modal.dataset.kind = 'transfer-export';
  modal.dataset.transferScope = scope;
  modal.dataset.workspaceId = workspace.id;
  modal.dataset.challengeId = challenge?.id || '';
  modal.dataset.transferName = name;
}

async function downloadTransfer() {
  if (modal.dataset.kind !== 'transfer-export' || transferExportController) return;
  const scope = modal.dataset.transferScope, workspaceId = modal.dataset.workspaceId, challengeId = modal.dataset.challengeId;
  const includeRemote = modal.querySelector('#transfer-include-remote')?.checked === true;
  const endpoint = scope === 'challenge'
    ? `${path(challengeId,workspaceId)}/transfer`
    : `/api/workspaces/${workspaceId}/transfer`;
  const url = `${endpoint}?include_remote=${includeRemote}`;
  const filename = transferFilename(modal.dataset.transferName,scope);
  const controller = new AbortController();
  transferExportController = controller;
  const status = modal.querySelector('#transfer-export-status');
  if (status) status.textContent = i18n.t('ZIP을 준비하는 중입니다…');
  try {
    // The File System Access API streams directly to disk. Other browsers use
    // their native download manager, which also avoids buffering the ZIP in JS.
    if (typeof window.showSaveFilePicker !== 'function') {
      const link = document.createElement('a');
      link.href = url; link.download = filename;
      document.body.append(link); link.click(); link.remove();
      if (modal.dataset.kind === 'transfer-export') modal.close();
      toast(i18n.t('ZIP 다운로드를 시작했습니다.'));
      return;
    }
    const handle = await window.showSaveFilePicker({suggestedName:filename,types:[{description:'ZIP archive',accept:{'application/zip':['.zip']}}]});
    if (controller.signal.aborted) return;
    const response = await fetch(url, {
      headers:csrf ? {'X-CSRF-Token':csrf} : {}, credentials:'same-origin', signal:controller.signal,
    });
    if (!response.ok) {
      let payload = {};
      try { payload = await response.json(); } catch {}
      throw new Error(typeof payload.detail === 'string' ? payload.detail : payload.detail?.message || payload.message || `${i18n.t('다운로드에 실패했습니다')} (${response.status}).`);
    }
    if (!response.body) throw new Error(i18n.t('이 브라우저에서는 스트리밍 다운로드를 사용할 수 없습니다.'));
    const writable = await handle.createWritable();
    if (status?.isConnected) status.textContent = i18n.t('ZIP을 디스크에 저장하는 중입니다…');
    await response.body.pipeTo(writable,{signal:controller.signal});
    if (controller.signal.aborted) return;
    if (modal.dataset.kind === 'transfer-export') modal.close();
    toast(i18n.t('ZIP을 저장했습니다.'));
  } catch (error) {
    if (error.name !== 'AbortError') {
      if (status?.isConnected) status.textContent = error.message;
      throw error;
    }
  } finally {
    if (transferExportController === controller) transferExportController = null;
  }
}

function showTransferImport(scope, workspaceId = '') {
  if (scope === 'challenge' && !workspaceId) throw new Error(i18n.t('가져올 작업공간을 먼저 선택하세요.'));
  openModal(i18n.t(scope === 'challenge' ? '문제 ZIP 가져오기' : '작업공간 ZIP 가져오기'),
    scope === 'challenge' ? `${currentWorkspace?.name || i18n.t('작업공간')} · ${i18n.t('새 문제 추가')}` : i18n.t('새 작업공간으로 복원'),
    `<div class="transfer-explainer"><p>${tr(scope === 'challenge' ? '문제 ZIP 한 개를 이 작업공간에 추가합니다.' : '작업공간 ZIP을 새 작업공간으로 가져옵니다.')} ${tr('원본 ID와 무관하게 새 ID가 부여됩니다.')}</p><label>${tr('ZIP 파일')}<input id="transfer-archive" type="file" accept=".zip,application/zip,application/x-zip-compressed"></label><p class="form-hint">${tr('같은 파일을 다시 선택하면 서버에 저장된 지점부터 이어 올릴 수 있습니다.')}</p><div id="transfer-upload-status" class="transfer-upload-status" role="status" aria-live="polite">${tr('ZIP 파일을 선택하세요.')}</div><div id="transfer-preview" class="transfer-preview" hidden></div></div>`,
    `<button type="button" data-action="close-modal">${tr('닫기')}</button><button type="button" class="ghost" data-action="pause-transfer-upload" hidden>${tr('일시 중지')}</button><button type="button" class="danger ghost" data-action="cancel-transfer-upload" hidden>${tr('업로드 취소')}</button><button type="button" data-action="start-transfer-upload" disabled>${tr('업로드 및 미리보기')}</button><button type="button" class="primary" data-action="confirm-transfer-import" hidden>${tr('가져오기')}</button>`);
  // Keep this dialog free of a form so choosing a file does not trigger the
  // unrelated unsaved-edit guard used by workspace and challenge forms.
  modal.dataset.kind = 'transfer-import';
  transferState = {kind:'import',scope,workspaceId,file:null,uploadId:'',storageKey:'',offset:0,preview:null,running:false,importing:false,paused:false,cancelled:false,controller:null};
}

function transferUploadStatus(state, message, offset = state.offset || 0) {
  if (transferState !== state || modal.dataset.kind !== 'transfer-import') return;
  const area = modal.querySelector('#transfer-upload-status');
  const total = state.file?.size || 0;
  if (area) area.innerHTML = `<span>${esc(message)}</span>${total ? `<progress max="${total}" value="${Math.min(total,Math.max(0,offset))}"></progress><small>${esc(size(offset))} / ${esc(size(total))}</small>` : ''}`;
  const start = modal.querySelector('[data-action="start-transfer-upload"]');
  const pause = modal.querySelector('[data-action="pause-transfer-upload"]');
  const cancel = modal.querySelector('[data-action="cancel-transfer-upload"]');
  const confirm = modal.querySelector('[data-action="confirm-transfer-import"]');
  if (start) { start.disabled = !state.file || state.running || state.importing; start.hidden = Boolean(state.preview); start.textContent = i18n.t(state.uploadId ? '이어 올리고 미리보기' : '업로드 및 미리보기'); }
  if (pause) pause.hidden = !state.running;
  if (cancel) { cancel.hidden = !state.uploadId; cancel.disabled = state.importing; }
  if (confirm) { confirm.hidden = !state.preview; confirm.disabled = state.running || state.importing || state.preview?.sufficient_space === false || state.preview?.scope !== state.scope; }
}

async function transferFileIdentity(file) {
  const metadata = `${file.name}:${file.size}:${file.lastModified}`;
  if (!globalThis.crypto?.subtle) return {fingerprint:metadata,sha256:null};
  const full = file.size <= 64 * 1024 * 1024;
  const sampleBytes = 1024 * 1024;
  const bytes = full ? await file.arrayBuffer() : await new Blob([
    file.slice(0,sampleBytes), file.slice(Math.max(0,file.size - sampleBytes)), metadata,
  ]).arrayBuffer();
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),value => value.toString(16).padStart(2,'0')).join('');
  return {fingerprint:digest,sha256:full ? digest : null};
}

function transferStorageKey(state, file, fingerprint) {
  return `ctf-transfer:${sessionUser?.id || 'local'}:${state.scope}:${file.name}:${file.size}:${file.lastModified}:${fingerprint}`;
}

function transferPreviewMarkup(preview, scope) {
  const scopeMismatch = preview.scope !== scope;
  const names = Array.isArray(preview.challenges) ? preview.challenges : [];
  const collisions = Array.isArray(preview.name_collisions) ? preview.name_collisions : [];
  return `<div class="section-head"><h3>${tr('가져오기 미리보기')}</h3><span class="tag ${scopeMismatch ? 'muted' : ''}">${tr(preview.scope === 'challenge' ? '문제' : '작업공간')}</span></div>
    <dl class="transfer-preview-facts"><div><dt>${tr('이름')}</dt><dd data-i18n-ignore>${esc(preview.name)}</dd></div><div><dt>${tr('문제')}</dt><dd>${esc(preview.challenge_count)}</dd></div><div><dt>${tr('첨부파일')}</dt><dd>${esc(preview.attachment_count)} · ${esc(size(Number(preview.attachment_bytes || 0)))}</dd></div><div><dt>${tr('세션 기록')}</dt><dd>${esc(preview.solver_job_count || 0)} · ${tr('이벤트')} ${esc(preview.solver_event_count || 0)}</dd></div><div><dt>${tr('원격 접속 정보')}</dt><dd>${tr(preview.remote_endpoints_included ? '포함됨' : '제외됨')}</dd></div></dl>
    ${scopeMismatch ? `<p class="notice error-notice">${tr(scope === 'challenge' ? '문제 ZIP을 선택하세요.' : '작업공간 ZIP을 선택하세요.')} ${tr(preview.scope === 'challenge' ? '이 파일은 문제 ZIP입니다.' : '이 파일은 작업공간 ZIP입니다.')}</p>` : ''}
    ${preview.sufficient_space === false ? `<p class="notice error-notice">${tr('저장 공간이 부족합니다. 공간을 확보한 뒤 다시 시도하세요.')}</p>` : ''}
    ${collisions.length ? `<p class="notice">${tr('같은 이름이 이미 있습니다:')} <span data-i18n-ignore>${collisions.map(esc).join(', ')}</span>. ${tr('가져온 항목은 새 ID로 추가됩니다.')}</p>` : ''}
    <p class="form-hint">${tr('세션 기록은 읽기 전용 과거 이력으로 가져옵니다. 계정과 인증 정보는 제외됩니다. 설명·노트·로그에는 민감한 내용이 있을 수 있습니다.')}</p>
    ${names.length ? `<details><summary>${tr('문제 목록')} ${names.length}</summary><ul>${names.map(item => `<li><span data-i18n-ignore>${esc(item.name)}</span> <small data-i18n-ignore>${esc(item.category || i18n.t('미분류'))} · ${tr('첨부')} ${esc(item.attachment_count || 0)}</small></li>`).join('')}</ul></details>` : ''}`;
}

async function startTransferUpload() {
  const state = transferState;
  if (!state?.file || state.running || state.importing) return;
  const file = state.file;
  state.running = true; state.paused = false; state.cancelled = false; state.preview = null;
  const controller = new AbortController(); state.controller = controller;
  transferUploadStatus(state,i18n.t('파일 확인 중…'));
  try {
    const identity = await transferFileIdentity(file);
    if (state.paused || transferState !== state) return;
    state.storageKey = transferStorageKey(state,file,identity.fingerprint);
    let savedId = '';
    try { savedId = localStorage.getItem(state.storageKey) || ''; } catch {}
    let upload = null, resumed = false;
    if (savedId) {
      try { upload = await api(`/api/transfers/uploads/${encodeURIComponent(savedId)}`,{signal:controller.signal}); resumed = true; }
      catch (error) {
        if (![404,410].includes(error.status)) throw error;
        try { localStorage.removeItem(state.storageKey); } catch {}
      }
      if (upload && ((upload.size !== undefined && Number(upload.size) !== file.size) || !Number.isSafeInteger(Number(upload.offset)) || Number(upload.offset) < 0 || Number(upload.offset) > file.size)) {
        upload = null; resumed = false;
        try { localStorage.removeItem(state.storageKey); } catch {}
      }
    }
    if (!upload) upload = await api('/api/transfers/uploads',{method:'POST',body:{size:file.size,...(identity.sha256 ? {sha256:identity.sha256} : {})},signal:controller.signal});
    if (state.paused || transferState !== state) return;
    state.uploadId = upload.upload_id || upload.id || (resumed ? savedId : '');
    if (!state.uploadId) throw new Error(i18n.t('서버가 업로드 ID를 반환하지 않았습니다.'));
    try { localStorage.setItem(state.storageKey,state.uploadId); } catch {}
    let offset = Number(upload.offset || 0);
    state.offset = offset;
    transferUploadStatus(state,i18n.t('ZIP 업로드 중…'),offset);
    while (offset < file.size) {
      if (state.paused || transferState !== state) return;
      const chunk = file.slice(offset,Math.min(file.size,offset + TRANSFER_CHUNK_BYTES));
      const result = await api(`/api/transfers/uploads/${encodeURIComponent(state.uploadId)}/chunks?offset=${offset}`,{
        method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:chunk,signal:controller.signal,
      });
      const next = Number(result.offset);
      if (!Number.isSafeInteger(next) || next <= offset || next > file.size) throw new Error(i18n.t('서버가 잘못된 업로드 위치를 반환했습니다.'));
      offset = next;
      state.offset = offset;
      transferUploadStatus(state,i18n.t('ZIP 업로드 중…'),offset);
    }
    if (state.paused || transferState !== state) return;
    transferUploadStatus(state,i18n.t('ZIP 검증 중…'),offset);
    if (!(upload.finalized === true || upload.status === 'finalized')) {
      await api(`/api/transfers/uploads/${encodeURIComponent(state.uploadId)}/finalize`,{method:'POST',signal:controller.signal});
    }
    if (state.paused || transferState !== state) return;
    const query = state.workspaceId ? `?workspace_id=${encodeURIComponent(state.workspaceId)}` : '';
    const result = await api(`/api/transfers/uploads/${encodeURIComponent(state.uploadId)}/preview${query}`,{signal:controller.signal});
    const preview = result.preview || result;
    state.preview = preview;
    const area = modal.querySelector('#transfer-preview');
    if (area) { area.innerHTML = transferPreviewMarkup(preview,state.scope); area.hidden = false; }
    transferUploadStatus(state,i18n.t('업로드를 마쳤습니다. 아래 내용을 확인하고 가져오기를 누르세요.'),file.size);
  } catch (error) {
    if (error.name !== 'AbortError') {
      transferUploadStatus(state,`${i18n.t('오류')}: ${error.message}`);
      throw error;
    }
  } finally {
    state.running = false;
    if (state.controller === controller) state.controller = null;
    if (transferState === state && state.cancelled) transferUploadStatus(state,i18n.t('임시 업로드를 삭제했습니다. 다른 ZIP을 선택할 수 있습니다.'));
    else if (transferState === state && state.paused) transferUploadStatus(state,i18n.t('일시 중지했습니다. 같은 파일을 선택해 이어 올릴 수 있습니다.'));
    else if (transferState === state) transferUploadStatus(state,modal.querySelector('#transfer-upload-status span')?.textContent || i18n.t('ZIP 파일을 선택하세요.'));
  }
}

async function cancelTransferUpload() {
  const state = transferState;
  if (!state || state.importing) return;
  state.paused = true; state.cancelled = true;
  state.controller?.abort();
  const uploadId = state.uploadId;
  if (uploadId) await api(`/api/transfers/uploads/${encodeURIComponent(uploadId)}`,{method:'DELETE'});
  try { if (state.storageKey) localStorage.removeItem(state.storageKey); } catch {}
  state.uploadId = ''; state.offset = 0; state.preview = null;
  const area = modal.querySelector('#transfer-preview');
  if (area) { area.innerHTML = ''; area.hidden = true; }
  transferUploadStatus(state,i18n.t('임시 업로드를 삭제했습니다. 다른 ZIP을 선택할 수 있습니다.'));
}

async function confirmTransferImport() {
  const state = transferState;
  if (!state?.preview || !state.uploadId || state.running || state.importing) return;
  if (state.preview.scope !== state.scope || state.preview.sufficient_space === false) throw new Error(i18n.t('미리보기를 확인하세요.'));
  state.importing = true;
  transferUploadStatus(state,i18n.t('가져오는 중…'),state.file?.size || 0);
  try {
    const result = await api(`/api/transfers/uploads/${encodeURIComponent(state.uploadId)}/import`,{
      method:'POST',body:state.workspaceId ? {workspace_id:state.workspaceId} : {},
    });
    try { if (state.storageKey) localStorage.removeItem(state.storageKey); } catch {}
    const workspaceId = result.workspace_id || state.workspaceId;
    const challengeId = result.challenge_id || result.challenge_ids?.[0];
    modal.close();
    if (state.scope === 'workspace') {
      if (!workspaceId) throw new Error(i18n.t('가져온 작업공간을 찾을 수 없습니다. 화면을 새로고침하세요.'));
      location.hash = `w/${workspaceId}`;
      toast(i18n.t('작업공간 ZIP을 가져왔습니다.'));
    } else {
      if (currentWorkspace?.id === workspaceId) {
        await refreshChallenges();
        if (challengeId) await openChallenge(challengeId);
      } else location.hash = `w/${workspaceId}${challengeId ? `/c/${challengeId}` : ''}`;
      toast(i18n.t('문제 ZIP을 가져왔습니다.'));
    }
  } finally {
    state.importing = false;
    if (transferState === state) transferUploadStatus(state,i18n.t('가져오기를 다시 시도할 수 있습니다.'),state.file?.size || 0);
  }
}

function directInvitationKey(scope, workspaceId) {
  return `ctf-direct-invitation:${sessionUser?.id || 'local'}:${scope}:${workspaceId || 'new'}`;
}

const DIRECT_INVITE_ACTIVE = ['issued','awaiting_approval','uploading'];

function directByteText(value) {
  if (value < 1024) return size(value);
  const exact = Number(value).toLocaleString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US');
  return i18n.locale === 'ko' ? `${size(value)} (${exact}바이트)` : `${size(value)} (${exact} bytes)`;
}

function directInvitationStatus(status) {
  return i18n.t({issued:'보내는 설치 대기',awaiting_approval:'받기 승인 대기',uploading:'전송 중',completed:'가져오기 완료',revoked:'초대 취소됨',expired:'초대 만료됨'}[status] || '상태 확인 중');
}

function directInvitationShown(state) {
  // The status API keeps the stored row after expires_at. Polling continues
  // because an import that started in time can still report completed.
  if (DIRECT_INVITE_ACTIVE.includes(state.status) && (state.expired || (state.expiresAt && state.expiresAt * 1000 <= Date.now()))) return 'expired';
  return state.status;
}

function paintDirectInvitation(state) {
  if (directInviteState !== state || modal.dataset.kind !== 'direct-invite') return;
  const status = modal.querySelector('#direct-invite-status');
  const credentials = modal.querySelector('#direct-invite-credentials');
  const missingToken = modal.querySelector('#direct-invite-missing-token');
  const result = modal.querySelector('#direct-invite-result');
  const offer = modal.querySelector('#direct-invite-offer');
  const progress = modal.querySelector('#direct-invite-progress');
  const total = modal.querySelector('#direct-invite-size');
  const approve = modal.querySelector('[data-action="approve-direct-invitation"]');
  const create = modal.querySelector('[data-action="create-direct-invitation"]');
  const revoke = modal.querySelector('[data-action="revoke-direct-invitation"]');
  const shown = directInvitationShown(state);
  const active = DIRECT_INVITE_ACTIVE.includes(shown);
  if (shown && !active) { state.url = ''; state.token = ''; }
  if (status) {
    const label = shown === 'revoked' && state.rejected ? `${i18n.t('가져오기 거절됨')} · ${i18n.t('보내는 설치의 전송이 중단됩니다.')}` : directInvitationStatus(shown);
    const expiry = active && state.expiresAt ? ` · ${i18n.t('만료 시각')} ${new Date(state.expiresAt * 1000).toLocaleString(i18n.locale === 'ko' ? 'ko-KR' : 'en-US')}` : '';
    status.textContent = state.pending || state.error || (state.invitationId
      ? `${label}${expiry}${state.reconnecting ? ` · ${i18n.t('다시 연결하는 중…')}` : ''}`
      : i18n.t('초대를 발급하면 URL과 토큰을 한 번 표시합니다.'));
    status.classList.toggle('error-text',!state.pending && Boolean(state.error));
  }
  if (credentials) {
    credentials.hidden = !(active && state.url && state.token);
    const url = credentials.querySelector('#direct-invite-url'), token = credentials.querySelector('#direct-invite-token');
    if (url) url.value = state.url || '';
    if (token) token.value = state.token || '';
  }
  if (missingToken) missingToken.hidden = !(state.invitationId && active && !state.token);
  if (offer) {
    offer.hidden = shown !== 'awaiting_approval' || !Number.isSafeInteger(state.size);
    if (!offer.hidden) {
      const zip = offer.querySelector('#direct-invite-offer-zip');
      const extract = offer.querySelector('#direct-invite-offer-extract');
      const attachments = offer.querySelector('#direct-invite-offer-attachments');
      if (zip) zip.textContent = directByteText(state.size);
      if (extract) extract.hidden = !Number.isSafeInteger(state.attachmentBytes);
      if (attachments && extract && !extract.hidden) attachments.textContent = directByteText(state.attachmentBytes);
    }
  }
  // The receiver API reports no received offset, so this bar never claims a percentage.
  if (progress) progress.hidden = shown !== 'uploading';
  if (total) {
    total.hidden = !Number.isSafeInteger(state.size) || !['uploading','completed'].includes(shown);
    if (!total.hidden) total.textContent = `${i18n.t('전송 총 용량')}: ${directByteText(state.size)}${shown === 'uploading' ? ` · ${i18n.t('받은 용량은 보내는 설치 화면에 표시됩니다.')}` : ''}`;
  }
  if (result) {
    result.hidden = shown !== 'completed';
    const imported = state.result || {};
    result.innerHTML = shown === 'completed'
      ? `<p>${tr('대상 설치에서 가져오기를 마쳤습니다.')}</p>${imported.workspace_id ? `<button type="button" data-action="open-direct-result">${tr('가져온 자료 열기')}</button>` : ''}` : '';
  }
  if (create) { create.hidden = Boolean(state.invitationId && (active || !shown)); create.disabled = state.busy; create.textContent = i18n.t(state.invitationId ? '새 초대 발급' : '초대 발급'); }
  if (approve) { approve.hidden = shown !== 'awaiting_approval'; approve.disabled = state.busy || !state.sha256; }
  if (revoke) { revoke.hidden = !state.invitationId || !active; revoke.disabled = state.busy; revoke.textContent = i18n.t(shown === 'awaiting_approval' ? '가져오기 거절' : '초대 취소'); }
}

function applyDirectInvitation(state, result) {
  state.status = result.status || state.status;
  state.expiresAt = result.expires_at || state.expiresAt;
  state.result = result.result || null;
  if ('size' in result) state.size = result.size;
  if ('sha256' in result) state.sha256 = result.sha256 || '';
  if ('attachment_bytes' in result) state.attachmentBytes = result.attachment_bytes;
}

function scheduleDirectInvitation(state) {
  if (directInviteTimer !== null) clearTimeout(directInviteTimer);
  directInviteTimer = null;
  if (directInviteState === state && state.invitationId && (!state.status || DIRECT_INVITE_ACTIVE.includes(state.status))) {
    directInviteTimer = setTimeout(() => pollDirectInvitation(state),4000);
  }
}

function forgetDirectInvitation(state) {
  try { localStorage.removeItem(directInvitationKey(state.scope,state.workspaceId)); } catch {}
  Object.assign(state,{invitationId:'',url:'',token:'',status:'',expiresAt:0,result:null,size:null,sha256:'',attachmentBytes:null,reconnecting:false,expired:false,rejected:false});
  state.error = i18n.t('초대를 찾을 수 없습니다. 새 초대를 발급하세요.');
  paintDirectInvitation(state);
}

async function pollDirectInvitation(state) {
  if (!state.invitationId || directInviteState !== state) return;
  if (directInviteTimer !== null) clearTimeout(directInviteTimer);
  directInviteTimer = null;
  const generation = ++state.pollGeneration;
  try {
    const result = await api(`/api/transfers/direct/invitations/${encodeURIComponent(state.invitationId)}`);
    if (directInviteState !== state || modal.dataset.kind !== 'direct-invite' || state.pollGeneration !== generation) return;
    applyDirectInvitation(state,result);
    state.reconnecting = false;
    const shown = directInvitationShown(state);
    if (shown !== state.lastShown) { state.lastShown = shown; state.error = ''; }
    paintDirectInvitation(state);
  } catch (error) {
    if (directInviteState !== state || state.pollGeneration !== generation) return;
    if (error.status === 404) { forgetDirectInvitation(state); return; }
    state.reconnecting = true;
    paintDirectInvitation(state);
  }
  scheduleDirectInvitation(state);
}

function showDirectInvitation(scope, workspaceId = '') {
  if (scope === 'challenge' && !workspaceId) throw new Error(i18n.t('가져올 작업공간을 먼저 선택하세요.'));
  openModal(i18n.t(scope === 'challenge' ? '문제 직접 받기' : '작업공간 직접 받기'),
    scope === 'challenge' ? `${currentWorkspace?.name || i18n.t('작업공간')} · ${i18n.t('새 문제 추가')}` : i18n.t('새 작업공간으로 복원'),
    `<div class="direct-transfer"><p>${tr('이 설치에서 일회용 초대를 발급한 뒤, 보내는 설치에 URL과 토큰을 입력하세요.')}</p><p class="form-hint">${tr('초대는 1시간 후 만료됩니다. URL과 토큰은 보내는 설치에만 전달하세요.')}</p><div id="direct-invite-status" class="direct-status" role="status" aria-live="polite"></div><div id="direct-invite-offer" class="direct-offer" hidden><dl class="transfer-preview-facts"><div><dt>${tr('전송 총 용량')}</dt><dd id="direct-invite-offer-zip"></dd></div><div id="direct-invite-offer-extract"><dt>${tr('예상 추출 공간 (첨부파일)')}</dt><dd id="direct-invite-offer-attachments"></dd></div></dl><p class="form-hint">${tr('받기를 누르면 저장 공간을 확인하고 전송을 시작합니다.')}</p></div><progress id="direct-invite-progress" aria-label="${tr('전송 중')}" hidden></progress><p id="direct-invite-size" class="form-hint" hidden></p><div id="direct-invite-credentials" class="direct-credentials" hidden><label>${tr('초대 URL')}<input id="direct-invite-url" type="text" readonly></label><button type="button" class="small ghost" data-action="copy-direct-url">${tr('URL 복사')}</button><label>${tr('초대 토큰')}<input id="direct-invite-token" type="text" readonly></label><button type="button" class="small ghost" data-action="copy-direct-token">${tr('토큰 복사')}</button></div><p id="direct-invite-missing-token" class="form-hint" hidden>${tr('이 초대의 토큰은 다시 표시되지 않습니다. 새 초대를 발급하려면 현재 초대를 취소하세요.')}</p><div id="direct-invite-result" class="direct-result" hidden></div></div>`,
    `<button type="button" data-action="close-modal">${tr('닫기')}</button><button type="button" class="danger ghost" data-action="revoke-direct-invitation" hidden>${tr('초대 취소')}</button><button type="button" class="primary" data-action="approve-direct-invitation" hidden>${tr('받기')}</button><button type="button" class="primary" data-action="create-direct-invitation">${tr('초대 발급')}</button>`);
  modal.dataset.kind = 'direct-invite';
  const state = {scope,workspaceId,invitationId:'',url:'',token:'',status:'',expiresAt:0,result:null,size:null,sha256:'',attachmentBytes:null,error:'',pending:'',busy:false,reconnecting:false,expired:false,rejected:false,lastShown:'',pollGeneration:0};
  directInviteState = state;
  const key = directInvitationKey(scope,workspaceId);
  try { state.invitationId = localStorage.getItem(key) || ''; } catch {}
  paintDirectInvitation(state);
  if (state.invitationId) pollDirectInvitation(state);
}

async function createDirectInvitation() {
  const state = directInviteState;
  if (!state || state.busy) return;
  state.busy = true; state.pending = i18n.t('초대 발급 중…'); state.error = ''; paintDirectInvitation(state);
  try {
    const result = await api('/api/transfers/direct/invitations',{
      method:'POST',body:{scope:state.scope,...(state.workspaceId ? {workspace_id:state.workspaceId} : {}),ttl_seconds:3600},
    });
    if (directInviteState !== state) return;
    state.pollGeneration++;
    Object.assign(state,{invitationId:result.invitation_id,url:result.url,token:result.token,status:result.status || 'issued',expiresAt:result.expires_at || 0,result:null,size:null,sha256:'',attachmentBytes:null,error:'',reconnecting:false,expired:false,rejected:false});
    state.lastShown = state.status;
    try { localStorage.setItem(directInvitationKey(state.scope,state.workspaceId),state.invitationId); } catch {}
    paintDirectInvitation(state);
    scheduleDirectInvitation(state);
  } catch (error) {
    error.message = error.code === 'origin_unconfigured'
      ? i18n.t('초대를 발급할 수 없습니다. 관리자에게 CTF_PUBLIC_ORIGIN을 이 설치의 공개 HTTPS 주소로 설정해 달라고 요청하세요.')
      : transferErrorText(error);
    if (directInviteState === state) { state.error = error.message; paintDirectInvitation(state); }
    throw error;
  } finally {
    state.busy = false; state.pending = '';
    if (directInviteState === state) paintDirectInvitation(state);
  }
}

async function approveDirectInvitation() {
  const state = directInviteState;
  if (!state?.invitationId || directInvitationShown(state) !== 'awaiting_approval' || !state.sha256 || state.busy) return;
  state.busy = true; state.error = ''; state.pollGeneration++; paintDirectInvitation(state);
  try {
    let result;
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        result = await api(`/api/transfers/direct/invitations/${encodeURIComponent(state.invitationId)}/approve`,{
          method:'POST',body:{sha256:state.sha256},
        });
        break;
      } catch (error) {
        if (error.code !== 'busy' || attempt === 3) throw error;
        await new Promise(resolve => setTimeout(resolve,200 * (attempt + 1)));
      }
    }
    if (directInviteState !== state) return;
    applyDirectInvitation(state,result);
    state.status = result.status || 'uploading';
    state.lastShown = directInvitationShown(state);
    state.error = '';
    paintDirectInvitation(state);
  } catch (error) {
    error.message = error.status === 507 || error.code === 'low_space'
      ? i18n.t('저장 공간이 부족해 받을 수 없습니다. 공간을 확보한 뒤 다시 받기를 누르거나 거절하세요.')
      : error.code === 'expired' ? i18n.t('초대가 만료되었습니다. 새 초대를 발급하세요.') : transferErrorText(error);
    if (directInviteState === state) {
      if (error.status === 404) forgetDirectInvitation(state);
      else {
        if (error.code === 'expired') state.expired = true;
        state.error = error.message;
        paintDirectInvitation(state);
      }
    } else throw error;
  } finally {
    state.busy = false;
    if (directInviteState === state) { paintDirectInvitation(state); scheduleDirectInvitation(state); }
  }
}

async function revokeDirectInvitation() {
  const state = directInviteState;
  if (!state?.invitationId || state.busy) return;
  const rejecting = directInvitationShown(state) === 'awaiting_approval';
  state.busy = true; state.error = ''; state.pollGeneration++; paintDirectInvitation(state);
  try {
    const result = await api(`/api/transfers/direct/invitations/${encodeURIComponent(state.invitationId)}`,{method:'DELETE'});
    if (directInviteState !== state) return;
    applyDirectInvitation(state,result);
    state.status = result.status || 'revoked';
    state.lastShown = state.status;
    state.rejected = rejecting && state.status === 'revoked';
    state.url = ''; state.token = ''; state.error = ''; state.reconnecting = false;
    // A completed import wins over the cancel; keep it so the result stays reachable.
    if (state.status === 'revoked') { try { localStorage.removeItem(directInvitationKey(state.scope,state.workspaceId)); } catch {} }
    paintDirectInvitation(state);
  } catch (error) {
    error.message = transferErrorText(error);
    if (directInviteState === state && error.status === 404) forgetDirectInvitation(state);
    throw error;
  } finally {
    state.busy = false;
    if (directInviteState === state) { paintDirectInvitation(state); scheduleDirectInvitation(state); }
  }
}

function openDirectResult() {
  const state = directInviteState, result = state?.result;
  if (!result?.workspace_id) return;
  const route = `w/${result.workspace_id}${state.scope === 'challenge' && result.challenge_id ? `/c/${result.challenge_id}` : ''}`;
  modal.close();
  location.hash = route;
}

function directSendStorageKey(state) {
  return ['ctf-direct-send',sessionUser?.id || 'local',state.scope,state.workspaceId,state.challengeId || ''].join(':');
}

function directSendStatusLabel(status) {
  return i18n.t({queued:'대기 중',exporting:'ZIP 생성 중',sending:'서버 간 전송 중',completed:'전송 완료',failed:'전송 실패',cancelled:'전송 취소됨',interrupted:'전송 중단'}[status] || '전송 상태 확인 중');
}

function directSendActive(state) {
  return ['queued','exporting','sending'].includes(state.status);
}

function directSendProgressLabel(state) {
  if (state.status === 'sending') {
    const total = Number(state.size), offset = Number(state.offset) || 0;
    if (!offset) return `${i18n.t('받는 설치의 승인 대기')} · ${i18n.t('받는 쪽에서 받기를 누르면 전송을 시작합니다.')}`;
    if (Number.isSafeInteger(total) && total > 0 && offset >= total) return i18n.t('받는 설치에서 가져오는 중');
  }
  return directSendStatusLabel(state.status);
}

function paintDirectSend(state) {
  if (directSendState !== state || modal.dataset.kind !== 'direct-send') return;
  const status = modal.querySelector('#direct-send-status');
  const progress = modal.querySelector('#direct-send-progress');
  const progressText = modal.querySelector('#direct-send-progress-text');
  const start = modal.querySelector('[data-action="start-direct-send"]');
  const cancel = modal.querySelector('[data-action="cancel-direct-send"]');
  const renew = modal.querySelector('[data-action="new-direct-send"]');
  const active = directSendActive(state);
  if (status) {
    status.textContent = state.error || (state.jobId || state.status !== 'idle'
      ? directSendProgressLabel(state) + (state.cancelRequested && active ? ' · ' + i18n.t('취소 요청 중') : '')
        + (state.status === 'completed' && state.result?.workspace_id ? ' · ' + i18n.t('대상 작업공간 ID') + ': ' + state.result.workspace_id : '')
        + (state.status === 'completed' && state.reused ? ' · ' + i18n.t('이 초대는 이미 완료되어 다시 전송하지 않았습니다.') : '')
        + (state.reconnecting ? ' · ' + i18n.t('다시 연결하는 중…') : '')
      : i18n.t(state.renewed ? '완료된 초대는 다시 사용할 수 없습니다. 받는 설치에서 새 초대를 발급한 뒤 URL과 토큰을 입력하세요.' : '초대 URL과 토큰을 입력한 뒤 전송을 시작하세요.'));
    status.classList.toggle('error-text',Boolean(state.error) || ['failed','interrupted'].includes(state.status));
  }
  const total = Number(state.size);
  if (progress) {
    progress.hidden = !(Number.isSafeInteger(total) && total > 0);
    if (!progress.hidden) { progress.max = total; progress.value = Math.min(total,Math.max(0,Number(state.offset) || 0)); }
  }
  if (progressText) {
    progressText.hidden = progress?.hidden !== false;
    if (!progressText.hidden) progressText.textContent = size(Math.max(0,Number(state.offset) || 0)) + ' / ' + size(total);
  }
  if (start) {
    start.hidden = active || state.status === 'completed' || (Boolean(state.jobId) && state.status === 'idle');
    start.disabled = state.busy;
    start.textContent = i18n.t(['failed','interrupted','cancelled'].includes(state.status) ? '다시 시도' : '전송 시작');
  }
  if (cancel) { cancel.hidden = !active; cancel.disabled = state.busy || state.cancelRequested; }
  if (renew) renew.hidden = state.status !== 'completed' || state.busy;
  // Once, for the token this modal submitted: later text is for the next invitation.
  if (state.status === 'completed' && state.clearToken) {
    state.clearToken = false;
    const tokenInput = modal.querySelector('#direct-send-token');
    if (tokenInput) tokenInput.value = '';
  }
}

async function pollDirectSend(state) {
  if (!state.jobId || directSendState !== state) return;
  if (directSendTimer !== null) clearTimeout(directSendTimer);
  directSendTimer = null;
  // New transfer keeps the state object, so only the id tells a stale answer apart.
  const jobId = state.jobId;
  try {
    const result = await api('/api/transfers/direct/sends/' + encodeURIComponent(jobId));
    if (directSendState !== state || state.jobId !== jobId || modal.dataset.kind !== 'direct-send') return;
    state.reconnecting = false;
    state.status = result.status || state.status;
    state.offset = result.offset || 0;
    state.size = result.size;
    state.result = result.result || null;
    if (result.cancel_requested === true) state.cancelRequested = true;
    state.error = state.status === 'cancelled' || !result.error ? '' : transferErrorText(result.error);
    if (!directSendActive(state)) {
      try { if (state.status !== 'completed') localStorage.removeItem(directSendStorageKey(state)); } catch {}
      state.cancelRequested = false;
    }
    paintDirectSend(state);
  } catch (error) {
    if (directSendState !== state || state.jobId !== jobId) return;
    if (error.status === 404) {
      try { localStorage.removeItem(directSendStorageKey(state)); } catch {}
      state.jobId = '';
      state.status = 'interrupted';
      state.reconnecting = false;
      state.error = i18n.t('전송 작업을 찾을 수 없습니다. 같은 초대 URL과 토큰으로 다시 시도하세요.');
    } else state.reconnecting = true;
    paintDirectSend(state);
  }
  if (directSendState === state && state.jobId && (directSendActive(state) || state.status === 'idle')) {
    directSendTimer = setTimeout(() => pollDirectSend(state),2500);
  }
}

function showDirectSend(scope) {
  const workspace = currentWorkspace, challenge = scope === 'challenge' ? currentChallenge : null;
  if (!workspace || (scope === 'challenge' && (!challenge || challenge.workspace_id !== workspace.id))) throw new Error(i18n.t('보낼 자료를 다시 선택하세요.'));
  openModal(i18n.t(scope === 'challenge' ? '문제 직접 보내기' : '작업공간 직접 보내기'),challenge?.name || workspace.name,
    '<div class="direct-transfer"><p>' + tr('받는 설치에서 직접 받기 초대를 발급하고, 아래에 URL과 토큰을 입력하세요. 파일은 서버 간에 직접 전송됩니다.') + '</p>' +
    '<label>' + tr('초대 URL') + '<input id="direct-send-url" type="url" placeholder="https://" autocomplete="off" spellcheck="false"></label>' +
    '<label>' + tr('초대 토큰') + '<input id="direct-send-token" type="password" autocomplete="off" spellcheck="false"></label>' +
    '<label class="transfer-remote-option"><input id="direct-include-remote" type="checkbox"><span><strong>' + tr('원격 접속 정보 포함') + '</strong><small>' + tr('서버 주소, URL, 접속 명령도 전송합니다. 필요한 경우에만 선택하세요.') + '</small></span></label>' +
    '<p class="form-hint">' + tr('설명과 힌트의 자유 입력 내용은 그대로 전송될 수 있습니다.') + '</p>' +
    '<div id="direct-send-status" class="direct-status" role="status" aria-live="polite"></div>' +
    '<progress id="direct-send-progress" hidden></progress><small id="direct-send-progress-text" class="form-hint" hidden></small></div>',
    '<button type="button" data-action="close-modal">' + tr('닫기') + '</button>' +
    '<button type="button" class="danger ghost" data-action="cancel-direct-send" hidden>' + tr('전송 취소') + '</button>' +
    '<button type="button" class="primary" data-action="new-direct-send" hidden>' + tr('새 전송') + '</button>' +
    '<button type="button" class="primary" data-action="start-direct-send">' + tr('전송 시작') + '</button>');
  modal.dataset.kind = 'direct-send'; modal.dataset.transferScope = scope;
  modal.dataset.workspaceId = workspace.id; modal.dataset.challengeId = challenge?.id || '';
  const state = {scope,workspaceId:workspace.id,challengeId:challenge?.id || '',jobId:'',status:'idle',offset:0,size:null,result:null,error:'',busy:false,cancelRequested:false,reconnecting:false,reused:false,renewed:false,sentUrl:'',clearToken:false};
  directSendState = state;
  try { state.jobId = localStorage.getItem(directSendStorageKey(state)) || ''; } catch {}
  paintDirectSend(state);
  if (state.jobId) pollDirectSend(state);
}

// The head, and the foot on a phone, stay pinned over the scrolling modal, and a plain focus()
// can stop under them. The field must show, then the status, then the field's label. The
// 8 px keep the focus ring clear of the head, unless the status needs them to fit.
function focusDirectSendField() {
  const field = ['#direct-send-url','#direct-send-token'].map(selector => modal.querySelector(selector)).find(input => !input.value.trim());
  (field || modal.querySelector('[data-action="start-direct-send"]')).focus({preventScroll:true});
  const head = modal.querySelector('.dialog-head'), foot = modal.querySelector('.dialog-foot');
  const frame = modal.getBoundingClientRect(), pinned = node => getComputedStyle(node).position === 'sticky';
  const top = pinned(head) ? head.getBoundingClientRect().bottom : frame.top;
  const bottom = pinned(foot) ? foot.getBoundingClientRect().top : frame.bottom;
  const statusBelow = modal.querySelector('#direct-send-status').getBoundingClientRect().bottom - bottom;
  const fieldRoom = field ? field.getBoundingClientRect().top - top : Infinity;
  const labelRoom = field ? field.closest('label').getBoundingClientRect().top - top - 8 : 0;
  modal.scrollTop += Math.min(statusBelow <= fieldRoom ? fieldRoom : fieldRoom - 8,Math.max(statusBelow,Math.min(0,labelRoom)));
}

// The server answers a repeated invitation with its finished job and sends nothing, so the
// spent URL goes. Any other text is for the next invitation: the spent token was cleared on
// completion. The remote option is chosen per send.
function resetDirectSend() {
  const state = directSendState;
  if (!state || modal.dataset.kind !== 'direct-send' || state.busy || state.status !== 'completed') return;
  if (directSendTimer !== null) clearTimeout(directSendTimer);
  directSendTimer = null;
  // Another tab may have started its own job under this key since.
  try { const key = directSendStorageKey(state); if (localStorage.getItem(key) === state.jobId) localStorage.removeItem(key); } catch {}
  const url = modal.querySelector('#direct-send-url'), remote = modal.querySelector('#direct-include-remote');
  if (url?.value.trim() === state.sentUrl) url.value = '';
  if (remote) remote.checked = false;
  Object.assign(state,{jobId:'',status:'idle',offset:0,size:null,result:null,error:'',cancelRequested:false,reconnecting:false,reused:false,renewed:true,sentUrl:''});
  paintDirectSend(state);
  focusDirectSendField();
}

async function startDirectSend(clicks = 0) {
  const state = directSendState;
  if (!state || modal.dataset.kind !== 'direct-send' || state.busy || directSendActive(state)) return;
  const invitationUrl = modal.querySelector('#direct-send-url')?.value.trim() || '';
  const token = modal.querySelector('#direct-send-token')?.value.trim() || '';
  // Start takes New transfer's place under the pointer, so a double click lands here by accident.
  if (state.renewed && (clicks > 1 || (!invitationUrl && !token))) { focusDirectSendField(); return; }
  let url;
  try { url = new URL(invitationUrl); } catch { throw new Error(i18n.t('올바른 HTTPS 초대 URL을 입력하세요.')); }
  if (url.protocol !== 'https:') throw new Error(i18n.t('올바른 HTTPS 초대 URL을 입력하세요.'));
  if (!token) throw new Error(i18n.t('초대 토큰을 입력하세요.'));
  const endpoint = state.scope === 'challenge'
    ? path(state.challengeId,state.workspaceId) + '/transfer/direct'
    : '/api/workspaces/' + state.workspaceId + '/transfer/direct';
  state.busy = true; directSendBusy = true; state.error = i18n.t('전송 작업을 시작하는 중입니다.');
  Object.assign(state,{renewed:false,sentUrl:invitationUrl,clearToken:true});
  paintDirectSend(state);
  try {
    const result = await api(endpoint,{method:'POST',body:{invitation_url:invitationUrl,token,include_remote:modal.querySelector('#direct-include-remote')?.checked === true}});
    if (directSendState !== state) return;
    state.error = '';
    if (result.job_id) {
      state.jobId = result.job_id;
      state.status = result.status || 'queued';
      state.offset = result.offset || 0;
      state.size = result.size;
      state.result = result.result || null;
      state.cancelRequested = false;
      // A new job always starts queued, so 'completed' here is the earlier job of this invitation.
      state.reused = state.status === 'completed';
      try { localStorage.setItem(directSendStorageKey(state),state.jobId); } catch {}
      paintDirectSend(state);
      directSendTimer = setTimeout(() => pollDirectSend(state),1000);
    } else {
      state.status = 'completed';
      state.result = result;
      paintDirectSend(state);
      toast(i18n.t('직접 전송을 마쳤습니다.'));
    }
  } catch (error) {
    error.message = transferErrorText(error);
    if (directSendState === state) {
      state.status = 'failed';
      state.error = i18n.t('전송 실패') + ': ' + error.message;
      paintDirectSend(state);
    }
    throw error;
  } finally {
    state.busy = false; directSendBusy = false;
    if (directSendState === state) paintDirectSend(state);
  }
}

async function cancelDirectSend() {
  const state = directSendState;
  if (!state?.jobId || !directSendActive(state) || state.busy) return;
  state.busy = true; state.cancelRequested = true; paintDirectSend(state);
  try {
    const result = await api('/api/transfers/direct/sends/' + encodeURIComponent(state.jobId),{method:'DELETE'});
    if (directSendState !== state) return;
    state.status = result.status || state.status;
    state.cancelRequested = directSendActive(state);
    state.error = state.status === 'cancelled' || !result.error ? '' : transferErrorText(result.error);
    paintDirectSend(state);
    if (directSendTimer !== null) clearTimeout(directSendTimer);
    directSendTimer = setTimeout(() => pollDirectSend(state),1000);
  } catch (error) {
    error.message = transferErrorText(error);
    state.cancelRequested = false;
    throw error;
  } finally {
    state.busy = false;
    if (directSendState === state) paintDirectSend(state);
  }
}

function workspaceForm(edit = false) {
  const w = edit ? currentWorkspace : {};
  openModal(edit ? '작업공간 설정' : '새 작업공간 만들기', '', `
    <label>작업공간 이름<input name="name" value="${esc(w.name)}" placeholder="예: 2026 가을 CTF" maxlength="160" required autofocus></label>
    <label>설명 <span class="optional">선택 입력</span><textarea name="description" rows="3" placeholder="${tr('대회 일정이나 기억할 내용을 적어 주세요.')}">${esc(w.description)}</textarea></label>
    <label>Flag 형식 <span class="optional">선택 입력</span><input name="flag_format" value="${esc(w.flag_format)}" maxlength="500"><span class="form-hint">접두어만 입력하면 {…} 형식을 적용합니다.</span></label>
    <label class="workspace-option"><input type="checkbox" name="open_challenge_after_create" ${w.open_challenge_after_create ? 'checked' : ''}><span>문제 등록 후 상세창 열기</span></label>
    ${edit ? '<section class="workspace-ctfd-setting"><div><strong>CTFd 연결</strong><small id="workspace-ctfd-status">연결 확인 중</small></div><button type="button" data-action="workspace-ctfd-connection">연결 관리</button></section>' : ''}
    ${edit ? `<section class="workspace-ctfd-setting"><div><strong>${tr('내보내기')}</strong></div><div class="line-actions"><button type="button" data-action="send-workspace-direct">${tr('직접 보내기')}</button><button type="button" data-action="export-workspace-transfer">${tr('ZIP 내보내기')}</button></div></section>` : ''}
    ${edit ? '<div class="danger-zone"><button class="danger small icon-action" type="button" data-action="delete-workspace" aria-label="작업공간 삭제" title="작업공간 삭제">⌫</button></div>' : ''}`, `<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">${edit ? '변경 저장' : '작업공간 만들기'}</button>`, edit ? 'edit-workspace-form' : 'new-workspace-form');
  if (edit) {
    modal.querySelector('form').dataset.editToken = w.edit_token || '';
    const generation = modalRendering;
    api(`/api/workspaces/${w.id}/ctfd/connection`).then(state => {
      if (modal.open && modalRendering === generation && modal.querySelector('#edit-workspace-form')?.dataset.workspaceId === w.id) {
        modal.querySelector('#workspace-ctfd-status').textContent = state.connected
          ? `${state.url} · ${i18n.t(state.auth_type === 'password' ? '아이디·비밀번호' : 'API 토큰')}`
          : '연결 안 됨';
      }
    }).catch(() => {
      if (modal.open && modalRendering === generation) modal.querySelector('#workspace-ctfd-status').textContent = '연결 상태를 확인할 수 없습니다.';
    });
  }
}

function stagedPickerRow(file, challenge) {
  const ready = file.status === 'ready' && file.file_available !== false;
  const stored = ready ? i18n.t('보관 중')
    : file.status === 'ready' ? i18n.t('원본 파일 확인 필요')
    : file.status === 'verifying' ? i18n.t('전체 파일 SHA-256 확인 중')
    : `${i18n.t('업로드 미완료')} ${size(file.offset)} / ${size(file.size)}`;
  const linkedCount = Number(file.linked_count || 0);
  const linked = linkedCount ? i18n.t('문제 {count}개에 연결됨').replace('{count}',linkedCount) : i18n.t('문제에 연결 안 됨');
  const here = (challenge.attachments || []).some(item => item.size === file.size && String(item.original_name).normalize('NFC') === file.name.normalize('NFC'));
  return `<label class="file-item" data-staged-name="${esc(file.name.normalize('NFC').toLocaleLowerCase())}"><input type="checkbox" name="staged_file_ids" value="${esc(file.id)}" data-name="${esc(file.name)}" data-size="${Number(file.size) || 0}" ${ready ? '' : 'disabled'}><span><strong data-i18n-ignore>${esc(file.name)}</strong><small>${size(file.size)} · ${esc(stored)} · ${esc(linked)}</small>${here ? `<small class="staged-attached">${tr('이 문제에 같은 이름·크기의 첨부가 있습니다.')}</small>` : ''}</span></label>`;
}

function stagedPickerMarkup(staged, challenge) {
  const legend = `<legend>${tr('사전 업로드 파일')} <span class="optional">${tr('선택 입력')}</span></legend>`;
  if (!staged) return `<fieldset class="challenge-staged-picker">${legend}<small class="form-hint">${tr('사전 파일 목록을 불러오지 못했습니다.')}</small></fieldset>`;
  const files = staged.files || [];
  if (!files.length) return '';
  const label = i18n.t('사전 파일 검색');
  return `<fieldset class="challenge-staged-picker">${legend}<div class="challenge-staged-tools"><input id="challenge-staged-search" type="search" autocomplete="off" aria-label="${esc(label)}" placeholder="${esc(label)}"><small id="challenge-staged-count" class="form-hint"></small></div><div class="file-list">${files.map(file => stagedPickerRow(file,challenge)).join('')}</div><p id="challenge-staged-empty" class="muted" hidden>${tr('검색 결과가 없습니다.')}</p><small class="form-hint">${tr('같은 파일을 여러 문제에 빠르게 연결할 수 있습니다. 원본을 삭제해도 이미 연결한 첨부는 남습니다. 파일탐색기에서 어느 쪽이든 수정하면 양쪽 내용이 함께 바뀝니다.')}</small></fieldset>`;
}

function bindStagedPicker(form) {
  const search = form.querySelector('#challenge-staged-search');
  if (!search) return;
  const rows = [...form.querySelectorAll('.challenge-staged-picker [data-staged-name]')];
  const count = form.querySelector('#challenge-staged-count'), empty = form.querySelector('#challenge-staged-empty');
  const sync = () => {
    const query = search.value.trim().normalize('NFC').toLocaleLowerCase();
    let visible = 0;
    for (const row of rows) {
      row.hidden = Boolean(query) && !row.dataset.stagedName.includes(query);
      if (!row.hidden) visible++;
    }
    empty.hidden = visible > 0;
    const selected = form.querySelectorAll('input[name="staged_file_ids"]:checked').length;
    count.textContent = selected ? `${i18n.t('선택됨')} ${selected}` : '';
  };
  search.addEventListener('input',sync);
  // Enter here would otherwise submit the whole challenge form.
  search.addEventListener('keydown',event => { if (event.key === 'Enter') event.preventDefault(); });
  form.querySelector('.challenge-staged-picker').addEventListener('change',sync);
  sync();
}

async function challengeForm(edit = false) {
  const c = edit ? currentChallenge : {};
  const remoteMode = c.remote_mode || (c.remote ? 'endpoint' : 'unknown');
  const workspaceId = currentWorkspace?.id;
  const staged = workspaceId ? await api(`/api/workspaces/${workspaceId}/staged-files`).catch(() => null) : {files:[]};
  if (currentWorkspace?.id !== workspaceId) return;
  openModal(edit ? '문제 수정' : '문제 추가', '', `
    <label>문제 이름<input name="name" value="${esc(c.name)}" placeholder="문제 이름을 입력하세요" maxlength="200" required autofocus></label>
    <label>분류 <span class="optional">선택 입력</span><input name="category" value="${esc(c.category)}" placeholder="예: Web, Crypto, Reversing" maxlength="100"></label>
    <label>문제 설명<textarea name="description" rows="5" placeholder="${tr('문제 설명, 접속 정보, 참고 내용을 붙여 넣으세요.')}">${esc(c.description)}</textarea></label>
    <label>원격 대상<select name="remote_mode"><option value="unknown" ${remoteMode === 'unknown' ? 'selected' : ''}>아직 모름 · 풀이 중 요청 가능</option><option value="endpoint" ${remoteMode === 'endpoint' ? 'selected' : ''}>원격 대상 있음</option><option value="none" ${remoteMode === 'none' ? 'selected' : ''}>원격 대상 없음</option></select></label>
    <label data-remote-endpoint>원격 접속 정보<textarea name="remote" rows="2" maxlength="2000" placeholder="${tr('예: nc challenge.example 31337 또는 https://challenge.example/')}">${esc(c.remote)}</textarea></label>
    <label>Flag <span class="optional">선택 입력</span><input name="flag" value="${esc(c.flag)}" placeholder="찾은 Flag를 기록하세요" maxlength="4000"></label>
    ${stagedPickerMarkup(staged,c)}
    ${edit ? '' : `<section class="challenge-file-picker" data-file-drop-zone>
      <div class="challenge-file-heading"><span>문제 파일 <span class="optional">선택 입력</span></span><strong id="challenge-file-summary">여러 파일 · 용량 제한 없음</strong></div>
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
  bindStagedPicker(form);
}

function challengeStatusMarkup(challenge) {
  // A manual completion stays solved whatever the latest solver job ended as.
  const manual = challenge.completion_source === 'manual';
  const solved = manual || challenge.status === 'solved';
  return `<div id="challenge-status-badge">${badge(solved ? 'solved' : challenge.status)}</div>${manual ? '<span class="tag muted">수동 완료됨</span>' : ''}
    ${solved ? '<button data-action="reopen" class="primary">완료 취소</button>' : `<label class="sr-only" for="status-select">기록할 상태</label><select id="status-select">${Object.entries(statuses).filter(([key]) => key !== 'solved').map(([key,label]) => `<option value="${key}" ${challenge.status === key ? 'selected' : ''}>${label}</option>`).join('')}</select><button data-action="complete" class="primary">✓ 수동 완료</button>`}`;
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
    `<div class="file-item related-item"><div><button type="button" class="small ghost" data-action="open-related-challenge" data-id="${esc(item.id)}" data-i18n-ignore>${esc(relatedChallengeLabel(item))}</button><small>${esc(i18n.t(statuses[item.status] || item.status))}${item.evidence_reapproval_required ? ` · ${tr('재확인 필요')}` : item.evidence_stale ? ` · ${tr('공유 자료 재확인 필요')}` : item.evidence_active ? ` · ${tr('검증 자료 공유 중')}` : ''}</small></div>${item.status === 'solved' ? `<button type="button" class="small ghost" data-action="edit-related-evidence" data-id="${esc(item.id)}">${item.evidence_reapproval_required ? tr('재확인') : item.evidence_verified_at ? '공유 수정' : '자료 공유'}</button>` : ''}<button type="button" class="small danger icon-action" data-action="remove-relation" data-id="${esc(item.id)}" aria-label="문제 연결 해제" title="문제 연결 해제">×</button></div>`).join('') : '<p class="muted">없음</p>'}</div>
    ${available.length ? `<div class="related-add"><label class="sr-only" for="related-challenge-select">연결할 문제 선택</label><select id="related-challenge-select"><option value="">문제 선택</option>${available.map(item => `<option value="${esc(item.id)}" data-i18n-ignore>${esc(relatedChallengeLabel(item))}</option>`).join('')}</select><button type="button" class="small ghost" data-action="add-relation">연결</button></div>` : ''}`;
}

function editRelatedEvidence(relatedId) {
  const target = currentChallenge;
  const source = target?.related_challenges?.find(item => item.id === relatedId);
  if (!target || !source || source.status !== 'solved') throw new Error(i18n.t('완료한 연결 문제를 선택하세요.'));
  const flagChoice = source.evidence_can_share_flag
    ? `<label class="related-evidence-flag"><input type="checkbox" name="include_flag" ${source.evidence_include_flag ? 'checked' : ''}>검증된 Flag도 공유</label>` : '';
  const footer = `${source.evidence_verified_at ? '<button type="button" class="danger ghost" data-action="stop-related-evidence">공유 해제</button>' : ''}<button type="button" data-action="close-modal">취소</button><button type="submit" class="primary">공유 저장</button>`;
  openModal('검증 자료 공유', source.name,
    `<label>확인한 관찰<textarea name="observation" maxlength="1200" placeholder="${tr('이 문제와 관련된 검증 사실만 입력하세요.')}">${esc(source.evidence_observation || '')}</textarea></label>${flagChoice}<p class="form-hint">현재 문제의 다음 풀이에만 전달됩니다. 원본 노트와 라이트업은 공유하지 않습니다.</p>`,
    footer, 'related-evidence-form');
  const form = modal.querySelector('#related-evidence-form');
  form.dataset.workspaceId = target.workspace_id;
  form.dataset.challengeId = target.id;
  form.dataset.relatedId = source.id;
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
  if (!currentWorkspace) return;
  rememberNotes();
  stopSolverPolling();
  if (solverConsoleDialog?.open) solverConsoleDialog.close();
  const ticket = ++challengeRendering, workspaceId = currentWorkspace.id;
  const c = await api(path(id,workspaceId));
  if (ticket !== challengeRendering || currentWorkspace?.id !== workspaceId) return;
  rememberNotes();
  replaceKnownWriteup(c);
  const draft = noteDrafts.get(noteKey(c));
  const displayedNotes = draft ? draft.content : c.notes;
  if (draft) { c.notes = draft.baseline; c.notes_token = draft.token; }
  currentChallenge = c;
  detail.setAttribute('aria-labelledby','challenge-title');
  detail.innerHTML = challengeDetailMarkup(c,displayedNotes,Boolean(draft));
  if (!detail.open) detail.showModal();
  detail.scrollTop = 0;
  const report = error => { if (!signedOut) toast(error.message,true); };
  refreshUploads(c.workspace_id,c.id).catch(report);
  loadRelatedChallenges(c).catch(report);
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

function attachmentRowsMarkup(challenge) {
  return challenge.attachments.map(file => {
    const remove = esc(i18n.format('{name} 삭제',{name:file.original_name}));
    return `<div class="file-item"><div><a href="${path(challenge.id,challenge.workspace_id)}/attachments/${esc(file.id)}" target="_blank" rel="noopener" download data-i18n-ignore>${esc(file.original_name)}</a><small>${size(file.size)}</small></div><button class="small danger icon-action" data-action="delete-attachment" data-id="${esc(file.id)}" aria-label="${remove}" title="${remove}">×</button></div>`;
  }).join('');
}

function challengeDetailMarkup(c, displayedNotes, restored) {
  const refreshKey = `${c.workspace_id}:${c.id}`;
  const refreshingFromCTFd = activeCTFdChallengeRefreshes.has(refreshKey);
  const ctfdRefreshButton = c.ctfd_id !== null && c.ctfd_id !== undefined && c.ctfd_url
    ? `<button class="small ghost icon-action" data-action="refresh-ctfd-challenge" aria-label="CTFd 원본에서 문제 새로고침" title="CTFd 원본에서 문제 새로고침" aria-describedby="ctfd-refresh-help" ${refreshingFromCTFd ? 'disabled aria-busy="true"' : ''}>${refreshingFromCTFd ? '…' : '↻'}</button>` : '';
  return `<div class="dialog-head"><div class="detail-heading"><div class="eyebrow" data-i18n-ignore>${esc(c.category || 'CHALLENGE')}</div><h2 id="challenge-title" title="${esc(c.name)}" data-i18n-ignore>${esc(c.name)}</h2><div class="detail-full-name" data-name="${esc(c.name)}" aria-hidden="true"></div><p data-i18n-ignore>${esc(currentWorkspace.name)}</p></div><div class="line-actions"><div class="detail-head-actions">${ctfdRefreshButton}<button class="small" data-action="receive-challenge-direct" title="${tr('이 작업공간에 문제 직접 받기')}">${tr('직접 받기')}</button><button class="small" data-action="send-challenge-direct">${tr('직접 보내기')}</button><button class="small" data-action="import-challenge-transfer" title="${tr('이 작업공간에 문제 ZIP 가져오기')}">${tr('ZIP 가져오기')}</button><button class="small" data-action="export-challenge-transfer">${tr('ZIP 내보내기')}</button><button class="small icon-action" data-action="clone-challenge" aria-label="문제 복제" title="문제 복제">⧉</button><button class="small icon-action" data-action="edit-challenge" aria-label="문제 수정" title="문제 수정">✎</button></div><button class="icon-btn icon-action" data-action="close-detail" aria-label="문제 닫기" title="문제 닫기">×</button></div></div>
    <div class="detail-grid"><div class="detail-main">${c.description ? `<h3>문제 설명</h3><div class="description" data-i18n-ignore>${esc(c.description)}</div>` : ''}
    ${c.remote_mode === 'endpoint' && c.remote ? `<h3>원격 접속 정보</h3><div class="description"><code>${esc(c.remote)}</code></div>` : c.remote_mode === 'none' ? '<span class="tag muted">원격 대상 없음</span>' : '<span class="tag muted">원격 정보 미등록</span>'}
    <div class="section-head"><h3>풀이 노트</h3><span class="tag muted">MARKDOWN</span></div>
    <label class="sr-only" for="notes-editor">Markdown 풀이 노트</label><textarea id="notes-editor" class="notes-editor" spellcheck="false" placeholder="${tr('# 문제 이름\n\n## 풀이 과정\n\n확인한 내용과 풀이 과정을 기록하세요.')}">${esc(displayedNotes)}</textarea>
    <div class="notes-tools"><div class="actions"><button class="icon-action" data-action="upload-notes" aria-label="Markdown 노트 불러오기" title="Markdown 노트 불러오기">⇧</button><button class="icon-action" data-action="copy-notes" aria-label="풀이 노트 복사" title="풀이 노트 복사">⧉</button><button class="icon-action" data-action="download-notes" aria-label="풀이 노트 다운로드" title="풀이 노트 다운로드">⇩</button><button class="icon-action" data-action="reload-notes" aria-label="저장된 풀이 노트 새로고침" title="저장된 풀이 노트 새로고침">↻</button></div><button class="primary" data-action="save-notes">노트 저장</button></div><div class="form-hint${restored ? '' : ' hidden'}" id="notes-save-state" role="status" data-morph-keep>${restored ? '저장하지 않은 작성 내용을 복원했습니다.' : ''}</div><input id="notes-file" type="file" accept=".md,.markdown,.txt" hidden>
    </div><aside class="detail-side"><section><h3>진행 상태</h3><div id="challenge-status-controls">${challengeStatusMarkup(c)}</div></section>
    <section id="solver-panel" class="solver-panel" aria-live="polite" tabindex="-1" data-morph-keep>${solverPanelMarkup(null,[],true)}</section>
    <section><div class="section-head"><h3>Flag</h3><div class="actions"><button id="copy-flag-button" class="small ghost icon-action" data-action="copy-flag" aria-label="Flag 복사" title="Flag 복사" ${c.flag ? '' : 'disabled'}>⧉</button><button class="small ghost icon-action" data-action="edit-challenge" aria-label="Flag 편집" title="Flag 편집">✎</button></div></div><div id="challenge-flag-box" class="flag-box" role="status" aria-live="assertive" tabindex="0" data-i18n-ignore>${esc(c.flag || i18n.t('미등록'))}</div></section>
    ${ctfdRefreshButton ? `<section class="ctfd-source-tools"><div class="section-head"><h3>CTFd 원본</h3></div><p id="ctfd-refresh-help" class="form-hint">CTFd 내용·첨부 갱신 · 로컬 기록 유지</p><div class="actions"><button type="button" class="small ghost" data-action="ctfd-refresh-auth">다시 인증</button><button type="button" class="small ghost" data-action="ctfd-submit-settings">연결 설정</button><button type="button" class="small ghost" data-action="ctfd-job-history">가져오기 기록</button></div></section>` : ''}
    <section id="challenge-relations" data-morph-keep></section>
    <section><h3>첨부파일 <span class="muted">${c.attachments.length}</span></h3><div class="file-list">${attachmentRowsMarkup(c)}</div><div id="upload-progress" data-morph-keep></div><label class="sr-only" for="attachment-files">첨부파일 추가</label><input id="attachment-files" class="file-input" type="file" multiple title="대용량 파일 이어 올리기 지원"></section>
    <section><button class="danger small ghost icon-action" data-action="delete-challenge" aria-label="문제 삭제" title="문제 삭제">⌫</button></section></aside></div>${liveNoticeMarkup()}`;
}

async function cloneChallenge() {
  const source = currentChallenge;
  if (!source || !currentWorkspace) throw new Error(i18n.t('복제할 문제를 다시 불러와 주세요.'));
  const workspaceId = source.workspace_id;
  const cloned = await api(`${path(source.id,workspaceId)}/clone`, {method:'POST'});
  if (currentWorkspace?.id !== workspaceId || currentChallenge !== source) return;
  rememberNotes();
  stopSolverPolling();
  ++challengeRendering;
  detail.close();
  await refreshChallenges();
  toast(i18n.format('“{name}” 문제를 만들었습니다.',{name:cloned.name}));
  if (currentWorkspace?.id === workspaceId && currentWorkspace.open_challenge_after_create) {
    await openChallenge(cloned.id);
  }
}

async function openSolverSession(button) {
  if (!currentWorkspace || !button.dataset.id) throw new Error(i18n.t('풀이 세션을 다시 불러와 주세요.'));
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
  // Start the browser clipboard request in the click's user activation.
  // execCommand('copy') can report true while leaving the clipboard unchanged.
  if (window.isSecureContext !== false && typeof navigator.clipboard?.writeText === 'function') {
    let timeout;
    try {
      const writing = navigator.clipboard.writeText(value);
      await Promise.race([
        writing,
        new Promise((_,reject) => { timeout = setTimeout(() => reject(new Error(i18n.t('클립보드 응답이 지연되었습니다.'))), 1200); }),
      ]);
      return 'unverified';
    } catch { /* Keep a selectable copy when permission is denied or delayed. */ }
    finally { clearTimeout(timeout); }
  }
  showManualCopy(value);
  return 'manual';
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

function replaceSolverPanelPreservingConfiguration(panel, markup, preserveLog = false) {
  const painted = panel._solverPainted;
  if (preserveLog && painted?.markup === markup && painted.head?.parentNode === panel) return;
  if (!preserveLog) panel.querySelector(':scope > .solver-session-log')?.remove();
  const template = document.createElement('template');
  template.innerHTML = markup;
  // The native selects stay in the live DOM: detaching one closes an open menu.
  solverMorphChildren(panel,template.content);
  panel._solverPainted = {markup,head:panel.firstElementChild};
}

function paintSolver(job, events, workspaceId, challengeId, generation, guidance = []) {
  if (!solverContext(workspaceId,challengeId,generation)) return;
  let refreshDashboard = false;
  const panel = document.querySelector('#solver-panel');
  const previousJobId = solverJobId(currentSolverJob);
  const nextJobId = solverJobId(job);
  if (previousJobId && nextJobId && previousJobId !== nextJobId) {
    currentSolverEvents = [];
    currentSolverGuidance = [];
    solverEventCursor = 0;
    // A draft belongs to the run it was written for, never to its replacement.
    const consoleInput = solverConsoleDialog?.querySelector('#solver-console-message');
    if (solverGuidanceDraft || consoleInput?.value) toast('실행이 바뀌어 작성 중이던 추가 명령을 지웠습니다.');
    solverGuidanceDraft = '';
    if (consoleInput) consoleInput.value = '';
    solverConsoleAgentId = 'root'; solverConsoleFollowLatest = true; solverCollapsedAgentIds.clear(); solverConsoleCardStates.clear();
  }
  currentSolverJob = job;
  currentSolverEvents = mergeSolverEvents(currentSolverEvents,events,solverEventLimit(panel,events.length));
  currentSolverGuidance = mergeSolverGuidance(currentSolverGuidance,guidance);
  solverEventCursor = Math.max(solverEventCursor,...currentSolverEvents.map(solverEventSequence));
  const reportedCursor = Number(job?.event_cursor);
  if (Number.isSafeInteger(reportedCursor) && reportedCursor >= 0) solverEventCursor = Math.max(solverEventCursor,reportedCursor);
  panel.querySelector(':scope > .solver-poll-warning')?.remove();
  const previousLog = panel.querySelector('.solver-session-log');
  const sameLog = Boolean(previousLog && previousJobId === nextJobId);
  const active = solverIsActive(job);
  const logKey = `${nextJobId}:${currentSolverEvents.length}:${solverEventSequence(currentSolverEvents[currentSolverEvents.length - 1])}:${active}`;
  // Layout reads and log work are skipped entirely on a poll that changed nothing.
  const logChanged = !sameLog || panel.dataset.solverLogKey !== logKey;
  const previousConsole = logChanged ? panel.querySelector('.solver-live-console') : null;
  const previousScroll = Number(previousConsole?.scrollTop || 0);
  const followLatest = !previousConsole || Number(previousConsole.scrollHeight || 0) - previousScroll - Number(previousConsole.clientHeight || 0) < 32;
  const rowSelector = '.solver-events > li[data-event-sequence]';
  const anchors = sameLog && previousConsole && !followLatest ? solverReadingAnchors(previousConsole,rowSelector,row => row.dataset.eventSequence) : [];
  replaceSolverPanelPreservingConfiguration(panel,solverPanelMarkup(job,sameLog ? [] : currentSolverEvents),sameLog);
  if (logChanged) {
    const nextConsole = panel.querySelector('.solver-live-console');
    const nextLog = panel.querySelector('.solver-session-log');
    if (nextLog && nextLog === previousLog) reconcileCompactSolverLog(nextLog,currentSolverEvents,active);
    if (nextConsole) {
      if (followLatest) nextConsole.scrollTop = nextConsole.scrollHeight;
      else if (anchors.length) restoreSolverReadingAnchors(nextConsole,rowSelector,'data-event-sequence',anchors);
      else nextConsole.scrollTop = previousScroll;
    }
    panel.dataset.solverLogKey = logKey;
  }
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
      refreshDashboard = true;
    }
  }

  const completedStatus = currentChallenge.status === 'solved' || currentChallenge.completion_source === 'agent'
    ? 'solved' : job.flag ? 'flag_found' : null;
  const manual = currentChallenge.completion_source === 'manual' && !solverIsActive(job);
  const status = manual || job.flag_rejected ? null : job.phase === 'completed' ? completedStatus : job.flag ? 'flag_found'
    : ['cancelled','needs_input'].includes(job.phase) ? 'stopped' : ['failed','refused'].includes(job.phase) ? 'failed'
      : ['queued','staging','awaiting_credential','validating','running','writing','cleanup_blocked'].includes(job.phase) ? 'running' : null;
  if (status) {
    const changed = currentChallenge.status !== status;
    currentChallenge.status = status;
    if (changed) refreshDashboard = true;
    const controls = document.querySelector('#challenge-status-controls');
    if (changed && controls) controls.innerHTML = challengeStatusMarkup(currentChallenge);
    else {
      const holder = document.querySelector('#challenge-status-badge');
      if (holder) holder.innerHTML = badge(status);
    }
  }

  if (refreshDashboard) refreshChallenges().catch(() => {});

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
  replaceKnownWriteup(latest);
  if (editorWasSaved && editor && typeof latest.notes === 'string') editor.value = latest.notes;
  rememberNotes();
  const state = document.querySelector('#notes-save-state');
  if (state) {
    state.classList?.remove('hidden');
    state.textContent = editorWasSaved
      ? 'write-up을 풀이 노트에 반영했습니다.'
      : 'write-up을 저장했습니다. 작성 중인 노트는 유지됩니다.';
  }
  const controls = document.querySelector('#challenge-status-controls');
  if (controls) controls.innerHTML = challengeStatusMarkup(currentChallenge);
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
    if (!normalized.job) throw new Error(i18n.t('풀이 실행 상태 응답을 확인할 수 없습니다.'));
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
    if (!solverIsActive(normalized.job) && (
      solverOptionsState === 'idle' || solverConfigurationJobId !== solverJobId(normalized.job)
    )) {
      await loadSolverConfiguration(workspaceId,challengeId,generation,'',normalized.job);
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
  if (!panel) return;
  const current = panel.querySelector(':scope > .solver-configuration');
  if (!current) {
    panel.innerHTML = solverPanelMarkup(currentSolverJob,currentSolverEvents);
    return;
  }
  const template = document.createElement('template');
  template.innerHTML = solverProviderSelector();
  const next = template.content.querySelector('.solver-configuration');
  if (!next) return;
  const focused = current.contains(document.activeElement) ? document.activeElement.closest('label') : null;
  const nextFocused = focused?.querySelector('[id]')?.id
    ? next.querySelector(`[id="${focused.querySelector('[id]').id}"]`)?.closest('label') : null;
  if (focused?.parentElement === current && nextFocused?.parentElement === next) {
    // Reconcile the other fields while an open select and its label stay put.
    const children = Array.from(next.children);
    const index = children.indexOf(nextFocused);
    while (current.firstChild && current.firstChild !== focused) current.firstChild.remove();
    while (focused.nextSibling) focused.nextSibling.remove();
    for (const child of children.slice(0,index)) current.insertBefore(child,focused);
    for (const child of children.slice(index + 1)) current.append(child);
  } else if (!focused) current.replaceWith(next);
  // A focused field absent from the new state updates when focus leaves.
  panel.querySelectorAll('[data-action="start-solver"]').forEach(button => {
    button.disabled = !solverConfigurationReady() || button.hasAttribute('data-attachment-hold');
  });
}

async function loadSolverConfiguration(workspaceId, challengeId, generation, preferredAccountId = '', retryJob = null) {
  const ticket = ++solverOptionsGeneration;
  const retry = solverRetryConfiguration(retryJob);
  const issues = [];
  solverConfigurationJobId = solverJobId(currentSolverJob);
  clearSolverRetryWarning();
  if (retry) solverProvider = retry.provider;
  solverOptionsState = 'loading'; solverOptionsError = '';
  repaintSolverConfiguration(workspaceId,challengeId,generation);
  try {
    const payload = await api('/api/accounts');
    if (!solverContext(workspaceId,challengeId,generation) || ticket !== solverOptionsGeneration) return;
    solverAccounts = Array.isArray(payload?.accounts) ? payload.accounts.filter(account => account && typeof account.id === 'string') : [];
    const available = solverAccounts.filter(account => account.provider === solverProvider && account.snapshot?.status === 'authenticated');
    if (retry) {
      const previous = solverAccounts.find(item => item.id === retry.accountId);
      const label = retry.accountLabel || i18n.t('이전 계정');
      if (!retry.accountId) issues.push(['이전 실행 계정을 식별할 수 없습니다.']);
      else if (!previous || previous.provider !== retry.provider) issues.push(['이전 실행 계정({label})을 찾을 수 없습니다.',{label}]);
      else if (previous.snapshot?.status !== 'authenticated') issues.push(['이전 실행 계정({label})에 다시 로그인해야 합니다.',{label}]);
    }
    const preferred = preferredAccountId || retry?.accountId || solverAccountId;
    const account = available.find(item => item.id === preferred)
      || available.find(item => item.selected === true)
      || available[0]
      || null;
    solverAccountId = account?.id || '';
    solverModels = []; solverModel = ''; solverReasoning = ''; solverServiceTier = null; solverUltracode = false;
    if (!account) {
      solverRetryIssues = issues;
      solverRetryRequiresSelection = issues.length > 0;
      solverOptionsState = 'ready';
      repaintSolverConfiguration(workspaceId,challengeId,generation);
      return;
    }
    const catalog = await api(`/api/accounts/${encodeURIComponent(account.id)}/models`);
    if (!solverContext(workspaceId,challengeId,generation) || ticket !== solverOptionsGeneration) return;
    if (catalog?.status !== 'available' || !Array.isArray(catalog.models)) throw new Error(i18n.t('선택한 계정의 모델 목록을 사용할 수 없습니다.'));
    solverModels = catalog.models.filter(item => item && typeof (item.model || item.id) === 'string');
    const chosen = solverModels.find(item => (item.model || item.id) === (retry?.model || account.model))
      || solverModels.find(item => (item.model || item.id) === account.model)
      || solverModels.find(item => item.isDefault === true || item.default === true)
      || solverModels[0]
      || null;
    solverModel = chosen ? (chosen.model || chosen.id) : '';
    if (retry?.model && solverModel !== retry.model) issues.push(['이전 모델({label})을 현재 계정에서 사용할 수 없습니다.',{label:retry.model}]);
    const efforts = Array.isArray(chosen?.supportedReasoningEfforts)
      ? chosen.supportedReasoningEfforts.map(item => item?.reasoningEffort).filter(Boolean) : [];
    solverReasoning = retry?.reasoning && efforts.includes(retry.reasoning) ? retry.reasoning
      : efforts.includes(account.reasoning_effort) ? account.reasoning_effort
      : efforts.includes(chosen?.defaultReasoningEffort) ? chosen.defaultReasoningEffort
      : efforts[0] || '';
    if (retry?.reasoning && solverReasoning !== retry.reasoning) issues.push(['이전 추론 수준({label})을 현재 모델에서 사용할 수 없습니다.',{label:retry.reasoning}]);
    const tiers = Array.isArray(chosen?.serviceTiers) ? chosen.serviceTiers.map(item => item?.id).filter(Boolean) : [];
    solverServiceTier = retry ? (retry.serviceTier === 'fast' && tiers.includes('fast') ? 'fast' : null)
      : account.service_tier === 'fast' && tiers.includes('fast') ? 'fast' : null;
    if (retry?.serviceTier === 'fast' && solverServiceTier !== 'fast') issues.push(['이전 Fast 티어를 현재 모델에서 사용할 수 없습니다.']);
    solverUltracode = solverProvider === 'claude' && chosen?.supportsUltracode === true
      && (retry ? retry.ultracode : (chosen.model || chosen.id) === account.model && account.ultracode === true);
    if (retry?.ultracode && !solverUltracode) issues.push(['이전 Ultracode 설정을 현재 모델에서 사용할 수 없습니다.']);
    if (retry) {
      solverUltraEscalationMode = ['ask','auto','off'].includes(retry.ultraEscalationMode) ? retry.ultraEscalationMode : 'off';
      if (solverUltraEscalationMode !== 'off' && !solverUltraEscalationEligible()) {
        issues.push(['이전 Ultra 전환 설정을 현재 모델에서 사용할 수 없습니다.']);
      }
    }
    solverRetryIssues = issues;
    solverRetryRequiresSelection = issues.length > 0;
    solverOptionsState = 'ready';
  } catch (error) {
    if (!solverContext(workspaceId,challengeId,generation) || ticket !== solverOptionsGeneration) return;
    solverModels = []; solverModel = ''; solverReasoning = ''; solverServiceTier = null; solverUltracode = false;
    solverOptionsState = 'error';
    solverOptionsError = error.message || '계정 설정을 불러오지 못했습니다.';
    solverRetryIssues = issues;
    solverRetryRequiresSelection = issues.length > 0;
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
      if (!solverIsActive(normalized.job)) await loadSolverConfiguration(workspaceId,challengeId,generation,'',normalized.job);
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
  requireNoAttachmentWork(workspaceId,challengeId);
  if (!solverConfigurationReady()) throw new Error(i18n.t('로그인된 계정과 모델·추론 수준을 선택해 주세요.'));
  if (solverPollTimer) clearTimeout(solverPollTimer);
  const generation = ++solverRendering;
  solverPollTimer = null; currentSolverJob = null; currentSolverEvents = []; currentSolverGuidance = []; solverEventCursor = 0; solverGuidanceDraft = ''; solverListedFlag = ''; solverSyncedWriteup = '';
  solverConsoleAgentId = 'root'; solverConsoleFollowLatest = true; solverCollapsedAgentIds.clear(); solverConsoleCardStates.clear();
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
    if (!normalized.job) throw new Error(i18n.t('풀이 실행을 시작했지만 상태 응답을 확인할 수 없습니다.'));
    paintSolver(normalized.job,normalized.events,workspaceId,challengeId,generation,normalized.guidance);
    const id = solverJobId(normalized.job);
    if (id && solverIsActive(normalized.job)) await pollSolverJob(id,workspaceId,challengeId,generation);
    else if (!solverIsActive(normalized.job)) await loadSolverConfiguration(workspaceId,challengeId,generation,'',normalized.job);
  } catch (error) {
    if (solverContext(workspaceId,challengeId,generation)) panel.innerHTML = `${solverPanelMarkup(null)}${solverErrorMarkup(error)}`;
    throw error;
  }
}

async function approveUltraEscalation() {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || job?.error?.code !== 'ultra_escalation_requested' || !job?.ultra_escalation?.eligible) return;
  const workspaceId = currentWorkspace?.id, challengeId = currentChallenge?.id, generation = solverRendering;
  requireNoAttachmentWork(workspaceId,challengeId);
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/ultra-escalate`,{method:'POST'});
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const normalized = normalizeSolverPayload(payload);
  if (!normalized.job) throw new Error(i18n.t('Ultra 작업 상태를 확인할 수 없습니다.'));
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
  if (typeof latest.writeup_markdown !== 'string' || !latest.writeup_markdown) throw new Error(i18n.t('보완된 write-up을 확인할 수 없습니다. 기존 write-up은 유지했습니다.'));
  const editorWasSaved = Boolean(editor && editor.value === savedNotes);
  currentChallenge.writeup_markdown = latest.writeup_markdown;
  currentChallenge.writeup_updated_at = latest.writeup_updated_at;
  currentChallenge.has_writeup = true;
  replaceKnownWriteup(latest);
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
  if (!normalized.job) throw new Error(i18n.t('write-up 보완 작업 상태를 확인할 수 없습니다.'));
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
  if (!writeupRefinementEligible(challenge)) throw new Error(i18n.t('완료된 write-up만 보완할 수 있습니다.'));
  if (!solverConfigurationReady()) throw new Error(i18n.t('계정·모델·추론 수준을 선택해 주세요.'));
  if (solverIsActive(writeupRefineJob)) return;
  const workspaceId = challenge.workspace_id, challengeId = challenge.id, generation = solverRendering;
  const input = document.querySelector('#writeup-refine-instruction');
  writeupRefineInstruction = normalizeWriteupRefinementInstruction(input ? input.value : writeupRefineInstruction);
  writeupRefineError = null;
  const body = {provider:solverProvider,account_id:solverAccountId,model:solverModel,reasoning_effort:solverReasoning,service_tier:solverServiceTier,ultracode:solverUltracode,writeup_locale:i18n.locale};
  try {
    if (writeupRefinementInstructionBytes(writeupRefineInstruction) > writeupRefinementInstructionLimit) {
      const error = new Error(i18n.t('추가 요청은 UTF-8 기준 12 KiB 이하로 입력하세요.'));
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
  if (!await siteConfirm('write-up 보완을 중단할까요?', 'write-up 보완 중단', '중단')) return;
  if (solverJobId(writeupRefineJob) !== jobId || !solverIsActive(writeupRefineJob)) return;
  const workspaceId = currentWorkspace.id, challengeId = currentChallenge.id, generation = solverRendering;
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/cancel`,{method:'POST'});
  if (!solverContext(workspaceId,challengeId,generation)) return;
  await acceptWriteupRefinement(payload,workspaceId,challengeId,generation);
  if (writeupRefineJob?.phase !== 'completed') toast(writeupRefineJob?.phase === 'cancelled' ? 'write-up 보완을 중단했습니다.' : 'write-up 보완 중단을 요청했습니다.');
}

async function cancelSolver(button) {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || !solverIsActive(job)) return;
  if (!await siteConfirm('현재 풀이를 중단할까요? 발견한 Flag와 저장된 결과는 유지됩니다.', '풀이 중단', '중단')) return;
  if (solverJobId(currentSolverJob) !== jobId || !solverIsActive(currentSolverJob)) return;
  const workspaceId = currentWorkspace.id, challengeId = currentChallenge.id, generation = solverRendering;
  if (button) button.disabled = true;
  let payload;
  try { payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/cancel`,{method:'POST'}); }
  catch (error) { if (button) button.disabled = false; throw error; }
  if (!solverContext(workspaceId,challengeId,generation)) return;
  const normalized = normalizeSolverPayload(payload);
  paintSolver(normalized.job || {...job,phase:'cancelled',terminal:true},normalized.events.length ? normalized.events : currentSolverEvents,workspaceId,challengeId,generation,normalized.guidance);
  if (normalized.job && solverIsActive(normalized.job)) scheduleSolverPoll(normalized.job,workspaceId,challengeId,generation);
  toast('풀이 중단을 요청했습니다.');
}

async function sendSolverGuidance(value, requestedDelivery = 'same_turn', {expectedJobId = '', keepDraft = false} = {}) {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (expectedJobId && expectedJobId !== jobId) throw new Error(i18n.t('풀이 실행이 바뀌었습니다. 내용을 확인한 뒤 다시 보내세요.'));
  if (!jobId || !solverIsActive(job)) throw new Error(i18n.t('진행 중인 풀이 세션이 없습니다.'));
  if (job.guidance_allowed === false) throw new Error(i18n.t('현재 풀이 단계에는 추가 명령을 보낼 수 없습니다.'));
  const message = String(value ?? '').replace(/\r\n?/g,'\n').trim();
  if (!message) throw new Error(i18n.t('추가 명령을 입력하세요.'));
  if (new TextEncoder().encode(message).byteLength > 16 * 1024) throw new Error(i18n.t('추가 명령은 UTF-8 기준 16 KiB 이하여야 합니다.'));
  const workspaceId = currentWorkspace?.id, challengeId = currentChallenge?.id, generation = solverRendering;
  if (!workspaceId || !challengeId || !solverContext(workspaceId,challengeId,generation)) throw new Error(i18n.t('풀이 화면을 다시 열어 주세요.'));
  if (!keepDraft) solverGuidanceDraft = message;
  const payload = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/guidance`,{method:'POST',body:{message,requested_delivery:requestedDelivery}});
  if (!solverContext(workspaceId,challengeId,generation) || solverJobId(currentSolverJob) !== jobId) return;
  // A system-generated message leaves what the user is still typing alone.
  if (!keepDraft) {
    solverGuidanceDraft = '';
    for (const input of document.querySelectorAll('#solver-guidance-message,#solver-console-message')) input.value = '';
  }
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

async function openSolverPeerEvidence() {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || !solverIsActive(job)) throw new Error(i18n.t('진행 중인 풀이가 없습니다.'));
  const workspaceId = currentWorkspace?.id, challengeId = currentChallenge?.id;
  const result = await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/peers`);
  if (currentWorkspace?.id !== workspaceId || currentChallenge?.id !== challengeId || solverJobId(currentSolverJob) !== jobId) return;
  const peers = Array.isArray(result?.peers) ? result.peers.filter(peer => peer?.job_id && peer.job_id !== jobId) : [];
  if (!peers.length) { toast(i18n.t('함께 푸는 복제 문제가 없습니다.')); return; }
  const options = peers.map(peer => {
    const model = typeof peer.model === 'string' ? peer.model : peer.model?.model || '';
    const label = [peer.challenge_name || peer.challenge_id, model, peer.reasoning_effort, peer.status].filter(Boolean).join(' · ');
    return `<option value="${esc(peer.job_id)}" data-i18n-ignore>${esc(label)}</option>`;
  }).join('');
  const shares = Array.isArray(result?.shares) ? result.shares.slice(-5) : [];
  const history = shares.length ? `<ul class="solver-peer-history">${shares.map(item => `<li><span data-i18n-ignore>${esc(item.observation || '')}</span><small>${esc(i18n.t(item.delivery_status || ''))}</small></li>`).join('')}</ul>` : '';
  const claude = (job.provider || job.configuration?.provider || job.model?.provider) === 'claude';
  openModal(i18n.t('공동 풀이 자료'), currentChallenge?.name || '',
    `<label>${tr('자료 출처')}<select name="source_job_id" required>${options}</select></label>
     <label>${tr('확인한 관찰')}<textarea name="observation" rows="4" maxlength="1200" required placeholder="${esc(i18n.t('다른 풀이에서 재현한 사실이나 명령 결과를 입력하세요.'))}"></textarea></label>
     <label>${tr('전달 시점')}<select name="requested_delivery"><option value="${claude ? 'next_turn' : 'same_turn'}">${tr(claude ? '다음 응답' : '현재 응답')}</option>${claude ? '' : `<option value="next_turn">${tr('다음 응답')}</option>`}</select></label>
     ${history}`,
    `<button type="button" data-action="close-modal">${tr('취소')}</button><button type="submit" class="primary">${tr('전달')}</button>`,
    'solver-peer-evidence-form');
  const form = modal.querySelector('#solver-peer-evidence-form');
  form.dataset.jobId = jobId;
  form.dataset.challengeId = challengeId;
}

async function sendSolverPeerEvidence(form, body) {
  const jobId = form.dataset.jobId;
  if (!jobId || solverJobId(currentSolverJob) !== jobId || currentChallenge?.id !== form.dataset.challengeId || !solverIsActive(currentSolverJob)) {
    throw new Error(i18n.t('풀이가 변경됐습니다. 다시 확인해 주세요.'));
  }
  await api(`/api/solver/jobs/${encodeURIComponent(jobId)}/peer-evidence`, {
    method:'POST', body:{source_job_id:body.source_job_id,observation:body.observation,requested_delivery:body.requested_delivery}
  });
  if (modal.open && modal.querySelector('#solver-peer-evidence-form') === form) modal.close();
  scheduleSolverPoll(currentSolverJob,currentWorkspace.id,currentChallenge.id,solverRendering,100);
  toast(i18n.t('다른 풀이의 관찰을 전달했습니다.'));
}

async function rejectSolverFlag() {
  const job = currentSolverJob, jobId = solverJobId(job);
  if (!jobId || !job?.flag || job.flag_rejected) return;
  if (!confirm(i18n.t('이 Flag를 오답으로 제외할까요? 기존 write-up 원본은 실행 기록에 보존되고, 문제는 미완료 상태로 돌아갑니다.'))) return;
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
  invalidateWriteupCopy(workspaceId,challengeId);
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
  if (box) box.textContent = i18n.t('미등록');
  if (copy) copy.disabled = true;
  const controls = document.querySelector('#challenge-status-controls');
  if (controls) controls.innerHTML = challengeStatusMarkup(currentChallenge);
  paintSolver(normalized.job || {...job,flag_rejected:true,writeup_markdown:null},normalized.events.length ? normalized.events : currentSolverEvents,workspaceId,challengeId,generation,normalized.guidance);
  await refreshChallenges();
  toast('오답 Flag를 제외했습니다. 다음 풀이가 이전 분석에서 계속됩니다.');
}

function uploadETA(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  if (seconds < 60) return i18n.format('{n}초',{n:Math.max(1,Math.ceil(seconds))});
  if (seconds < 3600) return i18n.format('{n}분',{n:Math.ceil(seconds/60)});
  const hours = Math.floor(seconds/3600), minutes = Math.ceil((seconds%3600)/60);
  return `${i18n.format('{n}시간',{n:hours})}${minutes ? ` ${i18n.format('{n}분',{n:minutes})}` : ''}`;
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
  const markup = visible.map(upload => {
    const active = activeUploads.get(upload.id), amount = active?.offset ?? upload.offset;
    const telemetry = active?.running && active.message === '전송 중' && active.bytesPerSecond > 0
      ? ` · ${size(active.bytesPerSecond)}/s · ${i18n.t('남은 시간')} ${uploadETA((upload.size-amount)/active.bytesPerSecond)}` : '';
    return `<div class="file-item upload-item"><div><strong data-i18n-ignore>${esc(upload.name)}</strong><small data-i18n-ignore>${size(amount)} / ${size(upload.size)} · ${esc(i18n.t(active?.message || '같은 원본 파일을 다시 선택하면 이어서 올립니다.'))}${esc(telemetry)}</small><progress max="${Math.max(1,upload.size)}" value="${amount}" aria-label="${esc(i18n.format('{name} 업로드 진행',{name:upload.name}))}"></progress><div class="actions">${active?.running ? `<button class="small" data-action="pause-upload" data-id="${upload.id}">일시 중지</button>` : active?.file ? `<button class="small" data-action="resume-upload" data-id="${upload.id}">이어서 올리기</button>` : ''}<button class="small danger" data-action="cancel-upload" data-id="${upload.id}">업로드 취소</button></div></div></div>`;
  }).join('');
  area.innerHTML = markup;
  const mirror = solverConsoleDialog?.querySelector('.solver-console-uploads');
  if (mirror) mirror.innerHTML = markup;
}

async function refreshUploads(workspaceId, challengeId) {
  const result = await api(`${path(challengeId,workspaceId)}/uploads`);
  paintUploads(result.uploads,workspaceId,challengeId,true);
  return result.uploads;
}

async function refreshChallengeAttachmentsInPlace(workspaceId, challengeId) {
  const latest = await api(path(challengeId,workspaceId));
  if (currentChallenge?.workspace_id !== workspaceId || currentChallenge?.id !== challengeId) return;
  const oldAttachmentIds = (currentChallenge.attachments || []).map(file => file.id).join(',');
  currentChallenge.attachments = latest.attachments || [];
  const list = detail.querySelector('.file-list');
  if (list) list.innerHTML = attachmentRowsMarkup(currentChallenge);
  const heading = list?.closest('section')?.querySelector('h3 .muted');
  if (heading) heading.textContent = String(currentChallenge.attachments.length);
  if (oldAttachmentIds !== currentChallenge.attachments.map(file => file.id).join(',') && currentSolverJob?.phase === 'needs_input') {
    await loadSolver(workspaceId,challengeId);
  }
}

function queueAttachmentWork(workspaceId, challengeId, sources) {
  if (!sources.length) return [];
  const key = attachmentWorkKey(workspaceId,challengeId);
  const work = attachmentWork.get(key) || {workspaceId,challengeId,items:[],stopped:false};
  const items = sources.map(source => ({work,source,name:source.name,size:source.size,offset:0,done:false}));
  work.items.push(...items);
  attachmentWork.set(key,work);
  paintAttachmentWork(workspaceId,challengeId);
  return items;
}

function finishAttachmentItem(item, saved) {
  const {work} = item;
  if (work.stopped) return;
  if (saved) { item.offset = item.size; item.done = true; }
  else work.items = work.items.filter(other => other !== item);
  if (work.items.every(other => other.done)) attachmentWork.delete(attachmentWorkKey(work.workspaceId,work.challengeId));
  paintAttachmentWork(work.workspaceId,work.challengeId);
}

function stopAttachmentWork() {
  for (const work of attachmentWork.values()) work.stopped = true;
  attachmentWork.clear();
}

function requireNoAttachmentWork(workspaceId, challengeId) {
  if (!attachmentsPending(workspaceId,challengeId)) return;
  paintAttachmentWork(workspaceId,challengeId);
  throw new Error(i18n.t(attachmentHoldReason));
}

function inlineInputWaiting(form) {
  return form.elements.remote_mode.value !== 'endpoint' && form.dataset.originalRemoteMode === 'none' && form.dataset.inputReady !== 'true';
}

function syncInlineInput(form) {
  // A form in flight stays locked through a morph. It syncs again once runForm has finished.
  if (busyForms.has(form)) {
    form.setAttribute('aria-busy','true');
    for (const control of form.elements) control.disabled = true;
    return;
  }
  const remote = form.elements.remote, enabled = form.elements.remote_mode.value === 'endpoint';
  remote.disabled = !enabled; remote.required = enabled;
  remote.closest('label').classList.toggle('is-disabled',!enabled);
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = submit.hasAttribute('data-attachment-hold') || inlineInputWaiting(form);
}

// Runs on every chunk, so it patches what is there: a rebuilt card would lose focus.
function paintCardAttachmentWork(card, work) {
  const held = Boolean(work), line = card.querySelector(':scope > .challenge-card-upload');
  const startable = Boolean(card.querySelector('[data-action="start-list-solver"],.challenge-inline-input'));
  if (!work) line?.remove();
  else if (line) morphMarkup(line,attachmentWorkBody(work,startable));
  else card.querySelector(':scope > .challenge-card-footer')?.insertAdjacentHTML('beforebegin',attachmentWorkMarkup(work,startable));
  const start = card.querySelector('[data-action="start-list-solver"]');
  if (start) { start.toggleAttribute('data-attachment-hold',held); start.disabled = held || start.hasAttribute('aria-busy'); }
  const submit = card.querySelector('.challenge-inline-input button[type="submit"]');
  if (submit) { submit.toggleAttribute('data-attachment-hold',held); submit.disabled = held || inlineInputWaiting(submit.form); }
}

function paintSolverStartHold() {
  const panel = detail.querySelector('#solver-panel');
  if (!panel) return;
  const held = solverAttachmentHold();
  const controls = [...panel.querySelectorAll('[data-action="start-solver"],[data-action="approve-ultra-escalation"]')];
  for (const control of controls) {
    control.toggleAttribute('data-attachment-hold',held);
    control.disabled = held || (control.dataset.action === 'start-solver' && !solverConfigurationReady());
  }
  const hint = panel.querySelector(':scope > .solver-attachment-hold');
  if (!held || !controls.length) hint?.remove();
  else if (!hint) panel.insertAdjacentHTML('beforeend',solverAttachmentHoldMarkup());
}

function paintAttachmentWork(workspaceId, challengeId) {
  const card = currentWorkspace?.id === workspaceId
    ? document.querySelector(`#challenge-area [data-challenge-id="${CSS.escape(challengeId)}"]`) : null;
  if (card) paintCardAttachmentWork(card,attachmentWork.get(attachmentWorkKey(workspaceId,challengeId)));
  if (detail.open && currentChallenge?.workspace_id === workspaceId && currentChallenge.id === challengeId) paintSolverStartHold();
}

async function uploadFile(file, workspaceId, challengeId, resumeId, item = queueAttachmentWork(workspaceId,challengeId,[file])[0]) {
  const endpoint = path(challengeId,workspaceId);
  let upload, active = null, saved = false;
  const paint = () => {
    item.offset = active.offset;
    paintUploads([upload],workspaceId,challengeId);
    paintAttachmentWork(workspaceId,challengeId);
  };
  try {
    if (resumeId) upload = await api(`/api/uploads/${resumeId}`);
    else {
      const pending = await api(`${endpoint}/uploads`);
      paintUploads(pending.uploads,workspaceId,challengeId,true);
      upload = pending.uploads.find(entry => entry.name === file.name && entry.size === file.size && entry.last_modified === file.lastModified);
      if (!upload) upload = await api(`${endpoint}/uploads`,{method:'POST',body:{name:file.name,size:file.size,last_modified:file.lastModified}});
    }
    if (item.work.stopped) return false;
    if (upload.status === 'completed') return saved = true;
    if (activeUploads.get(upload.id)?.running) throw new Error('이 파일은 이미 업로드 중입니다.');
    const startedAt = Date.now();
    active = {file,workspaceId,challengeId,offset:upload.offset,running:true,paused:false,controller:new AbortController(),message:'전송 준비 중',
      startedAt,sampleAt:startedAt,sampleOffset:upload.offset,bytesPerSecond:0};
    activeUploads.set(upload.id,active);
    paint();
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
    return saved = true;
  } catch (error) {
    if (error.name === 'AbortError') return false;
    // The row keeps source text and paintUploads translates it, so it follows a language switch.
    if (active) active.message = error instanceof TypeError ? '서버에 연결할 수 없습니다. 연결을 확인하세요.' : error.message;
    // Callers show this text as it is, and fetch's own message is a browser English string.
    throw new Error(transferErrorText(error));
  } finally {
    if (active) {
      active.running = false;
      if (active.paused) active.message = '일시 중지됨 · 이어서 올릴 수 있습니다.';
      if (activeUploads.has(upload.id)) paint();
    }
    finishAttachmentItem(item,saved);
  }
}

// One after another. A sign-out stops the batch: the next file would only meet a 401.
async function uploadQueuedAttachments(items, workspaceId, challengeId) {
  const failures = [];
  let saved = 0;
  for (const item of items) {
    if (item.work.stopped) break;
    try { if (await uploadFile(item.source,workspaceId,challengeId,undefined,item)) saved++; }
    catch (error) { failures.push(`${item.name}: ${error.message}`); }
  }
  return {saved,failures};
}

async function reloadNotes() {
  if (notesDirty() && !confirm(i18n.t('작성 중인 내용을 저장본으로 바꿀까요? 필요한 내용은 먼저 복사하거나 다운로드해 주세요.'))) return;
  const c = currentChallenge;
  const previous = document.querySelector('#notes-editor').value;
  const latest = await api(path(c.id,c.workspace_id));
  if (currentChallenge !== c) return;
  if (document.querySelector('#notes-editor').value !== previous) throw new Error(i18n.t('불러오는 동안 추가로 입력한 내용이 있어 변경하지 않았습니다.'));
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
    <div class="divider"></div><section class="settings-card"><h2>비밀번호 변경</h2><form id="password-form"><label>현재 비밀번호<input type="password" name="current_password" autocomplete="current-password" maxlength="1024" required></label><label>새 비밀번호<input type="password" name="new_password" autocomplete="new-password" minlength="4" maxlength="1024" required><span class="form-hint">최소 4자</span></label><label>새 비밀번호 확인<input type="password" name="confirmation" autocomplete="new-password" minlength="4" maxlength="1024" required></label><div><button class="primary">비밀번호 변경</button></div></form><div class="divider"></div><div class="actions"><button class="ghost" data-action="toggle-session-persistence">${sessionPersistent ? '30일 로그인 해제' : '이 기기에서 30일 로그인 유지'}</button><button class="ghost" data-action="logout">로그아웃</button></div></section><div class="divider"></div>` : '';
  content.innerHTML = `<div class="page-head"><div><div class="eyebrow">PERSONAL SETTINGS</div><h1>개인 설정</h1></div></div>
    ${credentialSettings}<section class="settings-card"><h2>${tr('Solve defaults')}</h2>
    <form id="solver-preferences-form"><label>${tr('Escalate to Ultra when stuck')}
      <select name="ultra_escalation_default">
        <option value="ask" ${sessionUser?.ultra_escalation_default === 'ask' ? 'selected' : ''}>${tr('Ask first')}</option>
        <option value="auto" ${sessionUser?.ultra_escalation_default === 'auto' ? 'selected' : ''}>${tr('Automatic when eligible')}</option>
        <option value="off" ${sessionUser?.ultra_escalation_default === 'off' ? 'selected' : ''}>${tr('Disabled')}</option>
      </select></label><div><button class="primary">${tr('Save')}</button></div></form></section>
    <div class="divider"></div><section class="settings-card"><h2>${tr('Profile image')}</h2>
      <div class="profile-avatar-control"><div id="profile-avatar-preview">${avatarMarkup(sessionUser)}</div>
      <button type="button" data-action="refresh-profile-avatar">${tr('Generate another')}</button></div></section>
    <div class="divider"></div><section id="telegram-settings"></section>`;
  const container = document.querySelector('#telegram-settings');
  import(new URL('./telegram.js', import.meta.url)).then(async module => { const dispose = await module.renderTelegram(container,api,{user:sessionUser}); if (container.isConnected) disposeTelegram = dispose; else dispose?.(); }).catch(() => { if (container.isConnected) container.textContent = '알림 설정을 불러올 수 없습니다. 잠시 후 다시 시도하세요.'; });
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
    const labels = {idle:'대기',queued:'대기 중',downloading:'다운로드 중',verifying:'검증 중',installing:'설치 중',health_check:'서비스 상태 확인 중',rolling_back:'이전 버전 복구 중',completed:'완료',failed:'실패'};
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
    toast(i18n.format('{tag} 업데이트를 시작했습니다.',{tag:result.tag}));
  } finally {
    await refreshReleaseUpdatePanel();
  }
}

function adminUserActiveButton(user, activeAdminCount) {
  const reason = user.role === 'admin' && user.active && activeAdminCount <= 1
    ? '마지막 활성 관리자는 비활성화할 수 없습니다.'
    : user.id === sessionUser?.id ? '현재 로그인한 계정은 비활성화할 수 없습니다.' : '';
  const reasonId = `user-active-reason-${esc(user.id)}`;
  const disabled = reason ? `disabled title="${esc(reason)}" aria-label="${esc(user.username)}: ${tr(reason)}" aria-describedby="${reasonId}"` : '';
  return `<span class="admin-active-control"><button class="small" data-action="user-active" data-id="${esc(user.id)}" data-active="${user.active ? 'false' : 'true'}" ${disabled}>${user.active ? '비활성화' : '활성화'}</button>${reason ? `<small id="${reasonId}" class="admin-disabled-reason">${esc(reason)}</small>` : ''}</span>`;
}

function solverCapacityAdminMarkup(capacity) {
  const maximum = capacity.admin_max || '';
  const limit = capacity.hard_max ? i18n.format('{n}개',{n:capacity.hard_max}) : i18n.t('제한 없음');
  const warning = capacity.warning
    ? `<p class="notice error-notice" role="status">${esc(capacity.warning_message)}</p>`
    : '';
  const summary = i18n.locale === 'en'
    ? `Running ${esc(capacity.configured)} · jobs ${esc(capacity.open_jobs)} · recommended ${esc(capacity.recommended)} · maximum ${esc(limit)} · estimated web PIDs ${esc(capacity.estimated_web_pids)} / ${capacity.web_pids_limit ? esc(capacity.web_pids_limit) : i18n.t('제한 없음')}`
    : `실행 ${esc(capacity.configured)} · 작업 ${esc(capacity.open_jobs)} · 권장 ${esc(capacity.recommended)} · 최대 ${esc(limit)} · 웹 PID 예상 ${esc(capacity.estimated_web_pids)} / ${capacity.web_pids_limit ? esc(capacity.web_pids_limit) : '제한 없음'}`;
  return `<section class="settings-card"><h2>솔버 자동 확장</h2>
    <p class="form-hint">${summary}</p>
    ${warning}
    <form id="solver-capacity-form"><label>최대 솔버 수 <span class="optional">비우면 제한 없음</span><input name="maximum" type="number" min="${esc(capacity.baseline)}" step="1" value="${esc(maximum)}" placeholder="제한 없음"></label><div><button class="primary">저장</button></div></form>
  </section>`;
}

async function renderAdmin(ticket = rendering) {
  if (sessionUser?.role !== 'admin') { location.hash = 'settings'; toast('관리자 권한이 필요합니다.',true); return; }
  const capacity = await pageRequest('/api/admin/solver-capacity');
  if (ticket !== rendering) return;
  if (authMode === 'nologin') {
    adminView = {capacity,users:null};
    shell('admin','관리자 설정').innerHTML = adminMarkup(adminView);
    renderAdminCliVersions(document.querySelector('#admin-cli-version-panel'), api, {scope:sessionUser.id, locale:i18n.locale});
    refreshReleaseUpdatePanel();
    return;
  }
  const {users} = await pageRequest('/api/admin/users');
  if (ticket !== rendering) return;
  adminView = {capacity,users};
  shell('admin','관리자 설정').innerHTML = adminMarkup(adminView);
  renderAdminCliVersions(document.querySelector('#admin-cli-version-panel'), api, {scope:sessionUser.id, locale:i18n.locale});
  refreshReleaseUpdatePanel();
}

function adminMarkup({capacity,users}) {
  const panels = `<section class="settings-card"><h2>미완료 업로드 정리</h2><p class="form-hint">7일 이상 진행하지 않은 미완료 임시 파일만 정리합니다. 완료된 첨부파일은 유지됩니다.</p><button data-action="cleanup-uploads">만료된 업로드 정리</button></section><div class="divider"></div><section class="settings-card"><h2>${tr("Service logs")}</h2><p class="form-hint">${tr("Download rotated service logs and recent solver job states for debugging.")}</p><button data-action="open-admin-log-export">${tr("Download logs")}</button></section><div class="divider"></div><section id="admin-cli-version-panel" class="settings-card account-runtime" data-morph-keep></section><div class="divider"></div><section id="release-update-panel" class="settings-card" data-morph-keep></section>`;
  if (!users) return `<div class="page-head"><div><div class="eyebrow">ADMIN SETTINGS</div><h1>관리자 설정</h1></div></div>
      ${solverCapacityAdminMarkup(capacity)}<div class="divider"></div>
      ${panels}`;
  const activeAdminCount = users.filter(user => user.role === 'admin' && user.active).length;
  return `<div class="page-head"><div><div class="eyebrow">ADMIN SETTINGS</div><h1>사용자 관리</h1></div><button class="primary" data-action="new-user">＋ 사용자 추가</button></div>
    <div class="table-wrap"><table class="challenge-table admin-user-table"><thead><tr><th>아이디</th><th>권한</th><th>상태</th><th>최근 로그인</th><th>작업공간 / 계정</th><th>Telegram</th><th>관리</th></tr></thead><tbody>${users.map(user => `<tr><td class="challenge-title"><span data-i18n-ignore>${esc(user.username)}</span>${user.id === sessionUser.id ? ' <span class="tag">나</span>' : ''}</td><td><select data-action="user-role" data-id="${user.id}" aria-label="${esc(user.username)} ${tr('권한')}"><option value="user" ${user.role === 'user' ? 'selected' : ''}>일반 사용자</option><option value="admin" ${user.role === 'admin' ? 'selected' : ''}>관리자</option></select></td><td>${user.active ? '활성' : '비활성'}</td><td>${user.last_login_at ? date(user.last_login_at) : '기록 없음'}</td><td>${user.workspace_count} / ${user.account_count}</td><td>${user.telegram_linked ? (user.telegram_enabled ? '알림 켜짐' : '연결됨 · 알림 꺼짐') : '미연결'}${user.telegram_last_failure_at ? '<br><small>최근 전송 오류 기록</small>' : ''}</td><td><div class="actions">${adminUserActiveButton(user,activeAdminCount)}<button class="small" data-action="user-password" data-id="${user.id}" data-name="${esc(user.username)}">비밀번호 초기화</button></div></td></tr>`).join('')}</tbody></table></div>
    <div class="divider"></div>${solverCapacityAdminMarkup(capacity)}
    <div class="divider"></div>${panels}`;
}

function adminLogParams(form) {
  const params = new URLSearchParams({hours:form.elements.hours.value});
  if (form.elements.workspace_id.value) params.set('workspace_id',form.elements.workspace_id.value);
  if (form.elements.challenge_id.value) params.set('challenge_id',form.elements.challenge_id.value);
  return params;
}

async function adminLogChallenges(workspaceId) {
  const form = modal.querySelector('#admin-log-export-form');
  if (!form) return;
  const select = form.elements.challenge_id;
  select.innerHTML = `<option value="">${tr('All challenges')}</option>`;
  select.disabled = !workspaceId;
  if (!workspaceId) return;
  const [result, trash] = await Promise.all([
    api(`/api/workspaces/${workspaceId}/challenges`),
    api(`/api/workspaces/${workspaceId}/trash`),
  ]);
  if (form !== modal.querySelector('#admin-log-export-form') || form.elements.workspace_id.value !== workspaceId) return;
  const challenges = [...(result.challenges || []), ...(trash.challenges || [])];
  select.innerHTML += challenges.map(item =>
    `<option value="${esc(item.id)}" data-i18n-ignore>${esc(item.name)}${item.deleted_at ? ` (${tr('Trash')})` : ''}</option>`).join('');
}

function showAdminLogExport() {
  const body = `<label>${tr('Period')}<select name="hours"><option value="24">24 ${tr('hours')}</option><option value="72" selected>72 ${tr('hours')}</option><option value="168">7 ${tr('days')}</option><option value="720">30 ${tr('days')}</option></select></label>
    <label>${tr('Workspace')}<select name="workspace_id" id="admin-log-workspace"><option value="">${tr('All workspaces')}</option>${workspaces.map(item => `<option value="${esc(item.id)}" data-i18n-ignore>${esc(item.name)}</option>`).join('')}</select></label>
    <label>${tr('Challenge')}<select name="challenge_id" disabled><option value="">${tr('All challenges')}</option></select></label>
    <div id="admin-log-preview" class="form-hint" aria-live="polite">${tr('Preview before downloading.')}</div>`;
  const footer = `<button type="button" data-action="close-modal">${tr('Cancel')}</button><button type="submit">${tr('Preview')}</button><button type="button" class="primary" data-action="download-admin-logs" disabled>${tr('Download logs')}</button>`;
  openModal(tr('Service logs'),'',body,footer,'admin-log-export-form');
}

async function previewAdminLogs(form) {
  const result = await api(`/api/admin/logs/preview?${adminLogParams(form)}`);
  const target = form.querySelector('#admin-log-preview');
  target.textContent = `${tr('Estimated size before compression')}: ${size(result.estimated_uncompressed_bytes)} · ${tr('Solve jobs')}: ${result.solver_jobs} · ${tr('Events')}: ${result.solver_events} · CTFd: ${result.ctfd_imports + result.ctfd_submissions}${result.truncated ? ` · ${tr('Older records are omitted by the export limit.')}` : ''}`;
  form.dataset.previewReady = 'true';
  form.querySelector('[data-action="download-admin-logs"]').disabled = false;
}

function newUserForm() {
  openModal('사용자 추가','', '<label>아이디<input name="username" autocomplete="off" maxlength="100" required></label><label>초기 비밀번호<input type="password" name="password" autocomplete="new-password" minlength="4" maxlength="1024" required><span class="form-hint">4자 이상 · 조합 조건 없음</span></label><label>권한<select name="role"><option value="user">일반 사용자</option><option value="admin">관리자</option></select></label>','<button type="button" data-action="close-modal">취소</button><button type="submit" class="primary">사용자 만들기</button>','new-user-form');
}

function syncCTFdImportSource(form) {
  const saved = form.elements.connection_mode?.value === 'saved';
  const manual = form.querySelector('#ctfd-import-manual');
  manual.hidden = saved;
  const url = form.elements.url, auth = form.elements.auth_type;
  url.disabled = saved; url.required = !saved;
  auth.disabled = saved;
  for (const [id,type] of [['ctfd-token-fields','token'],['ctfd-password-fields','password']]) {
    const fields = form.querySelector(`#${id}`), enabled = !saved && auth.value === type;
    fields.hidden = !enabled;
    // Disabled inputs keep their value but stay out of FormData.
    fields.querySelectorAll('input').forEach(node => { node.disabled = !enabled; node.required = enabled; });
  }
}

function rememberCTFdForm(form) {
  const {connection_mode:mode, url, auth_type:auth, username} = form.elements;
  const draft = ctfdDrafts.get(form.dataset.workspaceId) || {};
  ctfdDrafts.set(form.dataset.workspaceId,{...draft,mode:mode.value,url:url.value,auth:auth.value,username:username.value});
}

function restoreCTFdForm(form, workspaceId) {
  const draft = ctfdDrafts.get(workspaceId);
  if (!draft?.mode) return;
  const {connection_mode:mode, url, auth_type:auth, username} = form.elements;
  mode.value = draft.mode;
  if (mode.selectedIndex < 0) mode.selectedIndex = 0; // The saved connection was removed.
  url.value = draft.url; auth.value = draft.auth; username.value = draft.username;
}

function rememberCTFdSelection(form) {
  const key = form.id === 'ctfd-sync-form' ? 'sync' : 'import';
  const draft = ctfdDrafts.get(form.dataset.workspaceId) || {};
  const unchecked = [...form.querySelectorAll('input[name="challenge"]:not(:checked)')].map(node => node.value);
  ctfdDrafts.set(form.dataset.workspaceId,{...draft,[key]:{source:importPreview?.result?.source_url,unchecked}});
}

function restoreCTFdSelection(form, key, source) {
  const saved = ctfdDrafts.get(form.dataset.workspaceId)?.[key];
  if (saved?.source !== source) return;
  for (const node of form.querySelectorAll('input[name="challenge"]')) node.checked = !saved.unchecked.includes(node.value);
}

function ctfdImportHistoryMarkup() {
  return `<section class="ctfd-import-history" aria-labelledby="ctfd-import-history-title">
    <div class="section-head ctfd-import-history-head"><h3 id="ctfd-import-history-title">가져오기 기록</h3><button type="button" class="small ghost icon-action" data-action="refresh-ctfd-jobs" aria-label="CTFd 가져오기 기록 새로고침" title="CTFd 가져오기 기록 새로고침">↻</button></div>
    <p id="ctfd-job-notice" class="notice error-notice" role="status" hidden></p>
    <div id="ctfd-job-area" role="region" tabindex="0" aria-label="CTFd 가져오기 기록"><p class="form-hint">기록을 불러오는 중입니다.</p></div>
  </section>`;
}

function showCTFdImportProgress(workspaceId) {
  openModal('CTFd 가져오기', '', ctfdImportHistoryMarkup(),
    '<button type="button" data-action="close-modal">닫기</button><button type="button" class="primary" data-action="ctfd-import">다른 문제 가져오기</button>');
  modal.dataset.kind = 'ctfd-import'; modal.dataset.workspaceId = workspaceId;
}

async function importForm() {
  if (!currentWorkspace) return;
  const workspaceId = currentWorkspace.id, page = rendering, hash = location.hash;
  importPreview = null;
  const state = await api(`/api/workspaces/${workspaceId}/ctfd/connection`);
  if (page !== rendering || hash !== location.hash || currentWorkspace?.id !== workspaceId) return;
  openModal('CTFd 문제 가져오기', '', `
    <label>연결 방식<select id="ctfd-import-source" name="connection_mode">
      ${state.connected ? `<option value="saved">${esc(i18n.t('저장된 연결'))} · ${esc(state.url)}</option>` : ''}
      <option value="new">새 연결 입력</option>
    </select></label>
    <div id="ctfd-import-manual" class="ctfd-import-manual">
      <label>CTFd 사이트 주소<input name="url" inputmode="url" placeholder="ctf.example.com" required><span class="form-hint">https://를 생략하면 자동으로 붙입니다.</span></label>
      <label>인증 방식<select id="ctfd-auth-type" name="auth_type"><option value="none">로그인 없이 가져오기</option><option value="token">API 토큰</option><option value="password">아이디와 비밀번호</option></select></label>
      <div id="ctfd-token-fields" hidden><label>API 토큰<input name="token" type="password" autocomplete="off" disabled><span class="form-hint">창을 닫으면 지워집니다.</span></label></div>
      <div id="ctfd-password-fields" hidden><label>CTFd 아이디<input name="username" autocomplete="off" disabled></label><label>CTFd 비밀번호<input name="password" type="password" autocomplete="off" disabled><span class="form-hint">창을 닫으면 지워집니다.</span></label></div>
    </div>${ctfdImportHistoryMarkup()}`, '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">문제 목록 확인</button>', 'ctfd-preview-form');
  modal.dataset.kind = 'ctfd-import'; modal.dataset.workspaceId = workspaceId;
  const form = modal.querySelector('#ctfd-preview-form');
  restoreCTFdForm(form,workspaceId);
  syncCTFdImportSource(form);
  form.dataset.initial = formSnapshot(form);
  pollCTFdJobs(workspaceId);
}

function ctfdRefreshAuthForm() {
  const challenge = currentChallenge;
  if (!challenge?.ctfd_url || challenge.ctfd_id === null || challenge.ctfd_id === undefined) throw new Error(i18n.t('CTFd에서 가져온 문제만 다시 인증할 수 있습니다.'));
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
  return history.submissions.map(job => `<div class="submission-row"><div><strong data-i18n-ignore>${esc(job.challenge_name || i18n.format('문제 #{id}',{id:job.ctfd_id}))}</strong><small data-i18n-ignore>CTFd #${esc(job.ctfd_id)} · ${esc(i18n.t(submissionLabels[job.status] || job.status))} · ${esc(i18n.format('시도 {n}',{n:job.attempts}))}</small>${job.display_message ? `<p>${esc(job.display_message)}</p>` : ''}</div><span class="status ${['correct','already_solved'].includes(job.status) ? 'status-solved' : job.status === 'incorrect' ? 'status-failed' : ''}">${esc(submissionLabels[job.status] || job.status)}</span></div>`).join('') || '<p class="form-hint">자동 제출 기록이 없습니다.</p>';
}

function ctfdConnectionState(state) {
  const reason = {
    csrf_unavailable:'이 사이트의 로그인 세션에서 제출용 CSRF 토큰을 확인하지 못했습니다.',
    challenge_access_unavailable:'문제 목록 접근을 확인하지 못했습니다.',
    recheck_required:'제출 인증 상태를 다시 확인해야 합니다. 연결을 다시 저장하세요.',
  }[state.submit_check_reason] || '제출 인증 상태를 확인하지 못했습니다. 연결을 다시 저장하세요.';
  return `<div class="section-head"><h3>작업공간 연결</h3><span class="connection-state ${state.connected ? 'connected' : ''}">${state.connected ? (state.submit_ready ? '제출 인증 준비됨' : '조회 확인됨') : '연결 안 됨'}</span></div>
      ${state.connected ? `<p class="ctfd-connection-meta"><strong data-i18n-ignore>${esc(state.url)}</strong><small>${state.auth_type === 'password' ? '아이디·비밀번호' : 'API 토큰'}</small></p>` : '<p class="form-hint">CTFd 연결을 저장하세요.</p>'}
      <div class="ctfd-submit-toggle-row"><label class="ctfd-submit-toggle"><input id="ctfd-auto-submit-toggle" type="checkbox" data-saved="${Boolean(state.auto_submit)}" aria-describedby="ctfd-auto-submit-help" ${state.auto_submit ? 'checked' : ''} ${state.submit_ready ? '' : 'disabled'}><span>Flag 자동 제출</span></label></div>
      <p id="ctfd-auto-submit-help" class="notice ctfd-submit-help ${state.auto_submit ? '' : 'muted'}">${state.connected && !state.submit_ready ? esc(reason) : '기본 OFF · CTFd 오답 패널티가 적용될 수 있습니다.'}</p>
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
        modal.querySelector('#ctfd-connection-summary').textContent = scope.state.connected ? '연결 바꾸기' : 'CTFd 연결';
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
    if (desired && !confirm(i18n.t('자동 제출을 켜면 {name}에서 발견한 CTFd Flag를 즉시 전송합니다. 오답 패널티가 적용될 수 있습니다. 켤까요?').replace('{name}',() => scope.workspaceName))) return;
    scope.state = await api(`/api/workspaces/${scope.workspaceId}/ctfd/settings`,{method:'PUT',body:{auto_submit:desired}});
    scope.focusSelector = '#ctfd-auto-submit-toggle';
    if (ctfdSubmitCurrent(scope)) toast(desired ? 'CTFd 자동 제출을 켰습니다.' : 'CTFd 자동 제출을 껐습니다.');
  });
}

async function disconnectCTFdSubmit() {
  await ctfdSubmitAction(async scope => {
    if (!confirm(i18n.t('저장된 CTFd 연결을 해제할까요? 가져오기와 자동 제출에 더 이상 사용되지 않습니다.'))) return;
    scope.state = await api(`/api/workspaces/${scope.workspaceId}/ctfd/connection`,{method:'DELETE'});
    if (ctfdSubmitCurrent(scope)) {
      modal.querySelector('#ctfd-connection-details').open = true;
      scope.focusSelector = 'input[name="url"]';
      toast('CTFd 연결을 해제했습니다.');
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
    toast('CTFd 연결을 저장했습니다. 자동 제출은 직접 켜야 합니다.');
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
  openModal('CTFd 연결·자동 제출', '', `<div class="ctfd-submit-panel">
    <section id="ctfd-connection-state" class="ctfd-connection-state">${ctfdConnectionState(state)}</section>
    <div class="divider"></div>
    <details id="ctfd-connection-details" class="ctfd-submit-connection-details" ${state.connected ? '' : 'open'}><summary id="ctfd-connection-summary">${state.connected ? '연결 바꾸기' : 'CTFd 연결'}</summary>
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
  openModal('가져올 문제 선택', `${i18n.format('문제 {n}개',{n:result.challenges.length})} · ${result.source_url}`, `<div class="import-preview">${result.challenges.map(c => `<label class="import-row"><input type="checkbox" name="challenge" value="${c.id}" checked><span><span data-i18n-ignore>${esc(c.name)}</span> <small data-i18n-ignore>${esc(c.category || i18n.t('미분류'))} · ${esc(result.details_pending ? `${i18n.t('첨부')} ${i18n.t('가져올 때 확인')}` : i18n.format('첨부 {n}',{n:(c.files || []).length}))}</small></span></label>`).join('') || '<p>가져올 문제가 없습니다.</p>'}</div>${result.errors.length ? `<div class="notice error-notice">${importErrors(result.errors)}</div>` : ''}<p class="form-hint">기존 문제는 변경하지 않습니다.</p>${ctfdImportHistoryMarkup()}`, '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">선택한 문제 가져오기</button>', 'ctfd-import-form');
  modal.dataset.kind = 'ctfd-import'; modal.dataset.workspaceId = importPreview.workspaceId;
  const form = modal.querySelector('#ctfd-import-form');
  restoreCTFdSelection(form,'import',result.source_url);
  form.dataset.initial = formSnapshot(form);
  pollCTFdJobs(importPreview.workspaceId);
}

function showCTFdSyncPreview(result, workspaceId) {
  const challenges = Array.isArray(result?.challenges) ? result.challenges : [];
  const sourceStatuses = Array.isArray(result?.source_statuses) ? result.source_statuses : [];
  const existingCount = Number.isInteger(result?.existing_count) && result.existing_count >= 0 ? result.existing_count : 0;
  const newCount = Number.isInteger(result?.new_count) && result.new_count >= 0 ? result.new_count : challenges.length;
  const errors = Array.isArray(result?.errors) ? result.errors : [];
  importPreview = {mode:'sync', workspaceId, result};
  const rows = challenges.map(c => `<label class="import-row"><input type="checkbox" name="challenge" value="${esc(c.id)}" checked><span><span data-i18n-ignore>${esc(c.name)}</span> <small data-i18n-ignore>${esc(c.category || i18n.t('미분류'))} · ${esc(result.details_pending ? `${i18n.t('첨부')} ${i18n.t('동기화할 때 확인')}` : i18n.format('첨부 {n}',{n:(c.files || []).length}))}</small></span></label>`).join('');
  const unavailable = sourceStatuses.filter(item => item.state !== 'visible');
  const sourceLabels = {hidden:'원본에서 숨김',locked:'원본에서 잠김',unlisted:'원본 목록에서 확인되지 않음'};
  const unavailableRows = unavailable.map(item => `<div class="import-row ctfd-source-status"><span><strong data-i18n-ignore>${esc(item.name || `CTFd #${item.remote_id}`)}</strong><small data-i18n-ignore>CTFd #${esc(item.remote_id)} · ${esc(i18n.t(sourceLabels[item.state] || '원본 상태 미확인'))}</small></span><button type="button" class="small ghost" data-action="open-ctfd-source-challenge" data-workspace-id="${esc(workspaceId)}" data-id="${esc(item.challenge_id)}">문제 보기</button></div>`).join('');
  const body = `<div class="ctfd-sync-counts"><span><strong>${newCount}</strong> 신규</span><span><strong>${existingCount}</strong> 기존 유지</span></div>
    <div class="import-preview">${rows || '<p>새로 추가된 문제가 없습니다.</p>'}</div>
    ${unavailableRows ? `<div class="section-head"><h3>원본 상태 확인 필요</h3></div><div class="import-preview">${unavailableRows}</div><p class="form-hint">목록에 없다고 삭제된 것으로 단정하지 않습니다. 로컬 문제와 풀이 자료는 유지됩니다.</p>` : ''}
    ${errors.length ? `<div class="notice error-notice">${importErrors(errors)}</div>` : ''}
    <p class="notice muted">기존 상태, Flag, 풀이 노트, write-up, 첨부파일은 변경하지 않습니다.</p>`;
  const footer = challenges.length
    ? '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">선택한 새 문제 동기화</button>'
    : '<button type="button" data-action="close-modal" class="primary">확인</button>';
  openModal('새 문제 동기화', `${i18n.format('{n}개 신규',{n:newCount})} · ${result?.source_url || i18n.t('연결된 CTFd')}`, body, footer,
    challenges.length ? 'ctfd-sync-form' : undefined);
  const form = modal.querySelector('#ctfd-sync-form') || (challenges.length ? modal.querySelector('form') : null);
  if (form) {
    form.dataset.workspaceId = workspaceId;
    restoreCTFdSelection(form,'sync',result?.source_url);
    form.dataset.initial = formSnapshot(form);
  }
  modal.dataset.kind = 'ctfd-sync-preview'; modal.dataset.workspaceId = workspaceId;
}

async function startCTFdSync(form, challengeIds) {
  const preview = importPreview;
  const workspaceId = form.dataset.workspaceId;
  if (!preview || preview.mode !== 'sync' || preview.workspaceId !== workspaceId || currentWorkspace?.id !== workspaceId ||
      !preview.result?.preview_id) throw new Error(i18n.t('동기화 목록이 만료되었습니다. 새 문제를 다시 확인하세요.'));
  if (!challengeIds.length) throw new Error(i18n.t('동기화할 새 문제를 선택하세요.'));
  const generation = modalRendering, page = rendering, hash = location.hash;
  await api(`/api/workspaces/${workspaceId}/ctfd/sync`,{
    method:'POST', body:{preview_id:preview.result.preview_id,challenge_ids:challengeIds},
  });
  const draft = ctfdDrafts.get(workspaceId);
  if (draft) delete draft.sync;
  if (ctfdSyncViewCurrent(workspaceId,generation,page,hash,'ctfd-sync-preview')) {
    importPreview = null; showCTFdImportProgress(workspaceId);
    await refreshChallenges();
    await pollCTFdJobs(workspaceId);
  }
  toast(`새 문제 ${challengeIds.length}개 동기화를 시작했습니다.`);
}

function ctfdJobError(job) {
  const first = Array.isArray(job?.errors) ? job.errors[0] : null;
  if (typeof first === 'string') return first;
  return first?.message || 'CTFd에서 문제를 갱신하지 못했습니다.';
}

async function watchCTFdChallengeRefresh(initialJob, workspaceId, challengeId, key) {
  let job = initialJob;
  while (ctfdActiveJobStatuses.has(job?.status)) {
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
  // The import record holds the outcome. A stop the user asked for is not an error.
  if (job?.status !== 'cancelled') throw new Error(ctfdJobError(job));
}

async function launchCTFdChallengeRefresh(credentials = {}) {
  const challenge = currentChallenge, workspace = currentWorkspace;
  if (!challenge || !workspace || challenge.workspace_id !== workspace.id || challenge.ctfd_id === null ||
      challenge.ctfd_id === undefined || !challenge.ctfd_url) throw new Error(i18n.t('CTFd에서 가져온 문제만 새로고침할 수 있습니다.'));
  const workspaceId = workspace.id, challengeId = challenge.id, key = `${workspaceId}:${challengeId}`;
  if (activeCTFdChallengeRefreshes.has(key)) return;
  rememberNotes();
  activeCTFdChallengeRefreshes.set(key,'starting');
  try {
    const result = await api(`/api/workspaces/${workspaceId}/challenges/${challengeId}/ctfd/refresh`,{method:'POST',body:credentials});
    const job = result?.job || result;
    if (!job?.id) throw new Error(i18n.t('CTFd 새로고침 작업 정보를 받지 못했습니다.'));
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

function showCTFdRefreshPreview(result, challenge) {
  if (currentChallenge?.id !== challenge.id || currentWorkspace?.id !== challenge.workspace_id) return;
  const fields = Array.isArray(result.field_diff) ? result.field_diff : [];
  const labels = {name:'이름', category:'분야', description:'문제 설명', remote:'원격 접속 정보'};
  const rows = fields.filter(item => item.changed).map(item => {
    const locked = item.local_override || !item.selectable;
    const status = locked ? '로컬 수정 유지' : '원본 변경';
    return `<div class="import-row ctfd-refresh-row"><label><input type="checkbox" name="field" value="${esc(item.field)}" ${locked ? 'disabled' : 'checked'}><span><strong>${esc(labels[item.field] || item.field)}</strong> · <span>${status}</span></span></label>
      <details><summary>변경 내용</summary><div><small>현재</small><pre class="ctfd-diff-value">${esc(item.current || i18n.t('(없음)'))}</pre><small>CTFd</small><pre class="ctfd-diff-value">${esc(item.incoming || i18n.t('(없음)'))}</pre></div></details></div>`;
  }).join('');
  const files = result.challenges?.[0]?.files || [];
  importPreview = {mode:'refresh',workspaceId:challenge.workspace_id,challengeId:challenge.id,result};
  openModal('CTFd 변경 확인', challenge.name,
    `<div class="import-preview">${rows || '<p>문제 정보의 변경사항이 없습니다.</p>'}</div>
     <p class="form-hint">원본 첨부파일 ${files.length}개를 다시 확인합니다. 로컬에서 추가한 파일과 풀이 기록은 유지됩니다.</p>
     ${Array.isArray(result.errors) && result.errors.length ? `<div class="notice error-notice">${importErrors(result.errors)}</div>` : ''}`,
    '<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">선택한 변경 적용</button>',
    'ctfd-refresh-preview-form');
  const form = modal.querySelector('#ctfd-refresh-preview-form');
  form.dataset.workspaceId = challenge.workspace_id;
  form.dataset.challengeId = challenge.id;
  form.dataset.initial = formSnapshot(form);
  modal.dataset.kind = 'ctfd-refresh-preview'; modal.dataset.workspaceId = challenge.workspace_id;
}

async function previewCTFdChallengeRefresh(credentials = {}) {
  const challenge = currentChallenge;
  if (!challenge?.ctfd_url || challenge.ctfd_id === null || challenge.ctfd_id === undefined ||
      currentWorkspace?.id !== challenge.workspace_id) throw new Error(i18n.t('CTFd에서 가져온 문제만 새로고침할 수 있습니다.'));
  const result = await api(`/api/workspaces/${challenge.workspace_id}/challenges/${challenge.id}/ctfd/refresh/preview`,
    {method:'POST',body:credentials});
  showCTFdRefreshPreview(result,challenge);
}

async function refreshCTFdChallenge() {
  const challenge = currentChallenge;
  try { return await previewCTFdChallengeRefresh({}); }
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
  if (currentWorkspace?.id !== workspaceId || currentChallenge?.id !== challengeId) throw new Error(i18n.t('문제를 다시 연 뒤 인증해 주세요.'));
  body.url = String(body.url || '').trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(body.url)) body.url = `https://${body.url}`;
  if (body.auth_type === 'token') { delete body.username; delete body.password; }
  else if (body.auth_type === 'password') delete body.token;
  else { delete body.token; delete body.username; delete body.password; }
  try {
    await previewCTFdChallengeRefresh(body);
  } finally {
    for (const key of ['token','username','password']) if (Object.hasOwn(body,key)) body[key] = '';
    for (const input of form.querySelectorAll('input[name="token"],input[name="username"],input[name="password"]')) input.value = '';
  }
}

const ctfdJobLabels = {queued:'대기',running:'가져오는 중',completed:'완료',partial:'일부 실패',failed:'실패',cancelled:'취소됨',interrupted:'중단'};
const ctfdActiveJobStatuses = new Set(['queued','running']);
const ctfdVisibleHistoryLimit = 2;
let ctfdImportBadge = null;

function ctfdReuseMarkup(job) {
  const labels = [];
  if (job.reused_without_download) labels.push(i18n.format('사전 파일 재사용 {n}개 · 다운로드 생략', {n:job.reused_without_download}));
  if (job.downloaded_then_reused) labels.push(i18n.format('사전 파일 재사용 {n}개 · 다운로드 후', {n:job.downloaded_then_reused}));
  return labels.length ? `<div class="form-hint">${labels.map(esc).join(' · ')}</div>` : '';
}

function ctfdJobMarkup(job) {
  const operation = job.mode === 'new' ? 'CTFd 새 문제 동기화' : job.mode === 'refresh' ? 'CTFd 문제 새로고침' : 'CTFd 가져오기';
  const progress = i18n.format(job.mode === 'refresh' ? '업데이트 {n}개' : job.mode === 'new' ? '신규 {n}개' : '문제 {n}개',{n:(job.mode === 'refresh' ? job.refreshed : job.imported) || 0});
  let controls = '';
  if (ctfdActiveJobStatuses.has(job.status)) controls = `<button type="button" class="small" data-action="cancel-ctfd" data-id="${esc(job.id)}">작업 중단</button>`;
  else if (['partial','failed','cancelled','interrupted'].includes(job.status)) {
    if (job.mode === 'refresh' && job.target_challenge_id) {
      controls += `<button type="button" class="small" data-action="fresh-refresh-ctfd" data-challenge-id="${esc(job.target_challenge_id)}">최신 원본으로 새 작업</button>`;
    } else {
      const retryLabel = job.mode === 'new' ? '같은 연결로 다시 시도' : '다시 인증하고 이어 받기';
      controls = `<button type="button" class="small" data-action="retry-ctfd" data-id="${esc(job.id)}" data-mode="${esc(job.mode || 'import')}">${retryLabel}</button>`;
    }
  }
  return `<section class="workspace-summary" data-job-id="${esc(job.id)}"><div><strong>${esc(i18n.t(operation))} · ${esc(i18n.t(ctfdJobLabels[job.status] || job.status))}</strong><div class="form-hint">${esc(progress)} · ${esc(i18n.format('첨부 {n}개',{n:job.attachments || 0}))} · ${size(job.downloaded_bytes || 0)}${job.current_file ? ` · <span data-i18n-ignore>${esc(job.current_file)}</span>` : ''}</div>${ctfdReuseMarkup(job)}${job.errors?.length ? `<div class="notice error-notice">${importErrors(job.errors)}</div>` : ''}</div><div class="actions">${controls}</div></section>`;
}

function ctfdJobsMarkup(jobs) {
  if (!jobs.length) return '<p class="form-hint">가져오기 기록이 없습니다.</p>';
  const active = jobs.filter(job => ctfdActiveJobStatuses.has(job.status));
  const history = jobs.filter(job => !ctfdActiveJobStatuses.has(job.status));
  const recent = history.slice(0,ctfdVisibleHistoryLimit);
  const older = history.slice(ctfdVisibleHistoryLimit);
  const folded = older.length ? `<details class="ctfd-job-history"><summary>이전 CTFd 가져오기 기록 ${older.length}개 보기</summary><div class="ctfd-job-history-list">${older.map(ctfdJobMarkup).join('')}</div></details>` : '';
  return `${active.map(ctfdJobMarkup).join('')}${recent.map(ctfdJobMarkup).join('')}${folded}`;
}

function updateCTFdImportButton(jobs, workspaceId) {
  if (currentWorkspace?.id !== workspaceId) return;
  ctfdImportBadge = {jobs,workspaceId};
  const button = document.querySelector('.head-actions [data-action="ctfd-import"]');
  const badge = button?.querySelector('.ctfd-import-badge');
  if (!badge) return;
  const activeCount = jobs.filter(job => ctfdActiveJobStatuses.has(job.status)).length;
  const latestFinished = jobs.find(job => !ctfdActiveJobStatuses.has(job.status));
  const issue = ['failed','partial','interrupted'].includes(latestFinished?.status);
  const label = activeCount ? (activeCount === 1 ? i18n.t('진행 중') : i18n.format('진행 {n}',{n:activeCount}))
    : i18n.t(issue ? (latestFinished.status === 'partial' ? '일부 실패' : latestFinished.status === 'interrupted' ? '중단' : '실패') : '');
  badge.hidden = !label;
  badge.textContent = label;
  badge.classList.toggle('is-failed', Boolean(issue && !activeCount));
  if (label) {
    button.setAttribute('aria-label', `${i18n.t('CTFd 가져오기')} · ${label}`);
    button.title = `${i18n.t('CTFd 가져오기')} · ${label}`;
  } else {
    button.removeAttribute('aria-label');
    button.removeAttribute('title');
  }
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
  if (activeJob) return null;
  const previousJobId = previous.get(key);
  if (!previousJobId || watchedCTFdRefreshJobs.has(previousJobId)) return null;
  return jobs.find(job => job.id === previousJobId && job.mode === 'refresh' && job.target_challenge_id === challengeId) || null;
}

async function pollCTFdJobs(workspaceId) {
  if (ctfdJobsPollTimer) { clearTimeout(ctfdJobsPollTimer); ctfdJobsPollTimer = null; }
  if (!workspaceId || currentWorkspace?.id !== workspaceId || currentWorkspace.gone) return;
  const generation = ++ctfdJobsRequestGeneration;
  try {
    const result = await api(`/api/workspaces/${workspaceId}/ctfd/jobs`);
    if (generation !== ctfdJobsRequestGeneration || currentWorkspace?.id !== workspaceId) return;
    const completedRefresh = reflectActiveCTFdRefreshes(result.jobs,workspaceId);
    updateCTFdImportButton(result.jobs,workspaceId);
    const area = modal.open && modal.dataset.kind === 'ctfd-import' && modal.dataset.workspaceId === workspaceId
      ? modal.querySelector('#ctfd-job-area') : null;
    if (area) { updateCTFdJobs(area,result.jobs); paintCTFdJobNotice(area); }
    if (result.jobs.some(job => ctfdActiveJobStatuses.has(job.status))) {
      ctfdJobsPollTimer = setTimeout(() => { if (currentWorkspace?.id === workspaceId) pollCTFdJobs(workspaceId); },2000);
    }
    else {
      if (completedRefresh?.status === 'completed' && Number(completedRefresh.refreshed || 0) > 0 && currentChallenge?.id === completedRefresh.target_challenge_id && detail.open) {
        rememberNotes();
        await openChallenge(completedRefresh.target_challenge_id);
        toast('CTFd 문제 새로고침이 완료되었습니다. 로컬 풀이 자료는 유지했습니다.');
      } else if (completedRefresh && completedRefresh.status !== 'cancelled') toast(ctfdJobError(completedRefresh),true);
      await refreshChallenges();
    }
  } catch (error) {
    if (generation === ctfdJobsRequestGeneration && currentWorkspace?.id === workspaceId) {
      const area = modal.open && modal.dataset.kind === 'ctfd-import' && modal.dataset.workspaceId === workspaceId
        ? modal.querySelector('#ctfd-job-area') : null;
      if (area) paintCTFdJobNotice(area,'기록을 갱신하지 못했습니다. 자동으로 다시 시도합니다.');
      ctfdJobsPollTimer = setTimeout(() => { if (currentWorkspace?.id === workspaceId) pollCTFdJobs(workspaceId); },2000);
    }
  }
}

function paintCTFdJobNotice(area, message = '') {
  const notice = area.closest('.ctfd-import-history')?.querySelector('#ctfd-job-notice');
  if (!notice) return;
  notice.textContent = message;
  notice.hidden = !message;
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
  return importForm();
}

async function freshCTFdRefreshFromJob(button) {
  const workspaceId = currentWorkspace?.id, challengeId = button.dataset.challengeId;
  if (!workspaceId || !challengeId) throw new Error(i18n.t('새로고침할 문제를 다시 선택하세요.'));
  if (modal.open && modal.dataset.kind === 'ctfd-import') modal.close();
  await openChallenge(challengeId);
  if (currentWorkspace?.id !== workspaceId || currentChallenge?.id !== challengeId) throw new Error(i18n.t('문제를 다시 연 뒤 새로고침해 주세요.'));
  await refreshCTFdChallenge();
}

document.addEventListener('click', event => {
  // A link to the failed route itself fires no hashchange, so it would do nothing.
  const link = event.target.closest('a[href^="#"]');
  if (link?.getAttribute('href') === (location.hash || '#') && document.querySelector('[data-action="retry-page"]')) { run(pageRetry); return; }
  const button = event.target.closest('[data-action]');
  if (!button || button.disabled) return;
  const action = button.dataset.action;
  const actions = {
    'logout': async () => {
      if (authMode !== 'password') return;
      signingOut = true;
      try { await api('/api/auth/logout',{method:'POST'}); }
      catch (error) { if (!signedOut) throw error; }
      finally { signingOut = false; }
      // A poll can see the session end first. The form it opened may already hold typed text.
      sessionPersistent = false; if (!signedOut) showLogin(); noteDrafts.clear(); ctfdDrafts.clear(); detail.innerHTML = ''; modal.innerHTML = '';
    },
    'retry-page': async () => { await pageRetry?.(); document.querySelector('[data-action="retry-page"]')?.focus(); },
    'toggle-session-persistence': async () => {
      if (authMode !== 'password') return;
      const epoch = authEpoch;
      const result = await api('/api/auth/session/refresh',{method:'POST',body:{remember:!sessionPersistent}});
      if (epoch !== authEpoch) return;
      csrf = result.csrf_token;
      sessionPersistent = result.session_persistent === true;
      button.textContent = sessionPersistent ? '30일 로그인 해제' : '이 기기에서 30일 로그인 유지';
      toast(sessionPersistent ? '이 기기의 로그인을 30일간 유지합니다.' : '이 기기의 로그인이 기본 기간으로 변경됐습니다.');
    },
    'toggle-sidebar': () => toggleSidebar(button),
    'toggle-resource-meter': () => toggleResourceMeter(button),
    'toggle-solver-log-size': () => toggleSolverLogSize(button),
    'select-solver-agent': () => selectSolverAgent(button),
    'toggle-solver-agent-branch': () => toggleSolverAgentBranch(button),
    'solver-console-bottom': () => solverConsoleBottom(),
    'close-solver-console': () => solverConsoleDialog?.close(),
    'open-solver-accounts': () => openSolverAccounts(),
    'new-workspace': () => workspaceForm(), 'edit-workspace': () => workspaceForm(true),
    'show-challenge-trash': () => showChallengeTrash(),
    'show-clone-groups': () => showCloneGroups(),
    'move-clone-group': () => changeCloneGroup(button),
    'split-clone-group': () => changeCloneGroup(button, true),
    'restore-trash-challenge': async () => {
      const workspaceId = modal.dataset.workspaceId;
      if (!workspaceId || currentWorkspace?.id !== workspaceId) return;
      await api(`/api/workspaces/${workspaceId}/trash/${button.dataset.id}/restore`, {method:'POST'});
      await showChallengeTrash();
      await refreshChallenges();
    },
    'purge-trash-challenge': async () => {
      const workspaceId = modal.dataset.workspaceId;
      if (!workspaceId || currentWorkspace?.id !== workspaceId) return;
      if (!confirm(tr('Delete this challenge permanently?'))) return;
      await api(`/api/workspaces/${workspaceId}/trash/${button.dataset.id}`, {method:'DELETE'});
      await showChallengeTrash();
    },
    'show-staged-files': () => showStagedFiles(),
    'pause-staged-upload': () => {
      const active = stagedActiveUploads.get(button.dataset.id);
      if (active) { active.paused = true; active.controller.abort(); }
    },
    'resume-staged-upload': async () => {
      const active = stagedActiveUploads.get(button.dataset.id);
      if (active?.file) await uploadStagedFile(active.file,active.workspaceId,button.dataset.id);
    },
    'retry-staged-verification': () => uploadStagedFile(null,modal.dataset.workspaceId,button.dataset.id),
    'delete-staged-file': async () => {
      const workspaceId = modal.dataset.workspaceId, fileId = button.dataset.id;
      if (!workspaceId || !fileId || !confirm(i18n.t(button.dataset.unfinished ? '이 미완료 업로드와 임시 파일을 삭제할까요?' : '사전 파일을 삭제할까요? 이미 문제에 연결한 첨부는 남습니다.'))) return;
      const active = stagedActiveUploads.get(fileId);
      if (active) { active.paused = true; active.deleted = true; active.controller.abort(); }
      try { await stagedRequest(`/api/workspaces/${workspaceId}/staged-files/${fileId}`,{method:'DELETE'}); }
      catch (error) {
        if (active) active.deleted = false;
        await refreshStagedFiles(workspaceId).catch(() => {});
        throw error;
      }
      stagedActiveUploads.delete(fileId);
      await refreshStagedFiles(workspaceId);
    },
    'import-workspace-transfer': () => showTransferImport('workspace'),
    'export-workspace-transfer': () => showTransferExport('workspace'),
    'import-challenge-transfer': () => showTransferImport('challenge',currentWorkspace?.id),
    'export-challenge-transfer': () => showTransferExport('challenge'),
    'receive-workspace-direct': () => showDirectInvitation('workspace'),
    'receive-challenge-direct': () => showDirectInvitation('challenge',currentWorkspace?.id),
    'send-workspace-direct': () => showDirectSend('workspace'),
    'send-challenge-direct': () => showDirectSend('challenge'),
    'create-direct-invitation': () => createDirectInvitation(),
    'approve-direct-invitation': () => approveDirectInvitation(),
    'revoke-direct-invitation': () => revokeDirectInvitation(),
    'copy-direct-url': async () => { const value = directInviteState?.url; if (!value) return; const result = await copyText(value); copyToast(result,value); },
    'copy-direct-token': async () => { const value = directInviteState?.token; if (!value) return; const result = await copyText(value); copyToast(result,value); },
    'open-direct-result': () => openDirectResult(),
    'start-direct-send': () => startDirectSend(event.detail),
    'cancel-direct-send': () => cancelDirectSend(),
    'new-direct-send': () => resetDirectSend(),
    'download-transfer': () => downloadTransfer(),
    'start-transfer-upload': () => startTransferUpload(),
    'pause-transfer-upload': () => { if (transferState?.running) { transferState.paused = true; transferState.controller?.abort(); } },
    'cancel-transfer-upload': () => cancelTransferUpload(),
    'confirm-transfer-import': () => confirmTransferImport(),
    'workspace-ctfd-connection': () => {
      if (formDirty()) throw new Error(i18n.t('작업공간 변경사항을 먼저 저장하세요.'));
      return ctfdSubmitSettings();
    },
    'new-challenge': () => challengeForm(), 'edit-challenge': async () => { const c = currentChallenge; await saveNotes(true); if (currentChallenge === c && currentWorkspace?.id === c.workspace_id) await challengeForm(true); },
    'clone-challenge': () => cloneChallenge(),
    'add-relation': () => changeRelation(),
    'install-release-update': () => installReleaseUpdate(button),
    'refresh-release-update': () => refreshReleaseUpdatePanel(true),
    'open-admin-log-export': () => showAdminLogExport(),
    'download-admin-logs': async () => {
      const form = modal.querySelector('#admin-log-export-form');
      if (!form) return;
      button.disabled = true;
      try {
        const response = await fetch(`/api/admin/logs/export?${adminLogParams(form)}`, {credentials:'same-origin'});
        if (!response.ok) throw new Error(i18n.t('Could not export service logs.'));
        downloadBlob(await response.blob(), 'ctf-agent-diagnostics.zip');
        modal.close();
      } finally {
        button.disabled = false;
      }
    },
    'refresh-profile-avatar': async () => {
      sessionUser = await api('/api/auth/avatar/refresh', {method:'POST'});
      const topAvatar = document.querySelector('.topbar .avatar');
      if (topAvatar) topAvatar.innerHTML = avatarMarkup(sessionUser);
      const preview = document.querySelector('#profile-avatar-preview');
      if (preview) preview.innerHTML = avatarMarkup(sessionUser);
    },
    'remove-relation': () => changeRelation(button.dataset.id),
    'open-related-challenge': () => openChallenge(button.dataset.id),
    'edit-related-evidence': () => editRelatedEvidence(button.dataset.id),
    'stop-related-evidence': async () => {
      const form = modal.querySelector('#related-evidence-form');
      const target = currentChallenge;
      if (!form || !target || target.id !== form.dataset.challengeId || target.workspace_id !== form.dataset.workspaceId) throw new Error(i18n.t('문제를 다시 선택하세요.'));
      const result = await api(`${path(target.id,target.workspace_id)}/relations/${form.dataset.relatedId}/evidence`,{method:'DELETE'});
      target.related_challenges = result.related_challenges || [];
      modal.close();
      const area = detail.querySelector('#challenge-relations');
      if (area) area.innerHTML = relatedChallengeMarkup(target);
      toast('공유 자료를 해제했습니다.');
    },
    'remove-challenge-file': () => {
      const form = activeChallengeUploadForm(), index = Number(button.dataset.index);
      if (!form || !Number.isInteger(index)) return;
      selectedChallengeFiles(form).splice(index,1); renderChallengeFiles(form);
    },
    'close-modal': () => { if (busyForms.has(modal.querySelector('form')) || transferState?.importing || directSendBusy) return; if (modalInputAtRisk() && !confirm(i18n.t('작성 중인 변경 내용을 버리고 닫을까요?'))) return; pauseStagedUploads(); ++modalRendering; modal.close(); importPreview = null; },
    'close-detail': () => {
      if (detailBusy) return;
      if (notesDirty() && !confirm(i18n.t('저장하지 않은 노트가 있습니다. 닫을까요?'))) return;
      rememberNotes(); stopSolverPolling(); ++challengeRendering;
      if (solverConsoleDialog?.open) solverConsoleDialog.close();
      detail.close();
    },
    'open-challenge': () => openChallenge(button.dataset.id),
    'open-solver-session': () => openSolverSession(button),
    'copy-list-flag': async () => { const flag = challengeFlags.get(button.dataset.id); if (!flag || currentWorkspace?.id !== button.dataset.workspaceId) throw new Error(i18n.t('Flag를 다시 불러와 주세요.')); const result = await copyText(flag); copyToast(result, flag); },
    'copy-list-writeup': () => copyChallengeWriteup(button),
    'complete-list-challenge': () => completeListChallenge(button),
    'start-list-solver': () => startListSolver(button),
    'filter': async () => { selectedStatus = button.dataset.status; await refreshChallenges(); },
    'clear-filter': () => clearChallengeFilters(),
    'save-notes': () => saveNotes(),
    'copy-notes': async () => { const notes = document.querySelector('#notes-editor').value; const result = await copyText(notes); copyToast(result, notes); },
    'copy-flag': async () => { const flag = currentChallenge.flag || ''; const result = await copyText(flag); copyToast(result, flag); },
    'start-solver': () => startSolver(),
    'confirm-solver-retry-settings': () => {
      clearSolverRetryWarning();
      repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
    },
    'approve-ultra-escalation': () => approveUltraEscalation(),
    'open-solver-peer-evidence': () => openSolverPeerEvidence(),
    'cancel-solver': () => cancelSolver(button),
    'reject-solver-flag': () => rejectSolverFlag(),
    'copy-solver-flag': async () => { if (!currentSolverJob?.flag) throw new Error(i18n.t('발견된 Flag가 없습니다.')); const flag = currentSolverJob.flag; const result = await copyText(flag); copyToast(result, flag); },
    'copy-solver-writeup': async () => { const writeup = solverWriteup(); if (!writeup) throw new Error(i18n.t('완성된 write-up이 없습니다.')); const result = await copyText(writeup); copyToast(result, writeup); },
    'download-solver-writeup': () => { const writeup = solverWriteup(); if (!writeup) throw new Error(i18n.t('완성된 write-up이 없습니다.')); downloadBlob(new Blob([writeup],{type:'text/markdown;charset=utf-8'}),solverFilename()); },
    'refine-writeup': () => startWriteupRefinement(),
    'cancel-writeup-refine': () => cancelWriteupRefinement(),
    'download-notes': () => downloadNotes(),
    'reload-notes': () => reloadNotes(),
    'upload-notes': () => document.querySelector('#notes-file').click(),
    'complete': () => changeCompletion('complete'),
    'reopen': () => changeCompletion('reopen'),
    'delete-challenge': async () => { const c = currentChallenge; if (!confirm(i18n.format('Move {name} to the trash?',{name:c.name}))) return; await api(path(c.id,c.workspace_id),{method:'DELETE'}); noteDrafts.delete(noteKey(c)); if (currentChallenge === c) { stopSolverPolling(); detail.close(); } await refreshChallenges(); toast(i18n.t('Moved to trash.')); },
    'delete-workspace': async () => { const w = currentWorkspace; if (!confirm(i18n.format('“{name}” 작업공간의 모든 문제와 자료를 삭제할까요? 되돌릴 수 없습니다.',{name:w.name}))) return; stopChallengeListPolling(); try { await api(`/api/workspaces/${w.id}`,{method:'DELETE'}); } catch (error) { if (currentWorkspace?.id === w.id) startChallengeListPolling(w.id); throw error; } ctfdDrafts.delete(w.id); if (currentWorkspace?.id === w.id) { modal.close(); location.hash = ''; } toast('작업공간을 삭제했습니다.'); },
    'delete-attachment': async () => { const c = currentChallenge; if (!confirm(i18n.t('첨부파일을 삭제할까요?'))) return; await saveNotes(true); await api(`${path(c.id,c.workspace_id)}/attachments/${button.dataset.id}`,{method:'DELETE'}); if (currentChallenge === c) await openChallenge(c.id); },
    'ctfd-import': () => { ctfdRetryId = null; return importForm(); },
    'refresh-ctfd-jobs': () => pollCTFdJobs(currentWorkspace?.id),
    'ctfd-job-history': () => { showCTFdImportProgress(currentWorkspace.id); return pollCTFdJobs(currentWorkspace.id); },
    'ctfd-sync': () => previewCTFdSync(),
    'ctfd-sync-retry': () => previewCTFdSync(),
    'open-ctfd-source-challenge': async () => {
      if (currentWorkspace?.id !== button.dataset.workspaceId) throw new Error(i18n.t('작업공간을 다시 확인하세요.'));
      if (modal.open) modal.close();
      await openChallenge(button.dataset.id);
    },
    'refresh-ctfd-challenge': () => refreshCTFdChallenge(),
    'ctfd-refresh-auth': () => ctfdRefreshAuthForm(),
    'ctfd-submit-settings': () => ctfdSubmitSettings(),
    'refresh-ctfd-submit': () => refreshCTFdSubmit(),
    'disconnect-ctfd-submit': () => disconnectCTFdSubmit(),
    'cancel-ctfd': async () => { await api(`/api/workspaces/${currentWorkspace.id}/ctfd/jobs/${button.dataset.id}/cancel`,{method:'POST'}); await pollCTFdJobs(currentWorkspace?.id); },
    'retry-ctfd': () => retryCTFdJob(button),
    'fresh-refresh-ctfd': () => freshCTFdRefreshFromJob(button),
    'new-user': () => newUserForm(),
    'user-active': async () => { if (!confirm(i18n.t('사용자 활성 상태를 변경할까요? 비활성 사용자는 기존 세션으로도 접근할 수 없습니다.'))) return; await api(`/api/admin/users/${button.dataset.id}`,{method:'PATCH',body:{active:button.dataset.active === 'true'}}); await renderAdmin(); },
    'user-password': () => { openModal('비밀번호 초기화',i18n.format('{name} 사용자의 로그인 비밀번호를 바꿉니다.',{name:button.dataset.name}),'<label>새 비밀번호<input type="password" name="password" autocomplete="new-password" minlength="4" maxlength="1024" required><span class="form-hint">4자 이상 · 조합 조건 없음</span></label>','<button type="button" data-action="close-modal">취소</button><button class="primary" type="submit">비밀번호 변경</button>','reset-user-form'); modal.querySelector('form').dataset.userId = button.dataset.id; },
    'cleanup-uploads': async () => { const result = await api('/api/admin/uploads/cleanup',{method:'POST'}); toast(`만료된 업로드 ${result.removed}개를 정리했습니다.`); },
    'pause-upload': () => { const active = activeUploads.get(button.dataset.id); if (active) { active.paused = true; active.controller.abort(); } },
    'resume-upload': async () => { const active = activeUploads.get(button.dataset.id); if (active) { await uploadFile(active.file,active.workspaceId,active.challengeId,button.dataset.id); if (detail.open && currentChallenge?.id === active.challengeId) await openChallenge(active.challengeId); } },
    'cancel-upload': async () => { if (!confirm(i18n.t('이 미완료 업로드와 임시 파일을 삭제할까요?'))) return; const active = activeUploads.get(button.dataset.id); if (active) { active.paused = true; active.controller.abort(); } await api(`/api/uploads/${button.dataset.id}`,{method:'DELETE'}); activeUploads.delete(button.dataset.id); if (currentWorkspace && currentChallenge) await refreshUploads(currentWorkspace.id,currentChallenge.id); },
  };
  if (actions[action]) {
    event.preventDefault();
    if (['save-notes','reload-notes','complete','reopen','reject-solver-flag','delete-challenge','delete-attachment','edit-challenge','clone-challenge'].includes(action)) detailAction(actions[action],button);
    else if (['refresh-ctfd-submit','disconnect-ctfd-submit','cancel-solver','filter'].includes(action)) run(actions[action]);
    else run(actions[action], button);
  }
});

// A status filter sits beside the search box: clicking one leaves the caret where it was.
document.addEventListener('mousedown', event => {
  if (document.activeElement?.id === 'search-input' && event.target.closest?.('[data-action="filter"]')) event.preventDefault();
});

document.addEventListener('submit', event => {
  const form = event.target;
  if (form.matches?.('.challenge-inline-input')) {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    runForm(() => continueListSolver(form,body),form,form.querySelector('button[type="submit"]')).then(() => syncInlineInput(form));
    return;
  }
  if (!form.id) return;
  const known = ['login-form','setup-form','new-workspace-form','edit-workspace-form','new-challenge-form','edit-challenge-form','search-form','password-form','username-form','new-user-form','reset-user-form','solver-capacity-form','solver-preferences-form','admin-log-export-form','solver-guidance-form','solver-console-guidance-form','solver-peer-evidence-form','ctfd-preview-form','ctfd-import-form','ctfd-sync-form','ctfd-refresh-preview-form','ctfd-refresh-auth-form','ctfd-submit-connection-form','related-evidence-form'];
  if (!known.includes(form.id)) return;
  event.preventDefault();
  const challengeFiles = form.id === 'new-challenge-form' ? [...selectedChallengeFiles(form)] : [];
  const data = new FormData(form);
  const body = Object.fromEntries(data);
  const stagedFiles = [...form.querySelectorAll('input[name="staged_file_ids"]:checked')].map(input => ({id:input.value,name:input.dataset.name,size:Number(input.dataset.size) || 0}));
  if (form.id === 'ctfd-submit-connection-form') { run(() => saveCTFdSubmitConnection(form,body)); return; }
  const submitForm = async () => {
    if (form.id === 'setup-form') {
      if (body.password !== body.confirmation) throw new Error('비밀번호 확인이 일치하지 않습니다.');
      const result = await api('/api/auth/setup',{method:'POST',body:{username:body.username,password:body.password,setup_token:body.setup_token || ''}});
      sessionStarted(); csrf = result.csrf_token; sessionUser = result.user; sessionPersistent = false; form.reset(); await render();
    } else if (form.id === 'login-form') {
      const result = await api('/api/auth/login',{method:'POST',body:{username:body.username,password:body.password,remember:data.has('remember')}}); sessionStarted(); csrf = result.csrf_token; if (sessionUser && sessionUser.id !== result.user.id) { noteDrafts.clear(); ctfdDrafts.clear(); clearAccountsReturnTarget(); } sessionUser = result.user; sessionPersistent = result.session_persistent === true; form.reset(); await render();
    } else if (form.id === 'related-evidence-form') {
      const target = currentChallenge;
      if (!target || target.id !== form.dataset.challengeId || target.workspace_id !== form.dataset.workspaceId) throw new Error(i18n.t('문제를 다시 선택하세요.'));
      const result = await api(`${path(target.id,target.workspace_id)}/relations/${form.dataset.relatedId}/evidence`,
        {method:'PUT',body:{observation:body.observation || '',include_flag:data.has('include_flag')}});
      target.related_challenges = result.related_challenges || [];
      modal.close();
      const area = detail.querySelector('#challenge-relations');
      if (area) area.innerHTML = relatedChallengeMarkup(target);
      toast('검증 자료를 공유했습니다.');
    } else if (form.id === 'new-workspace-form' || form.id === 'edit-workspace-form') {
      const edit = form.id === 'edit-workspace-form';
      body.open_challenge_after_create = data.has('open_challenge_after_create');
      const w = await api(edit ? `/api/workspaces/${form.dataset.workspaceId}` : '/api/workspaces',{method:edit?'PATCH':'POST',headers:edit ? conditional(form.dataset.editToken) : {},body}); modal.close();
      if (signedOut) return;
      if (location.hash === `#w/${w.id}`) { currentWorkspace = w; await renderWorkspace(); } else { selectedStatus='';selectedCategory='';selectedSort='added_desc';search='';location.hash = `w/${w.id}`; }
      toast(edit ? '작업공간 설정을 저장했습니다.' : '작업공간을 만들었습니다.');
    } else if (form.id === 'new-challenge-form' || form.id === 'edit-challenge-form') {
      const edit = form.id === 'edit-challenge-form'; delete body.files; delete body.staged_file_ids;
      if (body.remote_mode !== 'endpoint') body.remote = '';
      const workspaceId = form.dataset.workspaceId;
      const c = await api(edit ? path(form.dataset.challengeId,workspaceId) : path(null,workspaceId),{method:edit?'PATCH':'POST',headers:edit ? conditional(form.dataset.editToken) : {},body});
      // Nothing awaits before this: the list poll can paint the card from now on.
      const items = queueAttachmentWork(workspaceId,c.id,[...stagedFiles,...challengeFiles]);
      const linking = items.slice(0,stagedFiles.length), uploading = items.slice(stagedFiles.length);
      const attachmentsStopped = () => items[0]?.work.stopped === true;
      const failures = [];
      modal.close();
      let attached = 0;
      for (const item of linking) {
        if (attachmentsStopped()) break;
        let linked = false;
        try {
          await stagedRequest(`/api/workspaces/${workspaceId}/challenges/${c.id}/staged-files/${encodeURIComponent(item.source.id)}/attach`,{method:'POST'});
          linked = true; attached++;
        } catch (error) { failures.push(`${item.name || item.source.id}: ${transferErrorText(error)}`); }
        finishAttachmentItem(item,linked);
      }
      // The files are queued and Start is held, so a failed repaint must not skip them.
      try {
        if (currentWorkspace?.id === workspaceId) {
          await refreshChallenges();
          if (edit || currentWorkspace?.open_challenge_after_create) await openChallenge(c.id);
        }
      } catch (error) { failures.push(transferErrorText(error)); }
      if (!attachmentsStopped()) {
        toast('문제를 저장했습니다.');
        if (attached) toast(i18n.t('사전 파일 {count}개를 문제에 연결했습니다.').replace('{count}',attached));
      }
      const uploads = await uploadQueuedAttachments(uploading,workspaceId,c.id);
      failures.push(...uploads.failures);
      if (uploading.length) {
        try {
          if (detail.open && currentChallenge?.id === c.id) await refreshChallengeAttachmentsInPlace(workspaceId,c.id);
          if (currentWorkspace?.id === workspaceId) await refreshChallenges();
        } catch (error) { failures.push(transferErrorText(error)); }
      }
      if (attachmentsStopped()) return;
      if (uploads.saved) toast(`첨부파일 ${uploads.saved}개를 저장했습니다.`);
      if (failures.length) toast(failures.join(' / '),true);
    } else if (form.id === 'search-form') { search = body.q; selectedCategory = document.querySelector('#category-filter').value; selectedSort = document.querySelector('#sort-order').value; await refreshChallenges(); }
    else if (form.id === 'solver-preferences-form') {
      sessionUser = await api('/api/auth/preferences', {method:'PATCH',body:{ultra_escalation_default:body.ultra_escalation_default}});
      solverUltraEscalationMode = sessionUser.ultra_escalation_default;
      toast(i18n.t('Solver preference saved.'));
    }
    else if (form.id === 'password-form') { if (body.new_password !== body.confirmation) throw new Error(i18n.t('새 비밀번호 확인이 일치하지 않습니다.')); delete body.confirmation; const epoch = authEpoch; const result = await api('/api/auth/password',{method:'POST',body}); if (epoch !== authEpoch) return; csrf = result.csrf_token; form.reset(); toast('비밀번호를 변경했습니다.'); }
    else if (form.id === 'username-form') { const epoch = authEpoch; const result = await api('/api/auth/username',{method:'POST',body}); if (epoch !== authEpoch) return; sessionUser.username = result.username; csrf = result.csrf_token; renderSettings(); toast('아이디를 변경했습니다.'); }
    else if (form.id === 'new-user-form') { await api('/api/admin/users',{method:'POST',body}); form.reset(); modal.close(); await renderAdmin(); toast('사용자를 추가했습니다.'); }
    else if (form.id === 'reset-user-form') { await api(`/api/admin/users/${form.dataset.userId}/password`,{method:'POST',body}); form.reset(); modal.close(); toast('비밀번호를 변경했습니다.'); }
    else if (form.id === 'solver-capacity-form') { const maximum = String(body.maximum || '').trim(); await api('/api/admin/solver-capacity',{method:'PUT',body:{maximum:maximum ? Number(maximum) : null}}); await renderAdmin(); toast('솔버 최대 수를 저장했습니다.'); }
    else if (form.id === 'admin-log-export-form') { await previewAdminLogs(form); }
    else if (form.id === 'solver-guidance-form') { await sendSolverGuidance(body.message,'same_turn',{expectedJobId:form.dataset.jobId}); }
    else if (form.id === 'solver-console-guidance-form') { await sendSolverGuidance(body.message,body.requested_delivery || 'next_turn',{expectedJobId:form.dataset.jobId}); }
    else if (form.id === 'solver-peer-evidence-form') { await sendSolverPeerEvidence(form,body); }
    else if (form.id === 'ctfd-preview-form') {
      const saved = body.connection_mode === 'saved';
      delete body.connection_mode;
      if (saved) {
        for (const key of ['url','auth_type','token','username','password']) delete body[key];
        body.use_saved_connection = true;
      } else {
        if (!body.token) delete body.token;
        body.url = body.url.trim(); if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(body.url)) body.url = `https://${body.url}`;
      }
      const workspaceId = currentWorkspace.id, generation = modalRendering, page = rendering, hash = location.hash;
      const stillHere = () => ctfdSyncViewCurrent(workspaceId,generation,page,hash,'ctfd-import');
      let result;
      try { result = await api(`/api/workspaces/${workspaceId}/ctfd/preview`,{method:'POST',body}); }
      catch (error) { if (stillHere()) throw error; return; }
      form.reset();
      if (stillHere()) showImportPreview(result,body);
    } else if (form.id === 'ctfd-import-form') {
      const ids = data.getAll('challenge').map(Number); if (!ids.length) throw new Error(i18n.t('가져올 문제를 선택하세요.'));
      const workspaceId = currentWorkspace.id, generation = modalRendering, page = rendering, hash = location.hash, retryId = ctfdRetryId;
      const endpoint = retryId ? `/api/workspaces/${workspaceId}/ctfd/jobs/${retryId}/retry` : `/api/workspaces/${workspaceId}/ctfd/import`;
      const payload = importPreview.result.preview_id ? {preview_id:importPreview.result.preview_id,challenge_ids:ids} : {...importPreview.credentials,challenge_ids:ids};
      await api(endpoint,{method:'POST',body:payload});
      ctfdDrafts.delete(workspaceId);
      if (ctfdRetryId === retryId) ctfdRetryId = null;
      if (ctfdSyncViewCurrent(workspaceId,generation,page,hash,'ctfd-import')) {
        importPreview = null; showCTFdImportProgress(workspaceId); await refreshChallenges(); await pollCTFdJobs(workspaceId);
      }
      toast('CTFd 가져오기를 시작했습니다.');
    } else if (form.id === 'ctfd-sync-form') {
      const ids = data.getAll('challenge').map(Number).filter(id => Number.isInteger(id) && id > 0);
      await startCTFdSync(form,ids);
    } else if (form.id === 'ctfd-refresh-preview-form') {
      const preview = importPreview;
      if (!preview || preview.mode !== 'refresh' || !preview.result?.preview_id ||
          preview.workspaceId !== form.dataset.workspaceId || preview.challengeId !== form.dataset.challengeId ||
          currentWorkspace?.id !== preview.workspaceId || currentChallenge?.id !== preview.challengeId) {
        throw new Error(i18n.t('CTFd 변경 미리보기가 만료되었습니다. 다시 확인하세요.'));
      }
      const generation = modalRendering, page = rendering, hash = location.hash;
      await launchCTFdChallengeRefresh({
        preview_id:preview.result.preview_id,
        selected_fields:data.getAll('field'),
      });
      if (ctfdSyncViewCurrent(preview.workspaceId,generation,page,hash,'ctfd-refresh-preview')) {
        importPreview = null; showCTFdImportProgress(preview.workspaceId); await pollCTFdJobs(preview.workspaceId);
      }
    } else if (form.id === 'ctfd-refresh-auth-form') {
      await startAuthenticatedCTFdRefresh(form,body);
    }
  };
  const submitButton = form.querySelector('button[type="submit"],button:not([type])');
  if (form.id === 'login-form' || form.id === 'setup-form') submitCredentials(form,submitForm,submitButton);
  else runForm(submitForm,form,submitButton);
});

document.addEventListener('change', event => {
  const input = event.target;
  if (input.id === 'admin-log-workspace') run(() => adminLogChallenges(input.value));
  if (input.closest?.('#admin-log-export-form')) {
    const form = input.closest('form');
    form.dataset.previewReady = 'false';
    form.querySelector('[data-action="download-admin-logs"]').disabled = true;
    form.querySelector('#admin-log-preview').textContent = tr('Preview before downloading.');
  }
  if (input.id === 'transfer-archive' && transferState?.kind === 'import') {
    const state = transferState;
    if (state.running || state.importing) return;
    state.file = input.files?.[0] || null;
    state.uploadId = ''; state.storageKey = ''; state.offset = 0; state.preview = null; state.paused = false;
    const area = modal.querySelector('#transfer-preview');
    if (area) { area.innerHTML = ''; area.hidden = true; }
    transferUploadStatus(state,state.file ? `${state.file.name} · ${size(state.file.size)} · ${i18n.t('업로드할 준비가 됐습니다.')}` : i18n.t('ZIP 파일을 선택하세요.'));
  }
  if (input.id === 'challenge-files') {
    addChallengeFiles(input.closest('form'),input.files);
    input.value = '';
  }
  if (input.id === 'staged-files-input' && input.files?.length) run(async () => {
    const workspaceId = modal.dataset.workspaceId, files = [...input.files];
    input.value = '';
    await addStagedFiles(files,workspaceId);
  });
  if (input.dataset.stagedResume && input.files?.length) run(async () => {
    const workspaceId = modal.dataset.workspaceId, fileId = input.dataset.stagedResume;
    const file = input.files[0]; input.value = '';
    await uploadStagedFile(file,workspaceId,fileId);
  },input);
  if (input.matches?.('.challenge-inline-input select[name="remote_mode"]')) syncInlineInput(input.form);
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
    clearSolverRetryWarning();
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
    clearSolverRetryWarning();
    solverReasoning = input.value;
    repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
  }
  if (input.id === 'solver-fast-toggle') {
    clearSolverRetryWarning();
    solverServiceTier = input.checked ? 'fast' : null;
    repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
  }
  if (input.id === 'solver-ultracode-toggle') {
    clearSolverRetryWarning();
    solverUltracode = input.checked;
    repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
  }
  if (input.id === 'solver-ultra-escalation') {
    clearSolverRetryWarning();
    solverUltraEscalationMode = ['ask','auto','off'].includes(input.value) ? input.value : 'ask';
    repaintSolverConfiguration(currentWorkspace?.id,currentChallenge?.id,solverRendering);
  }
  if (input.id === 'category-filter') run(async () => { selectedCategory = input.value; await refreshChallenges(); });
  if (input.id === 'sort-order') run(async () => { selectedSort = input.value; await refreshChallenges(); });
  if (['ctfd-auth-type','ctfd-import-source'].includes(input.id)) syncCTFdImportSource(input.closest('form'));
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
    const c = currentChallenge, items = queueAttachmentWork(c.workspace_id,c.id,[...input.files]);
    const {saved,failures} = await uploadQueuedAttachments(items,c.workspace_id,c.id);
    if (items[0]?.work.stopped) return;
    if (detail.open && currentChallenge?.id === c.id) await openChallenge(c.id); input.value = '';
    if (failures.length) throw new Error(failures.join(' / ')); if (saved) toast(`첨부파일 ${saved}개를 저장했습니다.`);
  },input);
  if (input.id === 'solver-console-files') run(async () => {
    const challenge = currentChallenge, files = [...input.files];
    if (!challenge) return;
    const items = queueAttachmentWork(challenge.workspace_id,challenge.id,files);
    try {
      const {saved:completed,failures} = await uploadQueuedAttachments(items,challenge.workspace_id,challenge.id);
      if (items[0]?.work.stopped) return;
      await refreshChallengeAttachmentsInPlace(challenge.workspace_id,challenge.id);
      if (completed && currentChallenge?.id === challenge.id && solverIsActive(currentSolverJob) && currentSolverJob.guidance_allowed !== false) {
        const names = files.filter(file => file?.name).map(file => file.name).slice(0, 20);
        try {
          await sendSolverGuidance(`새 문제 파일 ${completed}개를 업로드했습니다. attachments/에서 새로 추가된 파일을 확인하고 풀이를 이어가세요.${names.length ? ` 파일: ${names.join(', ')}` : ''}`.slice(0, 4000),
            (currentSolverJob.model || currentSolverJob.configuration || {}).provider === 'claude' ? 'next_turn' : 'same_turn',{keepDraft:true});
        } catch (error) { toast(`${i18n.t('파일은 저장됐습니다. 추가 명령 전달')}: ${i18n.t(error.message)}`, true); }
      }
      if (completed) toast(`첨부파일 ${completed}개를 저장했습니다.`);
      if (failures.length) throw new Error(failures.join(' / '));
    } finally { input.value = ''; }
  },input);
  if (input.id === 'notes-file' && input.files.length) detailAction(async () => {
    const c = currentChallenge, editor = document.querySelector('#notes-editor'), previous = editor.value;
    try {
      if (previous && !confirm(i18n.t('현재 노트를 선택한 파일의 내용으로 바꿀까요?'))) return;
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

// Focus only reveals the caret line, and a tap reveals nothing, so at phone width the
// editor could stay a thin strip at the bottom of the dialog while the user types.
document.addEventListener('focusin', event => {
  const editor = event.target;
  if (editor.id !== 'notes-editor' || !window.matchMedia?.('(max-width: 500px)').matches) return;
  requestAnimationFrame(() => editor.scrollIntoView({block:'nearest'}));
});

document.addEventListener('focusout', event => {
  if (!event.target.closest?.('#solver-panel .solver-configuration')) return;
  const workspaceId = currentWorkspace?.id, challengeId = currentChallenge?.id, generation = solverRendering;
  setTimeout(() => {
    if (solverContext(workspaceId,challengeId,generation)) {
      repaintSolverConfiguration(workspaceId,challengeId,generation);
    }
  },0);
});

document.addEventListener('input', event => {
  if (event.target.id === 'notes-editor') { rememberNotes(); const state = document.querySelector('#notes-save-state'); if (state) { state.classList?.remove('hidden'); state.textContent = '저장하지 않은 변경 사항'; } }
  if (event.target.id === 'writeup-refine-instruction') writeupRefineInstruction = event.target.value;
  if (['solver-guidance-message','solver-console-message'].includes(event.target.id)) {
    solverGuidanceDraft = event.target.value;
    // Polls no longer rebuild the forms, so the two composers stay in step here.
    const other = document.querySelector(event.target.id === 'solver-console-message' ? '#solver-guidance-message' : '#solver-console-message');
    if (other) other.value = event.target.value;
  }
  const ctfdForm = event.target.closest?.('#ctfd-preview-form,#ctfd-import-form,#ctfd-sync-form');
  if (ctfdForm?.id === 'ctfd-preview-form') rememberCTFdForm(ctfdForm);
  else if (ctfdForm) rememberCTFdSelection(ctfdForm);
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
document.addEventListener('dragover', event => {
  if (!modal.open || modal.dataset.kind !== 'staged-files' || !fileDrag(event.dataTransfer)) return;
  event.preventDefault();
  modal.classList.add('staged-dragover');
  try { event.dataTransfer.dropEffect = 'copy'; } catch {}
});
document.addEventListener('dragleave', event => {
  if (!event.relatedTarget) modal.classList.remove('staged-dragover');
});
document.addEventListener('drop', event => {
  if (!modal.open || modal.dataset.kind !== 'staged-files' || !fileDrag(event.dataTransfer)) return;
  event.preventDefault(); modal.classList.remove('staged-dragover');
  const workspaceId = modal.dataset.workspaceId;
  run(() => addStagedFiles([...event.dataTransfer.files],workspaceId));
});
window.addEventListener('dragend',resetChallengeFileDrag);
window.addEventListener('blur',resetChallengeFileDrag);

document.addEventListener('keydown', event => {
  if (['Enter',' '].includes(event.key) && event.target.matches('tr[data-action]')) { event.preventDefault(); event.target.click(); }
});
detail.addEventListener('cancel', event => {
  if (detailBusy || (notesDirty() && !confirm(i18n.t('저장하지 않은 노트가 있습니다. 닫을까요?')))) event.preventDefault();
  else { rememberNotes(); stopSolverPolling(); ++challengeRendering; }
});
detail.addEventListener('close', () => { if (!detail.open) stopSolverPolling(); leaveGoneWorkspace(); });
modal.addEventListener('cancel', event => { if (busyForms.has(modal.querySelector('form')) || transferState?.importing || directSendBusy || (modalInputAtRisk() && !confirm(i18n.t('작성 중인 변경 내용을 버리고 닫을까요?')))) event.preventDefault(); else { pauseStagedUploads(); ++modalRendering; } });
modal.addEventListener('close', () => {
  resetChallengeFileDrag(); modal.classList.remove('staged-dragover'); pauseStagedUploads();
  if (!modal.open) {
    if (transferState?.running) { transferState.paused = true; transferState.controller?.abort(); }
    transferState = null;
    transferExportController?.abort(); transferExportController = null;
    if (directInviteTimer !== null) clearTimeout(directInviteTimer);
    directInviteTimer = null; directInviteState = null;
    if (directSendTimer !== null) clearTimeout(directSendTimer);
    directSendTimer = null; directSendState = null;
    const directToken = modal.querySelector('#direct-send-token');
    if (directToken) directToken.value = '';
    for (const secret of modal.querySelectorAll('#ctfd-preview-form input[type="password"]')) secret.value = '';
    ++modalRendering; modal.removeAttribute('aria-busy'); modal.dataset.kind = '';
  }
  importPreview = null;
  leaveGoneWorkspace();
});
window.addEventListener('hashchange', event => {
  if ((modalInputAtRisk() || notesDirty() || detailBusy || transferState?.running || transferState?.importing || directSendBusy || [...stagedActiveUploads.values()].some(upload => upload.running) || (modal.open && busyForms.has(modal.querySelector('form')))) && !confirm(i18n.t('저장하지 않은 내용이나 진행 중인 요청이 있습니다. 다른 화면으로 이동할까요?'))) { if (accountsReturnPending) clearAccountsReturnTarget(); history.replaceState(null,'',event.oldURL); return; }
  accountsReturnPending = false;
  const returnRoute = accountsReturnRoute();
  if (returnRoute && location.hash === `#${returnRoute}`) clearAccountsReturnTarget();
  rememberNotes(); pauseStagedUploads(); stopSolverPolling(); stopResourcePolling(); stopChallengeListPolling(); ++challengeRendering; ++listRendering; ++modalRendering; challengeFlags.clear(); selectedStatus=''; selectedCategory=''; selectedSort='added_desc'; search=''; if (solverConsoleDialog?.open) solverConsoleDialog.close(); detail.close(); modal.close(); if (csrf) run(render);
});
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') { stopResourcePolling(); stopChallengeListPolling(); }
  else if (currentWorkspace?.id) {
    if (document.querySelector('#workspace-resource-meter') && !resourceMeterHidden()) startResourcePolling(currentWorkspace.id);
    if (document.querySelector('#challenge-area')) startChallengeListPolling(currentWorkspace.id);
  }
});
function repaintSolverLanguage(challenge) {
  const panel = detail.querySelector('#solver-panel');
  if (!panel) return;
  if (solverConsoleDialog?.open && currentSolverJob) morphMarkup(solverConsoleDialog,solverConsoleMarkup('',''));
  // These caches compare content, so unchanged events would keep their old language.
  panel._solverPainted = null;
  delete panel.dataset.solverLogKey;
  solverConsolePaintKey = '';
  const idle = panel.querySelector(':scope > .solver-configuration') && !panel.querySelector(':scope > .solver-error');
  if (currentSolverJob || idle) paintSolver(currentSolverJob,[],challenge.workspace_id,challenge.id,solverRendering);
  if (panel.querySelector(':scope > .solver-configuration')) repaintSolverConfiguration(challenge.workspace_id,challenge.id,solverRendering);
}

function repaintChallengeDetail() {
  const challenge = currentChallenge;
  if (!challenge || !detail.querySelector('#notes-editor')) return;
  morphMarkup(detail,challengeDetailMarkup(challenge,'',false));
  const relations = detail.querySelector('#challenge-relations');
  if (relations) morphMarkup(relations,relatedChallengeMarkup(challenge));
  paintUploads([],challenge.workspace_id,challenge.id);
  repaintSolverLanguage(challenge);
}

function repaintWorkspace(content) {
  const workspace = currentWorkspace;
  morphMarkup(content,workspaceMarkup(workspace));
  const area = content.querySelector('#challenge-area');
  if (area && challengeListing?.workspaceId === workspace.id) morphChallengeListing(area,challengeListing.result,workspace.id);
  if (resourceMeterSnapshot) paintResourceMeter(resourceMeterSnapshot);
  if (ctfdImportBadge) updateCTFdImportButton(ctfdImportBadge.jobs,ctfdImportBadge.workspaceId);
}

// Morphing keeps every node that survives, so open disclosures, typed values, focus
// and scroll stay put, and uploads and polls never notice. The observer has already
// switched literal source text; this redoes what was rendered in the old language.
// #accounts and #settings repaint themselves. An open modal is left as it is: only the
// picker changes language and showModal() makes it inert.
document.addEventListener('ctf-language-changed',() => {
  const content = document.querySelector('#content'), hash = location.hash.slice(1);
  if (document.querySelector('.page-failure')) repaintPageNotice();
  else if (content && hash === 'admin') {
    if (adminView) morphMarkup(content,adminMarkup(adminView));
    refreshReleaseUpdatePanel();
  } else if (content && currentWorkspace) repaintWorkspace(content);
  else if (content && !['accounts','settings'].includes(hash)) morphMarkup(content,overviewMarkup());
  if (detail.open) repaintChallengeDetail();
});
window.addEventListener('beforeunload', event => { if (notesDirty() || formDirty() || transferState?.running || transferState?.importing || directSendBusy || attachmentWork.size || [...stagedActiveUploads.values()].some(upload => upload.running)) { event.preventDefault(); event.returnValue = ''; } });
async function boot() {
  const attempt = ++bootAttempt;
  // Started first, so its limit runs beside the other steps and not after them.
  const language = i18n.init();
  language.catch(() => {});
  try {
    let state = await pageRequest('/api/auth/state');
    if (state?.authenticated) {
      // Open local access and an existing local cookie need no one-use ticket.
      // Start.cmd may still have supplied a fragment; do not leave it in the route.
      if (/^#\/local-access\/[A-Za-z0-9_-]{32}$/.test(window.location.hash))
        window.history.replaceState(null, '', window.location.pathname + window.location.search);
      pendingLocalTicket = '';
    } else if (await bootstrapLocalBrowser()) state = await pageRequest('/api/auth/state');
    await language;
    if (attempt !== bootAttempt) return;
    if (typeof state?.auth_mode !== 'string') throw new Error('서버 응답을 확인할 수 없습니다. 잠시 후 다시 시도하세요.');
    authMode = state.auth_mode;
    if (state.authenticated) { sessionStarted(); csrf = state.csrf_token; sessionUser = state.user; sessionPersistent = state.session_persistent === true; await render(); }
    else if (authMode === 'password') showLogin(false,state.configured,state.setup_available,state.setup_token_required);
    else app.innerHTML = `<main class="login-shell"><div class="login-card"><h1>${tr('Start.cmd를 실행해 이 브라우저를 연결하세요.')}</h1></div></main>`;
  } catch (error) {
    await language.catch(() => {});
    if (attempt === bootAttempt && !signedOut) showBootFailure(unanswered(error));
  }
}

async function bootstrapLocalBrowser() {
  const match = /^#\/local-access\/([A-Za-z0-9_-]{32})$/.exec(window.location.hash);
  if (match) {
    // The fragment never enters the HTTP request or access log. Remove it from
    // browser history before exchanging the single-use ticket for a cookie.
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    pendingLocalTicket = match[1];
  }
  if (!pendingLocalTicket) return false;
  await i18n.init();
  const response = await fetch('/api/auth/local/bootstrap', {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ticket: pendingLocalTicket}),
    signal: pageLoadSignal(),
  });
  // The server answered, so the ticket is spent. A request that never arrived keeps it for Retry.
  pendingLocalTicket = '';
  if (!response.ok) throw new Error('로컬 접속 링크를 확인할 수 없습니다. Start.cmd를 다시 실행하세요.');
  return true;
}
function pageLoadSignal() {
  return window.AbortSignal?.timeout?.(PAGE_LOAD_LIMIT_MS);
}
let pendingLocalTicket = '';

run(async () => { if (typeof window.setInterval === 'function') window.setInterval(updateSolverElapsedLabels,1000); await boot(); });
