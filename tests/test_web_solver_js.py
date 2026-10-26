"""Browser-independent UI regressions for solver polling and CSP-safe copy."""

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def _node(source: str, harness: str) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for browser-independent JavaScript regressions")
    result = subprocess.run(
        [node, "-e", harness], input=source, text=True, encoding="utf-8",
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_web_assets_use_external_csp_safe_styles_and_include_mobile_layouts():
    web = ROOT / "ctf_agent" / "web"
    for path in [web / "index.html", *web.glob("*.js")]:
        source = path.read_text(encoding="utf-8")
        assert "style=" not in source.lower(), path.name
        assert ".style." not in source, path.name
    theme = (web / "theme.css").read_text(encoding="utf-8")
    accounts = (web / "accounts.css").read_text(encoding="utf-8")
    app = (web / "app.js").read_text(encoding="utf-8")
    telegram = (web / "telegram.js").read_text(encoding="utf-8")
    assert "@media (max-width: 800px)" in theme
    assert ".sidebar nav { overflow-x: auto" in theme
    assert "@media (max-width: 500px)" in theme
    # Wide table descendants used to expand the document's top-layer
    # containing block on narrow Chrome viewports and shift dialogs off-screen.
    assert ".challenge-table { min-width: 0; table-layout: fixed; }" in theme
    assert ".challenge-table th:nth-child(5), .challenge-table td:nth-child(5) { display: none; }" in theme
    assert ".model-fields { grid-template-columns: 1fr; }" in accounts
    assert ".clipboard-proxy" in theme
    assert 'name="username" autocomplete="username"' in app
    assert 'name="password" autocomplete="current-password"' in app
    assert app.count('minlength="4"') == 6
    assert 'minlength="12"' not in app
    assert "최소 4자" in app
    assert '<option value="none">로그인 없이 가져오기</option>' in app
    assert '<option value="token">API 토큰</option>' in app
    assert '<option value="password">아이디와 비밀번호</option>' in app
    assert "body.url = `https://${body.url}`" in app
    assert "기본 OFF · CTFd 오답 패널티가 적용될 수 있습니다." in app
    assert "data-action=\"complete\"" in app and "data-action=\"reopen\"" in app
    assert 'data-action="toggle-solver-log-size"' in app
    assert ".solver-session-log.expanded" in theme
    assert 'data-action="reject-solver-flag"' in app
    assert "/reject-flag" in app
    assert "waiting_for_model:'모델 응답 대기'" in app
    assert "provider_connection_retry:'공급자 연결 재시도'" in app
    assert "reasoning_escalated:'추론 max 자동 승격'" in app
    assert "MAX_REQUIRED + 작업 근거 확인" in app
    assert "이번 실행에만 적용" in app
    assert 'id="solver-account-select"' in app
    assert 'id="solver-model-select"' in app
    assert 'id="solver-reasoning-select"' in app
    assert 'id="solver-fast-toggle"' in app
    assert "계정 관리에서 이 공급자의 선택 계정·모델·추론 수준을 먼저 설정하세요" not in app
    assert "일회용 연결 링크 발급" in telegram
    assert "Chat ID는 일회용 링크로 연결합니다" in telegram
    assert "Flag 알림에는 바로 쓰는 복사 버튼" not in telegram


def test_solver_ui_preserves_full_artifacts_explains_policy_and_stops_stale_polling():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'), events={}, timers=[];
function element(extra={}) { return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',value:'',disabled:false,
  dataset:{},options:[],append(){},remove(){},focus(){document.activeElement=this;},select(){},setSelectionRange(){},
  setAttribute(){},removeAttribute(){},querySelector(){return null;},querySelectorAll(){return [];},addEventListener(k,fn){this.listeners??={};this.listeners[k]=fn;},
  showModal(){this.open=true;},close(){this.open=false;}},extra); }
const nodes={app:element(),modal:element(),detail:element({open:true}),toasts:element(),'solver-panel':element(),
  'challenge-flag-box':element(),'copy-flag-button':element({disabled:true}),'challenge-status-badge':element(),
  'challenge-status-controls':element(),
  'notes-editor':element({value:'saved'}),'notes-save-state':element(),'challenge-area':null};
const document={activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)]??null,getElementById:id=>nodes[id]??null,
  createElement:()=>element(),addEventListener(k,fn){events[k]=fn;},execCommand:()=>true};
const reply=value=>({ok:true,status:200,json:async()=>value});
let fetchCalls=0;
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{clipboard:{writeText:async()=>{}}},
  location:{hash:'#w/workspace-one/c/challenge-one'},history:{replaceState(){}},console,Blob,File:class{},
  FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,
  confirm:()=>true,fetch:async()=>{fetchCalls++;throw new Error('unexpected fetch');},renderAccounts:async()=>{},
  setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){},assert,nodes,timers,reply,fetchCalls:0,setImmediate};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  currentWorkspace={id:'workspace-one',name:'One'};
  currentChallenge={id:'challenge-one',workspace_id:'workspace-one',name:'Long Flag',notes:'saved',notes_token:'t',flag:'',status:'pending'};
  solverRendering=7;
  const flag='FLAG{'+('<&"'.repeat(700))+'}';
  const policy={id:'job-one',workspace_id:'workspace-one',challenge_id:'challenge-one',status:'flag_found',terminal:true,flag,
    configuration:{model:'gpt-daybreak-blue-latest',reasoning_effort:'high'},network_policy:'general_internet',supported_challenge_mode:'static_attachments_and_open_internet',
    error:{code:'policy_security',category:'policy_security',provider_code:'CVP',message:'보안 정책으로 write-up 작성이 제한됐습니다.',retryable:false}};
  solverListedFlag='job-one:'+flag;solverSyncedWriteup='job-one';
  const normalizedPolicy=normalizeSolverPayload(policy);
  paintSolver(normalizedPolicy.job,[{sequence:2,status:'flag_found',progress:{code:'validating_flag',percent:100}}],'workspace-one','challenge-one',7);
  assert.equal(nodes['challenge-flag-box'].textContent,flag);
  assert.equal(nodes['copy-flag-button'].disabled,false);
  assert.ok(nodes['solver-panel'].innerHTML.includes('CVP'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('보안 작업 정책 제한'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('인터넷 사용 가능'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('&lt;&amp;&quot;'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('Flag 복사'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('오답으로 제외'));

  const completedAfterCancellation=solverPanelMarkup({
    ...policy,phase:'completed',status:'completed',terminal:true,cancel_requested:true,
  },[]);
  assert.ok(completedAfterCancellation.includes('완료'));
  assert.ok(!completedAfterCancellation.includes('중단 요청 중'));
  const cancelling=solverPanelMarkup({
    ...policy,phase:'running',status:'running',terminal:false,cancel_requested:true,
  },[]);
  assert.ok(cancelling.includes('중단 요청 중'));

  // A terminal worker release must not turn an authoritative flag_found
  // challenge into solved before a valid write-up commit reaches the API.
  currentChallenge.flag='FLAG{candidate}';currentChallenge.status='flag_found';currentChallenge.completion_source=null;
  solverListedFlag='job-one:FLAG{candidate}';
  paintSolver({...policy,phase:'completed',status:'completed',terminal:true,flag:'FLAG{candidate}',writeup_markdown:null,error:null},[],
    'workspace-one','challenge-one',7);
  assert.equal(currentChallenge.status,'flag_found');
  assert.ok(nodes['challenge-status-controls'].innerHTML.includes('data-action="complete"'));
  assert.ok(!nodes['challenge-status-controls'].innerHTML.includes('data-action="reopen"'));

  const toolsHtml=solverErrorMarkup({code:'provider_tools_unavailable',category:'provider',retryable:false,
    message:'선택한 모델 응답에서 로컬 풀이 도구를 사용할 수 없다고 보고했습니다.'});
  assert.ok(toolsHtml.includes('로컬 풀이 도구 사용 불가'));
  assert.ok(toolsHtml.includes('shell·terminal·command를 지원'));

  const authHtml=solverErrorMarkup({code:'auth_required',category:'auth',retryable:false,
    message:'선택한 공급자 계정에 다시 로그인해야 합니다.'});
  assert.ok(authHtml.includes('계정 다시 로그인 필요'));
  assert.ok(authHtml.includes('href="#accounts"'));
  assert.ok(authHtml.includes('data-action="open-solver-accounts"'));
  assert.ok(authHtml.includes('계정 다시 로그인'));

  const accessHtml=solverErrorMarkup({code:'access_denied',category:'authorization',retryable:false,
    message:'선택한 공급자 또는 모델에 이 실행 방식의 사용 권한이 없습니다.'});
  assert.ok(accessHtml.includes('모델 사용 권한 없음'));
  assert.ok(accessHtml.includes('계정·모델 설정'));

  const daybreakHtml=solverErrorMarkup({code:'daybreak_route_rejected',category:'authorization',retryable:false,
    message:'Daybreak 요청을 현재 Codex 실행 경로에서 완료하지 못했습니다.',
    requirements:['현재 서버 실행 경로의 승인 상태 확인']});
  assert.ok(daybreakHtml.includes('Daybreak 실행 경로 확인 필요'));
  assert.ok(daybreakHtml.includes('계정·모델 확인'));
  assert.ok(daybreakHtml.includes('Daybreak 권한과 서버 실행 경로'));
  assert.ok(daybreakHtml.includes('https://openai.com/daybreak/'));
  assert.ok(daybreakHtml.includes('target="_blank" rel="noopener noreferrer"'));
  assert.ok(daybreakHtml.includes('현재 서버 실행 경로의 승인 상태 확인'));

  const attestationHtml=solverErrorMarkup({code:'codex_attestation_unavailable',category:'authorization',retryable:false,
    message:'현재 서버 실행 방식에서 요청된 Codex 클라이언트 attestation을 제공할 수 없습니다.'});
  assert.ok(attestationHtml.includes('Codex 실행 방식 확인 필요'));
  assert.ok(attestationHtml.includes('모델 변경'));

  // A remote handoff is terminal, keeps the problem resumable, and directs
  // the user to the tri-state challenge editor before a fresh job is queued.
  currentChallenge.flag='';currentChallenge.status='running';currentChallenge.remote_mode='unknown';
  const needsInput={...policy,status:'needs_input',flag:null,error:{code:'remote_input_required',category:'input',message:'Need host and port',retryable:false}};
  paintSolver(normalizeSolverPayload(needsInput).job,[],'workspace-one','challenge-one',7);
  assert.equal(currentChallenge.status,'stopped');
  assert.ok(nodes['solver-panel'].innerHTML.includes('solver-phase-needs_input'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('data-action="edit-challenge"'));

  const quotaHtml=solverErrorMarkup({code:'usage_limit_exceeded',category:'quota',retryable:true,
    message:'선택한 계정의 사용량 한도에 도달했습니다.',additionalDetails:'raw-private-value',quota:{
      limit_id:'codex',limit_name:'Codex Standard',reached_type:'workspace_member_usage_limit_reached',
      windows:[{kind:'primary',window_minutes:300,used_percent:100,resets_at:1788941100},
        {kind:'secondary',window_minutes:10080,used_percent:32,resets_at:1789369200}]}});
  assert.ok(quotaHtml.includes('계정 사용량 한도'));
  assert.ok(quotaHtml.includes('워크스페이스 사용자 사용 한도'));
  assert.ok(quotaHtml.includes('제한 항목 · Codex Standard'));
  assert.ok(quotaHtml.includes('5시간'));
  assert.ok(quotaHtml.includes('7일'));
  assert.ok(quotaHtml.includes('0% 남음'));
  assert.ok(quotaHtml.includes('68% 남음'));
  assert.ok(!quotaHtml.includes('% 사용'));
  assert.ok(quotaHtml.includes('KST'));
  assert.ok(!quotaHtml.includes('raw-private-value'));

  const zeroAndMissingHtml=solverErrorMarkup({code:'quota_exceeded',category:'quota',retryable:true,
    message:'quota context',quota:{limit_id:'codex',windows:[
      {kind:'primary',window_minutes:300,used_percent:0,resets_at:1788941100},
      {kind:'secondary',window_minutes:10080,resets_at:1789369200}]}});
  assert.ok(zeroAndMissingHtml.includes('100% 남음'));
  assert.ok(zeroAndMissingHtml.includes('남은 사용량 미제공'));
  const nullHtml=solverQuotaMarkup({limit_id:'codex',windows:[
    {kind:'primary',window_minutes:300,used_percent:null,resets_at:1788941100}]});
  assert.ok(nullHtml.includes('남은 사용량 미제공'));

  fetch=async()=>({ok:false,status:429,json:async()=>({detail:'fixed quota failure',code:'usage_limit_exceeded',category:'quota',stage:'solve',retryable:true,
    quota:{limit_id:'codex',reached_type:'workspace_member_usage_limit_reached',windows:[{kind:'primary',window_minutes:300,used_percent:100,resets_at:1788941100}]}})});
  let immediateError;try{await api('/api/workspaces/workspace-one/challenges/challenge-one/solver',{method:'POST',body:{}});}catch(error){immediateError=error;}
  assert.equal(immediateError.code,'usage_limit_exceeded');
  assert.equal(immediateError.quota.windows[0].window_minutes,300);
  const immediateHtml=solverErrorMarkup(immediateError);
  assert.ok(immediateHtml.includes('워크스페이스 사용자 사용 한도'));
  assert.ok(immediateHtml.includes('5시간'));
  assert.ok(immediateHtml.includes('0% 남음'));

  const hostileMessage='다시 로그인 <img src=x onerror=alert(1)>';
  solverAccounts=[{id:'a'.repeat(32),provider:'codex',label:'Default',selected:true,snapshot:{status:'authenticated'}}];
  solverAccountId='a'.repeat(32);solverModels=[{id:'gpt-5.6-sol',model:'gpt-5.6-sol',supportedReasoningEfforts:[{reasoningEffort:'xhigh'}],serviceTiers:[]}];
  solverModel='gpt-5.6-sol';solverReasoning='xhigh';solverServiceTier=null;solverOptionsState='ready';
  fetch=async()=>({ok:false,status:409,json:async()=>({detail:{message:hostileMessage,
    code:'auth_required',category:'auth',stage:'solve',retryable:false,requirements:['다시 로그인','<svg/onload=alert(2)>']}})});
  let nestedError;try{await startSolver();}catch(error){nestedError=error;}
  assert.equal(nestedError.message,hostileMessage);
  assert.equal(nestedError.code,'auth_required');
  assert.equal(nestedError.retryable,false);
  assert.equal(nestedError.requirements[0],'다시 로그인');
  const nestedHtml=nodes['solver-panel'].innerHTML;
  assert.ok(nestedHtml.includes('계정 다시 로그인 필요'));
  assert.ok(nestedHtml.includes('href="#accounts"'));
  assert.ok(nestedHtml.includes('data-action="open-solver-accounts"'));
  assert.ok(nestedHtml.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(nestedHtml.includes('&lt;svg/onload=alert(2)&gt;'));
  assert.ok(!nestedHtml.includes('<img src=x'));
  assert.ok(!nestedHtml.includes('<svg/onload'));
  solverRendering=7;

  // A rejected historical candidate stays visible as context but cannot
  // repopulate the challenge's current Flag or solved state.
  currentChallenge.flag='';currentChallenge.status='pending';nodes['challenge-flag-box'].textContent='미등록';
  solverSyncedWriteup='';const fetchesBeforeRejected=fetchCalls;
  const rejected={...policy,status:'completed',flag_rejected:true,retry_checkpoint:{revision:2,rejected_count:2},writeup_markdown:'# Preserved audit copy',error:null};
  paintSolver(normalizeSolverPayload(rejected).job,[],'workspace-one','challenge-one',7);
  await new Promise(setImmediate);assert.equal(fetchCalls,fetchesBeforeRejected);
  assert.equal(currentChallenge.flag,'');assert.equal(currentChallenge.status,'pending');
  assert.equal(nodes['challenge-flag-box'].textContent,'미등록');
  assert.ok(!nodes['solver-panel'].innerHTML.includes('Preserved audit copy'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('제외한 Flag'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('오답 2개'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('오답을 제외하고 다시 풀기'));

  // A response from a challenge that was left while GET /solver was pending cannot repaint the new page.
  let resolveLatest;fetch=()=>new Promise(resolve=>{resolveLatest=resolve;});
  const pending=loadSolver('workspace-one','challenge-one');
  const loading=nodes['solver-panel'].innerHTML;
  currentChallenge={id:'challenge-two',workspace_id:'workspace-one',name:'Other',notes:''};
  ++solverRendering;
  resolveLatest(reply({id:'late',status:'running'}));await pending;
  assert.equal(nodes['solver-panel'].innerHTML,loading);

  // Clearing the detail/page scope makes an already scheduled callback a no-op.
  currentChallenge={id:'challenge-one',workspace_id:'workspace-one',name:'One',notes:''};solverRendering=20;
  const active={id:'active',workspace_id:'workspace-one',challenge_id:'challenge-one',phase:'running',terminal:false};
  currentSolverJob=active;scheduleSolverPoll(active,'workspace-one','challenge-one',20);
  const callback=timers.at(-1), before=fetchCalls;stopSolverPolling();callback();
  await new Promise(setImmediate);assert.equal(fetchCalls,before);

      // POST binds the selected provider and renders the exact selected configuration.
  currentChallenge={id:'challenge-one',workspace_id:'workspace-one',name:'One',notes:'',flag:'',status:'pending'};
  detail.open=true;solverRendering=30;
  solverAccounts=[{id:'a'.repeat(32),provider:'codex',label:'Default',selected:true,snapshot:{status:'authenticated'}}];
  solverAccountId='a'.repeat(32);solverModels=[{id:'gpt-5.6-sol',model:'gpt-5.6-sol',supportedReasoningEfforts:[{reasoningEffort:'xhigh'}],serviceTiers:[]}];
  solverModel='gpt-5.6-sol';solverReasoning='xhigh';solverServiceTier=null;solverOptionsState='ready';
  fetch=async(url,options={})=>{fetchCalls++;assert.ok(url.endsWith('/api/workspaces/workspace-one/challenges/challenge-one/solver'));
        assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{provider:'codex',account_id:'a'.repeat(32),model:'gpt-5.6-sol',reasoning_effort:'xhigh',service_tier:null});
    return reply({id:'done',workspace_id:'workspace-one',challenge_id:'challenge-one',status:'completed',released_at:1,network_policy:'general_internet',supported_challenge_mode:'static_attachments_and_open_internet',
      configuration:{model:'gpt-5.6-sol',reasoning_effort:'xhigh',service_tier:null}});};
  await startSolver();
  assert.ok(nodes['solver-panel'].innerHTML.includes('gpt-5.6-sol'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('xhigh'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('완료'));

  // The guided return route is exact, tab-local, user-bound, and one-shot.
  const returnWorkspace='a'.repeat(32),returnChallenge='b'.repeat(32);
  sessionUser={id:'owner'};currentWorkspace={id:returnWorkspace,name:'Return'};
  currentChallenge={id:returnChallenge,workspace_id:returnWorkspace,name:'Return',notes:'',notes_token:'n'};
  location.hash='#w/'+returnWorkspace+'/c/'+returnChallenge;
  openSolverAccounts();
  assert.equal(location.hash,'#accounts');
  assert.equal(accountsReturnRoute(),'w/'+returnWorkspace+'/c/'+returnChallenge);
  returnFromAccounts();
  assert.equal(location.hash,'#w/'+returnWorkspace+'/c/'+returnChallenge);
  assert.equal(accountsReturnTarget,null);
  openSolverAccounts();sessionUser={id:'different-user'};
  assert.equal(accountsReturnRoute(),'');assert.equal(accountsReturnTarget,null);
  sessionUser={id:'owner'};
  openSolverAccounts();assert.ok(accountsReturnTarget);showLogin();assert.equal(accountsReturnTarget,null);
  currentWorkspace={id:returnWorkspace};
  currentChallenge={id:returnChallenge,workspace_id:'c'.repeat(32)};
  openSolverAccounts();assert.equal(accountsReturnTarget,null);
  currentWorkspace={id:'../invalid'};currentChallenge={id:returnChallenge,workspace_id:'../invalid'};
  openSolverAccounts();assert.equal(accountsReturnTarget,null);
})()`,context);console.log('solver UI regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_telegram_clipboard_fallback_has_no_inline_style_and_reports_failure():
    source = (ROOT / "ctf_agent" / "web" / "telegram.js").read_text(encoding="utf-8")
    assert ".style." not in source
    source = source.replace("export async function renderTelegram", "async function renderTelegram")
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),created=[];
function node(){return {className:'',value:'',selectionStart:0,selectionEnd:0,removed:false,setAttribute(){},
  focus(){document.activeElement=this;},select(){},setSelectionRange(a,b){this.selectionStart=a;this.selectionEnd=b;},remove(){this.removed=true;}};}
const focused=node();focused.selectionStart=3;focused.selectionEnd=6;
const document={activeElement:focused,body:{append(item){created.push(item);}},createElement(){return node();},execCommand(command){assert.equal(command,'copy');return true;}};
const context={document,window:{isSecureContext:true},navigator:{clipboard:{writeText:async()=>{throw new Error('denied');}}},console,assert,created,focused};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  await copyText('https://t.me/Bot?start=one-time');
  assert.equal(created[0].className,'clipboard-proxy');assert.equal(created[0].removed,true);
  assert.equal(document.activeElement,focused);assert.equal(focused.selectionStart,3);assert.equal(focused.selectionEnd,6);
  document.execCommand=()=>false;
  await assert.rejects(copyText('cannot-copy'),/자동으로 복사하지 못했습니다/);
})()`,context);console.log('telegram clipboard regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_telegram_identity_failure_is_distinct_from_missing_configuration():
    source = (ROOT / "ctf_agent" / "web" / "telegram.js").read_text(encoding="utf-8")
    assert "state.configuration_error" in source
    assert "Telegram 봇 신원을 확인하지 못했습니다" in source


def test_authenticated_render_opens_workspace_challenge_deep_link():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),workspace='a'.repeat(32),challenge='b'.repeat(32),calls=[],events={};
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',value:'',dataset:{},disabled:false,
  append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},querySelector(){return null;},
  querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}},extra);}
const nodes={app:element(),modal:element(),detail:element(),content:element(),'challenge-area':element(),'ctfd-job-area':element(),
  'upload-progress':element(),toasts:element()};
const document={activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)]??null,getElementById:id=>nodes[id]??null,
  createElement:()=>element(),addEventListener(k,fn){events[k]=fn;},execCommand:()=>true};
const counts={pending:1,running:0,stopped:0,failed:0,flag_found:0,solved:0};
const row={id:challenge,workspace_id:workspace,name:'Deep Link Challenge',description:'body',category:'Web',status:'pending',flag:'',
  completion_source:null,ctfd_id:null,updated_at:'2026-09-09T00:00:00Z',attachments:[],notes:'',notes_token:'n',edit_token:'e'};
const fetch=async(url,options={})=>{calls.push(url);
  if(url==='/api/auth/login'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{username:'admin',password:'synthetic-local-password'});
    return {ok:true,status:200,json:async()=>({csrf_token:'csrf',user:{id:'owner',username:'admin',role:'admin'}})};}
  if(url==='/api/workspaces')return {ok:true,status:200,json:async()=>({workspaces:[{id:workspace,name:'Deep Workspace',description:'',flag_format:'',challenge_count:1,solved_count:0,running_count:0}]})};
  if(url===`/api/workspaces/${workspace}`)return {ok:true,status:200,json:async()=>({id:workspace,name:'Deep Workspace',description:'',flag_format:''})};
  if(url.startsWith(`/api/workspaces/${workspace}/challenges?`))return {ok:true,status:200,json:async()=>({challenges:[row],counts,categories:['Web']})};
  if(url===`/api/workspaces/${workspace}/challenges/${challenge}`)return {ok:true,status:200,json:async()=>row};
  if(url.endsWith('/uploads'))return {ok:true,status:200,json:async()=>({uploads:[]})};
  if(url.endsWith('/ctfd/jobs'))return {ok:true,status:200,json:async()=>({jobs:[]})};
  if(url.endsWith('/solver'))return {ok:false,status:404,json:async()=>({detail:'not found'})};
  throw new Error('unexpected '+url);};
const location={hash:`#w/${workspace}/c/${challenge}`};
class TestFormData {constructor(form){this.items=form.fields.map(field=>[field.name,field.value]);}[Symbol.iterator](){return this.items[Symbol.iterator]();}getAll(key){return this.items.filter(([name])=>name===key).map(([,value])=>value);}}
const loginButton=element({type:'submit'}),loginForm=element({id:'login-form',fields:[{name:'username',value:'admin'},{name:'password',value:'synthetic-local-password'}],
  reset(){this.wasReset=true;},querySelector(){return loginButton;},querySelectorAll(){return [...this.fields,loginButton];}});
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{clipboard:{writeText:async()=>{}}},location,
  history:{replaceState(){}},console,Blob,File:class{},FormData:TestFormData,ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch,renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,calls,events,loginForm,workspace,challenge,setImmediate};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{events.submit({target:loginForm,preventDefault(){}});
  for(let i=0;i<12&&!currentChallenge;i++)await new Promise(setImmediate);
  assert.equal(loginForm.wasReset,true);assert.equal(location.hash,'#w/'+workspace+'/c/'+challenge);assert.equal(currentWorkspace.id,workspace);
  assert.equal(currentChallenge.id,challenge);assert.equal(detail.open,true);assert.ok(detail.innerHTML.includes('Deep Link Challenge'));
  assert.ok(calls.includes('/api/workspaces/'+workspace+'/challenges/'+challenge));})()`,context);
  console.log('authenticated deep link regression passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_large_upload_ui_keeps_siblings_and_shows_speed_eta_and_gigabytes():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function node(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',dataset:{},append(){},remove(){},focus(){},select(){},
  setSelectionRange(){},setAttribute(){},removeAttribute(){},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},close(){}},extra);}
const progress=node(),detail=node(),modal=node(),app=node();
const document={body:node(),activeElement:null,querySelector:s=>s==='#upload-progress'?progress:s==='#detail'?detail:s==='#modal'?modal:s==='#app'?app:null,
  getElementById:()=>null,createElement:()=>node(),addEventListener(){},execCommand:()=>true};
const context={document,window:{addEventListener(){},isSecureContext:true},navigator:{},location:{hash:''},history:{replaceState(){}},console,
  Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,
  confirm:()=>true,fetch:async()=>{throw new Error('no fetch');},renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,progress};
vm.createContext(context);vm.runInContext(source,context);
vm.runInContext(`currentWorkspace={id:'w'};currentChallenge={id:'c'};
  paintUploads([{id:'one',name:'one.bin',size:5*1024**3,offset:1024**3},{id:'two',name:'two.bin',size:2*1024**3,offset:0}],'w','c',true);
  assert.ok(progress.innerHTML.includes('one.bin'));assert.ok(progress.innerHTML.includes('two.bin'));assert.ok(progress.innerHTML.includes('5.00 GB'));
  activeUploads.set('one',{offset:2*1024**3,running:true,message:'전송 중',bytesPerSecond:100*1024**2});
  paintUploads([{id:'one',name:'one.bin',size:5*1024**3,offset:2*1024**3}],'w','c');
  assert.ok(progress.innerHTML.includes('two.bin'),'updating one upload must retain its sibling');
  assert.ok(progress.innerHTML.includes('100.0 MB/s'));assert.ok(progress.innerHTML.includes('남은 시간'));
  assert.equal(size(2*1024**4),'2.00 TB');`,context);
console.log('large upload UI regressions passed');
'''
    _node(source, harness)


def test_account_ui_hides_empty_notice_and_exposes_real_model_controls():
    source = (ROOT / "ctf_agent" / "web" / "accounts.js").read_text(encoding="utf-8")
    source = source.replace("export async function renderAccounts", "async function renderAccounts")
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),all=[];
class Node {
  constructor(tag='div'){this.tag=tag;this.children=[];this.listeners={};this.attributes={};this.textContent='';this.className='';this.hidden=false;this.value='';this.disabled=false;this.isConnected=true;all.push(this);}
  append(...items){for(const item of items){if(item==null)continue;this.children.push(item);item.parent=this;if(item.selected)this.value=item.value;}}
  prepend(item){this.children.unshift(item);item.parent=this;}
  replaceChildren(...items){this.children=[];this.append(...items);}
  contains(item){return this===item||this.children.some(child=>child.contains?.(item));}
  addEventListener(k,fn){this.listeners[k]=fn;}
  setAttribute(k,v){this.attributes[k]=v;}
  focus(){document.activeElement=this;}
  querySelector(selector){if(selector==='a')return this.walk().find(n=>n.tag==='a')||null;return null;}
  walk(){return [this,...this.children.flatMap(child=>child.walk?.()||[])];}
}
const document={createElement:tag=>new Node(tag),body:new Node('body'),activeElement:null};
const container=new Node('main'),metrics={automaticRefreshes:0};
const account={id:'one',label:'Admin Codex',provider:'codex',selected:true,model:'gpt-5.6-sol',reasoning_effort:'high',service_tier:'fast',
  checked_at:1,stale:false,login:{status:'idle'},snapshot:{status:'authenticated',identity:{email:'user@example.test',planType:'Pro'},
  error:{code:'policy_security',category:'policy_security',provider_code:'TAC',stage:'solve',retryable:false},
  quota:{status:'available',limited:true,reset_credits:{available_count:2},buckets:[
    {id:'gpt-5.3-spark',name:'GPT-5.3 Spark',limited:false,windows:[{label:'1일',used_percent:10,resets_at:1789369200}]},
    {id:'codex',name:'Codex',limited:true,
    reached_type:'workspace_member_usage_limit_reached',spend_control_reached:false,
    windows:[{label:'5시간',used_percent:100,resets_at:1788941100},{label:'7일',used_percent:64,resets_at:1789369200}],
    individual_limit:{remaining_percent:0,resets_at:1788941100},credits:{has_credits:false,unlimited:false}}]}}};
const api=async url=>{
  if(url==='/api/accounts')return {accounts:[account]};
  if(url==='/api/accounts/one/refresh'){metrics.automaticRefreshes++;return {ok:true};}
  if(url==='/api/providers/codex/runtime')return {version:'0.153.4',operation:{status:'idle'},can_manage:false,update_supported:true};
  if(url==='/api/providers/claude/runtime')return {version:'2.1.263',can_manage:false};
  if(url==='/api/accounts/one/models')return {status:'available',models:[{id:'gpt-5.6-sol',model:'gpt-5.6-sol',displayName:'GPT-5.6 Sol',
    defaultReasoningEffort:'high',supportedReasoningEfforts:[{reasoningEffort:'low'},{reasoningEffort:'high'}],
    serviceTiers:[{id:'fast',name:'1.5배 Fast',description:'응답 1.5배 · 크레딧 2.5배'}]}]};
  throw new Error('unexpected '+url);
};
const context={document,window:{setTimeout(){},confirm:()=>true},navigator:{},FormData:class{},console,assert,container,api,all,metrics,setImmediate};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{let returns=0;await renderAccounts(container,api,{onReturnToChallenge:()=>{returns++;}});
  const nodes=container.walk(),feedback=nodes.find(n=>n.className==='notice');
  const heading=nodes.find(n=>n.tag==='h1'&&n.textContent==='에이전트');
  assert.ok(nodes.some(n=>n.className==='eyebrow'&&n.textContent==='AGENTS'));
  assert.equal(metrics.automaticRefreshes,1);
  assert.equal(heading.attributes.tabindex,'-1');assert.equal(document.activeElement,heading);
  const returnButton=nodes.find(n=>n.tag==='button'&&n.textContent==='문제로 돌아가기');
  assert.ok(returnButton);returnButton.listeners.click();assert.equal(returns,1);
  assert.equal(feedback.hidden,true);assert.equal(feedback.textContent,'');
  assert.ok(nodes.some(n=>n.textContent.includes('추론: high')&&n.textContent.includes('Fast 1.5')));
  assert.ok(nodes.some(n=>n.textContent.includes('TAC')&&n.textContent.includes('보안 작업 정책 제한')));
  assert.ok(nodes.some(n=>n.className.includes('quota-limited')));
  assert.ok(nodes.some(n=>n.textContent.includes('다른 등록 계정을 선택')));
  assert.ok(nodes.some(n=>n.textContent.includes('워크스페이스 사용자 사용 한도')));
  assert.ok(nodes.some(n=>n.textContent.includes('5시간: 0% 남음')));
  assert.ok(nodes.some(n=>n.textContent.includes('7일: 36% 남음')));
  assert.ok(nodes.some(n=>n.textContent.includes('초기화 크레딧: 2개')));
  assert.ok(nodes.some(n=>n.textContent.includes('개인 사용 한도: 0% 남음')));
  const accountCard=nodes.find(n=>n.tag==='h3'&&n.textContent.includes('Admin Codex')).parent;
  const quotaBuckets=accountCard.children.filter(n=>n.className==='quota-bucket');
  assert.equal(quotaBuckets[0].children[0].textContent,'Codex');assert.equal(quotaBuckets[1].children[0].textContent,'GPT-5.3 Spark');
  const resetCredits=accountCard.children.find(n=>n.className==='quota-reset-credits');
  assert.ok(accountCard.children.indexOf(resetCredits)>accountCard.children.indexOf(quotaBuckets[1]));
  const modelSummary=accountCard.children.find(n=>n.className==='account-model-summary');
  assert.ok(accountCard.children.indexOf(modelSummary)>accountCard.children.indexOf(quotaBuckets[1]));
  const accountActions=accountCard.children.find(n=>n.className==='actions');
  assert.ok(accountCard.children.indexOf(modelSummary)<accountCard.children.indexOf(accountActions));
  assert.equal(modelSummary.textContent,'모델: gpt-5.6-sol · 추론: high · 속도: Fast 1.5×');
  assert.equal(modelSummary.attributes['aria-label'],'기본 풀이 설정');
  const identityLine=accountCard.children.find(n=>n.tag==='p'&&n.textContent.includes('user@example.test'));
  assert.ok(!identityLine.textContent.includes('모델:'));
  assert.ok(nodes.some(n=>n.tag==='button'&&n.textContent==='다시 로그인'));
  assert.ok(!nodes.some(n=>n.tag==='button'&&n.textContent==='로그인'));
  assert.ok(nodes.some(n=>n.tag==='button'&&n.textContent==='사용량 새로고침'));
  assert.ok(nodes.some(n=>n.tag==='button'&&n.textContent==='계정 삭제'));
  assert.ok(!nodes.some(n=>n.tag==='button'&&['↻','⌫'].includes(n.textContent)));
  const modelButton=nodes.find(n=>n.tag==='button'&&n.textContent==='모델·속도 설정');modelButton.listeners.click();
  await new Promise(setImmediate);await new Promise(setImmediate);
  const refreshed=container.walk();
  assert.ok(refreshed.some(n=>n.className==='model-fields'));
  assert.ok(refreshed.some(n=>n.attributes['aria-label']==='추론 수준'));
  assert.ok(refreshed.some(n=>n.attributes['aria-label']==='응답 속도'));
  assert.ok(refreshed.some(n=>n.tag==='option'&&n.textContent==='1.5배 Fast'&&n.selected));
  const uploadButton=refreshed.find(n=>n.tag==='button'&&n.textContent==='auth.json 업로드');uploadButton.listeners.click();
  await new Promise(setImmediate);assert.ok(container.walk().some(n=>n.tag==='label'&&n.textContent==='auth.json 파일'));
})()`,context);console.log('account UI regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_cyber_challenge_cards_lazy_writeup_safe_markdown_and_sidebar_state():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    styles = (ROOT / "ctf_agent" / "web" / "style.css").read_text(encoding="utf-8")
    assert ".challenge-card-grid" in styles
    assert ".shell.sidebar-collapsed" in styles
    assert "@media(max-width:800px)" in styles
    assert "@media(max-width:580px)" in styles
    assert ".markdown-preview" in styles
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),stored={'ctf-sidebar-collapsed':'true'},fetches=[],copied=[];
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',dataset:{},disabled:false,
  attributes:{},append(){},remove(){},focus(){},select(){},setSelectionRange(){},showModal(){this.open=true;},close(){this.open=false;},
  setAttribute(k,v){this.attributes[k]=String(v);},removeAttribute(k){delete this.attributes[k];},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){}},extra);}
const nodes={app:element(),modal:element(),detail:element(),toasts:element(),content:element(),shell:element({classList:{values:new Set(),toggle(name,on){on?this.values.add(name):this.values.delete(name);}}})};
const document={activeElement:null,body:element(),querySelector(selector){if(selector==='#app')return nodes.app;if(selector==='#modal')return nodes.modal;if(selector==='#detail')return nodes.detail;if(selector==='#toasts')return nodes.toasts;if(selector==='#content')return nodes.content;if(selector==='.shell')return nodes.shell;return null;},
  getElementById(id){return nodes[id]||null;},createElement(){return element();},addEventListener(){},execCommand(){return true;}};
const localStorage={getItem:key=>stored[key]??null,setItem:(key,value)=>{stored[key]=value;}};
const context={document,localStorage,window:{isSecureContext:true,addEventListener(){}},navigator:{clipboard:{writeText:async value=>copied.push(value)}},
  location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  crypto:require('node:crypto').webcrypto,confirm:()=>true,renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,stored,fetches,copied,nodes,element};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const tick=String.fromCharCode(96);
  const hostile=['# 제목','<img src=x onerror=alert(1)>','**굵게**',tick+'inline'+tick,tick.repeat(3)+'js','<script>alert(2)</script>',tick.repeat(3)].join('\\n');
  const preview=safeMarkdown(hostile);
  assert.ok(preview.includes('<h1>제목</h1>'));assert.ok(preview.includes('<strong>굵게</strong>'));assert.ok(preview.includes('<code>inline</code>'));
  assert.ok(preview.includes('&lt;img src=x onerror=alert(1)&gt;'));assert.ok(preview.includes('&lt;script&gt;alert(2)&lt;/script&gt;'));
  assert.ok(!preview.includes('<img'));assert.ok(!preview.includes('<script'));

  const workspace='b'.repeat(32),id='c'.repeat(32),base={id,workspace_id:workspace,name:'<img onerror=1>',category:'web',description:'hostile <svg/onload=1>',updated_at:'2026-09-10T00:00:00Z',ctfd_id:3,flag:'FLAG{card}'};
  const agent=challengeCardMarkup({...base,status:'solved',completion_source:'agent',has_writeup:true,latest_solver:{status:'completed',elapsed_seconds:125,elapsed_includes_queue:false,account_label:'Primary',configuration:{provider:'codex',model:'gpt-5.6-sol',reasoning_effort:'high',service_tier:'fast'}}},workspace);
  assert.ok(agent.includes('challenge-card-grid')===false);assert.ok(agent.includes('write-up 복사'));assert.ok(agent.includes('Flag 복사'));assert.ok(agent.includes('결과 보기'));
  assert.ok(agent.includes('Primary'));assert.ok(agent.includes('gpt-5.6-sol'));assert.ok(agent.includes('Fast 1.5×'));
  assert.ok(agent.includes('완료<small title="풀이 시간">· 2분 5초</small>'));
  assert.ok(agent.includes('data-action="open-solver-session"'));assert.ok(agent.includes('이전 풀이 터미널'));assert.ok(agent.includes('&gt;_'));
  assert.ok(agent.includes('&lt;img onerror=1&gt;'));assert.ok(!agent.includes('<img onerror=1>'));
  const live=challengeCardMarkup({...base,flag:null,status:'running',completion_source:null,has_writeup:false,latest_solver:{status:'running',configuration:{provider:'codex',model:'gpt-5.6-sol',reasoning_effort:'high'}}},workspace);
  assert.ok(live.includes('session-action live'));assert.ok(live.includes('data-live="true"'));assert.ok(live.includes('실시간 풀이 터미널'));assert.ok(live.includes('LIVE'));
  const manual=challengeCardMarkup({...base,flag:null,status:'solved',completion_source:'manual',has_writeup:true},workspace);
  assert.ok(!manual.includes('copy-list-writeup'));assert.ok(manual.includes('수동 완료'));assert.ok(!manual.includes('Agent write-up 없음'));
  const pending=challengeCardMarkup({...base,flag:null,status:'pending',completion_source:null,has_writeup:false},workspace);
  assert.ok(pending.includes('complete-list-challenge'));assert.ok(pending.includes('start-list-solver'));assert.ok(pending.includes('▶ 풀이 시작'));assert.ok(pending.includes('풀이 설정'));assert.ok(!pending.includes('AI 풀이 설정'));
  assert.ok(!pending.includes('open-solver-session'));
  for(const status of ['stopped','failed']) assert.ok(challengeCardMarkup({...base,flag:null,status,completion_source:null,has_writeup:false},workspace).includes('start-list-solver'));
  const needsInput=challengeCardMarkup({...base,edit_token:'edit-token',flag:null,status:'stopped',completion_source:null,has_writeup:false,latest_solver:{status:'needs_input',configuration:{provider:'codex',model:'gpt-5.6-sol',reasoning_effort:'high'}}},workspace);
  assert.ok(needsInput.includes('class="challenge-inline-input"'));assert.ok(needsInput.includes('추가 입력 필요'));
  assert.ok(needsInput.includes('name="remote"'));assert.ok(needsInput.includes('원격 대상 없음'));
  assert.ok(!needsInput.includes('data-action="start-list-solver"'));
  for(const status of ['running','solved']) assert.ok(!challengeCardMarkup({...base,status,completion_source:status==='solved'?'agent':null,has_writeup:false},workspace).includes('start-list-solver'));
  const writing=challengeCardMarkup({...base,status:'flag_found',completion_source:null,has_writeup:false},workspace);
  assert.ok(!writing.includes('complete-list-challenge'));assert.ok(!writing.includes('start-list-solver'));assert.ok(writing.includes('Flag 확인'));

  currentWorkspace={id:workspace};
  const opened=[];openChallenge=async(...args)=>opened.push(args);
  await openSolverSession(element({dataset:{id}}));
  assert.deepEqual(opened,[[id,true]],'the card session control must open and focus the stored solver session');
  await openSolverSession(element({dataset:{id,live:'true'}}));
  assert.deepEqual(opened.at(-1),[id,true,true],'LIVE must open the solver session in expanded mode');
  fetch=async(url,options={})=>{fetches.push([url,options.method||'GET']);return {ok:true,status:200,json:async()=>({markdown:'# fetched only on click'})};};
  const copyButton=element({dataset:{workspaceId:workspace,id}});
  await copyChallengeWriteup(copyButton);
  assert.equal(fetches.length,1);assert.equal(fetches[0][0],'/api/workspaces/'+workspace+'/challenges/'+id+'/writeup');assert.equal(fetches[0][1],'GET');
  assert.equal(copied.length,1);assert.equal(copied[0],'# fetched only on click');assert.equal(copyButton.disabled,false);assert.equal(copyButton.attributes['aria-busy'],undefined);

  sessionUser={id:'owner',username:'owner',role:'user'};workspaces=[];shell('workspaces');
  assert.ok(nodes.app.innerHTML.includes('shell sidebar-collapsed'));assert.ok(nodes.app.innerHTML.includes('aria-expanded="false"'));
  assert.ok(nodes.app.innerHTML.includes('<span class="nav-text">에이전트</span>'));assert.ok(!nodes.app.innerHTML.includes('>모델 계정<'));
  const icon=element(),toggle=element({querySelector:()=>icon});toggleSidebar(toggle);
  assert.equal(stored['ctf-sidebar-collapsed'],'false');assert.equal(toggle.attributes['aria-expanded'],'true');assert.equal(toggle.attributes['aria-label'],'사이드바 접기');
})()`,context);console.log('cyber card, lazy write-up, safe markdown and sidebar regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_challenge_card_starts_solver_with_saved_default_without_opening_detail():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    styles = (ROOT / "ctf_agent" / "web" / "style.css").read_text(encoding="utf-8")
    assert ".challenge-card-actions .solve-action" in styles
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',dataset:{},disabled:false,
  attributes:{},append(){},remove(){},focus(){},select(){},setSelectionRange(){},showModal(){this.open=true;},close(){this.open=false;},
  setAttribute(k,v){this.attributes[k]=String(v);},removeAttribute(k){delete this.attributes[k];},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){}},extra);}
const nodes={app:element(),modal:element(),detail:element(),toasts:element()};
const document={visibilityState:'visible',activeElement:null,body:element(),querySelector(selector){return nodes[selector.slice(1)]||null;},
  getElementById(id){return nodes[id]||null;},createElement(){return element();},addEventListener(){},execCommand(){return true;}};
const context={document,localStorage:{getItem:()=>null,setItem(){}},window:{isSecureContext:true,addEventListener(){}},navigator:{},
  location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  crypto:require('node:crypto').webcrypto,confirm:()=>true,renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,element};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const workspace='b'.repeat(32),challenge='c'.repeat(32),calls=[],messages=[];
  let resolveStart,refreshes=0;
  currentWorkspace={id:workspace};solverProvider='codex';
  api=(url,options={})=>{calls.push([url,options]);return new Promise(resolve=>{resolveStart=resolve;});};
  refreshChallenges=async()=>{refreshes++;};toast=message=>messages.push(message);
  const button=element({textContent:'▶ 풀이 시작',dataset:{workspaceId:workspace,id:challenge,name:'Token Guard'}});
  const first=startListSolver(button),duplicate=startListSolver(button);
  await duplicate;
  assert.equal(calls.length,1,'a pending start must not enqueue twice');
  assert.equal(button.disabled,true);assert.equal(button.attributes['aria-busy'],'true');assert.equal(button.textContent,'시작 중');
  assert.equal(calls[0][0],'/api/workspaces/'+workspace+'/challenges/'+challenge+'/solver');
  assert.equal(calls[0][1].method,'POST');assert.deepEqual(calls[0][1].body,{provider:'codex'});
  resolveStart({id:'job',status:'queued',capacity:{warning:true,warning_message:'리소스 사용량 확인'}});
  await first;
  assert.equal(refreshes,1);assert.deepEqual(messages,['리소스 사용량 확인','“Token Guard” 풀이를 시작했습니다.']);
  assert.equal(button.disabled,false);assert.equal(button.attributes['aria-busy'],undefined);assert.equal(button.textContent,'▶ 풀이 시작');
  assert.equal(detail.open,false,'the challenge detail must stay closed');
  messages.length=0;api=async()=>({id:'job-two',status:'queued'});refreshChallenges=async()=>{throw new Error('poll catches up');};
  await startListSolver(button);assert.deepEqual(messages,['“Token Guard” 풀이를 시작했습니다.'],'a refresh failure must not report a successful enqueue as failed');
  await assert.rejects(startListSolver(element({dataset:{workspaceId:'d'.repeat(32),id:challenge}})),/문제 목록을 다시 불러와/);
})()`,context);console.log('challenge card default solver start passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_inline_remote_input_updates_challenge_then_restarts_solver():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',dataset:{},disabled:false,
  attributes:{},append(){},remove(){},focus(){},select(){},setSelectionRange(){},showModal(){this.open=true;},close(){this.open=false;},
  setAttribute(k,v){this.attributes[k]=String(v);},removeAttribute(k){delete this.attributes[k];},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){}},extra);}
const nodes={app:element(),modal:element(),detail:element(),toasts:element()};
const document={visibilityState:'visible',activeElement:null,body:element(),querySelector(selector){return nodes[selector.slice(1)]||null;},
  getElementById(id){return nodes[id]||null;},createElement(){return element();},addEventListener(){},execCommand(){return true;}};
const context={document,localStorage:{getItem:()=>null,setItem(){}},window:{isSecureContext:true,addEventListener(){}},navigator:{},
  location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  crypto:require('node:crypto').webcrypto,confirm:()=>true,renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,element};
vm.createContext(context);vm.runInContext(fs.readFileSync(0,'utf8'),context);
(async()=>{await vm.runInContext(`(async()=>{
  const workspace='b'.repeat(32),challenge='c'.repeat(32),calls=[];
  currentWorkspace={id:workspace};solverProvider='codex';refreshChallenges=async()=>{};toast=()=>{};
  const button=element({textContent:'계속 풀기',dataset:{}});
  const form=element({dataset:{workspaceId:workspace,challengeId:challenge,editToken:'before',name:'Remote Task'},querySelector(selector){return selector==='button[type="submit"]'?button:null;}});
  api=async(url,options={})=>{calls.push([url,options]);return calls.length===1?{edit_token:'after'}:{id:'job',status:'queued'};};
  await continueListSolver(form,{remote_mode:'endpoint',remote:'  nc task.example 31337  '});
  assert.equal(calls.length,2);assert.equal(calls[0][0],'/api/workspaces/'+workspace+'/challenges/'+challenge);
  assert.equal(calls[0][1].method,'PATCH');assert.deepEqual(calls[0][1].headers,{'If-Match':'before'});
  assert.deepEqual(calls[0][1].body,{remote_mode:'endpoint',remote:'nc task.example 31337'});
  assert.equal(calls[1][0],'/api/workspaces/'+workspace+'/challenges/'+challenge+'/solver');
  assert.deepEqual(calls[1][1].body,{provider:'codex'});assert.equal(form.dataset.editToken,'after');
  calls.length=0;
  await continueListSolver(form,{remote_mode:'none',remote:'ignored'});
  assert.deepEqual(calls[0][1].body,{remote_mode:'none',remote:''});
  await assert.rejects(continueListSolver(form,{remote_mode:'endpoint',remote:'  '}),/원격 접속 정보를 입력/);
})()`,context);console.log('inline remote input regression passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_new_challenge_save_stays_on_the_problem_list():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    branch = source.split("form.id === 'new-challenge-form' || form.id === 'edit-challenge-form'", 1)[1]
    branch = branch.split("} else if (form.id === 'search-form')", 1)[0]
    assert "if (edit || currentWorkspace.open_challenge_after_create) await openChallenge(c.id);" in branch
    assert "await refreshChallenges(); await openChallenge(c.id)" not in branch
    assert 'name="open_challenge_after_create"' in source


def test_challenge_clone_button_uses_clone_api_and_workspace_popup_preference():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    assert 'data-action="clone-challenge"' in source
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
function element(extra={}){return Object.assign({open:true,innerHTML:'',dataset:{},append(){},remove(){},addEventListener(){},
  querySelector(){return null;},querySelectorAll(){return[];},setAttribute(){},removeAttribute(){},showModal(){this.open=true;},close(){this.open=false;}},extra);}
const nodes={app:element(),modal:element(),detail:element(),toasts:element()};
const document={visibilityState:'visible',activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)]||null,
  getElementById:id=>nodes[id]||null,createElement:()=>element(),addEventListener(){},execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},localStorage:{getItem:()=>null,setItem(){}},
  location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,
  AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert};
vm.createContext(context);vm.runInContext(fs.readFileSync(0,'utf8'),context);
(async()=>{await vm.runInContext(`(async()=>{
  const workspace='b'.repeat(32),challenge='c'.repeat(32),calls=[],messages=[],opened=[];
  currentWorkspace={id:workspace,open_challenge_after_create:false};
  currentChallenge={id:challenge,workspace_id:workspace,name:'Token Guard'};
  api=async(url,options)=>{calls.push([url,options]);return {id:'d'.repeat(32),name:'Token Guard 복사본'};};
  refreshChallenges=async()=>{};toast=message=>messages.push(message);openChallenge=async id=>opened.push(id);
  await cloneChallenge();
  assert.equal(calls[0][0],'/api/workspaces/'+workspace+'/challenges/'+challenge+'/clone');
  assert.equal(calls[0][1].method,'POST');assert.equal(detail.open,false);assert.equal(opened.length,0);
  assert.deepEqual(messages,['“Token Guard 복사본” 문제를 만들었습니다.']);

  detail.open=true;currentWorkspace.open_challenge_after_create=true;
  currentChallenge={id:challenge,workspace_id:workspace,name:'Token Guard'};
  await cloneChallenge();
  assert.deepEqual(opened,['d'.repeat(32)]);
})()`,context);console.log('challenge clone UI passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_challenge_sort_control_updates_server_query_and_markup():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
function element(){return {innerHTML:'',dataset:{},open:false,append(){},remove(){},addEventListener(){},querySelector(){return null;},querySelectorAll(){return[];},setAttribute(){},removeAttribute(){},close(){},showModal(){}};}
const nodes={app:element(),modal:element(),detail:element()};
const document={visibilityState:'visible',activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)]||null,getElementById:()=>null,createElement:()=>element(),addEventListener(){},execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},localStorage:{getItem:()=>null,setItem(){}},location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert};
vm.createContext(context);vm.runInContext(fs.readFileSync(0,'utf8'),context);
(async()=>{await vm.runInContext(`(async()=>{
  selectedStatus='running';selectedCategory='web';selectedSort='solver_asc';search='wing';
  const params=challengeListParams();
  assert.equal(params.get('status'),'running');assert.equal(params.get('category'),'web');
  assert.equal(params.get('q'),'wing');assert.equal(params.get('sort'),'solver_asc');
  const counts={pending:0,running:0,stopped:0,failed:0,flag_found:0,solved:0};
  const markup=challengeListingMarkup({counts,categories:[],challenges:[]},'workspace');
  for(const label of ['최근 추가순','오래된 추가순','이름 오름차순','이름 내림차순','최근 풀이 시작순','오래된 풀이 시작순']) assert.ok(markup.includes(label));
  assert.ok(markup.includes('value="solver_asc" selected'));
})()`,context);console.log('challenge sorting UI passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_terminal_poll_loads_retry_configuration_after_opening_active_job():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function element(extra={}){return Object.assign({open:true,isConnected:true,innerHTML:'',dataset:{},append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},showModal(){},close(){}},extra);}
const nodes={app:element(),modal:element(),detail:element(),'solver-panel':element(),toasts:element()};
const document={activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)]||null,getElementById:id=>nodes[id]||null,createElement:()=>element(),addEventListener(){},execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch:async()=>{throw new Error('unused');},renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const loads=[];
  solverContext=()=>true;
  paintSolver=(job)=>{currentSolverJob=job;};
  scheduleSolverPoll=()=>{};
  loadSolverConfiguration=async(...args)=>{loads.push(args);solverOptionsState='ready';};
  api=async()=>({id:'job',status:'failed',released_at:1,events:[]});
  currentSolverJob={id:'job',phase:'running'};solverOptionsState='idle';
  await pollSolverJob('job','workspace','challenge',9);
  assert.equal(loads.length,1);
  assert.deepEqual(loads[0],['workspace','challenge',9]);

  solverOptionsState='ready';
  await pollSolverJob('job','workspace','challenge',9);
  assert.equal(loads.length,1,'an already loaded selector must not be fetched again');
})()`,context);console.log('terminal retry configuration regression passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)


def test_reject_flag_refreshes_notes_and_removes_generated_copy_from_unsaved_draft():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function element(extra={}){return Object.assign({open:true,isConnected:true,innerHTML:'',textContent:'',value:'',dataset:{},disabled:false,
  append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},querySelector(){return null;},
  querySelectorAll(){return[];},addEventListener(){},showModal(){},close(){}},extra);}
const editor=element(),nodes={app:element(),modal:element(),detail:element(),'solver-panel':element(),'notes-editor':editor,
  'challenge-flag-box':element(),'copy-flag-button':element(),'challenge-status-controls':element(),toasts:element()};
const document={activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)]||null,getElementById:id=>nodes[id]||null,
  createElement:()=>element(),addEventListener(){},execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},location:{hash:''},history:{replaceState(){}},console,
  Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch:async()=>{throw new Error('unused');},renderAccounts:async()=>{},
  setTimeout:()=>1,clearTimeout(){},assert,editor};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const start=generatedWriteupStart,end=generatedWriteupEnd;
  const saved='# 수동 메모\\n\\n'+start+'\\n# 오답\\n'+end;
  currentWorkspace={id:'workspace'};
  currentChallenge={id:'challenge',workspace_id:'workspace',notes:saved,notes_token:'old',flag:'FLAG{wrong}',status:'solved',completion_source:'agent',has_writeup:true,writeup_markdown:'# 오답'};
  currentSolverJob={id:'job',phase:'completed',released_at:1,flag:'FLAG{wrong}',flag_rejected:false};
  solverRendering=3;editor.value='# 수동 메모 수정\\n\\n'+start+'\\n# 오답\\n'+end+'\\n\\n# 추가 분석';
  solverContext=()=>true;paintSolver=()=>{};refreshChallenges=async()=>{};toast=()=>{};
  const calls=[];api=async url=>{calls.push(url);return calls.length===1
    ? {...currentSolverJob,flag_rejected:true}
    : {...currentChallenge,notes:'# 수동 메모',notes_token:'new',flag:null,status:'pending',completion_source:null,has_writeup:false,writeup_markdown:null};};
  await rejectSolverFlag();
  assert.equal(calls.length,2);assert.ok(calls[0].endsWith('/reject-flag'));assert.ok(calls[1].endsWith('/challenges/challenge'));
  assert.equal(currentChallenge.notes,'# 수동 메모');assert.equal(currentChallenge.notes_token,'new');
  assert.ok(editor.value.includes('# 수동 메모 수정'));assert.ok(editor.value.includes('# 추가 분석'));
  assert.ok(!editor.value.includes(start));assert.ok(!editor.value.includes('# 오답'));
  assert.equal(noteDrafts.get('workspace:challenge').baseline,'# 수동 메모');
})()`,context);console.log('reject notes synchronization regression passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(source, harness)
