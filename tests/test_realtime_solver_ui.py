"""Browser-independent regressions for live solver and dashboard updates."""

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def _source() -> str:
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    return "\n".join(
        line
        for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )


def _node(harness: str) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for browser-independent JavaScript regressions")
    result = subprocess.run(
        [node, "-e", harness],
        input=_source(),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_live_session_log_incremental_cursor_and_mid_solve_guidance():
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),requests=[],timers=[];
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',value:'',id:'',dataset:{},disabled:false,
  append(){},remove(){},focus(){document.activeElement=this;},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},
  querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}},extra);}
const nodes={app:element(),modal:element(),detail:element({open:true}),'solver-panel':element(),'challenge-flag-box':element(),
  'copy-flag-button':element(),'challenge-status-controls':element(),toasts:element()};
const document={activeElement:null,visibilityState:'visible',body:element(),querySelector:s=>nodes[s.slice(1)]||null,
  getElementById:id=>nodes[id]||null,createElement:()=>element(),addEventListener(){},execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},localStorage:{getItem(){return null;},setItem(){}},
  location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,
  TextEncoder:require('node:util').TextEncoder,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,
  fetch:async()=>{throw new Error('unused');},renderAccounts:async()=>{},setTimeout(fn,delay){timers.push([fn,delay]);return timers.length;},
  clearTimeout(){},assert,requests,nodes,timers};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const workspace='workspace-one',challenge='challenge-one',jobId='job-live-one';
  currentWorkspace={id:workspace};currentChallenge={id:challenge,workspace_id:workspace,status:'running',flag:'',completion_source:null,notes:'',notes_token:'n'};
  const job={id:jobId,status:'running',phase:'running',account_label:'Codex Pro',configuration:{provider:'codex',model:'gpt-daybreak-blue-latest',reasoning_effort:'high'}};
  currentSolverJob=job;currentSolverEvents=[{sequence:5,kind:'progress',code:'analyzing',created_at:10}];solverEventCursor=5;
  currentSolverGuidance=[{id:'g0',job_id:jobId,message:'기존 명령',status:'delivered',created_at:9}];solverRendering=7;
  solverContext=()=>true;refreshChallenges=async()=>{};syncSolverWriteup=async()=>{};
  let html=solverPanelMarkup(job,[...currentSolverEvents,{sequence:6,kind:'activity',phase:'started',tool:'shell',summary:'파일 <검사>',command:'file ./chall',output:'ELF 64-bit\\n검사 완료',created_at:11}]);
  assert.ok(html.includes('세션 로그'));assert.ok(html.includes('LIVE'));assert.ok(html.includes(jobId));
  assert.ok(html.includes('도구 실행'));assert.ok(html.includes('shell · 시작 · 파일 &lt;검사&gt; · file ./chall'));
  assert.ok(html.includes('ELF 64-bit\\n검사 완료'));
  assert.ok(!html.includes('파일 <검사>'));assert.ok(html.includes('id="solver-guidance-form"'));assert.ok(html.includes('기존 명령'));
  assert.ok(!solverPanelMarkup({...job,guidance_allowed:false},currentSolverEvents).includes('id="solver-guidance-form"'));

  api=async(url,options={})=>{requests.push([url,options]);
    if(url.endsWith('/guidance'))return {guidance:{id:'g1',job_id:jobId,message:'다음 단계 <확인>',status:'queued',created_at:12},job};
    assert.equal(url,'/api/solver/jobs/'+jobId+'?after=5');
    return {...job,last_event_sequence:6,guidance:[{id:'g1',job_id:jobId,message:'다음 단계 <확인>',status:'delivered',created_at:12}],events:[{sequence:6,kind:'activity',phase:'completed',tool:'shell',summary:'파일 확인 완료',created_at:13}]};
  };
  await sendSolverGuidance('  다음 단계 <확인>  ');
  assert.equal(requests[0][0],'/api/solver/jobs/'+jobId+'/guidance');assert.equal(requests[0][1].method,'POST');
  assert.deepEqual(requests[0][1].body,{message:'다음 단계 <확인>'});assert.equal(solverGuidanceDraft,'');
  assert.equal(currentSolverGuidance.at(-1).status,'queued');assert.ok(nodes['solver-panel'].innerHTML.includes('다음 단계 &lt;확인&gt;'));
  assert.ok(!nodes['solver-panel'].innerHTML.includes('다음 단계 <확인>'));

  await pollSolverJob(jobId,workspace,challenge,7);
  assert.equal(requests[1][0],'/api/solver/jobs/'+jobId+'?after=5');
  assert.deepEqual(currentSolverEvents.map(event=>event.sequence),[5,6]);assert.equal(solverEventCursor,6);
  assert.equal(currentSolverGuidance.at(-1).status,'delivered');assert.ok(nodes['solver-panel'].innerHTML.includes('파일 확인 완료'));
  const beforePaging=timers.length;scheduleSolverPoll({...job,status:'completed',phase:'completed',released_at:14,last_event_sequence:8},workspace,challenge,7);
  assert.equal(timers.length,beforePaging+1,'terminal session history must continue paging until the last event');
  scheduleSolverPoll({...job,status:'completed',phase:'completed',released_at:14,last_event_sequence:6},workspace,challenge,7);
  assert.equal(timers.length,beforePaging+1);
  const before=requests.length;await assert.rejects(sendSolverGuidance('가'.repeat(6000)),/16 KiB/);assert.equal(requests.length,before);
})()`,context);console.log('live solver UI regression passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(harness)


def test_dashboard_poll_patches_changed_card_without_replacing_filters():
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),requests=[],timers=[];
function plain(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',dataset:{},disabled:false,
  append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},querySelector(){return null;},
  querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}},extra);}
const base={id:'challenge-one',workspace_id:'workspace-one',name:'Live Card',category:'web',description:'desc',status:'pending',flag:'',
  completion_source:null,has_writeup:false,updated_at:'2026-09-11T00:00:00Z'};
let cards=[];
function card(id,html=''){const item=plain({dataset:{challengeId:id},html});item.replaceWith=replacement=>{cards[cards.indexOf(item)]=replacement;};return item;}
cards=[card(base.id,'old-card')];
const grid=plain({querySelectorAll:selector=>selector==='[data-challenge-id]'?cards:[]});
const footer=plain({textContent:'1개 문제'}),live=plain(),count=plain({textContent:'1'});
const filterNumber=plain(),filter=plain({dataset:{status:'flag_found'},querySelector:s=>s==='span'?filterNumber:null});
const area=plain({innerHTML:'UNCHANGED',querySelector(selector){if(selector==='.challenge-card-grid')return grid;if(selector==='.table-footer')return footer;return null;},
  querySelectorAll(selector){return selector==='[data-action="filter"]'?[filter]:[];}});
function template(){const item={content:{firstElementChild:null}};Object.defineProperty(item,'innerHTML',{set(html){
  const id=/data-challenge-id="([^"]+)"/.exec(html)?.[1]||'';item.content.firstElementChild=card(id,html);
}});return item;}
const nodes={app:plain(),modal:plain(),detail:plain(),toasts:plain(),'challenge-area':area,'challenge-live-state':live};
const document={activeElement:null,visibilityState:'visible',body:plain(),querySelector(selector){
  if(selector==='[data-workspace-challenge-count]')return count;return nodes[selector.slice(1)]||null;},getElementById:id=>nodes[id]||null,
  createElement:tag=>tag==='template'?template():plain(),addEventListener(){},execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},location:{hash:''},history:{replaceState(){}},console,
  Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,TextEncoder:require('node:util').TextEncoder,
  AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch:async()=>{throw new Error('unused');},renderAccounts:async()=>{},
  setTimeout(fn,delay){timers.push([fn,delay]);return timers.length;},clearTimeout(){},assert,base,area,cards:()=>cards,requests,timers,live,count,filterNumber};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  currentWorkspace={id:'workspace-one'};challengeListCategories=JSON.stringify(['web']);
  challengeListSignatures=new Map([[base.id,challengeCardSignature(base)]]);challengeListPollGeneration=4;listRendering=2;
  const changed={...base,status:'flag_found',flag:'FLAG{live}',has_writeup:true,updated_at:'2026-09-11T00:01:00Z'};
  const result={challenges:[changed],counts:{pending:0,running:0,stopped:0,failed:0,flag_found:1,solved:0},categories:['web']};
  api=async url=>{requests.push(url);return result;};
  await pollChallengeList('workspace-one',4);
  assert.equal(requests[0],'/api/workspaces/workspace-one/challenges?');assert.equal(area.innerHTML,'UNCHANGED');
  assert.ok(cards()[0].html.includes('challenge-card-flag_found'));assert.ok(cards()[0].html.includes('FLAG{live}'));
  assert.ok(cards()[0].html.includes('write-up 복사'));assert.equal(challengeFlags.get(base.id),'FLAG{live}');
  assert.equal(count.textContent,'1');assert.equal(filterNumber.textContent,'1');assert.equal(live.textContent,'문제 1개의 상태가 갱신되었습니다.');
  assert.ok(timers.some(([,delay])=>delay===2000));
})()`,context);console.log('live dashboard regression passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    _node(harness)


def test_live_styles_keep_console_and_guidance_responsive():
    theme = (ROOT / "ctf_agent" / "web" / "theme.css").read_text(encoding="utf-8")
    assert ".solver-live-console" in theme
    assert ".solver-guidance" in theme
    assert ".solver-fast-placeholder" in theme
    assert "animation: solver-config-loading" in theme
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    assert 'class="solver-configuration solver-configuration-loading"' in source
    assert source.count('<option>불러오는 중…</option>') == 3
    assert ".solver-live-state.live" in theme
    assert ".challenge-card-actions .session-action.live" in theme
    assert "@media (min-width: 801px)" in theme
