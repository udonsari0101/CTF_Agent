"""Browser-independent regressions for write-up refinement and compact controls."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def _app_source() -> str:
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    return "\n".join(
        line
        for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )


def test_writeup_refinement_keeps_old_artifact_on_failure_and_allows_retry():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the browser-independent JavaScript regression")
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8'),timers=[],requests=[],messages=[];
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',value:'',className:'',dataset:{},
  disabled:false,attributes:{},append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(k,v){this.attributes[k]=String(v);},
  removeAttribute(k){delete this.attributes[k];},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}},extra);}
const nodes={app:element(),modal:element(),detail:element({open:true}),'solver-panel':element(),'writeup-refine-container':element(),
  'writeup-refine-instruction':element({value:'  코드 설명 보강  '}),'notes-editor':element({value:'# old notes'}),'notes-save-state':element(),toasts:element()};
const document={activeElement:null,body:element(),querySelector(selector){return nodes[selector.slice(1)]||null;},getElementById(id){return nodes[id]||null;},
  createElement(){return element();},addEventListener(){},execCommand(){return true;}};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},localStorage:{getItem(){return null;},setItem(){}},
  location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,
  TextEncoder:require('node:util').TextEncoder,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch:async()=>{throw new Error('unexpected fetch');},renderAccounts:async()=>{},
  setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){},assert,nodes,timers,requests,messages,element};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const workspaceId='workspace-one',challengeId='challenge-one';
  currentWorkspace={id:workspaceId};
  currentChallenge={id:challengeId,workspace_id:workspaceId,status:'solved',completion_source:'agent',flag:'FLAG{kept}',
    notes:'# old notes',notes_token:'old-token',writeup_markdown:'# 기존 write-up',has_writeup:true};
  currentSolverJob={id:'solve-one',phase:'completed',writeup_markdown:'# 이전 write-up'};currentSolverEvents=[];
  solverProvider='codex';solverOptionsState='ready';solverAccountId='account-one';solverAccounts=[{id:'account-one',provider:'codex'}];
  solverModel='gpt-5.6-sol';solverModels=[{model:'gpt-5.6-sol'}];solverReasoning='high';solverServiceTier='fast';solverRendering=7;
  solverContext=()=>true;refreshChallenges=async()=>{};rememberNotes=()=>{};toast=(message,error)=>messages.push([message,error]);
  const initial=solverWriteupArtifact(currentChallenge.writeup_markdown);
  assert.ok(initial.includes('<h1>기존 write-up</h1>'));assert.ok(initial.includes('write-up 보완'));
  assert.ok(initial.includes('id="writeup-refine-instruction"'));
  assert.ok(initial.includes('maxlength="12288"'));
  assert.equal(solverWriteup(),'# 기존 write-up');
  for(const invalid of [
    {...currentChallenge,status:'pending'},
    {...currentChallenge,completion_source:'manual'},
    {...currentChallenge,flag:''},
    {...currentChallenge,flag:'FLAG{bad}\\n'},
    {...currentChallenge,writeup_markdown:''},
  ]){
    const valid=currentChallenge;currentChallenge=invalid;
    assert.equal(writeupRefinementMarkup(),'');
    currentChallenge=valid;
  }

  api=async(url,options)=>{requests.push([url,options]);return {job:{id:'refine-recovered',phase:'writing',job_mode:'writeup_refine'}};};
  await loadWriteupRefinement(workspaceId,challengeId,7);
  assert.equal(requests.at(-1)[0],'/api/workspaces/'+workspaceId+'/challenges/'+challengeId+'/writeup/refine');
  assert.equal(writeupRefineJob.id,'refine-recovered');assert.ok(nodes['writeup-refine-container'].innerHTML.includes('보완 중'));
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('data-action="cancel-writeup-refine"'));
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('aria-label="write-up 보완 중단"'));
  assert.ok(timers.length>0);
  api=async(url,options)=>{requests.push([url,options]);return {job:{id:'refine-recovered',phase:'cancelled',job_mode:'writeup_refine'}};};
  await cancelWriteupRefinement();
  assert.equal(requests.at(-1)[0],'/api/solver/jobs/refine-recovered/cancel');assert.equal(requests.at(-1)[1].method,'POST');
  assert.equal(currentChallenge.writeup_markdown,'# 기존 write-up');assert.equal(currentChallenge.notes,'# old notes');
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('보완을 중단했습니다'));
  writeupRefineJob=null;writeupRefineEvents=[];writeupRefineError=null;writeupRefineTimer=null;requests.length=0;

  api=async(url,options)=>{requests.push([url,JSON.parse(JSON.stringify(options||{}))]);return {job:{id:'refine-one',phase:'queued'}};};
  await startWriteupRefinement();
  assert.equal(requests[0][0],'/api/workspaces/'+workspaceId+'/challenges/'+challengeId+'/writeup/refine');
  assert.deepEqual(requests[0][1].body,{provider:'codex',account_id:'account-one',model:'gpt-5.6-sol',reasoning_effort:'high',service_tier:'fast',instruction:'코드 설명 보강'});
  assert.equal(currentChallenge.writeup_markdown,'# 기존 write-up');assert.equal(currentChallenge.notes,'# old notes');
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('보완 중'));

  api=async()=>({job:{id:'refine-one',phase:'failed',error:{message:'refinement failed',code:'policy_security',category:'policy_security',provider_code:'TAC',retryable:false}}});
  await pollWriteupRefinement('refine-one',workspaceId,challengeId,7);
  assert.equal(currentChallenge.writeup_markdown,'# 기존 write-up');assert.equal(nodes['notes-editor'].value,'# old notes');
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('refinement failed'));
  assert.equal(writeupRefineError.provider_code,'TAC');
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('TAC'));
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('policy-error'));

  for(const [error,needle] of [
    [{message:'login required',code:'auth_required'},'data-action="open-solver-accounts"'],
    [{message:'quota reached',code:'usage_limit_exceeded',quota:{limit_name:'Codex',windows:[{kind:'primary',window_minutes:300,used_percent:50,resets_at:1770000000}]}},'solver-quota'],
    [{message:'TAC blocked',provider_code:'TAC-42'},'policy-error'],
    [{message:'CVP blocked',provider_code:'CVP_DENIED'},'policy-error'],
  ]){
    writeupRefineError=error;
    assert.ok(writeupRefinementMarkup().includes(needle));
  }
  writeupRefineError=null;

  nodes['writeup-refine-instruction'].value='가'.repeat(4097);
  const beforeOversize=requests.length;
  await assert.rejects(startWriteupRefinement,/12 KiB/);
  assert.equal(requests.length,beforeOversize);
  assert.equal(writeupRefineError.code,'invalid_writeup_instruction');
  assert.ok(nodes['writeup-refine-container'].innerHTML.includes('12 KiB'));

  nodes['writeup-refine-instruction'].value='';nodes['notes-editor'].value='# local unsaved notes';
  api=async(url,options={})=>{
    requests.push([url,JSON.parse(JSON.stringify(options))]);
    if(url.endsWith('/writeup/refine'))return {job:{id:'refine-two',phase:'completed'}};
    if(url.endsWith('/challenges/'+challengeId))return {...currentChallenge,notes:'# server notes with refined block',notes_token:'new-token',writeup_markdown:'# 개선된 write-up',writeup_updated_at:22};
    throw new Error('unexpected '+url);
  };
  await startWriteupRefinement();
  assert.equal(currentChallenge.writeup_markdown,'# 개선된 write-up');assert.equal(currentChallenge.notes,'# server notes with refined block');
  assert.equal(nodes['notes-editor'].value,'# local unsaved notes');
  assert.ok(nodes['solver-panel'].innerHTML.includes('<h1>개선된 write-up</h1>'));
  assert.ok(nodes['solver-panel'].innerHTML.includes('보완 완료'));
  assert.ok(messages.some(([message])=>message.includes('보완을 완료')));
})()`,context);console.log('write-up refinement UI regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run(
        [node, "-e", harness],
        input=_app_source(),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_icon_only_controls_have_names_and_account_screen_uses_text_buttons():
    app = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    accounts = (ROOT / "ctf_agent" / "web" / "accounts.js").read_text(encoding="utf-8")
    telegram = (ROOT / "ctf_agent" / "web" / "telegram.js").read_text(encoding="utf-8")
    theme = (ROOT / "ctf_agent" / "web" / "theme.css").read_text(encoding="utf-8")

    controls = re.findall(r"<button\b[^>]*\bicon-action\b[^>]*>", app + telegram)
    assert len(controls) >= 12
    for control in controls:
        assert "aria-label=" in control, control
        assert "title=" in control, control
    assert "iconButton(" not in accounts
    assert "icon-action" not in accounts
    for label in ("사용량 새로고침", "계정 삭제", "최신 버전 조회"):
        assert f"button('{label}'" in accounts
    assert ".icon-action" in theme and "min-width: 36px" in theme
    assert ".icon-action { min-width: 44px; min-height: 44px; }" in theme
    assert "AI 문제 풀이" not in app
    assert "AI 공급자" not in app
    assert "AI 풀이 설정" not in app
    assert "<h1>작업공간</h1>" in app
