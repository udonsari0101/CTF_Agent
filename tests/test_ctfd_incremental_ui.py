"""Browser-independent checks for incremental CTFd synchronization controls."""

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def test_incremental_ctfd_ui_uses_saved_connection_and_preserves_local_work():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the browser-independent JavaScript regression")

    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line
        for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',className:'',dataset:{},
  disabled:false,attributes:{},append(){},remove(){},focus(){},select(){},setSelectionRange(){},
  setAttribute(k,v){this.attributes[k]=String(v);},removeAttribute(k){delete this.attributes[k];},
  querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}},extra);}
const nodes={app:element(),modal:element(),detail:element(),toasts:element(),'ctfd-refresh-state':element()};
const document={activeElement:null,body:element(),querySelector(selector){return nodes[selector.slice(1)]||null;},
  getElementById(id){return nodes[id]||null;},createElement(){return element();},addEventListener(){},execCommand(){return true;}};
class FormData {constructor(form){this.items=form?.items||[];}[Symbol.iterator](){return this.items[Symbol.iterator]();}}
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},localStorage:{getItem(){return null;},setItem(){}},
  location:{hash:'#w/workspace-one'},history:{replaceState(){}},console,Blob,File:class{},FormData,ArrayBuffer,
  URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,
  fetch:async()=>{throw new Error('unexpected fetch');},renderAccounts:async()=>{},setTimeout,clearTimeout,assert,nodes,element};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  const workspaceId='workspace-one',challengeId='challenge-one',opened=[],requests=[],messages=[];
  currentWorkspace={id:workspaceId,name:'Workspace'};
  const modalCalls=[],syncForm=element({id:'ctfd-sync-form',dataset:{},items:[["challenge","11"]]});
  openModal=(...args)=>{modalCalls.push(args);nodes.modal.open=true;nodes.modal.dataset={};nodes.modal.querySelector=selector=>
    (selector==='#ctfd-sync-form'||selector==='form')&&args[4]==='ctfd-sync-form'?syncForm:null;};
  showCTFdSyncPreview({preview_id:'preview-one',source_url:'https://ctf.example',existing_count:4,new_count:2,
    details_pending:true,errors:[],challenges:[{id:11,name:'New <img src=x>',category:'web',files:[]},{id:12,name:'Second',category:'',files:[]}]},workspaceId);
  const preview=modalCalls.at(-1);
  assert.equal(preview[0],'새 문제 동기화');assert.equal(preview[4],'ctfd-sync-form');
  assert.ok(preview[2].includes('&lt;img src=x&gt;'));assert.ok(!preview[2].includes('<img src=x>'));
  assert.ok(preview[2].includes('Flag'));assert.ok(preview[2].includes('write-up'));assert.ok(preview[2].includes('변경하지'));
  assert.ok(preview[2].includes('<strong>2</strong> 신규'));assert.ok(preview[2].includes('<strong>4</strong> 기존 유지'));
  assert.equal(importPreview.mode,'sync');assert.equal(importPreview.workspaceId,workspaceId);
  assert.equal(syncForm.dataset.workspaceId,workspaceId);

  nodes.modal.close=()=>{nodes.modal.open=false;};
  refreshChallenges=async()=>{messages.push('list')};pollCTFdJobs=async id=>{assert.equal(id,workspaceId);messages.push('jobs')};
  toast=message=>messages.push(message);
  api=async(url,options)=>{requests.push([url,options]);return {job:{id:'sync-job',status:'queued',mode:'new'}};};
  await startCTFdSync(syncForm,[11]);
  assert.equal(requests[0][0],'/api/workspaces/'+workspaceId+'/ctfd/sync');
  assert.deepEqual(requests[0][1].body,{preview_id:'preview-one',challenge_ids:[11]});
  assert.deepEqual(messages.slice(0,2),['list','jobs']);assert.ok(messages.at(-1).includes('1개'));

  let remembered=0,polled=0;
  currentChallenge={id:challengeId,workspace_id:workspaceId,ctfd_id:11,ctfd_url:'https://ctf.example',
    status:'solved',flag:'FLAG{kept}',notes:'# kept',writeup_markdown:'# kept write-up',completion_source:'agent'};
  nodes.detail.open=true;rememberNotes=()=>{remembered++};openChallenge=async id=>opened.push(id);
  pollCTFdJobs=async()=>{polled++};
  api=async(url,options)=>{requests.push([url,options]);return {job:{id:'refresh-job',status:'completed',mode:'refresh',refreshed:1}};};
  await refreshCTFdChallenge();
  await new Promise(resolve=>setTimeout(resolve,0));
  const refreshRequest=requests.at(-1);
  assert.equal(refreshRequest[0],'/api/workspaces/'+workspaceId+'/challenges/'+challengeId+'/ctfd/refresh');
  assert.equal(refreshRequest[1].method,'POST');assert.deepEqual(refreshRequest[1].body,{});
  assert.equal(currentChallenge.status,'solved');assert.equal(currentChallenge.flag,'FLAG{kept}');
  assert.equal(currentChallenge.notes,'# kept');assert.equal(currentChallenge.writeup_markdown,'# kept write-up');
  assert.deepEqual(opened,[challengeId]);assert.ok(remembered>=2);assert.equal(polled,1);
  assert.ok(messages.at(-1).includes('로컬 풀이 자료는 유지'));

  const secretToken=element({name:'token',value:'unused'}),secretUser=element({name:'username',value:'ctf-user'}),secretPassword=element({name:'password',value:'ctf-password'});
  const authForm=element({dataset:{workspaceId,challengeId},querySelectorAll:()=>[secretToken,secretUser,secretPassword]});
  currentChallenge={id:challengeId,workspace_id:workspaceId,ctfd_id:11,ctfd_url:'https://ctf.example',notes:'# kept'};
  nodes.modal.open=true;nodes.modal.close=()=>{nodes.modal.open=false;};
  let sentCredentials;
  api=async(url,options)=>{sentCredentials=JSON.parse(JSON.stringify(options.body));return {job:{id:'reauth-job',status:'completed',mode:'refresh',refreshed:1}};};
  const credentials={url:'https://ctf.example',auth_type:'password',token:'must-not-send',username:'ctf-user',password:'ctf-password'};
  await startAuthenticatedCTFdRefresh(authForm,credentials);
  await new Promise(resolve=>setTimeout(resolve,0));
  assert.deepEqual(sentCredentials,{url:'https://ctf.example',auth_type:'password',username:'ctf-user',password:'ctf-password'});
  assert.equal(secretToken.value,'');assert.equal(secretUser.value,'');assert.equal(secretPassword.value,'');
  assert.equal(credentials.username,'');assert.equal(credentials.password,'');assert.equal(nodes.modal.open,false);

  currentChallenge={id:'manual',workspace_id:workspaceId,ctfd_id:null,ctfd_url:null};
  await assert.rejects(refreshCTFdChallenge(),/CTFd에서 가져온 문제만/);

  currentChallenge={id:challengeId,workspace_id:workspaceId,ctfd_id:11,ctfd_url:'https://ctf.example'};
  api=async()=>{throw new Error('saved connection expired');};
  const fallback=await refreshCTFdChallenge();
  assert.equal(fallback,null);
  const fallbackModal=modalCalls.at(-1);
  assert.equal(fallbackModal[0],'CTFd 연결 확인');
  assert.ok(fallbackModal[2].includes('saved connection expired'));
  assert.ok(fallbackModal[3].includes('data-action="ctfd-refresh-auth"'));
  assert.ok(fallbackModal[3].includes('data-action="ctfd-submit-settings"'));
  assert.equal(nodes.modal.dataset.kind,'ctfd-refresh-fallback');
  ctfdRefreshAuthForm();
  assert.equal(modalCalls.at(-1)[4],'ctfd-refresh-auth-form');

  const fresh=ctfdJobMarkup({id:'new-job',mode:'new',status:'failed',imported:2,attachments:1,errors:[]});
  assert.ok(fresh.includes('CTFd 새 문제 동기화'));assert.ok(fresh.includes('신규 2개'));
  assert.ok(fresh.includes('data-mode="new"'));assert.ok(fresh.includes('같은 연결로 다시 시도'));
  const refreshed=ctfdJobMarkup({id:'refresh-job',mode:'refresh',status:'completed',refreshed:1,attachments:2,errors:[]});
  assert.ok(refreshed.includes('CTFd 문제 새로고침'));assert.ok(refreshed.includes('업데이트 1개'));
  const changedManifest=ctfdJobMarkup({id:'refresh-failed',mode:'refresh',target_challenge_id:challengeId,status:'partial',errors:[]});
  assert.ok(changedManifest.includes('data-action="fresh-refresh-ctfd"'));assert.ok(changedManifest.includes('최신 원본으로 새 작업'));
  assert.ok(!changedManifest.includes('data-action="retry-ctfd"'));

  const refreshButton=element({dataset:{action:'refresh-ctfd-challenge'}}),authButton=element({dataset:{action:'ctfd-refresh-auth'}});
  nodes.detail.open=true;nodes.detail.querySelectorAll=()=>[refreshButton,authButton];
  currentChallenge={id:challengeId,workspace_id:workspaceId};
  const activeJob={id:'reload-job',mode:'refresh',target_challenge_id:challengeId,status:'running'};
  assert.equal(reflectActiveCTFdRefreshes([activeJob],workspaceId),null);
  assert.equal(activeCTFdChallengeRefreshes.get(workspaceId+':'+challengeId),'reload-job');
  assert.equal(refreshButton.disabled,true);assert.equal(authButton.disabled,true);assert.equal(refreshButton.textContent,'…');
  const terminalJob={...activeJob,status:'completed',refreshed:1};
  assert.equal(reflectActiveCTFdRefreshes([terminalJob],workspaceId),terminalJob);
  assert.equal(refreshButton.disabled,false);assert.equal(authButton.disabled,false);assert.equal(refreshButton.textContent,'↻');
})()`,context);console.log('incremental CTFd UI regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run(
        [node, "-e", harness],
        input=source,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_incremental_ctfd_controls_are_visible_and_styled():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    styles = (ROOT / "ctf_agent" / "web" / "theme.css").read_text(encoding="utf-8")

    assert 'data-action="ctfd-sync"' in source
    assert 'data-action="refresh-ctfd-challenge"' in source
    assert 'data-action="ctfd-submit-settings">연결 설정' in source
    assert "'ctfd-refresh-auth-form'" in source
    assert 'id="ctfd-refresh-state"' in source
    assert "'/ctfd/sync/preview'" not in source  # endpoints retain their workspace scope
    assert "/ctfd/sync/preview`" in source
    assert "/ctfd/refresh`" in source
    assert ".ctfd-sync-counts" in styles
    assert ".ctfd-source-tools" in styles
