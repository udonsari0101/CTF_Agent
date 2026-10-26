"""Browser-independent regressions for async editing and clipboard behavior."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_manual_challenge_form_accepts_normal_remote_connection_details():
    source = (
        Path(__file__).parents[1] / "ctf_agent" / "web" / "app.js"
    ).read_text(encoding="utf-8")
    assert 'name="remote"' in source
    assert 'maxlength="2000"' in source
    endpoint_label = source.split('<label data-remote-endpoint>', 1)[1].split('</label>', 1)[0]
    assert '<span class="form-hint">' not in endpoint_label
    assert "RESTRICTED TARGET" not in source


def test_late_save_preserves_draft_stale_fetch_is_ignored_and_copy_falls_back():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed for the browser-independent JavaScript regression')
    source = (Path(__file__).parents[1]/'ctf_agent'/'web'/'app.js').read_text(encoding='utf-8')
    source = source.replace("import {renderAccounts} from './accounts.js';", '')
    source = '\n'.join(line for line in source.splitlines() if not line.startswith("run(async () => { const state = await api('/api/auth/state');"))
    harness = r'''
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync(0,'utf8');
function element() { return {open:false,isConnected:true,innerHTML:'',textContent:'',value:'',dataset:{},disabled:false,
  append(){},remove(){},focus(){this.focused=true;},select(){},setSelectionRange(a,b){this.selectionStart=a;this.selectionEnd=b;},
  setAttribute(){},removeAttribute(){},querySelector(){return null;},querySelectorAll(){return [];},addEventListener(){},
  showModal(){this.open=true;},close(){this.open=false;},click(){this.clicked=true;}}; }
const elements = Object.fromEntries(['#app','#modal','#detail','#notes-editor','#notes-save-state','#upload-progress','#toasts','#challenge-area'].map(key=>[key,element()]));
elements['#detail'].open=true;
const created=[];
const document={querySelector:selector=>elements[selector] || null,getElementById:id=>elements['#'+id],addEventListener(){},
  createElement(){const node=element();created.push(node);return node;},body:element(),activeElement:elements['#notes-editor'],
  execCommand(command){assert.equal(command,'copy');this.copied=true;return true;}};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{clipboard:{writeText:async()=>{throw new Error('denied');}}},
  location:{hash:'#w/workspace-one'},history:{replaceState(){}},console,Blob,File,FormData,ArrayBuffer,URLSearchParams,Uint8Array,
  URL:{createObjectURL(blob){context.lastBlob=blob;return 'blob:test';},revokeObjectURL(){}},
  setTimeout(){return 1;},clearTimeout(){},AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,
  fetch:async()=>{throw new Error('unexpected fetch');},renderAccounts:async()=>{}};
vm.createContext(context);vm.runInContext(source,context);
context.assert=assert;context.elements=elements;context.created=created;
(async()=>{
 await vm.runInContext(`(async()=>{
   currentWorkspace={id:'workspace-one',name:'CTF'};
   currentChallenge={id:'challenge-one',workspace_id:'workspace-one',name:'한글: 문제',notes:'old',notes_token:'old-token'};
   elements['#notes-editor'].value='saved first';
   let resolve;
   fetch=async(_url,options)=>{assert.equal(options.headers['If-Match'],'old-token');return await new Promise(done=>{resolve=done;});};
   const saving=saveNotes(true);
   elements['#notes-editor'].value='typed during request';
   resolve({ok:true,json:async()=>({ok:true,notes_token:'new-token'})});
   await saving;
   assert.equal(currentChallenge.notes,'saved first');
   assert.equal(noteDrafts.get('workspace-one:challenge-one').content,'typed during request');
   assert.equal(noteDrafts.get('workspace-one:challenge-one').token,'new-token');
   fetch=async(url)=>({ok:true,json:async()=>url.endsWith('/uploads')?{uploads:[]}:{id:'challenge-one',workspace_id:'workspace-one',name:'한글: 문제',notes:'saved first',notes_token:'new-token',attachments:[],status:'pending',category:'',description:''}});
   elements['#detail'].scrollTop=640;
   await openChallenge('challenge-one');
   assert.ok(elements['#detail'].innerHTML.includes('typed during request'));
   assert.equal(elements['#detail'].scrollTop,0);
   assert.equal(currentChallenge.notes,'saved first');
   const previous=elements['#detail'].innerHTML;
   let staleResolve;
   fetch=async()=>await new Promise(done=>{staleResolve=done;});
   const stale=openChallenge('challenge-one');
   currentWorkspace={id:'workspace-two',name:'Other'};
   staleResolve({ok:true,json:async()=>({id:'challenge-one',workspace_id:'workspace-one',notes:'stale',attachments:[]})});
   await stale;
   assert.equal(elements['#detail'].innerHTML,previous);
   elements['#notes-editor'].selectionStart=2;elements['#notes-editor'].selectionEnd=5;
   await copyText('copied text');
   assert.equal(document.copied,true);
   assert.equal(document.activeElement.selectionStart,2);
   assert.equal(document.activeElement.selectionEnd,5);
   document.execCommand=()=>false;
   await assert.rejects(copyText('cannot copy'),/자동 복사를 지원하지 않는 브라우저/);
   fetch=async()=>{throw new Error('downloading an unsaved draft must not send a save request');};
   elements['#notes-editor'].value='# local unsaved draft';
   downloadNotes();
   assert.equal(await lastBlob.text(),'# local unsaved draft');
   assert.equal(created[created.length-1].download,'한글_ 문제-notes.md');
 })()`,context);
 console.log('editing, stale response, clipboard and local download regressions passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run([node,'-e',harness],input=source,text=True,encoding='utf-8',capture_output=True,timeout=30)
    assert result.returncode == 0, result.stderr


def test_ctfd_job_history_and_admin_disabled_button_are_accessible():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed for the browser-independent JavaScript regression')
    source = (Path(__file__).parents[1]/'ctf_agent'/'web'/'app.js').read_text(encoding='utf-8')
    source = source.replace("import {renderAccounts} from './accounts.js';", '')
    source = '\n'.join(line for line in source.splitlines() if not line.startswith("run(async () => { const state = await api('/api/auth/state');"))
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function element(){return {open:false,isConnected:true,innerHTML:'',textContent:'',value:'',dataset:{},disabled:false,
  append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},
  querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;},click(){}};}
const elements=Object.fromEntries(['#app','#modal','#detail','#toasts','#challenge-area','#ctfd-job-area'].map(key=>[key,element()]));
const document={querySelector:selector=>elements[selector]||null,getElementById:id=>elements['#'+id],addEventListener(){},
  createElement:()=>element(),body:element(),activeElement:null,execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},location:{hash:''},history:{replaceState(){}},console,
  Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,
  confirm:()=>true,fetch:async()=>{throw new Error('unexpected fetch');},renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert};
vm.createContext(context);vm.runInContext(source,context);
vm.runInContext(`
  const jobs=[
    {id:'active-queued',status:'queued'},{id:'recent-complete',status:'completed'},
    {id:'recent-failed',status:'failed'},{id:'active-running',status:'running'},
    {id:'older-cancelled',status:'cancelled'},{id:'older-partial',status:'partial'}
  ];
  const markup=ctfdJobsMarkup(jobs);
  const split=markup.indexOf('<details class="ctfd-job-history">');
  assert.ok(split>0);const visible=markup.slice(0,split),folded=markup.slice(split);
  assert.ok(visible.includes('active-queued'));assert.ok(visible.includes('active-running'));
  assert.ok(visible.includes('recent-complete'));assert.ok(visible.includes('recent-failed'));
  assert.ok(!visible.includes('older-cancelled'));assert.ok(!visible.includes('older-partial'));
  assert.ok(folded.includes('older-cancelled'));assert.ok(folded.includes('older-partial'));
  assert.ok(folded.includes('<summary>이전 CTFd 가져오기 기록 2개 보기</summary>'));

  function jobArea(initialMarkup) {
    const area={dataset:{},writes:0,_markup:'',_history:null,_jobs:[],
      querySelector(selector){return selector==='.ctfd-job-history'?this._history:null;},
      querySelectorAll(selector){return selector==='[data-job-id]'?this._jobs:[];},
      contains(node){return node===this._history||node===this._history?.summary||this._jobs.some(job=>job===node||job.buttons.includes(node));}};
    Object.defineProperty(area,'innerHTML',{get(){return this._markup;},set(value){
      this.writes++;this._markup=value;this._history=null;this._jobs=[];
      if(value.includes('<details class="ctfd-job-history">')){
        const history={open:false,summary:null,querySelector(selector){return selector==='summary'?this.summary:null;}};
        history.summary={tagName:'SUMMARY',dataset:{},focus(){document.activeElement=this;},closest(selector){return selector==='.ctfd-job-history'?history:null;}};
        this._history=history;
      }
      const starts=[...value.matchAll(/<section class="workspace-summary" data-job-id="([^"]+)">/g)];
      starts.forEach((match,index)=>{
        const segment=value.slice(match.index,index+1<starts.length?starts[index+1].index:value.length);
        const job={dataset:{jobId:match[1]},buttons:[],querySelectorAll(selector){return selector==='[data-action]'?this.buttons:[];}};
        job.buttons=[...segment.matchAll(/data-action="([^"]+)"/g)].map(action=>({dataset:{action:action[1]},focus(){document.activeElement=this;},closest(selector){return selector==='[data-job-id]'?job:null;}}));
        this._jobs.push(job);
      });
    }});
    area.innerHTML=initialMarkup;ctfdJobMarkupCache.set(area,initialMarkup);area.writes=0;
    return area;
  }

  const area=jobArea(markup);
  area._history.open=true;document.activeElement=area._history.summary;
  const changed=jobs.map(job=>job.id==='active-running'?{...job,current_file:'part-one.bin'}:job);
  updateCTFdJobs(area,changed);
  assert.equal(area._history.open,true);assert.equal(document.activeElement,area._history.summary);
  const running=area._jobs.find(job=>job.dataset.jobId==='active-running');
  document.activeElement=running.buttons.find(button=>button.dataset.action==='cancel-ctfd');
  const changedAgain=changed.map(job=>job.id==='active-running'?{...job,current_file:'part-two.bin'}:job);
  updateCTFdJobs(area,changedAgain);
  const nextRunning=area._jobs.find(job=>job.dataset.jobId==='active-running');
  assert.equal(document.activeElement,nextRunning.buttons.find(button=>button.dataset.action==='cancel-ctfd'));
  const writes=area.writes,focused=document.activeElement;
  updateCTFdJobs(area,changedAgain);
  assert.equal(area.writes,writes);assert.equal(document.activeElement,focused);

  sessionUser={id:'admin-one'};
  const lastAdmin=adminUserActiveButton({id:'admin-one',username:'admin',role:'admin',active:true},1);
  assert.ok(lastAdmin.includes('disabled'));assert.ok(lastAdmin.includes('title="마지막 활성 관리자는 비활성화할 수 없습니다."'));
  assert.ok(lastAdmin.includes('aria-label="admin: 마지막 활성 관리자는 비활성화할 수 없습니다."'));
  assert.ok(lastAdmin.includes('aria-describedby="user-active-reason-admin-one"'));
  assert.ok(lastAdmin.includes('class="admin-disabled-reason">마지막 활성 관리자는 비활성화할 수 없습니다.</small>'));
  const otherAdmin=adminUserActiveButton({id:'admin-two',username:'peer',role:'admin',active:true},2);
  assert.ok(!otherAdmin.includes('disabled'));
`,context);
console.log('CTFd job history and admin accessibility regressions passed');
'''
    result = subprocess.run([node,'-e',harness],input=source,text=True,encoding='utf-8',capture_output=True,timeout=30)
    assert result.returncode == 0, result.stderr


def test_pausing_one_selected_attachment_does_not_discard_later_files():
    """A paused transfer keeps its session while the remaining selection proceeds."""
    source = (Path(__file__).parents[1] / 'ctf_agent' / 'web' / 'app.js').read_text(encoding='utf-8')

    new_challenge_loop = (
        "if (!edit) for (const file of challengeFiles) { try { "
        "if (await uploadFile(file,workspaceId,c.id)) uploaded++;"
    )
    existing_challenge_loop = (
        "for (const file of input.files) { try { "
        "if (await uploadFile(file,c.workspace_id,c.id)) completed++;"
    )

    assert new_challenge_loop in source
    assert existing_challenge_loop in source
    assert "if (!await uploadFile(file,workspaceId,c.id)) break" not in source
    assert "else break; } catch(error)" not in source
