"""Exercise the real event handlers with a small DOM contract, without a browser."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_submission_panel_drafts_stale_responses_failures_and_flag_controls():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed for the browser-independent JavaScript regression')
    web_root = Path(__file__).parents[1] / 'ctf_agent/web'
    source = (web_root / 'app.js').read_text(encoding='utf-8')
    styles = (web_root / 'theme.css').read_text(encoding='utf-8')
    assert '.ctfd-submit-toggle { display: inline-flex;' in styles
    assert 'max-width: 100%; margin: 0; white-space: nowrap;' in styles
    assert '.dialog-body .ctfd-submit-toggle > input { flex: 0 0 18px; width: 18px; max-width: 18px;' in styles
    assert '.ctfd-submit-panel .divider { margin: 0; }' in styles
    assert '.ctfd-submit-panel .submission-history { width: 100%; min-width: 0; }' in styles
    assert '.ctfd-submit-actions, .ctfd-submit-actions button { width: 100%; }' in styles
    source = source.replace("import {renderAccounts} from './accounts.js';", '')
    source = '\n'.join(line for line in source.splitlines() if not line.startswith("run(async () => { const state = await api('/api/auth/state');"))
    harness = r'''
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const events = {}, nodes = {}, created = [], copied = [];
function element(extra={}) {
  return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',value:'',dataset:{},disabled:false,checked:false,
    attributes:{},listeners:{},children:[],append(node){this.children.push(node);},remove(){this.isConnected=false;},
    focus(){document.activeElement=this;},select(){},click(){this.clicked=true;},
    setAttribute(k,v){this.attributes[k]=v;},removeAttribute(k){delete this.attributes[k];},
    querySelector(){return null;},querySelectorAll(){return [];},addEventListener(k,fn){this.listeners[k]=fn;},
    showModal(){this.open=true;},close(){this.open=false;this.listeners.close?.();},
    closest(){return this.dataset.action ? this : null;},matches(selector){return selector==='tr[data-action]' && this.tagName==='TR';}},extra);
}
for (const id of ['app','modal','detail','toasts','challenge-area']) nodes[id]=element();
const document={activeElement:null,body:element(),querySelector:s=>nodes[s.slice(1)] || null,getElementById:id=>nodes[id],
  createElement(){const node=element();created.push(node);return node;},addEventListener(k,fn){events[k]=fn;}};
class FormData {
  constructor(form) {this.items=(form?.fields || []).filter(node=>!node.disabled).map(node=>[node.name,node.value]);}
  [Symbol.iterator](){return this.items[Symbol.iterator]();}
  getAll(key){return this.items.filter(([name])=>name===key).map(([,value])=>value);}
}
const context={document,window:{isSecureContext:true,addEventListener(k,fn){events['window:'+k]=fn;}},
  location:{hash:'#w/workspace-one'},history:{replaceState(){}},navigator:{clipboard:{async writeText(text){copied.push(text);}}},
  console,Blob,File,FormData,ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  setTimeout(){return 1;},clearTimeout(){},confirm:()=>true,fetch:async()=>{throw new Error('unexpected fetch');},
  renderAccounts:async()=>{},assert,nodes,events,copied,tick:()=>new Promise(setImmediate)};
vm.createContext(context);vm.runInContext(fs.readFileSync(0,'utf8'),context);
function mountPanel() {
  const form=element({id:'ctfd-submit-connection-form'});
  const url=element({name:'url',value:'https://ctf.example'}), token=element({name:'token',value:'',required:true});
  const username=element({name:'username',disabled:true}), password=element({name:'password',disabled:true});
  const auth=element({name:'auth_type',value:'token'}), submit=element({type:'submit'});
  const toggle=element({id:'ctfd-auto-submit-toggle',dataset:{saved:'false'}});
  const refresh=element({dataset:{action:'refresh-ctfd-submit'}}), disconnect=element({dataset:{action:'disconnect-ctfd-submit'}});
  const summary=element(), details=element({open:true}), history=element(), state=element();
  Object.defineProperty(state,'innerHTML',{get(){return this.html || '';},set(html){
    this.html=html;toggle.checked=/data-saved="true"/.test(html);toggle.dataset.saved=String(toggle.checked);
    toggle.disabled=/id="ctfd-auto-submit-toggle"[^>]* disabled/.test(html);
  }});
  form.fields=[url,auth,token,username,password];
  form.querySelector=selector=>selector==='input[name="url"]' ? url : null;
  form.querySelectorAll=selector=>selector.startsWith('input[name="token"]') ? [token,username,password] : [...form.fields,submit];
  const lookup={'form':form,'#ctfd-submit-connection-form':form,'#ctfd-connection-state':state,
    '#ctfd-connection-summary':summary,'#ctfd-connection-details':details,'#ctfd-submission-history':history,
    '#ctfd-auto-submit-toggle':toggle,'input[name="url"]':url,'.toasts':nodes.toasts};
  nodes.modal.querySelector=selector=>lookup[selector] || null;
  nodes.modal.querySelectorAll=()=>[...form.fields,submit,toggle,refresh,disconnect];
  nodes.modal.open=true;nodes.modal.dataset={kind:'ctfd-submit',workspaceId:'workspace-one'};
  context.panel={form,url,token,username,password,auth,submit,toggle,refresh,disconnect,summary,details,history,state};
  document.activeElement=token;
  vm.runInContext(`currentWorkspace={id:'workspace-one',name:'One'};location.hash='#w/workspace-one';++modalRendering;
    panel.form.dataset.workspaceId='workspace-one';panel.form.dataset.initial=formSnapshot(panel.form);`,context);
  return context.panel;
}
context.mountPanel=mountPanel;
(async()=>{
await vm.runInContext(`(async()=>{
  const reply=value=>({ok:true,json:async()=>value});
  const saved={connected:true,auto_submit:false,url:'https://ctf.example',auth_type:'token'};
  // A late initial load may neither reopen a closed panel nor overwrite another form/page.
  for (const action of ['workspace','modal','close']) {
    mountPanel();const pending=[];
    fetch=()=>new Promise(resolve=>pending.push(resolve));
    const loading=ctfdSubmitSettings();
    if (action==='workspace') {currentWorkspace={id:'workspace-two'};location.hash='#w/workspace-two';}
    if (action==='modal') openModal('다른 입력창','','새 입력 내용');
    if (action==='close') nodes.modal.close();
    const previous=nodes.modal.innerHTML, wasOpen=nodes.modal.open;
    pending[0](reply(saved));pending[1](reply({submissions:[]}));await loading;
    assert.equal(nodes.modal.innerHTML,previous,action);assert.equal(nodes.modal.open,wasOpen,action);
  }
  // The real markup connects help text, gives the scrollable history a keyboard stop,
  // and contains one independent form (no nested outer form).
  mountPanel();fetch=async url=>reply(url.endsWith('/submissions')?{submissions:[]}:saved);
  await ctfdSubmitSettings();
  assert.equal((nodes.modal.innerHTML.match(/<form /g)||[]).length,1);
  assert.ok(nodes.modal.innerHTML.includes('class="ctfd-submit-panel"'));
  assert.ok(nodes.modal.innerHTML.includes('class="ctfd-submit-connection-details"'));
  assert.ok(nodes.modal.innerHTML.includes('class="section-head ctfd-submit-history-head"'));
  assert.ok(nodes.modal.innerHTML.includes('<div class="ctfd-submit-toggle-row"><label class="ctfd-submit-toggle"><input'));
  assert.ok(nodes.modal.innerHTML.includes('<span>Flag 자동 제출</span></label></div>'));
  assert.ok(!nodes.modal.innerHTML.includes('class="telegram-toggle"'));
  assert.ok(nodes.modal.innerHTML.includes('aria-describedby="ctfd-auto-submit-help"'));
  assert.ok(nodes.modal.innerHTML.includes('id="ctfd-auto-submit-help"'));
  assert.ok(nodes.modal.innerHTML.includes('기본 OFF · CTFd 오답 패널티가 적용될 수 있습니다.'));
  assert.ok(!nodes.modal.innerHTML.includes('오답은 자동으로 다시 보내지 않습니다'));
  assert.ok(nodes.modal.innerHTML.includes('role="region" tabindex="0" aria-label="최근 자동 제출 기록"'));
  // Refresh stays inside saved state/history and preserves a dirty connection draft.
  mountPanel();panel.url.value='draft.example';panel.token.value='draft-token';
  const baseline=panel.form.dataset.initial, originalForm=panel.form;
  const pending=[];fetch=url=>new Promise(resolve=>pending.push([url,resolve]));
  const refreshing=refreshCTFdSubmit();
  assert.equal(panel.token.disabled,true);assert.equal(busyForms.has(panel.form),true);
  panel.toggle.checked=true;await toggleCTFdSubmit(panel.toggle);assert.equal(pending.length,2);
  pending[0][1](reply(saved));pending[1][1](reply({submissions:[{challenge_name:'<b>untrusted</b>',ctfd_id:1,status:'incorrect',attempts:1,display_message:'<img src=x>'}]}));
  await refreshing;
  assert.equal(panel.form,originalForm);assert.equal(panel.token.value,'draft-token');assert.equal(panel.url.value,'draft.example');
  assert.equal(panel.form.dataset.initial,baseline);assert.equal(formDirty(),true);assert.equal(panel.token.disabled,false);
  assert.ok(panel.history.innerHTML.includes('&lt;b&gt;untrusted&lt;/b&gt;'));assert.ok(!panel.history.innerHTML.includes('<img'));
  // A failed toggle and a cancelled enable keep the previously saved checkbox value.
  panel.toggle.dataset.saved='true';panel.toggle.checked=false;
  let writes=0;fetch=async(url,options)=>{writes++;assert.ok(url.includes('/workspace-one/'));assert.equal(JSON.parse(options.body).auto_submit,false);return {ok:false,status:503,json:async()=>({detail:'temporarily unavailable'})};};
  await assert.rejects(toggleCTFdSubmit(panel.toggle),/temporarily unavailable/);
  assert.equal(panel.toggle.checked,true);assert.equal(panel.toggle.disabled,false);assert.equal(writes,1);
  panel.toggle.dataset.saved='false';panel.toggle.checked=true;confirm=()=>false;
  await toggleCTFdSubmit(panel.toggle);assert.equal(panel.toggle.checked,false);assert.equal(writes,1);confirm=()=>true;
  // Saving a replacement takes the OFF state from the server, erases only successful
  // credentials, and measures the clean baseline after re-enabling its controls.
  mountPanel();panel.token.value='draft-token';panel.url.value=' ctf.example ';panel.toggle.dataset.saved='true';panel.toggle.checked=true;
  fetch=async(url,options)=>{
    assert.ok(url.endsWith('/workspace-one/ctfd/connection'));assert.equal(options.method,'PUT');
    const body=JSON.parse(options.body);assert.equal(body.url,'https://ctf.example');assert.equal(body.token,'draft-token');
    assert.equal('username' in body,false);assert.equal('password' in body,false);return reply(saved);
  };
  await saveCTFdSubmitConnection(panel.form,{url:panel.url.value,auth_type:'token',token:panel.token.value,username:'dormant',password:'dormant'});
  assert.equal(panel.toggle.checked,false);assert.equal(panel.token.value,'');assert.equal(panel.url.value,'https://ctf.example');
  assert.equal(formDirty(),false);assert.equal(panel.token.disabled,false);assert.equal(document.activeElement,panel.toggle);
  panel.token.value='keep-on-error';fetch=async()=>({ok:false,status:400,json:async()=>({detail:'invalid connection'})});
  await assert.rejects(saveCTFdSubmitConnection(panel.form,{url:'ctf.example',auth_type:'token',token:'keep-on-error'}),/invalid connection/);
  assert.equal(panel.token.value,'keep-on-error');assert.equal(formDirty(),true);
  // A disconnect keeps an in-progress replacement form. A late save uses the old
  // workspace endpoint and cannot change the new page/modal or clear its draft.
  fetch=async(url,options)=>{assert.equal(options.method,'DELETE');return reply({connected:false,auto_submit:false});};
  await disconnectCTFdSubmit();assert.equal(panel.token.value,'keep-on-error');assert.equal(formDirty(),true);assert.equal(panel.toggle.disabled,true);
  mountPanel();panel.token.value='old-workspace-token';let resolveSave, writeURL;
  fetch=async url=>{writeURL=url;return await new Promise(resolve=>{resolveSave=resolve;});};
  const saving=saveCTFdSubmitConnection(panel.form,{url:'ctf.example',auth_type:'token',token:panel.token.value});
  currentWorkspace={id:'workspace-two'};location.hash='#w/workspace-two';openModal('다른 창','','보존할 내용');
  const afterNavigation=nodes.modal.innerHTML;resolveSave(reply(saved));await saving;
  assert.ok(writeURL.includes('/workspace-one/'));assert.equal(nodes.modal.innerHTML,afterNavigation);
  assert.equal(panel.token.value,'old-workspace-token');assert.equal(nodes.modal.attributes['aria-busy'],undefined);
  // Copy uses the full flag, escapes displayed content, and does not activate its row.
  mountPanel();nodes.modal.open=false;
  const flag='flag{'+ '<&"'.repeat(80) +'}';
  fetch=async()=>reply({challenges:[{id:'challenge-one',name:'한글 <문제>',flag,status:'flag_found',category:'',ctfd_id:1,updated_at:'2026-09-01T00:00:00Z'}],counts:{pending:0,running:0,stopped:0,failed:0,flag_found:1,solved:0},categories:[]});
  await refreshChallenges();
  assert.ok(nodes['challenge-area'].innerHTML.includes(esc(flag)));
  assert.ok(nodes['challenge-area'].innerHTML.includes('data-workspace-id="workspace-one"'));
  assert.ok(nodes['challenge-area'].innerHTML.includes('aria-label="한글 &lt;문제&gt; Flag 복사"'));
  const button={dataset:{action:'copy-list-flag',id:'challenge-one',workspaceId:'workspace-one'},disabled:false,closest(){return this;},matches(){return false;}};
  let prevented=0;events.keydown({target:button,key:'Enter',preventDefault(){prevented++;}});assert.equal(prevented,0);
  fetch=async()=>{throw new Error('copy must never open a challenge or send a request');};
  events.click({target:button,preventDefault(){prevented++;}});await tick();assert.equal(copied.at(-1),flag);assert.equal(prevented,1);
  const copies=copied.length;currentWorkspace={id:'workspace-two'};
  events.click({target:button,preventDefault(){}});await tick();assert.equal(copied.length,copies);
})()`,context);
console.log('submission panel and flag control regressions passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run([node, '-e', harness], input=source, text=True, encoding='utf-8', capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
