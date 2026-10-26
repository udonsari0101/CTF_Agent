"""Regressions for the full-screen, multi-file challenge picker."""
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def test_challenge_file_picker_supports_multiple_files_and_full_screen_drop():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the browser-independent JavaScript regression")

    source = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")
    styles = (ROOT / "ctf_agent/web/theme.css").read_text(encoding="utf-8")
    assert 'id="challenge-files" class="sr-only" type="file" name="files" multiple' in source
    assert 'class="challenge-drop-screen" aria-hidden="true"' in source
    assert ".modal.file-drag-active .challenge-drop-screen" in styles
    assert ".challenge-file-row" in styles

    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const events={};
function classes(){const values=new Set();return {toggle(name,on){on?values.add(name):values.delete(name);},contains:name=>values.has(name)};}
function element(extra={}){return Object.assign({open:false,isConnected:true,innerHTML:'',textContent:'',value:'',dataset:{},disabled:false,hidden:false,
  classList:classes(),attributes:{},append(){},remove(){},focus(){},select(){},click(){},setAttribute(k,v){this.attributes[k]=v;},
  removeAttribute(k){delete this.attributes[k];},querySelector(){return null;},querySelectorAll(){return[];},addEventListener(k,fn){this.listeners??={};this.listeners[k]=fn;},
  showModal(){this.open=true;},close(){this.open=false;this.listeners?.close?.();},closest(){return null;},matches(){return false;}},extra);}
const zone=element(),list=element({hidden:true}),summary=element(),overlay=element();
const form=element({id:'new-challenge-form',_challengeFiles:[]});
form.querySelector=selector=>({'[data-file-drop-zone]':zone,'#challenge-file-list':list,'#challenge-file-summary':summary}[selector]||null);
const app=element(),modal=element({open:true}),detail=element(),toasts=element(),area=element();
modal.querySelector=selector=>selector==='#new-challenge-form'||selector==='form'?form:selector==='.challenge-drop-screen'?overlay:null;
const document={visibilityState:'visible',activeElement:null,body:element(),querySelector:s=>({'#app':app,'#modal':modal,'#detail':detail,'#toasts':toasts,'#challenge-area':area}[s]||null),
  getElementById(){return null;},createElement:()=>element(),addEventListener(k,fn){events[k]=fn;}};
class TestFile {}
class TestFormData {constructor(){this.items=[];}[Symbol.iterator](){return this.items[Symbol.iterator]();}getAll(){return[];}}
const context={document,window:{isSecureContext:true,addEventListener(k,fn){events['window:'+k]=fn;}},navigator:{},location:{hash:''},history:{replaceState(){}},
  console,Blob,File:TestFile,FormData:TestFormData,ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,
  confirm:()=>true,fetch:async()=>{throw new Error('unexpected fetch');},renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},
  assert,form,zone,list,summary,overlay,modal,events,tick:()=>new Promise(setImmediate)};
vm.createContext(context);vm.runInContext(fs.readFileSync(0,'utf8'),context);
(async()=>{await vm.runInContext(`(async()=>{
  const first={name:'firmware.bin',size:3*1024**3,lastModified:11};
  const second={name:'설명 & payload.zip',size:2048,lastModified:12};
  const duplicate={...first};
  assert.equal(addChallengeFiles(form,[first,second,duplicate]),2);
  assert.equal(selectedChallengeFiles(form).length,2);
  assert.equal(summary.textContent,'2개 · 3.00 GB');
  assert.equal(zone.classList.contains('has-files'),true);
  assert.equal(list.hidden,false);
  assert.ok(list.innerHTML.includes('firmware.bin'));
  assert.ok(list.innerHTML.includes('설명 &amp; payload.zip'));
  assert.ok(formSnapshot(form).includes('__selected_files__'));

  let prevented=0;
  const transfer={types:['Files'],files:[{name:'capture.pcap',size:4096,lastModified:13}],dropEffect:'none'};
  events.dragenter({dataTransfer:transfer,preventDefault(){prevented++;}});
  assert.equal(modal.classList.contains('file-drag-active'),true);
  assert.equal(overlay.attributes['aria-hidden'],'false');
  events.dragover({dataTransfer:transfer,preventDefault(){prevented++;}});
  assert.equal(transfer.dropEffect,'copy');
  events.drop({dataTransfer:transfer,preventDefault(){prevented++;}});
  assert.equal(prevented,3);assert.equal(selectedChallengeFiles(form).length,3);
  assert.equal(modal.classList.contains('file-drag-active'),false);
  assert.equal(overlay.attributes['aria-hidden'],'true');

  const remove={disabled:false,dataset:{action:'remove-challenge-file',index:'1'},closest(){return this;}};
  events.click({target:remove,preventDefault(){}});await tick();
  assert.equal(selectedChallengeFiles(form).length,2);
  assert.equal(selectedChallengeFiles(form)[1].name,'capture.pcap');
  assert.equal(summary.textContent,'2개 · 3.00 GB');

  modal.open=false;
  const ignored={types:['Files'],files:[{name:'ignored',size:1,lastModified:1}]};
  events.drop({dataTransfer:ignored,preventDefault(){throw new Error('closed modal must not capture drop');}});
  assert.equal(selectedChallengeFiles(form).length,2);
})()`,context);console.log('challenge upload picker regressions passed');})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run(
        [node, "-e", harness], input=source, text=True, encoding="utf-8",
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
