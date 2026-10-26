"""Browser-independent workspace resource meter behavior."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_workspace_resource_meter_polls_hides_and_suspends_in_background():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the browser-independent JavaScript regression")
    source = (Path(__file__).parents[1] / "ctf_agent/web/app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const listeners={},store=new Map(),timers=[],cleared=[];
const cpu={textContent:''},memory={textContent:''};
const classes=new Set();
const meter={classList:{contains:value=>classes.has(value),toggle(value,on){on?classes.add(value):classes.delete(value);}},
  querySelector(selector){return selector.includes('cpu')?cpu:selector.includes('memory')?memory:null;}};
const app={innerHTML:''},modal={open:false,close(){},querySelector(){return null;},addEventListener(){}},detail={open:false,close(){},querySelector(){return null;},addEventListener(){}};
const document={visibilityState:'visible',activeElement:null,body:{append(){}},
  querySelector(selector){return selector==='#app'?app:selector==='#modal'?modal:selector==='#detail'?detail:selector==='#workspace-resource-meter'?meter:null;},
  getElementById(){return null;},createElement(){return {remove(){},setAttribute(){},append(){}};},
  addEventListener(name,callback){listeners[name]=callback;}};
const localStorage={getItem:key=>store.has(key)?store.get(key):null,setItem:(key,value)=>store.set(key,value)};
const context={document,window:{isSecureContext:true,addEventListener(name,callback){listeners['window:'+name]=callback;}},localStorage,
  navigator:{},location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,
  URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,renderAccounts:async()=>{},
  fetch:async()=>{throw new Error('unexpected fetch');},setTimeout(callback,delay){timers.push({callback,delay});return timers.length;},
  clearTimeout(id){cleared.push(id);},assert,cpu,memory,meter,classes,store,listeners,timers,cleared,
  tick:()=>new Promise(setImmediate)};
vm.createContext(context);vm.runInContext(fs.readFileSync(0,'utf8'),context);
(async()=>{
  await vm.runInContext(`(async()=>{
    sessionUser={id:'user-one'};currentWorkspace={id:'workspace-one'};
    let requests=0;api=async url=>{requests++;assert.equal(url,'/api/workspaces/workspace-one/resources');return {
      cpu_percent:12.5,memory_percent:25,memory_used_bytes:4294967296,memory_total_bytes:17179869184};};
    startResourcePolling('workspace-one');await tick();
    assert.equal(requests,1);assert.equal(cpu.textContent,'12.5%');assert.equal(memory.textContent,'4.00 GB / 16.0 GB · 25.0%');
    assert.equal(timers.at(-1).delay,5000);
    const button={textContent:'',attributes:{},setAttribute(k,v){this.attributes[k]=v;}};
    toggleResourceMeter(button);
    assert.equal(store.get('ctf-resource-meter-hidden:user-one'),'true');assert.equal(classes.has('hidden'),true);
    assert.equal(button.textContent,'리소스 보기');assert.equal(button.attributes['aria-pressed'],'true');
    toggleResourceMeter(button);await tick();
    assert.equal(store.get('ctf-resource-meter-hidden:user-one'),'false');assert.equal(classes.has('hidden'),false);
    assert.equal(button.textContent,'리소스 숨기기');assert.equal(requests,2);
    document.visibilityState='hidden';listeners.visibilitychange();assert.ok(cleared.length>0);
    const before=requests;document.visibilityState='visible';listeners.visibilitychange();await tick();assert.equal(requests,before+1);
  })()`,context);
  console.log('workspace resource meter regression passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run(
        [node, "-e", harness], input=source, text=True, encoding="utf-8",
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_workspace_resource_meter_has_compact_responsive_styles():
    theme = (Path(__file__).parents[1] / "ctf_agent/web/theme.css").read_text(encoding="utf-8")
    source = (Path(__file__).parents[1] / "ctf_agent/web/app.js").read_text(encoding="utf-8")
    assert 'class="workspace-resource-meter' in source
    assert 'data-action="toggle-resource-meter"' in source
    assert ".workspace-resource-meter > span" in theme
    assert ".workspace-resource-zone { width: 100%" in theme
