// List-card starts must not change the operator's current view.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../../ctf_agent/web/app.js'), 'utf8');
const first = source.indexOf('async function startListSolver(');
const last = source.indexOf('async function continueListSolver(', first);
assert.ok(first >= 0 && last > first);

async function scenario({provider='codex', account=true, confirmNoRemote=false, active=false, selectAccount=false}={}) {
  const calls = [];
  const button = {
    dataset:{workspaceId:'w',id:'c',name:'Example'}, isConnected:true,
    disabled:false, textContent:'▶ 풀이 시작', attributes:new Set(),
    setAttribute(name) { this.attributes.add(name); },
    removeAttribute(name) { this.attributes.delete(name); },
    hasAttribute(name) { return this.attributes.has(name); },
  };
  if (selectAccount) button.attributes.add('data-account-selection');
  const context = {
    button, currentWorkspace:{id:'w'}, currentChallenge:null, detail:{open:false},
    startingListSolvers:new Set(), solverProvider:provider,
    sessionUser:{ultra_escalation_default:'ask'}, i18n:{locale:'en',t:value=>value},
    requireNoAttachmentWork:()=>{}, path:(id,w)=>`/api/workspaces/${w}/challenges/${id}`,
    normalizeSolverPayload:payload=>payload, solverIsActive:job=>job?.phase==='running',
    solverRetryConfiguration:()=>null, refreshChallenges:async()=>{}, toast:()=>{},
    openChallenge:async(id)=>{ calls.push({opened:id}); },
    async api(url,options) {
      if (url === '/api/workspaces/w/challenges/c') return {id:'c',workspace_id:'w',remote_mode:confirmNoRemote?'none':'unknown'};
      if (url === '/api/workspaces/w/challenges/c/solver' && !options) {
        if (active) return {job:{phase:'running'}};
        if (confirmNoRemote) return {job:{phase:'needs_input',error:{code:'remote_input_required'},confirm_no_remote_eligible:true}};
        throw {status:404};
      }
      if (url === '/api/accounts') return {accounts:account ? [{id:'a'.repeat(32),provider,snapshot:{status:'authenticated'},selected:true,model:provider==='codex'?'gpt-6-sol':'claude-opus-4-8',reasoning_effort:'high'}] : []};
      if (url === `/api/accounts/${'a'.repeat(32)}/models`) return {status:'available',models:[{model:provider==='codex'?'gpt-6-sol':'claude-opus-4-8',supportedReasoningEfforts:[{reasoningEffort:'high'},{reasoningEffort:'ultra'}]}]};
      assert.equal(url,'/api/workspaces/w/challenges/c/solver');
      assert.equal(options.method,'POST');
      calls.push(options.body);
      return {job:{id:'j',phase:'completed'}};
    },
  };
  vm.createContext(context);
  vm.runInContext(source.slice(first,last),context);
  let error = null;
  try { await vm.runInContext(`startListSolver(button,${confirmNoRemote})`,context); }
  catch (caught) { error = caught; }
  return {calls,button,context,error};
}

(async()=>{
  const codex = await scenario();
  assert.equal(codex.error,null);
  assert.equal(codex.context.detail.open,false);
  assert.equal(codex.context.currentChallenge,null);
  assert.equal(codex.calls.length,1);
  assert.equal(codex.calls[0].model,'gpt-6-sol');
  assert.equal(codex.calls[0].reasoning_effort,'high');
  assert.equal(codex.calls[0].subagents_enabled,false);
  assert.equal(codex.calls[0].writeup_locale,'en');
  assert.equal(codex.button.disabled,false);
  assert.equal(codex.button.attributes.has('aria-busy'),false);
  const claude = await scenario({provider:'claude'});
  assert.equal(claude.error,null);
  assert.equal(claude.context.detail.open,false);
  assert.equal('subagents_enabled' in claude.calls[0],false);
  const missing = await scenario({account:false});
  assert.match(String(missing.error?.message),/계정/);
  assert.equal(missing.calls.length,0);
  assert.equal(missing.context.detail.open,false);
  const offline = await scenario({confirmNoRemote:true});
  assert.equal(offline.calls[0].confirm_no_remote,true);
  const busy = await scenario({active:true});
  assert.equal(busy.calls.length,0);
  const selectAccount = await scenario({selectAccount:true});
  assert.equal(selectAccount.error,null);
  assert.equal(selectAccount.calls.length,1);
  assert.equal(selectAccount.calls[0].opened,'c');
  console.log('PASS: list starts in place with validated account/model defaults');
})().catch(error=>{console.error(error);process.exitCode=1;});
