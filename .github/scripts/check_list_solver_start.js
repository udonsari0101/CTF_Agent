// Exercise the shipped list-card and detail start handlers with the same
// account/model configuration that the detail panel has already validated.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
  process.argv[2] || path.join(__dirname, '../../ctf_agent/web/app.js'), 'utf8',
);
function section(start, end) {
  return source.slice(source.indexOf(start), source.indexOf(end));
}
const implementation = [
  section('async function startListSolver(', 'async function continueListSolver('),
  section('async function startSolver(', 'async function approveUltraEscalation('),
].join('\n');

async function scenario(configurationReady, provider, confirmNoRemote = false) {
  const calls = [];
  const notices = [];
  let opened = false;
  let refreshes = 0;
  const button = {
    dataset: {workspaceId:'w', id:'c', name:'Example'},
    isConnected: true, disabled: false, textContent:'▶ 풀이 시작',
    attributes: new Set(),
    setAttribute(name) { this.attributes.add(name); },
    removeAttribute(name) { this.attributes.delete(name); },
    hasAttribute(name) { return this.attributes.has(name); },
  };
  const panel = {innerHTML:''};
  const context = {
    currentWorkspace:{id:'w'}, currentChallenge:null, currentSolverJob:null,
    challengeListing:{result:{challenges:[{id:'c',name:'Example'}]}},
    currentSolverEvents:[], currentSolverGuidance:[], solverEventCursor:0,
    solverGuidanceDraft:'', solverListedFlag:'', solverSyncedWriteup:'',
    solverConsoleAgentId:'root', solverConsoleFollowLatest:true,
    solverCollapsedAgentIds:new Set(), solverConsoleCardStates:new Map(),
    solverPollTimer:null, solverRendering:0, startingListSolvers:new Set(),
    solverProvider:provider, solverAccountId:'a'.repeat(32),
    solverModel:provider === 'claude' ? 'claude-opus-4-8' : 'gpt-6-sol',
    solverReasoning:'high', solverServiceTier:null, solverUltracode:false,
    solverSubagentsEnabled:provider === 'codex', solverUltraEscalationMode:'ask',
    i18n:{locale:'en',t:value=>value}, detail:{open:false},
    document:{querySelector:selector=>selector === '#solver-panel' ? panel : null},
    requireNoAttachmentWork:()=>{},
    async openChallenge(id, waitForConfiguration) {
      assert.equal(id,'c'); assert.equal(waitForConfiguration,true);
      opened = true;
      context.currentChallenge = {id:'c',workspace_id:'w',remote_mode:confirmNoRemote ? 'none' : 'unknown'};
      if (confirmNoRemote) context.currentSolverJob = {phase:'needs_input',error:{code:'remote_input_required'},confirm_no_remote_eligible:true};
      context.detail.open = true;
    },
    solverConfigurationReady:()=>configurationReady,
    path:(challengeId,workspaceId)=>`/api/workspaces/${workspaceId}/challenges/${challengeId}`,
    solverIsActive:()=>false,
    solverContext:()=>true,
    solverUltraEscalationEligible:()=>false,
    solverPanelMarkup:()=>'<p>loading</p>',
    normalizeSolverPayload:payload=>payload,
    paintSolver:job=>{ context.currentSolverJob = job; },
    solverJobId:job=>job?.id,
    loadSolverConfiguration:async()=>{},
    refreshChallenges:async()=>{refreshes++;},
    toast:(message,error)=>{notices.push({message,error});},
    async api(url,options) {
      assert.equal(url,'/api/workspaces/w/challenges/c/solver');
      assert.equal(options.method,'POST');
      calls.push(options.body);
      return {job:{id:'j',phase:'completed'}};
    },
  };
  vm.createContext(context);
  vm.runInContext(implementation,context);
  await vm.runInContext(`startListSolver(button,${confirmNoRemote})`,Object.assign(context,{button}));
  return {calls,notices,opened,refreshes,button,context};
}

(async()=>{
  const codex = await scenario(true,'codex');
  assert.equal(codex.opened,true);
  assert.equal(codex.calls.length,1);
  assert.equal(codex.calls[0].account_id,'a'.repeat(32));
  assert.equal(codex.calls[0].model,'gpt-6-sol');
  assert.equal(codex.calls[0].reasoning_effort,'high');
  assert.equal(codex.calls[0].subagents_enabled,true);
  assert.equal(codex.calls[0].writeup_locale,'en');
  assert.equal(codex.refreshes,1);
  assert.equal(codex.button.disabled,false);
  assert.equal(codex.button.attributes.has('aria-busy'),false);

  const claude = await scenario(true,'claude');
  assert.equal(claude.calls.length,1);
  assert.equal(claude.calls[0].provider,'claude');
  assert.equal(claude.calls[0].account_id,'a'.repeat(32));
  assert.equal(claude.calls[0].model,'claude-opus-4-8');
  assert.equal('subagents_enabled' in claude.calls[0],false);

  const missing = await scenario(false,'codex');
  assert.equal(missing.opened,true);
  assert.equal(missing.calls.length,0);
  assert.equal(missing.context.detail.open,true);
  assert.equal(missing.notices.some(notice=>notice.error),true);
  assert.equal(missing.button.disabled,false);
  const offline = await scenario(true,'codex',true);
  assert.equal(offline.calls.length,1);
  assert.equal(offline.calls[0].confirm_no_remote,true);
  console.log('PASS: list start uses validated account/model settings and opens detail on missing configuration');
})().catch(error=>{console.error(error);process.exitCode=1;});
