"""Manual-note and generated-write-up separation regressions."""

from __future__ import annotations

import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote

from fastapi.testclient import TestClient

from ctf_agent.db import Settings, connect, initialize
from ctf_agent.main import create_app
from ctf_agent.writeups import (
    GENERATED_WRITEUP_END,
    GENERATED_WRITEUP_START,
    WriteupStore,
    merge_generated_writeup,
    remove_generated_writeup,
)


ROOT = Path(__file__).parents[1]
PASSWORD = "writeup-separation-test-password"


def _login_app(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    settings = Settings(
        tmp_path / "data",
        tmp_path / "database",
        tmp_path / "config",
        tmp_path / "logs",
    )
    app = create_app(settings)
    client = TestClient(app)
    client.__enter__()
    login = client.post("/api/auth/login", json={"password": PASSWORD})
    assert login.status_code == 200
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return client, app, settings, login.json()["user"]["id"]


def test_solver_commit_embeds_writeup_without_replacing_manual_notes(
    tmp_path, monkeypatch
):
    client, app, settings, owner = _login_app(tmp_path, monkeypatch)
    try:
        workspace = client.post("/api/workspaces", json={"name": "Write-up CTF"}).json()
        challenge = client.post(
            f"/api/workspaces/{workspace['id']}/challenges",
            json={"name": '한글/Problem: 1'},
        ).json()
        route = f"/api/workspaces/{workspace['id']}/challenges/{challenge['id']}"
        manual_notes = "# 내 메모\n\n직접 확인한 내용"
        generated = "# Problem 1\n\n## 풀이\n\nGenerated result."
        assert client.put(route + "/notes", json={"content": manual_notes}).status_code == 200

        job_id = "a" * 32
        with connect(settings) as db:
            db.execute(
                "UPDATE challenges SET flag=?,status='flag_found' WHERE id=?",
                ("SARI{separate}", challenge["id"]),
            )
            db.execute(
                """INSERT INTO solver_jobs(
                       id,owner_user_id,workspace_id,challenge_id,account_id,
                       provider,model,reasoning_effort,status,flag,flag_hooked,
                       created_at,updated_at
                   ) VALUES(?,?,?,?,?,'codex','gpt-5.6-sol','high','writing',?,1,?,?)""",
                (
                    job_id,
                    owner,
                    workspace["id"],
                    challenge["id"],
                    "b" * 32,
                    "SARI{separate}",
                    time.time(),
                    time.time(),
                ),
            )
            job = dict(db.execute("SELECT * FROM solver_jobs WHERE id=?", (job_id,)).fetchone())

        event = {
            "protocol": 1,
            "job_id": job_id,
            "sequence": 1,
            "kind": "writeup",
            "flag": "SARI{separate}",
            "writeup_markdown": generated,
            "terminal": False,
            "created_at": time.time(),
        }
        app.state.solver.coordinator._commit_event(job, event)

        notifications = []
        app.state.telegram_writeup_ready = (
            lambda *_args: notifications.append(_args[-1]) or True
        )
        assert app.state.solver._writeup_committed(
            owner, workspace["id"], challenge["id"], generated
        )
        assert notifications == [generated]

        detail = client.get(route)
        assert detail.status_code == 200
        result = detail.json()
        merged_notes = merge_generated_writeup(manual_notes, generated)
        assert result["notes"] == merged_notes
        assert result["notes"].startswith(manual_notes)
        assert GENERATED_WRITEUP_START not in result["notes"]
        assert GENERATED_WRITEUP_END not in result["notes"]
        assert result["writeup_markdown"] == generated
        assert result["has_writeup"] is True
        assert result["completion_source"] == "agent"

        listing = client.get(f"/api/workspaces/{workspace['id']}/challenges").json()
        listed = listing["challenges"][0]
        assert listed["has_writeup"] is True
        assert "writeup_markdown" not in listed

        notes = client.get(route + "/notes/download")
        writeup = client.get(route + "/writeup/download")
        assert notes.text == merged_notes
        assert writeup.text == generated
        assert "한글_Problem_ 1-notes.md" in unquote(
            notes.headers["content-disposition"]
        )
        assert "한글_Problem_ 1-writeup.md" in unquote(
            writeup.headers["content-disposition"]
        )
        assert client.get(route + "/writeup").json()["markdown"] == generated

        with connect(settings) as db:
            db.execute(
                "UPDATE solver_jobs SET status='completed',released_at=? WHERE id=?",
                (time.time(), job_id),
            )
        revised_manual = manual_notes + "\n\n추가 기록"
        saved = client.put(route + "/notes", json={"content": revised_manual})
        assert saved.status_code == 200
        assert saved.json()["notes"] == merge_generated_writeup(
            revised_manual, generated
        )
        revised = client.get(route).json()
        assert revised["notes"] == merge_generated_writeup(revised_manual, generated)
        assert GENERATED_WRITEUP_START not in revised["notes"]
        assert GENERATED_WRITEUP_END not in revised["notes"]
        assert revised["writeup_markdown"] == generated
        assert client.put(
            route + "/notes", json={"content": revised["notes"]}
        ).status_code == 200
        assert client.get(route).json()["notes"] == revised["notes"]
    finally:
        client.__exit__(None, None, None)


def test_legacy_migration_copies_latest_writeup_without_changing_notes(tmp_path):
    settings = Settings(
        tmp_path / "data",
        tmp_path / "database",
        tmp_path / "config",
        tmp_path / "logs",
    )
    initialize(settings)
    timestamp = "2026-09-09T00:00:00+00:00"
    with connect(settings) as db:
        owner = db.execute(
            "SELECT value FROM meta WHERE key='legacy_owner_id'"
        ).fetchone()[0]
        db.execute(
            """INSERT INTO workspaces(
                   id,name,description,created_at,updated_at,owner_user_id
               ) VALUES('workspace','Legacy','','2026-09-09T00:00:00+00:00',?,?)""",
            (timestamp, owner),
        )
        db.execute(
            """INSERT INTO challenges(
                   id,workspace_id,name,notes,status,completion_source,created_at,updated_at
               ) VALUES('challenge','workspace','Legacy challenge',?,'solved','agent',?,?)""",
            ("manual text that must survive", timestamp, timestamp),
        )
        db.execute(
            """CREATE TABLE solver_jobs (
                   id TEXT PRIMARY KEY,
                   workspace_id TEXT NOT NULL,
                   challenge_id TEXT NOT NULL,
                   writeup_markdown TEXT,
                   created_at REAL NOT NULL
               )"""
        )
        db.executemany(
            "INSERT INTO solver_jobs VALUES(?,?,?,?,?)",
            [
                ("old", "workspace", "challenge", "# old", 1.0),
                ("new", "workspace", "challenge", "# newest", 2.0),
            ],
        )

    @contextmanager
    def database():
        connection = connect(settings)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    WriteupStore(database)
    with connect(settings) as db:
        assert db.execute(
            "SELECT notes FROM challenges WHERE id='challenge'"
        ).fetchone()[0] == "manual text that must survive"
        assert db.execute(
            "SELECT markdown FROM challenge_writeups WHERE challenge_id='challenge'"
        ).fetchone()[0] == "# newest"

        db.execute(
            "INSERT INTO solver_jobs VALUES('newer','workspace','challenge','# after rollback',3.0)"
        )
        db.execute(
            "UPDATE challenges SET notes=? WHERE id='challenge'",
            (
                "manual text that must survive\n\n"
                f"{GENERATED_WRITEUP_START}\n# newest\n{GENERATED_WRITEUP_END}",
            ),
        )

    # Re-upgrading picks up the latest result and replaces old implementation
    # markers with the plain Markdown that users download and edit.
    WriteupStore(database)
    with connect(settings) as db:
        row = db.execute(
            """SELECT c.notes,w.markdown FROM challenges c
               JOIN challenge_writeups w ON w.challenge_id=c.id
               WHERE c.id='challenge'"""
        ).fetchone()
        assert tuple(row) == (
            "manual text that must survive\n\n# after rollback",
            "# after rollback",
        )
        assert GENERATED_WRITEUP_START not in row["notes"]
        assert GENERATED_WRITEUP_END not in row["notes"]


def test_generated_note_block_is_idempotent_and_keeps_surrounding_manual_text():
    first = "# 첫 메모\n\n직접 확인한 값"
    trailing = "\n\n# 추가 메모\n\n사용자 기록"
    old_writeup = "# 문제\n\n## 문제 요약\n\n이전 내용"
    new_writeup = "# 문제\n\n## 문제 요약\n\n새 내용"

    embedded = merge_generated_writeup(first, old_writeup) + trailing
    replaced = merge_generated_writeup(embedded, new_writeup, old_writeup)

    assert replaced == merge_generated_writeup(replaced, new_writeup, new_writeup)
    assert replaced.startswith(first)
    assert replaced.endswith(trailing)
    assert old_writeup not in replaced and new_writeup in replaced
    assert GENERATED_WRITEUP_START not in replaced
    assert GENERATED_WRITEUP_END not in replaced
    removed = remove_generated_writeup(replaced, new_writeup)
    assert removed.startswith(first) and removed.endswith(trailing)
    assert new_writeup not in removed


def test_notes_save_cannot_restore_a_stale_generated_block_without_an_artifact(
    tmp_path, monkeypatch
):
    client, _app, _settings, _owner = _login_app(tmp_path, monkeypatch)
    try:
        workspace = client.post("/api/workspaces", json={"name": "Rejected"}).json()
        challenge = client.post(
            f"/api/workspaces/{workspace['id']}/challenges",
            json={"name": "Rejected candidate"},
        ).json()
        route = f"/api/workspaces/{workspace['id']}/challenges/{challenge['id']}"
        stale = (
            "# manual note\n\n"
            f"{GENERATED_WRITEUP_START}\n# rejected write-up\n{GENERATED_WRITEUP_END}"
        )

        saved = client.put(route + "/notes", json={"content": stale})

        assert saved.status_code == 200
        assert saved.json()["notes"] == remove_generated_writeup(stale)
        detail = client.get(route).json()
        assert detail["notes"] == remove_generated_writeup(stale)
        assert detail["has_writeup"] is False
        assert GENERATED_WRITEUP_START not in detail["notes"]
    finally:
        client.__exit__(None, None, None)


def test_concurrent_writeup_delivery_keeps_canonical_artifact_and_notes_copy_equal(
    tmp_path, monkeypatch
):
    client, app, settings, owner = _login_app(tmp_path, monkeypatch)
    try:
        workspace = client.post("/api/workspaces", json={"name": "Concurrent"}).json()
        challenge = client.post(
            f"/api/workspaces/{workspace['id']}/challenges",
            json={"name": "Race"},
        ).json()
        manual = "# 사용자 메모\n\n보존할 분석"
        route = f"/api/workspaces/{workspace['id']}/challenges/{challenge['id']}"
        assert client.put(route + "/notes", json={"content": manual}).status_code == 200
        with connect(settings) as db:
            db.execute(
                """UPDATE challenges SET status='solved',completion_source='agent'
                   WHERE id=?""",
                (challenge["id"],),
            )

        candidates = (
            "# Race\n\n## 문제 요약\n\n첫 번째 결과",
            "# Race\n\n## 문제 요약\n\n두 번째 결과",
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    lambda markdown: app.state.writeups.record_agent_writeup(
                        owner, workspace["id"], challenge["id"], markdown
                    ),
                    candidates,
                )
            )
        assert outcomes == [True, True]

        with connect(settings) as db:
            row = db.execute(
                """SELECT c.notes,w.markdown FROM challenges c
                   JOIN challenge_writeups w ON w.challenge_id=c.id
                   WHERE c.id=?""",
                (challenge["id"],),
            ).fetchone()
        assert row["markdown"] in candidates
        assert row["notes"] == merge_generated_writeup(manual, row["markdown"])
        assert GENERATED_WRITEUP_START not in row["notes"]
        assert GENERATED_WRITEUP_END not in row["notes"]

        assert app.state.writeups.record_agent_writeup(
            "f" * 32, workspace["id"], challenge["id"], "# foreign"
        ) is False
        with connect(settings) as db:
            after = db.execute(
                """SELECT c.notes,w.markdown FROM challenges c
                   JOIN challenge_writeups w ON w.challenge_id=c.id
                   WHERE c.id=?""",
                (challenge["id"],),
            ).fetchone()
        assert tuple(after) == tuple(row)
    finally:
        client.__exit__(None, None, None)


def test_manual_completion_never_creates_or_embeds_agent_writeup(tmp_path, monkeypatch):
    client, _app, _settings, _owner = _login_app(tmp_path, monkeypatch)
    try:
        workspace = client.post("/api/workspaces", json={"name": "Manual"}).json()
        challenge = client.post(
            f"/api/workspaces/{workspace['id']}/challenges",
            json={"name": "Manual solve"},
        ).json()
        route = f"/api/workspaces/{workspace['id']}/challenges/{challenge['id']}"
        manual = "# 직접 풀이\n\n수동으로 완료했다."
        assert client.put(route + "/notes", json={"content": manual}).status_code == 200
        assert client.post(route + "/complete").status_code == 200

        detail = client.get(route).json()
        assert detail["completion_source"] == "manual"
        assert detail["notes"] == manual
        assert detail["has_writeup"] is False
        assert GENERATED_WRITEUP_START not in detail["notes"]
        assert client.get(route + "/writeup").status_code == 404
    finally:
        client.__exit__(None, None, None)


def test_web_reflects_persisted_writeup_without_overwriting_unsaved_editor():
    source = (ROOT / "ctf_agent" / "web" / "app.js").read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line
        for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
const editor={value:'# unsaved manual draft'},saveState={textContent:''},panel={isConnected:true,innerHTML:'',querySelector(){return null;},append(){}};
const element={open:true,isConnected:true,innerHTML:'',append(){},addEventListener(){},setAttribute(){},remove(){},focus(){},select(){},querySelector(){return null;},querySelectorAll(){return[];}};
const document={activeElement:null,body:element,querySelector(selector){if(selector==='#notes-editor')return editor;if(selector==='#notes-save-state')return saveState;if(selector==='#solver-panel')return panel;return element;},getElementById(){return element;},createElement(){return {...element};},addEventListener(){},execCommand(){return true;}};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},location:{hash:''},history:{replaceState(){}},console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,AbortController,crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch:async()=>{throw new Error('unused');},renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,editor,saveState,panel};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{await vm.runInContext(`(async()=>{
  currentWorkspace={id:'workspace'};
  currentChallenge={id:'challenge',workspace_id:'workspace',name:'Manual / Agent',notes:'# saved manual',notes_token:'old',writeup_markdown:'# persisted agent'};
  currentSolverJob=null;
  assert.equal(solverWriteup(),'# persisted agent');
  const idle=solverPanelMarkup(null);
  assert.ok(idle.includes('<strong>write-up</strong>'));
  assert.ok(idle.includes('data-action="copy-solver-writeup"'));
  assert.ok(idle.includes('data-action="download-solver-writeup"'));
  let downloaded='';downloadBlob=(_blob,name)=>{downloaded=name;};downloadNotes();
  assert.equal(downloaded,'Manual _ Agent-notes.md');
  solverContext=()=>true;refreshChallenges=async()=>{};
  let response={flag:'SARI{ui}',status:'solved',completion_source:'agent',notes:'# server manual\\n\\n# new agent',notes_token:'new',writeup_markdown:'# new agent',writeup_updated_at:'now'};
  api=async()=>response;
  const originalEditor=editor.value;
  await syncSolverWriteup({writeup_markdown:'# event agent'},'workspace','challenge',0);
  assert.equal(currentChallenge.notes,response.notes);
  assert.equal(currentChallenge.notes_token,'new');
  assert.equal(editor.value,originalEditor);
  assert.equal(currentChallenge.writeup_markdown,'# new agent');
  assert.ok(saveState.textContent.includes('\uC791\uC131 \uC911\uC778 \uB178\uD2B8\uB294 \uC720\uC9C0'));

  editor.value=currentChallenge.notes;
  response={...response,notes:'# server manual\\n\\n# newest agent',notes_token:'newer',writeup_markdown:'# newest agent'};
  await syncSolverWriteup({writeup_markdown:'# newest agent'},'workspace','challenge',0);
  assert.equal(editor.value,response.notes);
  assert.equal(currentChallenge.notes,response.notes);
  assert.equal(currentChallenge.notes_token,'newer');
  assert.ok(saveState.textContent.includes('\uD480\uC774 \uB178\uD2B8\uC5D0 \uBC18\uC601'));
})()`,context);console.log('write-up UI separation passed');})().catch(error=>{console.error(error);process.exitCode=1;});
"""
    result = subprocess.run(
        ["node", "-e", harness],
        input=source,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
