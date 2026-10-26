import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ctf_agent.db import Settings, connect, initialize
from ctf_agent.main import create_app


def local_settings(tmp_path, *, auth_mode="nologin"):
    return Settings(
        tmp_path / "data",
        tmp_path / "db",
        tmp_path / "config",
        tmp_path / "logs",
        auth_mode=auth_mode,
    )


def test_auth_mode_setting_defaults_normalizes_and_rejects_invalid(tmp_path, monkeypatch):
    assert local_settings(tmp_path, auth_mode=" PASSWORD ").auth_mode == "password"
    assert local_settings(tmp_path, auth_mode="NoLogin").auth_mode == "nologin"
    with pytest.raises(ValueError, match="CTF_AUTH_MODE"):
        local_settings(tmp_path, auth_mode="disabled")

    monkeypatch.setenv("CTF_AUTH_MODE", "NOLOGIN")
    assert Settings.from_env().auth_mode == "nologin"

    root = Path(__file__).parents[1]
    local_compose = (root / "compose.local.yaml").read_text(encoding="utf-8")
    assert "CTF_AUTH_MODE: ${CTF_AUTH_MODE:-nologin}" in local_compose
    assert "CTF_ALLOW_WEB_BOOTSTRAP: ${CTF_ALLOW_WEB_BOOTSTRAP:-false}" in local_compose


def test_nologin_uses_one_local_owner_without_cookie_and_disables_account_apis(
    tmp_path, monkeypatch,
):
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD", raising=False)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = local_settings(tmp_path)
    initialize(settings)
    with connect(settings) as db:
        owner_id = db.execute(
            "SELECT value FROM meta WHERE key='legacy_owner_id'"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO sessions(token_hash,csrf_token,expires_at,user_id) VALUES(?,?,?,?)",
            ("stale-password-session", "stale-csrf", 4102444800, owner_id),
        )

    app = create_app(settings)
    with TestClient(app) as first:
        state = first.get("/api/auth/state")
        assert state.status_code == 200
        session = state.json()
        assert session["auth_mode"] == "nologin"
        assert session["authentication_required"] is False
        assert session["configured"] is True and session["authenticated"] is True
        assert session["user"]["id"] == owner_id
        assert session["user"]["role"] == "admin"
        assert session["csrf_token"] and session["username"]
        assert first.cookies.get("ctf_session") is None

        # Automatic ownership does not weaken the mutation origin/CSRF gate.
        assert first.post("/api/workspaces", json={"name": "No token"}).status_code == 403
        first.headers["X-CSRF-Token"] = session["csrf_token"]
        assert first.post(
            "/api/workspaces",
            json={"name": "Cross site"},
            headers={"Origin": "https://attacker.invalid"},
        ).status_code == 403
        created = first.post("/api/workspaces", json={"name": "Local CTF"})
        assert created.status_code == 201

        disabled = [
            ("post", "/api/auth/login", {"username": "admin", "password": "anything"}),
            ("post", "/api/auth/logout", None),
            ("post", "/api/auth/password", {"current_password": "x", "new_password": "yyyy"}),
            ("post", "/api/auth/username", {"current_password": "x", "new_username": "new"}),
            ("get", "/api/admin/users", None),
            ("post", "/api/admin/users", {"username": "member", "password": "yyyy"}),
            ("patch", f"/api/admin/users/{owner_id}", {"active": False}),
            ("post", f"/api/admin/users/{owner_id}/password", {"password": "yyyy"}),
        ]
        for method, url, body in disabled:
            response = first.request(method, url, json=body)
            assert response.status_code == 404, (method, url, response.text)

    with connect(settings) as db:
        assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0

    # A separate browser automatically receives the same local owner context.
    with TestClient(app) as second:
        session = second.get("/api/auth/state").json()
        second.headers["X-CSRF-Token"] = session["csrf_token"]
        listing = second.get("/api/workspaces")
        assert listing.status_code == 200
        assert [item["name"] for item in listing.json()["workspaces"]] == ["Local CTF"]


def test_nologin_ui_hides_password_and_user_management_but_keeps_admin_tools():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the browser-independent UI regression")
    source = (
        Path(__file__).parents[1] / "ctf_agent" / "web" / "app.js"
    ).read_text(encoding="utf-8")
    source = source.replace("import {renderAccounts} from './accounts.js';", "")
    source = "\n".join(
        line for line in source.splitlines()
        if not line.startswith("run(async () => { const state = await api('/api/auth/state');")
    )
    harness = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');
function element(){return {open:false,isConnected:true,innerHTML:'',textContent:'',dataset:{},className:'',
  append(){},remove(){},focus(){},select(){},setSelectionRange(){},setAttribute(){},removeAttribute(){},
  querySelector(){return null;},querySelectorAll(){return[];},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}};}
const elements={'#app':element(),'#modal':element(),'#detail':element(),'#content':element(),'#telegram-settings':element()};
const document={querySelector:selector=>elements[selector]||null,getElementById:id=>elements['#'+id]||null,
  addEventListener(){},createElement:()=>element(),body:element(),activeElement:null,execCommand:()=>true};
const context={document,window:{isSecureContext:true,addEventListener(){}},navigator:{},location:{hash:''},history:{replaceState(){}},
  console,Blob,File:class{},FormData:class{},ArrayBuffer,URLSearchParams,Uint8Array,URL,TextEncoder,AbortController,
  crypto:require('node:crypto').webcrypto,confirm:()=>true,fetch:async url=>{
    if(url==='/api/admin/solver-capacity') return {ok:true,status:200,json:async()=>({configured:1,open_jobs:0,recommended:1,hard_max:0,admin_max:0,baseline:1,estimated_web_pids:8,web_pids_limit:0,warning:false,warning_message:''})};
    throw new Error('unexpected fetch: '+url);
  },
  renderAccounts:async()=>{},setTimeout:()=>1,clearTimeout(){},assert,elements};
vm.createContext(context);vm.runInContext(source,context);
const checks=vm.runInContext(`(async()=>{
  authMode='nologin';sessionUser={id:'local-owner',username:'local',role:'admin'};workspaces=[];
  shell('workspaces');
  assert.ok(!elements['#app'].innerHTML.includes('data-action="logout"'));
  renderSettings();
  assert.ok(!elements['#content'].innerHTML.includes('id="username-form"'));
  assert.ok(!elements['#content'].innerHTML.includes('id="password-form"'));
  assert.ok(elements['#content'].innerHTML.includes('id="telegram-settings"'));
  await renderAdmin();
  assert.ok(!elements['#content'].innerHTML.includes('data-action="new-user"'));
  assert.ok(elements['#content'].innerHTML.includes('data-action="cleanup-uploads"'));

  authMode='password';
  renderSettings();
  assert.ok(elements['#content'].innerHTML.includes('id="username-form"'));
  assert.ok(elements['#content'].innerHTML.includes('id="password-form"'));
  shell('workspaces');
  assert.ok(elements['#app'].innerHTML.includes('data-action="logout"'));
})()`,context);
checks.then(()=>console.log('no-login and password UI modes passed')).catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run(
        [node, "-e", harness], input=source, text=True, encoding="utf-8",
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
