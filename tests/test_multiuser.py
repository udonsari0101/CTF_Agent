import hashlib
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from ctf_agent.db import Settings, connect
import ctf_agent.main as main_module
from ctf_agent.main import create_app, password_hash
from test_workspace import PASSWORD, base, challenge, web, workspace


def sign_in(client, username, password=PASSWORD):
    response = client.post('/api/auth/login', json={'username': username, 'password': password})
    assert response.status_code == 200
    client.headers['X-CSRF-Token'] = response.json()['csrf_token']
    return response.json()['user']


def add_user(client, username, role='user'):
    response = client.post('/api/admin/users', json={'username': username, 'password': PASSWORD, 'role': role})
    assert response.status_code == 201
    return response.json()


def test_relaxed_password_policy_is_consistent_across_user_flows(tmp_path, monkeypatch):
    short_passwords = {
        "bootstrap": "aaaa",
        "created": "bbbb",
        "changed": "cccc",
        "reset": "dddd",
    }
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", short_passwords["bootstrap"])
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs",
    )
    app = create_app(settings)

    with TestClient(app) as admin:
        sign_in(admin, "admin", short_passwords["bootstrap"])
        too_short = admin.post(
            "/api/admin/users",
            json={"username": "too-short", "password": "bbb"},
        )
        assert too_short.status_code == 422
        assert '"bbb"' not in too_short.text

        created = admin.post(
            "/api/admin/users",
            json={"username": "relaxed-user", "password": short_passwords["created"]},
        )
        assert created.status_code == 201
        user_id = created.json()["id"]

        with TestClient(app) as member:
            sign_in(member, "relaxed-user", short_passwords["created"])
            rejected = member.post(
                "/api/auth/password",
                json={
                    "current_password": short_passwords["created"],
                    "new_password": "ccc",
                },
            )
            assert rejected.status_code == 422
            changed = member.post(
                "/api/auth/password",
                json={
                    "current_password": short_passwords["created"],
                    "new_password": short_passwords["changed"],
                },
            )
            assert changed.status_code == 200

        rejected_reset = admin.post(
            f"/api/admin/users/{user_id}/password", json={"password": "ddd"},
        )
        assert rejected_reset.status_code == 422
        reset = admin.post(
            f"/api/admin/users/{user_id}/password",
            json={"password": short_passwords["reset"]},
        )
        assert reset.status_code == 200

        with TestClient(app) as member:
            sign_in(member, "relaxed-user", short_passwords["reset"])


def test_bootstrap_password_file_removes_only_its_line_ending(tmp_path, monkeypatch):
    bootstrap_file = tmp_path / "bootstrap-password"
    bootstrap_file.write_text(" ab \n", encoding="utf-8")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD", raising=False)
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD_FILE", str(bootstrap_file))
    settings = Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        sign_in(client, "admin", " ab ")


def test_user_ownership_applies_to_every_workspace_route_and_admin_metadata(web):
    admin, app, _ = web
    person = add_user(admin, 'member')
    own = workspace(admin, 'Administrator private')
    item = challenge(admin, own['id'])
    route = base(own['id'], item['id'])
    upload = admin.post(route + '/uploads', json={'name': 'sample.txt', 'size': 6}).json()
    assert admin.put(
        f"/api/uploads/{upload['id']}/chunks?offset=0",
        content=b'sample', headers={'Content-Type': 'application/octet-stream'},
    ).status_code == 200
    attachment = admin.post(f"/api/uploads/{upload['id']}/finalize").json()
    with TestClient(app) as member:
        sign_in(member, 'member')
        assert member.get('/api/workspaces').json()['workspaces'] == []
        area = workspace(member, 'Member private')
        for suffix in ('', '/challenges'):
            assert member.get(f"/api/workspaces/{own['id']}" + suffix).status_code == 404
        for suffix in (
            '', '/notes/download', '/writeup', '/writeup/download',
            '/attachments/' + attachment['id'], '/uploads',
        ):
            assert member.get(route + suffix).status_code == 404
        assert member.patch(route, json={'remote': 'nc public.example 31337'}).status_code == 404
        assert member.post(route + '/complete').status_code == 404
        assert member.patch(route + '/status', json={'status': 'running'}).status_code == 404
        assert member.put(route + '/notes', json={'content': 'wrong'}).status_code == 404
        assert member.post(route + '/attachments', files={'file': ('x', b'x')}).status_code == 404
        assert member.post(route + '/uploads', json={'name': 'x', 'size': 1}).status_code == 404
        assert member.delete(route).status_code == 404
        assert member.delete(f"/api/workspaces/{own['id']}").status_code == 404
        assert member.get('/api/admin/users').status_code == 403
        assert member.post('/api/admin/users', json={'username': 'bad', 'password': PASSWORD}).status_code == 403
        assert admin.get(f"/api/workspaces/{area['id']}").status_code == 404
        assert [row['id'] for row in admin.get('/api/workspaces').json()['workspaces']] == [own['id']]
    summary = admin.get('/api/admin/users').json()['users']
    metadata = next(row for row in summary if row['id'] == person['id'])
    assert metadata['workspace_count'] == 1 and metadata['last_login_at']
    assert not {'password_hash', 'token', 'csrf_token', 'snapshot', 'chat_id'} & set(metadata)


def test_admin_protections_and_disabled_sessions(web):
    admin, app, _ = web
    admin_id = admin.get('/api/auth/state').json()['user']['id']
    assert admin.patch(f'/api/admin/users/{admin_id}', json={'active': False}).status_code == 409
    assert admin.patch(f'/api/admin/users/{admin_id}', json={'role': 'user'}).status_code == 409
    user = add_user(admin, 'ordinary')
    with TestClient(app) as member:
        sign_in(member, 'ordinary')
        assert admin.patch(f"/api/admin/users/{user['id']}", json={'active': False}).status_code == 200
        assert member.get('/api/workspaces').status_code == 401
        assert member.get('/api/accounts').status_code == 401
        assert member.post('/api/auth/login', json={'username': 'ordinary', 'password': PASSWORD}).status_code == 401
        assert admin.patch(f"/api/admin/users/{user['id']}", json={'active': True}).status_code == 200
        assert member.get('/api/workspaces').status_code == 401
        sign_in(member, 'ordinary')
        assert admin.post(f"/api/admin/users/{user['id']}/password", json={'password': 'reset-password-2026'}).status_code == 200
        assert member.get('/api/workspaces').status_code == 401
    assert admin.post('/api/admin/users', json={'username': 'ordinary', 'password': PASSWORD}).status_code == 409
    with TestClient(app) as member:
        assert member.post('/api/auth/login', json={'username': 'ordinary', 'password': PASSWORD}).status_code == 401
        sign_in(member, 'ordinary', 'reset-password-2026')


def test_deactivation_reports_and_retries_an_incomplete_service_barrier(web, monkeypatch):
    admin, app, settings = web
    user = add_user(admin, 'draining-user')
    service = app.state.ctfd_jobs
    original = service.cancel_owner
    monkeypatch.setattr(service, 'cancel_owner', lambda _owner: False)

    response = admin.patch(
        f"/api/admin/users/{user['id']}", json={'active': False},
    )
    assert response.status_code == 503
    with connect(settings) as db:
        assert db.execute(
            "SELECT active FROM users WHERE id=?", (user['id'],)
        ).fetchone()[0] == 0

    monkeypatch.setattr(service, 'cancel_owner', original)
    retry = admin.patch(
        f"/api/admin/users/{user['id']}", json={'active': False},
    )
    assert retry.status_code == 200


def test_username_and_password_change_only_affect_current_user(web):
    admin, app, _ = web
    add_user(admin, 'member')
    with TestClient(app) as one, TestClient(app) as two:
        sign_in(one, 'member')
        sign_in(two, 'member')
        response = one.post('/api/auth/username', json={'current_password': PASSWORD, 'new_username': 'member-renamed'})
        assert response.status_code == 200
        assert two.get('/api/auth/state').json()['username'] == 'member-renamed'
        assert one.post('/api/auth/password', json={'current_password': PASSWORD, 'new_password': 'different-password-2026'}).status_code == 200
        assert two.get('/api/workspaces').status_code == 200
        assert admin.get('/api/workspaces').status_code == 200
        assert one.post('/api/auth/logout').status_code == 200
        assert two.get('/api/workspaces').status_code == 200
        assert one.post(
            '/api/auth/login',
            json={'username': 'member-renamed', 'password': PASSWORD},
        ).status_code == 401
        sign_in(one, 'member-renamed', 'different-password-2026')


def test_atomic_legacy_migration_preserves_password_sessions_workspace_and_unrelated_rows(tmp_path, monkeypatch):
    monkeypatch.setenv('CTF_BOOTSTRAP_PASSWORD', 'must-not-replace-password')
    monkeypatch.setenv('CTF_BOOTSTRAP_USERNAME', 'must-not-rename-existing-admin')
    monkeypatch.delenv('CTF_BOOTSTRAP_PASSWORD_FILE', raising=False)
    settings = Settings(tmp_path/'data', tmp_path/'db', tmp_path/'config', tmp_path/'logs')
    settings.db_dir.mkdir()
    db = sqlite3.connect(settings.database_path)
    db.executescript('''CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,csrf_token TEXT NOT NULL,expires_at INTEGER NOT NULL);
        CREATE TABLE workspaces(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',flag_format TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE untouched_provider_fixture(id TEXT PRIMARY KEY,credential_marker TEXT);''')
    area_id, token, csrf = uuid.uuid4().hex, 'legacy-browser-cookie', 'legacy-csrf-token'
    encoded = password_hash(PASSWORD)
    db.execute("INSERT INTO meta VALUES('admin_password_hash',?)", (encoded,))
    db.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), csrf, int(time.time())+3600))
    db.execute('INSERT INTO workspaces VALUES(?,?,?,?,?,?)', (area_id,'Legacy area','Existing notes','FLAG{}','2026-01-01','2026-01-01'))
    db.execute('INSERT INTO untouched_provider_fixture VALUES(?,?)', ('original-account-id','existing-auth-file-marker'))
    db.commit(); db.close()
    app = create_app(settings)
    with TestClient(app) as client:
        client.cookies.set('ctf_session', token)
        client.headers['X-CSRF-Token'] = csrf
        assert client.get('/api/auth/state').json()['username'] == 'admin'
        assert client.get(f'/api/workspaces/{area_id}').json()['description'] == 'Existing notes'
        assert client.patch(f'/api/workspaces/{area_id}', json={'flag_format':'NEW{}'}).status_code == 200
        sign_in(client, 'admin')
    db = connect(settings)
    owner = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone()[0]
    assert db.execute('SELECT password_hash FROM users WHERE id=?',(owner,)).fetchone()[0] == encoded
    assert db.execute('SELECT owner_user_id FROM workspaces WHERE id=?',(area_id,)).fetchone()[0] == owner
    assert db.execute('SELECT credential_marker FROM untouched_provider_fixture').fetchone()[0] == 'existing-auth-file-marker'
    db.close()
    repeated = create_app(settings)
    with TestClient(repeated) as client:
        sign_in(client, 'admin')
        assert len(client.get('/api/admin/users').json()['users']) == 1


def test_two_simultaneous_writers_cannot_both_replace_same_notes_token(web):
    client, _, _ = web
    area = workspace(client)
    item = challenge(client, area['id'])
    path = base(area['id'],item['id'])
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda value: client.put(path+'/notes',json={'content':value},headers={'If-Match':item['notes_token']}), ['one','two']))
    assert sorted(response.status_code for response in responses) == [200,409]
    assert client.get(path).json()['notes'] in ('one','two')


def test_concurrent_login_burst_cannot_bypass_attempt_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    monkeypatch.setenv("CTF_BOOTSTRAP_USERNAME", "admin")
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")

    guard = threading.Lock()
    activity = {"current": 0, "maximum": 0}

    def deliberately_slow_failure(_password, _encoded):
        # Make all admitted requests overlap after the atomic admission step.
        with guard:
            activity["current"] += 1
            activity["maximum"] = max(activity["maximum"], activity["current"])
        time.sleep(0.15)
        with guard:
            activity["current"] -= 1
        return False

    monkeypatch.setattr(main_module, "password_matches", deliberately_slow_failure)
    app = create_app(settings)
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=20) as executor:
        responses = list(executor.map(
            lambda _: client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "incorrect"},
            ),
            range(20),
        ))

    statuses = [response.status_code for response in responses]
    assert 1 <= statuses.count(401) <= 10
    assert statuses.count(401) + statuses.count(429) == 20
    assert activity["maximum"] <= 2
    with connect(settings) as db:
        assert db.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == 10


def test_authenticated_password_work_is_bounded_without_parking_workers(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    monkeypatch.setenv("CTF_BOOTSTRAP_USERNAME", "admin")
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    original = main_module.password_matches
    guard = threading.Lock()
    release, two_started = threading.Event(), threading.Event()
    activity = {"block": False, "current": 0, "maximum": 0}

    def controlled_verify(raw, encoded):
        if activity["block"]:
            with guard:
                activity["current"] += 1
                activity["maximum"] = max(activity["maximum"], activity["current"])
                if activity["current"] == 2:
                    two_started.set()
            assert release.wait(5)
            with guard:
                activity["current"] -= 1
        return original(raw, encoded)

    monkeypatch.setattr(main_module, "password_matches", controlled_verify)
    app = create_app(settings)
    with TestClient(app) as client:
        sign_in(client, "admin")
        activity["block"] = True
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(
                client.post, "/api/auth/username",
                json={"current_password": PASSWORD, "new_username": "admin"},
            ) for _ in range(16)]
            assert two_started.wait(2)
            time.sleep(.05)
            release.set()
            responses = [future.result() for future in futures]
    statuses = [response.status_code for response in responses]
    assert all(status in (200, 429) for status in statuses)
    assert statuses.count(429) >= 1 and activity["maximum"] == 2


def test_flag_event_commits_before_notification_and_does_not_notify_manual_notes(web):
    client, app, settings = web
    events = []
    def hook(user_id, workspace_id, challenge_id, flag):
        connection = connect(settings)
        try:
            row = connection.execute('SELECT status,flag FROM challenges WHERE id=?',(challenge_id,)).fetchone()
            events.append((row['status'],row['flag'],flag))
        finally:
            connection.close()
        raise RuntimeError('notification transport is unavailable')
    app.state.telegram_flag_found = hook
    area = workspace(client)
    item = challenge(client, area['id'], flag='FLAG{one}')
    assert item['status'] == 'flag_found' and events == [('flag_found','FLAG{one}','FLAG{one}')]
    path = base(area['id'],item['id'])
    assert client.patch(path,json={'flag':'FLAG{one}'}).status_code == 200
    assert len(events) == 1
    assert client.put(path+'/notes',json={'content':'manual note'}).status_code == 200
    assert len(events) == 1
