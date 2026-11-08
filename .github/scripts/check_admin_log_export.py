"""Offline check for the bounded administrator diagnostic archive."""

import io
import gc
import json
import sys
import time
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local_test_client import TestClient
from ctf_agent.db import Settings, connect
from ctf_agent.main import create_app
from ctf_agent.diagnostics import _safe_event, _scrub


def main() -> None:
    with TemporaryDirectory(ignore_cleanup_errors=True) as temp:
        root = Path(temp)
        settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                            storage_min_free_bytes=0, auth_mode="nologin")
        app = create_app(settings)
        with TestClient(app) as client:
            estimate = client.get('/api/admin/logs/preview?hours=24')
            assert estimate.status_code == 200, estimate.text
            assert estimate.json()['solver_events'] == 0
            response = client.get("/api/admin/logs/export")
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"] == "no-store"
            with ZipFile(io.BytesIO(response.content)) as archive:
                names = set(archive.namelist())
                assert {"about.json", "solver-jobs.json", "solver-events.jsonl",
                        "ctfd-submissions.json", "ctfd-imports.json", "logs/web.log"} <= names, names
                assert json.loads(archive.read("solver-jobs.json")) == []
                assert json.loads(archive.read("about.json"))["summary"]["job_limit"] == 10000
            assert client.get('/api/admin/logs/export?hours=0').status_code == 422
            assert client.get('/api/admin/logs/export?workspace_id=bad').status_code == 422
            csrf = client.get('/api/auth/state').json()['csrf_token']
            client.headers['x-csrf-token'] = csrf
            workspace = client.post('/api/workspaces', json={'name':'diagnostic'}).json()['id']
            challenge = client.post(f'/api/workspaces/{workspace}/challenges', json={
                'name':'sample', 'category':'misc', 'description':'offline', 'remote_mode':'none',
            }).json()['id']
            with connect(settings) as db:
                owner = db.execute('SELECT owner_user_id FROM workspaces WHERE id=?', (workspace,)).fetchone()[0]
                job_id = uuid.uuid4().hex
                now = time.time()
                db.execute(
                    """INSERT INTO solver_jobs(id,owner_user_id,workspace_id,challenge_id,
                       account_id,provider,model,reasoning_effort,status,created_at,updated_at)
                       VALUES(?,?,?,?,?,'codex','test','high','completed',?,?)""",
                    (job_id,owner,workspace,challenge,uuid.uuid4().hex,now,now),
                )
                db.execute(
                    'INSERT INTO solver_job_events VALUES(?,?,?,?,?)',
                    (job_id,1,'activity',json.dumps({
                        'kind':'activity','summary':'Bearer sample-secret-1234567890',
                        'flag':'FLAG{hidden}', 'sequence':1,
                    }),now),
                )
                db.execute("""INSERT INTO ctfd_submit_jobs
                    (id,workspace_id,challenge_id,owner_user_id,connection_generation,
                     ctfd_id,flag_digest,completion_source,status,next_attempt_at,
                     created_at,updated_at)
                    VALUES(?,?,?,?,?,7,?,'agent','incorrect',0,?,?)""",
                    (uuid.uuid4().hex,workspace,challenge,owner,'test','a'*64,
                     '2000-01-01T00:00:00+00:00','2000-01-01T00:00:00+00:00'))
                db.execute("""INSERT INTO ctfd_jobs
                    (id,owner_user_id,workspace_id,source_url,auth_type,status,created_at,updated_at)
                    VALUES(?,?,?,'https://ctf.example.org','token','completed',?,?)""",
                    (uuid.uuid4().hex,owner,workspace,
                     '2000-01-01T00:00:00+00:00','2000-01-01T00:00:00+00:00'))
            estimate = client.get(f'/api/admin/logs/preview?workspace_id={workspace}')
            assert estimate.status_code == 200 and estimate.json()['solver_events'] == 1
            assert estimate.json()['ctfd_submissions'] == 0 and estimate.json()['ctfd_imports'] == 0
            archive_response = client.get(
                f'/api/admin/logs/export?workspace_id={workspace}&challenge_id={challenge}'
            )
            assert archive_response.status_code == 200, archive_response.text
            with ZipFile(io.BytesIO(archive_response.content)) as archive:
                events = archive.read('solver-events.jsonl').decode()
                assert 'sample-secret' not in events and 'FLAG{hidden}' not in events
                assert 'redacted credential' in events
                assert len(json.loads(archive.read('solver-jobs.json'))) == 1
                assert not any(name.startswith('logs/') for name in archive.namelist())
        event = _safe_event(json.dumps({
            'kind': 'flag', 'flag': 'FLAG{hidden}', 'summary': 'Authorization: Bearer ctfd_secret123456789',
            'message': 'do not export', 'created_at': 123,
        }))
        assert 'flag' not in event and 'message' not in event
        assert 'flag_sha256' in event and 'ctfd_secret' not in event['summary']
        assert 'SENSITIVE123456' not in _scrub(json.dumps({'token':'SENSITIVE123456'}))
        assert 'SENSITIVE123456' not in _scrub(json.dumps({'nested':json.dumps({'token':'SENSITIVE123456'})}))
        gc.collect()
    with TemporaryDirectory(ignore_cleanup_errors=True) as temp:
        root = Path(temp)
        app = create_app(Settings(root / 'data', root / 'db', root / 'config', root / 'logs',
                                  storage_min_free_bytes=0, auth_mode='password',
                                  allow_web_bootstrap=True))
        with TestClient(app) as admin, TestClient(app) as viewer:
            assert viewer.get('/api/admin/logs/preview').status_code == 401
            setup = admin.post('/api/auth/setup', json={
                'username':'owner', 'password':'pass1234',
            })
            assert setup.status_code == 200, setup.text
            admin.headers['x-csrf-token'] = setup.json()['csrf_token']
            created = admin.post('/api/admin/users', json={
                'username':'viewer', 'password':'pass1234', 'role':'user',
            })
            assert created.status_code == 201, created.text
            login = viewer.post('/api/auth/login', json={
                'username':'viewer', 'password':'pass1234',
            })
            assert login.status_code == 200, login.text
            assert viewer.get('/api/admin/logs/preview').status_code == 403
            assert viewer.get('/api/admin/logs/export').status_code == 403
        gc.collect()
    print("PASS: admin log export archive")


if __name__ == "__main__":
    main()
