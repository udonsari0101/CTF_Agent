import hashlib
import os
import threading
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from ctf_agent.db import connect
from ctf_agent.main import create_app
from ctf_agent.uploads import CHUNK_BYTES, EXPIRY_SECONDS, MAX_ACTIVE_UPLOADS_PER_USER, UploadInit
from test_workspace import PASSWORD, base, challenge, web, workspace
from test_multiuser import add_user, sign_in


def start(client, route, content, name='original.bin'):
    response = client.post(route+'/uploads',json={'name':name,'size':len(content),'sha256':hashlib.sha256(content).hexdigest(),'last_modified':1234})
    assert response.status_code == 201
    return response.json()


def put(client, upload_id, offset, content):
    return client.put(f'/api/uploads/{upload_id}/chunks',params={'offset':offset},content=content,headers={'Content-Type':'application/octet-stream'})


def test_chunk_idempotency_out_of_order_integrity_and_range_download(web):
    client, _, _ = web
    area = workspace(client)
    item = challenge(client,area['id'])
    route = base(area['id'],item['id'])
    content = b'0123456789abcdef'*1000
    upload = start(client,route,content,'원본 데이터.bin')
    assert client.app.state.storage_budget.snapshot(kind='upload') == []
    assert put(client,upload['id'],1,b'wrong').status_code == 409
    first = content[:4000]
    assert put(client,upload['id'],0,first).json()['offset'] == 4000
    assert put(client,upload['id'],0,first).json()['offset'] == 4000
    assert put(client,upload['id'],0,b'wrong').status_code == 409
    manifest = client.get(f"/api/uploads/{upload['id']}/chunks").json()['chunks']
    assert manifest == [{'offset':0,'size':4000,'sha256':hashlib.sha256(first).hexdigest()}]
    assert client.post(f"/api/uploads/{upload['id']}/finalize").status_code == 409
    assert put(client,upload['id'],4000,content[4000:]).status_code == 200
    finalized = client.post(f"/api/uploads/{upload['id']}/finalize").json()
    assert finalized['status'] == 'completed' and finalized['sha256'] == hashlib.sha256(content).hexdigest()
    assert client.post(f"/api/uploads/{upload['id']}/finalize").json() == finalized
    files = client.get(route).json()['attachments']
    assert len(files) == 1 and files[0]['id'] == finalized['attachment_id']
    downloaded = client.get(route+'/attachments/'+files[0]['id'],headers={'Range':'bytes=3-10'})
    assert downloaded.status_code == 206 and downloaded.content == content[3:11]
    assert downloaded.headers['content-range'] == f'bytes 3-10/{len(content)}'
    assert client.app.state.storage_budget.snapshot(kind='upload') == []
    assert client.get(route+'/attachments/'+files[0]['id'],headers={'Range':f'bytes={len(content)+1}-'}).status_code == 416


def test_duplicate_finalize_is_rejected_before_waiting_on_workspace_lock(web, monkeypatch):
    client, app, _ = web
    area = workspace(client)
    item = challenge(client, area['id'])
    route = base(area['id'], item['id'])
    content = b'bounded-finalize-test'
    upload = start(client, route, content)
    assert put(client, upload['id'], 0, content).status_code == 200
    manager = app.state.uploads
    original = manager.finalize
    entered, release = threading.Event(), threading.Event()
    first = []

    def blocking_finalize(upload_id, user):
        entered.set()
        assert release.wait(5)
        return original(upload_id, user)

    monkeypatch.setattr(manager, 'finalize', blocking_finalize)

    def run_first():
        first.append(client.post(f"/api/uploads/{upload['id']}/finalize"))

    worker = threading.Thread(target=run_first)
    worker.start()
    assert entered.wait(2)
    before = time.monotonic()
    duplicate = client.post(f"/api/uploads/{upload['id']}/finalize")
    elapsed = time.monotonic() - before
    assert duplicate.status_code == 409 and elapsed < 1
    release.set()
    worker.join(5)
    assert not worker.is_alive() and first[0].status_code == 200


def test_rolling_workspace_delete_cannot_cross_active_upload_writer(web):
    client, app, settings = web
    area = workspace(client)
    item = challenge(client, area['id'])
    route = base(area['id'], item['id'])
    upload = start(client, route, b'rolling-writer')
    entered, release = threading.Event(), threading.Event()

    def hold_writer():
        with app.state.uploads.try_workspace_lock(area['id']):
            entered.set()
            assert release.wait(5)

    worker = threading.Thread(target=hold_writer)
    worker.start()
    assert entered.wait(2)
    resumed_app = create_app(settings)
    try:
        with TestClient(resumed_app) as resumed:
            sign_in(resumed, 'admin')
            started = time.monotonic()
            response = resumed.delete(f"/api/workspaces/{area['id']}")
            assert response.status_code == 409
            assert time.monotonic() - started < 1
            assert resumed.get(f"/api/uploads/{upload['id']}").status_code == 200
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()


def test_finalize_hashing_has_two_global_slots(web):
    _, app, _ = web
    manager = app.state.uploads
    release = threading.Event()
    entered = [threading.Event(), threading.Event()]
    workers = []

    def hold(owner, ready):
        with manager.finalize_slot(owner):
            ready.set()
            assert release.wait(5)

    for index in range(2):
        worker = threading.Thread(target=hold, args=(f'owner-{index}', entered[index]))
        workers.append(worker)
        worker.start()
    assert all(event.wait(2) for event in entered)
    with pytest.raises(HTTPException) as error:
        with manager.finalize_slot('owner-third'):
            pass
    assert error.value.status_code == 429
    release.set()
    for worker in workers:
        worker.join(5)
        assert not worker.is_alive()


def test_upload_resume_survives_new_application_and_uncommitted_tail(web):
    client, _, settings = web
    area = workspace(client)
    item = challenge(client,area['id'])
    route = base(area['id'],item['id'])
    content = b'first-half|second-half'
    upload = start(client,route,content)
    assert put(client,upload['id'],0,content[:11]).status_code == 200
    assert client.app.state.storage_budget.snapshot(kind='upload') == []
    db = connect(settings)
    owner = db.execute('SELECT owner_user_id FROM upload_sessions WHERE id=?',(upload['id'],)).fetchone()[0]
    db.close()
    staged = settings.data_dir/'workspaces'/'.uploads'/owner/(upload['id']+'.part')
    with staged.open('ab') as handle:
        handle.write(b'uncommitted-after-crash'); handle.flush(); os.fsync(handle.fileno())
    resumed_app = create_app(settings)
    with TestClient(resumed_app) as resumed:
        sign_in(resumed,'admin')
        assert resumed.get(f"/api/uploads/{upload['id']}").json()['offset'] == 11
        assert staged.stat().st_size == 11
        assert resumed_app.state.storage_budget.snapshot(kind='upload') == []
        assert put(resumed,upload['id'],11,content[11:]).status_code == 200
        completed = resumed.post(f"/api/uploads/{upload['id']}/finalize").json()
        assert completed['sha256'] == hashlib.sha256(content).hexdigest()
        assert resumed.get(route+'/attachments/'+completed['attachment_id']).content == content
        assert resumed_app.state.storage_budget.snapshot(kind='upload') == []


def test_finalize_retries_after_atomic_move_before_metadata_commit(web):
    client, _, settings = web
    area = workspace(client)
    item = challenge(client, area['id'])
    route = base(area['id'], item['id'])
    content = b'fully-durable-before-crash'
    upload = start(client, route, content)
    assert put(client, upload['id'], 0, content).status_code == 200
    with connect(settings) as db:
        row = db.execute('SELECT * FROM upload_sessions WHERE id=?', (upload['id'],)).fetchone()
    source = settings.data_dir/'workspaces'/'.uploads'/row['owner_user_id']/(upload['id']+'.part')
    destination = settings.data_dir/'workspaces'/area['id']/'challenges'/item['id']/'attachments'/row['attachment_id']
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)

    resumed_app = create_app(settings)
    with TestClient(resumed_app) as resumed:
        sign_in(resumed, 'admin')
        completed = resumed.post(f"/api/uploads/{upload['id']}/finalize")
        assert completed.status_code == 200, completed.text
        assert completed.json()['sha256'] == hashlib.sha256(content).hexdigest()
        assert resumed.get(route+'/attachments/'+row['attachment_id']).content == content
        assert resumed_app.state.storage_budget.snapshot(kind='upload') == []


def test_cancel_removes_finalize_crash_tail_from_canonical_storage(web):
    client, _, settings = web
    area = workspace(client)
    item = challenge(client, area['id'])
    route = base(area['id'], item['id'])
    content = b'cancel-after-rename'
    upload = start(client, route, content)
    assert put(client, upload['id'], 0, content).status_code == 200
    with connect(settings) as db:
        row = db.execute(
            'SELECT * FROM upload_sessions WHERE id=?', (upload['id'],)
        ).fetchone()
    source = (
        settings.data_dir / 'workspaces' / '.uploads' /
        row['owner_user_id'] / (upload['id'] + '.part')
    )
    destination = (
        settings.data_dir / 'workspaces' / area['id'] / 'challenges' /
        item['id'] / 'attachments' / row['attachment_id']
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)

    resumed_app = create_app(settings)
    with TestClient(resumed_app) as resumed:
        sign_in(resumed, 'admin')
        cancelled = resumed.delete(f"/api/uploads/{upload['id']}")
        assert cancelled.status_code == 200, cancelled.text
    assert not source.exists()
    assert not destination.exists()
    with connect(settings) as db:
        state = db.execute(
            'SELECT status FROM upload_sessions WHERE id=?', (upload['id'],)
        ).fetchone()[0]
        mapping = db.execute(
            "SELECT 1 FROM readable_storage_paths WHERE kind='attachment' AND entity_id=?",
            (row['attachment_id'],),
        ).fetchone()
    assert state == 'cancelled' and mapping is None


def test_idle_huge_declarations_cannot_reserve_volume_and_active_sessions_are_bounded(web, monkeypatch):
    client, app, settings = web
    area = workspace(client)
    item = challenge(client, area['id'])
    with connect(settings) as db:
        owner = db.execute('SELECT owner_user_id FROM workspaces WHERE id=?', (area['id'],)).fetchone()[0]
    budget = app.state.storage_budget
    monkeypatch.setattr(budget, '_free', lambda: budget.minimum_free_bytes + CHUNK_BYTES)
    gate = threading.Barrier(2)
    results = []

    def initialize(name):
        gate.wait()
        try:
            results.append(app.state.uploads.create(
                area['id'], item['id'], UploadInit(name=name, size=2**50), {'id': owner}
            ))
        except Exception as exc:
            results.append(exc)

    workers = [threading.Thread(target=initialize, args=(f'{index}.bin',)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(5)
    assert all(not worker.is_alive() for worker in workers) and len(results) == 2
    assert all(isinstance(result, dict) for result in results)
    assert budget.snapshot(kind='upload') == []
    for index in range(2, MAX_ACTIVE_UPLOADS_PER_USER):
        app.state.uploads.create(
            area['id'], item['id'], UploadInit(name=f'{index}.bin', size=2**50), {'id': owner}
        )
    with pytest.raises(HTTPException) as saturated:
        app.state.uploads.create(
            area['id'], item['id'], UploadInit(name='one-too-many.bin', size=1), {'id': owner}
        )
    assert saturated.value.status_code == 429
    # The first real chunk reserves only itself, even though the declared file
    # is much larger. It is consumed as soon as the durable write commits.
    assert app.state.uploads.chunk(results[0]['id'], 0, b'x', {'id': owner})['offset'] == 1
    assert budget.snapshot(kind='upload') == []
    for result in results:
        app.state.uploads.cancel(result['id'], {'id': owner})


def test_new_upload_cannot_race_an_open_solver_snapshot(web, monkeypatch):
    client, app, settings = web
    area = workspace(client)
    item = challenge(client, area['id'])
    route = base(area['id'], item['id'])
    monkeypatch.setattr(
        app.state.solver_jobs,
        'has_open_challenge',
        lambda owner, workspace_id, challenge_id, connection=None: True,
    )

    response = client.post(route + '/uploads', json={'name': 'late.bin', 'size': 1024})
    assert response.status_code == 409
    with connect(settings) as db:
        assert db.execute(
            'SELECT COUNT(*) FROM upload_sessions WHERE workspace_id=? AND challenge_id=?',
            (area['id'], item['id']),
        ).fetchone()[0] == 0


def test_new_upload_transaction_rejects_active_ctfd_refresh(web):
    client, _app, settings = web
    area = workspace(client)
    item = challenge(client, area["id"])
    route = base(area["id"], item["id"])
    with connect(settings) as db:
        owner = db.execute(
            "SELECT owner_user_id FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0]
        db.execute(
            """INSERT INTO ctfd_jobs
               (id,owner_user_id,workspace_id,source_url,auth_type,mode,
                target_challenge_id,status,created_at,updated_at)
               VALUES('refresh-race',?,?,?,'none','refresh',?,'queued',?,?)""",
            (owner, area["id"], "https://ctf.example", item["id"], "now", "now"),
        )

    response = client.post(
        route + "/uploads", json={"name": "late.bin", "size": 1024}
    )
    assert response.status_code == 409
    with connect(settings) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM upload_sessions WHERE challenge_id=?",
            (item["id"],),
        ).fetchone()[0] == 0
        db.execute("UPDATE ctfd_jobs SET status='completed' WHERE id='refresh-race'")
    assert client.post(
        route + "/uploads", json={"name": "after.bin", "size": 1}
    ).status_code == 201


def test_large_sparse_offset_uses_64_bit_offsets_without_allocating_whole_file(web):
    client, _, settings = web
    area = workspace(client)
    item = challenge(client,area['id'])
    route = base(area['id'],item['id'])
    offset = 2**31 + 17
    upload = client.post(route+'/uploads',json={'name':'large-fixture.bin','size':offset+4}).json()
    assert upload['size'] > 2**31
    db = connect(settings)
    row = db.execute('SELECT * FROM upload_sessions WHERE id=?',(upload['id'],)).fetchone()
    staged = settings.data_dir/'workspaces'/'.uploads'/row['owner_user_id']/(upload['id']+'.part')
    with staged.open('r+b') as handle:
        handle.seek(offset-1); handle.write(b'\0')
    with db:
        db.execute('UPDATE upload_sessions SET offset=? WHERE id=?',(offset,upload['id']))
    db.close()
    assert put(client,upload['id'],offset,b'tail').json()['offset'] == offset+4
    with staged.open('rb') as handle:
        handle.seek(offset)
        assert handle.read(4) == b'tail'
    assert client.delete(f"/api/uploads/{upload['id']}").status_code == 200
    assert not staged.exists()


def test_upload_owner_guard_expiry_and_delete_cascade(web):
    client, app, settings = web
    area = workspace(client)
    item = challenge(client,area['id'])
    route = base(area['id'],item['id'])
    upload = start(client,route,b'1234')
    assert put(client,upload['id'],0,b'12').status_code == 200
    add_user(client,'other')
    with TestClient(app) as other:
        sign_in(other,'other')
        assert other.get(f"/api/uploads/{upload['id']}").status_code == 404
        assert other.get(f"/api/uploads/{upload['id']}/chunks").status_code == 404
        assert put(other,upload['id'],2,b'34').status_code == 404
        assert other.post(f"/api/uploads/{upload['id']}/finalize").status_code == 404
        assert other.delete(f"/api/uploads/{upload['id']}").status_code == 404
        assert other.post('/api/admin/uploads/cleanup').status_code == 403
    stale = start(client,route,b'old','stale.bin')
    db = connect(settings)
    with db:
        db.execute('UPDATE upload_sessions SET updated_at=? WHERE id=?',(int(time.time())-EXPIRY_SECONDS-1,stale['id']))
    db.close()
    assert client.post('/api/admin/uploads/cleanup').json()['removed'] == 1
    assert client.get(f"/api/uploads/{upload['id']}").status_code == 200
    assert client.get(f"/api/uploads/{stale['id']}").status_code == 404
    assert client.app.state.storage_budget.snapshot(kind='upload') == []
    assert client.delete(route).status_code == 200
    db = connect(settings)
    assert db.execute('SELECT COUNT(*) FROM upload_sessions WHERE challenge_id=?',(item['id'],)).fetchone()[0] == 0
    assert db.execute('SELECT COUNT(*) FROM upload_chunks WHERE upload_id=?',(upload['id'],)).fetchone()[0] == 0
    db.close()
    assert not list((settings.data_dir/'workspaces'/'.uploads').rglob('*.part'))
    assert client.app.state.storage_budget.snapshot(kind='upload') == []


def test_workspace_delete_reclaims_active_upload_reservation(web):
    client, app, settings = web
    area = workspace(client)
    item = challenge(client, area['id'])
    upload = start(client, base(area['id'], item['id']), b'not-yet-written')
    assert app.state.storage_budget.snapshot(kind='upload') == []
    assert client.delete(f"/api/workspaces/{area['id']}").status_code == 200
    assert app.state.storage_budget.snapshot(kind='upload') == []
    assert not list((settings.data_dir/'workspaces'/'.uploads').rglob('*.part'))


def test_chunk_limit_disk_failure_and_empty_file(web, monkeypatch):
    client, app, settings = web
    area = workspace(client)
    item = challenge(client,area['id'])
    route = base(area['id'],item['id'])
    empty = start(client,route,b'','empty.txt')
    assert client.post(f"/api/uploads/{empty['id']}/finalize").json()['sha256'] == hashlib.sha256(b'').hexdigest()
    data = start(client,route,b'abc')
    response = client.put(f"/api/uploads/{data['id']}/chunks?offset=0",content=(b'x'*1024*1024 for _ in range(CHUNK_BYTES//(1024*1024)+1)),headers={'Content-Type':'application/octet-stream'})
    assert response.status_code == 413
    with connect(settings) as db:
        owner = db.execute('SELECT owner_user_id FROM upload_sessions WHERE id=?', (data['id'],)).fetchone()[0]
    with pytest.raises(HTTPException) as too_large:
        app.state.uploads.chunk(data['id'], 0, b'x' * (CHUNK_BYTES + 1), {'id': owner})
    assert too_large.value.status_code == 413 and '8MiB' in too_large.value.detail
    assert client.get(f"/api/uploads/{data['id']}").json()['offset'] == 0
    monkeypatch.setattr(app.state.storage_budget, '_free', lambda: 0)
    assert put(client,data['id'],0,b'abc').status_code == 507
    assert client.get(f"/api/uploads/{data['id']}").json()['offset'] == 0
