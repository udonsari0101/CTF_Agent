import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from ctf_agent.ctfd import CTFdClient, CTFdError, Response
from ctf_agent.ctfd_submit import (
    CTFdSubmitService,
    ConnectionInput,
    MAX_ATTEMPTS,
    register_ctfd_submit,
)
from ctf_agent.db import SCHEMA


class FakeRemote:
    def __init__(self):
        self.validations = 0
        self.submissions = []
        self.outcomes = []
        self.factory_kwargs = []
        self.validation_error = None
        self.on_submit = None
        self.last_submit_client = None

    def factory(self, **kwargs):
        owner = self
        self.factory_kwargs.append(kwargs.copy())

        class Client:
            def __init__(self):
                self.cancel_event = None

            def validate(self):
                owner.validations += 1
                if owner.validation_error:
                    raise owner.validation_error

            def submit(self, challenge_id, flag):
                owner.last_submit_client = self
                owner.submissions.append((challenge_id, flag, kwargs["auth_type"]))
                if owner.on_submit:
                    owner.on_submit()
                outcome = owner.outcomes.pop(0) if owner.outcomes else {"status": "incorrect"}
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

            def clear_credentials(self):
                kwargs["token"] = kwargs["username"] = kwargs["password"] = ""

        return Client()


@pytest.fixture
def api(tmp_path):
    path = tmp_path / "database.sqlite3"

    def connect():
        db = sqlite3.connect(path, timeout=2)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=2000")
        return db

    with connect() as db:
        db.executescript(SCHEMA)
        db.execute("ALTER TABLE workspaces ADD COLUMN owner_user_id TEXT REFERENCES users(id)")
        db.executemany(
            "INSERT INTO users(id,username,password_hash,role,active,created_at) VALUES(?,?,?,'user',1,'now')",
            [("owner-one", "one", "hash"), ("owner-two", "two", "hash")],
        )
        db.executemany(
            "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) VALUES(?,?,'now','now',?)",
            [("workspace-one", "One", "owner-one"), ("workspace-two", "Two", "owner-two")],
        )
        db.executemany(
            """INSERT INTO challenges
               (id,workspace_id,name,status,flag,ctfd_id,ctfd_url,created_at,updated_at)
               VALUES(?,?,?,'flag_found',?,7,'https://ctf.example','now','now')""",
            [
                ("challenge-one", "workspace-one", "First", "flag{one}"),
                ("challenge-two", "workspace-two", "Second", "flag{two}"),
            ],
        )

    app = FastAPI()
    remote = FakeRemote()
    app.state.connect = connect
    app.state.ctfd_client_factory = remote.factory

    def require_auth(request: Request):
        user = {"id": request.headers.get("X-User", "owner-one"), "active": True, "role": "user"}
        request.state.user = user
        return user

    def require_owner(workspace_id, user):
        with connect() as db:
            row = db.execute(
                "SELECT * FROM workspaces WHERE id=? AND owner_user_id=?",
                (workspace_id, user["id"]),
            ).fetchone()
        if not row:
            raise HTTPException(404, "Workspace not found")
        return dict(row)

    app.state.require_workspace_owner = require_owner
    settings = SimpleNamespace(config_dir=tmp_path / "config")
    service = register_ctfd_submit(app, require_auth, settings)
    client = TestClient(app)
    yield client, service, remote, connect, path
    service.stop()
    client.close()


def save_connection(client, workspace="workspace-one", **body):
    payload = {"url": "ctf.example", "auth_type": "token", "token": "top-secret-token"}
    payload.update(body)
    return client.put(f"/api/workspaces/{workspace}/ctfd/connection", json=payload)


def test_legacy_connection_schema_adds_bounded_attempt_policy(tmp_path):
    path = tmp_path / "legacy.sqlite3"

    def open_database():
        database = sqlite3.connect(path)
        database.row_factory = sqlite3.Row
        return database

    with open_database() as database:
        database.executescript(
            """CREATE TABLE ctfd_submit_connections (
                   workspace_id TEXT PRIMARY KEY,
                   owner_user_id TEXT NOT NULL,
                   url TEXT NOT NULL,
                   auth_type TEXT NOT NULL,
                   credentials_ciphertext TEXT NOT NULL,
                   auto_submit INTEGER NOT NULL DEFAULT 0,
                   generation TEXT NOT NULL,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL
               );
               INSERT INTO ctfd_submit_connections VALUES(
                   'workspace','owner','https://ctf.example','token','ciphertext',
                   0,'generation','now','now'
               );"""
        )
    app = FastAPI()
    app.state.connect = open_database
    service = CTFdSubmitService(
        app, SimpleNamespace(config_dir=tmp_path / "config")
    )
    try:
        with open_database() as database:
            columns = {
                row["name"] for row in database.execute(
                    "PRAGMA table_info(ctfd_submit_connections)"
                )
            }
            value = database.execute(
                "SELECT max_attempts FROM ctfd_submit_connections"
            ).fetchone()[0]
        assert "max_attempts" in columns
        assert value == MAX_ATTEMPTS
    finally:
        service.stop()


def enable(client, workspace="workspace-one"):
    return client.put(f"/api/workspaces/{workspace}/ctfd/settings", json={"auto_submit": True})


def job(connect, challenge="challenge-one"):
    with connect() as db:
        row = db.execute(
            "SELECT * FROM ctfd_submit_jobs WHERE challenge_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
            (challenge,),
        ).fetchone()
    return dict(row) if row else None


def test_default_off_and_enabling_requires_a_validated_connection(api):
    client, service, remote, connect, _ = api
    state = client.get("/api/workspaces/workspace-one/ctfd/settings")
    assert state.status_code == 200
    assert state.json() == {"connected": False, "auto_submit": False}
    assert enable(client).status_code == 409
    assert not service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    assert job(connect) is None


def test_inactive_owner_cannot_leave_submission_that_revives_on_reactivation(api):
    client, service, _remote, connect, _ = api
    assert save_connection(client).status_code == 200
    assert enable(client).status_code == 200
    with connect() as db:
        db.execute("UPDATE users SET active=0 WHERE id='owner-one'")

    assert not service.enqueue_flag(
        "owner-one", "workspace-one", "challenge-one", "flag{one}", "agent"
    )
    with connect() as db:
        db.execute("UPDATE users SET active=1 WHERE id='owner-one'")
    assert job(connect) is None


def test_safe_solver_hook_retries_sqlite_failure_but_accepts_disabled_noop(api):
    client, service, _remote, _connect, _ = api
    hook = client.app.state.ctfd_auto_submit_flag
    # Auto-submit is intentionally off, so this is a completed no-op.
    assert hook("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent") is True

    original = service.db

    def unavailable():
        raise sqlite3.OperationalError("fixture database unavailable")

    service.db = unavailable
    try:
        # A storage failure must remain retryable by the durable solver hook.
        assert hook("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent") is False
    finally:
        service.db = original


def test_connection_is_validated_encrypted_and_never_echoes_credentials(api):
    client, service, remote, connect, database_path = api
    response = save_connection(client)
    assert response.status_code == 200, response.text
    assert remote.validations == 1
    body = response.json()
    assert body["connected"] is True and body["auto_submit"] is False
    assert all(
        key not in body for key in ("token", "username", "password", "max_attempts")
    )
    with connect() as db:
        row = dict(db.execute("SELECT * FROM ctfd_submit_connections").fetchone())
    assert row["credentials_ciphertext"].startswith("ctfv1.")
    assert row["max_attempts"] == MAX_ATTEMPTS
    assert "top-secret-token" not in row["credentials_ciphertext"]
    assert b"top-secret-token" not in database_path.read_bytes()


def test_public_connection_save_always_restores_normal_retry_policy(api):
    client, _service, _remote, connect, _ = api
    assert save_connection(client).status_code == 200
    with connect() as database:
        database.execute(
            "UPDATE ctfd_submit_connections SET max_attempts=1 "
            "WHERE workspace_id='workspace-one'"
        )
    assert save_connection(client).status_code == 200
    with connect() as database:
        attempts = database.execute(
            "SELECT max_attempts FROM ctfd_submit_connections "
            "WHERE workspace_id='workspace-one'"
        ).fetchone()[0]
    assert attempts == MAX_ATTEMPTS


def test_saved_connection_builds_owner_scoped_short_lived_import_client(api):
    client, service, remote, connect, _database_path = api
    assert save_connection(client).status_code == 200
    importer = service.client_for_import("workspace-one", {"id": "owner-one"})
    assert remote.factory_kwargs[-1] == {
        "url": "https://ctf.example",
        "auth_type": "token",
        "token": "top-secret-token",
        "username": "",
        "password": "",
    }
    with connect() as db:
        generation = db.execute(
            """SELECT generation FROM ctfd_submit_connections
                WHERE workspace_id='workspace-one' AND owner_user_id='owner-one'"""
        ).fetchone()[0]
    assert importer.saved_connection_generation == generation
    assert service.import_connection_matches(
        "workspace-one",
        "owner-one",
        "https://ctf.example",
        generation,
    )
    assert not service.import_connection_matches(
        "workspace-one",
        "owner-one",
        "https://ctf.example",
        "0" * 32,
    )
    assert save_connection(client).status_code == 200
    with connect() as db:
        replacement = db.execute(
            """SELECT generation FROM ctfd_submit_connections
                WHERE workspace_id='workspace-one' AND owner_user_id='owner-one'"""
        ).fetchone()[0]
    assert replacement != generation
    assert not service.import_connection_matches(
        "workspace-one",
        "owner-one",
        "https://ctf.example",
        generation,
    )
    assert service.import_connection_matches(
        "workspace-one",
        "owner-one",
        "https://ctf.example",
        replacement,
    )
    importer.clear_credentials()
    with pytest.raises(HTTPException) as cross_owner:
        service.client_for_import("workspace-one", {"id": "owner-two"})
    assert cross_owner.value.status_code == 404
    assert client.delete("/api/workspaces/workspace-one/ctfd/connection").status_code == 200
    with pytest.raises(HTTPException) as disconnected:
        service.client_for_import("workspace-one", {"id": "owner-one"})
    assert disconnected.value.status_code == 409


def test_connection_validation_slots_reject_same_owner_before_factory_or_network(api):
    client, service, _remote, connect, _ = api
    with connect() as db:
        db.execute(
            "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) "
            "VALUES('workspace-one-b','One B','now','now','owner-one')"
        )
    entered = threading.Event()
    release = threading.Event()
    calls = []

    class HoldingClient:
        def validate(self):
            entered.set()
            assert release.wait(5)

        def clear_credentials(self):
            return None

    def factory(**_kwargs):
        calls.append("factory")
        return HoldingClient()

    client.app.state.ctfd_client_factory = factory
    payload = ConnectionInput(url="ctf.example", auth_type="token", token="fixture-token")
    outcomes = []
    worker = threading.Thread(
        target=lambda: outcomes.append(
            service.save_connection("workspace-one", {"id": "owner-one"}, payload)
        )
    )
    worker.start()
    assert entered.wait(5)
    try:
        with pytest.raises(HTTPException) as failure:
            service.save_connection("workspace-one-b", {"id": "owner-one"}, payload)
        assert failure.value.status_code == 409
        assert calls == ["factory"]
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert outcomes and outcomes[0]["connected"] is True


def test_connection_validation_slots_reject_fifth_owner_before_factory_or_network(api):
    client, service, _remote, connect, _ = api
    with connect() as db:
        for number in range(3, 6):
            owner = f"owner-{number}"
            db.execute(
                "INSERT INTO users(id,username,password_hash,role,active,created_at) "
                "VALUES(?,?,?,'user',1,'now')",
                (owner, owner, "hash"),
            )
            db.execute(
                "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) "
                "VALUES(?,?,'now','now',?)",
                (f"workspace-{number}", f"Workspace {number}", owner),
            )

    all_entered = threading.Event()
    release = threading.Event()
    call_lock = threading.Lock()
    calls = []

    class HoldingClient:
        def validate(self):
            with call_lock:
                if len(calls) == 4:
                    all_entered.set()
            assert release.wait(5)

        def clear_credentials(self):
            return None

    def factory(**_kwargs):
        with call_lock:
            calls.append("factory")
        return HoldingClient()

    client.app.state.ctfd_client_factory = factory
    payload = ConnectionInput(url="ctf.example", auth_type="token", token="fixture-token")
    outcomes = []
    scopes = [
        ("workspace-one", "owner-one"),
        ("workspace-two", "owner-two"),
        ("workspace-3", "owner-3"),
        ("workspace-4", "owner-4"),
    ]
    workers = [
        threading.Thread(
            target=lambda workspace=workspace, owner=owner: outcomes.append(
                service.save_connection(workspace, {"id": owner}, payload)
            )
        )
        for workspace, owner in scopes
    ]
    for worker in workers:
        worker.start()
    assert all_entered.wait(5)
    try:
        with pytest.raises(HTTPException) as failure:
            service.save_connection("workspace-5", {"id": "owner-5"}, payload)
        assert failure.value.status_code == 429
        assert len(calls) == 4
    finally:
        release.set()
        for worker in workers:
            worker.join(5)
    assert all(not worker.is_alive() for worker in workers)
    assert len(outcomes) == 4


@pytest.mark.parametrize("cancel_scope", ["owner", "workspace"])
def test_rolling_cancellation_stops_connection_validation_before_credentials_continue(api, cancel_scope):
    client, service, _remote, connect, _ = api
    entered = threading.Event()
    stages = []

    class CancellableClient:
        def __init__(self):
            self.cancel_event = None

        def validate(self):
            stages.append("remote-started")
            entered.set()
            deadline = time.monotonic() + 2
            while not self.cancel_event.is_set() and time.monotonic() < deadline:
                time.sleep(.005)
            if self.cancel_event.is_set():
                stages.append("cancelled-before-next-request")
                raise CTFdError("Import cancelled.")
            stages.append("credentials-continued")

        def clear_credentials(self):
            return None

    client.app.state.ctfd_client_factory = lambda **_kwargs: CancellableClient()
    peer = type(service)(service.app, service.settings)
    payload = ConnectionInput(
        url="ctf.example", auth_type="password", username="testuser", password="fixture-password",
    )
    failures = []

    def validate():
        try:
            service.save_connection("workspace-one", {"id": "owner-one"}, payload)
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=validate)
    worker.start()
    assert entered.wait(2)
    owner = {"id": "owner-one", "active": True, "role": "user"}
    try:
        if cancel_scope == "owner":
            with connect() as db:
                db.execute("UPDATE users SET active=0 WHERE id='owner-one'")
            assert peer.cancel_owner("owner-one")
        else:
            assert peer.cancel_workspace("workspace-one", owner)
        worker.join(2)
        assert not worker.is_alive()
        assert failures and isinstance(failures[0], HTTPException)
        assert stages == ["remote-started", "cancelled-before-next-request"]
        with connect() as db:
            assert db.execute(
                "SELECT COUNT(*) FROM ctfd_submit_connections WHERE workspace_id='workspace-one'"
            ).fetchone()[0] == 0
    finally:
        if cancel_scope == "workspace":
            peer.release_delete_block("workspace-one", owner)
        peer.stop()


def test_connection_delete_and_validation_share_workspace_lifecycle_boundary(api):
    client, service, _remote, _connect, _ = api
    entered = threading.Event()
    release = threading.Event()
    gate = threading.Lock()

    class WorkspaceGate:
        @contextmanager
        def try_workspace_lock(self, _workspace_id):
            if not gate.acquire(blocking=False):
                raise HTTPException(409, "workspace busy")
            try:
                yield
            finally:
                gate.release()

    class HoldingClient:
        cancel_event = None

        def validate(self):
            entered.set()
            assert release.wait(5)

        def clear_credentials(self):
            return None

    client.app.state.uploads = WorkspaceGate()
    client.app.state.ctfd_client_factory = lambda **_kwargs: HoldingClient()
    payload = ConnectionInput(url="ctf.example", auth_type="token", token="fixture-token")
    outcomes = []
    worker = threading.Thread(
        target=lambda: outcomes.append(
            service.save_connection("workspace-one", {"id": "owner-one"}, payload)
        )
    )
    worker.start()
    assert entered.wait(2)
    try:
        # DELETE cannot report success while an older validation can still
        # persist credentials after the response.
        response = client.delete("/api/workspaces/workspace-one/ctfd/connection")
        assert response.status_code == 409
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert outcomes and outcomes[0]["connected"] is True
    assert client.delete("/api/workspaces/workspace-one/ctfd/connection").status_code == 200


def test_connection_validation_rechecks_active_owner_before_persisting(api):
    client, service, _remote, connect, _ = api

    class DeactivatingClient:
        cancel_event = None

        def validate(self):
            with connect() as db:
                db.execute("UPDATE users SET active=0 WHERE id='owner-one'")

        def clear_credentials(self):
            return None

    client.app.state.ctfd_client_factory = lambda **_kwargs: DeactivatingClient()
    with pytest.raises(HTTPException) as failure:
        service.save_connection(
            "workspace-one",
            {"id": "owner-one"},
            ConnectionInput(url="ctf.example", auth_type="token", token="fixture-token"),
        )
    assert failure.value.status_code == 404
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM ctfd_submit_connections").fetchone()[0] == 0


def test_password_reconnection_is_encrypted_and_returns_to_off(api):
    client, service, remote, connect, database_path = api
    first = save_connection(
        client,
        auth_type="password",
        token="",
        username="fixture-user",
        password="first-fixture-password",
    )
    assert first.status_code == 200 and first.json()["auth_type"] == "password"
    assert "username" not in first.json() and "password" not in first.json()
    enable(client)
    with connect() as db:
        first_ciphertext = db.execute("SELECT credentials_ciphertext FROM ctfd_submit_connections").fetchone()[0]
    second = save_connection(
        client,
        auth_type="password",
        token="",
        username="fixture-user",
        password="second-fixture-password",
    )
    assert second.status_code == 200 and second.json()["auto_submit"] is False
    with connect() as db:
        second_ciphertext = db.execute("SELECT credentials_ciphertext FROM ctfd_submit_connections").fetchone()[0]
    assert second_ciphertext != first_ciphertext
    raw = database_path.read_bytes()
    assert b"first-fixture-password" not in raw and b"second-fixture-password" not in raw


def test_replacing_submission_connection_requires_explicit_reenable(api):
    client, service, _remote, connect, _ = api
    assert save_connection(client).status_code == 200
    assert enable(client).json()["auto_submit"] is True
    assert service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    replaced = save_connection(client, token="replacement-secret-token")
    assert replaced.status_code == 200
    assert replaced.json()["auto_submit"] is False
    with connect() as db:
        row = db.execute("SELECT status,result_code FROM ctfd_submit_jobs").fetchone()
    assert tuple(row) == ("disabled", "connection_replaced")


def test_replacing_connection_ignores_an_in_flight_old_connection_result(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    entered, release = threading.Event(), threading.Event()

    def block_old_connection():
        entered.set()
        assert release.wait(2)

    remote.on_submit = block_old_connection
    remote.outcomes = [{"status": "correct"}]
    worker = threading.Thread(target=service.process_once)
    worker.start()
    assert entered.wait(2)

    replaced = save_connection(client, token="replacement-secret-token")
    assert replaced.status_code == 200
    assert replaced.json()["auto_submit"] is False
    assert remote.last_submit_client.cancel_event.is_set()
    with connect() as db:
        assert tuple(db.execute("SELECT status,result_code FROM ctfd_submit_jobs").fetchone()) == (
            "disabled", "connection_replaced"
        )
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    with connect() as db:
        challenge = db.execute("SELECT status,completion_source,flag FROM challenges WHERE id='challenge-one'").fetchone()
    assert tuple(challenge) == ("flag_found", None, "flag{one}")


def test_invalid_connection_is_not_stored_and_password_is_not_echoed(api):
    client, service, remote, connect, _ = api
    remote.validation_error = CTFdError("CTFd login failed. Check the username and password.")
    response = save_connection(
        client,
        auth_type="password",
        token="",
        username="fixture-user",
        password="fixture-password",
    )
    assert response.status_code == 400
    assert "fixture-user" not in response.text and "fixture-password" not in response.text
    assert "CTFd 인증에 실패" in response.json()["detail"]
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM ctfd_submit_connections").fetchone()[0] == 0


def test_owner_isolation_applies_to_every_management_endpoint(api):
    client, service, remote, connect, _ = api
    headers = {"X-User": "owner-two"}
    for method, suffix, payload in (
        (client.get, "connection", None),
        (client.get, "settings", None),
        (client.get, "submissions", None),
        (client.put, "settings", {"auto_submit": True}),
        (client.delete, "connection", None),
    ):
        kwargs = {"headers": headers}
        if payload is not None:
            kwargs["json"] = payload
        assert method(f"/api/workspaces/workspace-one/ctfd/{suffix}", **kwargs).status_code == 404


def test_opt_in_queue_deduplicates_and_correct_marks_local_solved(api):
    client, service, remote, connect, _ = api
    assert save_connection(client).status_code == 200
    assert enable(client).json()["auto_submit"] is True
    assert service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    assert not service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    remote.outcomes = [{"status": "correct", "message": "accepted"}]
    assert service.process_once()
    assert remote.submissions == [(7, "flag{one}", "token")]
    record = job(connect)
    assert record["status"] == "correct" and record["attempts"] == 1
    with connect() as db:
        challenge = db.execute(
            "SELECT status,completion_source,flag FROM challenges WHERE id='challenge-one'"
        ).fetchone()
    assert tuple(challenge) == ("solved", "agent", "flag{one}")


def test_incorrect_is_never_retried_and_preserves_flag(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "manual")
    remote.outcomes = [{"status": "incorrect", "message": "Nope"}, {"status": "correct"}]
    service.process_once()
    assert not service.process_once()
    assert len(remote.submissions) == 1
    record = job(connect)
    assert record["status"] == "incorrect" and record["attempts"] == 1
    assert "자동으로 다시 제출하지 않습니다" in record["display_message"]
    with connect() as db:
        challenge = db.execute("SELECT status,flag FROM challenges WHERE id='challenge-one'").fetchone()
    assert tuple(challenge) == ("flag_found", "flag{one}")


def test_network_errors_retry_only_to_the_bounded_limit(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    remote.outcomes = [CTFdError("The remote request failed or timed out.") for _ in range(MAX_ATTEMPTS)]
    for attempt in range(MAX_ATTEMPTS):
        assert service.process_once()
        with connect() as db:
            db.execute("UPDATE ctfd_submit_jobs SET next_attempt_at=0 WHERE status='retry'")
    assert not service.process_once()
    record = job(connect)
    assert record["status"] == "network_error"
    assert record["attempts"] == MAX_ATTEMPTS
    assert len(remote.submissions) == MAX_ATTEMPTS


def test_registration_recovers_interrupted_jobs_without_exceeding_retry_limit(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    claimed = service._claim()
    assert claimed and claimed["attempts"] == 1
    restarted = type(service)(service.app, service.settings)
    # Construction alone cannot distinguish an abandoned claim from a live
    # rolling peer. Recovery happens only after owning the global worker lease.
    assert job(connect)["status"] == "running"
    remote.outcomes = [{"status": "incorrect"}]
    assert restarted.process_once()
    assert job(connect)["status"] == "incorrect"
    assert len(remote.submissions) == 1
    with connect() as db:
        db.execute(
            "UPDATE ctfd_submit_jobs SET status='running',attempts=?",
            (MAX_ATTEMPTS,),
        )
    restarted_again = type(service)(service.app, service.settings)
    assert job(connect)["status"] == "running"
    assert not restarted_again.process_once()
    record = job(connect)
    assert record["status"] == "network_error"
    assert record["result_code"] == "worker_interrupted"
    restarted.stop()
    restarted_again.stop()


def test_single_attempt_policy_never_retries_an_abandoned_claim(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    with connect() as database:
        database.execute(
            "UPDATE ctfd_submit_connections SET max_attempts=1 "
            "WHERE workspace_id='workspace-one'"
        )
    enable(client)
    service.enqueue_flag(
        "owner-one", "workspace-one", "challenge-one", "flag{one}"
    )
    claimed = service._claim()
    assert claimed and claimed["attempts"] == MAX_ATTEMPTS
    history = client.get("/api/workspaces/workspace-one/ctfd/submissions").json()
    assert history["submissions"][0]["attempts"] == 1

    restarted = type(service)(service.app, service.settings)
    try:
        assert not restarted.process_once()
        record = job(connect)
        assert record["status"] == "network_error"
        assert record["attempts"] == MAX_ATTEMPTS
        assert remote.submissions == []
    finally:
        restarted.stop()


def test_tampered_or_cross_scope_credentials_never_reach_network(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    with connect() as db:
        value = db.execute("SELECT credentials_ciphertext FROM ctfd_submit_connections").fetchone()[0]
        db.execute(
            "UPDATE ctfd_submit_connections SET credentials_ciphertext=?",
            (value[:-1] + ("A" if value[-1] != "A" else "B"),),
        )
    service.process_once()
    assert remote.submissions == []
    assert job(connect)["status"] == "auth_error"


def test_ciphertext_copied_to_another_owner_scope_cannot_be_used(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    headers = {"X-User": "owner-two"}
    connected = client.put(
        "/api/workspaces/workspace-two/ctfd/connection",
        headers=headers,
        json={"url": "ctf.example", "auth_type": "token", "token": "owner-two-token"},
    )
    assert connected.status_code == 200
    assert client.put(
        "/api/workspaces/workspace-two/ctfd/settings",
        headers=headers,
        json={"auto_submit": True},
    ).status_code == 200
    with connect() as db:
        owner_one_ciphertext = db.execute(
            "SELECT credentials_ciphertext FROM ctfd_submit_connections WHERE workspace_id='workspace-one'"
        ).fetchone()[0]
        db.execute(
            "UPDATE ctfd_submit_connections SET credentials_ciphertext=? WHERE workspace_id='workspace-two'",
            (owner_one_ciphertext,),
        )
    assert service.enqueue_flag("owner-two", "workspace-two", "challenge-two", "flag{two}")
    service.process_once()
    assert remote.submissions == []
    assert job(connect, "challenge-two")["status"] == "auth_error"


def test_changed_flag_supersedes_old_job_without_submitting(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    with connect() as db:
        db.execute("UPDATE challenges SET flag='flag{new}' WHERE id='challenge-one'")
    service.process_once()
    assert remote.submissions == []
    assert job(connect)["status"] == "superseded"


def test_network_call_holds_no_sqlite_write_lock(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")

    def write_during_submit():
        with connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO meta(key,value) VALUES('network-lock-check','ok')")

    remote.on_submit = write_during_submit
    remote.outcomes = [{"status": "incorrect"}]
    service.process_once()
    with connect() as db:
        assert db.execute("SELECT value FROM meta WHERE key='network-lock-check'").fetchone()[0] == "ok"


def test_simultaneous_workers_claim_a_job_once(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    entered = threading.Event()
    release = threading.Event()

    def block():
        entered.set()
        assert release.wait(2)

    remote.on_submit = block
    remote.outcomes = [{"status": "incorrect"}]
    first = threading.Thread(target=service.process_once)
    first.start()
    assert entered.wait(2)
    peer = type(service)(service.app, service.settings)
    try:
        # A rolling replacement neither recovers nor rewrites a live claim,
        # and cannot enter the remote submission boundary concurrently.
        assert job(connect)["status"] == "running"
        assert peer.process_once() is False
        peer.stop()
        assert job(connect)["status"] == "running"
        release.set()
        first.join(2)
        assert len(remote.submissions) == 1
        assert job(connect)["attempts"] == 1
    finally:
        release.set()
        first.join(2)
        peer.stop()


def test_other_users_connection_toggle_does_not_wait_for_unrelated_remote_claim(api):
    client, service, remote, _connect, _ = api
    assert save_connection(client).status_code == 200
    assert enable(client).status_code == 200
    other_headers = {"X-User": "owner-two"}
    assert client.put(
        "/api/workspaces/workspace-two/ctfd/connection",
        headers=other_headers,
        json={"url": "ctf.example", "auth_type": "token", "token": "owner-two-token"},
    ).status_code == 200
    assert client.put(
        "/api/workspaces/workspace-two/ctfd/settings",
        headers=other_headers,
        json={"auto_submit": True},
    ).status_code == 200
    assert service.enqueue_flag(
        "owner-two", "workspace-two", "challenge-two", "flag{two}", "agent",
    )
    entered, release = threading.Event(), threading.Event()

    def block():
        entered.set()
        assert release.wait(2)

    remote.on_submit = block
    worker = threading.Thread(target=service.process_once)
    worker.start()
    assert entered.wait(2)
    try:
        started = time.monotonic()
        response = client.put(
            "/api/workspaces/workspace-one/ctfd/settings",
            json={"auto_submit": False},
        )
        assert response.status_code == 200
        assert time.monotonic() - started < .5
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()


def test_shutdown_requeues_in_flight_work_and_ignores_its_late_result(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    entered = threading.Event()

    def wait_for_shutdown():
        entered.set()
        assert service.stop_event.wait(2)

    remote.on_submit = wait_for_shutdown
    remote.outcomes = [{"status": "correct"}]
    service.start()
    assert entered.wait(2)
    service.stop()
    assert service.worker is None
    assert remote.last_submit_client.cancel_event.is_set()
    record = job(connect)
    assert record["status"] == "retry"
    assert record["result_code"] == "worker_stopping"
    assert "다음 시작 때 다시 시도" in record["display_message"]
    with connect() as db:
        challenge = db.execute("SELECT status,completion_source FROM challenges WHERE id='challenge-one'").fetchone()
    assert tuple(challenge) == ("flag_found", None)


def test_disabling_submission_ignores_an_in_flight_result(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    entered, release = threading.Event(), threading.Event()

    def block():
        entered.set()
        assert release.wait(2)

    remote.on_submit = block
    remote.outcomes = [{"status": "correct"}]
    worker = threading.Thread(target=service.process_once)
    worker.start()
    assert entered.wait(2)
    response = client.put(
        "/api/workspaces/workspace-one/ctfd/settings",
        json={"auto_submit": False},
    )
    assert response.status_code == 200 and response.json()["auto_submit"] is False
    release.set()
    worker.join(2)
    assert job(connect)["status"] == "disabled"
    with connect() as db:
        assert db.execute("SELECT status FROM challenges WHERE id='challenge-one'").fetchone()[0] == "flag_found"


def test_challenge_delete_cancellation_disables_queue_and_blocks_racing_new_flag(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    assert service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    user = {"id": "owner-one", "active": True, "role": "user"}
    assert service.cancel_challenge("workspace-one", "challenge-one", user)
    record = job(connect)
    assert record["status"] == "disabled" and record["result_code"] == "challenge_deleting"
    with connect() as db:
        db.execute("UPDATE challenges SET flag='flag{raced}' WHERE id='challenge-one'")
    assert not service.enqueue_flag(
        "owner-one", "workspace-one", "challenge-one", "flag{raced}", "agent"
    )
    assert not service.process_once()
    assert remote.submissions == []
    service.release_delete_block(
        "workspace-one", user, challenge_id="challenge-one",
    )
    assert service.enqueue_flag(
        "owner-one", "workspace-one", "challenge-one", "flag{raced}", "agent"
    )


def test_workspace_delete_cancellation_is_owner_scoped_and_turns_connection_off(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    other = {"id": "owner-two", "active": True, "role": "user"}
    with pytest.raises(HTTPException, match="Workspace not found"):
        service.cancel_workspace("workspace-one", other)
    assert job(connect)["status"] == "queued"
    owner = {"id": "owner-one", "active": True, "role": "user"}
    assert service.cancel_workspace("workspace-one", owner)
    assert service.connection_state("workspace-one", owner)["auto_submit"] is False
    assert job(connect)["result_code"] == "workspace_deleting"
    with connect() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_submit_blocks WHERE workspace_id='workspace-one'"
        ).fetchone()[0] == 1
    service.release_delete_block("workspace-one", owner)
    with connect() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_submit_blocks WHERE workspace_id='workspace-one'"
        ).fetchone()[0] == 0


def test_challenge_delete_cancels_and_waits_for_cooperative_in_flight_client(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    entered = threading.Event()

    def wait_for_cancellation():
        entered.set()
        deadline = time.monotonic() + 2
        while not remote.last_submit_client.cancel_event.is_set() and time.monotonic() < deadline:
            time.sleep(.005)
        assert remote.last_submit_client.cancel_event.is_set()

    remote.on_submit = wait_for_cancellation
    remote.outcomes = [{"status": "correct"}]
    worker = threading.Thread(target=service.process_once)
    worker.start()
    assert entered.wait(2)
    owner = {"id": "owner-one", "active": True, "role": "user"}
    peer = type(service)(service.app, service.settings)
    try:
        assert peer.cancel_challenge("workspace-one", "challenge-one", owner)
        worker.join(2)
        assert not worker.is_alive()
        assert job(connect)["status"] == "disabled"
        with connect() as db:
            challenge = db.execute(
                "SELECT status,completion_source,flag FROM challenges WHERE id='challenge-one'"
            ).fetchone()
        assert tuple(challenge) == ("flag_found", None, "flag{one}")
    finally:
        peer.release_delete_block(
            "workspace-one", owner, challenge_id="challenge-one",
        )
        peer.stop()


def test_delete_cancellation_times_out_for_uncooperative_client_then_finishes_safely(api):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}", "agent")
    entered, release = threading.Event(), threading.Event()

    def ignore_cancellation_temporarily():
        entered.set()
        assert release.wait(2)

    remote.on_submit = ignore_cancellation_temporarily
    remote.outcomes = [{"status": "correct"}]
    worker = threading.Thread(target=service.process_once)
    worker.start()
    assert entered.wait(2)
    owner = {"id": "owner-one", "active": True, "role": "user"}
    started = time.monotonic()
    assert not service.cancel_challenge(
        "workspace-one", "challenge-one", owner, wait_seconds=.03
    )
    assert time.monotonic() - started < .5
    assert job(connect)["status"] == "disabled"
    assert remote.last_submit_client.cancel_event.is_set()
    # A repeated delete request must still see the terminal row's in-memory
    # client and refuse deletion until it has actually unwound.
    assert not service.cancel_challenge(
        "workspace-one", "challenge-one", owner, wait_seconds=.03
    )
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    assert service.cancel_challenge("workspace-one", "challenge-one", owner)
    with connect() as db:
        assert db.execute("SELECT status FROM challenges WHERE id='challenge-one'").fetchone()[0] == "flag_found"


def test_client_posts_json_and_password_session_csrf_token():
    captured = []

    def transport(target, headers, maximum, timeout, deadline, **options):
        captured.append((target.url, headers, options))
        data = {"success": True, "data": {"status": "correct", "message": "ok"}}
        return Response(200, {"content-type": "application/json"}, json.dumps(data).encode())

    client = CTFdClient(
        "https://ctf.example",
        auth_type="password",
        username="user",
        password="password",
        resolver=lambda host, port, **kwargs: [(2, 1, 6, "", ("93.184.216.34", port))],
        transport=transport,
    )
    client.logged_in = True
    client.csrf_nonce = "fixture-csrf"
    result = client.submit(7, "flag{value}")
    assert result["status"] == "correct"
    url, headers, options = captured[0]
    assert url.endswith("/api/v1/challenges/attempt")
    assert headers["Content-Type"] == "application/json"
    assert headers["CSRF-Token"] == "fixture-csrf"
    assert json.loads(options["body"]) == {"challenge_id": 7, "submission": "flag{value}"}


def test_client_reads_authenticated_solved_state_without_mutation():
    captured = []

    def transport(target, headers, maximum, timeout, deadline, **options):
        captured.append((target.url, options))
        data = {"success": True, "data": {"id": 7, "solved_by_me": True}}
        return Response(
            200,
            {"content-type": "application/json"},
            json.dumps(data).encode(),
        )

    client = CTFdClient(
        "https://ctf.example",
        token="fixture-token",
        resolver=lambda host, port, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", port))
        ],
        transport=transport,
    )
    assert client.challenge_solved_by_me(7) is True
    assert captured == [("https://ctf.example/api/v1/challenges/7", {})]


@pytest.mark.parametrize(
    "data",
    [
        {"id": 8, "solved_by_me": True},
        {"id": 7},
        {"id": 7, "solved_by_me": 1},
    ],
)
def test_client_rejects_untrustworthy_solved_state(data):
    def transport(target, headers, maximum, timeout, deadline, **options):
        payload = {"success": True, "data": data}
        return Response(
            200,
            {"content-type": "application/json"},
            json.dumps(payload).encode(),
        )

    client = CTFdClient(
        "https://ctf.example",
        token="fixture-token",
        resolver=lambda host, port, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", port))
        ],
        transport=transport,
    )
    with pytest.raises(CTFdError, match="trustworthy solve state"):
        client.challenge_solved_by_me(7)


def test_client_never_accepts_a_status_from_an_unsuccessful_response():
    def transport(target, headers, maximum, timeout, deadline, **options):
        payload = {"success": False, "data": {"status": "correct", "message": "forged"}}
        return Response(200, {"content-type": "application/json"}, json.dumps(payload).encode())

    client = CTFdClient(
        "https://ctf.example",
        token="fixture-token",
        resolver=lambda host, port, **kwargs: [(2, 1, 6, "", ("93.184.216.34", port))],
        transport=transport,
    )
    with pytest.raises(CTFdError, match="unsupported response"):
        client.submit(7, "flag{value}")


@pytest.mark.parametrize(
    "http_status,ctfd_status",
    [
        (200, "correct"),
        (200, "incorrect"),
        (200, "already_solved"),
        (403, "authentication_required"),
        (403, "paused"),
        (429, "ratelimited"),
    ],
)
def test_client_preserves_supported_real_ctfd_attempt_statuses(http_status, ctfd_status):
    def transport(target, headers, maximum, timeout, deadline, **options):
        payload = {"success": True, "data": {"status": ctfd_status, "message": "fixture"}}
        return Response(http_status, {"content-type": "application/json"}, json.dumps(payload).encode())

    client = CTFdClient(
        "https://ctf.example",
        token="fixture-token",
        resolver=lambda host, port, **kwargs: [(2, 1, 6, "", ("93.184.216.34", port))],
        transport=transport,
    )
    assert client.submit(7, "flag{value}")["status"] == ctfd_status


@pytest.mark.parametrize(
    "remote_status,local_status",
    [
        ("already_solved", "already_solved"),
        ("ratelimited", "rate_limited"),
        ("authentication_required", "auth_error"),
        ("paused", "paused"),
    ],
)
def test_safe_remote_status_mapping(api, remote_status, local_status):
    client, service, remote, connect, _ = api
    save_connection(client)
    enable(client)
    service.enqueue_flag("owner-one", "workspace-one", "challenge-one", "flag{one}")
    remote.outcomes = [{"status": remote_status, "message": "remote detail"}]
    service.process_once()
    record = job(connect)
    assert record["status"] == local_status
    assert any("가" <= char <= "힣" for char in record["display_message"])
