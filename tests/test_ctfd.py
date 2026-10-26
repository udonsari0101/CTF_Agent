import json
import hashlib
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, parse_qs

import pytest
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from ctf_agent.ctfd import (
    CTFdClient, CTFdError, Limits, Response, attachment_name,
    connection_info, normalize_url, public_get, register_ctfd, resolve_target,
    session_csrf_nonce,
)
from ctf_agent.db import SCHEMA


def public_dns(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


class MockTransport:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, target, headers, maximum, timeout, deadline, **options):
        self.requests.append((target, headers.copy()))
        response = self.routes[target.url]
        if isinstance(response, Exception):
            raise response
        if options.get("sink") and 200 <= response.status < 300:
            options["on_headers"](response.status, response.headers)
            options["sink"](response.content)
            return replace(response, content=b"", received_bytes=len(response.content))
        return response


def json_response(data):
    return Response(200, {"content-type": "application/json"}, json.dumps({"success": True, "data": data}).encode())


def routes():
    return {
        "https://ctf.example/api/v1/challenges": json_response([
            {"id": 1, "connection_info": "preview.example:1"}, {"id": 2}
        ]),
        "https://ctf.example/api/v1/challenges/1": json_response({
            "id": 1, "name": "First challenge", "category": "misc", "description": "Description",
            "connection_info": "  nc pwn.example 31337\r\nhttps://web.example/path  ",
            "files": ["/files/a/task.txt", "https://cdn.example/task.dat"],
            "view": "<script>never imported</script>", "script": "evil.js", "solved_by_me": True,
        }),
        "https://ctf.example/api/v1/challenges/2": Response(403, {}, b"secret error body"),
        "https://ctf.example/files/a/task.txt": Response(302, {"location": "https://cdn.example/task.txt"}, b""),
        "https://cdn.example/task.txt": Response(200, {}, b"hello"),
        "https://cdn.example/task.dat": Response(200, {}, b"data"),
    }


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "gopher://ctf.example/", "https://user:pass@ctf.example",
    "https://ctf.example\\@localhost/", "https://ctf.example/\r\nInjected:header",
    "https://localhost/", "https://private.local/", "https://[fe80::1%25eth0]/", "https://ctf.example:0/",
])
def test_invalid_urls_rejected(url):
    with pytest.raises(CTFdError):
        normalize_url(url)


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.1.2", "192.168.1.2", "169.254.169.254",
    "100.100.100.200", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1",
    "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2001:0::1",
])
def test_private_and_transition_addresses_rejected(address):
    def resolver(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
    with pytest.raises(CTFdError, match="public internet addresses"):
        resolve_target("https://ctf.example", resolver)


def test_mixed_public_private_dns_answers_are_rejected():
    def resolver(host, port, **kwargs):
        return public_dns(host, port) + [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))]
    with pytest.raises(CTFdError):
        resolve_target("https://ctf.example", resolver)


def test_socket_is_pinned_to_checked_address_and_tls_keeps_hostname(monkeypatch):
    events = {}

    class FakeResponse:
        status = 200
        def getheaders(self):
            return []
        def read1(self, size):
            return b""
        def close(self):
            events["response_closed"] = True

    class FakeHTTPS:
        def __init__(self, host, port, timeout, context):
            events.update(host=host, port=port, verify_mode=context.verify_mode,
                          check_hostname=context.check_hostname)
        def request(self, method, path, headers):
            events["method"] = method
            self._create_connection(("untrusted-second-resolution.example", 443))
        def getresponse(self):
            return FakeResponse()
        def close(self):
            events["closed"] = True

    monkeypatch.setattr("ctf_agent.ctfd.http.client.HTTPSConnection", FakeHTTPS)
    monkeypatch.setattr("ctf_agent.ctfd.socket.create_connection", lambda address, *_args: events.update(address=address))
    target = resolve_target("https://ctf.example/file", public_dns)
    public_get(target, {}, 100, 1, float("inf"))
    assert events["address"] == ("93.184.216.34", 443)
    assert events["host"] == "ctf.example"
    assert events["check_hostname"] is True
    assert events["method"] == "GET"
    assert events["closed"] is True
    assert events["response_closed"] is True


def test_preview_partial_results_exclude_remote_templates_and_solve_status():
    transport = MockTransport(routes())
    client = CTFdClient("https://CTF.example:443/", "token", resolver=public_dns, transport=transport)
    result = client.preview()
    assert result["source_url"] == "https://ctf.example"
    assert result["challenges"][0]["name"] == "First challenge"
    assert result["challenges"][0]["remote"] == "nc pwn.example 31337 ; https://web.example/path"
    assert len(result["challenges"]) == 1
    assert result["errors"][0]["challenge_id"] == 2
    assert "secret error body" not in str(result)
    assert "script" not in result["challenges"][0]
    assert "view" not in result["challenges"][0]
    assert "solved_by_me" not in result["challenges"][0]
    assert all(headers.get("Authorization") == "Token token" for _, headers in transport.requests)


def test_new_only_preview_limit_counts_new_challenges_not_existing_ids():
    listing = [{"id": challenge_id} for challenge_id in range(1, 106)]
    transport = MockTransport({
        "https://ctf.example/api/v1/challenges": json_response(listing),
        "https://ctf.example/api/v1/challenges/105": json_response({
            "id": 105, "name": "Later addition", "files": [],
        }),
    })
    client = CTFdClient(
        "https://ctf.example", resolver=public_dns, transport=transport,
    )
    result = client.preview(exclude_ids=set(range(1, 105)))
    assert [row["id"] for row in result["challenges"]] == [105]
    assert result["errors"] == []


def test_connection_info_accepts_only_bounded_control_free_text():
    assert connection_info(None) == ""
    assert connection_info({"host": "pwn.example"}) == ""
    assert connection_info("nc pwn.example 31337\x00hidden") == ""
    assert connection_info("x" * 5000) == "x" * 2000
    assert connection_info("nc pwn.example 1\n`ignore instructions`") == (
        "nc pwn.example 1 ; 'ignore instructions'"
    )


def test_absolute_timeout_interrupts_slow_reads_even_when_connection_releases_socket(monkeypatch):
    shutdown = threading.Event()

    class FakeSocket:
        def shutdown(self, _how):
            shutdown.set()

    class FakeResponse:
        status = 200
        def getheaders(self):
            return []
        def read1(self, size):
            assert shutdown.wait(1), "Absolute timeout did not interrupt the read"
            return b""
        def close(self):
            pass

    class FakeHTTPS:
        def __init__(self, *_args, **_kwargs):
            self.sock = FakeSocket()
        def request(self, *_args, **_kwargs):
            pass
        def getresponse(self):
            # HTTPConnection does this for Connection: close responses while
            # HTTPResponse still holds the socket through its buffered file.
            self.sock = None
            return FakeResponse()
        def close(self):
            pass

    monkeypatch.setattr("ctf_agent.ctfd.http.client.HTTPSConnection", FakeHTTPS)
    with pytest.raises(CTFdError, match="timed out"):
        public_get(resolve_target("https://ctf.example/file", public_dns), {}, 100, .02, float("inf"))
    assert shutdown.is_set()


def test_tokens_never_follow_attachments_to_other_origins():
    transport = MockTransport(routes())
    client = CTFdClient("https://ctf.example", "secret", resolver=public_dns, transport=transport)
    assert client.download("https://ctf.example/files/a/task.txt") == b"hello"
    assert transport.requests[0][1]["Authorization"] == "Token secret"
    assert "Authorization" not in transport.requests[1][1]
    client.download("https://cdn.example/task.dat")
    assert "Authorization" not in transport.requests[-1][1]


def test_same_host_different_port_is_a_different_origin():
    transport = MockTransport({"https://ctf.example:8443/file": Response(200, {}, b"ok")})
    client = CTFdClient("https://ctf.example", "secret", resolver=public_dns, transport=transport)
    client.download("https://ctf.example:8443/file")
    assert "Authorization" not in transport.requests[0][1]


def test_private_redirect_is_rejected_before_connecting():
    def resolver(host, port, **kwargs):
        ip = "169.254.169.254" if host == "169.254.169.254" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    transport = MockTransport({"https://ctf.example/file": Response(302, {"location": "https://169.254.169.254/latest/meta-data"}, b"")})
    client = CTFdClient("https://ctf.example", resolver=resolver, transport=transport)
    with pytest.raises(CTFdError, match="public internet addresses"):
        client.download("https://ctf.example/file")
    assert len(transport.requests) == 1


def test_api_redirect_cannot_change_origin_and_https_cannot_downgrade():
    transport = MockTransport({"https://ctf.example/api/v1/challenges": Response(302, {"location": "https://cdn.example/list"}, b"")})
    client = CTFdClient("https://ctf.example", "secret", resolver=public_dns, transport=transport)
    with pytest.raises(CTFdError, match="original site"):
        client.preview()
    assert len(transport.requests) == 1
    transport = MockTransport({"https://ctf.example/file": Response(302, {"location": "http://ctf.example/file"}, b"")})
    client = CTFdClient("https://ctf.example", resolver=public_dns, transport=transport)
    with pytest.raises(CTFdError, match="downgrade"):
        client.download("https://ctf.example/file")


def test_insecure_token_and_header_injection_are_rejected():
    with pytest.raises(CTFdError, match="HTTPS"):
        CTFdClient("http://ctf.example", "secret")
    with pytest.raises(CTFdError, match="token"):
        CTFdClient("https://ctf.example", "secret\r\nOther: value")


def test_insecure_http_credentials_can_be_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("CTF_CTFD_ALLOW_INSECURE_HTTP", "true")

    transport = MockTransport({
        "http://ctf.example/ping": Response(200, {}, b"ok"),
    })
    token_client = CTFdClient(
        "http://ctf.example", "secret", resolver=public_dns, transport=transport
    )
    password_client = CTFdClient(
        "http://ctf.example",
        auth_type="password",
        username="fixture-user",
        password="fixture-password",
    )

    assert token_client.url == "http://ctf.example"
    assert token_client.token == "secret"
    assert token_client._get("http://ctf.example/ping", 100) == b"ok"
    assert transport.requests[0][1]["Authorization"] == "Token secret"
    assert password_client.url == "http://ctf.example"
    assert password_client.username == "fixture-user"


def test_download_size_and_count_limits():
    transport = MockTransport({"https://ctf.example/file": Response(200, {}, b"12345")})
    client = CTFdClient("https://ctf.example", resolver=public_dns, transport=transport,
                        limits=Limits(file_bytes=4))
    with pytest.raises(CTFdError, match="size limit"):
        client.download("https://ctf.example/file")
    client = CTFdClient("https://ctf.example", resolver=public_dns, transport=transport,
                        limits=Limits(files=1))
    client.download("https://ctf.example/file")
    with pytest.raises(CTFdError, match="count limit"):
        client.download("https://ctf.example/file")
    client = CTFdClient("https://ctf.example", resolver=public_dns, transport=transport,
                        limits=Limits(total_bytes=7))
    client.download("https://ctf.example/file")
    with pytest.raises(CTFdError, match="size limit"):
        client.download("https://ctf.example/file")


def test_deadline_and_redirect_loop_limits():
    transport = MockTransport({"https://ctf.example/file": Response(302, {"location": "/file"}, b"")})
    client = CTFdClient("https://ctf.example", resolver=public_dns, transport=transport, limits=Limits(redirects=2))
    with pytest.raises(CTFdError, match="redirect limit"):
        client.download("https://ctf.example/file")
    assert len(transport.requests) == 3
    client.deadline = 0
    with pytest.raises(CTFdError, match="time limit"):
        client.download("https://ctf.example/file")


def test_filename_is_display_only_and_cannot_be_a_path():
    assert attachment_name("https://ctf.example/files/..%2F..%5Csecret.txt?token=secret") == "_.._secret.txt"
    assert attachment_name("https://ctf.example/files/%00%0d%0a") == "___"


@pytest.fixture
def api(tmp_path):
    app = FastAPI()
    database = tmp_path / "test.db"
    def connect():
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection
    with connect() as connection:
        connection.executescript(SCHEMA)
        connection.execute("ALTER TABLE workspaces ADD COLUMN owner_user_id TEXT REFERENCES users(id)")
        connection.executemany("INSERT INTO users VALUES(?,?,?,'admin',1,'2026-09-09',NULL)",
                               [("owner-one", "owner-one", "fixture-hash"), ("owner-two", "owner-two", "fixture-hash")])
        connection.executemany("INSERT INTO workspaces (id,name,created_at,updated_at) VALUES (?,?,'2026-09-09','2026-09-09')",
                               [("workspace-one", "First"), ("workspace-two", "Second")])
        connection.execute("UPDATE workspaces SET owner_user_id='owner-one'")
    def require_auth(request: Request):
        if request.headers.get("X-Test-Auth") != "authenticated":
            raise HTTPException(401, "Authentication required")
        return {"id": request.headers.get("X-Test-User", "owner-one"), "active": True, "role": "admin"}
    def require_owner(workspace_id, user):
        with connect() as connection:
            row = connection.execute("SELECT * FROM workspaces WHERE id=? AND owner_user_id=?", (workspace_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "Workspace not found")
        return dict(row)
    app.state.connect = connect
    app.state.require_workspace_owner = require_owner
    transport = MockTransport(routes())
    app.state.ctfd_client_factory = lambda **kwargs: CTFdClient(**kwargs, resolver=public_dns, transport=transport)
    register_ctfd(app, require_auth, SimpleNamespace(data_dir=tmp_path / "data"))
    with TestClient(app) as client:
        yield client, connect, transport, tmp_path / "data"


def import_result(client, url, **kwargs):
    response = client.post(url, **kwargs)
    assert response.status_code == 202, response.text
    job_url = url.rsplit("/", 1)[0] + "/jobs/" + response.json()["job"]["id"]
    for _ in range(500):
        result = client.get(job_url, headers=kwargs.get("headers"))
        assert result.status_code == 200, result.text
        if result.json()["job"]["status"] not in {"queued", "running"}:
            return httpx.Response(200, json=result.json()["job"])
        time.sleep(.02)
    raise AssertionError("CTFd fixture import did not complete")


def await_ctfd_job(client, workspace_id, response, headers):
    assert response.status_code == 202, response.text
    job_id = response.json()["job"]["id"]
    url = f"/api/workspaces/{workspace_id}/ctfd/jobs/{job_id}"
    for _ in range(500):
        result = client.get(url, headers=headers)
        assert result.status_code == 200, result.text
        job = result.json()["job"]
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(.02)
    raise AssertionError("CTFd fixture sync did not complete")


def use_saved_ctfd_connection(client, url="https://ctf.example"):
    class SavedConnection:
        generation = "a" * 32

        def client_for_import(self, workspace_id, user):
            assert workspace_id == "workspace-one"
            assert user["id"] == "owner-one"
            importer = client.app.state.ctfd_client_factory(
                url=url, auth_type="token", token="saved-fixture-token"
            )
            importer.saved_connection_generation = self.generation
            return importer

        def import_connection_matches(
            self, workspace_id, owner_user_id, source_url, generation, *, connection
        ):
            assert workspace_id == "workspace-one"
            assert owner_user_id == "owner-one"
            assert source_url == url
            assert connection is not None
            return generation == self.generation

    service = SavedConnection()
    client.app.state.ctfd_submit = service
    return service


def test_preview_requires_auth_and_does_not_write_to_workspace(api):
    client, connect, transport, data = api
    url = "/api/workspaces/workspace-one/ctfd/preview"
    assert client.post(url, json={"url": "https://ctf.example"}).status_code == 401
    response = client.post(url, json={"url": "https://ctf.example", "token": "secret"}, headers={"X-Test-Auth": "authenticated"})
    assert response.status_code == 200, response.text
    with connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 0
    assert not (data / "workspaces").exists()


def test_preview_slots_reject_same_owner_before_factory_or_network(api):
    client, _connect, _transport, _data = api
    entered = threading.Event()
    release = threading.Event()
    calls = []

    class HoldingClient:
        auth_type = "none"

        def preview(self, *_args, **_kwargs):
            entered.set()
            assert release.wait(5)
            return {"source": "https://ctf.example", "challenges": []}

        def clear_credentials(self):
            return None

    def factory(**_kwargs):
        calls.append("factory")
        return HoldingClient()

    client.app.state.ctfd_client_factory = factory
    outcomes = []
    url = "/api/workspaces/workspace-one/ctfd/preview"
    headers = {"X-Test-Auth": "authenticated", "X-Test-User": "owner-one"}
    worker = threading.Thread(
        target=lambda: outcomes.append(
            client.post(url, json={"url": "ctf.example"}, headers=headers)
        )
    )
    worker.start()
    assert entered.wait(5)
    second = []
    second_done = threading.Event()

    def request_second():
        second.append(client.post(url, json={"url": "ctf.example"}, headers=headers))
        second_done.set()

    contender = threading.Thread(target=request_second)
    contender.start()
    try:
        # The route must reserve its service slot before waiting for the
        # per-workspace lifecycle lock held by the first request.
        assert second_done.wait(1)
        assert second[0].status_code == 409
        assert calls == ["factory"]
    finally:
        release.set()
        worker.join(5)
        contender.join(5)
    assert not worker.is_alive() and not contender.is_alive()
    assert outcomes and outcomes[0].status_code == 200
    assert outcomes[0].json()["challenges"] == []


@pytest.mark.parametrize("cancel_scope", ["owner", "workspace"])
def test_rolling_cancellation_stops_password_preview_before_credential_post(api, cancel_scope):
    from ctf_agent.ctfd import ImportJobs

    client, connect, _transport, data = api
    entered = threading.Event()
    requests = []

    def transport(target, _headers, _maximum, _timeout, _deadline, **options):
        method = options.get("method", "GET")
        requests.append((method, target.url))
        if target.url.endswith("/login") and method == "GET":
            entered.set()
            cancellation = options["cancel"]
            deadline = time.monotonic() + 2
            while not cancellation.is_set() and time.monotonic() < deadline:
                time.sleep(.005)
            assert cancellation.is_set()
            return Response(
                200,
                {"content-type": "text/html"},
                b'<form method="post" action="/login"><input name="nonce" value="fixture">'
                b'<input name="name"><input name="password"></form>',
            )
        raise AssertionError("credentials were sent after cancellation")

    client.app.state.ctfd_client_factory = lambda **kwargs: CTFdClient(
        **kwargs, resolver=public_dns, transport=transport,
    )
    primary = client.app.state.ctfd_jobs
    peer = ImportJobs(client.app, SimpleNamespace(data_dir=data))
    failures = []
    worker = threading.Thread(
        target=lambda: _capture_failure(
            failures,
            primary.preview,
            "workspace-one",
            {"id": "owner-one", "active": True, "role": "admin"},
            {
                "url": "ctf.example",
                "auth_type": "password",
                "username": "testuser",
                "password": "fixture-password",
            },
        )
    )
    worker.start()
    assert entered.wait(2)
    try:
        if cancel_scope == "owner":
            with connect() as db:
                db.execute("UPDATE users SET active=0 WHERE id='owner-one'")
            assert peer.cancel_owner("owner-one")
        else:
            assert peer.cancel_workspace("workspace-one")
        worker.join(2)
        assert not worker.is_alive()
        assert failures and isinstance(failures[0], CTFdError)
        assert requests == [("GET", "https://ctf.example/login")]
    finally:
        peer.shutdown()


def _capture_failure(target, operation, *args):
    try:
        operation(*args)
    except BaseException as exc:
        target.append(exc)


def test_rolling_startup_does_not_recover_job_before_worker_handoff(api, monkeypatch):
    from ctf_agent.ctfd import ImportJobs

    client, _connect, _transport, data = api
    primary = client.app.state.ctfd_jobs
    handoff = threading.Event()
    release = threading.Event()
    original_start = threading.Thread.start

    def delayed_start(thread):
        if thread.name.startswith("ctfd-import-"):
            handoff.set()
            assert release.wait(2)
        return original_start(thread)

    monkeypatch.setattr("ctf_agent.ctfd.threading.Thread.start", delayed_start)
    outcomes = []
    request = threading.Thread(
        target=lambda: outcomes.append(
            primary.start(
                "workspace-one",
                {"id": "owner-one", "active": True, "role": "admin"},
                {"url": "ctf.example", "challenge_ids": [1]},
            )
        ),
        name="fixture-import-request",
    )
    request.start()
    assert handoff.wait(2)
    peer = ImportJobs(client.app, SimpleNamespace(data_dir=data))
    try:
        with peer.db() as db:
            row = db.execute("SELECT id,status FROM ctfd_jobs").fetchone()
        assert row["status"] == "queued"
        release.set()
        request.join(2)
        assert not request.is_alive() and outcomes
        job_id = row["id"]
        for _ in range(200):
            with peer.db() as db:
                status = db.execute(
                    "SELECT status FROM ctfd_jobs WHERE id=?", (job_id,)
                ).fetchone()[0]
            if status not in {"queued", "running"}:
                break
            time.sleep(.01)
        assert status == "completed"
    finally:
        release.set()
        request.join(2)
        peer.shutdown()


def test_preview_slots_reject_fifth_owner_before_factory_or_network(api):
    client, connect, _transport, _data = api
    with connect() as db:
        db.execute("UPDATE workspaces SET owner_user_id='owner-two' WHERE id='workspace-two'")
        for number in range(3, 6):
            owner = f"owner-{number}"
            db.execute(
                "INSERT INTO users(id,username,password_hash,role,active,created_at) "
                "VALUES(?,?,?,'admin',1,'2026-09-09')",
                (owner, owner, "fixture-hash"),
            )
            db.execute(
                "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) "
                "VALUES(?,?,'2026-09-09','2026-09-09',?)",
                (f"workspace-{number}", f"Workspace {number}", owner),
            )

    all_entered = threading.Event()
    release = threading.Event()
    call_lock = threading.Lock()
    calls = []

    class HoldingClient:
        auth_type = "none"

        def preview(self, *_args, **_kwargs):
            with call_lock:
                if len(calls) == 4:
                    all_entered.set()
            assert release.wait(5)
            return {"source": "https://ctf.example", "challenges": []}

        def clear_credentials(self):
            return None

    def factory(**_kwargs):
        with call_lock:
            calls.append("factory")
        return HoldingClient()

    client.app.state.ctfd_client_factory = factory
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
                client.post(
                    f"/api/workspaces/{workspace}/ctfd/preview",
                    json={"url": "ctf.example"},
                    headers={"X-Test-Auth": "authenticated", "X-Test-User": owner},
                )
            )
        )
        for workspace, owner in scopes
    ]
    for worker in workers:
        worker.start()
    assert all_entered.wait(5)
    try:
        fifth = client.post(
            "/api/workspaces/workspace-5/ctfd/preview",
            json={"url": "ctf.example"},
            headers={"X-Test-Auth": "authenticated", "X-Test-User": "owner-5"},
        )
        assert fifth.status_code == 429
        assert len(calls) == 4
    finally:
        release.set()
        for worker in workers:
            worker.join(5)
    assert all(not worker.is_alive() for worker in workers)
    assert len(outcomes) == 4
    assert all(response.status_code == 200 for response in outcomes)


def test_import_is_partial_deduplicated_preserves_solve_state_and_refreshes_remote(api):
    client, connect, transport, data = api
    url = "/api/workspaces/workspace-one/ctfd/import"
    body = {"url": "https://ctf.example/", "token": "secret"}
    headers = {"X-Test-Auth": "authenticated"}
    response = import_result(client, url, json=body, headers=headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["imported"] == 1
    assert result["attachments"] == 2
    assert len(result["errors"]) == 1
    with connect() as connection:
        challenge = connection.execute("SELECT * FROM challenges").fetchone()
        assert challenge["status"] == "pending"  # remote solved_by_me is deliberately ignored
        assert challenge["remote"] == "nc pwn.example 31337 ; https://web.example/path"
        assert challenge["remote_mode"] == "endpoint"
        connection.execute("UPDATE challenges SET name='Local edit', description='Edited text', remote='ssh local.example', status='solved', completion_source='manual', flag='later flag', notes='my notes'")
        attachment = connection.execute("SELECT * FROM attachments LIMIT 1").fetchone()
    path = data / "workspaces" / "workspace-one" / "challenges" / challenge["id"] / "attachments" / attachment["stored_name"]
    assert path.read_bytes() == b"hello"
    second = import_result(client, url, json=body, headers=headers).json()
    assert second["imported"] == 0
    assert second["skipped"] == 1
    assert second["attachments"] == 0
    with connect() as connection:
        updated = connection.execute("SELECT * FROM challenges").fetchone()
        assert updated["name"] == "Local edit"
        assert updated["description"] == "Edited text"
        assert updated["remote"] == "nc pwn.example 31337 ; https://web.example/path"
        assert updated["remote_mode"] == "endpoint"
        assert updated["status"] == "solved"
        assert updated["completion_source"] == "manual"
        assert updated["flag"] == "later flag"
        assert updated["notes"] == "my notes"
        assert connection.execute("SELECT COUNT(*) FROM attachments").fetchone()[0] == 2
    assert path.read_bytes() == b"hello"
    other = import_result(client, "/api/workspaces/workspace-two/ctfd/import", json=body, headers=headers).json()
    assert other["imported"] == 1  # deduplication is scoped to each workspace


def test_saved_connection_sync_previews_and_imports_only_new_challenges(api):
    client, connect, transport, _data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    first = import_result(
        client, prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]}, headers=headers,
    ).json()
    assert first["status"] == "completed" and first["imported"] == 1

    transport.routes["https://ctf.example/api/v1/challenges"] = json_response([
        {"id": 1, "name": "First challenge"},
        {"id": 3, "name": "New challenge", "category": "crypto"},
    ])
    transport.routes["https://ctf.example/api/v1/challenges/3"] = json_response({
        "id": 3, "name": "New challenge", "category": "crypto",
        "description": "New description", "connection_info": "",
        "files": ["/files/new.bin"],
    })
    transport.routes["https://ctf.example/files/new.bin"] = Response(200, {}, b"new")
    use_saved_ctfd_connection(client)

    preview = client.post(prefix + "/sync/preview", json={}, headers=headers)
    assert preview.status_code == 200, preview.text
    preview = preview.json()
    assert preview["existing_count"] == 1 and preview["new_count"] == 1
    assert [(row["id"], row["name"]) for row in preview["challenges"]] == [
        (3, "New challenge")
    ]
    job = await_ctfd_job(
        client,
        "workspace-one",
        client.post(
            prefix + "/sync",
            json={"preview_id": preview["preview_id"], "challenge_ids": [3]},
            headers=headers,
        ),
        headers,
    )
    assert job["mode"] == "new" and job["imported"] == 1
    assert job["refreshed"] == 0 and job["skipped"] == 0
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 2
        added = db.execute("SELECT * FROM challenges WHERE ctfd_id=3").fetchone()
        assert added["name"] == "New challenge"
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_managed_attachments WHERE challenge_id=?",
            (added["id"],),
        ).fetchone()[0] == 1

    again = client.post(prefix + "/sync/preview", json={}, headers=headers)
    assert again.status_code == 200
    assert again.json()["new_count"] == 0 and again.json()["challenges"] == []
    direct = await_ctfd_job(
        client, "workspace-one",
        client.post(prefix + "/sync", json={}, headers=headers), headers,
    )
    assert direct["status"] == "completed" and direct["imported"] == 0
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 2


def test_new_sync_partial_retry_resumes_its_own_challenge_attachments(api):
    client, connect, transport, _data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client,
        prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]},
        headers=headers,
    )
    transport.routes["https://ctf.example/api/v1/challenges"] = json_response(
        [{"id": 1}, {"id": 3}]
    )
    transport.routes["https://ctf.example/api/v1/challenges/3"] = json_response(
        {
            "id": 3,
            "name": "Partially added",
            "files": ["/new-good.bin", "/new-retry.bin"],
        }
    )
    transport.routes["https://ctf.example/new-good.bin"] = Response(
        200, {}, b"first"
    )
    transport.routes["https://ctf.example/new-retry.bin"] = CTFdError(
        "Attachment timed out."
    )
    use_saved_ctfd_connection(client)

    first = await_ctfd_job(
        client,
        "workspace-one",
        client.post(prefix + "/sync", json={}, headers=headers),
        headers,
    )
    assert first["status"] == "partial" and first["imported"] == 1
    with connect() as db:
        challenge_id = db.execute(
            "SELECT id FROM challenges WHERE ctfd_id=3"
        ).fetchone()[0]
        assert db.execute(
            "SELECT COUNT(*) FROM attachments WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()[0] == 1

    # A temporarily hidden row cannot make an unfinished, job-owned challenge
    # look complete merely because this direct sync had no explicit selection.
    transport.routes["https://ctf.example/api/v1/challenges"] = json_response(
        [{"id": 1}]
    )
    hidden = await_ctfd_job(
        client,
        "workspace-one",
        client.post(
            prefix + f"/jobs/{first['id']}/retry", json={}, headers=headers
        ),
        headers,
    )
    assert hidden["status"] == "partial" and hidden["imported"] == 1
    assert any(error.get("challenge_id") is None for error in hidden["errors"])

    transport.routes["https://ctf.example/new-retry.bin"] = Response(
        200, {}, b"second"
    )
    transport.routes["https://ctf.example/api/v1/challenges"] = json_response(
        [{"id": 1}, {"id": 3}]
    )
    retried = await_ctfd_job(
        client,
        "workspace-one",
        client.post(
            prefix + f"/jobs/{first['id']}/retry", json={}, headers=headers
        ),
        headers,
    )
    assert retried["status"] == "completed" and retried["imported"] == 1
    with connect() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM attachments WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()[0] == 2
    requested = [target.url for target, _headers in transport.requests]
    assert requested.count("https://ctf.example/new-good.bin") == 1
    assert requested.count("https://ctf.example/new-retry.bin") == 2


def test_saved_connection_preview_generation_must_still_be_current(api):
    client, connect, transport, _data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client,
        prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]},
        headers=headers,
    )
    service = use_saved_ctfd_connection(client)
    preview = client.post(prefix + "/sync/preview", json={}, headers=headers)
    assert preview.status_code == 200
    before = len(transport.requests)
    service.generation = "b" * 32

    stale = client.post(
        prefix + "/sync",
        json={
            "preview_id": preview.json()["preview_id"],
            "challenge_ids": [2],
        },
        headers=headers,
    )
    assert stale.status_code == 422
    assert len(transport.requests) == before
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM ctfd_jobs").fetchone()[0] == 1


def test_new_sync_is_owner_and_existing_source_bound_before_network(api):
    client, _connect, transport, _data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client, prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]}, headers=headers,
    )
    before = len(transport.requests)
    mismatch = client.post(
        prefix + "/sync/preview",
        json={"url": "other.example", "auth_type": "none"}, headers=headers,
    )
    assert mismatch.status_code == 422
    assert len(transport.requests) == before
    other = {**headers, "X-Test-User": "owner-two"}
    assert client.post(prefix + "/sync/preview", json={}, headers=other).status_code == 404


def test_refresh_atomically_updates_remote_fields_and_only_managed_attachments(api):
    client, connect, transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    initial = import_result(
        client, prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]}, headers=headers,
    ).json()
    assert initial["status"] == "completed"
    with connect() as db:
        challenge = db.execute("SELECT * FROM challenges WHERE ctfd_id=1").fetchone()
        challenge_id = challenge["id"]
        managed = db.execute(
            """SELECT a.id,a.stored_name FROM attachments a
               JOIN ctfd_managed_attachments m ON m.attachment_id=a.id
               WHERE a.challenge_id=? ORDER BY a.id""",
            (challenge_id,),
        ).fetchall()
        db.execute(
            """UPDATE challenges SET status='solved',completion_source='manual',
                      flag='FLAG{local}',notes='local notes' WHERE id=?""",
            (challenge_id,),
        )
        manual_id = "a" * 32
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (manual_id, "workspace-one", challenge_id, "manual.bin", manual_id, 6, "local"),
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS challenge_writeups(
                   challenge_id TEXT PRIMARY KEY,markdown TEXT NOT NULL,created_at TEXT,updated_at TEXT)"""
        )
        db.execute(
            "INSERT INTO challenge_writeups VALUES(?,?,?,?)",
            (challenge_id, "# retained writeup", "local", "local"),
        )
    attachment_root = (
        data / "workspaces" / "workspace-one" / "challenges" /
        challenge_id / "attachments"
    )
    (attachment_root / manual_id).write_bytes(b"manual")
    old_paths = [attachment_root / row["stored_name"] for row in managed]
    assert all(path.is_file() for path in old_paths)

    transport.routes["https://ctf.example/api/v1/challenges/1"] = json_response({
        "id": 1, "name": "Updated upstream name", "category": "reverse",
        "description": "Updated upstream description",
        "connection_info": "nc rotated.example 4444", "files": ["/fresh.bin"],
    })
    transport.routes["https://ctf.example/fresh.bin"] = Response(200, {}, b"fresh")
    use_saved_ctfd_connection(client)
    response = client.post(
        f"/api/workspaces/workspace-one/challenges/{challenge_id}/ctfd/refresh",
        json={}, headers=headers,
    )
    job = await_ctfd_job(client, "workspace-one", response, headers)
    assert job["mode"] == "refresh" and job["target_challenge_id"] == challenge_id
    assert job["status"] == "completed" and job["refreshed"] == 1
    assert job["imported"] == 0 and job["attachments"] == 1
    with connect() as db:
        updated = db.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
        assert (
            updated["name"], updated["category"], updated["description"],
            updated["remote"], updated["remote_mode"], updated["status"],
            updated["completion_source"], updated["flag"], updated["notes"],
        ) == (
            "Updated upstream name", "reverse", "Updated upstream description",
            "nc rotated.example 4444", "endpoint", "solved", "manual",
            "FLAG{local}", "local notes",
        )
        attachments = db.execute(
            "SELECT id,stored_name FROM attachments WHERE challenge_id=? ORDER BY id",
            (challenge_id,),
        ).fetchall()
        assert len(attachments) == 2 and any(row["id"] == manual_id for row in attachments)
        imported = db.execute(
            """SELECT a.id,a.stored_name,r.name AS readable_name FROM attachments a
                JOIN ctfd_managed_attachments m ON m.attachment_id=a.id
                JOIN readable_storage_paths r
                  ON r.kind='attachment' AND r.entity_id=a.id
                WHERE a.challenge_id=?""",
            (challenge_id,),
        ).fetchone()
        assert db.execute(
            "SELECT markdown FROM challenge_writeups WHERE challenge_id=?", (challenge_id,)
        ).fetchone()[0] == "# retained writeup"
    assert (attachment_root / manual_id).read_bytes() == b"manual"
    assert (attachment_root / imported["stored_name"]).read_bytes() == b"fresh"
    assert all(not path.exists() for path in old_paths)
    stable_readable = client.app.state.storage_layout.readable_attachment_path(
        "workspace-one", challenge_id, imported["id"]
    )
    assert stable_readable.name == imported["readable_name"] == "fresh.bin"
    assert stable_readable.read_bytes() == b"fresh"

    # Repeating the same refresh replaces one managed generation with one new
    # generation and never duplicates or removes the manual upload.
    repeated = await_ctfd_job(
        client, "workspace-one",
        client.post(
            f"/api/workspaces/workspace-one/challenges/{challenge_id}/ctfd/refresh",
            json={}, headers=headers,
        ), headers,
    )
    assert repeated["status"] == "completed" and repeated["refreshed"] == 1
    with connect() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM attachments WHERE challenge_id=?", (challenge_id,)
        ).fetchone()[0] == 2
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_managed_attachments WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()[0] == 1
        repeated_import = db.execute(
            """SELECT a.id,r.name AS readable_name FROM attachments a
                 JOIN ctfd_managed_attachments m ON m.attachment_id=a.id
                 JOIN readable_storage_paths r
                   ON r.kind='attachment' AND r.entity_id=a.id
                WHERE a.challenge_id=?""",
            (challenge_id,),
        ).fetchone()
    repeated_readable = client.app.state.storage_layout.readable_attachment_path(
        "workspace-one", challenge_id, repeated_import["id"]
    )
    assert repeated_readable == stable_readable
    assert repeated_import["readable_name"] == "fresh.bin"
    assert repeated_readable.read_bytes() == b"fresh"


def test_refresh_download_failure_keeps_local_metadata_and_attachment_generation(api):
    client, connect, transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client, prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]}, headers=headers,
    )
    with connect() as db:
        challenge = db.execute("SELECT * FROM challenges WHERE ctfd_id=1").fetchone()
        challenge_id = challenge["id"]
        before = dict(challenge)
        attachments = [dict(row) for row in db.execute(
            "SELECT * FROM attachments WHERE challenge_id=? ORDER BY id", (challenge_id,)
        )]
    root = data / "workspaces/workspace-one/challenges" / challenge_id / "attachments"
    payloads = {row["id"]: (root / row["stored_name"]).read_bytes() for row in attachments}
    transport.routes["https://ctf.example/api/v1/challenges/1"] = json_response({
        "id": 1, "name": "Must not publish", "category": "web",
        "description": "Must not publish", "connection_info": "new.example:1",
        "files": ["/good.bin", "/failed.bin"],
    })
    transport.routes["https://ctf.example/good.bin"] = Response(200, {}, b"good")
    transport.routes["https://ctf.example/failed.bin"] = CTFdError("Attachment timed out.")
    response = client.post(
        f"/api/workspaces/workspace-one/challenges/{challenge_id}/ctfd/refresh",
        json={"url": "ctf.example", "auth_type": "token", "token": "fresh-token"},
        headers=headers,
    )
    job = await_ctfd_job(client, "workspace-one", response, headers)
    assert job["status"] == "partial" and job["refreshed"] == 0
    with connect() as db:
        after = db.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
        assert (
            after["name"], after["category"], after["description"],
            after["remote"], after["remote_mode"], after["status"],
            after["completion_source"], after["flag"], after["notes"],
        ) == (
            before["name"], before["category"], before["description"],
            before["remote"], before["remote_mode"], before["status"],
            before["completion_source"], before["flag"], before["notes"],
        )
        current = [dict(row) for row in db.execute(
            "SELECT * FROM attachments WHERE challenge_id=? ORDER BY id", (challenge_id,)
        )]
        assert [row["id"] for row in current] == [row["id"] for row in attachments]
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_job_files WHERE job_id=?", (job["id"],)
        ).fetchone()[0] == 0
        assert "fresh-token" not in "\n".join(db.iterdump())
    assert all((root / row["stored_name"]).read_bytes() == payloads[row["id"]] for row in current)
    assert not (
        data / "workspaces/workspace-one/ctfd_jobs" / job["id"]
    ).exists()
    assert {path.name for path in root.iterdir()} == {
        row["stored_name"] for row in attachments
    }

    # A retry starts a whole new unpublished generation. Even a successful
    # file from the partial run is downloaded again, so upstream changes at
    # the same URL cannot create a mixed attachment snapshot.
    transport.routes["https://ctf.example/good.bin"] = Response(
        200, {}, b"new-good"
    )
    transport.routes["https://ctf.example/failed.bin"] = Response(
        200, {}, b"recovered"
    )
    retried = await_ctfd_job(
        client,
        "workspace-one",
        client.post(
            prefix + f"/jobs/{job['id']}/retry",
            json={
                "url": "ctf.example",
                "auth_type": "token",
                "token": "fresh-token",
            },
            headers=headers,
        ),
        headers,
    )
    assert retried["status"] == "completed" and retried["refreshed"] == 1
    with connect() as db:
        published = db.execute(
            """SELECT a.original_name,a.stored_name FROM attachments a
                JOIN ctfd_managed_attachments m ON m.attachment_id=a.id
                WHERE a.challenge_id=? ORDER BY a.original_name""",
            (challenge_id,),
        ).fetchall()
        assert len(published) == 2
    assert {
        row["original_name"]: (root / row["stored_name"]).read_bytes()
        for row in published
    } == {"failed.bin": b"recovered", "good.bin": b"new-good"}
    requested = [target.url for target, _headers in transport.requests]
    assert requested.count("https://ctf.example/good.bin") == 2
    assert requested.count("https://ctf.example/failed.bin") == 2
    assert not (
        data / "workspaces/workspace-one/ctfd_jobs" / job["id"]
    ).exists()


def test_refresh_retry_rechecks_published_state_inside_enqueue_transaction(
    api, monkeypatch
):
    client, connect, transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client,
        prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]},
        headers=headers,
    )
    with connect() as db:
        challenge_id = db.execute(
            "SELECT id FROM challenges WHERE ctfd_id=1"
        ).fetchone()[0]
    transport.routes["https://ctf.example/api/v1/challenges/1"] = json_response(
        {
            "id": 1,
            "name": "Published once",
            "description": "Published once",
            "files": ["/fresh.bin"],
        }
    )
    transport.routes["https://ctf.example/fresh.bin"] = Response(
        200, {}, b"fresh"
    )
    use_saved_ctfd_connection(client)
    route = (
        f"/api/workspaces/workspace-one/challenges/{challenge_id}/ctfd/refresh"
    )
    completed = await_ctfd_job(
        client, "workspace-one", client.post(route, json={}, headers=headers), headers
    )
    assert completed["status"] == "completed" and completed["refreshed"] == 1

    manager = client.app.state.ctfd_jobs
    real_get = manager.get
    calls = 0

    def stale_get(workspace_id, user, job_id):
        nonlocal calls
        current = real_get(workspace_id, user, job_id)
        calls += 1
        if calls == 1:
            return {**current, "status": "failed", "refreshed": 0}
        return current

    # Simulate another application process publishing after this process made
    # its optimistic retry read. The BEGIN IMMEDIATE check must still reject
    # the stale retry without clearing the committed generation.
    monkeypatch.setattr(manager, "get", stale_get)
    retried = client.post(
        prefix + f"/jobs/{completed['id']}/retry", json={}, headers=headers
    )
    assert retried.status_code == 409
    with connect() as db:
        job = db.execute(
            "SELECT status,refreshed FROM ctfd_jobs WHERE id=?",
            (completed["id"],),
        ).fetchone()
        files = db.execute(
            "SELECT stored_name FROM attachments WHERE challenge_id=?",
            (challenge_id,),
        ).fetchall()
    assert tuple(job) == ("completed", 1)
    root = (
        data
        / "workspaces/workspace-one/challenges"
        / challenge_id
        / "attachments"
    )
    assert files and all((root / row["stored_name"]).is_file() for row in files)


def test_terminal_refresh_cleanup_removes_rowed_and_rowless_job_staging(api):
    client, connect, _transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    import_result(
        client,
        "/api/workspaces/workspace-one/ctfd/import",
        json={"url": "ctf.example", "challenge_ids": [1]},
        headers=headers,
    )
    with connect() as db:
        challenge_id = db.execute(
            "SELECT id FROM challenges WHERE ctfd_id=1"
        ).fetchone()[0]
        for job_id in ("c" * 32, "d" * 32):
            db.execute(
                """INSERT INTO ctfd_jobs
                   (id,owner_user_id,workspace_id,source_url,auth_type,selected_ids,
                    mode,target_challenge_id,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    "owner-one",
                    "workspace-one",
                    "https://ctf.example",
                    "token",
                    "[1]",
                    "refresh",
                    challenge_id,
                    "failed",
                    "before",
                    "before",
                ),
            )
        file_id = "e" * 32
        db.execute(
            """INSERT INTO ctfd_job_files
               (id,job_id,challenge_id,remote_id,file_index,original_name,
                url_hash,status,bytes,total,validator,sha256)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                file_id,
                "c" * 32,
                challenge_id,
                1,
                0,
                "staged.bin",
                "0" * 64,
                "ready",
                6,
                6,
                "",
                hashlib.sha256(b"staged").hexdigest(),
            ),
        )
    manager = client.app.state.ctfd_jobs
    rowed = manager.path("workspace-one", "ctfd_jobs", "c" * 32, "ready")
    rowed.mkdir(parents=True)
    (rowed / file_id).write_bytes(b"staged")
    rowless = manager.path("workspace-one", "ctfd_jobs", "d" * 32, "orphan")
    rowless.mkdir(parents=True)
    (rowless / "unrecorded.partial").write_bytes(b"orphan")

    assert manager.cleanup_terminal_refresh_staging() == 2
    with connect() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_job_files WHERE job_id IN (?,?)",
            ("c" * 32, "d" * 32),
        ).fetchone()[0] == 0
    assert not (data / "workspaces/workspace-one/ctfd_jobs" / ("c" * 32)).exists()
    assert not (data / "workspaces/workspace-one/ctfd_jobs" / ("d" * 32)).exists()


def test_refresh_retry_does_not_enqueue_until_old_generation_is_clean(api, monkeypatch):
    client, connect, _transport, _data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    imported = import_result(
        client,
        prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]},
        headers=headers,
    ).json()
    with connect() as db:
        challenge_id = db.execute(
            "SELECT id FROM challenges WHERE ctfd_id=1"
        ).fetchone()[0]
        db.execute(
            """UPDATE ctfd_jobs SET mode='refresh',target_challenge_id=?,
                      status='failed',refreshed=0 WHERE id=?""",
            (challenge_id, imported["id"]),
        )
    use_saved_ctfd_connection(client)
    manager = client.app.state.ctfd_jobs
    monkeypatch.setattr(manager, "_discard_refresh_generation", lambda *_args: False)

    retry = client.post(
        prefix + f"/jobs/{imported['id']}/retry", json={}, headers=headers
    )
    assert retry.status_code == 409
    with connect() as db:
        job = db.execute(
            "SELECT status,refreshed FROM ctfd_jobs WHERE id=?", (imported["id"],)
        ).fetchone()
    assert tuple(job) == ("failed", 0)


@pytest.mark.parametrize("interference", ("file", "solver", "upload"))
def test_refresh_publish_rechecks_staged_files_and_active_writers(
    api, monkeypatch, interference
):
    client, connect, transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client,
        prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]},
        headers=headers,
    )
    with connect() as db:
        challenge = db.execute(
            "SELECT * FROM challenges WHERE ctfd_id=1"
        ).fetchone()
        challenge_id = challenge["id"]
        original = dict(challenge)
        attachment = db.execute(
            "SELECT * FROM attachments WHERE challenge_id=? ORDER BY id LIMIT 1",
            (challenge_id,),
        ).fetchone()
        if interference == "solver":
            db.execute(
                """CREATE TABLE solver_jobs(
                     id TEXT PRIMARY KEY,owner_user_id TEXT,workspace_id TEXT,
                     challenge_id TEXT,status TEXT)"""
            )
        elif interference == "upload":
            db.execute(
                """CREATE TABLE upload_sessions(
                     id TEXT PRIMARY KEY,owner_user_id TEXT,workspace_id TEXT,
                     challenge_id TEXT,status TEXT)"""
            )
    root = (
        data
        / "workspaces/workspace-one/challenges"
        / challenge_id
        / "attachments"
    )
    original_payload = (root / attachment["stored_name"]).read_bytes()
    readable = client.app.state.storage_layout.readable_attachment_path(
        "workspace-one", challenge_id, attachment["id"]
    )
    readable_name = readable.name
    readable_payload = readable.read_bytes()
    transport.routes["https://ctf.example/api/v1/challenges/1"] = json_response(
        {
            "id": 1,
            "name": "Must remain unpublished",
            "description": "Must remain unpublished",
            "files": ["/fresh.bin"],
        }
    )
    transport.routes["https://ctf.example/fresh.bin"] = Response(
        200, {}, b"fresh"
    )
    use_saved_ctfd_connection(client)
    manager = client.app.state.ctfd_jobs
    publish = manager.publish_refresh

    def interfere(job_id, workspace_id, owner, source, remote, target, cancel):
        if interference == "file":
            with connect() as db:
                file_id = db.execute(
                    "SELECT id FROM ctfd_job_files WHERE job_id=?",
                    (job_id,),
                ).fetchone()[0]
            ready = manager.path(
                workspace_id, "ctfd_jobs", job_id, "ready", file_id
            )
            ready.write_bytes(b"other")
        else:
            with connect() as db:
                table = "solver_jobs" if interference == "solver" else "upload_sessions"
                db.execute(
                    f"INSERT INTO {table} VALUES(?,?,?,?,?)",
                    (
                        interference,
                        owner,
                        workspace_id,
                        target,
                        "queued" if interference == "solver" else "uploading",
                    ),
                )
        return publish(job_id, workspace_id, owner, source, remote, target, cancel)

    monkeypatch.setattr(manager, "publish_refresh", interfere)
    job = await_ctfd_job(
        client,
        "workspace-one",
        client.post(
            f"/api/workspaces/workspace-one/challenges/{challenge_id}/ctfd/refresh",
            json={},
            headers=headers,
        ),
        headers,
    )
    # Publication fails before the normal per-file result is finalized, so the
    # job is terminally failed and retryable. The live generation is untouched.
    assert job["status"] == "failed" and job["refreshed"] == 0
    with connect() as db:
        current = db.execute(
            "SELECT * FROM challenges WHERE id=?", (challenge_id,)
        ).fetchone()
        assert (current["name"], current["description"]) == (
            original["name"], original["description"],
        )
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_job_files WHERE job_id=?", (job["id"],)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM attachments WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()[0] == 2
    assert (root / attachment["stored_name"]).read_bytes() == original_payload
    assert readable.name == readable_name
    assert readable.read_bytes() == readable_payload
    assert os.path.samefile(readable, root / attachment["stored_name"])
    assert not (
        data / "workspaces/workspace-one/ctfd_jobs" / job["id"]
    ).exists()


def test_refresh_start_transaction_rejects_open_solver_and_upload(api):
    client, connect, transport, _data = api
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    import_result(
        client, prefix + "/import",
        json={"url": "ctf.example", "challenge_ids": [1]}, headers=headers,
    )
    with connect() as db:
        challenge_id = db.execute(
            "SELECT id FROM challenges WHERE ctfd_id=1"
        ).fetchone()[0]
        db.executescript(
            """
            CREATE TABLE solver_jobs(
              id TEXT PRIMARY KEY,owner_user_id TEXT,workspace_id TEXT,
              challenge_id TEXT,status TEXT
            );
            CREATE TABLE upload_sessions(
              id TEXT PRIMARY KEY,owner_user_id TEXT,workspace_id TEXT,
              challenge_id TEXT,status TEXT
            );
            """
        )
        db.execute(
            "INSERT INTO solver_jobs VALUES('solve',?,?,?,'queued')",
            ("owner-one", "workspace-one", challenge_id),
        )
    use_saved_ctfd_connection(client)
    route = f"/api/workspaces/workspace-one/challenges/{challenge_id}/ctfd/refresh"
    assert client.post(route, json={}, headers=headers).status_code == 409
    with connect() as db:
        # Only the original completed import exists; a rejected refresh never
        # leaves a queued job behind.
        assert db.execute("SELECT COUNT(*) FROM ctfd_jobs").fetchone()[0] == 1
        db.execute("UPDATE solver_jobs SET status='completed'")
        db.execute(
            "INSERT INTO upload_sessions VALUES('upload',?,?,?,'uploading')",
            ("owner-one", "workspace-one", challenge_id),
        )
    assert client.post(route, json={}, headers=headers).status_code == 409
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM ctfd_jobs").fetchone()[0] == 1
        db.execute("UPDATE upload_sessions SET status='completed'")
    completed = await_ctfd_job(
        client, "workspace-one", client.post(route, json={}, headers=headers), headers,
    )
    assert completed["status"] == "completed" and completed["refreshed"] == 1


def test_attachment_failure_keeps_imported_description_and_reports_partial_result(api):
    client, connect, transport, data = api
    transport.routes["https://cdn.example/task.dat"] = CTFdError("Attachment timed out.")
    response = import_result(client, "/api/workspaces/workspace-one/ctfd/import", json={"url": "https://ctf.example", "challenge_ids": [1]}, headers={"X-Test-Auth": "authenticated"})
    assert response.status_code == 200, response.text
    assert response.json()["imported"] == 1
    assert response.json()["attachments"] == 1
    assert response.json()["errors"] == [{"challenge_id": 1, "file": "task.dat", "message": "Attachment timed out."}]
    with connect() as connection:
        assert connection.execute("SELECT description FROM challenges").fetchone()[0] == "Description"


def test_unknown_workspace_and_empty_selection_do_not_import(api):
    client, connect, transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    response = client.post("/api/workspaces/missing/ctfd/import", json={"url": "https://ctf.example"}, headers=headers)
    assert response.status_code == 404
    assert transport.requests == []
    response = client.post("/api/workspaces/workspace-one/ctfd/import", json={"url": "https://ctf.example", "challenge_ids": []}, headers=headers)
    assert response.status_code == 422


@pytest.fixture
def network_ctfd(tmp_path, monkeypatch):
    """Serve the documented CTFd API shape over a real, verified TLS socket.

    Only this test transport maps fixed synthetic hosts to the loopback fixture.
    Production URL validation still rejects private addresses and has no bypass.
    This is an API-compatible fixture, not a deployment of the CTFd application.
    """
    executable = shutil.which("openssl")
    if executable is None:
        windows_openssl = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        executable = str(windows_openssl) if windows_openssl.is_file() else None
    if executable is None:
        pytest.skip("OpenSSL is required to generate the local TLS fixture certificate")
    certificate, key = tmp_path / "fixture.pem", tmp_path / "fixture.key"
    subprocess.run([executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=ctf.example",
                    "-addext", "subjectAltName=DNS:ctf.example,DNS:cdn.example"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    trusted_context = ssl.create_default_context(cafile=str(certificate))
    monkeypatch.setattr("ctf_agent.ctfd.ssl.create_default_context", lambda: trusted_context)
    requests = []
    base = "/ctf/" + quote("대회")
    fixture_routes = {
        base + "/api/v1/challenges": json_response([{"id": 1, "name": "네트워크 문제", "type": "standard"}, {"id": 2}]),
        base + "/api/v1/challenges/1": json_response({
            "id": 1, "name": "네트워크 문제", "category": "misc", "description": "원본 설명",
            "files": ["files/" + quote("자료.txt") + "?filename=한글",
                      "https://cdn.example/redirect", "/missing-file"],
            "type": "standard", "solved_by_me": True,
        }),
        base + "/api/v1/challenges/2": Response(403, {}, b"private upstream error"),
        base + "/files/" + quote("자료.txt") + "?filename=" + quote("한글"): Response(200, {}, "보존할 첨부".encode()),
        "/redirect": Response(302, {"location": "https://cdn.example/payload.bin"}, b""),
        "/payload.bin": Response(200, {}, b"binary-attachment"),
        "/missing-file": Response(404, {}, b"private upstream error"),
        "/truncated": Response(200, {"content-length": "100", "connection": "close"}, b"short"),
        "/oversized": Response(200, {"connection": "close"}, b"0123456789"),
    }
    login_form = b'<form method="post"><input name="name"><input name="password"><input name="nonce" value="fixture-nonce"></form>'
    fixture_routes[base + "/login"] = Response(200, {}, login_form)
    fixture_routes[base + "/challenges"] = Response(
        200,
        {},
        b'''<script>window.init = {'csrfNonce': "fixture-session-nonce-0123456789abcdef"};</script>''',
    )
    fixture_state = {"login_required": False, "login_result": "success", "posts": [], "range_payload": b"range-payload-" * 10000, "drop_range_once": False}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_args):
            pass
        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            if self.path == "/large":
                self.send_response(200)
                self.send_header("Content-Length", str(51 * 1024 * 1024))
                self.end_headers()
                try:
                    for _ in range(51 * 1024):
                        self.wfile.write(b"x" * 1024)
                except OSError:
                    pass
                return
            if self.path == "/range":
                payload = fixture_state["range_payload"]
                start = int(self.headers.get("Range", "bytes=0-").split("=")[1].split("-")[0])
                code = 416 if start >= len(payload) else 206 if start else 200
                self.send_response(code)
                self.send_header("ETag", '"fixture-entity"')
                self.send_header("Content-Length", str(len(payload) - start if code != 416 else 0))
                self.send_header("Connection", "close")
                if code == 206:
                    self.send_header("Content-Range", f"bytes {start}-{len(payload)-1}/{len(payload)}")
                self.end_headers()
                if code != 416:
                    if fixture_state["drop_range_once"]:
                        fixture_state["drop_range_once"] = False
                        self.wfile.write(payload[start:start + 65536])
                    else:
                        self.wfile.write(payload[start:])
                    self.wfile.flush()
                return
            if self.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(.02)
                except OSError:
                    pass
                return
            response = fixture_routes.get(self.path, Response(404, {}, b"unknown fixture route"))
            if fixture_state["login_required"] and self.path.startswith(base + "/api/") and "fixture_session=authenticated" not in self.headers.get("Cookie", ""):
                response = Response(403, {}, b"authentication required")
            self.send_response(response.status)
            if self.path == base + "/login":
                self.send_header("Set-Cookie", "fixture_session=prelogin; Path=/; HttpOnly; Secure")
                self.send_header("Set-Cookie", "fixture_extra=second-cookie; Path=/; Secure")
            for name, value in response.headers.items():
                self.send_header(name, value)
            # /oversized deliberately has no length so the streamed limit is tested.
            if "content-length" not in response.headers and self.path != "/oversized":
                self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            if response.content:
                try:
                    self.wfile.write(response.content)
                    self.wfile.flush()
                except OSError:
                    pass

        def do_POST(self):
            # Synthetic credentials are asserted in memory and never logged.
            body = self.rfile.read(int(self.headers["Content-Length"])).decode("ascii")
            fields = parse_qs(body)
            fixture_state["posts"].append((self.path, fields, dict(self.headers)))
            valid = (self.path == base + "/login" and fields == {"name": ["fixture-user"], "password": ["fixture-password"], "nonce": ["fixture-nonce"]}
                     and "fixture_session=prelogin" in self.headers.get("Cookie", "") and fixture_state["login_result"] == "success")
            if fixture_state["login_result"] == "rate-limit":
                self.send_response(429)
                self.send_header("Retry-After", "30")
                response = b"private upstream error"
            elif valid or fixture_state["login_result"] == "external":
                self.send_response(302)
                self.send_header("Location", "https://cdn.example/challenges" if fixture_state["login_result"] == "external" else base + "/challenges")
                self.send_header("Set-Cookie", "fixture_session=authenticated; Path=/; HttpOnly; Secure")
                response = b""
            else:
                self.send_response(200)
                response = login_form
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def transport(target, headers, maximum, timeout, deadline, **options):
        assert target.host in {"ctf.example", "cdn.example"}
        return public_get(replace(target, address="127.0.0.1", port=server.server_port),
                          headers, maximum, timeout, deadline, **options)

    def client(url="https://ctf.example" + base, token="fixture-token", **kwargs):
        return CTFdClient(url, token, resolver=public_dns, transport=transport, **kwargs)

    try:
        yield SimpleNamespace(client=client, requests=requests, routes=fixture_routes, base=base, state=fixture_state,
                              transport=transport, port=server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_real_tls_import_handles_subpath_unicode_partial_failure_and_reimport(api, network_ctfd):
    client, connect, _mock, data = api
    client.app.state.ctfd_client_factory = network_ctfd.client
    headers = {"X-Test-Auth": "authenticated"}
    body = {"url": "https://ctf.example/ctf/대회/", "token": "fixture-token"}
    preview = client.post("/api/workspaces/workspace-one/ctfd/preview", json=body, headers=headers)
    assert preview.status_code == 200, preview.text
    assert preview.json()["challenges"][0]["name"] == "네트워크 문제"
    result = import_result(client, "/api/workspaces/workspace-one/ctfd/import", json=body, headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["imported"] == 1
    assert result.json()["attachments"] == 2
    assert len(result.json()["errors"]) == 2
    assert "private upstream error" not in result.text
    assert "fixture-token" not in result.text
    with connect() as connection:
        challenge = connection.execute("SELECT * FROM challenges").fetchone()
        assert challenge["status"] == "pending"
        connection.execute("UPDATE challenges SET name='Local name', notes='Preserve notes', flag='later flag', status='solved', completion_source='manual',ctfd_url=?",
                           ("https://ctf.example/ctf/대회",))
        attachments = connection.execute("SELECT * FROM attachments ORDER BY original_name").fetchall()
    stored = {row["original_name"]: (data / "workspaces" / "workspace-one" / "challenges" / challenge["id"] / "attachments" / row["stored_name"]).read_bytes() for row in attachments}
    assert stored["자료.txt"] == "보존할 첨부".encode()
    assert stored["redirect"] == b"binary-attachment"
    second = import_result(client, "/api/workspaces/workspace-one/ctfd/import", json={**body, "url": "https://ctf.example" + network_ctfd.base}, headers=headers)
    assert second.status_code == 200, second.text
    assert second.json()["skipped"] == 1
    assert second.json()["imported"] == 0
    with connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 1
        preserved = connection.execute("SELECT name,notes,flag,status FROM challenges").fetchone()
        assert tuple(preserved) == ("Local name", "Preserve notes", "later flag", "solved")
    for _path, sent in network_ctfd.requests:
        if sent["Host"].startswith("cdn.example:"):
            assert "Authorization" not in sent
        else:
            assert sent.get("Authorization") == "Token fixture-token"


def test_real_socket_partial_downloads_consume_total_budget(network_ctfd):
    client = network_ctfd.client(limits=Limits(file_bytes=3, total_bytes=5))
    with pytest.raises(CTFdError, match="size limit"):
        client.download("https://ctf.example/oversized")
    assert client.downloaded == 4
    with pytest.raises(CTFdError, match="size limit"):
        client.download("https://ctf.example/oversized")
    count = len(network_ctfd.requests)
    with pytest.raises(CTFdError, match="total import size limit"):
        client.download("https://ctf.example/oversized")
    assert len(network_ctfd.requests) == count


def test_real_socket_truncated_response_is_not_accepted(network_ctfd):
    client = network_ctfd.client()
    with pytest.raises(CTFdError, match="declared content length"):
        client.download("https://ctf.example/truncated")
    assert client.downloaded == len(b"short")


def test_real_socket_slow_response_has_an_absolute_timeout(network_ctfd):
    client = network_ctfd.client(limits=Limits(timeout=.3))
    started = time.monotonic()
    with pytest.raises(CTFdError, match="time|timed"):
        client.download("https://ctf.example/slow")
    assert time.monotonic() - started < 1.5
    assert client.downloaded > 0


def test_unicode_and_encoded_site_urls_have_one_deduplication_key():
    assert normalize_url("https://ctf.example/ctf/대회", site=True) == normalize_url("https://ctf.example/ctf/%eb%8c%80%ed%9a%8c/", site=True)


def test_non_ascii_access_token_is_rejected_before_http():
    with pytest.raises(CTFdError, match="token"):
        CTFdClient("https://ctf.example", "토큰")


def test_signed_attachment_urls_keep_their_exact_existing_escape_representation():
    url = "https://cdn.example/%eb%8c%80%ed%9a%8c?path=%2fprivate&signature=a%2bb%3d"
    assert normalize_url(url) == url
    assert normalize_url("https://ctf.example/a%2Fb", site=True) != normalize_url("https://ctf.example/a/b", site=True)


def test_real_app_ctfd_auth_csrf_token_redaction_and_read_only_preview(tmp_path, monkeypatch, network_ctfd):
    from ctf_agent.db import Settings, connect
    from ctf_agent.main import create_app

    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", "ctfd-local-test-password")
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs",
                        public_origin="https://workspace.example", cookie_secure=True)
    app = create_app(settings)
    app.state.ctfd_client_factory = network_ctfd.client
    with TestClient(app, base_url="https://workspace.example") as client:
        origin_headers = {"Origin": "https://workspace.example"}
        login = client.post("/api/auth/login", json={"username": "admin", "password": "ctfd-local-test-password"}, headers=origin_headers)
        assert login.status_code == 200
        headers = {**origin_headers, "X-CSRF-Token": login.json()["csrf_token"]}
        workspace = client.post("/api/workspaces", json={"name": "TLS fixture"}, headers=headers).json()
        url = f"/api/workspaces/{workspace['id']}/ctfd/preview"
        body = {"url": "https://ctf.example" + network_ctfd.base, "token": "fixture-token"}
        assert client.post(url, json=body, headers=origin_headers).status_code == 403
        assert network_ctfd.requests == []
        invalid = client.post(url, json={**body, "token": "sensitive-token-" * 400}, headers=headers)
        assert invalid.status_code == 422
        assert "sensitive-token-" not in invalid.text
        preview = client.post(url, json=body, headers=headers)
        assert preview.status_code == 200, preview.text
        assert "fixture-token" not in preview.text
        with connect(settings) as connection:
            assert connection.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 0
        assert not list((settings.data_dir / "workspaces" / workspace["id"]).glob("challenges/*"))
    assert "fixture-token" not in (settings.log_dir / "web.log").read_text(encoding="utf-8")
    assert b"fixture-token" not in settings.database_path.read_bytes()


def test_scheme_defaults_and_auth_selection_are_explicit():
    assert normalize_url("ctf.example/ctf", site=True) == "https://ctf.example/ctf"
    assert normalize_url("http://ctf.example/ctf/", site=True) == "http://ctf.example/ctf"
    assert CTFdClient("ctf.example", token="ignored", auth_type="none").token == ""
    with pytest.raises(CTFdError, match="HTTPS"):
        CTFdClient("http://ctf.example", auth_type="password", username="fixture-user", password="fixture-password")
    with pytest.raises(CTFdError, match="authentication"):
        CTFdClient("ctf.example", auth_type=[])


def test_session_csrf_nonce_requires_one_unambiguous_bounded_bootstrap_value():
    nonce = "0123456789abcdef" * 4
    assert session_csrf_nonce(f'''<script>window.init={{'csrfNonce': "{nonce}"}}</script>''') == nonce
    assert session_csrf_nonce(
        f'''<script>window.init={{'csrfNonce': "{nonce}", "csrfNonce": '{nonce}'}}</script>'''
    ) == nonce
    assert session_csrf_nonce("'csrfNonce': 'short'") == ""
    assert session_csrf_nonce(
        f'''<script>'csrfNonce': "{nonce}", 'csrfNonce': "{'f' * 64}"</script>'''
    ) == ""


def test_real_tls_password_login_preserves_nonce_cookie_and_exact_origin(network_ctfd, tmp_path):
    network_ctfd.state["login_required"] = True
    client = network_ctfd.client(auth_type="password", username="fixture-user", password="fixture-password")
    preview = client.preview([1])
    assert preview["challenges"][0]["id"] == 1
    assert len(network_ctfd.state["posts"]) == 1
    path, fields, headers = network_ctfd.state["posts"][0]
    assert path == network_ctfd.base + "/login"
    assert headers["Origin"] == "https://ctf.example"
    assert "fixture_extra=second-cookie" in headers["Cookie"]
    assert client.username == client.password == ""
    assert client.logged_in
    assert client.csrf_nonce == "fixture-session-nonce-0123456789abcdef"
    client.download_to("https://cdn.example/redirect", tmp_path / "download.partial")
    for _path, sent in network_ctfd.requests:
        if sent["Host"].startswith("cdn.example:"):
            assert "Cookie" not in sent and "Authorization" not in sent
    assert len(network_ctfd.state["posts"]) == 1
    client.clear_credentials()
    assert not list(client.cookies)


@pytest.mark.parametrize(("result", "message"), [("bad-password", "login failed"), ("external", "original site"), ("rate-limit", "30 seconds")])
def test_real_tls_login_failure_does_not_retry_or_echo_credentials(network_ctfd, result, message):
    network_ctfd.state["login_result"] = result
    client = network_ctfd.client(auth_type="password", username="fixture-user", password="fixture-password")
    with pytest.raises(CTFdError, match=message) as failure:
        client.preview()
    assert "fixture-password" not in str(failure.value)
    assert client.username == client.password == ""
    with pytest.raises(CTFdError, match="Start a new connection"):
        client.preview()
    assert len(network_ctfd.state["posts"]) == 1
    assert all(not sent["Host"].startswith("cdn.example:") for _path, sent in network_ctfd.requests)


def test_real_tls_login_form_cannot_send_credentials_to_another_host(network_ctfd):
    network_ctfd.routes[network_ctfd.base + "/login"] = Response(200, {}, b'<form action="https://cdn.example/login" method="post"><input name="name"><input name="password"><input name="nonce" value="fixture-nonce"></form>')
    client = network_ctfd.client(auth_type="password", username="fixture-user", password="fixture-password")
    with pytest.raises(CTFdError, match="unexpected endpoint"):
        client.preview()
    assert network_ctfd.state["posts"] == []


def test_real_stream_survives_total_duration_beyond_idle_timeout(network_ctfd, tmp_path):
    client = network_ctfd.client(limits=Limits(timeout=.3))
    started = time.monotonic()
    result = client.download_to("https://ctf.example/slow", tmp_path / "slow.partial")
    assert result["bytes"] == 100
    assert time.monotonic() - started > 1.5
    assert (tmp_path / "slow.partial").read_bytes() == b"x" * 100


def test_real_stream_download_exceeds_previous_50_mib_cap_without_buffering(network_ctfd, tmp_path):
    client = network_ctfd.client()
    assert client.limits.file_bytes is None and client.limits.total_bytes is None and client.limits.duration is None
    result = client.download_to("https://ctf.example/large", tmp_path / "large.partial")
    assert result["bytes"] == result["total"] == 51 * 1024 * 1024
    assert (tmp_path / "large.partial").stat().st_size == result["bytes"]


def test_real_stream_resume_and_full_partial_range_restart(network_ctfd, tmp_path):
    partial = tmp_path / "resume.partial"
    network_ctfd.state["drop_range_once"] = True
    client = network_ctfd.client()
    progress = []
    with pytest.raises(CTFdError, match="declared content length"):
        client.download_to("https://ctf.example/range", partial, progress=lambda *args: progress.append(args))
    assert partial.stat().st_size == 65536
    assert progress[-1][2] == 'etag:"fixture-entity"'
    result = client.download_to("https://ctf.example/range", partial, validator=progress[-1][2])
    assert partial.read_bytes() == network_ctfd.state["range_payload"]
    assert [headers["Range"] for path, headers in network_ctfd.requests if path == "/range" and "Range" in headers] == ["bytes=65536-"]
    assert result["bytes"] == len(network_ctfd.state["range_payload"])
    # A process can die after its last write but before final metadata commits.
    result = client.download_to("https://ctf.example/range", partial, validator=result["validator"])
    assert result["bytes"] == len(network_ctfd.state["range_payload"])
    assert partial.read_bytes() == network_ctfd.state["range_payload"]


def test_real_stream_server_without_range_support_restarts_file(network_ctfd, tmp_path):
    partial = tmp_path / "resume.partial"
    partial.write_bytes(b"old partial data")
    result = network_ctfd.client().download_to("https://cdn.example/payload.bin", partial, validator='etag:"old-entity"')
    assert partial.read_bytes() == b"binary-attachment"
    assert result["bytes"] == len(b"binary-attachment")


def test_preview_cache_jobs_and_retry_are_owner_scoped(api):
    client, connect, transport, data = api
    headers = {"X-Test-Auth": "authenticated"}
    other = {**headers, "X-Test-User": "owner-two"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    preview = client.post(prefix + "/preview", json={"url": "ctf.example", "token": "fixture-token"}, headers=headers).json()
    assert preview["details_pending"] and preview["challenges"][0]["files"] == []
    assert len(transport.requests) == 1  # Quick metadata preview does not wait for individual details.
    assert client.post(prefix + "/import", json={"preview_id": preview["preview_id"]}, headers=other).status_code == 404
    result = import_result(client, prefix + "/import", json={"preview_id": preview["preview_id"], "challenge_ids": [1]}, headers=headers).json()
    assert result["status"] == "completed"
    job = prefix + "/jobs/" + result["id"]
    assert client.get(prefix + "/jobs", headers=other).status_code == 404
    assert client.get(job, headers=other).status_code == 404
    assert client.post(job + "/cancel", headers=other).status_code == 404
    assert client.post(job + "/retry", json={}, headers=other).status_code == 404
    assert client.post(job + "/retry", json={}, headers=headers).status_code == 422
    assert client.post(prefix + "/import", json={"preview_id": preview["preview_id"]}, headers=headers).status_code == 404
    assert client.get(prefix + "/jobs", headers=headers).json()["jobs"][0]["id"] == result["id"]
    with connect() as db:
        dump = "\n".join(db.iterdump())
    assert "fixture-token" not in dump


@pytest.mark.parametrize(
    ("refreshed_connection", "refreshed_mode"),
    (
        ("nc rotated.example 4444", "endpoint"),
        ("", "none"),
    ),
)
def test_durable_job_retry_after_restart_resumes_with_fresh_remote_and_local_edits(
    api, network_ctfd, refreshed_connection, refreshed_mode
):
    from ctf_agent.ctfd import ImportJobs
    client, connect, transport, data = api
    detail = network_ctfd.base + "/api/v1/challenges/1"
    network_ctfd.routes[detail] = json_response({
        "id": 1,
        "name": "Resume challenge",
        "description": "remote description",
        "connection_info": "https://old-target.example/",
        "files": ["/range"],
    })
    network_ctfd.state["drop_range_once"] = True
    client.app.state.ctfd_client_factory = network_ctfd.client
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    body = {"url": "https://ctf.example" + network_ctfd.base, "auth_type": "token", "token": "fixture-token", "challenge_ids": [1]}
    result = import_result(client, prefix + "/import", json=body, headers=headers).json()
    assert result["status"] == "partial" and result["downloaded_bytes"] == 65536
    assert client.app.state.storage_budget.snapshot(kind="ctfd") == []
    network_ctfd.routes[detail] = json_response({
        "id": 1,
        "name": "Changed upstream name",
        "description": "changed upstream description",
        "connection_info": refreshed_connection,
        "files": ["/range"],
    })
    with connect() as db:
        db.execute(
            """UPDATE challenges SET name='retained local name',description='retained local description',
               notes='retained local notes',status='solved',completion_source='manual',flag='SARI{retained}'"""
        )
        # Emulate a crash marker with a durable partial already on the data volume.
        db.execute("UPDATE ctfd_jobs SET status='running' WHERE id=?", (result["id"],))
    manager = ImportJobs(client.app, SimpleNamespace(data_dir=data))
    user = {"id": "owner-one", "active": True}
    assert manager.get("workspace-one", user, result["id"])["status"] == "interrupted"
    try:
        manager.start("workspace-one", user, body, result["id"])
        for _ in range(200):
            job = manager.get("workspace-one", user, result["id"])
            if job["status"] not in {"queued", "running"}:
                break
            time.sleep(.02)
        assert job["status"] == "completed", job
        assert job["imported"] == 1 and job["attachments"] == 1
        with connect() as db:
            challenge = db.execute(
                "SELECT name,description,notes,status,completion_source,flag,remote,remote_mode FROM challenges"
            ).fetchone()
            assert tuple(challenge) == (
                "retained local name",
                "retained local description",
                "retained local notes",
                "solved",
                "manual",
                "SARI{retained}",
                refreshed_connection,
                refreshed_mode,
            )
            assert db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM ctfd_job_challenges").fetchone()[0] == 1
            attachment = db.execute("SELECT * FROM attachments").fetchone()
            assert "fixture-token" not in "\n".join(db.iterdump())
        saved = data / "workspaces/workspace-one/challenges" / attachment["challenge_id"] / "attachments" / attachment["stored_name"]
        assert saved.read_bytes() == network_ctfd.state["range_payload"]
        assert any(path == "/range" and sent.get("Range") == "bytes=65536-" for path, sent in network_ctfd.requests)
    finally:
        manager.shutdown()


def test_job_can_be_cancelled_during_a_stream_and_new_import_does_not_hold_db_lock(api, network_ctfd):
    client, connect, transport, data = api
    network_ctfd.routes[network_ctfd.base + "/api/v1/challenges/1"] = json_response({"id": 1, "name": "Slow challenge", "files": ["/slow"]})
    def unlocked_transport(*args, **kwargs):
        db = connect()
        try:
            db.execute("PRAGMA busy_timeout=100")
            db.execute("BEGIN IMMEDIATE")
            db.rollback()
        finally:
            db.close()
        return network_ctfd.transport(*args, **kwargs)
    client.app.state.ctfd_client_factory = lambda **kwargs: CTFdClient(**kwargs, resolver=public_dns, transport=unlocked_transport)
    headers = {"X-Test-Auth": "authenticated"}
    prefix = "/api/workspaces/workspace-one/ctfd"
    body = {"url": "https://ctf.example" + network_ctfd.base, "challenge_ids": [1]}
    response = client.post(prefix + "/import", json=body, headers=headers)
    assert response.status_code == 202
    job_url = prefix + "/jobs/" + response.json()["job"]["id"]
    for _ in range(100):
        job = client.get(job_url, headers=headers).json()["job"]
        if job["downloaded_bytes"]:
            break
        time.sleep(.02)
    assert job["status"] == "running" and job["downloaded_bytes"] > 0
    assert client.post(job_url + "/cancel", headers=headers).status_code == 200
    for _ in range(100):
        job = client.get(job_url, headers=headers).json()["job"]
        if job["status"] == "cancelled":
            break
        time.sleep(.02)
    assert job["status"] == "cancelled"
    assert client.app.state.storage_budget.snapshot(kind="ctfd") == []
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM attachments").fetchone()[0] == 0
    assert list(data.glob("workspaces/workspace-one/ctfd_jobs/*/partials/*.partial"))


@pytest.mark.parametrize("corrupt", [False, True])
def test_job_recovers_atomic_move_crash_or_restarts_corrupt_unpublished_file(api, corrupt):
    client, connect, transport, data = api
    transport.routes["https://ctf.example/api/v1/challenges/1"] = json_response({"id": 1, "name": "Atomic recovery", "files": ["/artifact"]})
    transport.routes["https://ctf.example/artifact"] = CTFdError("Synthetic interruption.")
    prefix = "/api/workspaces/workspace-one/ctfd"
    headers = {"X-Test-Auth": "authenticated"}
    body = {"url": "ctf.example", "challenge_ids": [1]}
    result = import_result(client, prefix + "/import", json=body, headers=headers).json()
    assert result["status"] == "partial"
    with connect() as db:
        file = db.execute("SELECT * FROM ctfd_job_files").fetchone()
        db.execute("UPDATE ctfd_job_files SET status='ready',bytes=5,total=5,sha256=?", (hashlib.sha256(b"hello").hexdigest(),))
    destination = data / "workspaces/workspace-one/challenges" / file["challenge_id"] / "attachments" / file["id"]
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"wrong" if corrupt else b"hello")
    transport.routes["https://ctf.example/artifact"] = Response(200, {}, b"hello")
    previous = len(transport.requests)
    response = client.post(prefix + "/jobs/" + result["id"] + "/retry", json={}, headers=headers)
    assert response.status_code == 202, response.text
    for _ in range(100):
        job = client.get(prefix + "/jobs/" + result["id"], headers=headers).json()["job"]
        if job["status"] not in {"queued", "running"}:
            break
        time.sleep(.02)
    assert job["status"] == "completed", job
    assert destination.read_bytes() == b"hello"
    fetched = [target.url for target, _ in transport.requests[previous:]]
    assert ("https://ctf.example/artifact" in fetched) == corrupt
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM attachments").fetchone()[0] == 1


def test_stream_checks_available_disk_space_before_writing(api, tmp_path, monkeypatch):
    mock = MockTransport({"https://ctf.example/file": Response(200, {"content-length": "100"}, b"x" * 100)})
    client = CTFdClient("ctf.example", resolver=public_dns, transport=mock)
    monkeypatch.setattr("ctf_agent.ctfd.shutil.disk_usage", lambda _path: SimpleNamespace(free=0))
    with pytest.raises(CTFdError, match="insufficient free space"):
        client.download_to("https://ctf.example/file", tmp_path / "file.partial")
    assert (tmp_path / "file.partial").stat().st_size == 0


def test_two_ctfd_streams_cannot_reserve_the_same_remaining_capacity(api, monkeypatch):
    web, _connect, _transport, data = api
    budget = web.app.state.storage_budget
    budget.minimum_free_bytes = 50
    monkeypatch.setattr(budget, "_free", lambda: 150)
    first_reserved = threading.Event()
    release_first = threading.Event()
    first_result = []

    class HoldingTransport:
        def __call__(self, target, headers, maximum, timeout, deadline, **options):
            options["on_headers"](200, {"content-length": "100", "etag": '"one"'})
            first_reserved.set()
            assert release_first.wait(5)
            options["sink"](b"a" * 100)
            return Response(200, {"content-length": "100"}, b"", received_bytes=100)

    first = CTFdClient("ctf.example", resolver=public_dns, transport=HoldingTransport())
    first_path = data / "first.partial"

    def download_first():
        try:
            first_result.append(first.download_to(
                "https://ctf.example/first", first_path,
                storage_budget=budget,
                storage_reservation=("ctfd:first", "owner-one", "workspace-one", "challenge-one"),
            ))
        except Exception as exc:
            first_result.append(exc)

    worker = threading.Thread(target=download_first)
    worker.start()
    assert first_reserved.wait(5)
    second_transport = MockTransport({
        "https://ctf.example/second": Response(200, {"content-length": "100"}, b"b" * 100)
    })
    second = CTFdClient("ctf.example", resolver=public_dns, transport=second_transport)
    with pytest.raises(CTFdError, match="저장 공간"):
        second.download_to(
            "https://ctf.example/second", data / "second.partial",
            storage_budget=budget,
            storage_reservation=("ctfd:second", "owner-two", "workspace-two", "challenge-two"),
        )
    rows = budget.snapshot(kind="ctfd")
    assert [(row["reservation_key"], row["remaining_bytes"]) for row in rows] == [("ctfd:first", 100)]
    release_first.set()
    worker.join(5)
    assert not worker.is_alive()
    assert first_result and isinstance(first_result[0], dict)
    assert first_path.read_bytes() == b"a" * 100
    assert budget.snapshot(kind="ctfd") == []


def test_unknown_length_ctfd_stream_checks_floor_under_shared_lock(api, monkeypatch):
    web, _connect, _transport, data = api
    budget = web.app.state.storage_budget
    budget.minimum_free_bytes = 100
    monkeypatch.setattr(budget, "_free", lambda: 103)
    transport = MockTransport({"https://ctf.example/unknown": Response(200, {}, b"four")})
    client = CTFdClient("ctf.example", resolver=public_dns, transport=transport)
    destination = data / "unknown.partial"
    with pytest.raises(CTFdError, match="저장 공간"):
        client.download_to(
            "https://ctf.example/unknown", destination,
            storage_budget=budget,
            storage_reservation=("ctfd:unknown", "owner-one", "workspace-one", "challenge-one"),
        )
    assert destination.read_bytes() == b""
    assert budget.snapshot(kind="ctfd") == []


def test_rate_limit_stops_further_read_requests_without_retrying():
    mock = MockTransport(routes())
    mock.routes["https://ctf.example/api/v1/challenges/1"] = Response(429, {"retry-after": "30"}, b"private upstream body")
    client = CTFdClient("ctf.example", resolver=public_dns, transport=mock)
    preview = client.preview()
    assert "30 seconds" in preview["errors"][0]["message"]
    assert len(mock.requests) == 2
    with pytest.raises(CTFdError, match="rate limited"):
        client.download("https://cdn.example/task.dat")
    assert len(mock.requests) == 2
