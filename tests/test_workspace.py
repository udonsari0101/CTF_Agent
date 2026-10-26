"""Workspace behavior and boundary tests, entirely in-process with temporary data."""

import asyncio
import hashlib
import json
import sqlite3
import time
from urllib.parse import unquote

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from ctf_agent.db import SCHEMA, Settings, connect, initialize
from ctf_agent.flag_formats import normalize_flag_format
from ctf_agent.main import BodySizeLimit, create_app, validate_filename


PASSWORD = "workspace-test-password"


def test_body_gate_rejects_unauthenticated_stream_before_reading_it():
    called = []
    sent = []

    async def inner(_scope, _receive, _send):
        called.append("inner")

    async def receive():
        called.append("receive")
        raise AssertionError("unauthenticated body must not be read")

    async def send(message):
        sent.append(message)

    middleware = BodySizeLimit(
        inner,
        max_bytes=1024,
        chunk_bytes=2048,
        authorize=lambda _scope: (401, "Authentication required"),
    )
    scope = {
        "type": "http",
        "method": "PUT",
        "path": "/api/uploads/unknown/chunks",
        "headers": [],
    }
    asyncio.run(middleware(scope, receive, send))
    assert called == []
    assert sent[0]["status"] == 401


def test_zero_length_mutation_holds_body_gate_until_endpoint_finishes():
    observed = []
    sent = []
    middleware = None

    async def inner(_scope, receive, send):
        observed.append(middleware.body_gate.locked())
        assert (await receive())["body"] == b""
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    middleware = BodySizeLimit(inner, max_bytes=1024, concurrent_bodies=1)
    scope = {
        "type": "http", "method": "POST", "path": "/api/resource/finalize",
        "headers": [(b"content-length", b"0")],
    }
    asyncio.run(middleware(scope, receive, send))
    assert observed == [True] and sent[0]["status"] == 204
    assert not middleware.body_gate.locked()


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs")
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post("/api/auth/login", json={"password": PASSWORD})
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        yield client, app, settings


def workspace(client, name="Practice CTF"):
    response = client.post("/api/workspaces", json={"name": name})
    assert response.status_code == 201
    return response.json()


def challenge(client, workspace_id, name="Example problem", **fields):
    response = client.post(f"/api/workspaces/{workspace_id}/challenges", json={"name": name, **fields})
    assert response.status_code == 201
    return response.json()


def test_bad_direct_markdown_edit_is_reported_without_blocking_the_app(web):
    client, app, _settings = web
    area = workspace(client, "Readable artifacts")
    problem = challenge(client, area["id"], name="Broken notes")
    notes = app.state.storage_layout.challenge_path(
        area["id"], problem["id"]
    ) / "notes.md"
    notes.write_bytes(b"\xff\xfe")
    response = client.get(base(area["id"], problem["id"]))
    assert response.status_code == 409
    assert "notes.md" in response.json()["detail"]
    assert "UTF-8" in response.json()["detail"]
    assert client.get("/api/workspaces").status_code == 200


def base(workspace_id, challenge_id):
    return f"/api/workspaces/{workspace_id}/challenges/{challenge_id}"


@pytest.mark.parametrize(
    ("entered", "expected"),
    [
        (None, None),
        ("", ""),
        ("HeXA", "HeXA{...}"),
        ("  picoCTF_2026  ", "picoCTF_2026{...}"),
        ("HeXA{...}", "HeXA{...}"),
        ("HeXA{example_flag}", "HeXA{example_flag}"),
        (r"^HeXA\{[0-9a-f]+\}$", r"^HeXA\{[0-9a-f]+\}$"),
        ("예: HeXA{...} 또는 FLAG[...]", "예: HeXA{...} 또는 FLAG[...]"),
    ],
)
def test_flag_format_prefix_shorthand_preserves_explicit_formats(entered, expected):
    assert normalize_flag_format(entered) == expected


def test_workspace_flag_prefix_is_canonical_for_manual_challenges_and_edits(web):
    client, _, settings = web
    created = client.post(
        "/api/workspaces",
        json={"name": "Prefix CTF", "flag_format": "HeXA"},
    )
    assert created.status_code == 201
    area = created.json()
    assert area["flag_format"] == "HeXA{...}"

    problem = challenge(client, area["id"], name="Manual challenge")
    assert problem["status"] == "pending"
    assert client.get(f"/api/workspaces/{area['id']}").json()["flag_format"] == "HeXA{...}"
    with connect(settings) as db:
        assert db.execute(
            "SELECT flag_format FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0] == "HeXA{...}"

    edited = client.patch(
        f"/api/workspaces/{area['id']}",
        headers={"If-Match": area["edit_token"]},
        json={"flag_format": "SARI"},
    )
    assert edited.status_code == 200
    assert edited.json()["flag_format"] == "SARI{...}"

    preserved = client.patch(
        f"/api/workspaces/{area['id']}",
        json={"flag_format": r"^SARI\{[A-Za-z0-9_]+\}$"},
    )
    assert preserved.status_code == 200
    assert preserved.json()["flag_format"] == r"^SARI\{[A-Za-z0-9_]+\}$"


def test_workspace_controls_whether_new_challenge_detail_opens(web):
    client, _, settings = web
    created = client.post(
        "/api/workspaces",
        json={
            "name": "Popup preference",
            "open_challenge_after_create": True,
        },
    )
    assert created.status_code == 201
    area = created.json()
    assert area["open_challenge_after_create"] is True
    with connect(settings) as db:
        assert db.execute(
            "SELECT open_challenge_after_create FROM workspaces WHERE id=?",
            (area["id"],),
        ).fetchone()[0] == 1

    updated = client.patch(
        f"/api/workspaces/{area['id']}",
        headers={"If-Match": area["edit_token"]},
        json={"open_challenge_after_create": False},
    )
    assert updated.status_code == 200
    assert updated.json()["open_challenge_after_create"] is False
    assert updated.json()["edit_token"] != area["edit_token"]
    assert client.patch(
        f"/api/workspaces/{area['id']}",
        json={"open_challenge_after_create": None},
    ).status_code == 422


def test_challenge_list_includes_only_owners_latest_solver_summary(web):
    client, _, settings = web
    area = workspace(client, "Card metadata")
    problem = challenge(client, area["id"], name="Latest run")
    with connect(settings) as db:
        owner = db.execute(
            "SELECT owner_user_id FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0]
        rows = (
            (
                "1" * 32,
                owner,
                "a" * 32,
                "Older account",
                "gpt-5.6-sol",
                "completed",
                1.0,
            ),
            (
                "2" * 32,
                owner,
                "b" * 32,
                "Challenge account",
                "gpt-daybreak-blue-latest",
                "failed",
                2.0,
            ),
            (
                "3" * 32,
                "f" * 32,
                "c" * 32,
                "Foreign account",
                "foreign-model",
                "completed",
                3.0,
            ),
        )
        for job_id, job_owner, account_id, label, model, status, created_at in rows:
            db.execute(
                """INSERT INTO solver_jobs(
                       id,owner_user_id,workspace_id,challenge_id,account_id,
                       account_label,provider,model,reasoning_effort,service_tier,
                       status,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,'codex',?,'xhigh',NULL,?,?,?)""",
                (
                    job_id,
                    job_owner,
                    area["id"],
                    problem["id"],
                    account_id,
                    label,
                    model,
                    status,
                    created_at,
                    created_at,
                ),
            )

    listing = client.get(f"/api/workspaces/{area['id']}/challenges")
    assert listing.status_code == 200
    summary = listing.json()["challenges"][0]["latest_solver"]
    assert summary == {
        "account_label": "Challenge account",
        "status": "failed",
        "configuration": {
            "provider": "codex",
            "model": "gpt-daybreak-blue-latest",
            "reasoning_effort": "xhigh",
            "service_tier": None,
        },
    }


def test_completed_challenge_list_includes_time_to_flag(web):
    client, _, settings = web
    area = workspace(client, "Solve timing")
    problem = challenge(client, area["id"], name="Timed run")
    job_id = "5" * 32
    with connect(settings) as db:
        owner = db.execute(
            "SELECT owner_user_id FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0]
        db.execute(
            """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,
                   account_label,provider,model,reasoning_effort,status,
                   created_at,updated_at,released_at
               ) VALUES(?,?,?,?,?,?,'codex','gpt-5.6-sol','xhigh',
                        'completed',100,200,200)""",
            (job_id, owner, area["id"], problem["id"], "a" * 32, "Timed"),
        )
        db.executemany(
            """INSERT INTO solver_job_events(job_id,sequence,kind,event_json,created_at)
               VALUES(?,?,?,?,?)""",
            (
                (
                    job_id,
                    1,
                    "status",
                    json.dumps({"status": "running"}),
                    120,
                ),
                (job_id, 2, "flag", json.dumps({"flag": "FLAG{timed}"}), 165),
            ),
        )
        db.execute(
            """UPDATE challenges
                  SET status='solved',completion_source='agent',flag='FLAG{timed}'
                WHERE id=?""",
            (problem["id"],),
        )

    listed = client.get(f"/api/workspaces/{area['id']}/challenges").json()
    latest = listed["challenges"][0]["latest_solver"]
    assert latest["elapsed_seconds"] == 45
    assert latest["elapsed_includes_queue"] is False


def test_generation_two_database_migrates_remote_column_and_solver_generation(tmp_path):
    settings = Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs"
    )
    settings.db_dir.mkdir(parents=True)
    old_schema = SCHEMA.replace(", remote TEXT NOT NULL DEFAULT ''", "")
    assert old_schema != SCHEMA
    with sqlite3.connect(settings.database_path) as db:
        db.executescript(old_schema)
        db.execute("INSERT INTO meta(key,value) VALUES('schema_version','2')")

    initialize(settings)

    with connect(settings) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(challenges)")}
        assert "remote" in columns
        assert db.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"


def test_manual_challenge_remote_is_normalized_editable_and_concurrency_protected(web):
    client, _, _ = web
    area = workspace(client)
    problem = challenge(
        client,
        area["id"],
        remote="  nc target.example 31337\n  ",
    )
    assert problem["remote"] == "nc target.example 31337"
    assert problem["remote_mode"] == "endpoint"
    detail = client.get(base(area["id"], problem["id"]))
    listing = client.get(f"/api/workspaces/{area['id']}/challenges")
    assert detail.status_code == listing.status_code == 200
    assert detail.json()["remote"] == "nc target.example 31337"
    assert listing.json()["challenges"][0]["remote"] == "nc target.example 31337"

    edited = client.patch(
        base(area["id"], problem["id"]),
        headers={"If-Match": problem["edit_token"]},
        json={"remote": "https://target.example/play"},
    )
    assert edited.status_code == 200
    assert edited.json()["remote"] == "https://target.example/play"
    assert edited.json()["remote_mode"] == "endpoint"
    assert edited.json()["edit_token"] != problem["edit_token"]
    stale = client.patch(
        base(area["id"], problem["id"]),
        headers={"If-Match": problem["edit_token"]},
        json={"description": "stale edit"},
    )
    assert stale.status_code == 409

    invalid = client.post(
        f"/api/workspaces/{area['id']}/challenges",
        json={"name": "unsafe", "remote": "target.example:1\u0000hidden"},
    )
    assert invalid.status_code == 422


def test_remote_mode_distinguishes_unknown_none_and_endpoint(web):
    client, _, _ = web
    area = workspace(client)
    unknown = challenge(client, area["id"], name="Unknown remote")
    assert unknown["remote_mode"] == "unknown" and unknown["remote"] == ""

    no_server = challenge(
        client, area["id"], name="Static", remote_mode="none", remote=""
    )
    assert no_server["remote_mode"] == "none" and no_server["remote"] == ""

    endpoint = challenge(
        client,
        area["id"],
        name="Service",
        remote_mode="endpoint",
        remote="nc target.example 31337",
    )
    assert endpoint["remote_mode"] == "endpoint"

    for payload in (
        {"name": "missing", "remote_mode": "endpoint", "remote": ""},
        {"name": "contradiction", "remote_mode": "none", "remote": "nc x.example 1"},
        {"name": "null", "remote_mode": None},
    ):
        assert client.post(
            f"/api/workspaces/{area['id']}/challenges", json=payload
        ).status_code == 422


def test_remote_mode_migration_preserves_legacy_uncertainty_and_known_endpoint(tmp_path):
    settings = Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs"
    )
    settings.db_dir.mkdir(parents=True)
    old_schema = SCHEMA.replace(
        "    remote_mode TEXT NOT NULL DEFAULT 'unknown' CHECK(remote_mode IN ('unknown','none','endpoint')),\n",
        "",
    )
    with sqlite3.connect(settings.database_path) as db:
        db.executescript(old_schema)
        db.execute("INSERT INTO meta(key,value) VALUES('schema_version','2')")
        db.execute(
            "INSERT INTO workspaces(id,name,created_at,updated_at) VALUES('w','W','t','t')"
        )
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,remote,created_at,updated_at) VALUES('a','w','A','','t','t')"
        )
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,remote,created_at,updated_at) VALUES('b','w','B','nc example.test 1','t','t')"
        )
        db.execute(
            """INSERT INTO challenges
               (id,workspace_id,name,remote,ctfd_id,ctfd_url,created_at,updated_at)
               VALUES('c','w','C','',28,'https://ctf.example','t','t')"""
        )

    initialize(settings)

    with connect(settings) as db:
        modes = dict(db.execute("SELECT id,remote_mode FROM challenges ORDER BY id"))
    assert modes == {"a": "unknown", "b": "endpoint", "c": "none"}

    # The compatibility correction is intentionally one-shot.  A user can
    # later mark an imported challenge unknown when its description contains
    # an out-of-band endpoint without the next restart overwriting that edit.
    with connect(settings) as db:
        db.execute("UPDATE challenges SET remote_mode='unknown' WHERE id='c'")
    initialize(settings)
    with connect(settings) as db:
        assert db.execute(
            "SELECT remote_mode FROM challenges WHERE id='c'"
        ).fetchone()[0] == "unknown"


def upload_attachment(client, route, name, content):
    initialized = client.post(
        route + "/uploads",
        json={"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()},
    )
    assert initialized.status_code == 201, initialized.text
    upload = initialized.json()
    if content:
        chunk = client.put(
            f"/api/uploads/{upload['id']}/chunks?offset=0",
            content=content,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert chunk.status_code == 200, chunk.text
    finalized = client.post(f"/api/uploads/{upload['id']}/finalize")
    assert finalized.status_code == 200, finalized.text
    return {"id": finalized.json()["attachment_id"], "original_name": name, "size": len(content)}


def test_optional_flags_can_be_added_later(web):
    client, _, _ = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    assert area["flag_format"] is None and problem["flag"] is None
    edited = client.patch(f"/api/workspaces/{area['id']}", json={"name": area["name"], "flag_format": "CTF{...}"})
    assert edited.status_code == 200 and edited.json()["flag_format"] == "CTF{...}"
    edited = client.patch(base(area["id"], problem["id"]), json={"name": problem["name"], "flag": "CTF{test-result}"})
    assert edited.status_code == 200 and edited.json()["flag"] == "CTF{test-result}"
    assert edited.json()["status"] == "flag_found"


def test_committed_flag_reaches_telegram_before_optional_ctfd_submission(web):
    client, app, settings = web
    area = workspace(client)
    events = []

    def telegram(owner, workspace_id, challenge_id, flag):
        with connect(settings) as db:
            stored = db.execute("SELECT flag,status FROM challenges WHERE id=?", (challenge_id,)).fetchone()
        assert tuple(stored) == (flag, "flag_found")
        events.append(("telegram", owner, workspace_id, challenge_id, flag))
        return True

    def submit(owner, workspace_id, challenge_id, flag, source):
        events.append(("ctfd", owner, workspace_id, challenge_id, flag, source))
        return True

    app.state.telegram_flag_found = telegram
    app.state.ctfd_auto_submit_flag = submit
    problem = challenge(client, area["id"], flag="CTF{first}")
    assert [event[0] for event in events] == ["telegram", "ctfd"]
    assert events[1][-1] == "manual"
    events.clear()
    same = client.patch(base(area["id"], problem["id"]), json={"flag": "CTF{first}"})
    assert same.status_code == 200 and events == []
    changed = client.patch(base(area["id"], problem["id"]), json={"flag": "CTF{second}"})
    assert changed.status_code == 200
    assert [event[0] for event in events] == ["telegram", "ctfd"]


def test_same_names_have_isolated_workspaces_problems_and_files(web):
    client, _, settings = web
    first, second = workspace(client, "Same CTF"), workspace(client, "Same CTF")
    a, b = challenge(client, first["id"], "Same problem"), challenge(client, second["id"], "Same problem")
    assert first["id"] != second["id"] and a["id"] != b["id"]
    pa, pb = base(first["id"], a["id"]), base(second["id"], b["id"])
    fa = upload_attachment(client, pa, "same.bin", b"first")
    fb = upload_attachment(client, pb, "same.bin", b"second")
    assert client.get(pa + "/attachments/" + fa["id"]).content == b"first"
    assert client.get(pb + "/attachments/" + fb["id"]).content == b"second"
    assert client.get(pb + "/attachments/" + fa["id"]).status_code == 404
    wrong = base(second["id"], a["id"])
    assert client.get(wrong).status_code == 404
    assert client.patch(wrong, json={"name": "Changed"}).status_code == 404
    assert client.put(wrong + "/notes", json={"content": "Changed"}).status_code == 404
    assert client.post(wrong + "/complete").status_code == 404
    assert client.post(wrong + "/attachments", files={"file": ("file.bin", b"wrong")}).status_code == 404
    assert client.delete(wrong).status_code == 404
    assert client.get(pa).json()["notes"] == ""
    assert client.delete(f"/api/workspaces/{first['id']}").status_code == 200
    assert not (settings.data_dir / "workspaces" / first["id"]).exists()
    assert client.get(pb + "/attachments/" + fb["id"]).content == b"second"


def test_challenge_clone_copies_inputs_and_resets_solution_state(web):
    client, _, settings = web
    area = workspace(client, "Clone CTF")
    source = challenge(
        client,
        area["id"],
        name="Token Guard",
        category="web",
        description="Find the token.",
        remote_mode="endpoint",
        remote="https://challenge.example",
        flag="FLAG{source}",
    )
    source_route = base(area["id"], source["id"])
    assert client.put(source_route + "/notes", json={"content": "# Source notes"}).status_code == 200
    assert client.post(source_route + "/complete").status_code == 200
    first_file = upload_attachment(client, source_route, "token-guard.zip", b"archive bytes")
    empty_file = upload_attachment(client, source_route, "empty.txt", b"")
    with connect(settings) as db:
        db.execute(
            "UPDATE challenges SET ctfd_id=?,ctfd_url=? WHERE id=?",
            (7, "https://ctf.example", source["id"]),
        )

    response = client.post(source_route + "/clone")
    assert response.status_code == 201, response.text
    cloned = response.json()
    clone_route = base(area["id"], cloned["id"])
    assert cloned["id"] != source["id"]
    assert cloned["name"] == "Token Guard 복사본"
    assert {
        key: cloned[key]
        for key in ("category", "description", "remote_mode", "remote")
    } == {
        "category": "web",
        "description": "Find the token.",
        "remote_mode": "endpoint",
        "remote": "https://challenge.example",
    }
    assert cloned["status"] == "pending"
    assert cloned["previous_status"] is None
    assert cloned["completion_source"] is None
    assert cloned["flag"] is None
    assert cloned["notes"] == ""
    assert cloned["ctfd_id"] is None and cloned["ctfd_url"] is None
    assert cloned["has_writeup"] is False and cloned["writeup_markdown"] is None
    cloned_files = {item["original_name"]: item for item in cloned["attachments"]}
    assert {name: item["size"] for name, item in cloned_files.items()} == {
        "token-guard.zip": len(b"archive bytes"),
        "empty.txt": 0,
    }
    assert {item["id"] for item in cloned["attachments"]}.isdisjoint(
        {first_file["id"], empty_file["id"]}
    )
    assert client.get(
        clone_route + "/attachments/" + cloned_files["token-guard.zip"]["id"]
    ).content == b"archive bytes"
    assert client.get(
        clone_route + "/attachments/" + cloned_files["empty.txt"]["id"]
    ).content == b""

    with connect(settings) as db:
        source_stored = db.execute(
            "SELECT stored_name FROM attachments WHERE id=?", (first_file["id"],)
        ).fetchone()[0]
        clone_stored = db.execute(
            "SELECT stored_name FROM attachments WHERE id=?",
            (cloned_files["token-guard.zip"]["id"],),
        ).fetchone()[0]
        assert db.execute(
            "SELECT COUNT(*) FROM storage_reservations WHERE kind='challenge_clone'"
        ).fetchone()[0] == 0
    source_file = (
        settings.data_dir / "workspaces" / area["id"] / "challenges"
        / source["id"] / "attachments" / source_stored
    )
    clone_file = (
        settings.data_dir / "workspaces" / area["id"] / "challenges"
        / cloned["id"] / "attachments" / clone_stored
    )
    clone_file.write_bytes(b"independent copy")
    assert source_file.read_bytes() == b"archive bytes"
    assert client.get(source_route + "/attachments/" + first_file["id"]).content == b"archive bytes"

    original = client.get(source_route).json()
    assert original["status"] == "solved"
    assert original["completion_source"] == "manual"
    assert original["flag"] == "FLAG{source}"
    assert original["notes"] == "# Source notes"
    second = client.post(source_route + "/clone")
    assert second.status_code == 201
    assert second.json()["name"] == "Token Guard 복사본 (2)"


@pytest.mark.parametrize("filename", ["../outside.txt", "nested/file.txt", "..\\outside.txt", ".", "..", "line\nname", "name\x00.txt"])
def test_attachment_filename_validation_rejects_paths_and_controls(filename):
    with pytest.raises(HTTPException):
        validate_filename(filename)


def test_upload_download_filename_and_size_cleanup(web):
    client, _, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    path = base(area["id"], problem["id"])
    uploaded = upload_attachment(client, path, "한글 문제.zip", b"opaque archive bytes")
    attachment_id = uploaded["id"]
    downloaded = client.get(path + "/attachments/" + attachment_id)
    assert downloaded.content == b"opaque archive bytes"
    assert "한글 문제.zip" in unquote(downloaded.headers["content-disposition"])
    assert downloaded.headers["content-type"] == "application/octet-stream"
    retired = client.post(path + "/attachments", files={"file": ("old-client.bin", b"x")})
    assert retired.status_code == 410 and "이어 올리기" in retired.json()["detail"]
    attachments = client.get(path).json()["attachments"]
    assert [item["id"] for item in attachments] == [attachment_id]
    saved = list((settings.data_dir / "workspaces" / area["id"] / "challenges" / problem["id"] / "attachments").iterdir())
    assert len(saved) == 1 and saved[0].name != "한글 문제.zip"
    assert client.delete(path + "/attachments/" + attachment_id).status_code == 200
    assert client.get(path + "/attachments/" + attachment_id).status_code == 404


def test_attachment_delete_waits_until_solver_snapshot_is_closed(web, monkeypatch):
    client, app, _ = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    route = base(area["id"], problem["id"])
    attachment = upload_attachment(client, route, "race.bin", b"immutable solver input")
    endpoint = route + "/attachments/" + attachment["id"]

    monkeypatch.setattr(
        app.state.solver_jobs,
        "has_open_challenge",
        lambda owner, workspace_id, challenge_id, connection=None: True,
    )
    assert client.delete(endpoint).status_code == 409
    assert client.get(endpoint).content == b"immutable solver input"

    monkeypatch.setattr(
        app.state.solver_jobs,
        "has_open_challenge",
        lambda owner, workspace_id, challenge_id, connection=None: False,
    )
    assert client.delete(endpoint).status_code == 200


def test_metadata_and_attachment_mutations_cannot_cross_active_ctfd_refresh(web):
    client, _app, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    route = base(area["id"], problem["id"])
    attachment = upload_attachment(client, route, "manual.bin", b"manual bytes")
    current = client.get(route).json()
    with connect(settings) as db:
        owner = db.execute(
            "SELECT owner_user_id FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0]
        db.execute(
            """INSERT INTO ctfd_jobs
               (id,owner_user_id,workspace_id,source_url,auth_type,mode,
                target_challenge_id,status,created_at,updated_at)
               VALUES('refresh-mutation-race',?,?,?,'none','refresh',?,'running',?,?)""",
            (owner, area["id"], "https://ctf.example", problem["id"], "now", "now"),
        )

    edited = client.patch(
        route, json={"description": "lost update"},
        headers={"If-Match": current["edit_token"]},
    )
    assert edited.status_code == 409
    assert client.delete(route + "/attachments/" + attachment["id"]).status_code == 409
    assert client.get(route + "/attachments/" + attachment["id"]).content == b"manual bytes"

    # Flag/state fields are not replaced by refresh publication and remain
    # available while a large remote attachment is downloading.
    flag = client.patch(
        route, json={"flag": "CTF{during_refresh}"},
        headers={"If-Match": current["edit_token"]},
    )
    assert flag.status_code == 200
    assert flag.json()["flag"] == "CTF{during_refresh}"

    with connect(settings) as db:
        db.execute(
            "UPDATE ctfd_jobs SET status='completed' WHERE id='refresh-mutation-race'"
        )
    latest = client.get(route).json()
    assert client.patch(
        route, json={"description": "after refresh"},
        headers={"If-Match": latest["edit_token"]},
    ).status_code == 200
    assert client.delete(route + "/attachments/" + attachment["id"]).status_code == 200


def test_failed_challenge_delete_releases_ctfd_submission_tombstone(web, monkeypatch):
    client, app, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    route = base(area["id"], problem["id"])

    monkeypatch.setattr(app.state.solver_jobs, "cancel_challenge", lambda *_args: True)
    monkeypatch.setattr(
        app.state.solver_jobs,
        "has_open_challenge",
        lambda *_args, **_kwargs: True,
    )
    response = client.delete(route)
    assert response.status_code == 409
    with connect(settings) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_submit_blocks WHERE workspace_id=? AND challenge_id=?",
            (area["id"], problem["id"]),
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT 1 FROM challenges WHERE workspace_id=? AND id=?",
            (area["id"], problem["id"]),
        ).fetchone() is not None


def test_challenge_delete_waits_for_running_solver_cleanup(web, monkeypatch):
    client, app, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    route = base(area["id"], problem["id"])
    calls = []

    def cancel_solver(workspace_id, challenge_id, owner_id):
        calls.append((workspace_id, challenge_id, owner_id))
        return len(calls) > 1

    monkeypatch.setattr(app.state.solver_jobs, "cancel_challenge", cancel_solver)
    monkeypatch.setattr(
        app.state.solver_jobs,
        "has_open_challenge",
        lambda *_args, **_kwargs: False,
    )

    stopping = client.delete(route)
    assert stopping.status_code == 409
    assert "격리 정리 중" in stopping.json()["detail"]
    with connect(settings) as db:
        assert db.execute(
            "SELECT 1 FROM challenges WHERE workspace_id=? AND id=?",
            (area["id"], problem["id"]),
        ).fetchone() is not None

    deleted = client.delete(route)
    assert deleted.status_code == 200
    assert client.get(route).status_code == 404
    assert len(calls) == 2


def test_failed_workspace_delete_releases_ctfd_submission_tombstones(web, monkeypatch):
    client, app, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])

    monkeypatch.setattr(app.state.solver_jobs, "cancel_workspace", lambda *_args: True)
    monkeypatch.setattr(
        app.state.solver_jobs,
        "has_open_workspace",
        lambda *_args, **_kwargs: True,
    )
    response = client.delete(f"/api/workspaces/{area['id']}")
    assert response.status_code == 409
    with connect(settings) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM ctfd_submit_blocks WHERE workspace_id=?",
            (area["id"],),
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT 1 FROM challenges WHERE workspace_id=? AND id=?",
            (area["id"], problem["id"]),
        ).fetchone() is not None


@pytest.mark.parametrize("claimed_length", [None, "10"])
def test_retired_multipart_returns_410_without_spooling_body(web, claimed_length):
    client, _, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    path = base(area["id"], problem["id"])
    yielded = [0]
    def content():
        yielded[0] += 1
        yield b'--test-boundary\r\nContent-Disposition: form-data; name="file"; filename="test.bin"\r\n\r\n'
        for _ in range(48):
            yielded[0] += 1
            yield b"x" * 65536
        yielded[0] += 1
        yield b"\r\n--test-boundary--\r\n"
    headers = {"content-type": "multipart/form-data; boundary=test-boundary"}
    if claimed_length:
        headers["content-length"] = claimed_length
    response = client.post(path + "/attachments", content=content(), headers=headers)
    assert response.status_code == 410 and "이어 올리기" in response.json()["detail"]
    assert yielded[0] == 0
    assert client.get(path).json()["attachments"] == []
    directory = settings.data_dir / "workspaces" / area["id"] / "challenges" / problem["id"] / "attachments"
    assert not directory.exists() or not list(directory.iterdir())


def test_manual_completion_is_idempotent_and_reopen_restores_status(web):
    client, _, _ = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    path = base(area["id"], problem["id"])
    assert client.patch(path + "/status", json={"status": "stopped"}).status_code == 200
    assert client.put(path + "/notes", json={"content": "Manual notes"}).status_code == 200
    first = client.post(path + "/complete").json()
    second = client.post(path + "/complete").json()
    assert first["status"] == second["status"] == "solved"
    assert first["previous_status"] == second["previous_status"] == "stopped"
    assert first["completion_source"] == second["completion_source"] == "manual"
    assert second["notes"] == "Manual notes"
    assert client.patch(path + "/status", json={"status": "running"}).status_code == 409
    reopened = client.post(path + "/reopen").json()
    assert reopened["status"] == "stopped" and reopened["completion_source"] is None
    assert reopened["notes"] == "Manual notes"
    assert client.post(path + "/reopen").status_code == 409
    assert client.patch(path + "/status", json={"status": "solved"}).status_code == 422


def test_manual_completion_does_not_create_agent_writeup(web):
    client, _, settings = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    path = base(area["id"], problem["id"])
    result = client.post(path + "/complete").json()
    assert result["completion_source"] == "manual" and result["notes"] == ""
    assert not list(settings.data_dir.rglob("writeups"))
    assert client.post(path + "/reopen").json()["status"] == "pending"


def test_notes_utf8_download_and_unsupported_upload_formats(web):
    client, _, _ = web
    area = workspace(client)
    problem = challenge(client, area["id"], "한글: 문제")
    path = base(area["id"], problem["id"])
    content = "# 한글 문제\n\n직접 작성한 기록.\n\n```text\nresult\n```\n"
    assert client.put(path + "/notes", json={"content": content}).status_code == 200
    downloaded = client.get(path + "/notes/download")
    assert downloaded.content.decode("utf-8") == content
    assert downloaded.headers["content-type"].startswith("text/markdown")
    assert "한글_ 문제-notes.md" in unquote(downloaded.headers["content-disposition"])
    replacement = "# 새 기록\n"
    assert client.post(path + "/notes/upload", files={"file": ("기록.md", replacement.encode("utf-8-sig"))}).status_code == 200
    assert client.get(path).json()["notes"] == replacement
    assert client.post(path + "/notes/upload", files={"file": ("notes.pdf", b"pdf")}).status_code == 400
    assert client.post(path + "/notes/upload", files={"file": ("notes.md", b"\xff\xfe\x00")}).status_code == 400
    assert client.get(path).json()["notes"] == replacement


def test_filters_counts_and_categories_are_workspace_scoped(web):
    client, _, _ = web
    area, other = workspace(client), workspace(client)
    alpha = challenge(client, area["id"], "Alpha", category="web")
    beta = challenge(client, area["id"], "Beta", category="crypto", description="searchable description")
    challenge(client, other["id"], "Alpha other", category="other")
    client.patch(base(area["id"], alpha["id"]) + "/status", json={"status": "running"})
    client.post(base(area["id"], beta["id"]) + "/complete")
    endpoint = f"/api/workspaces/{area['id']}/challenges"
    result = client.get(endpoint, params={"status": "running", "category": "web", "q": "alpha"}).json()
    assert [item["id"] for item in result["challenges"]] == [alpha["id"]]
    assert result["counts"]["running"] == 1 and result["counts"]["solved"] == 1
    assert result["categories"] == ["crypto", "web"]
    assert client.get(endpoint, params={"q": "searchable"}).json()["challenges"][0]["id"] == beta["id"]
    assert client.get(endpoint, params={"status": "invented"}).status_code == 400
    overview = client.get("/api/workspaces").json()["workspaces"]
    selected = next(item for item in overview if item["id"] == area["id"])
    assert selected["challenge_count"] == 2 and selected["solved_count"] == 1 and selected["running_count"] == 1


def test_challenge_sorting_is_stable_and_owner_scoped(web):
    client, _, settings = web
    area = workspace(client, "Sorted challenges")
    zulu = challenge(client, area["id"], "Zulu")
    alpha = challenge(client, area["id"], "alpha")
    beta = challenge(client, area["id"], "Beta")
    with connect(settings) as db:
        owner = db.execute(
            "SELECT owner_user_id FROM workspaces WHERE id=?", (area["id"],)
        ).fetchone()[0]
        for challenge_id, created_at in (
            (zulu["id"], "2026-01-01T00:00:00+00:00"),
            (alpha["id"], "2026-01-02T00:00:00+00:00"),
            (beta["id"], "2026-01-03T00:00:00+00:00"),
        ):
            db.execute(
                "UPDATE challenges SET created_at=? WHERE id=?",
                (created_at, challenge_id),
            )
        runs = (
            ("1" * 32, owner, zulu["id"], "solve", 10.0),
            ("2" * 32, owner, alpha["id"], "solve", 20.0),
            # A write-up run and another user's run must not change solve order.
            ("3" * 32, owner, beta["id"], "writeup_refine", 30.0),
            ("4" * 32, "f" * 32, beta["id"], "solve", 99.0),
        )
        for job_id, job_owner, challenge_id, mode, created_at in runs:
            db.execute(
                """INSERT INTO solver_jobs(
                       id,job_mode,owner_user_id,workspace_id,challenge_id,
                       account_id,account_label,provider,model,reasoning_effort,
                       status,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,'Account','codex','gpt-5.6-sol',
                            'xhigh','completed',?,?)""",
                (
                    job_id,
                    mode,
                    job_owner,
                    area["id"],
                    challenge_id,
                    job_id,
                    created_at,
                    created_at,
                ),
            )

    endpoint = f"/api/workspaces/{area['id']}/challenges"

    def names(sort):
        response = client.get(endpoint, params={"sort": sort})
        assert response.status_code == 200, response.text
        return [item["name"] for item in response.json()["challenges"]]

    assert names("added_desc") == ["Beta", "alpha", "Zulu"]
    assert names("added_asc") == ["Zulu", "alpha", "Beta"]
    assert names("name_asc") == ["alpha", "Beta", "Zulu"]
    assert names("name_desc") == ["Zulu", "Beta", "alpha"]
    assert names("solver_desc") == ["alpha", "Zulu", "Beta"]
    assert names("solver_asc") == ["Zulu", "alpha", "Beta"]
    assert client.get(endpoint, params={"sort": "raw sql"}).status_code == 400


def test_auth_csrf_rate_limit_and_validation_redaction(web):
    client, _, settings = web
    saved_csrf = client.headers.pop("X-CSRF-Token")
    assert client.post("/api/workspaces", json={"name": "Denied"}).status_code == 403
    client.headers["X-CSRF-Token"] = saved_csrf
    assert client.post("/api/workspaces", json={"name": "Denied"}, headers={"Origin": "https://other.example"}).status_code == 403
    sensitive = "validation-secret-" * 80
    response = client.post("/api/auth/login", json={"password": sensitive})
    assert response.status_code == 422 and sensitive not in response.text
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/workspaces").status_code == 401
    for _ in range(10):
        assert client.post("/api/auth/login", json={"password": "incorrect"}).status_code == 401
    assert client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 429
    db = connect(settings)
    try:
        with db:
            db.execute("UPDATE login_attempts SET attempted_at=?", (int(time.time()) - 301,))
    finally:
        db.close()
    assert client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 200


def test_cloudflare_visitor_ip_keeps_login_limits_per_real_client(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    monkeypatch.setattr("ctf_agent.main.password_matches", lambda raw, _encoded: raw == PASSWORD)
    settings = Settings(
        tmp_path / "data", tmp_path / "db", tmp_path / "config", tmp_path / "logs",
        trust_cf_connecting_ip=True,
    )
    app = create_app(settings)
    first = {"CF-Connecting-IP": "198.51.100.10"}
    second = {"CF-Connecting-IP": "198.51.100.11"}
    third = {"CF-Connecting-IP": "198.51.100.12"}
    with TestClient(app) as client:
        assert client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 400
        assert client.post(
            "/api/auth/login", json={"password": PASSWORD},
            headers={"CF-Connecting-IP": "198.51.100.10, 198.51.100.11"},
        ).status_code == 400
        # Cycling requested usernames must not bypass the visitor-wide CPU and
        # login-attempt allowance.
        for index in range(10):
            assert client.post(
                "/api/auth/login",
                json={"username": f"unknown-{index}", "password": "incorrect"},
                headers=first,
            ).status_code == 401
        assert client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}, headers=first,
        ).status_code == 429
        assert client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}, headers=second,
        ).status_code == 200
        for index in range(5):
            assert client.post(
                "/api/auth/login",
                json={"username": f"before-success-{index}", "password": "incorrect"},
                headers=third,
            ).status_code == 401
        assert client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}, headers=third,
        ).status_code == 200
        for index in range(5):
            assert client.post(
                "/api/auth/login",
                json={"username": f"after-success-{index}", "password": "incorrect"},
                headers=third,
            ).status_code == 401
        assert client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}, headers=third,
        ).status_code == 429


def test_password_change_preserves_existing_sessions_and_current_csrf(web):
    client, app, _ = web
    with TestClient(app) as another:
        other_login = another.post("/api/auth/login", json={"password": PASSWORD})
        assert other_login.status_code == 200
        another.headers["X-CSRF-Token"] = other_login.json()["csrf_token"]
        old_csrf = client.headers["X-CSRF-Token"]
        response = client.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "updated-test-password"})
        assert response.status_code == 200 and response.json()["csrf_token"] == old_csrf
        assert another.get("/api/workspaces").status_code == 200
        assert another.post("/api/workspaces", json={"name": "Other browser"}).status_code == 201
        assert client.post("/api/workspaces", json={"name": "Allowed"}).status_code == 201
        assert client.post("/api/auth/logout").status_code == 200
        assert another.get("/api/workspaces").status_code == 200
        assert client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 401
        assert client.post("/api/auth/login", json={"password": "updated-test-password"}).status_code == 200


def test_public_health_and_auth_state_expose_no_credentials(web, monkeypatch):
    _, app, _ = web
    monkeypatch.setenv("CTF_RELEASE_SHA", "test-release")
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok", "release": "test-release"}
        readiness = client.get("/readyz")
        # The unit fixture intentionally has no isolated PID-1 worker. A web
        # process must stay unready until that mandatory boundary is attested.
        assert readiness.status_code == 503
        assert readiness.json() == {"status": "unavailable"}
        state = client.get("/api/auth/state").json()
        assert state == {
            "auth_mode": "password",
            "authentication_required": True,
            "configured": True,
            "setup_available": False,
            "authenticated": False,
            "csrf_token": None,
            "user": None,
            "username": None,
        }
        assert client.get("/").status_code == 200
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/assets/style.css").status_code == 200


def test_index_uses_release_versioned_assets_to_avoid_stale_edge_cache(
    tmp_path, monkeypatch
):
    release = "a" * 40
    monkeypatch.setenv("CTF_RELEASE_SHA", release)
    monkeypatch.setenv("CTF_BOOTSTRAP_PASSWORD", PASSWORD)
    monkeypatch.delenv("CTF_BOOTSTRAP_PASSWORD_FILE", raising=False)
    settings = Settings(
        tmp_path / "data",
        tmp_path / "db",
        tmp_path / "config",
        tmp_path / "logs",
    )
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        for name in ("icon.svg", "style.css", "accounts.css", "theme.css", "app.js"):
            assert f'/assets/{release}/{name}' in response.text
            assert client.get(f"/assets/{release}/{name}").status_code == 200
        app_source = client.get(f"/assets/{release}/app.js").text
        assert "import {renderAccounts} from './accounts.js';" in app_source
        assert client.get(f"/assets/{release}/accounts.js").status_code == 200
        # Old HTML that was already open remains functional during a deploy.
        assert client.get("/assets/app.js").status_code == 200


def test_conditional_edit_tokens_and_partial_patch_preserve_newer_content(web):
    client, _, _ = web
    area = workspace(client)
    path = f"/api/workspaces/{area['id']}"
    newer = client.patch(path, headers={"If-Match": area["edit_token"]}, json={"description": "new description"}).json()
    assert newer["name"] == area["name"] and newer["description"] == "new description"
    assert newer["edit_token"] != area["edit_token"]
    assert client.patch(path, headers={"If-Match": area["edit_token"]}, json={"flag_format": "stale"}).status_code == 409
    assert client.patch(path, json={"flag_format": "CTF{...}"}).json()["description"] == "new description"
    problem = challenge(client, area["id"], category="crypto", description="original")
    path = base(area["id"], problem["id"])
    assert client.patch(path, json={"flag": "CTF{later}"}, headers={"If-Match": problem["edit_token"]}).status_code == 200
    assert client.patch(path, json={"description": "stale"}, headers={"If-Match": problem["edit_token"]}).status_code == 409
    current = client.get(path).json()
    assert current["category"] == "crypto" and current["description"] == "original"
    saved = client.put(path + "/notes", json={"content": "first version"}, headers={"If-Match": current["notes_token"]})
    assert saved.status_code == 200
    assert client.put(path + "/notes", json={"content": "stale"}, headers={"If-Match": current["notes_token"]}).status_code == 409
    assert client.post(path + "/notes/upload", files={"file": ("stale.md", b"stale")}, headers={"If-Match": current["notes_token"]}).status_code == 409
    assert client.get(path).json()["notes"] == "first version"
    token = saved.json()["notes_token"]
    client.patch(path + "/status", json={"status": "running"})
    assert client.put(path + "/notes", json={"content": "second version"}, headers={"If-Match": token}).status_code == 200
    assert client.patch(path, json={"name": None}).status_code == 422


def test_concurrent_completion_preserves_one_previous_state(web):
    from concurrent.futures import ThreadPoolExecutor
    client, _, _ = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    path = base(area["id"], problem["id"])
    client.patch(path + "/status", json={"status": "stopped"})
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: client.post(path + "/complete"), range(12)))
    assert all(response.status_code == 200 for response in results)
    assert all(response.json()["previous_status"] == "stopped" for response in results)
    assert client.post(path + "/reopen").json()["status"] == "stopped"


def test_manual_challenge_writes_are_rejected_inside_transaction_while_solver_is_open(web, monkeypatch):
    client, app, _ = web
    area = workspace(client)
    problem = challenge(client, area["id"])
    path = base(area["id"], problem["id"])
    observed_transactions = []

    def open_job(owner, workspace_id, challenge_id, *, connection=None):
        observed_transactions.append(bool(connection and connection.in_transaction))
        return True

    monkeypatch.setattr(app.state.solver_jobs, "has_open_challenge", open_job)
    attempts = [
        client.patch(path, json={"flag": "CTF{manual}"}),
        client.patch(path + "/status", json={"status": "running"}),
        client.post(path + "/complete"),
        client.post(path + "/reopen"),
        client.put(path + "/notes", json={"content": "manual draft"}),
        client.post(path + "/notes/upload", files={"file": ("draft.md", b"manual draft")}),
    ]
    assert all(response.status_code == 409 and "풀이" in response.text for response in attempts)
    assert observed_transactions and all(observed_transactions)
    current = client.get(path).json()
    assert current["flag"] is None and current["status"] == "pending" and current["notes"] == ""


def test_workspace_flag_format_change_is_rejected_while_solver_is_open(web, monkeypatch):
    client, app, _ = web
    area = workspace(client)
    observed_transactions = []

    def open_workspace(owner, workspace_id, *, connection=None):
        observed_transactions.append(bool(connection and connection.in_transaction))
        return True

    monkeypatch.setattr(app.state.solver_jobs, "has_open_workspace", open_workspace)
    response = client.patch(
        f"/api/workspaces/{area['id']}",
        json={"flag_format": "NEW{...}"},
    )
    assert response.status_code == 409 and "풀이" in response.text
    assert observed_transactions == [True]
    assert client.get(f"/api/workspaces/{area['id']}").json()["flag_format"] == area["flag_format"]
