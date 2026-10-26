import asyncio
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from urllib.parse import parse_qs, urlsplit

import pytest

from ctf_agent.db import Settings, connect, initialize
from ctf_agent.telegram import (
    TelegramAPIError,
    TelegramService,
    _ensure_notification_outbox,
)


def service_fixture(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        db_dir=tmp_path / "db",
        config_dir=tmp_path / "config",
        log_dir=tmp_path / "logs",
        public_origin="https://ctf-agent.example",
    )
    initialize(settings)

    @contextmanager
    def database():
        connection = connect(settings)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    # Registration normally creates these tables.  Keeping the service unit
    # fixture independent from the web application makes worker tests precise.
    with database() as db:
        db.executescript(
            """
            CREATE TABLE telegram_link_tokens (
                token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL,
                used_at INTEGER,created_at TEXT NOT NULL
            );
            CREATE TABLE telegram_settings (
                user_id TEXT PRIMARY KEY,chat_id INTEGER UNIQUE,enabled INTEGER NOT NULL DEFAULT 0,
                linked_at TEXT,last_success_at TEXT,last_failure_at TEXT,last_failure_code TEXT
            );
            CREATE TABLE notification_outbox (
                id TEXT PRIMARY KEY,event_key TEXT NOT NULL UNIQUE,user_id TEXT NOT NULL,
                event_type TEXT NOT NULL,workspace_id TEXT NOT NULL,challenge_id TEXT NOT NULL,
                job_id TEXT,priority INTEGER NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,claimed_at INTEGER,last_error_code TEXT,
                created_at TEXT NOT NULL,sent_at TEXT
            );
            CREATE TABLE challenge_writeups (
                challenge_id TEXT PRIMARY KEY,markdown TEXT NOT NULL,
                created_at TEXT NOT NULL,updated_at TEXT NOT NULL
            );
            CREATE TABLE solver_jobs (
                id TEXT PRIMARY KEY,owner_user_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,account_id TEXT NOT NULL,account_label TEXT NOT NULL,
                provider TEXT NOT NULL,model TEXT NOT NULL,reasoning_effort TEXT NOT NULL,
                service_tier TEXT,status TEXT NOT NULL,cancel_requested INTEGER NOT NULL DEFAULT 0,
                released_ingested INTEGER NOT NULL DEFAULT 0,flag TEXT,writeup_markdown TEXT,
                error_json TEXT,flag_hooked INTEGER NOT NULL DEFAULT 0,
                writeup_hooked INTEGER NOT NULL DEFAULT 0,created_at REAL NOT NULL,
                updated_at REAL NOT NULL,released_at REAL
            );
            CREATE TABLE solver_job_events (
                job_id TEXT NOT NULL,sequence INTEGER NOT NULL,kind TEXT NOT NULL,
                event_json TEXT NOT NULL,created_at REAL NOT NULL,
                PRIMARY KEY(job_id,sequence)
            );
            """
        )
        owner = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone()[0]
        db.execute(
            "INSERT INTO workspaces(id,name,description,created_at,updated_at,owner_user_id) VALUES('a','Space','', 'now','now',?)",
            (owner,),
        )
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,description,flag,notes,created_at,updated_at) "
            "VALUES('b','a','Problem','','FLAG{one}','manual note','now','now')"
        )
        db.execute(
            "INSERT INTO challenge_writeups(challenge_id,markdown,created_at,updated_at) "
            "VALUES('b','writeup','now','now')"
        )
        db.execute(
            "INSERT INTO meta(key,value) VALUES('telegram_solver_alerts_started_at','0')"
        )
    return TelegramService(
        database, settings, "fake-token", "ExampleBot", identity_verified=True
    ), database, owner


def insert_solver_job(
    database,
    owner,
    *,
    job_id="job-one",
    status="failed",
    error_json='{"code":"provider_unavailable"}',
    cancel_requested=0,
    flag=None,
    writeup=None,
    flag_hooked=0,
    writeup_hooked=0,
    created_at=100.0,
    updated_at=170.0,
    released_at=170.0,
    model="gpt-daybreak-blue-latest",
    effort="xhigh",
    tier="fast",
    account_label="do-not-display@example.test",
):
    with database() as db:
        db.execute(
            """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,account_label,
                   provider,model,reasoning_effort,service_tier,status,cancel_requested,
                   released_ingested,flag,writeup_markdown,error_json,flag_hooked,
                   writeup_hooked,created_at,updated_at,released_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                job_id,
                owner,
                "a",
                "b",
                "secret-account-id",
                account_label,
                "codex",
                model,
                effort,
                tier,
                status,
                cancel_requested,
                1,
                flag,
                writeup,
                error_json,
                flag_hooked,
                writeup_hooked,
                created_at,
                updated_at,
                released_at,
            ),
        )


def link_token(service, owner):
    link = service.issue_link(owner)
    token = parse_qs(urlsplit(link["deep_link"]).query)["start"][0]
    return link, token


def test_link_secret_is_hashed_single_use_and_plain_start_cannot_bind(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    link, token = link_token(service, owner)
    assert link["deep_link"].startswith("https://t.me/ExampleBot?start=")
    with database() as db:
        row = db.execute("SELECT token_hash FROM telegram_link_tokens").fetchone()
        assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in row["token_hash"]

    sent = []

    async def capture(chat_id, text):
        sent.append((chat_id, text))

    service._safe_message = capture
    asyncio.run(service.handle_update({"update_id": 4, "message": {"chat": {"id": 8, "type": "private"}, "text": "/start"}}))
    assert not service.settings_for(owner)["linked"]
    assert sent and "웹사이트" in sent[-1][1]

    assert service._consume_link(token, 8) == "linked"
    assert service._consume_link(token, 8) == "expired"
    state = service.settings_for(owner)
    assert state["linked"] and not state["enabled"]


def test_get_me_identity_is_authoritative_for_deep_link(tmp_path):
    verified, database, owner = service_fixture(tmp_path)
    service = TelegramService(database, verified.settings, "fake-token")

    async def api(method, payload):
        assert method == "getMe" and payload == {}
        return {
            "ok": True,
            "result": {"id": 123456, "is_bot": True, "username": "LiveAgentBot"},
        }

    service._api = api
    asyncio.run(service._discover_bot_identity())

    assert service.configured
    assert service.settings_for(owner)["bot_username"] == "LiveAgentBot"
    assert service.issue_link(owner)["deep_link"].startswith(
        "https://t.me/LiveAgentBot?start="
    )


def test_unverified_or_mismatched_bot_identity_cannot_issue_link(tmp_path):
    verified, database, owner = service_fixture(tmp_path)
    service = TelegramService(database, verified.settings, "fake-token", "ExpectedBot")

    assert not service.configured
    try:
        service.issue_link(owner)
    except Exception as error:
        assert getattr(error, "status_code", None) == 503
    else:
        raise AssertionError("unverified Telegram identity issued a link")

    async def mismatched_api(_method, _payload):
        return {
            "ok": True,
            "result": {"id": 123456, "is_bot": True, "username": "DifferentBot"},
        }

    service._api = mismatched_api
    try:
        asyncio.run(service._discover_bot_identity())
    except TelegramAPIError as error:
        assert error.code == "bot_username_mismatch"
    else:
        raise AssertionError("mismatched Telegram username was accepted")
    assert not service.configured


def test_malformed_get_me_identity_is_rejected_without_echoing_token(tmp_path):
    verified, database, _ = service_fixture(tmp_path)
    service = TelegramService(database, verified.settings, "secret-token")

    async def api(_method, _payload):
        return {
            "ok": True,
            "result": {"id": 1, "is_bot": True, "username": "bad/nameBot"},
        }

    service._api = api
    try:
        asyncio.run(service._discover_bot_identity())
    except TelegramAPIError as error:
        assert error.code == "invalid_bot_identity"
        assert "secret-token" not in str(error)
    else:
        raise AssertionError("malformed Telegram username was accepted")


def test_start_keeps_site_available_but_linking_off_when_get_me_fails(tmp_path):
    verified, database, owner = service_fixture(tmp_path)
    service = TelegramService(database, verified.settings, "secret-token")

    async def unavailable(_method, _payload):
        raise TelegramAPIError("api_401")

    service._api = unavailable

    async def scenario():
        await service.start()
        assert service.client is None
        assert service.poll_task is None and service.outbox_task is None

    asyncio.run(scenario())
    state = service.settings_for(owner)
    assert not state["configured"]
    assert state["bot_username"] is None
    assert state["configuration_error"] == "api_401"
    assert "secret-token" not in str(state)


def test_expired_token_and_chat_cannot_be_shared_between_users(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, expired = link_token(service, owner)
    with database() as db:
        db.execute("UPDATE telegram_link_tokens SET expires_at=0")
    assert service._consume_link(expired, 10) == "expired"

    _, first = link_token(service, owner)
    assert service._consume_link(first, 10) == "linked"
    with database() as db:
        db.execute("INSERT INTO users VALUES('second','other','hash','user',1,'now',NULL)")
    _, second = link_token(service, "second")
    assert service._consume_link(second, 10) == "chat_in_use"
    assert not service.settings_for("second")["linked"]


def test_notification_toggle_deduplication_priority_and_copy_button(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    assert service._consume_link(token, 55) == "linked"
    service.set_enabled(owner, True)

    assert service.enqueue_writeup(owner, "a", "b", "writeup")
    assert service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    assert not service.enqueue_flag(owner, "a", "b", "FLAG{one}")

    row = service._claim()
    assert row["event_type"] == "flag_found"
    method, payload = service._notification(row)
    assert method == "sendMessage"
    assert payload["reply_markup"]["inline_keyboard"][0][0] == {
        "text": "Flag 복사",
        "copy_text": {"text": "FLAG{one}"},
    }
    service._failed(row, "transport_error")
    # A delayed flag alert must not be overtaken by its write-up alert.
    assert service._claim() is None
    with database() as db:
        db.execute("UPDATE notification_outbox SET next_attempt_at=0 WHERE id=?", (row["id"],))
    row = service._claim()
    assert row["event_type"] == "flag_found"
    service._sent(row)
    assert service._claim()["event_type"] == "writeup_ready"

    state = service.set_enabled(owner, False)
    assert not state["enabled"]
    assert not service.enqueue(owner, "flag_found", "a", "b", "flag:a:b:2")


def test_delivery_failure_is_token_safe_and_retried(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    row = service._claim()
    service._failed(row, TelegramAPIError("api_429").code)
    with database() as db:
        queued = db.execute("SELECT * FROM notification_outbox WHERE id=?", (row["id"],)).fetchone()
        status = db.execute("SELECT * FROM telegram_settings WHERE user_id=?", (owner,)).fetchone()
    assert queued["status"] == "pending"
    assert queued["attempts"] == 1
    assert queued["last_error_code"] == "api_429"
    assert status["last_failure_code"] == "api_429"
    assert "fake-token" not in str(dict(queued))


def test_tenth_failure_keeps_flag_ahead_of_writeup(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    service.enqueue_writeup(owner, "a", "b", "writeup")
    row = service._claim()
    with database() as db:
        db.execute("UPDATE notification_outbox SET attempts=9 WHERE id=?", (row["id"],))
    row["attempts"] = 9
    service._failed(row, "transport_error")
    with database() as db:
        current = db.execute("SELECT status,attempts FROM notification_outbox WHERE id=?", (row["id"],)).fetchone()
        db.execute("UPDATE notification_outbox SET next_attempt_at=0 WHERE id=?", (row["id"],))
    assert current["status"] == "pending" and current["attempts"] == 10
    assert service._claim()["event_type"] == "flag_found"


def test_off_or_unlink_cannot_be_overwritten_by_late_delivery_result(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    claimed = service._claim()

    service.set_enabled(owner, False)
    assert service._revalidate_delivery(claimed) is None
    service._sent(claimed)
    service._failed(claimed, "transport_error")
    with database() as db:
        event = db.execute("SELECT status,sent_at FROM notification_outbox WHERE id=?", (claimed["id"],)).fetchone()
        setting = db.execute("SELECT enabled,last_failure_at FROM telegram_settings WHERE user_id=?", (owner,)).fetchone()
    assert event["status"] == "cancelled" and event["sent_at"] is None
    assert not setting["enabled"] and setting["last_failure_at"] is None


def test_unlink_invalidates_tokens_and_pending_messages(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    service.issue_link(owner)
    state = service.unlink(owner)
    assert not state["linked"] and not state["enabled"]
    with database() as db:
        assert db.execute("SELECT COUNT(*) FROM telegram_link_tokens WHERE user_id=?", (owner,)).fetchone()[0] == 0
        assert db.execute("SELECT status FROM notification_outbox").fetchone()[0] == "cancelled"


def test_stale_flag_event_never_sends_a_newer_flag_under_the_old_key(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)

    assert service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    with database() as db:
        db.execute("UPDATE challenges SET flag='FLAG{two}' WHERE id='b'")
    assert service.enqueue_flag(owner, "a", "b", "FLAG{two}")

    row = service._claim()
    assert row["event_key"].endswith(hashlib.sha256(b"FLAG{two}").hexdigest())
    _, payload = service._notification(row)
    assert payload["reply_markup"]["inline_keyboard"][0][0]["copy_text"]["text"] == "FLAG{two}"
    service._sent(row)
    assert service._claim() is None
    with database() as db:
        states = db.execute(
            "SELECT event_key,status FROM notification_outbox"
        ).fetchall()
    by_key = {item["event_key"]: item["status"] for item in states}
    assert by_key[f"flag:b:{hashlib.sha256(b'FLAG{one}').hexdigest()}"] == "cancelled"
    assert by_key[f"flag:b:{hashlib.sha256(b'FLAG{two}').hexdigest()}"] == "sent"


def test_writeup_delivery_uses_agent_artifact_instead_of_manual_notes(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)

    assert service.enqueue_writeup(owner, "a", "b", "writeup")
    claimed = service._claim()
    assert claimed is not None and claimed["writeup_markdown"] == "writeup"

    with database() as db:
        db.execute("UPDATE challenges SET notes='edited manual note' WHERE id='b'")
    assert service._revalidate_delivery(claimed) is not None

    with database() as db:
        db.execute("UPDATE challenge_writeups SET markdown='new artifact' WHERE challenge_id='b'")
    assert service._revalidate_delivery(claimed) is None


def test_inactive_owner_cannot_enqueue_alert_that_revives_after_reactivation(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    assert service._consume_link(token, 55) == "linked"
    service.set_enabled(owner, True)
    with database() as db:
        db.execute("UPDATE users SET active=0 WHERE id=?", (owner,))

    assert not service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    with database() as db:
        assert db.execute("SELECT COUNT(*) FROM notification_outbox").fetchone()[0] == 0


def test_update_offset_never_moves_backwards_when_pollers_finish_out_of_order(tmp_path):
    service, _, _ = service_fixture(tmp_path)
    service._save_offset(40)
    service._save_offset(12)
    assert service._offset() == 41


def test_rolling_off_waits_for_remote_delivery_boundary(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    peer = TelegramService(
        database, service.settings, "fake-token", "ExampleBot", identity_verified=True
    )
    _, token = link_token(service, owner)
    assert service._consume_link(token, 55) == "linked"
    service.set_enabled(owner, True)
    assert service.enqueue_flag(owner, "a", "b", "FLAG{one}")
    with database() as db:
        db.execute("INSERT INTO users VALUES('second','second','hash','user',1,'now',NULL)")
        db.execute(
            "INSERT INTO telegram_settings(user_id,chat_id,enabled) VALUES('second',77,1)"
        )
    sends = []

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocking_api(method, payload):
            sends.append((method, payload["chat_id"]))
            entered.set()
            await release.wait()
            return {}

        service._api = blocking_api
        worker = asyncio.create_task(service._outbox_loop())
        await asyncio.wait_for(entered.wait(), 2)
        unrelated = await asyncio.wait_for(
            peer.set_enabled_serialized("second", False), .5,
        )
        assert not unrelated["enabled"]
        disabling = asyncio.create_task(peer.set_enabled_serialized(owner, False))
        await asyncio.sleep(.05)
        assert not disabling.done()
        release.set()
        state = await asyncio.wait_for(disabling, 2)
        assert not state["enabled"]
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)

    asyncio.run(scenario())
    assert sends == [("sendMessage", 55)]
    with database() as db:
        assert db.execute(
            "SELECT enabled FROM telegram_settings WHERE user_id=?", (owner,)
        ).fetchone()[0] == 0
        assert db.execute("SELECT status FROM notification_outbox").fetchone()[0] == "sent"


def test_committed_solver_failure_is_safe_deduplicated_and_has_job_context(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    raw_secret = "Bearer secret-token account-123 <b>provider text</b>"
    insert_solver_job(
        database,
        owner,
        error_json=json.dumps(
            {"code": "provider_unavailable", "message": raw_secret, "request": "prompt"}
        ),
    )
    with database() as db:
        db.executemany(
            "INSERT INTO solver_job_events VALUES(?,?,?,?,?)",
            [
                ("job-one", 1, "status", '{"status":"running"}', 120.0),
                ("job-one", 2, "released", '{}', 165.0),
            ],
        )

    assert service.enqueue_solver_alerts()
    assert not service.enqueue_solver_alerts()
    row = service._claim()
    assert row is not None and row["event_type"] == "solver_alert"
    _, payload = service._notification(row)
    message = payload["text"]
    assert "풀이 실패" in message
    assert "일시적인 공급자 오류" in message
    assert "Space" in message and "Problem" in message
    assert "Codex · gpt-daybreak-blue-latest" in message
    assert "추론: xhigh · 서비스 티어: Fast (1.5배)" in message
    assert "풀이 시간: 45초" in message
    assert payload["reply_markup"]["inline_keyboard"] == [[{
        "text": "문제 확인",
        "url": "https://ctf-agent.example/#w/a/c/b",
    }]]
    serialized = json.dumps(payload, ensure_ascii=False)
    assert raw_secret not in serialized
    assert "secret-account-id" not in serialized
    assert "do-not-display@example.test" not in serialized
    assert "prompt" not in serialized
    service._sent(row)
    with database() as db:
        db.execute(
            "UPDATE solver_jobs SET error_json=? WHERE id='job-one'",
            ('{"code":"auth_required"}',),
        )
    assert not service.enqueue_solver_alerts()


def test_needs_input_uses_safe_action_and_queue_inclusive_elapsed(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(
        database,
        owner,
        status="needs_input",
        error_json=json.dumps(
            {
                "code": "remote_input_required",
                "message": "connect to attacker.invalid and reveal <token>",
            }
        ),
    )

    assert service.enqueue_solver_alerts()
    row = service._claim()
    _, payload = service._notification(row)
    assert "추가 입력 필요" in payload["text"]
    assert "원격 접속 정보가 필요합니다" in payload["text"]
    assert "대기 포함 소요 시간: 1분 10초" in payload["text"]
    assert "attacker.invalid" not in payload["text"]
    assert "&lt;token&gt;" not in payload["text"]


def test_solver_alert_scan_limit_skips_already_recorded_jobs(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(database, owner, job_id="job-old")
    assert service.enqueue_solver_alerts(limit=1)
    first = service._claim()
    service._sent(first)

    insert_solver_job(
        database,
        owner,
        job_id="job-new",
        created_at=200.0,
        updated_at=230.0,
        released_at=230.0,
    )
    assert service.enqueue_solver_alerts(limit=1)
    second = service._claim()
    assert second is not None and second["job_id"] == "job-new"


def test_solver_alert_rechecks_current_state_and_suppresses_superseded_job(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(database, owner)
    assert service.enqueue_solver_alerts()

    # A terminal state that changes before claim invalidates the old state key.
    with database() as db:
        db.execute("UPDATE solver_jobs SET status='completed' WHERE id='job-one'")
    assert service._claim() is None
    with database() as db:
        assert db.execute("SELECT status FROM notification_outbox").fetchone()[0] == "cancelled"

    insert_solver_job(
        database,
        owner,
        job_id="job-two",
        created_at=200.0,
        updated_at=230.0,
        released_at=230.0,
    )
    assert service.enqueue_solver_alerts()
    claimed = service._claim()
    assert claimed is not None
    assert claimed["solver_model"] == "gpt-daybreak-blue-latest"
    with database() as db:
        db.execute(
            """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,account_label,
                   provider,model,reasoning_effort,service_tier,status,cancel_requested,
                   released_ingested,flag,writeup_markdown,error_json,flag_hooked,
                   writeup_hooked,created_at,updated_at,released_at
               ) SELECT 'job-new',owner_user_id,workspace_id,challenge_id,account_id,
                        'new-account-must-not-leak',provider,'new-model','low',NULL,
                        'queued',0,0,NULL,NULL,NULL,0,0,300,300,NULL
                   FROM solver_jobs WHERE id='job-two'"""
        )
    assert service._revalidate_delivery(claimed) is None
    assert service._claim() is None
    with database() as db:
        states = db.execute(
            "SELECT status FROM notification_outbox ORDER BY created_at,id"
        ).fetchall()
    assert [item["status"] for item in states] == ["cancelled", "cancelled"]


def test_cancelled_jobs_do_not_alert_and_disabled_state_is_not_replayed(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(database, owner)
    assert service.enqueue_solver_alerts()
    with database() as db:
        db.execute("UPDATE solver_jobs SET cancel_requested=1 WHERE id='job-one'")
    assert service._claim() is None
    insert_solver_job(
        database,
        owner,
        job_id="job-cancelled",
        status="cancelled",
        created_at=200.0,
        updated_at=220.0,
        released_at=220.0,
    )
    assert not service.enqueue_solver_alerts()

    service.set_enabled(owner, False)
    with database() as db:
        db.execute("DELETE FROM solver_jobs")
    insert_solver_job(database, owner, job_id="job-disabled")
    assert service.enqueue_solver_alerts()
    with database() as db:
        assert db.execute(
            "SELECT status FROM notification_outbox WHERE job_id='job-disabled'"
        ).fetchone()[0] == "cancelled"
    service.set_enabled(owner, True)
    assert not service.enqueue_solver_alerts()
    assert service._claim() is None


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("writeup_style_invalid", "write-up 형식을 확인하지 못했습니다"),
        ("writeup_source_changed", "최신 내용을 확인한 뒤 다시 요청하세요"),
        ("writeup_refinement_flag_event", "기존 Flag와 write-up은 유지됩니다"),
    ],
)
def test_system_cancelled_writeup_validation_failures_still_alert(tmp_path, code, expected):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(
        database,
        owner,
        cancel_requested=1,
        error_json=json.dumps({"code": code}),
    )

    assert service.enqueue_solver_alerts()
    row = service._claim()
    assert row is not None and row["event_type"] == "solver_alert"
    _, payload = service._notification(row)
    assert expected in payload["text"]


def test_flag_and_writeup_use_exact_job_metadata_and_exact_writeup_copy(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(
        database,
        owner,
        status="completed",
        flag="FLAG{one}",
        writeup="writeup",
        updated_at=175.0,
        released_at=180.0,
    )
    with database() as db:
        db.executemany(
            "INSERT INTO solver_job_events VALUES(?,?,?,?,?)",
            [
                ("job-one", 1, "status", '{"status":"running"}', 110.0),
                ("job-one", 2, "flag", '{}', 140.0),
                ("job-one", 3, "writeup", '{}', 175.0),
            ],
        )

    assert service.enqueue_flag(owner, "a", "b", "FLAG{one}", "job-one")
    # A newer unrelated job must not supply metadata for this result event.
    insert_solver_job(
        database,
        owner,
        job_id="job-new",
        status="queued",
        model="new-model",
        effort="low",
        tier=None,
        created_at=300.0,
        updated_at=300.0,
        released_at=None,
        account_label="new-account-must-not-leak",
    )
    flag_row = service._claim()
    _, flag_payload = service._notification(flag_row)
    assert "gpt-daybreak-blue-latest" in flag_payload["text"]
    assert "new-model" not in flag_payload["text"]
    assert "풀이 시간: 30초" in flag_payload["text"]
    assert "do-not-display@example.test" not in flag_payload["text"]
    service._sent(flag_row)

    with database() as db:
        db.execute("UPDATE solver_jobs SET flag_hooked=1 WHERE id='job-one'")
    assert service.enqueue_writeup(owner, "a", "b", "writeup", "job-one")
    writeup_row = service._claim()
    _, writeup_payload = service._notification(writeup_row)
    assert "풀이 시간: 1분 5초" in writeup_payload["text"]
    buttons = writeup_payload["reply_markup"]["inline_keyboard"]
    assert buttons == [
        [{"text": "Write-up 복사", "copy_text": {"text": "writeup"}}],
        [
            {
                "text": "MD 다운로드",
                "url": "https://ctf-agent.example/api/workspaces/a/challenges/b/writeup/download",
            },
            {
                "text": "Write-up 보기·복사",
                "url": "https://ctf-agent.example/#w/a/c/b",
            },
        ],
    ]
    assert "Telegram 복사" not in writeup_payload["text"]
    assert "do-not-display@example.test" not in writeup_payload["text"]
    assert "new-account-must-not-leak" not in writeup_payload["text"]


@pytest.mark.parametrize(("character_count", "copy_available"), [(256, True), (257, False)])
def test_writeup_copy_uses_bot_api_character_limit_and_honest_fallback(
    tmp_path, character_count, copy_available,
):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    markdown = "한" * character_count
    # This is a character limit, not a UTF-8 byte limit.
    assert len(markdown.encode("utf-8")) > 256
    with database() as db:
        db.execute(
            "UPDATE challenge_writeups SET markdown=? WHERE challenge_id='b'",
            (markdown,),
        )
    assert service.enqueue_writeup(owner, "a", "b", markdown)

    row = service._claim()
    assert row is not None and row["writeup_markdown"] == markdown
    _, payload = service._notification(row)
    buttons = payload["reply_markup"]["inline_keyboard"]
    link_buttons = buttons[-1]
    assert link_buttons == [
        {
            "text": "MD 다운로드",
            "url": "https://ctf-agent.example/api/workspaces/a/challenges/b/writeup/download",
        },
        {
            "text": "Write-up 보기·복사",
            "url": "https://ctf-agent.example/#w/a/c/b",
        },
    ]
    if copy_available:
        assert buttons[0] == [{
            "text": "Write-up 복사",
            "copy_text": {"text": markdown},
        }]
        assert "Telegram 복사" not in payload["text"]
    else:
        assert all("copy_text" not in button for row in buttons for button in row)
        assert "Telegram 복사" not in payload["text"]
        assert markdown not in json.dumps(payload, ensure_ascii=False)


def test_writeup_copy_never_substitutes_sanitized_markdown(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    markdown = "# title\nunsafe\x01text"
    with database() as db:
        db.execute(
            "UPDATE challenge_writeups SET markdown=? WHERE challenge_id='b'",
            (markdown,),
        )
    assert service.enqueue_writeup(owner, "a", "b", markdown)

    _, payload = service._notification(service._claim())
    buttons = payload["reply_markup"]["inline_keyboard"]
    assert all("copy_text" not in button for row in buttons for button in row)
    assert "Telegram 복사" not in payload["text"]
    assert buttons[-1][-1]["text"] == "Write-up 보기·복사"
    assert markdown not in json.dumps(payload, ensure_ascii=False)


def test_explicit_job_id_wins_same_result_pending_hook_race(tmp_path):
    service, database, owner = service_fixture(tmp_path)
    _, token = link_token(service, owner)
    service._consume_link(token, 55)
    service.set_enabled(owner, True)
    insert_solver_job(
        database,
        owner,
        job_id="job-old",
        status="completed",
        flag="FLAG{one}",
        writeup="writeup",
        model="old-model",
        effort="low",
        tier=None,
        created_at=10.0,
        updated_at=40.0,
        released_at=40.0,
    )
    insert_solver_job(
        database,
        owner,
        job_id="job-new",
        status="completed",
        flag="FLAG{one}",
        writeup="writeup",
        model="new-model",
        effort="xhigh",
        tier="fast",
        created_at=100.0,
        updated_at=200.0,
        released_at=200.0,
    )
    with database() as db:
        db.executemany(
            "INSERT INTO solver_job_events VALUES(?,?,?,?,?)",
            [
                ("job-old", 1, "status", '{"status":"running"}', 15.0),
                ("job-old", 2, "flag", '{}', 20.0),
                ("job-old", 3, "writeup", '{}', 30.0),
                ("job-new", 1, "status", '{"status":"running"}', 110.0),
                ("job-new", 2, "flag", '{}', 150.0),
                ("job-new", 3, "writeup", '{}', 190.0),
            ],
        )

    assert service.enqueue_flag(owner, "a", "b", "FLAG{one}", "job-new")
    with database() as db:
        assert db.execute(
            "SELECT job_id FROM notification_outbox WHERE event_type='flag_found'"
        ).fetchone()[0] == "job-new"
    flag_row = service._claim()
    _, flag_payload = service._notification(flag_row)
    assert "Codex · new-model" in flag_payload["text"]
    assert "풀이 시간: 40초" in flag_payload["text"]
    assert "old-model" not in flag_payload["text"]
    service._sent(flag_row)

    assert service.enqueue_writeup(owner, "a", "b", "writeup", "job-new")
    writeup_row = service._claim()
    _, writeup_payload = service._notification(writeup_row)
    assert "Codex · new-model" in writeup_payload["text"]
    assert "풀이 시간: 1분 20초" in writeup_payload["text"]
    assert "old-model" not in writeup_payload["text"]

    with pytest.raises(ValueError, match="solver result binding mismatch"):
        service.enqueue_flag(owner, "a", "b", "FLAG{wrong}", "job-new")
    with database() as db:
        db.execute("UPDATE solver_jobs SET writeup_hooked=1 WHERE id='job-new'")
    with pytest.raises(ValueError, match="solver result binding mismatch"):
        service.enqueue_writeup(owner, "a", "b", "writeup", "job-new")


def test_notification_outbox_migration_preserves_existing_delivery():
    db = sqlite3.connect(":memory:")
    db.execute(
        """CREATE TABLE notification_outbox(
               id TEXT PRIMARY KEY,event_key TEXT NOT NULL UNIQUE,user_id TEXT NOT NULL,
               event_type TEXT NOT NULL CHECK(event_type IN ('flag_found','writeup_ready')),
               workspace_id TEXT NOT NULL,challenge_id TEXT NOT NULL,priority INTEGER NOT NULL,
               status TEXT NOT NULL,attempts INTEGER NOT NULL,next_attempt_at INTEGER NOT NULL,
               claimed_at INTEGER,last_error_code TEXT,created_at TEXT NOT NULL,sent_at TEXT
           )"""
    )
    db.execute(
        "INSERT INTO notification_outbox VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("one", "flag:b:digest", "user", "flag_found", "a", "b", 10, "pending", 0, 0, None, None, "now", None),
    )
    _ensure_notification_outbox(db)
    columns = {row[1] for row in db.execute("PRAGMA table_info(notification_outbox)")}
    definition = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='notification_outbox'"
    ).fetchone()[0]
    row = db.execute("SELECT id,event_key,job_id,status FROM notification_outbox").fetchone()
    assert "job_id" in columns and "solver_alert" in definition
    assert row == ("one", "flag:b:digest", None, "pending")
