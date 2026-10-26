import asyncio
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from ctf_agent.agent_workspace import INITIAL_GOAL, NUDGE
from ctf_agent.solver import ModelConfiguration, normalize_provider_failure
from ctf_agent.submit_flag import record_candidate
from ctf_agent.solver_worker import (
    AppServerFailure,
    ClaudeFileCredential,
    ClaudePrintDriver,
    EventWriter,
    GuidanceMailbox,
    JobManifest,
    MAX_JOB_SECONDS,
    REQUIRED_CLAUDE_VERSION,
    REQUIRED_CODEX_VERSION,
    WorkerRefusal,
    _write_json,
    consume_staged_claude_credential,
)


JOB_ID = "a" * 32


def _manifest(tmp_path: Path) -> JobManifest:
    active = tmp_path / "active"
    active.mkdir(exist_ok=True)
    created = time.time()
    raw = b'{"claudeAiOauth":{"accessToken":"synthetic-never-log"}}'
    payload = {
        "protocol": 1,
        "job_id": JOB_ID,
        "challenge_name": "Claude fixture",
        "challenge_text": "Inspect the supplied sample.",
        "category": "misc",
        "flag_format": "SARI{...}",
        "remote": "",
        "remote_mode": "none",
        "provider": "claude",
        "model": "sonnet",
        "reasoning_effort": "high",
        "service_tier": None,
        "codex_version": REQUIRED_CODEX_VERSION,
        "codex_runtime_sha256": None,
        "claude_version": REQUIRED_CLAUDE_VERSION,
        "credential_file": ".credentials.json",
        "auth_sha256": hashlib.sha256(raw).hexdigest(),
        "max_seconds": MAX_JOB_SECONDS,
        "created_at": created,
        "deadline_unix": created + MAX_JOB_SECONDS if MAX_JOB_SECONDS else None,
        "network_enabled": True,
        "network_policy": "general_internet",
        "retry_checkpoint": None,
    }
    (active / "manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    return JobManifest.load(active)


def _workspace(tmp_path: Path) -> Path:
    workdir = tmp_path / "competition" / "challenge" / "codex-workdir"
    skills = tmp_path / "competition" / "skills"
    workdir.mkdir(parents=True)
    skills.mkdir(parents=True)
    return workdir


def test_claude_manifest_is_immutable_and_rejects_codex_credential_name(tmp_path):
    manifest = _manifest(tmp_path)
    assert manifest.configuration == ModelConfiguration("claude", "sonnet", "high", None)
    assert manifest.claude_version == REQUIRED_CLAUDE_VERSION
    assert manifest.credential_file == ".credentials.json"
    path = tmp_path / "active" / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["credential_file"] = "auth.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(Exception, match="인증 파일"):
        JobManifest.load(tmp_path / "active")


def test_claude_credential_is_unlinked_then_installed_private(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    raw = b'{"claudeAiOauth":{"accessToken":"synthetic-secret"}}'
    staged = active / ".credentials.json"
    staged.write_bytes(raw)
    staged.chmod(0o600)
    credential = consume_staged_claude_credential(active, hashlib.sha256(raw).hexdigest())
    assert isinstance(credential, ClaudeFileCredential)
    assert not staged.exists()
    target = credential.install(tmp_path / "private-config")
    assert target.read_bytes() == raw
    if os.name == "posix":
        assert not (target.stat().st_mode & 0o077)
    credential.erase()
    assert credential.raw == bytearray()


def test_claude_argv_pins_tools_settings_model_effort_and_one_resume_session(tmp_path):
    manifest = _manifest(tmp_path)
    workdir = _workspace(tmp_path)
    driver = ClaudePrintDriver(tmp_path / "home", workdir, manifest.configuration, command_prefix=["claude"])
    schema = {"type": "object", "required": ["flag"]}
    first = driver.command_arguments(manifest, schema)
    session = str(__import__("uuid").UUID(hex=JOB_ID))
    assert first[first.index("--session-id") + 1] == session
    assert "--resume" not in first
    assert first[first.index("--model") + 1] == "sonnet"
    assert first[first.index("--effort") + 1] == "high"
    assert first[first.index("--tools") + 1] == "Bash,Read,Write,Edit,Glob,Grep"
    assert first[first.index("--allowedTools") + 1] == first[first.index("--tools") + 1]
    assert first[first.index("--disallowedTools") + 1] == "mcp__*"
    assert first[first.index("--permission-prompts") + 1] == "none"
    assert json.loads(first[first.index("--mcp-config") + 1]) == {"mcpServers": {}}
    settings = json.loads(first[first.index("--settings") + 1])
    assert settings["switchModelsOnFlag"] is False
    assert settings["permissions"]["defaultMode"] == "dontAsk"
    assert settings["permissions"]["deny"] == ["mcp__*"]
    driver.turn_count = 1
    resumed = driver.command_arguments(manifest, schema)
    assert resumed[resumed.index("--resume") + 1] == session
    assert "--session-id" not in resumed


def test_claude_explicit_55_model_matches_only_its_own_response(tmp_path):
    workdir = _workspace(tmp_path)
    driver = ClaudePrintDriver(tmp_path / "home", workdir,
        ModelConfiguration("claude", "claude-opus-5-5", "high", None), command_prefix=["claude"])
    assert driver._model_matches("claude-opus-5-5", "claude-opus-5-5")
    assert not driver._model_matches("claude-opus-5-5", "claude-opus-5")
    assert "claude-opus-5-5" in driver.ALLOWED_MODELS


class _Lines:
    def __init__(self, values):
        self.values = [json.dumps(value, separators=(",", ":")).encode() + b"\n" for value in values]

    async def readline(self):
        return self.values.pop(0) if self.values else b""


class _Process:
    def __init__(self, events):
        self.stdout = _Lines(events)
        self.returncode = 0

    async def wait(self):
        return self.returncode


def _init_event(driver, *, model="claude-sonnet-4-6"):
    return {
        "type": "system",
        "subtype": "init",
        "session_id": driver.session_id,
        "model": model,
        "tools": [*driver.ALLOWED_TOOLS, "StructuredOutput"],
        "mcp_servers": [],
        "claude_code_version": REQUIRED_CLAUDE_VERSION,
        "permissionMode": "dontAsk",
        "slash_commands": [],
        "effort": "high",
    }


def test_claude_stream_success_progress_and_structured_output(tmp_path):
    async def scenario():
        manifest = _manifest(tmp_path)
        driver = ClaudePrintDriver(tmp_path / "home", _workspace(tmp_path), manifest.configuration, command_prefix=["claude"])
        driver.session_id = driver._session_uuid(JOB_ID)
        events = [
            _init_event(driver),
            {"type": "assistant", "session_id": driver.session_id,
             "message": {"content": [
                 {"type": "tool_use", "name": "Read"},
                 {"type": "tool_use", "name": "StructuredOutput"},
             ]}},
            {"type": "system", "subtype": "api_retry", "session_id": driver.session_id,
             "attempt": 1, "error": "raw-provider-diagnostic synthetic-secret"},
            {"type": "result", "subtype": "success", "is_error": False,
             "session_id": driver.session_id, "structured_output": {"flag": "SARI{ok}", "private_notes": "fact"}},
        ]
        progress = []
        async def report(value):
            progress.append(value)
        result = await driver._read_stream(_Process(events), manifest, report)
        assert result == {"flag": "SARI{ok}", "private_notes": "fact"}
        assert progress == ["inspecting_files", "waiting_for_model"]
        assert "synthetic-secret" not in repr(result)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"model": "claude-notsonnet-5"}, "model_mismatch"),
        ({"claude_code_version": None}, "claude_version_mismatch"),
        ({"permissionMode": "acceptEdits"}, "tool_policy_mismatch"),
        ({"slash_commands": ["help"]}, "tool_policy_mismatch"),
    ],
)
def test_claude_init_fails_closed_when_execution_contract_changes(tmp_path, override, code):
    async def scenario():
        manifest = _manifest(tmp_path)
        driver = ClaudePrintDriver(
            tmp_path / "home", _workspace(tmp_path), manifest.configuration, command_prefix=["claude"]
        )
        driver.session_id = driver._session_uuid(JOB_ID)
        initialized = {**_init_event(driver), **override}
        events = [
            initialized,
            {"type": "result", "subtype": "success", "is_error": False,
             "session_id": driver.session_id, "structured_output": {"flag": "SARI{bad}", "private_notes": "fact"}},
        ]
        with pytest.raises(Exception) as caught:
            await driver._read_stream(_Process(events), manifest, lambda _code: asyncio.sleep(0))
        assert getattr(caught.value, "error", None).code == code

    asyncio.run(scenario())


def test_claude_refusal_maps_to_bounded_cvp_without_raw_diagnostics(tmp_path):
    async def scenario():
        manifest = _manifest(tmp_path)
        driver = ClaudePrintDriver(tmp_path / "home", _workspace(tmp_path), manifest.configuration, command_prefix=["claude"])
        driver.session_id = driver._session_uuid(JOB_ID)
        events = [
            _init_event(driver),
            {"type": "result", "subtype": "error_during_execution", "is_error": True,
             "session_id": driver.session_id, "stop_reason": "refusal",
             "result": "raw synthetic-secret /private/auth"},
        ]
        with pytest.raises(AppServerFailure) as caught:
            await driver._read_stream(_Process(events), manifest, lambda _code: asyncio.sleep(0))
        public = normalize_provider_failure(caught.value.payload, stage="solve").public()
        assert public["code"] == "policy_security"
        assert public["provider_code"] == "CVP"
        assert "synthetic-secret" not in json.dumps(public)
        assert "/private" not in json.dumps(public)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("message", "expected_code", "provider_code"),
    [
        (
            "I cannot continue because the CVP security policy blocks this request. "
            "private-soft-marker",
            "policy_security",
            "CVP",
        ),
        (
            "I cannot access a shell or terminal tool in this environment. "
            "private-soft-marker",
            "provider_tools_unavailable",
            None,
        ),
    ],
)
def test_claude_assistant_text_soft_refusal_uses_only_fixed_error(
    tmp_path, message, expected_code, provider_code
):
    async def scenario():
        manifest = _manifest(tmp_path)
        driver = ClaudePrintDriver(
            tmp_path / "home",
            _workspace(tmp_path),
            manifest.configuration,
            command_prefix=["claude"],
        )
        driver.session_id = driver._session_uuid(JOB_ID)
        events = [
            _init_event(driver),
            {
                "type": "assistant",
                "session_id": driver.session_id,
                "message": {"content": [{"type": "text", "text": message}]},
            },
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "session_id": driver.session_id,
                "structured_output": {"flag": "", "private_notes": ""},
            },
        ]
        with pytest.raises(WorkerRefusal) as caught:
            await driver._read_stream(
                _Process(events), manifest, lambda _code: asyncio.sleep(0)
            )
        public = caught.value.error.public()
        assert public["code"] == expected_code
        assert public.get("provider_code") == provider_code
        serialized = json.dumps({"public": public, "exception": repr(caught.value)})
        assert "private-soft-marker" not in serialized
        assert message not in serialized

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("command_on_first_turn", "expected_code"),
    [
        (False, "premature_progress_response"),
        (True, "flag_not_submitted"),
    ],
)
def test_claude_final_progress_only_requires_no_tool_execution(
    tmp_path, command_on_first_turn, expected_code
):
    raw_message = (
        "I will continue analyzing the attachment and report back in the next step. "
        "private-progress-marker"
    )

    class ProgressOnlyClaude(ClaudePrintDriver):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.prompts = []
            self.session_id = self._session_uuid(JOB_ID)

        async def _turn(self, manifest, prompt, schema, cancelled, progress):
            self.prompts.append(prompt)
            content = [{"type": "text", "text": raw_message}]
            if command_on_first_turn and len(self.prompts) == 1:
                content.insert(0, {"type": "tool_use", "name": "Bash"})
            events = [
                _init_event(self),
                {
                    "type": "assistant",
                    "session_id": self.session_id,
                    "message": {"content": content},
                },
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "session_id": self.session_id,
                    "result": raw_message,
                },
            ]
            return await self._read_stream(_Process(events), manifest, progress)

    async def scenario():
        manifest = _manifest(tmp_path)
        workdir = _workspace(tmp_path)
        driver = ProgressOnlyClaude(
            tmp_path / "home",
            workdir,
            manifest.configuration,
            command_prefix=["claude"],
        )
        with pytest.raises(WorkerRefusal) as caught:
            await driver.run_discovery(
                manifest,
                workdir,
                asyncio.Event(),
                lambda _code: asyncio.sleep(0),
            )
        public = caught.value.error.public()
        assert public["code"] == expected_code
        serialized = json.dumps({"public": public, "exception": repr(caught.value)})
        assert "private-progress-marker" not in serialized
        assert len(driver.prompts) == 4
        assert driver.prompts[0].startswith(INITIAL_GOAL)
        assert all(prompt.startswith(NUDGE) for prompt in driver.prompts[1:])

    asyncio.run(scenario())


def test_claude_stream_close_uses_provider_neutral_public_message(tmp_path):
    async def scenario():
        manifest = _manifest(tmp_path)
        driver = ClaudePrintDriver(
            tmp_path / "home",
            _workspace(tmp_path),
            manifest.configuration,
            command_prefix=["claude"],
        )
        driver.session_id = driver._session_uuid(JOB_ID)
        with pytest.raises(AppServerFailure) as caught:
            await driver._read_stream(
                _Process([_init_event(driver)]),
                manifest,
                lambda _code: asyncio.sleep(0),
            )
        public = normalize_provider_failure(caught.value.payload, stage="solve").public()
        assert public["code"] == "provider_stream_closed"
        assert "모델 공급자" in public["message"]
        assert "Codex" not in public["message"]

    asyncio.run(scenario())


def test_claude_discovery_keeps_original_goal_nudge_and_flag_before_writeup(tmp_path):
    async def scenario():
        manifest = _manifest(tmp_path)
        workdir = _workspace(tmp_path)
        (workdir / "notes").mkdir()
        driver = ClaudePrintDriver(tmp_path / "home", workdir, manifest.configuration, command_prefix=["claude"])
        prompts = []

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            prompts.append(prompt)
            if len(prompts) == 1:
                return {"flag": "", "private_notes": "first observation"}
            record_candidate("SARI{claude}", workdir)
            return {"flag": "SARI{claude}", "private_notes": "verified observation"}

        driver._turn = turn
        progress = []
        async def report(value):
            progress.append(value)
        result = await driver.run_discovery(manifest, workdir, asyncio.Event(), report)
        assert result["flag"] == "SARI{claude}"
        assert prompts[0].startswith(INITIAL_GOAL)
        assert "Authoritative remote state for this job: `none`" in prompts[0]
        assert "does not apply to this challenge" in prompts[0]
        assert prompts[1].startswith(NUDGE)
        assert "Authoritative remote state for this job: `none`" in prompts[1]
        assert all("write-up" not in prompt.split("The web worker", 1)[0].lower() for prompt in prompts)

    asyncio.run(scenario())


def test_claude_queued_guidance_uses_next_turn_in_same_resume_session(tmp_path):
    async def scenario():
        manifest = _manifest(tmp_path)
        workdir = _workspace(tmp_path)
        driver = ClaudePrintDriver(
            tmp_path / "home", workdir, manifest.configuration, command_prefix=["claude"]
        )
        driver.session_id = driver._session_uuid(JOB_ID)
        driver.turn_count = 1
        driver.credential_path = tmp_path / "credential"
        driver.credential_path.write_text("{}", encoding="utf-8")
        writer = EventWriter(tmp_path / "active", JOB_ID)
        driver.guidance_mailbox = GuidanceMailbox(tmp_path / "active", JOB_ID, writer)
        guidance_id = "d" * 32
        directory = tmp_path / "active" / "guidance"
        directory.mkdir()
        _write_json(
            directory / f"{guidance_id}.json",
            {
                "protocol": 1,
                "job_id": JOB_ID,
                "guidance_id": guidance_id,
                "message": "이 관찰을 write-up에도 반영해 주세요.",
                "created_at": time.time(),
            },
        )
        written = bytearray()
        spawned = []

        class Input:
            def write(self, value):
                written.extend(value)

            async def drain(self):
                return None

            def close(self):
                return None

        class Empty:
            async def read(self, _size):
                return b""

        class Process:
            pid = 4242
            returncode = 0
            stdin = Input()
            stdout = object()
            stderr = Empty()

            async def wait(self):
                return 0

        async def spawn(arguments):
            spawned.append(arguments)
            process = Process()
            driver.process = process
            driver.pid = process.pid
            return process

        async def read_stream(_process, _manifest, _progress):
            return {"flag": "SARI{x}", "private_notes": "done"}

        driver._spawn = spawn
        driver._read_stream = read_stream
        result = await driver._turn(
            manifest,
            "write the result",
            {"type": "object"},
            asyncio.Event(),
            lambda _code: asyncio.sleep(0),
        )

        assert result["flag"] == "SARI{x}"
        assert "--resume" in spawned[0]
        assert spawned[0][spawned[0].index("--resume") + 1] == driver.session_id
        assert "이 관찰을 write-up에도 반영" in written.decode("utf-8")
        event = json.loads(
            (tmp_path / "active" / "events" / "00000001.json").read_text(encoding="utf-8")
        )
        assert event["state"] == "delivered"
        assert event["provider_delivery"] == "next_turn"

    asyncio.run(scenario())


@pytest.mark.parametrize("direct_task_cancel", [False, True])
def test_claude_turn_cancellation_interrupts_the_process_group(tmp_path, monkeypatch, direct_task_cancel):
    async def scenario():
        manifest = _manifest(tmp_path)
        workdir = _workspace(tmp_path)
        driver = ClaudePrintDriver(tmp_path / "home", workdir, manifest.configuration, command_prefix=["claude"])
        driver.session_id = driver._session_uuid(JOB_ID)
        driver.credential_path = tmp_path / "credential"
        driver.credential_path.write_text("{}", encoding="utf-8")
        stopped = asyncio.Event()
        sent = []

        class Input:
            def write(self, _value): pass
            async def drain(self): pass
            def close(self): pass

        class Blocking:
            async def readline(self):
                await stopped.wait()
                return b""
            async def read(self, _size):
                await stopped.wait()
                return b""

        class Process:
            pid = 424242
            returncode = None
            stdin = Input()
            stdout = Blocking()
            stderr = Blocking()
            async def wait(self):
                await stopped.wait()
                return self.returncode
            def send_signal(self, sig):
                sent.append(sig)
                self.returncode = 130
                stopped.set()

        process = Process()

        async def spawn(_arguments):
            driver.process = process
            driver.pid = process.pid
            return process

        driver._spawn = spawn
        if os.name == "posix":
            def killpg(_pid, sig):
                sent.append(sig)
                process.returncode = 130
                stopped.set()
            monkeypatch.setattr(os, "killpg", killpg)
        cancelled = asyncio.Event()
        if direct_task_cancel:
            turn = asyncio.create_task(
                driver._turn(manifest, "continue", {"type": "object"}, cancelled, lambda _code: asyncio.sleep(0))
            )
            for _ in range(10):
                if driver.process is process:
                    await asyncio.sleep(0)
                    break
                await asyncio.sleep(0)
            turn.cancel()
            with pytest.raises(asyncio.CancelledError):
                await turn
        else:
            cancelled.set()
            with pytest.raises(asyncio.CancelledError):
                await driver._turn(manifest, "continue", {"type": "object"}, cancelled, lambda _code: asyncio.sleep(0))
        assert sent and sent[0] == signal.SIGINT

    asyncio.run(scenario())


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups only")
def test_claude_spawn_owns_the_process_group_it_terminates(tmp_path):
    async def scenario():
        manifest = _manifest(tmp_path)
        driver = ClaudePrintDriver(
            tmp_path / "home",
            _workspace(tmp_path),
            manifest.configuration,
            command_prefix=[sys.executable],
        )
        # Exercise the real trusted launcher: it must be the single owner of
        # setsid(), otherwise a second setsid() exits with EPERM on Linux.
        process = await driver._spawn_exact(
            [sys.executable, "-c", "import time; time.sleep(60)"]
        )
        try:
            for _ in range(100):
                if os.getpgid(process.pid) == process.pid:
                    break
                await asyncio.sleep(0.01)
            assert os.getpgid(process.pid) == process.pid
            await asyncio.wait_for(driver._stop_current(interrupt=False), timeout=5)
            assert process.returncode is not None
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    asyncio.run(scenario())
