import asyncio
import json

import pytest

from ctf_agent.solver import (
    AdapterBinding,
    AdapterCapabilities,
    AdapterProviderFailure,
    DiscoveryResult,
    ModelConfiguration,
    NetworkEndpoint,
    NetworkPolicy,
    OwnedChallenge,
    ProgressCode,
    ProgressUpdate,
    RefusingAdapter,
    SelectedAccount,
    SolveRequest,
    SolverEngine,
    SolverError,
    SolverLookupError,
    normalize_rate_limit_context,
    normalize_provider_failure,
    normalize_provider_soft_refusal,
)


WORKSPACE_ID = "a" * 32
CHALLENGE_ID = "b" * 32
ACCOUNT_ID = "c" * 32
OWNER_ID = "owner-user"


def isolated_capabilities(**changes):
    values = {
        "backend": "test-container",
        "challenge_only_filesystem": True,
        "symlink_escape_blocked": True,
        "network_denied": True,
        "network_allowlist_enforced": True,
        "host_secrets_hidden": True,
        "auth_not_visible_to_model_tools": True,
        "unprivileged": True,
        "no_new_privileges": True,
        "supports_cancellation": True,
    }
    values.update(changes)
    return AdapterCapabilities(**values)


def make_request(tmp_path, *, owner=OWNER_ID, network=None, description="Inspect the supplied binary."):
    data = tmp_path / "data"
    challenge_dir = data / "workspaces" / WORKSPACE_ID / "challenges" / CHALLENGE_ID
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "sample.bin").write_bytes(b"CTF sample")
    challenge = OwnedChallenge.bind(data, owner, WORKSPACE_ID, CHALLENGE_ID)
    configuration = ModelConfiguration(
        provider="codex",
        model="gpt-daybreak-blue-latest",
        reasoning_effort="high",
        service_tier="fast",
    )
    account = SelectedAccount(ACCOUNT_ID, owner, configuration)
    return SolveRequest(
        challenge=challenge,
        account=account,
        challenge_name="Tiny Reverse",
        challenge_text=description,
        network=network or NetworkPolicy.offline(),
    )


class SuccessfulAdapter:
    def __init__(self, request, *, capabilities=None):
        self._binding = AdapterBinding(request.account.account_id, request.account.configuration)
        self._capabilities = capabilities or isolated_capabilities()
        self.discover_calls = 0
        self.writeup_calls = 0
        self.cancel_calls = 0
        self.contexts = []
        self.prompts = []
        self.flag_was_published = None

    async def capabilities(self, network):
        return self._capabilities

    async def binding(self):
        return self._binding

    async def discover(self, context, prompt, report, cancelled):
        self.discover_calls += 1
        self.contexts.append(context)
        self.prompts.append(prompt)
        await report(ProgressUpdate(ProgressCode.INSPECTING_FILES, 40))
        return DiscoveryResult("SARI{bounded}", "Used strings and verified the branch.")

    async def writeup(self, context, prompt, report, cancelled):
        self.writeup_calls += 1
        self.contexts.append(context)
        self.prompts.append(prompt)
        if self.flag_was_published is not None:
            assert self.flag_was_published()
        await report(ProgressUpdate(ProgressCode.DRAFTING_WRITEUP, 85))
        return f"# Tiny Reverse\n\nRead {context.challenge_root} and validated `SARI{{bounded}}`."

    async def cancel(self, run_id):
        self.cancel_calls += 1


def test_flag_is_published_before_writeup_and_exact_account_settings_are_used(tmp_path):
    async def scenario():
        request = make_request(tmp_path)
        delivered = []

        async def sink(owner_id, event):
            delivered.append((owner_id, event.public()))

        engine = SolverEngine(on_event=sink)
        adapter = SuccessfulAdapter(request)
        adapter.flag_was_published = lambda: any(item[1]["kind"] == "flag" for item in delivered)
        started = await engine.start(request, adapter)
        assert started["phase"] == "queued"
        result = await engine.wait(started["run_id"], OWNER_ID)

        assert result["phase"] == "completed" and result["terminal"] is True
        assert result["flag"] == "SARI{bounded}"
        assert result["writeup_markdown"].startswith("# Tiny Reverse")
        assert str(request.challenge.root) not in result["writeup_markdown"]
        assert "/challenge" in result["writeup_markdown"]
        assert result["model"] == {
            "provider": "codex",
            "model": "gpt-daybreak-blue-latest",
            "reasoning_effort": "high",
            "service_tier": "fast",
        }

        kinds = [item[1]["kind"] for item in delivered]
        assert kinds.index("flag") < kinds.index("writeup")
        assert all(owner == OWNER_ID for owner, _ in delivered)
        assert adapter.discover_calls == adapter.writeup_calls == 1
        assert all(context.configuration == request.account.configuration for context in adapter.contexts)
        assert all(context.network == NetworkPolicy.offline() for context in adapter.contexts)
        assert all(context.mount_path == "/challenge" for context in adapter.contexts)
        assert all(repr(prompt) == "<EphemeralPrompt redacted>" for prompt in adapter.prompts)
        assert all(str(request.challenge.root) not in prompt.text for prompt in adapter.prompts)
        assert all(ACCOUNT_ID not in prompt.text and OWNER_ID not in prompt.text for prompt in adapter.prompts)

        public_blob = json.dumps({"state": result, "events": engine.events(started["run_id"], OWNER_ID)})
        assert str(request.challenge.root) not in public_blob
        assert ACCOUNT_ID not in public_blob and OWNER_ID not in public_blob
        assert request.challenge_text not in public_blob

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("payload", "provider_code"),
    [
        ({"code": -32000, "message": "policy_violation TAC /private/auth.json bearer-secret"}, "TAC"),
        ({"code": "CVP-42", "message": "rejected; token=never-return"}, "CVP-42"),
    ],
)
def test_tac_and_cvp_are_normalized_without_raw_diagnostics_retry_or_fallback(tmp_path, payload, provider_code):
    class PolicyAdapter(SuccessfulAdapter):
        async def discover(self, context, prompt, report, cancelled):
            self.discover_calls += 1
            raise AdapterProviderFailure(payload)

    async def scenario():
        request = make_request(tmp_path)
        adapter = PolicyAdapter(request)
        engine = SolverEngine()
        started = await engine.start(request, adapter)
        result = await engine.wait(started["run_id"], OWNER_ID)

        assert result["phase"] == "failed" and result["terminal"] is True
        assert result["error"] == {
            "code": "policy_security",
            "message": "공급자의 보안 정책 제한으로 요청이 거절되었습니다.",
            "stage": "solve",
            "category": "policy_security",
            "retryable": False,
            "provider_code": provider_code,
        }
        assert adapter.discover_calls == 1
        assert adapter.writeup_calls == 0
        assert adapter.cancel_calls == 1
        serialized = json.dumps(result, ensure_ascii=False)
        assert "auth.json" not in serialized and "bearer-secret" not in serialized and "never-return" not in serialized

    asyncio.run(scenario())


def test_unsafe_execution_is_refused_before_adapter_can_see_prompt_or_files(tmp_path):
    async def scenario():
        request = make_request(tmp_path)
        binding = AdapterBinding(request.account.account_id, request.account.configuration)
        adapter = RefusingAdapter(binding, "shared-process")
        engine = SolverEngine()
        started = await engine.start(request, adapter)
        result = await engine.wait(started["run_id"], OWNER_ID)

        assert result["phase"] == "refused" and result["terminal"] is True
        assert result["error"]["code"] == "isolation_unavailable"
        assert result["error"]["category"] == "safety"
        assert "challenge_only_filesystem" in result["error"]["requirements"]
        assert "network_disabled" in result["error"]["requirements"]
        assert "shared-process" not in json.dumps(result)

    asyncio.run(scenario())


def test_owner_scoping_hides_run_existence_and_cancel_is_terminal(tmp_path):
    class BlockingAdapter(SuccessfulAdapter):
        def __init__(self, request):
            super().__init__(request)
            self.entered = asyncio.Event()
            self.stopped = asyncio.Event()

        async def discover(self, context, prompt, report, cancelled):
            self.discover_calls += 1
            self.entered.set()
            await cancelled.wait()
            self.stopped.set()
            raise asyncio.CancelledError

        async def cancel(self, run_id):
            self.cancel_calls += 1
            self.stopped.set()

    async def scenario():
        request = make_request(tmp_path)
        adapter = BlockingAdapter(request)
        engine = SolverEngine()
        started = await engine.start(request, adapter)
        await adapter.entered.wait()
        with pytest.raises(SolverLookupError, match="not found"):
            engine.get(started["run_id"], "another-user")
        with pytest.raises(SolverLookupError, match="not found"):
            engine.events(started["run_id"], "another-user")

        result = await engine.cancel(started["run_id"], OWNER_ID)
        assert result["phase"] == "cancelled" and result["terminal"] is True
        assert adapter.cancel_calls == 1 and adapter.stopped.is_set()

    asyncio.run(scenario())


def test_writeup_policy_failure_keeps_already_found_flag_visible(tmp_path):
    class WriteupFailureAdapter(SuccessfulAdapter):
        async def writeup(self, context, prompt, report, cancelled):
            self.writeup_calls += 1
            raise AdapterProviderFailure({"message": "CVP security policy; /secret/account-home"})

    async def scenario():
        request = make_request(tmp_path)
        adapter = WriteupFailureAdapter(request)
        engine = SolverEngine()
        started = await engine.start(request, adapter)
        result = await engine.wait(started["run_id"], OWNER_ID)

        assert result["phase"] == "flag_found" and result["terminal"] is True
        assert result["flag"] == "SARI{bounded}"
        assert "writeup_markdown" not in result
        assert result["error"]["stage"] == "writeup"
        assert result["error"]["provider_code"] == "CVP"
        events = engine.events(started["run_id"], OWNER_ID)
        assert [event["kind"] for event in events].index("flag") < [event["kind"] for event in events].index("error")
        assert "/secret/account-home" not in json.dumps(result)

    asyncio.run(scenario())


def test_network_is_off_by_default_and_opt_in_requires_enforced_allowlist(tmp_path):
    async def scenario():
        policy = NetworkPolicy.restricted((NetworkEndpoint("challenge.example", 31337),))
        request = make_request(tmp_path, network=policy)
        adapter = SuccessfulAdapter(request, capabilities=isolated_capabilities(network_allowlist_enforced=False))
        engine = SolverEngine()
        started = await engine.start(request, adapter)
        result = await engine.wait(started["run_id"], OWNER_ID)
        assert result["phase"] == "refused"
        assert result["error"]["requirements"] == ["network_endpoint_allowlist"]
        assert adapter.discover_calls == 0

    asyncio.run(scenario())


def test_account_and_path_binding_reject_cross_owner_or_arbitrary_directory(tmp_path):
    data = tmp_path / "data"
    expected = data / "workspaces" / WORKSPACE_ID / "challenges" / CHALLENGE_ID
    expected.mkdir(parents=True)
    outside = tmp_path / "other-users-challenge"
    outside.mkdir()

    with pytest.raises(ValueError, match="stored location"):
        OwnedChallenge.bind(data, OWNER_ID, WORKSPACE_ID, CHALLENGE_ID, challenge_dir=outside)
    with pytest.raises(ValueError, match="owned"):
        SelectedAccount.from_record(
            {
                "id": ACCOUNT_ID,
                "owner_user_id": "other-user",
                "provider": "codex",
                "model": "gpt-5.6-sol",
                "reasoning_effort": "high",
                "service_tier": None,
                "selected": 1,
            },
            OWNER_ID,
        )


def test_selected_account_requires_explicit_model_effort_and_selection():
    record = {
        "id": ACCOUNT_ID,
        "owner_user_id": OWNER_ID,
        "provider": "codex",
        "model": "gpt-5.6-sol",
        "reasoning_effort": "xhigh",
        "service_tier": None,
        "selected": 1,
    }
    selected = SelectedAccount.from_record(record, OWNER_ID)
    assert selected.configuration.model == "gpt-5.6-sol"
    with pytest.raises(ValueError, match="not selected"):
        SelectedAccount.from_record({**record, "selected": 0}, OWNER_ID)
    with pytest.raises(ValueError, match="model and reasoning"):
        SelectedAccount.from_record({**record, "reasoning_effort": None}, OWNER_ID)


def test_event_sink_failure_does_not_hide_flag_or_block_writeup(tmp_path):
    async def scenario():
        request = make_request(tmp_path)

        async def failing_sink(owner_id, event):
            if event.kind.value == "flag":
                raise RuntimeError("simulated outbox outage with a secret that must not surface")

        engine = SolverEngine(on_event=failing_sink)
        adapter = SuccessfulAdapter(request)
        started = await engine.start(request, adapter)
        result = await engine.wait(started["run_id"], OWNER_ID)
        assert result["phase"] == "completed"
        assert result["flag"] == "SARI{bounded}"
        assert "secret that must not surface" not in json.dumps(result)

    asyncio.run(scenario())


def test_normalizer_never_returns_arbitrary_provider_text():
    error = normalize_provider_failure(
        {"code": "unusual", "message": "failure /home/owner/.codex/auth.json token-super-secret"},
        stage="solve",
    )
    serialized = json.dumps(error.public(), ensure_ascii=False)
    assert error.code == "provider_error"
    assert "auth.json" not in serialized and "token-super-secret" not in serialized


@pytest.mark.parametrize(
    ("message", "provider_code"),
    [
        (
            "I cannot continue because the TAC security policy blocks this request. "
            "private-marker-must-never-surface",
            "TAC",
        ),
        (
            "I’m unable to assist under CVP-42 policy restrictions. "
            "private-marker-must-never-surface",
            "CVP-42",
        ),
        (
            "I must refuse this request because the provider security policy prohibits it. "
            "private-marker-must-never-surface",
            None,
        ),
    ],
)
def test_soft_policy_refusal_returns_only_fixed_public_fields(message, provider_code):
    error = normalize_provider_soft_refusal(
        message,
        stage="solve",
        command_execution_seen=False,
    )
    assert error is not None
    public = error.public()
    assert public == {
        "code": "policy_security",
        "message": "공급자의 보안 정책 제한으로 요청이 거절되었습니다.",
        "stage": "solve",
        "category": "policy_security",
        "retryable": False,
        **({"provider_code": provider_code} if provider_code else {}),
    }
    serialized = json.dumps(public, ensure_ascii=False)
    assert "private-marker" not in serialized
    assert message not in serialized


@pytest.mark.parametrize(
    "message",
    [
        "The CVP lattice instance can be reduced with fpylll before checking capture.pcap.",
        "I cannot solve the CVP lattice until I inspect capture.pcap and its parameters.",
        "I cannot continue due to the CVP lattice dimension; I will inspect capture.pcap next.",
        "The capture.pcap contains TACACS traffic that should be parsed next.",
        "I cannot run that command until I determine its arguments.",
        "The remote shell access is unavailable, so the endpoint details may be stale.",
        "I cannot confirm the answer yet; I will continue inspecting the attachment.",
        "I cannot inspect the security policy file until the archive finishes extracting.",
    ],
)
def test_soft_refusal_classifier_leaves_ambiguous_and_ctf_terms_unclassified(message):
    assert normalize_provider_soft_refusal(
        message,
        stage="solve",
        command_execution_seen=False,
    ) is None


def test_soft_tool_refusal_requires_zero_observed_command_executions():
    raw = (
        "I cannot access a shell or terminal tool in this environment, so I cannot inspect "
        "private-file-marker."
    )
    error = normalize_provider_soft_refusal(
        raw,
        stage="solve",
        command_execution_seen=False,
    )
    assert error is not None
    assert error.public() == {
        "code": "provider_tools_unavailable",
        "message": "선택한 모델 응답에서 로컬 풀이 도구를 사용할 수 없다고 보고했습니다.",
        "stage": "solve",
        "category": "provider",
        "retryable": False,
    }
    assert "private-file-marker" not in json.dumps(error.public(), ensure_ascii=False)
    assert normalize_provider_soft_refusal(
        raw,
        stage="solve",
        command_execution_seen=True,
    ) is None


def test_normalizer_preserves_fixed_tool_unavailable_code_without_raw_text():
    error = normalize_provider_failure(
        {
            "code": "provider_tools_unavailable",
            "message": "private provider response /home/user/auth.json",
        },
        stage="solve",
    )
    public = error.public()
    assert public["code"] == "provider_tools_unavailable"
    assert public["category"] == "provider" and public["retryable"] is False
    assert "auth.json" not in json.dumps(public)


def test_normalizer_does_not_treat_ctf_cvp_or_pcap_terms_as_policy_codes():
    error = normalize_provider_failure(
        {
            "code": "provider_error",
            "message": "Cannot solve the CVP lattice before inspecting capture.pcap.",
        },
        stage="solve",
    )
    assert error.code == "provider_error"
    assert error.provider_code is None


@pytest.mark.parametrize(
    ("info", "code", "category", "retryable"),
    [
        ("unauthorized", "auth_required", "auth", False),
        ("usageLimitExceeded", "usage_limit_exceeded", "quota", True),
        ("sessionBudgetExceeded", "session_budget_exceeded", "quota", True),
        ("rateLimitExceeded", "rate_limit_exceeded", "quota", True),
        ({"rateLimitExceeded": {"httpStatusCode": 429}}, "rate_limit_exceeded", "quota", True),
        ("cyberPolicy", "policy_security", "policy_security", False),
        ("contextWindowExceeded", "context_limit", "model", False),
        ({"httpConnectionFailed": {"httpStatusCode": 503}}, "provider_unavailable", "temporary", True),
    ],
)
def test_normalizer_uses_bounded_codex_error_info_without_raw_message(info, code, category, retryable):
    error = normalize_provider_failure(
        {"codexErrorInfo": info, "message": "private /home/account/auth.json bearer-secret"},
        stage="solve",
    )
    public = error.public()
    assert (public["code"], public["category"], public["retryable"]) == (code, category, retryable)
    assert "auth.json" not in json.dumps(public) and "bearer-secret" not in json.dumps(public)


def test_normalizer_distinguishes_daybreak_access_after_authenticated_preflight():
    error = normalize_provider_failure(
        {
            "codexErrorInfo": "unauthorized",
            "message": "private /home/account/auth.json bearer-secret",
        },
        stage="solve",
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    )
    assert error.public() == {
        "code": "daybreak_route_rejected",
        "message": "Daybreak 요청을 현재 Codex 실행 경로에서 완료하지 못했습니다.",
        "stage": "solve",
        "category": "authorization",
        "retryable": False,
        "requirements": ["현재 로그인과 서버의 Daybreak 전달 경로 확인"],
    }


def test_normalizer_keeps_explicit_refresh_failure_as_login_required_for_daybreak():
    error = normalize_provider_failure(
        {"code": "auth_required", "message": "private token"},
        stage="solve",
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    )
    assert error.code == "auth_required"
    assert error.category == "auth"


def test_normalizer_preserves_scoped_daybreak_route_failure():
    error = normalize_provider_failure(
        {"code": "daybreak_route_rejected", "message": "private token"},
        stage="solve",
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    )
    public = error.public()
    assert public["code"] == "daybreak_route_rejected"
    assert "private" not in json.dumps(public)


def test_normalizer_distinguishes_generic_forbidden_from_login_failure():
    error = normalize_provider_failure(
        {"codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 403}}},
        stage="solve",
    )
    assert error.code == "access_denied"
    assert error.category == "authorization"


def test_daybreak_forbidden_before_authenticated_preflight_stays_generic():
    error = normalize_provider_failure(
        {"codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 403}}},
        stage="auth",
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=False,
    )
    assert error.code == "access_denied"


def test_daybreak_forbidden_after_authenticated_preflight_is_program_access():
    error = normalize_provider_failure(
        {"codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 403}}},
        stage="solve",
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    )
    assert error.code == "daybreak_route_rejected"


def test_daybreak_bad_request_after_authenticated_preflight_is_scoped_access_failure():
    error = normalize_provider_failure(
        {
            "codexErrorInfo": "badRequest",
            "message": "private model is unsupported with this auth path",
        },
        stage="solve",
        model="gpt-daybreak-blue-latest",
        authenticated_preflight=True,
    )
    public = error.public()
    assert public["code"] == "daybreak_route_rejected"
    assert "private" not in json.dumps(public)


def test_normalizer_preserves_fixed_attestation_capability_failure():
    error = normalize_provider_failure(
        {"code": "codex_attestation_unavailable", "message": "private token"},
        stage="solve",
    )
    public = error.public()
    assert public["code"] == "codex_attestation_unavailable"
    assert public["category"] == "authorization"
    assert public["requirements"] == ["지원되는 Codex 클라이언트 실행 방식"]
    assert "private" not in json.dumps(public)


def test_quota_error_exposes_only_reviewed_rate_limit_context():
    error = normalize_provider_failure(
        {
            "codexErrorInfo": "usageLimitExceeded",
            "message": "private provider diagnostic",
            "additionalDetails": {"token": "must-not-surface"},
            "rate_limit": {
                "limit_id": "codex",
                "limit_name": "Codex Standard",
                "reached_type": "workspace_member_usage_limit_reached",
                "spend_control_reached": False,
                "windows": [
                    {"kind": "primary", "window_minutes": 300, "used_percent": 100, "resets_at": 1_788_941_100},
                    {"kind": "secondary", "window_minutes": 10_080, "used_percent": 32, "resets_at": 1_789_369_200},
                ],
                "credits": {"balance": "private-balance"},
                "backend": "private-value",
            },
        },
        stage="solve",
    )
    public = error.public()
    assert public["code"] == "usage_limit_exceeded"
    assert public["quota"] == {
        "limit_id": "codex",
        "limit_name": "Codex Standard",
        "reached_type": "workspace_member_usage_limit_reached",
        "spend_control_reached": False,
        "windows": [
            {"kind": "primary", "window_minutes": 300, "used_percent": 100, "resets_at": 1_788_941_100},
            {"kind": "secondary", "window_minutes": 10_080, "used_percent": 32, "resets_at": 1_789_369_200},
        ],
    }
    serialized = json.dumps(public)
    assert "additionalDetails" not in serialized
    assert "must-not-surface" not in serialized
    assert "private-balance" not in serialized


def test_solver_error_revalidates_quota_before_public_serialization():
    quota = {
        "limit_id": "codex/private-path",
        "reached_type": "future-private-reason",
        "windows": [{"kind": "primary", "window_minutes": 300, "used_percent": 5}],
        "secret": "never-public",
    }
    public = SolverError("quota_exceeded", "fixed", "solve", "quota", True, quota=quota).public()
    assert public["quota"] == {
        "windows": [{"kind": "primary", "window_minutes": 300, "used_percent": 5}],
    }
    assert normalize_rate_limit_context(public["quota"]) == public["quota"]
    assert "never-public" not in json.dumps(public)


def test_normalizer_preserves_only_safe_app_server_stream_diagnostics():
    error = normalize_provider_failure(
        {"code": "provider_stream_closed", "message": "raw stdout detail must not surface"},
        stage="solve",
    )
    assert error.public() == {
        "code": "provider_stream_closed",
        "message": "모델 공급자 연결이 예기치 않게 종료되었습니다.",
        "stage": "solve",
        "category": "temporary",
        "retryable": True,
    }
