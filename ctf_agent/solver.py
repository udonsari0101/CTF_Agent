"""Bounded, owner-scoped orchestration for an isolated CTF solver.

This module deliberately does not launch Codex, a shell, or a container.  The
web application must bind an authenticated provider account to an adapter that
can prove the isolation properties described by :class:`AdapterCapabilities`.
If those properties cannot be enforced, solving is refused before the adapter
is allowed to inspect a challenge.

Only structured progress, a discovered flag, and the final Markdown write-up
are retained.  Challenge text, solution scratch notes, prompts, physical paths,
and account identifiers are never placed in public snapshots or events.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence


_OPAQUE_ID = re.compile(r"[0-9a-f]{32}\Z")
_SAFE_SETTING = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}\Z")
_SAFE_PROVIDER_CODE = re.compile(r"(?:TAC|CVP)(?:[-_][A-Z0-9]{1,12})?\Z", re.IGNORECASE)
_PROVIDER_CODE_IN_TEXT = re.compile(
    r"(?<![A-Za-z0-9])((?:TAC|CVP)(?:[-_][A-Za-z0-9]{1,12})?)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_SOFT_REFUSAL = re.compile(
    r"\b(?:"
    r"(?:i|we)\s+(?:can(?:not|'t)|will\s+not|won't)\s+"
    r"(?:assist|help|comply|continue|proceed|perform|complete|execute|support|provide|work)\b|"
    r"(?:i|we)\s+(?:am|are)\s+unable\s+to\s+"
    r"(?:assist|help|comply|continue|proceed|perform|complete|execute|support|provide|work)\b|"
    r"(?:i|we)\s+(?:must|have\s+to)\s+(?:refuse|decline)\b|"
    r"(?:i'm|we're)\s+unable\s+to\s+"
    r"(?:assist|help|comply|continue|proceed|perform|complete|execute|support|provide|work)\b|"
    r"(?:i|we)\s+(?:must|have\s+to)\s+(?:stop|refuse|decline)\b|"
    r"(?:unable|not\s+(?:permitted|allowed))\s+to\s+"
    r"(?:assist|help|comply|continue|proceed|perform|complete|execute|work)|"
    r"(?:request|task|action|assistance)\s+(?:is|was|has\s+been)\s+"
    r"(?:denied|blocked|refused|restricted|disallowed|not\s+(?:permitted|allowed))"
    r")\b",
    re.IGNORECASE,
)
_SOFT_POLICY_CONTEXT = re.compile(
    r"\b(?:security|safety|content|cyber(?:security)?|provider)\s+"
    r"(?:policy|policies|restriction|restrictions|guardrail|guardrails)\b|"
    r"\b(?:policy|policies|guardrail|guardrails)\s+"
    r"(?:blocks?|blocked|prevents?|prevented|prohibits?|prohibited|"
    r"forbids?|forbidden|restricts?|restricted|does\s+not\s+allow)\b|"
    r"\b(?:disallowed|restricted|prohibited)\s+"
    r"(?:cyber|cybersecurity|security)\s+(?:request|task|activity|action)\b",
    re.IGNORECASE,
)
_SOFT_PROVIDER_CODE_CONTEXT = re.compile(
    r"(?:\b(?P<before>(?:TAC|CVP)(?:[-_][A-Za-z0-9]{1,12})?)\b"
    r".{0,48}\b(?:policy|restriction|violation|guardrail|blocked|denied|disallowed)\b)|"
    r"(?:\b(?:policy|restriction|violation|guardrail|blocked|denied|disallowed)\b"
    r".{0,48}\b(?P<reverse>(?:TAC|CVP)(?:[-_][A-Za-z0-9]{1,12})?)\b)",
    re.IGNORECASE,
)
_SOFT_TOOL_UNAVAILABLE = (
    re.compile(
        r"\b(?:i|we)\s+(?:do\s+not|don't|cannot|can't)\s+(?:have\s+)?"
        r"(?:access(?:\s+to)?|use)\s+(?:the\s+|a\s+)?(?:local\s+)?"
        r"(?<!remote\s)(?:shell|terminal|command(?:[- ]line|[- ]execution)?)"
        r"(?:\s+(?:tool|tools|access|capability|capabilities))?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?<!remote\s)(?:shell|terminal|command(?:[- ]line|[- ]execution)?)\s+"
        r"(?:tool|tools|access|capability|capabilities)\s+"
        r"(?:is|are)\s+(?:unavailable|disabled|inaccessible|not\s+(?:available|provided))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bno\s+(?:(?:local|built-in)\s+)?(?<!remote\s)"
        r"(?:shell|terminal|command(?:[- ]line|[- ]execution)?)\s+"
        r"(?:tool|tools|access|capability|capabilities)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:(?:i|we)\s+(?:cannot|can't|(?:am|are)\s+unable\s+to)|"
        r"(?:i'm|we're)\s+unable\s+to)\s+"
        r"(?:run|execute)\s+(?:shell\s+)?commands?\s+"
        r"(?:because|since|as)\s+(?:this\s+(?:session|environment)\s+"
        r"(?:does\s+not|doesn't)\s+(?:provide|have)|there\s+(?:is|are)\s+no)\s+"
        r"(?:a\s+)?(?:shell|terminal|command[- ]execution)?\s*tools?\b",
        re.IGNORECASE,
    ),
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RATE_LIMIT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RATE_LIMIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}\Z")
_RATE_LIMIT_REACHED_TYPES = frozenset({
    "rate_limit_reached",
    "workspace_owner_credits_depleted",
    "workspace_member_credits_depleted",
    "workspace_owner_usage_limit_reached",
    "workspace_member_usage_limit_reached",
})


def normalize_rate_limit_context(value: object) -> dict[str, Any] | None:
    """Validate the small quota subset allowed in public solver errors."""

    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    limit_id = value.get("limit_id")
    if isinstance(limit_id, str) and _RATE_LIMIT_ID.fullmatch(limit_id):
        result["limit_id"] = limit_id
    limit_name = value.get("limit_name")
    if isinstance(limit_name, str) and _RATE_LIMIT_NAME.fullmatch(limit_name):
        result["limit_name"] = limit_name
    reached_type = value.get("reached_type")
    if reached_type in _RATE_LIMIT_REACHED_TYPES:
        result["reached_type"] = reached_type
    spend_control = value.get("spend_control_reached")
    if isinstance(spend_control, bool):
        result["spend_control_reached"] = spend_control
    windows = []
    raw_windows = value.get("windows")
    if isinstance(raw_windows, Sequence) and not isinstance(raw_windows, (str, bytes, bytearray)):
        seen = set()
        for raw_window in raw_windows[:2]:
            if not isinstance(raw_window, Mapping) or raw_window.get("kind") not in {"primary", "secondary"}:
                continue
            kind = raw_window["kind"]
            if kind in seen:
                continue
            window: dict[str, Any] = {"kind": kind}
            minutes = raw_window.get("window_minutes")
            if isinstance(minutes, int) and not isinstance(minutes, bool) and 0 < minutes <= 525_600:
                window["window_minutes"] = minutes
            used = raw_window.get("used_percent")
            if isinstance(used, int) and not isinstance(used, bool) and 0 <= used <= 10_000:
                window["used_percent"] = used
            resets = raw_window.get("resets_at")
            if isinstance(resets, int) and not isinstance(resets, bool) and 0 <= resets <= 4_102_444_800:
                window["resets_at"] = resets
            if len(window) > 1:
                windows.append(window)
                seen.add(kind)
    if windows:
        result["windows"] = windows
    return result or None


class SolvePhase(StrEnum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    FLAG_FOUND = "flag_found"
    WRITING = "writing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    REFUSED = "refused"


class EventKind(StrEnum):
    STATUS = "status"
    PROGRESS = "progress"
    FLAG = "flag"
    WRITEUP = "writeup"
    ERROR = "error"


class ProgressCode(StrEnum):
    PREPARING = "preparing"
    ANALYZING = "analyzing"
    WAITING_FOR_MODEL = "waiting_for_model"
    INSPECTING_FILES = "inspecting_files"
    EXECUTING = "executing"
    VALIDATING_FLAG = "validating_flag"
    DRAFTING_WRITEUP = "drafting_writeup"


@dataclass(frozen=True, slots=True)
class ModelConfiguration:
    """Provider settings already validated against that account's catalog."""

    provider: str
    model: str
    reasoning_effort: str
    service_tier: str | None = None

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("provider", self.provider, 40),
            ("model", self.model, 200),
            ("reasoning_effort", self.reasoning_effort, 40),
        ):
            if not isinstance(value, str) or len(value) > maximum or not _SAFE_SETTING.fullmatch(value):
                raise ValueError(f"invalid {name}")
        if self.service_tier is not None and (
            not isinstance(self.service_tier, str)
            or len(self.service_tier) > 40
            or not _SAFE_SETTING.fullmatch(self.service_tier)
        ):
            raise ValueError("invalid service_tier")

    def public(self) -> dict[str, str | None]:
        return {
            "provider": self.provider,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "service_tier": self.service_tier,
        }


@dataclass(frozen=True, slots=True)
class SelectedAccount:
    """A selected account record resolved after an owner-scoped DB lookup.

    The account id is used only to verify that the injected adapter is bound to
    the same credential home.  It is intentionally absent from public output.
    """

    account_id: str = field(repr=False)
    owner_id: str = field(repr=False)
    configuration: ModelConfiguration

    def __post_init__(self) -> None:
        if not _OPAQUE_ID.fullmatch(self.account_id):
            raise ValueError("invalid account id")
        _validate_owner_id(self.owner_id)

    @classmethod
    def from_record(
        cls,
        record: Mapping[str, Any],
        expected_owner_id: str,
        *,
        require_selected: bool = True,
    ) -> "SelectedAccount":
        """Build from ``AccountManager.get`` output without accepting secrets."""

        values = dict(record)
        owner_id = values.get("owner_user_id")
        if not isinstance(owner_id, str) or not secrets.compare_digest(owner_id, expected_owner_id):
            raise ValueError("account is not owned by the authenticated user")
        if require_selected and values.get("selected") not in (True, 1):
            raise ValueError("account is not selected")
        # An explicit model and effort make the executed configuration
        # reviewable and prevent a provider-default change between runs.
        if not values.get("model") or not values.get("reasoning_effort"):
            raise ValueError("a model and reasoning effort must be selected")
        return cls(
            account_id=str(values.get("id", "")),
            owner_id=owner_id,
            configuration=ModelConfiguration(
                provider=str(values.get("provider", "")),
                model=str(values["model"]),
                reasoning_effort=str(values["reasoning_effort"]),
                service_tier=values.get("service_tier"),
            ),
        )


def _validate_owner_id(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 200
        or _CONTROL.search(value)
    ):
        raise ValueError("invalid owner id")


@dataclass(frozen=True, slots=True)
class OwnedChallenge:
    """A challenge directory bound after the caller checks DB ownership."""

    owner_id: str = field(repr=False)
    workspace_id: str
    challenge_id: str
    root: Path = field(repr=False)

    @classmethod
    def bind(
        cls,
        storage_root: Path,
        owner_id: str,
        workspace_id: str,
        challenge_id: str,
        *,
        challenge_dir: Path | None = None,
    ) -> "OwnedChallenge":
        """Bind exactly ``workspaces/<id>/challenges/<id>`` beneath storage.

        This is a path check, not an authorization lookup.  The route must first
        fetch the workspace with both ``workspace_id`` and the authenticated
        ``owner_id`` before calling this constructor.
        """

        _validate_owner_id(owner_id)
        if not _OPAQUE_ID.fullmatch(workspace_id) or not _OPAQUE_ID.fullmatch(challenge_id):
            raise ValueError("invalid workspace or challenge id")
        base = Path(storage_root).resolve(strict=True)
        expected_lexical = Path(storage_root) / "workspaces" / workspace_id / "challenges" / challenge_id
        supplied = expected_lexical if challenge_dir is None else Path(challenge_dir)
        expected = expected_lexical.resolve(strict=True)
        actual = supplied.resolve(strict=True)
        if actual != expected or not actual.is_dir() or not actual.is_relative_to(base):
            raise ValueError("challenge directory is outside its stored location")

        # Reject aliases in the user-controlled part of the storage tree.  A
        # future adapter still has to make symlinks *inside* the mounted tree
        # unable to reach anything outside /challenge.
        cursor = Path(storage_root)
        for part in ("workspaces", workspace_id, "challenges", challenge_id):
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("challenge directory may not traverse symlinks")
        return cls(owner_id=owner_id, workspace_id=workspace_id, challenge_id=challenge_id, root=actual)


@dataclass(frozen=True, slots=True)
class NetworkEndpoint:
    host: str
    port: int
    protocol: str = "tcp"

    def __post_init__(self) -> None:
        host = self.host.strip().lower() if isinstance(self.host, str) else ""
        valid_host = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            valid_host = True
        except ValueError:
            valid_host = bool(
                len(host) <= 253
                and re.fullmatch(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host)
            )
        if not valid_host or not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("invalid network endpoint")
        if self.protocol not in {"tcp", "udp"}:
            raise ValueError("invalid network protocol")
        object.__setattr__(self, "host", host)

    def public(self) -> dict[str, str | int]:
        return {"host": self.host, "port": self.port, "protocol": self.protocol}


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    enabled: bool = False
    endpoints: tuple[NetworkEndpoint, ...] = ()

    def __post_init__(self) -> None:
        if not self.enabled and self.endpoints:
            raise ValueError("offline policy cannot include endpoints")
        if self.enabled and not self.endpoints:
            raise ValueError("network access requires a non-empty endpoint allowlist")
        if len(self.endpoints) > 20:
            raise ValueError("too many network endpoints")

    @classmethod
    def offline(cls) -> "NetworkPolicy":
        return cls()

    @classmethod
    def restricted(cls, endpoints: Sequence[NetworkEndpoint]) -> "NetworkPolicy":
        return cls(enabled=True, endpoints=tuple(endpoints))


@dataclass(frozen=True, slots=True)
class SolverLimits:
    max_seconds: int = 3600
    max_challenge_text_chars: int = 256_000
    max_flag_chars: int = 4_000
    max_private_notes_chars: int = 1_000_000
    max_writeup_chars: int = 2_000_000

    def __post_init__(self) -> None:
        if not 10 <= self.max_seconds <= 86_400:
            raise ValueError("max_seconds is outside the supported range")
        for name in ("max_challenge_text_chars", "max_flag_chars", "max_private_notes_chars", "max_writeup_chars"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class SolveRequest:
    challenge: OwnedChallenge
    account: SelectedAccount
    challenge_name: str
    challenge_text: str = field(repr=False)
    network: NetworkPolicy = field(default_factory=NetworkPolicy.offline)
    limits: SolverLimits = field(default_factory=SolverLimits)

    def __post_init__(self) -> None:
        if not secrets.compare_digest(self.challenge.owner_id, self.account.owner_id):
            raise ValueError("challenge and account owners differ")
        if (
            not isinstance(self.challenge_name, str)
            or not self.challenge_name.strip()
            or len(self.challenge_name) > 300
            or _CONTROL.search(self.challenge_name)
        ):
            raise ValueError("invalid challenge name")
        if (
            not isinstance(self.challenge_text, str)
            or len(self.challenge_text) > self.limits.max_challenge_text_chars
            or _CONTROL.search(self.challenge_text)
        ):
            raise ValueError("invalid challenge text")


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Claims the engine requires from an independently audited adapter."""

    backend: str
    challenge_only_filesystem: bool
    symlink_escape_blocked: bool
    network_denied: bool
    network_allowlist_enforced: bool
    host_secrets_hidden: bool
    auth_not_visible_to_model_tools: bool
    unprivileged: bool
    no_new_privileges: bool
    supports_cancellation: bool


@dataclass(frozen=True, slots=True)
class AdapterBinding:
    account_id: str = field(repr=False)
    configuration: ModelConfiguration


class EphemeralPrompt:
    """Prompt wrapper whose repr/str never disclose its text."""

    __slots__ = ("__text",)

    def __init__(self, text: str):
        self.__text = text

    @property
    def text(self) -> str:
        return self.__text

    def __repr__(self) -> str:
        return "<EphemeralPrompt redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class AdapterContext:
    """The complete execution view; it contains no owner or account id."""

    run_id: str
    challenge_root: Path = field(repr=False)
    mount_path: str
    configuration: ModelConfiguration
    network: NetworkPolicy
    deadline_seconds: int


@dataclass(frozen=True, slots=True)
class ProgressUpdate:
    code: ProgressCode
    percent: int | None = None

    def __post_init__(self) -> None:
        if self.percent is not None and (
            not isinstance(self.percent, int) or isinstance(self.percent, bool) or not 0 <= self.percent <= 100
        ):
            raise ValueError("progress percent must be between 0 and 100")

    def public(self) -> dict[str, str | int | None]:
        return {"code": self.code.value, "percent": self.percent}


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    flag: str = field(repr=False)
    private_notes: str = field(default="", repr=False)


@dataclass(frozen=True, slots=True)
class AdapterProviderFailure(Exception):
    """A raw upstream failure transported to the normalizer, never to clients."""

    payload: object = field(repr=False)


class SolverAdapter(Protocol):
    """Account-bound adapter contract for a separately isolated executor."""

    async def capabilities(self, network: NetworkPolicy) -> AdapterCapabilities: ...

    async def binding(self) -> AdapterBinding: ...

    async def discover(
        self,
        context: AdapterContext,
        prompt: EphemeralPrompt,
        report: Callable[[ProgressUpdate], Awaitable[None]],
        cancelled: asyncio.Event,
    ) -> DiscoveryResult: ...

    async def writeup(
        self,
        context: AdapterContext,
        prompt: EphemeralPrompt,
        report: Callable[[ProgressUpdate], Awaitable[None]],
        cancelled: asyncio.Event,
    ) -> str: ...

    async def cancel(self, run_id: str) -> None: ...


class RefusingAdapter:
    """Safe default for deployments without a proven per-job sandbox."""

    def __init__(self, binding: AdapterBinding, reason: str = "per-job isolation is not configured"):
        self._binding = binding
        self.reason = reason

    async def capabilities(self, network: NetworkPolicy) -> AdapterCapabilities:
        return AdapterCapabilities(
            backend=self.reason,
            challenge_only_filesystem=False,
            symlink_escape_blocked=False,
            network_denied=False,
            network_allowlist_enforced=False,
            host_secrets_hidden=False,
            auth_not_visible_to_model_tools=False,
            unprivileged=False,
            no_new_privileges=False,
            supports_cancellation=False,
        )

    async def binding(self) -> AdapterBinding:
        return self._binding

    async def discover(self, *args: Any, **kwargs: Any) -> DiscoveryResult:
        raise AssertionError("unsafe adapter execution was not refused")

    async def writeup(self, *args: Any, **kwargs: Any) -> str:
        raise AssertionError("unsafe adapter execution was not refused")

    async def cancel(self, run_id: str) -> None:
        return None


@dataclass(frozen=True, slots=True)
class SolverError:
    code: str
    message: str
    stage: str
    category: str
    retryable: bool
    provider_code: str | None = None
    requirements: tuple[str, ...] = ()
    quota: Mapping[str, Any] | None = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "stage": self.stage,
            "category": self.category,
            "retryable": self.retryable,
        }
        if self.provider_code:
            result["provider_code"] = self.provider_code
        if self.requirements:
            result["requirements"] = list(self.requirements)
        quota = normalize_rate_limit_context(self.quota)
        if quota:
            result["quota"] = quota
        return result


class SolverLookupError(LookupError):
    pass


class SolverConflictError(RuntimeError):
    pass


class IsolationUnavailable(RuntimeError):
    def __init__(self, missing: Sequence[str]):
        super().__init__("required per-job isolation is unavailable")
        self.missing = tuple(missing)


@dataclass(frozen=True, slots=True)
class SolveEvent:
    sequence: int
    run_id: str
    workspace_id: str
    challenge_id: str
    kind: EventKind
    phase: SolvePhase
    terminal: bool
    occurred_at: float
    progress: dict[str, Any] | None = None
    flag: str | None = field(default=None, repr=False)
    writeup_markdown: str | None = field(default=None, repr=False)
    error: dict[str, Any] | None = None

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "sequence": self.sequence,
            "run_id": self.run_id,
            "workspace_id": self.workspace_id,
            "challenge_id": self.challenge_id,
            "kind": self.kind.value,
            "phase": self.phase.value,
            "terminal": self.terminal,
            "occurred_at": self.occurred_at,
        }
        if self.progress is not None:
            result["progress"] = self.progress
        if self.flag is not None:
            result["flag"] = self.flag
        if self.writeup_markdown is not None:
            result["writeup_markdown"] = self.writeup_markdown
        if self.error is not None:
            result["error"] = self.error
        return result


@dataclass(slots=True)
class _Run:
    run_id: str
    owner_id: str = field(repr=False)
    workspace_id: str
    challenge_id: str
    model: ModelConfiguration
    started_at: float
    updated_at: float
    phase: SolvePhase = SolvePhase.QUEUED
    terminal: bool = False
    sequence: int = 0
    progress: dict[str, Any] | None = None
    flag: str | None = field(default=None, repr=False)
    writeup_markdown: str | None = field(default=None, repr=False)
    error: SolverError | None = None
    events: list[SolveEvent] = field(default_factory=list, repr=False)
    cancelled: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    task: asyncio.Task[None] | None = field(default=None, repr=False)
    adapter: SolverAdapter | None = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "run_id": self.run_id,
            "workspace_id": self.workspace_id,
            "challenge_id": self.challenge_id,
            "phase": self.phase.value,
            "terminal": self.terminal,
            "progress": self.progress,
            "model": self.model.public(),
            "sequence": self.sequence,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }
        if self.flag is not None:
            result["flag"] = self.flag
        if self.writeup_markdown is not None:
            result["writeup_markdown"] = self.writeup_markdown
        if self.error is not None:
            result["error"] = self.error.public()
        return result


EventSink = Callable[[str, SolveEvent], Awaitable[None] | None]


class SolverEngine:
    """In-memory state machine around an externally isolated solver adapter."""

    def __init__(
        self,
        *,
        on_event: EventSink | None = None,
        max_active: int = 4,
        event_history: int = 200,
        clock: Callable[[], float] = time.time,
    ):
        if not 1 <= max_active <= 100 or not 10 <= event_history <= 10_000:
            raise ValueError("invalid engine limit")
        self._on_event = on_event
        self._max_active = max_active
        self._event_history = event_history
        self._clock = clock
        self._runs: dict[str, _Run] = {}
        self._active_challenges: dict[tuple[str, str, str], str] = {}
        self._lock = asyncio.Lock()

    async def start(self, request: SolveRequest, adapter: SolverAdapter) -> dict[str, Any]:
        """Start one run and return immediately with an owner-safe snapshot."""

        key = (request.challenge.owner_id, request.challenge.workspace_id, request.challenge.challenge_id)
        async with self._lock:
            if key in self._active_challenges:
                raise SolverConflictError("this challenge already has an active solver")
            if sum(not item.terminal for item in self._runs.values()) >= self._max_active:
                raise SolverConflictError("solver capacity is full")
            run_id = secrets.token_urlsafe(24)
            timestamp = self._clock()
            run = _Run(
                run_id=run_id,
                owner_id=request.challenge.owner_id,
                workspace_id=request.challenge.workspace_id,
                challenge_id=request.challenge.challenge_id,
                model=request.account.configuration,
                started_at=timestamp,
                updated_at=timestamp,
                adapter=adapter,
            )
            self._runs[run_id] = run
            self._active_challenges[key] = run_id
        await self._emit(run, EventKind.STATUS, SolvePhase.QUEUED)
        run.task = asyncio.create_task(self._execute(run, request, adapter), name=f"ctf-solver-{run_id}")
        return run.public()

    def get(self, run_id: str, owner_id: str) -> dict[str, Any]:
        return self._owned_run(run_id, owner_id).public()

    def events(self, run_id: str, owner_id: str, *, after: int = 0) -> list[dict[str, Any]]:
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise ValueError("after must be a non-negative integer")
        run = self._owned_run(run_id, owner_id)
        return [event.public() for event in run.events if event.sequence > after]

    async def wait(self, run_id: str, owner_id: str) -> dict[str, Any]:
        run = self._owned_run(run_id, owner_id)
        if run.task:
            await asyncio.gather(run.task, return_exceptions=True)
        return run.public()

    async def cancel(self, run_id: str, owner_id: str) -> dict[str, Any]:
        run = self._owned_run(run_id, owner_id)
        if run.terminal:
            return run.public()
        run.cancelled.set()
        adapter, task = run.adapter, run.task
        if adapter is not None:
            try:
                await asyncio.wait_for(adapter.cancel(run_id), timeout=5)
            except (Exception, asyncio.CancelledError):
                pass
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if not run.terminal:
            await self._emit(run, EventKind.STATUS, SolvePhase.CANCELLED, terminal=True)
            await self._release(run)
        return run.public()

    async def discard(self, run_id: str, owner_id: str) -> None:
        """Forget a terminal run after the integration layer persisted it."""

        run = self._owned_run(run_id, owner_id)
        if not run.terminal:
            raise SolverConflictError("an active run cannot be discarded")
        async with self._lock:
            self._runs.pop(run_id, None)

    def _owned_run(self, run_id: str, owner_id: str) -> _Run:
        _validate_owner_id(owner_id)
        run = self._runs.get(run_id)
        if run is None or not secrets.compare_digest(run.owner_id, owner_id):
            # Same response for an unknown run and another user's run.
            raise SolverLookupError("solver run was not found")
        return run

    async def _execute(self, run: _Run, request: SolveRequest, adapter: SolverAdapter) -> None:
        try:
            async with asyncio.timeout(request.limits.max_seconds):
                await self._emit(run, EventKind.STATUS, SolvePhase.VALIDATING)
                capabilities = await adapter.capabilities(request.network)
                _require_isolation(capabilities, request.network)
                binding = await adapter.binding()
                if (
                    not isinstance(binding, AdapterBinding)
                    or not secrets.compare_digest(binding.account_id, request.account.account_id)
                    or binding.configuration != request.account.configuration
                ):
                    raise SolverErrorException(
                        SolverError(
                            code="account_configuration_changed",
                            message="선택한 계정 또는 모델 설정이 바뀌어 실행하지 않았습니다.",
                            stage="validation",
                            category="account",
                            retryable=True,
                        )
                    )
                if run.cancelled.is_set():
                    raise asyncio.CancelledError

                context = AdapterContext(
                    run_id=run.run_id,
                    challenge_root=request.challenge.root,
                    mount_path="/challenge",
                    configuration=request.account.configuration,
                    network=request.network,
                    deadline_seconds=request.limits.max_seconds,
                )
                await self._emit(run, EventKind.STATUS, SolvePhase.RUNNING)
                discovery = await adapter.discover(
                    context,
                    _discovery_prompt(request),
                    self._progress_reporter(run, SolvePhase.RUNNING),
                    run.cancelled,
                )
                if run.cancelled.is_set():
                    raise asyncio.CancelledError
                discovery = _validate_discovery(discovery, request.limits)

                # This transition is deliberately completed before starting the
                # write-up request.  Integrations can persist the flag and enqueue
                # its Telegram event from this ordered event.
                await self._emit(run, EventKind.FLAG, SolvePhase.FLAG_FOUND, flag=discovery.flag)
                await self._emit(run, EventKind.STATUS, SolvePhase.WRITING)
                markdown = await adapter.writeup(
                    context,
                    _writeup_prompt(request, discovery),
                    self._progress_reporter(run, SolvePhase.WRITING),
                    run.cancelled,
                )
                if run.cancelled.is_set():
                    raise asyncio.CancelledError
                markdown = _validate_writeup(markdown, request.limits, request.challenge.root)
                await self._emit(
                    run,
                    EventKind.WRITEUP,
                    SolvePhase.COMPLETED,
                    writeup_markdown=markdown,
                    terminal=True,
                )
        except asyncio.CancelledError:
            if not run.terminal:
                # Shield the state transition from task cancellation so clients
                # always receive a terminal cancellation state.
                await asyncio.shield(self._emit(run, EventKind.STATUS, SolvePhase.CANCELLED, terminal=True))
        except IsolationUnavailable as exc:
            error = SolverError(
                code="isolation_unavailable",
                message="문제 전용 실행 격리를 확인할 수 없어 풀이를 시작하지 않았습니다.",
                stage="validation",
                category="safety",
                retryable=False,
                requirements=exc.missing,
            )
            await self._emit(run, EventKind.ERROR, SolvePhase.REFUSED, error=error, terminal=True)
        except SolverErrorException as exc:
            await self._emit(run, EventKind.ERROR, SolvePhase.FAILED, error=exc.error, terminal=True)
        except TimeoutError:
            await self._safe_adapter_cancel(adapter, run.run_id)
            await self._emit(
                run,
                EventKind.ERROR,
                SolvePhase.FLAG_FOUND if run.flag is not None else SolvePhase.FAILED,
                error=SolverError(
                    code="timeout",
                    message="문제 풀이 제한 시간이 지났습니다.",
                    stage="writeup" if run.flag is not None else "solve",
                    category="temporary",
                    retryable=True,
                ),
                terminal=True,
            )
        except Exception as exc:
            await self._safe_adapter_cancel(adapter, run.run_id)
            stage = "writeup" if run.flag is not None else "solve"
            error = normalize_provider_failure(exc, stage=stage)
            await self._emit(
                run,
                EventKind.ERROR,
                SolvePhase.FLAG_FOUND if run.flag is not None else SolvePhase.FAILED,
                error=error,
                terminal=True,
            )
        finally:
            await self._release(run)

    def _progress_reporter(self, run: _Run, expected_phase: SolvePhase):
        async def report(update: ProgressUpdate) -> None:
            if run.cancelled.is_set():
                raise asyncio.CancelledError
            if not isinstance(update, ProgressUpdate):
                raise ValueError("adapter emitted an invalid progress update")
            # An adapter cannot move the state machine or attach arbitrary log
            # text.  Only this fixed code and an optional percentage survive.
            await self._emit(run, EventKind.PROGRESS, expected_phase, progress=update.public())

        return report

    async def _emit(
        self,
        run: _Run,
        kind: EventKind,
        phase: SolvePhase,
        *,
        terminal: bool = False,
        progress: dict[str, Any] | None = None,
        flag: str | None = None,
        writeup_markdown: str | None = None,
        error: SolverError | None = None,
    ) -> None:
        if run.terminal:
            return
        run.phase = phase
        run.terminal = terminal
        run.sequence += 1
        run.updated_at = self._clock()
        if progress is not None:
            run.progress = dict(progress)
        if flag is not None:
            run.flag = flag
        if writeup_markdown is not None:
            run.writeup_markdown = writeup_markdown
        if error is not None:
            run.error = error
        event = SolveEvent(
            sequence=run.sequence,
            run_id=run.run_id,
            workspace_id=run.workspace_id,
            challenge_id=run.challenge_id,
            kind=kind,
            phase=phase,
            terminal=terminal,
            occurred_at=run.updated_at,
            progress=dict(progress) if progress is not None else None,
            flag=flag,
            writeup_markdown=writeup_markdown,
            error=error.public() if error else None,
        )
        run.events.append(event)
        if len(run.events) > self._event_history:
            del run.events[: len(run.events) - self._event_history]
        if self._on_event:
            try:
                result = self._on_event(run.owner_id, event)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                # State is committed before external notification.  A DB/outbox
                # integration retries independently and never hides a found flag.
                pass

    async def _release(self, run: _Run) -> None:
        key = (run.owner_id, run.workspace_id, run.challenge_id)
        async with self._lock:
            if self._active_challenges.get(key) == run.run_id:
                self._active_challenges.pop(key, None)
            run.adapter = None

    @staticmethod
    async def _safe_adapter_cancel(adapter: SolverAdapter, run_id: str) -> None:
        try:
            await asyncio.wait_for(adapter.cancel(run_id), timeout=5)
        except (Exception, asyncio.CancelledError):
            pass


@dataclass(frozen=True, slots=True)
class SolverErrorException(Exception):
    error: SolverError


def _require_isolation(capabilities: AdapterCapabilities, network: NetworkPolicy) -> None:
    if not isinstance(capabilities, AdapterCapabilities):
        raise IsolationUnavailable(("audited_adapter_capabilities",))
    missing: list[str] = []
    requirements = (
        ("challenge_only_filesystem", capabilities.challenge_only_filesystem),
        ("symlink_escape_blocked", capabilities.symlink_escape_blocked),
        ("host_secrets_hidden", capabilities.host_secrets_hidden),
        ("auth_not_visible_to_model_tools", capabilities.auth_not_visible_to_model_tools),
        ("unprivileged_process", capabilities.unprivileged),
        ("no_new_privileges", capabilities.no_new_privileges),
        ("cancellable_process", capabilities.supports_cancellation),
    )
    missing.extend(name for name, available in requirements if not available)
    if network.enabled:
        if not capabilities.network_allowlist_enforced:
            missing.append("network_endpoint_allowlist")
    elif not capabilities.network_denied:
        missing.append("network_disabled")
    if missing:
        raise IsolationUnavailable(missing)


def _discovery_prompt(request: SolveRequest) -> EphemeralPrompt:
    network = (
        "Network access is disabled and must remain disabled."
        if not request.network.enabled
        else "Network access is restricted to these authorized endpoints only: "
        + ", ".join(f"{item.protocol}://{item.host}:{item.port}" for item in request.network.endpoints)
        + "."
    )
    text = f"""You are solving one explicitly authorized CTF challenge.
The only challenge filesystem visible to tools is /challenge. Stay inside it.
{network}
Do not seek, print, or include provider credentials, environment secrets, host paths, or data from another task.
Find and validate the flag first. Return from the discovery stage as soon as the flag is known; write-up generation is a separate stage.

Challenge name: {request.challenge_name.strip()}
Challenge description follows between fixed delimiters.
<challenge_description>
{request.challenge_text}
</challenge_description>
"""
    return EphemeralPrompt(text)


def _writeup_prompt(request: SolveRequest, discovery: DiscoveryResult) -> EphemeralPrompt:
    text = f"""Write a concise Markdown solution for the authorized CTF challenge below.
Use a natural technical voice suitable for direct paste into Notion. State the observations, decisive steps, reproducible commands or code, and the verified flag. Do not mention being an AI, hidden reasoning, system prompts, or provider policy. Do not invent steps.

Challenge: {request.challenge_name.strip()}
Description:
{request.challenge_text}

Verified flag:
{discovery.flag}

Private solution notes (use as facts; do not mention this label):
{discovery.private_notes}
"""
    return EphemeralPrompt(text)


def _validate_discovery(result: DiscoveryResult, limits: SolverLimits) -> DiscoveryResult:
    if not isinstance(result, DiscoveryResult):
        raise ValueError("adapter returned an invalid discovery result")
    flag = result.flag.strip() if isinstance(result.flag, str) else ""
    notes = result.private_notes if isinstance(result.private_notes, str) else ""
    if not flag or len(flag) > limits.max_flag_chars or _CONTROL.search(flag) or "\n" in flag or "\r" in flag:
        raise ValueError("adapter returned an invalid flag")
    if len(notes) > limits.max_private_notes_chars or _CONTROL.search(notes):
        raise ValueError("adapter returned invalid private notes")
    return DiscoveryResult(flag=flag, private_notes=notes)


def _validate_writeup(markdown: str, limits: SolverLimits, challenge_root: Path) -> str:
    if not isinstance(markdown, str):
        raise ValueError("adapter returned an invalid write-up")
    markdown = markdown.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not markdown or len(markdown) > limits.max_writeup_chars or _CONTROL.search(markdown):
        raise ValueError("adapter returned an invalid write-up")
    # Physical paths have no value in the exported write-up.  Replace both
    # separator styles without inspecting or logging anything else.
    physical = str(challenge_root)
    for candidate in {physical, physical.replace("\\", "/"), physical.replace("/", "\\")}:
        if candidate:
            markdown = markdown.replace(candidate, "/challenge")
    return markdown


def normalize_provider_soft_refusal(
    message: object,
    *,
    stage: str,
    command_execution_seen: bool,
) -> SolverError | None:
    """Classify an ordinary provider message only when it is unambiguous.

    Codex can occasionally end a successful protocol turn with a natural
    language refusal instead of a machine-readable error.  The text is used
    only as an ephemeral discriminator: this function returns either a fully
    fixed public error or ``None`` and never copies, excerpts, or hashes the
    provider message into its result.
    """

    if not isinstance(message, str) or not message or len(message) > 2 * 1024 * 1024:
        return None
    # Normalize only punctuation and whitespace needed by the bounded regular
    # expressions.  The normalized text remains local to this call.
    text = re.sub(r"\s+", " ", message.replace("’", "'")).strip()
    if not text:
        return None

    code_match = _SOFT_PROVIDER_CODE_CONTEXT.search(text)
    if _SOFT_REFUSAL.search(text) and (
        _SOFT_POLICY_CONTEXT.search(text) or code_match is not None
    ):
        safe_provider_code = None
        if code_match is not None:
            candidate = next(
                (value for value in code_match.groupdict().values() if value),
                None,
            )
            if isinstance(candidate, str) and _SAFE_PROVIDER_CODE.fullmatch(candidate):
                safe_provider_code = candidate.upper()
        return SolverError(
            code="policy_security",
            message="공급자의 보안 정책 제한으로 요청이 거절되었습니다.",
            stage=stage,
            category="policy_security",
            retryable=False,
            provider_code=safe_provider_code,
        )

    if not command_execution_seen and any(
        pattern.search(text) for pattern in _SOFT_TOOL_UNAVAILABLE
    ):
        return SolverError(
            code="provider_tools_unavailable",
            message="선택한 모델 응답에서 로컬 풀이 도구를 사용할 수 없다고 보고했습니다.",
            stage=stage,
            category="provider",
            retryable=False,
        )
    return None


_DAYBREAK_MODELS = {
    "gpt-daybreak-blue-latest",
    "gpt-daybreak-red-latest",
}


def normalize_provider_failure(
    error: object,
    *,
    stage: str,
    model: str | None = None,
    authenticated_preflight: bool = False,
) -> SolverError:
    """Convert provider diagnostics to a bounded result without raw text."""

    payload = error.payload if isinstance(error, AdapterProviderFailure) else error
    if isinstance(payload, SolverError):
        return payload
    if isinstance(payload, Mapping):
        code = payload.get("code")
        category = payload.get("category")
        provider_code = payload.get("provider_code")
        message_value = payload.get("message")
        error_type = payload.get("type")
        retryable_value = payload.get("retryable")
        codex_error_info = payload.get("codexErrorInfo")
        quota = normalize_rate_limit_context(payload.get("rate_limit"))
    else:
        code = getattr(payload, "code", None)
        category = getattr(payload, "category", None)
        provider_code = getattr(payload, "provider_code", None)
        message_value = getattr(payload, "message", None) or str(payload)
        error_type = getattr(payload, "type", None)
        retryable_value = getattr(payload, "retryable", None)
        codex_error_info = None
        quota = None

    # App-server exposes a bounded machine-readable error union.  Prefer it to
    # the free-form provider message, which must never be copied into public
    # state.  Object variants contain only an optional HTTP status code.
    codex_error_kind = codex_error_info if isinstance(codex_error_info, str) else None
    codex_http_status = None
    if isinstance(codex_error_info, Mapping) and len(codex_error_info) == 1:
        codex_error_kind, details = next(iter(codex_error_info.items()))
        if isinstance(details, Mapping):
            candidate_status = details.get("httpStatusCode")
            if isinstance(candidate_status, int) and not isinstance(candidate_status, bool):
                codex_http_status = candidate_status

    # The worker emits this exact code only after app-server asked the isolated
    # client to refresh an externally supplied ChatGPT token.  Preserve it even
    # for Daybreak: unlike a turn-level authorization rejection, this really
    # does require the user to sign in again.
    if code in (401, "401", "auth_required", "invalid_auth"):
        return SolverError(
            code="auth_required",
            message="선택한 공급자 계정에 다시 로그인해야 합니다.",
            stage=stage,
            category="auth",
            retryable=False,
        )
    if code == "codex_attestation_unavailable":
        return SolverError(
            code="codex_attestation_unavailable",
            message="현재 서버 실행 방식에서 요청된 Codex 클라이언트 attestation을 제공할 수 없습니다.",
            stage=stage,
            category="authorization",
            retryable=False,
            requirements=("지원되는 Codex 클라이언트 실행 방식",),
        )
    if code == "daybreak_route_rejected":
        return SolverError(
            code="daybreak_route_rejected",
            message="Daybreak 요청을 현재 Codex 실행 경로에서 완료하지 못했습니다.",
            stage=stage,
            category="authorization",
            retryable=False,
            requirements=("현재 로그인과 서버의 Daybreak 전달 경로 확인",),
        )

    daybreak_model = model in _DAYBREAK_MODELS
    if codex_error_kind in {"cyberPolicy", "misalignmentPolicyViolation"}:
        return SolverError(
            code="policy_security",
            message="공급자의 보안 정책 제한으로 요청이 거절되었습니다.",
            stage=stage,
            category="policy_security",
            retryable=False,
        )
    if (
        daybreak_model
        and authenticated_preflight
        and (
            codex_error_kind in {"unauthorized", "badRequest"}
            or codex_http_status in {400, 403}
        )
    ):
        return SolverError(
            code="daybreak_route_rejected",
            message="Daybreak 요청을 현재 Codex 실행 경로에서 완료하지 못했습니다.",
            stage=stage,
            category="authorization",
            retryable=False,
            requirements=("현재 로그인과 서버의 Daybreak 전달 경로 확인",),
        )
    if codex_http_status == 403:
        return SolverError(
            code="access_denied",
            message="선택한 공급자 또는 모델에 이 실행 방식의 사용 권한이 없습니다.",
            stage=stage,
            category="authorization",
            retryable=False,
        )
    if codex_error_kind == "unauthorized" or codex_http_status == 401:
        return SolverError(
            code="auth_required",
            message="선택한 공급자 계정에 다시 로그인해야 합니다.",
            stage=stage,
            category="auth",
            retryable=False,
        )
    if codex_error_kind == "usageLimitExceeded":
        return SolverError(
            code="usage_limit_exceeded",
            message="선택한 계정의 사용량 한도에 도달했습니다.",
            stage=stage,
            category="quota",
            retryable=True,
            quota=quota,
        )
    if codex_error_kind == "sessionBudgetExceeded":
        return SolverError(
            code="session_budget_exceeded",
            message="현재 공급자 세션의 사용 예산에 도달했습니다.",
            stage=stage,
            category="quota",
            retryable=True,
            quota=quota,
        )
    if codex_error_kind == "rateLimitExceeded" or codex_http_status == 429:
        return SolverError(
            code="rate_limit_exceeded",
            message="공급자의 요청 속도 제한에 도달했습니다.",
            stage=stage,
            category="quota",
            retryable=True,
            quota=quota,
        )
    if codex_error_kind == "contextWindowExceeded":
        return SolverError(
            code="context_limit",
            message="현재 풀이가 모델의 컨텍스트 한도를 초과했습니다.",
            stage=stage,
            category="model",
            retryable=False,
        )
    if codex_error_kind == "badRequest":
        return SolverError(
            code="provider_request_rejected",
            message="공급자가 현재 모델 요청을 처리할 수 없습니다.",
            stage=stage,
            category="model",
            retryable=False,
        )
    if codex_error_kind in {
        "serverOverloaded",
        "internalServerError",
        "httpConnectionFailed",
        "responseStreamConnectionFailed",
        "responseStreamDisconnected",
        "responseTooManyFailedAttempts",
    }:
        return SolverError(
            code="provider_unavailable",
            message="공급자 응답을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.",
            stage=stage,
            category="temporary",
            retryable=True,
        )

    if code == "provider_tools_unavailable":
        return SolverError(
            code="provider_tools_unavailable",
            message="선택한 모델 응답에서 로컬 풀이 도구를 사용할 수 없다고 보고했습니다.",
            stage=stage,
            category="provider",
            retryable=False,
        )

    fragments = [value for value in (code, category, provider_code, message_value, error_type) if isinstance(value, (str, int))]
    diagnostic = " ".join(str(value) for value in fragments)[:65_536]
    lowered = diagnostic.lower()
    policy_text_context = any(
        term in lowered
        for term in (
            "policy_security",
            "policy_violation",
            "content_policy",
            "security policy",
            "safety restriction",
            "cyber policy",
        )
    ) or _SOFT_PROVIDER_CODE_CONTEXT.search(diagnostic) is not None
    safe_provider_code = None
    if isinstance(provider_code, str) and _SAFE_PROVIDER_CODE.fullmatch(provider_code):
        safe_provider_code = provider_code.upper()
    elif isinstance(code, str) and _SAFE_PROVIDER_CODE.fullmatch(code):
        safe_provider_code = code.upper()
    elif policy_text_context:
        found = _PROVIDER_CODE_IN_TEXT.search(diagnostic)
        if found:
            safe_provider_code = found.group(1).upper()

    if safe_provider_code or policy_text_context:
        return SolverError(
            code="policy_security",
            message="공급자의 보안 정책 제한으로 요청이 거절되었습니다.",
            stage=stage,
            category="policy_security",
            retryable=False,
            provider_code=safe_provider_code,
        )
    if any(
        term in lowered for term in ("unauthorized", "authentication", "invalid_api_key", "token expired")
    ):
        return SolverError(
            code="auth_required",
            message="선택한 공급자 계정에 다시 로그인해야 합니다.",
            stage=stage,
            category="auth",
            retryable=False,
        )
    if code in (429, "429", "quota_exceeded") or any(term in lowered for term in ("rate_limit", "rate limit", "quota")):
        return SolverError(
            code="quota_exceeded",
            message="선택한 계정의 사용량 제한에 도달했습니다.",
            stage=stage,
            category="quota",
            retryable=True,
            quota=quota,
        )
    if code in ("model_unavailable", "model_not_found") or any(
        term in lowered for term in ("unsupported model", "model unavailable", "model access")
    ):
        return SolverError(
            code="model_unavailable",
            message="선택한 모델을 현재 계정에서 사용할 수 없습니다.",
            stage=stage,
            category="model",
            retryable=False,
        )
    if code in {"provider_stream_closed", "provider_stream_failed", "provider_stream_cancelled"}:
        return SolverError(
            code=str(code),
            message="모델 공급자 연결이 예기치 않게 종료되었습니다.",
            stage=stage,
            category="temporary",
            retryable=True,
        )
    if code in ("timeout", "provider_unavailable", "busy") or isinstance(payload, (TimeoutError, ConnectionError)):
        return SolverError(
            code="provider_unavailable" if code != "timeout" else "timeout",
            message="공급자 응답을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.",
            stage=stage,
            category="temporary",
            retryable=True,
        )
    return SolverError(
        code="provider_error",
        message="공급자 요청을 완료하지 못했습니다.",
        stage=stage,
        category="temporary" if retryable_value is not False else "provider",
        retryable=retryable_value is not False,
    )


__all__ = [
    "AdapterBinding",
    "AdapterCapabilities",
    "AdapterContext",
    "AdapterProviderFailure",
    "DiscoveryResult",
    "EphemeralPrompt",
    "EventKind",
    "IsolationUnavailable",
    "ModelConfiguration",
    "NetworkEndpoint",
    "NetworkPolicy",
    "OwnedChallenge",
    "ProgressCode",
    "ProgressUpdate",
    "RefusingAdapter",
    "SelectedAccount",
    "SolveEvent",
    "SolvePhase",
    "SolveRequest",
    "SolverAdapter",
    "SolverConflictError",
    "SolverEngine",
    "SolverError",
    "SolverLimits",
    "SolverLookupError",
    "normalize_rate_limit_context",
    "normalize_provider_failure",
    "normalize_provider_soft_refusal",
]
