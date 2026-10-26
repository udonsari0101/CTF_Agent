"""Bounded, durable context for retrying a rejected solver candidate.

The checkpoint is copied into a new job manifest.  It never changes an active
job and contains only solver-produced notes plus the exact rejected flags.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping


CHECKPOINT_VERSION = 3
RESUME_REASONS = {
    "rejected_flag",
    "needs_remote",
    "timeout",
    "cancelled",
    "provider_failure",
    "turn_limit",
}
MAX_REJECTED_FLAGS = 32
# Together these can expand to at most about 100 KiB when JSON escaping is
# required.  That keeps the full manifest below its 512 KiB control-file bound
# even beside the API's worst-case UTF-8 challenge metadata.
MAX_REJECTED_FLAG_BYTES = 16 * 1024
MAX_CHECKPOINT_NOTES_BYTES = 20 * 1024
MAX_CHECKPOINT_WRITEUP_BYTES = 14 * 1024
MAX_CHECKPOINT_SOLVER_BYTES = 64 * 1024
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class SolverArtifact:
    """One bounded, immutable snapshot of the agent's reproducible solver."""

    content: bytes = field(repr=False)
    sha256: str
    name: str = "solver.py"

    def payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": len(self.content),
            "sha256": self.sha256,
            "content_b64": base64.b64encode(self.content).decode("ascii"),
        }

    def model_payload(self) -> dict[str, Any]:
        """Describe the restored file without duplicating source in POISON.json."""

        return {
            "name": self.name,
            "size": len(self.content),
            "sha256": self.sha256,
            "restored": True,
        }


def solver_artifact_from_bytes(content: bytes) -> SolverArtifact:
    if not isinstance(content, bytes) or not content or len(content) > MAX_CHECKPOINT_SOLVER_BYTES:
        raise ValueError("invalid solver artifact size")
    return SolverArtifact(content=content, sha256=hashlib.sha256(content).hexdigest())


def parse_solver_artifact(value: object) -> SolverArtifact:
    if not isinstance(value, Mapping) or set(value) != {"name", "size", "sha256", "content_b64"}:
        raise ValueError("invalid solver artifact")
    name, size, digest, encoded = (
        value.get("name"),
        value.get("size"),
        value.get("sha256"),
        value.get("content_b64"),
    )
    if (
        name != "solver.py"
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= MAX_CHECKPOINT_SOLVER_BYTES
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or not isinstance(encoded, str)
        or len(encoded) > ((MAX_CHECKPOINT_SOLVER_BYTES + 2) // 3) * 4
    ):
        raise ValueError("invalid solver artifact")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid solver artifact") from exc
    if len(content) != size or not secrets.compare_digest(hashlib.sha256(content).hexdigest(), digest):
        raise ValueError("invalid solver artifact")
    return SolverArtifact(content=content, sha256=digest)


def encode_solver_artifact(artifact: SolverArtifact | None) -> str | None:
    if artifact is None:
        return None
    parsed = parse_solver_artifact(artifact.payload())
    return json.dumps(parsed.payload(), ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def decode_solver_artifact(encoded: str | None) -> SolverArtifact | None:
    if encoded is None:
        return None
    if not isinstance(encoded, str) or len(encoded) > 128 * 1024:
        raise ValueError("invalid solver artifact encoding")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate solver artifact key")
            result[key] = value
        return result

    value = json.loads(
        encoded,
        object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid number")),
    )
    return parse_solver_artifact(value)


@dataclass(frozen=True, slots=True)
class RetryCheckpoint:
    revision: int
    rejected_flags: tuple[str, ...]
    private_notes: str
    prior_writeup: str
    reason: str = "rejected_flag"
    solver_artifact: SolverArtifact | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "version": CHECKPOINT_VERSION,
            "revision": self.revision,
            "rejected_flags": list(self.rejected_flags),
            "private_notes": self.private_notes,
            "prior_writeup": self.prior_writeup,
            "reason": self.reason,
            "solver_artifact": (
                self.solver_artifact.payload() if self.solver_artifact is not None else None
            ),
        }

    def model_payload(self) -> dict[str, Any]:
        payload = self.payload()
        payload["solver_artifact"] = (
            self.solver_artifact.model_payload()
            if self.solver_artifact is not None
            else None
        )
        return payload


def _valid_flag(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 4000
        and "\n" not in value
        and "\r" not in value
        and not _CONTROL.search(value)
    )


def _bounded_utf8(value: str, maximum: int) -> str:
    if _CONTROL.search(value):
        raise ValueError("checkpoint text contains control characters")
    raw = value.strip().encode("utf-8")
    if len(raw) <= maximum:
        return raw.decode("utf-8")
    return raw[:maximum].decode("utf-8", errors="ignore").rstrip()


def bounded_checkpoint_notes(value: str) -> str:
    return _bounded_utf8(value, MAX_CHECKPOINT_NOTES_BYTES)


def parse_checkpoint(value: object) -> RetryCheckpoint:
    if not isinstance(value, Mapping):
        raise ValueError("invalid retry checkpoint object")
    version, revision = value.get("version"), value.get("revision")
    legacy_v1 = version == 1
    legacy_v2 = version == 2
    allowed = {
        "version", "revision", "rejected_flags", "private_notes", "prior_writeup"
    }
    if legacy_v1:
        if set(value) != allowed:
            raise ValueError("invalid retry checkpoint object")
        reason = "rejected_flag"
        artifact = None
    elif legacy_v2:
        if set(value) != (allowed | {"reason"}):
            raise ValueError("invalid retry checkpoint object")
        reason = value.get("reason")
        artifact = None
    elif version == CHECKPOINT_VERSION:
        if set(value) != (allowed | {"reason", "solver_artifact"}):
            raise ValueError("invalid retry checkpoint object")
        reason = value.get("reason")
        raw_artifact = value.get("solver_artifact")
        artifact = parse_solver_artifact(raw_artifact) if raw_artifact is not None else None
    else:
        raise ValueError("invalid retry checkpoint version")
    flags = value.get("rejected_flags")
    notes, writeup = value.get("private_notes"), value.get("prior_writeup")
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or not 1 <= revision <= 2_147_483_647
        or reason not in RESUME_REASONS
    ):
        raise ValueError("invalid retry checkpoint version")
    if (
        not isinstance(flags, list)
        or not 0 <= len(flags) <= MAX_REJECTED_FLAGS
        or (reason == "rejected_flag" and not flags)
        or any(not _valid_flag(flag) for flag in flags)
        or len(set(flags)) != len(flags)
        or sum(len(flag.encode("utf-8")) for flag in flags) > MAX_REJECTED_FLAG_BYTES
    ):
        raise ValueError("invalid rejected flag history")
    if not isinstance(notes, str) or len(notes.encode("utf-8")) > MAX_CHECKPOINT_NOTES_BYTES or _CONTROL.search(notes):
        raise ValueError("invalid retry notes")
    if not isinstance(writeup, str) or len(writeup.encode("utf-8")) > MAX_CHECKPOINT_WRITEUP_BYTES or _CONTROL.search(writeup):
        raise ValueError("invalid prior write-up")
    return RetryCheckpoint(revision, tuple(flags), notes, writeup, reason, artifact)


def decode_checkpoint(encoded: str | None) -> RetryCheckpoint | None:
    if encoded is None:
        return None
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > 384 * 1024:
        raise ValueError("invalid retry checkpoint encoding")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate retry checkpoint key")
            result[key] = value
        return result

    value = json.loads(
        encoded,
        object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid number")),
    )
    return parse_checkpoint(value)


def encode_checkpoint(checkpoint: RetryCheckpoint) -> str:
    parsed = parse_checkpoint(checkpoint.payload())
    return json.dumps(parsed.payload(), ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def merge_checkpoint(
    previous: RetryCheckpoint | None,
    rejected_flag: str,
    private_notes: str,
    prior_writeup: str,
    solver_artifact: SolverArtifact | None = None,
) -> RetryCheckpoint:
    if not _valid_flag(rejected_flag):
        raise ValueError("invalid rejected flag")
    flags = list(previous.rejected_flags if previous else ())
    if rejected_flag not in flags:
        if len(flags) >= MAX_REJECTED_FLAGS:
            raise OverflowError("retry checkpoint flag limit reached")
        if sum(len(flag.encode("utf-8")) for flag in (*flags, rejected_flag)) > MAX_REJECTED_FLAG_BYTES:
            raise OverflowError("retry checkpoint byte limit reached")
        flags.append(rejected_flag)

    latest_notes = _bounded_utf8(private_notes, MAX_CHECKPOINT_NOTES_BYTES)
    older_notes = previous.private_notes if previous else ""
    if latest_notes and older_notes and latest_notes != older_notes:
        notes = f"# Most recent rejected attempt\n\n{latest_notes}\n\n# Earlier rejected attempts\n\n{older_notes}"
    else:
        notes = latest_notes or older_notes
    notes = _bounded_utf8(notes, MAX_CHECKPOINT_NOTES_BYTES)

    latest_writeup = _bounded_utf8(prior_writeup, MAX_CHECKPOINT_WRITEUP_BYTES)
    writeup = latest_writeup or (previous.prior_writeup if previous else "")
    writeup = _bounded_utf8(writeup, MAX_CHECKPOINT_WRITEUP_BYTES)
    return RetryCheckpoint(
        revision=(previous.revision + 1) if previous else 1,
        rejected_flags=tuple(flags),
        private_notes=notes,
        prior_writeup=writeup,
        reason="rejected_flag",
        solver_artifact=solver_artifact or (previous.solver_artifact if previous else None),
    )


def merge_continuation(
    previous: RetryCheckpoint | None,
    private_notes: str,
    reason: str,
    prior_writeup: str = "",
    solver_artifact: SolverArtifact | None = None,
) -> RetryCheckpoint:
    """Replace one bounded handoff while retaining exact poison candidates."""

    if reason not in RESUME_REASONS or reason == "rejected_flag":
        raise ValueError("invalid continuation reason")
    latest_notes = _bounded_utf8(private_notes, MAX_CHECKPOINT_NOTES_BYTES)
    older_notes = previous.private_notes if previous else ""
    if latest_notes and older_notes and latest_notes != older_notes:
        notes = (
            f"# Most recent interrupted attempt ({reason})\n\n{latest_notes}"
            f"\n\n# Earlier attempts\n\n{older_notes}"
        )
    else:
        notes = latest_notes or older_notes
    notes = _bounded_utf8(notes, MAX_CHECKPOINT_NOTES_BYTES)
    latest_writeup = _bounded_utf8(prior_writeup, MAX_CHECKPOINT_WRITEUP_BYTES)
    writeup = latest_writeup or (previous.prior_writeup if previous else "")
    return RetryCheckpoint(
        revision=(previous.revision + 1) if previous else 1,
        rejected_flags=previous.rejected_flags if previous else (),
        private_notes=notes,
        prior_writeup=_bounded_utf8(writeup, MAX_CHECKPOINT_WRITEUP_BYTES),
        reason=reason,
        solver_artifact=solver_artifact or (previous.solver_artifact if previous else None),
    )


__all__ = [
    "MAX_CHECKPOINT_NOTES_BYTES",
    "MAX_CHECKPOINT_SOLVER_BYTES",
    "SolverArtifact",
    "RetryCheckpoint",
    "bounded_checkpoint_notes",
    "decode_checkpoint",
    "decode_solver_artifact",
    "encode_checkpoint",
    "encode_solver_artifact",
    "merge_checkpoint",
    "merge_continuation",
    "parse_checkpoint",
    "parse_solver_artifact",
    "solver_artifact_from_bytes",
]
