import base64

import pytest

from ctf_agent.solver_retry import (
    MAX_CHECKPOINT_NOTES_BYTES,
    MAX_CHECKPOINT_SOLVER_BYTES,
    RetryCheckpoint,
    decode_checkpoint,
    encode_checkpoint,
    merge_checkpoint,
    merge_continuation,
    parse_solver_artifact,
    solver_artifact_from_bytes,
)


def test_checkpoint_is_canonical_bounded_and_deduplicates_exact_flags():
    first = merge_checkpoint(None, "FLAG{오답}", "가" * 100_000, "# old")
    assert len(first.private_notes.encode("utf-8")) <= MAX_CHECKPOINT_NOTES_BYTES
    repeated = merge_checkpoint(first, "FLAG{오답}", "new facts", "")
    assert repeated.rejected_flags == ("FLAG{오답}",)
    assert repeated.revision == 2
    assert decode_checkpoint(encode_checkpoint(repeated)) == repeated


def test_checkpoint_refuses_to_forget_an_old_exact_candidate_at_history_limit():
    full = RetryCheckpoint(
        revision=32,
        rejected_flags=tuple(f"FLAG{{wrong-{index}}}" for index in range(32)),
        private_notes="facts",
        prior_writeup="",
    )
    with pytest.raises(OverflowError):
        merge_checkpoint(full, "FLAG{one-too-many}", "new", "")


def test_v1_and_v2_checkpoints_decode_and_upgrade_to_v3():
    legacy = decode_checkpoint(
        '{"version":1,"revision":1,"rejected_flags":["FLAG{old}"],'
        '"private_notes":"facts","prior_writeup":""}'
    )
    assert legacy.reason == "rejected_flag"
    v2 = decode_checkpoint(
        '{"version":2,"revision":2,"rejected_flags":[],'
        '"private_notes":"facts","prior_writeup":"","reason":"cancelled"}'
    )
    assert v2.reason == "cancelled"
    assert '"version":3' in encode_checkpoint(legacy)
    assert '"solver_artifact":null' in encode_checkpoint(v2)


def test_solver_artifact_is_bounded_digest_checked_and_omitted_from_model_metadata():
    content = b"#!/usr/bin/env python3\nprint('resume')\n"
    artifact = solver_artifact_from_bytes(content)
    checkpoint = merge_continuation(
        None,
        "resume the verified decoder",
        "cancelled",
        solver_artifact=artifact,
    )
    encoded = encode_checkpoint(checkpoint)
    assert decode_checkpoint(encoded) == checkpoint
    assert checkpoint.model_payload()["solver_artifact"] == {
        "name": "solver.py",
        "size": len(content),
        "sha256": artifact.sha256,
        "restored": True,
    }
    assert "content_b64" not in str(checkpoint.model_payload())
    assert content.decode() not in repr(artifact)

    tampered = artifact.payload()
    tampered["content_b64"] = base64.b64encode(b"different").decode("ascii")
    with pytest.raises(ValueError):
        parse_solver_artifact(tampered)
    with pytest.raises(ValueError):
        solver_artifact_from_bytes(b"x" * (MAX_CHECKPOINT_SOLVER_BYTES + 1))


def test_continuation_checkpoint_allows_no_rejected_flags_and_remains_bounded():
    checkpoint = merge_continuation(
        None,
        "fact " * 100_000,
        "provider_failure",
    )
    assert checkpoint.reason == "provider_failure"
    assert checkpoint.rejected_flags == ()
    assert len(checkpoint.private_notes.encode("utf-8")) <= MAX_CHECKPOINT_NOTES_BYTES
    assert decode_checkpoint(encode_checkpoint(checkpoint)) == checkpoint


@pytest.mark.parametrize(
    "encoded",
    [
        '{"version":1,"version":1,"revision":1,"rejected_flags":["FLAG{x}"],"private_notes":"","prior_writeup":""}',
        '{"version":1,"revision":1,"rejected_flags":["FLAG{x}","FLAG{x}"],"private_notes":"","prior_writeup":""}',
        '{"version":1,"revision":1,"rejected_flags":["FLAG{x}\\nnext"],"private_notes":"","prior_writeup":""}',
    ],
)
def test_checkpoint_parser_rejects_ambiguous_or_unsafe_payloads(encoded):
    with pytest.raises(ValueError):
        decode_checkpoint(encoded)
