from __future__ import annotations

import os
import stat

import pytest

from ctf_agent import submit_flag


def test_records_exact_candidate_as_private_regular_file_without_echo(tmp_path, monkeypatch, capsys):
    candidate = "CTF{" + ("a" * (submit_flag.MAX_CANDIDATE_LENGTH - 5)) + "}"
    assert len(candidate) == submit_flag.MAX_CANDIDATE_LENGTH
    monkeypatch.chdir(tmp_path)

    assert submit_flag.main([candidate]) == 0

    captured = capsys.readouterr()
    destination = tmp_path / ".flag-candidate"
    assert destination.read_text(encoding="utf-8") == candidate
    assert stat.S_ISREG(destination.lstat().st_mode)
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert candidate not in captured.out
    assert candidate not in captured.err


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "a" * (submit_flag.MAX_CANDIDATE_LENGTH + 1),
        "CTF{line\nfeed}",
        "CTF{carriage\rreturn}",
        "CTF{nul\x00byte}",
        "CTF{escape\x1bcode}",
        "CTF{delete\x7fcode}",
        "CTF{unicode\x85control}",
        "CTF{surrogate\ud800}",
    ],
)
def test_rejects_empty_oversized_and_control_candidates(tmp_path, monkeypatch, capsys, candidate):
    monkeypatch.chdir(tmp_path)

    assert submit_flag.main([candidate]) == 65

    captured = capsys.readouterr()
    assert not (tmp_path / ".flag-candidate").exists()
    if candidate:
        assert candidate not in captured.out
        assert candidate not in captured.err


def test_requires_exactly_one_argument_without_echoing_extras(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    secret = "CTF{must-not-appear}"

    assert submit_flag.main([]) == 64
    assert submit_flag.main([secret, "extra"]) == 64

    captured = capsys.readouterr()
    assert not (tmp_path / ".flag-candidate").exists()
    assert secret not in captured.out
    assert secret not in captured.err


def test_atomically_replaces_symlink_without_touching_its_target(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.write_text("unchanged", encoding="utf-8")
    destination = tmp_path / ".flag-candidate"
    try:
        destination.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("creating symlinks is not permitted")
    monkeypatch.chdir(tmp_path)

    assert submit_flag.main(["CTF{replacement}"]) == 0

    assert not destination.is_symlink()
    assert stat.S_ISREG(destination.lstat().st_mode)
    assert destination.read_text(encoding="utf-8") == "CTF{replacement}"
    assert outside.read_text(encoding="utf-8") == "unchanged"


def test_write_failure_is_sanitized_and_removes_stage(tmp_path, monkeypatch, capsys):
    candidate = "CTF{never-log-this}"
    monkeypatch.chdir(tmp_path)

    def fail_replace(_source, _destination):
        raise OSError(f"failure involving {candidate}")

    monkeypatch.setattr(submit_flag.os, "replace", fail_replace)

    assert submit_flag.main([candidate]) == 73

    captured = capsys.readouterr()
    assert candidate not in captured.out
    assert candidate not in captured.err
    assert not (tmp_path / ".flag-candidate").exists()
    assert list(tmp_path.glob(".flag-candidate.*.tmp")) == []
