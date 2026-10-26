from __future__ import annotations

import os
import stat

import pytest

from ctf_agent import request_remote


def test_records_private_bounded_request_without_echo(tmp_path, monkeypatch, capsys):
    note = "Need the host, port, and protocol for the live service."
    monkeypatch.chdir(tmp_path)

    assert request_remote.main([note]) == 0

    captured = capsys.readouterr()
    target = tmp_path / request_remote.REQUEST_NAME
    assert target.read_text(encoding="utf-8") == note
    assert stat.S_ISREG(target.lstat().st_mode)
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert note not in captured.out
    assert note not in captured.err


@pytest.mark.parametrize(
    "note",
    [
        "",
        "a" * (request_remote.MAX_REQUEST_BYTES + 1),
        "two\nlines",
        "nul\x00byte",
        "escape\x1bcode",
        "surrogate\ud800",
    ],
)
def test_rejects_invalid_request_without_writing_or_echoing(
    tmp_path, monkeypatch, capsys, note
):
    monkeypatch.chdir(tmp_path)

    assert request_remote.main([note]) == 65

    captured = capsys.readouterr()
    assert not (tmp_path / request_remote.REQUEST_NAME).exists()
    if note:
        assert note not in captured.out
        assert note not in captured.err


def test_atomically_replaces_symlink_without_touching_target(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.write_text("unchanged", encoding="utf-8")
    destination = tmp_path / request_remote.REQUEST_NAME
    try:
        destination.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("creating symlinks is not permitted")
    monkeypatch.chdir(tmp_path)

    assert request_remote.main(["Need HTTPS base URL"]) == 0

    assert not destination.is_symlink()
    assert destination.read_text(encoding="utf-8") == "Need HTTPS base URL"
    assert outside.read_text(encoding="utf-8") == "unchanged"
