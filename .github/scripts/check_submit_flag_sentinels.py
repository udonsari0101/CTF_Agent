"""A CLI help probe must never become a discovered Flag."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.submit_flag import InvalidCandidate, record_candidate  # noqa: E402
from ctf_agent.solver_worker import WorkerRefusal, _validated_flag_candidate  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        candidate = root / ".flag-candidate"
        for option in ("--help", "-h", "--version", "-V"):
            try:
                record_candidate(option, root)
            except InvalidCandidate:
                pass
            else:
                raise AssertionError(f"accepted CLI option {option}")
            assert not candidate.exists()

            # A direct file write or an older CLI must be checked again at the
            # worker boundary before any flag event can be published.
            candidate.write_text(option, encoding="utf-8")
            try:
                _validated_flag_candidate(candidate)
            except WorkerRefusal as error:
                assert error.error.code == "invalid_flag_candidate"
            else:
                raise AssertionError(f"worker accepted CLI option {option}")
            candidate.unlink()

        record_candidate("Layer7{real_candidate}", root)
        assert _validated_flag_candidate(candidate) == "Layer7{real_candidate}"
        candidate.unlink()
        # A raw-string challenge remains possible without a workspace format.
        record_candidate("48characterinput", root)
        assert _validated_flag_candidate(candidate) == "48characterinput"
    print("Flag handoff rejects CLI options and preserves valid candidates: passed")


if __name__ == "__main__":
    main()
