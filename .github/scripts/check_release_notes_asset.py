"""Exercise release-note privacy checks and the publisher/reader asset contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "check_release_notes", ROOT / "scripts" / "check_release_notes.py"
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

repository = "example/CTF_Agent"
tag = "v0.4.40"
good = (
    "## Changes\n\n"
    "- Improve solver staging and README.md release verification\n\n"
    "[Full changelog](https://github.com/example/CTF_Agent/compare/v0.4.39...v0.4.40)\n"
)
module.validate_markdown(good, repository, tag)

for bad_entry in (
    "- Internal endpoint https://private.example.test/start",
    "- Internal hostname private.example.test",
    "- Contact somebody@example.test",
    "- Internal address 192.0.2.12",
    "- Local path C:\\Users\\Somebody\\data",
    "- Temporary token " + "ctfd_" + "a" * 24,
    "- Wrong changelog https://github.com/other/repository/compare/v0.4.39...v0.4.40",
):
    try:
        module.validate_markdown("## Changes\n\n" + bad_entry + "\n", repository, tag)
    except ValueError:
        pass
    else:
        raise AssertionError("Release notes accepted private or unexpected content")

publisher = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
reader = (ROOT / "ctf_agent/release_updates.py").read_text(encoding="utf-8")
assert 'python3 scripts/check_release_notes.py "$notes"' in publisher
assert 'cp "$notes" dist/release-notes.md' in publisher
assert '"dist/release-notes.md"' in publisher
assert '--notes-file "$notes"' in publisher
assert 'asset_root + "release-notes.md"' in reader
