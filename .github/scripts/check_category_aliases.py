"""Contest-defined Korean compound categories select relevant playbooks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.agent_workspace import normalize_categories  # noqa: E402


cases = {
    "웹·사이드채널": ("web",),
    "포너블": ("pwn",),
    "리버싱·암호": ("rev", "crypto"),
    "포렌식·리버싱": ("rev", "forensics"),
    "Web / Crypto": ("web", "crypto"),
    "연습": ("unknown",),
    "웹툰": ("unknown",),
    "": ("unknown",),
}
for label, expected in cases.items():
    assert normalize_categories(label) == expected, (label, normalize_categories(label))

print("PASS: contest-defined categories map to the relevant playbooks")
