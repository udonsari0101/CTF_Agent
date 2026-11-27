"""Distinguish Claude request limits from an explicit spend cap."""

import sys
from pathlib import Path
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.solver import normalize_provider_failure  # noqa: E402
from ctf_agent.solver_worker import ClaudePrintDriver  # noqa: E402
from ctf_agent.providers.claude import _api_catalog_limit_code  # noqa: E402


cases = (
    ({"type": "error", "error": {"type": "rate_limit_error", "status": 429}}, "rate_limit_exceeded"),
    ({"type": "error", "error": {"type": "rate_limit_error", "status": 429,
      "details": {"error_code": "ramp_limit_exceeded"}}}, "rate_limit_exceeded"),
    ({"type": "error", "error": {"type": "rate_limit_error", "status": 429,
      "details": {"error_code": "enforced_spend_limit_reached"}}}, "quota_exceeded"),
    ({"type": "error", "error": {"type": "billing_error", "status": 402}}, "billing_required"),
)

for event, expected in cases:
    reduced = ClaudePrintDriver._api_failure(event)
    assert reduced is not None and reduced["code"] == expected, (event, reduced)
    public = normalize_provider_failure(reduced, stage="solve")
    assert public.code == expected, (event, public.code)

for body, expected in (
    ({"type": "error", "error": {"type": "rate_limit_error"}}, "rate_limit_exceeded"),
    ({"type": "error", "error": {"type": "rate_limit_error",
     "details": {"error_code": "enforced_spend_limit_reached"}}}, "quota_exceeded"),
):
    response = httpx.Response(429, json=body)
    assert _api_catalog_limit_code(response) == expected

print("PASS: Claude rate and spend failures remain distinct")
