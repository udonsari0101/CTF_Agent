"""Validate paired CTF benchmark observations and emit an aggregate report.

This module never starts a solver or reads account credentials. Expected flags and
raw transcripts belong in the private oracle, not in either input file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


class BenchmarkError(ValueError):
    """An input cannot support a trustworthy paired comparison."""


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SPLITS = ("development", "holdout", "live")
_ARMS = ("baseline", "harness")
_ORACLES = ("official", "ctfd", "private_judge")
_STATUSES = ("completed", "failed", "timeout", "cancelled")
_PROVENANCE = ("remote", "artifact", "web_search", "unknown", "none")


def _fail(message: str) -> None:
    raise BenchmarkError(message)


def _object(value: Any, allowed: set[str], required: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{where}: expected object")
    if missing := required - value.keys():
        _fail(f"{where}: missing {','.join(sorted(missing))}")
    if extra := value.keys() - allowed:
        _fail(f"{where}: unexpected {','.join(sorted(extra))}")
    return value


def _choice(value: Any, choices: tuple[str, ...], where: str) -> str:
    if not isinstance(value, str) or value not in choices:
        _fail(f"{where}: invalid value")
    return value


def _match(value: Any, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail(f"{where}: invalid value")
    return value


def _number(value: Any, where: str, *, positive: bool = False) -> float:
    try:
        finite = math.isfinite(value) if isinstance(value, (int, float)) else False
    except OverflowError:
        finite = False
    if isinstance(value, bool) or not finite:
        _fail(f"{where}: expected finite number")
    if (value <= 0) if positive else (value < 0):
        _fail(f"{where}: out of range")
    return float(value)


def _integer(value: Any, where: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (1 if positive else 0):
        _fail(f"{where}: expected non-negative integer")
    return value


def _digest(value: Any, where: str) -> str:
    return _match(value, _SHA, where)


def _category(value: Any, where: str) -> str:
    # CTFd categories are user-defined, may be localized, and may be absent.
    if (not isinstance(value, str) or not 1 <= len(value) <= 100
            or value != value.strip() or any(ord(char) < 32 for char in value)):
        _fail(f"{where}: expected a nonempty category label")
    return value


def _validate_manifest(raw: Any) -> tuple[str, dict[str, dict[str, Any]]]:
    manifest = _object(raw, {"schema_version", "benchmark_id", "cases"},
                       {"schema_version", "benchmark_id", "cases"}, "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        _fail("manifest: unsupported schema_version")
    benchmark_id = _match(manifest["benchmark_id"], _ID, "manifest.benchmark_id")
    values = manifest["cases"]
    if not isinstance(values, list) or not values:
        _fail("manifest.cases: expected non-empty array")
    cases: dict[str, dict[str, Any]] = {}
    digests: set[str] = set()
    for index, raw_case in enumerate(values, 1):
        where = f"manifest.cases[{index}]"
        case = _object(raw_case,
                       {"case_id", "split", "category", "input_sha256", "oracle_kind"},
                       {"case_id", "split", "category", "input_sha256", "oracle_kind"}, where)
        case_id = _match(case["case_id"], _ID, f"{where}.case_id")
        if case_id in cases:
            _fail(f"manifest: duplicate case_id {case_id}")
        _choice(case["split"], _SPLITS, f"{where}.split")
        _category(case["category"], f"{where}.category")
        _digest(case["input_sha256"], f"{where}.input_sha256")
        if case["input_sha256"] in digests:
            _fail(f"{where}: duplicate frozen challenge input")
        digests.add(case["input_sha256"])
        _choice(case["oracle_kind"], _ORACLES, f"{where}.oracle_kind")
        cases[case_id] = case
    return benchmark_id, cases


_CONTROL_FIELDS = {
    "provider", "model", "runtime_version", "runtime_sha256", "account_ref",
    "reasoning_effort", "service_tier", "ultracode", "image_digest", "network_policy_sha256",
    "tool_policy_sha256", "wall_budget_seconds", "token_budget", "price_table_sha256",
}


def _validate_controls(raw: Any, where: str) -> dict[str, Any]:
    value = _object(raw, _CONTROL_FIELDS, _CONTROL_FIELDS, where)
    _choice(value["provider"], ("codex", "claude"), f"{where}.provider")
    _match(value["model"], _SLUG, f"{where}.model")
    _match(value["runtime_version"], _SLUG, f"{where}.runtime_version")
    _digest(value["runtime_sha256"], f"{where}.runtime_sha256")
    _digest(value["account_ref"], f"{where}.account_ref")
    _match(value["reasoning_effort"], _SLUG, f"{where}.reasoning_effort")
    if type(value["ultracode"]) is not bool:
        _fail(f"{where}.ultracode: expected boolean")
    if value["service_tier"] is not None:
        _match(value["service_tier"], _SLUG, f"{where}.service_tier")
    _match(value["image_digest"], _IMAGE, f"{where}.image_digest")
    _digest(value["network_policy_sha256"], f"{where}.network_policy_sha256")
    _digest(value["tool_policy_sha256"], f"{where}.tool_policy_sha256")
    _integer(value["wall_budget_seconds"], f"{where}.wall_budget_seconds", positive=True)
    if value["token_budget"] is not None:
        _integer(value["token_budget"], f"{where}.token_budget", positive=True)
    if value["price_table_sha256"] is not None:
        _digest(value["price_table_sha256"], f"{where}.price_table_sha256")
    return value


def _validate_oracle(raw: Any, case: dict[str, Any], where: str) -> dict[str, Any]:
    oracle = _object(raw, {"verdict", "source", "evidence_sha256"},
                     {"verdict", "source", "evidence_sha256"}, where)
    verdict = _choice(oracle["verdict"], ("accepted", "rejected", "not_submitted"),
                      f"{where}.verdict")
    if verdict == "not_submitted":
        if oracle["source"] is not None or oracle["evidence_sha256"] is not None:
            _fail(f"{where}: not_submitted must not claim verification")
    elif (oracle["source"] != case["oracle_kind"]
          or not isinstance(oracle["evidence_sha256"], str)):
        _fail(f"{where}: verdict requires the declared external oracle and evidence")
    else:
        _digest(oracle["evidence_sha256"], f"{where}.evidence_sha256")
    return oracle


def _validate_trial(raw: Any, benchmark_id: str, cases: dict[str, dict[str, Any]],
                    line: int) -> dict[str, Any]:
    where = f"trial line {line}"
    allowed = {
        "schema_version", "benchmark_id", "case_id", "input_sha256", "repetition",
        "arm", "order", "controls", "run_status", "solve_wall_seconds", "oracle",
        "flag_provenance", "input_tokens", "output_tokens", "cost_usd", "cost_source",
        "interventions", "failure_code",
    }
    row = _object(raw, allowed, allowed, where)
    if type(row["schema_version"]) is not int or row["schema_version"] != 1:
        _fail(f"{where}: unsupported schema_version")
    if row["benchmark_id"] != benchmark_id:
        _fail(f"{where}: benchmark_id mismatch")
    case_id = _match(row["case_id"], _ID, f"{where}.case_id")
    if case_id not in cases:
        _fail(f"{where}: undeclared case_id {case_id}")
    if row["input_sha256"] != cases[case_id]["input_sha256"]:
        _fail(f"{where}: input digest mismatch")
    _integer(row["repetition"], f"{where}.repetition", positive=True)
    _choice(row["arm"], _ARMS, f"{where}.arm")
    if row["order"] not in (1, 2) or isinstance(row["order"], bool):
        _fail(f"{where}.order: expected 1 or 2")
    _validate_controls(row["controls"], f"{where}.controls")
    _choice(row["run_status"], _STATUSES, f"{where}.run_status")
    _number(row["solve_wall_seconds"], f"{where}.solve_wall_seconds")
    if row["solve_wall_seconds"] > row["controls"]["wall_budget_seconds"] + 30:
        _fail(f"{where}: wall time exceeds budget plus shutdown grace")
    oracle = _validate_oracle(row["oracle"], cases[case_id], f"{where}.oracle")
    provenance = _choice(row["flag_provenance"], _PROVENANCE, f"{where}.flag_provenance")
    if oracle["verdict"] != "not_submitted" and provenance == "none":
        _fail(f"{where}: submitted result requires candidate provenance")
    for name in ("input_tokens", "output_tokens"):
        if row[name] is not None:
            _integer(row[name], f"{where}.{name}")
    if (row["input_tokens"] is None) != (row["output_tokens"] is None):
        _fail(f"{where}: token counts must both be present or absent")
    if row["cost_usd"] is None:
        if row["cost_source"] is not None:
            _fail(f"{where}: cost source without cost")
    else:
        _number(row["cost_usd"], f"{where}.cost_usd")
        _choice(row["cost_source"], ("provider", "versioned_price_table"),
                f"{where}.cost_source")
        if row["cost_source"] == "versioned_price_table" and row["controls"]["price_table_sha256"] is None:
            _fail(f"{where}: versioned cost requires price table digest")
    _integer(row["interventions"], f"{where}.interventions")
    if row["failure_code"] is not None:
        _match(row["failure_code"], _SLUG, f"{where}.failure_code")
    return row


def _quantile(values: list[float], percentile: float) -> float:
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * percentile
    low = int(position)
    fraction = position - low
    return values[low] * (1 - fraction) + values[min(low + 1, len(values) - 1)] * fraction


def _cluster_interval(differences: list[float], *, seed: int = 0,
                      samples: int = 10_000) -> list[float] | None:
    # Percentile bootstrap cannot estimate variance from a tiny or completely
    # homogeneous set of tasks. Returning [1, 1] for five wins is misleading.
    if len(differences) < 20 or len(set(differences)) < 2:
        return None
    rng = random.Random(seed)
    n = len(differences)
    means = [sum(differences[rng.randrange(n)] for _ in range(n)) / n
             for _ in range(samples)]
    return [round(_quantile(means, 0.025), 6), round(_quantile(means, 0.975), 6)]


def _arm_metrics(rows: list[dict[str, Any]], arm: str) -> dict[str, Any]:
    selected = [row for row in rows if row["arm"] == arm]
    times = [float(row["solve_wall_seconds"]) for row in selected]
    tokens = [row["input_tokens"] + row["output_tokens"] for row in selected
              if row["input_tokens"] is not None]
    costs = [float(row["cost_usd"]) for row in selected if row["cost_usd"] is not None]
    cost_sources = {row["cost_source"] for row in selected if row["cost_usd"] is not None}
    return {
        "trials": len(selected),
        "oracle_accepted": sum(row["oracle"]["verdict"] == "accepted" for row in selected),
        "solve_wall_median_seconds": round(statistics.median(times), 3),
        "solve_wall_p90_seconds": round(_quantile(times, 0.9), 3),
        "tokens_reported_trials": len(tokens),
        "tokens_median": statistics.median(tokens) if len(tokens) == len(selected) else None,
        "cost_reported_trials": len(costs),
        "cost_median_usd": (
            round(statistics.median(costs), 6)
            if len(costs) == len(selected) and len(cost_sources) == 1 else None
        ),
        "cost_source": next(iter(cost_sources)) if len(cost_sources) == 1 else None,
        "interventions": sum(row["interventions"] for row in selected),
        "runtime_failures": sum(row["run_status"] in {"failed", "timeout"} for row in selected),
        "accepted_unknown_provenance": sum(
            row["oracle"]["verdict"] == "accepted" and row["flag_provenance"] == "unknown"
            for row in selected
        ),
        "unverified_candidates": sum(
            row["oracle"]["verdict"] == "not_submitted" and row["flag_provenance"] != "none"
            for row in selected
        ),
    }


def build_report(manifest: Any, trials: list[Any]) -> dict[str, Any]:
    benchmark_id, cases = _validate_manifest(manifest)
    if not isinstance(trials, list) or not trials:
        _fail("trials: expected non-empty list")
    grouped: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
    common_controls: dict[str, Any] | None = None
    case_network_policy: dict[str, str] = {}
    for line, raw in enumerate(trials, 1):
        row = _validate_trial(raw, benchmark_id, cases, line)
        controls = {key: value for key, value in row["controls"].items()
                    if key != "network_policy_sha256"}
        if common_controls is None:
            common_controls = controls
        elif controls != common_controls:
            _fail(f"trial line {line}: execution controls differ across the experiment")
        network = row["controls"]["network_policy_sha256"]
        prior_network = case_network_policy.setdefault(row["case_id"], network)
        if prior_network != network:
            _fail(f"trial line {line}: network policy changed for a case")
        key = row["case_id"], row["repetition"]
        if row["arm"] in grouped[key]:
            _fail(f"trial line {line}: duplicate case/repetition/arm")
        grouped[key][row["arm"]] = row
    if set(cases) != {case_id for case_id, _ in grouped}:
        _fail("trials: every declared case needs a complete pair")
    for case_id in cases:
        repetitions = sorted(rep for name, rep in grouped if name == case_id)
        if repetitions != list(range(1, len(repetitions) + 1)):
            _fail(f"case {case_id}: repetitions must be consecutive from 1")
    for split in _SPLITS:
        counts = {
            sum(name == case_id for name, _ in grouped)
            for case_id, case in cases.items() if case["split"] == split
        }
        if len(counts) > 1:
            _fail(f"split {split}: cases require equal repetition counts")
    for (case_id, repetition), pair in grouped.items():
        if set(pair) != set(_ARMS):
            _fail(f"case {case_id} repetition {repetition}: incomplete pair")
        baseline, harness = pair["baseline"], pair["harness"]
        if {baseline["order"], harness["order"]} != {1, 2}:
            _fail(f"case {case_id} repetition {repetition}: invalid paired order")
        if baseline["controls"] != harness["controls"]:
            _fail(f"case {case_id} repetition {repetition}: unmatched execution controls")
        if baseline["input_sha256"] != harness["input_sha256"]:
            _fail(f"case {case_id} repetition {repetition}: mismatched challenge input")
    split_reports: dict[str, Any] = {}
    for split in _SPLITS:
        split_cases = sorted(case_id for case_id, case in cases.items() if case["split"] == split)
        if not split_cases:
            continue
        split_pairs = [pair for (case_id, _), pair in grouped.items() if case_id in split_cases]
        rows = [row for pair in split_pairs for row in pair.values()]
        differences = [
            statistics.mean(
                int(grouped[(case_id, repetition)]["harness"]["oracle"]["verdict"] == "accepted")
                - int(grouped[(case_id, repetition)]["baseline"]["oracle"]["verdict"] == "accepted")
                for repetition in sorted(rep for name, rep in grouped if name == case_id)
            )
            for case_id in split_cases
        ]
        interval = _cluster_interval(differences)
        split_reports[split] = {
            "cases": len(split_cases),
            "pairs": len(split_pairs),
            "category_case_counts": {
                category: sum(cases[case_id]["category"] == category for case_id in split_cases)
                for category in sorted({cases[case_id]["category"] for case_id in split_cases})
            },
            "baseline": _arm_metrics(rows, "baseline"),
            "harness": _arm_metrics(rows, "harness"),
            "paired_task_success_difference": round(statistics.mean(differences), 6),
            "paired_task_success_95pct_interval": interval,
            "uncertainty_method": "case-cluster bootstrap, 10000 resamples, seed 0",
            "uncertainty_note": (
                "insufficient or homogeneous task sample; interval withheld"
                if interval is None else "exploratory interval"
            ),
            "interpretation": "exploratory; no superiority claim",
        }
    return {
        "schema_version": 1,
        "benchmark_id": benchmark_id,
        "comparison": "paired baseline versus harness",
        "common_controls_sha256": hashlib.sha256(
            json.dumps(common_controls, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "splits": split_reports,
        "limitations": [
            "The reporter checks oracle evidence metadata, not the private oracle artifact itself.",
            "Public problems can be contaminated by training data or web search.",
            "Missing token or cost measurements remain null; account quota is not a substitute.",
            "A three-repeat pilot does not establish an improvement.",
        ],
    }


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("JSON: duplicate object key")
        value[key] = item
    return value


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys,
                      parse_constant=lambda _value: _fail("JSON: non-finite number"))


def _load_jsonl(path: Path) -> list[Any]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                _fail("JSONL: blank line")
            rows.append(json.loads(line, object_pairs_hook=_no_duplicate_keys,
                                   parse_constant=lambda _value: _fail("JSONL: non-finite number")))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("trials", type=Path, help="one strict JSON trial per line")
    parser.add_argument("--output", type=Path, help="write aggregate JSON here")
    args = parser.parse_args(argv)
    try:
        report = build_report(_load_json(args.manifest), _load_jsonl(args.trials))
    except (BenchmarkError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        # Never print input bytes: a malformed record might contain credentials.
        print(f"benchmark report rejected: {type(exc).__name__}", file=sys.stderr)
        return 2
    output = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(output)
    else:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
