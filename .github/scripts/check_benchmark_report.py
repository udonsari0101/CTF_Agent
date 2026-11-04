"""Offline contract checks for the paired benchmark report."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_report import BenchmarkError, build_report  # noqa: E402


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sample(count=1):
    manifest = {"schema_version": 1, "benchmark_id": "pilot-01", "cases": []}
    rows = []
    controls = {
        "provider": "codex", "model": "gpt-example", "runtime_version": "1.2.3",
        "runtime_sha256": digest("runtime"), "account_ref": digest("account-ref"),
        "reasoning_effort": "high", "service_tier": None, "ultracode": False,
        "image_digest": "sha256:" + digest("image"),
        "network_policy_sha256": digest("network"),
        "tool_policy_sha256": digest("tools"),
        "wall_budget_seconds": 600, "token_budget": None,
        "price_table_sha256": None,
    }
    for index in range(count):
        case_id = f"case-{index}"
        input_digest = digest(f"input-{index}")
        manifest["cases"].append({
            "case_id": case_id,
            "split": "development" if index < 3 else "holdout",
            "category": "web", "input_sha256": input_digest,
            "oracle_kind": "private_judge",
        })
        for arm, order in (("baseline", 1), ("harness", 2)):
            accepted = arm == "harness"
            rows.append({
                "schema_version": 1, "benchmark_id": "pilot-01",
                "case_id": case_id, "input_sha256": input_digest,
                "repetition": 1, "arm": arm, "order": order,
                "controls": copy.deepcopy(controls),
                "run_status": "completed", "solve_wall_seconds": 25.0,
                "oracle": {
                    "verdict": "accepted" if accepted else "not_submitted",
                    "source": "private_judge" if accepted else None,
                    "evidence_sha256": digest(case_id) if accepted else None,
                },
                "flag_provenance": "remote" if accepted else "none",
                "input_tokens": None, "output_tokens": None,
                "cost_usd": None, "cost_source": None,
                "interventions": 0, "failure_code": None,
            })
    return manifest, rows


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.rows = sample()

    def reject(self, rows=None, manifest=None):
        with self.assertRaises(BenchmarkError):
            build_report(manifest if manifest is not None else self.manifest,
                         rows if rows is not None else self.rows)

    def test_verified_success_and_missing_measurements(self):
        report = build_report(self.manifest, self.rows)
        split = report["splits"]["development"]
        self.assertEqual(split["paired_task_success_difference"], 1.0)
        self.assertEqual(split["baseline"]["oracle_accepted"], 0)
        self.assertEqual(split["harness"]["oracle_accepted"], 1)
        self.assertIsNone(split["paired_task_success_95pct_interval"])
        self.assertIsNone(split["harness"]["tokens_median"])

    def test_no_evidence_no_verified_success(self):
        rows = copy.deepcopy(self.rows)
        rows[1]["oracle"]["evidence_sha256"] = None
        self.reject(rows)

    def test_raw_result_fields_rejected(self):
        for field in ("flag", "api_key", "transcript", "success"):
            rows = copy.deepcopy(self.rows)
            rows[1][field] = "secret"
            self.reject(rows)

    def test_pair_must_have_same_input_controls_and_opposite_order(self):
        for field, changed in (("model", "other"), ("account_ref", digest("other"))):
            rows = copy.deepcopy(self.rows)
            rows[1]["controls"][field] = changed
            self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]["input_sha256"] = digest("other")
        self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]["order"] = 1
        self.reject(rows)

    def test_incomplete_duplicate_and_nonconsecutive_repetitions(self):
        self.reject(self.rows[:1])
        self.reject(self.rows + [copy.deepcopy(self.rows[1])])
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row["repetition"] = 2
        self.reject(rows)

    def test_global_model_change_rejected(self):
        manifest, rows = sample(2)
        for row in rows[2:]:
            row["controls"]["model"] = "other"
        self.reject(rows, manifest)

    def test_splits_remain_separate(self):
        manifest, rows = sample(5)
        report = build_report(manifest, rows)
        self.assertEqual(report["splits"]["development"]["cases"], 3)
        self.assertEqual(report["splits"]["holdout"]["cases"], 2)
        self.assertNotIn("overall_success_rate", report)

    def test_ctfd_category_labels_are_not_forced_into_a_fixed_taxonomy(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["cases"][0]["category"] = "커스텀 분야"
        report = build_report(manifest, self.rows)
        self.assertEqual(report["splits"]["development"]["category_case_counts"],
                         {"커스텀 분야": 1})

    def test_found_candidate_without_oracle_verdict_is_not_counted_as_success(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["flag_provenance"] = "artifact"
        report = build_report(self.manifest, rows)
        baseline = report["splits"]["development"]["baseline"]
        self.assertEqual(baseline["unverified_candidates"], 1)
        self.assertEqual(baseline["oracle_accepted"], 0)

    def test_duplicate_challenge_input_cannot_inflate_case_count(self):
        manifest, rows = sample(2)
        manifest["cases"][1]["input_sha256"] = manifest["cases"][0]["input_sha256"]
        for row in rows[2:]:
            row["input_sha256"] = manifest["cases"][0]["input_sha256"]
        self.reject(rows, manifest)

    def test_deterministic_interval_when_sample_is_sufficient(self):
        manifest, rows = sample(24)
        for case in manifest["cases"]:
            case["split"] = "holdout"
        for row in rows:
            if row["arm"] == "harness" and int(row["case_id"].split("-")[1]) % 3 == 0:
                row["oracle"] = {"verdict": "not_submitted", "source": None,
                                 "evidence_sha256": None}
                row["flag_provenance"] = "none"
        first = build_report(manifest, rows)["splits"]["holdout"]
        second = build_report(manifest, rows)["splits"]["holdout"]
        self.assertEqual(first["paired_task_success_95pct_interval"],
                         second["paired_task_success_95pct_interval"])
        self.assertIsNotNone(first["paired_task_success_95pct_interval"])

    def test_partial_tokens_and_nonfinite_time_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[1]["input_tokens"] = 1
        self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]["solve_wall_seconds"] = float("nan")
        self.reject(rows)

    def test_cost_requires_source_and_versioned_price_digest(self):
        rows = copy.deepcopy(self.rows)
        rows[1]["cost_usd"] = 0.1
        self.reject(rows)
        rows[1]["cost_source"] = "versioned_price_table"
        self.reject(rows)

    def test_cli_does_not_echo_bad_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")
            (root / "trials.jsonl").write_text(
                json.dumps({**self.rows[0], "api_key": "SECRET_MARKER"}) + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/benchmark_report.py"),
                 str(root / "manifest.json"), str(root / "trials.jsonl")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("SECRET_MARKER", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
