"""Offline regressions for a blinded, paired AB/BA benchmark schedule."""

from __future__ import annotations

import sys
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.benchmark_plan import build_plan  # noqa: E402
from scripts.benchmark_report import BenchmarkError  # noqa: E402


CONTROLS = {
    "provider": "codex", "model": "example", "runtime_version": "1.0.0",
    "runtime_sha256": "a" * 64, "account_ref": "b" * 64,
    "reasoning_effort": "high", "service_tier": None, "ultracode": False,
    "image_digest": "sha256:" + "c" * 64,
    "network_policy_sha256": "d" * 64,
    "tool_policy_sha256": "e" * 64,
    "wall_budget_seconds": 300, "token_budget": None,
    "price_table_sha256": None,
}
MANIFEST = {
    "schema_version": 1, "benchmark_id": "paired-01",
    "cases": [
        {"case_id": "a", "split": "development", "category": "WEB",
         "input_sha256": "1" * 64, "oracle_kind": "ctfd"},
        {"case_id": "b", "split": "holdout", "category": "misc",
         "input_sha256": "2" * 64, "oracle_kind": "official"},
    ],
}


class BenchmarkPlanTests(unittest.TestCase):
    def test_documented_cli_creates_schedule_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            controls = root / "controls.json"
            output = root / "plan.json"
            manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
            controls.write_text(json.dumps(CONTROLS), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/benchmark_plan.py"),
                 str(manifest), str(controls), "--repetitions", "2",
                 "--output", str(output)],
                cwd=ROOT, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(plan["runs"]), 8)
            self.assertNotIn("api_key", output.read_text(encoding="utf-8"))

    def test_each_case_alternates_order_before_any_results_exist(self) -> None:
        plan = build_plan(MANIFEST, CONTROLS, 4)
        self.assertEqual(plan, build_plan(MANIFEST, CONTROLS, 4))
        self.assertEqual(plan["controls"], CONTROLS)
        self.assertEqual(len(plan["runs"]), 16)
        for case in MANIFEST["cases"]:
            orders = []
            for repetition in range(1, 5):
                pair = [run for run in plan["runs"]
                        if run["case_id"] == case["case_id"]
                        and run["repetition"] == repetition]
                self.assertEqual([row["order"] for row in pair], [1, 2])
                self.assertEqual({row["arm"] for row in pair}, {"baseline", "harness"})
                self.assertEqual({row["input_sha256"] for row in pair}, {case["input_sha256"]})
                orders.append(tuple(row["arm"] for row in pair))
            self.assertEqual(orders[0], orders[2])
            self.assertEqual(orders[1], orders[3])
            self.assertNotEqual(orders[0], orders[1])

    def test_schedule_rejects_unpaired_or_secret_bearing_inputs(self) -> None:
        for repetitions in (0, 1, 101, True):
            with self.subTest(repetitions=repetitions), self.assertRaises(BenchmarkError):
                build_plan(MANIFEST, CONTROLS, repetitions)
        with self.assertRaises(BenchmarkError):
            build_plan(MANIFEST, {**CONTROLS, "api_key": "must-not-appear"}, 2)
        with self.assertRaises(BenchmarkError):
            build_plan({**MANIFEST, "cases": [MANIFEST["cases"][0]] * 2}, CONTROLS, 2)


if __name__ == "__main__":
    unittest.main()
