"""Make a deterministic, balanced run order for paired CTF solver evaluation.

This planner never invokes a solver, reads credentials, or submits a Flag.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

if __package__:
    from .benchmark_report import BenchmarkError, _validate_controls, _validate_manifest
else:
    from benchmark_report import BenchmarkError, _validate_controls, _validate_manifest


def build_plan(manifest: Any, controls: Any, repetitions: int) -> dict[str, Any]:
    benchmark_id, cases = _validate_manifest(manifest)
    if type(repetitions) is not int or not 2 <= repetitions <= 100:
        raise BenchmarkError("repetitions must be between 2 and 100")
    validated_controls = _validate_controls(controls, "controls")
    runs: list[dict[str, Any]] = []
    for case_id, case in sorted(cases.items(), key=lambda item: (item[1]["split"], item[0])):
        # One case alternates AB/BA across repetitions. Different cases get
        # independent deterministic starting arms, so order cannot be selected
        # after looking at either result.
        first_arm = hashlib.sha256(
            (benchmark_id + "\0" + case_id).encode("utf-8")
        ).digest()[0] & 1
        for repetition in range(1, repetitions + 1):
            arms = ("baseline", "harness") if (first_arm + repetition) % 2 else ("harness", "baseline")
            for order, arm in enumerate(arms, 1):
                runs.append({
                    "case_id": case_id,
                    "split": case["split"],
                    "input_sha256": case["input_sha256"],
                    "repetition": repetition,
                    "order": order,
                    "arm": arm,
                })
    return {
        "schema_version": 1,
        "benchmark_id": benchmark_id,
        "repetitions": repetitions,
        "controls": validated_controls,
        "runs": runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("controls", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        controls = json.loads(args.controls.read_text(encoding="utf-8"))
        plan = build_plan(manifest, controls, args.repetitions)
        if args.output.resolve() in {args.manifest.resolve(), args.controls.resolve()}:
            raise BenchmarkError("output must not replace an input")
        args.output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (BenchmarkError, OSError, ValueError) as exc:
        parser.exit(2, f"benchmark plan: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
