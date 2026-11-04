# CTF Agent benchmark protocol

This document describes a paired comparison of the unmodified provider CLI (`baseline`) and the current CTF Agent harness (`harness`). The scripts validate a schedule and a report; they do **not** start solvers, submit flags, read credentials, or prove that a solver is better. Keep the private oracle and raw transcripts outside the public repository.

The [2026-11-04 preflight audit](preflight-audit.md) inventories the prepared private static candidates, pending service fixtures, source-code comparisons, missing field coverage, and the concrete B0/B1 execution boundary. Prepared handouts and judge metadata are not actual model trials. In particular, the current planner/reporter are a **two-arm format**, not a runner or a three-arm candidate evaluator.

## Freeze the experiment before any run

Use the same frozen problem statement, files, reachable endpoints, provider account, model, reasoning level, CLI version, image digest, network/tool policy, wall-time limit, and token budget in both arms of each pair. The baseline receives only the problem and files. The harness receives the same input plus its normal instructions and tools. Do not leak prior solves or expected flags into either arm.

Partition cases into `development`, `holdout`, and `live` before looking at results. Tune only on development cases. Keep categories exactly as supplied, including localized or unusual CTFd labels. For an unclassified case, assign a neutral label such as `unknown`; do not infer an oracle answer from the category. Keep a private, dated oracle record from the official checker, CTFd, or another independent judge. A candidate flag without a verdict is unverified.

The manifest is JSON with `schema_version: 1`, a stable `benchmark_id`, and nonempty `cases`. Each case has `case_id`, `split`, `category`, `input_sha256`, and `oracle_kind` (`official`, `ctfd`, or `private_judge`). `input_sha256` covers the frozen challenge input bundle. The controls JSON has every field checked by `scripts/benchmark_report.py`: `provider`, `model`, `runtime_version`, `runtime_sha256`, `account_ref` (a digest, never a secret), `reasoning_effort`, `service_tier`, `ultracode`, `image_digest`, `network_policy_sha256`, `tool_policy_sha256`, `wall_budget_seconds`, `token_budget`, and `price_table_sha256` (nullable). Keep actual credentials out of both files.

Create a deterministic AB/BA schedule before observing outcomes:

```text
python scripts/benchmark_plan.py manifest.json controls.json --repetitions 3 --output plan.json
```

The planner alternates arm order within each case and freezes the input digest, repetition, and order. Three repetitions are a pilot for checking the apparatus, not enough to establish a performance gain. Record both outcomes even if one arm fails or times out. Prevent run-order effects by maintaining the scheduled order, using fresh isolated workspaces, and recording external service changes.

## Record and validate outcomes

Write one JSON object per trial to a JSONL file. Fields required by the reporter are `schema_version`, `benchmark_id`, `case_id`, `input_sha256`, `repetition`, `arm`, `order`, `controls`, `run_status`, `solve_wall_seconds`, `oracle`, `flag_provenance`, `input_tokens`, `output_tokens`, `cost_usd`, `cost_source`, `interventions`, and `failure_code`. The `oracle` object contains `verdict`, `source`, and `evidence_sha256`; `not_submitted` uses null source/evidence. Flag provenance is `remote`, `artifact`, `web_search`, `unknown`, or `none`. Measure wall-clock from the same start boundary in both arms and count manual steering. If token/cost numbers are unavailable, use null rather than account quota or an estimate without a versioned price table.

```text
python scripts/benchmark_report.py manifest.json trials.jsonl --output report.json
```

The validator rejects duplicate cases or trial arms, mismatched digests/controls, missing pairs, inconsistent repetition counts, unsupported oracle claims, malformed numbers, and unsupported cost provenance. The aggregate includes accepted results, median and p90 wall time, token/cost coverage, interventions, runtime failures, unknown flag provenance, and unverified candidates. It computes a task-level paired success difference per split. It withholds the case-cluster bootstrap interval for fewer than 20 varied tasks; even an interval is exploratory until a preregistered independent holdout/live evaluation supports a claim.

The reporter checks the **metadata** for oracle evidence, not the private evidence itself. Audit those records separately. Public CTF cases may be contaminated by training data or web search. Preserve versioned tool and model identifiers so a later rerun can explain changes.

Before calling this a performance benchmark, run a no-model fixture through both arm wrappers and prove that input/answer mounts are separated, the CLI process actually starts in the frozen image, the same judge scores both arms, every remote service resets between attempts, and failure/timeout paths still yield complete paired records. Then run a small **development** pilot to validate the apparatus. The eight currently prepared static holdout cases do not support broad all-field claims: the prepared static manifests contain no runnable web/pwn service or live task. Do not silently expand a holdout after inspecting its outcomes.

Offline checks: `python .github/scripts/check_benchmark_plan.py` and `python .github/scripts/check_benchmark_report.py`.
