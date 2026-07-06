"""
benchmark.py — Detection-rate benchmark (Step 5, Week 4).

Runs the Semantic Analyzer against every server in the test bed and
scores its findings against servers/ground_truth.json, producing
precision/recall/F1 — the actual numbers for your resume/paper, computed
from ground truth rather than eyeballed from terminal output.

Because local LLM judgment isn't fully deterministic (see the git_stauts
discussion in Week 3), this runs each server N times (default 3) and
reports both a per-run breakdown and an aggregate detection rate, which
is the more defensible way to report this than a single run.

Usage:
    python3 agents/benchmark.py                    # all 3 servers, 3 runs each
    python3 agents/benchmark.py --runs 5
    python3 agents/benchmark.py --servers servers/tool_poisoning_server.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from semantic_analyzer import analyze_server  # noqa: E402

GROUND_TRUTH_PATH = Path(__file__).resolve().parent.parent / "servers" / "ground_truth.json"
DEFAULT_SERVERS = [
    "servers/clean_server.py",
    "servers/tool_poisoning_server.py",
    "servers/permission_overreach_server.py",
    "servers/token_mismanagement_server.py",
]


def _load_ground_truth() -> dict[str, Any]:
    data = json.loads(GROUND_TRUTH_PATH.read_text())
    data.pop("_owasp_reference", None)
    return data


def _planted_tool_names(gt_entry: dict[str, Any]) -> set[str]:
    return {v["tool"] for v in gt_entry["planted_vulnerabilities"]}


def run_benchmark(server_paths: list[str], runs: int) -> dict[str, Any]:
    ground_truth = _load_ground_truth()
    project_root = Path(__file__).resolve().parent.parent

    per_server_runs: dict[str, list[dict[str, Any]]] = {}
    tp = fp = fn = tn = 0

    for server_path in server_paths:
        key = Path(server_path).name
        if key not in ground_truth:
            print(f"[benchmark] WARNING: no ground truth entry for {key}, skipping.")
            continue

        planted = _planted_tool_names(ground_truth[key])
        per_server_runs[key] = []

        for run_idx in range(runs):
            cmd = [sys.executable, str(project_root / server_path)]
            analysis = analyze_server(cmd)
            flagged = {f["tool_name"] for f in analysis["findings"] if f["flagged"]}
            all_tools = {f["tool_name"] for f in analysis["findings"]}
            clean_expected = all_tools - planted

            run_tp = len(flagged & planted)
            run_fp = len(flagged & clean_expected)
            run_fn = len(planted - flagged)
            run_tn = len(clean_expected - flagged)

            tp += run_tp
            fp += run_fp
            fn += run_fn
            tn += run_tn

            per_server_runs[key].append(
                {
                    "run": run_idx + 1,
                    "flagged": sorted(flagged),
                    "expected_planted": sorted(planted),
                    "true_positives": run_tp,
                    "false_positives": run_fp,
                    "false_negatives": run_fn,
                    "true_negatives": run_tn,
                }
            )
            print(
                f"  [{key}] run {run_idx + 1}/{runs}: "
                f"TP={run_tp} FP={run_fp} FN={run_fn} TN={run_tn} "
                f"flagged={sorted(flagged)}"
            )

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) and precision == precision and recall == recall
        else float("nan")
    )

    return {
        "runs_per_server": runs,
        "servers_tested": list(per_server_runs.keys()),
        "aggregate": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 3) if precision == precision else None,
            "recall": round(recall, 3) if recall == recall else None,
            "f1": round(f1, 3) if f1 == f1 else None,
        },
        "per_server_runs": per_server_runs,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--servers", nargs="+", default=DEFAULT_SERVERS)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    print(f"Running benchmark: {args.runs} run(s) per server, {len(args.servers)} server(s)\n")
    result = run_benchmark(args.servers, args.runs)

    print("\n=== Aggregate results ===")
    agg = result["aggregate"]
    print(f"TP={agg['true_positives']}  FP={agg['false_positives']}  "
          f"FN={agg['false_negatives']}  TN={agg['true_negatives']}")
    print(f"Precision: {agg['precision']}")
    print(f"Recall:    {agg['recall']}")
    print(f"F1:        {agg['f1']}")

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2))
        print(f"\n[written to {args.out}]")
