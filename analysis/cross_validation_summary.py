#!/usr/bin/env python3
"""
Cross-validation summary across benchmark corpora.
Loads calibration results JSON files and emits a combined summary.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> Dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _metric_block(result: Dict[str, object]) -> Dict[str, object]:
    metrics = result.get("metrics", {})
    return {
        "total_samples": result.get("total_samples"),
        "sample": result.get("sample", {}),
        "metrics": metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-validation summary.")
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=REPO_ROOT / "analysis" / "benchmark_calibration_results.json",
        help="Benchmark calibration JSON",
    )
    parser.add_argument(
        "--juliet",
        type=Path,
        default=REPO_ROOT / "analysis" / "juliet_calibration_results.json",
        help="Juliet calibration JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "analysis" / "cross_validation_summary.json",
        help="Output summary JSON",
    )
    args = parser.parse_args()

    if not args.benchmark.exists():
        print(f"Missing benchmark results: {args.benchmark}")
        return 1
    if not args.juliet.exists():
        print(f"Missing Juliet results: {args.juliet}")
        return 1

    bench = _load(args.benchmark)
    juliet = _load(args.juliet)

    summary = {
        "benchmark": _metric_block(bench),
        "juliet": _metric_block(juliet),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Cross-validation summary written to {args.output}")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
