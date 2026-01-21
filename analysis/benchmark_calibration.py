#!/usr/bin/env python3
"""
Calibration evaluation against OWASP Benchmark Java (v1.2).
Runs Bean Vulnerable on a stratified sample and computes ECE/Brier.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
DATASET_ROOT = REPO_ROOT / "datasets" / "benchmarkjava"
EXPECTED_CSV = DATASET_ROOT / "expectedresults-1.2.csv"
JAVA_ROOT = DATASET_ROOT / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"

# Map Benchmark categories to Bean Vulnerable detection types
CATEGORY_MAP = {
    "sqli": "sql_injection",
    "cmdi": "command_injection",
    "xss": "xss",
    "pathtraver": "path_traversal",
    "ldapi": "ldap_injection",
    "xxe": "xxe",
    "crypto": "weak_crypto",
    "hash": "weak_crypto",
    "weakrand": "insecure_randomness",
    "trustbound": "trust_boundary_violation",
    "csrf": "csrf",
}


@dataclass
class SampleEntry:
    test_name: str
    category: str
    vuln_type: str
    is_vulnerable: bool
    file_path: Path


def _iter_expected(csv_path: Path) -> Iterable[Tuple[str, str, bool, str]]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(line for line in handle if line.strip() and not line.startswith("#"))
        for row in reader:
            if len(row) < 4:
                continue
            test_name, category, real_vuln, cwe = row[0], row[1], row[2], row[3]
            yield test_name.strip(), category.strip().lower(), real_vuln.strip().lower() == "true", cwe.strip()


def _collect_samples(max_per_category: int, seed: int) -> List[SampleEntry]:
    grouped: Dict[str, List[SampleEntry]] = {}
    missing_files: List[str] = []

    for test_name, category, is_vulnerable, _cwe in _iter_expected(EXPECTED_CSV):
        vuln_type = CATEGORY_MAP.get(category)
        if vuln_type is None:
            continue
        file_path = JAVA_ROOT / f"{test_name}.java"
        if not file_path.exists():
            missing_files.append(test_name)
            continue
        entry = SampleEntry(
            test_name=test_name,
            category=category,
            vuln_type=vuln_type,
            is_vulnerable=is_vulnerable,
            file_path=file_path,
        )
        grouped.setdefault(vuln_type, []).append(entry)

    if missing_files:
        print(f"⚠️  Missing {len(missing_files)} files referenced by expectedresults-1.2.csv")

    rng = random.Random(seed)
    selected: List[SampleEntry] = []
    for vuln_type in sorted(grouped.keys()):
        items = grouped[vuln_type]
        if len(items) <= max_per_category:
            selected.extend(sorted(items, key=lambda e: e.test_name))
        else:
            selected.extend(sorted(rng.sample(items, max_per_category), key=lambda e: e.test_name))

    return selected


def _bin_index(conf: float, bins: int) -> int:
    if conf >= 1.0:
        return bins - 1
    if conf <= 0.0:
        return 0
    return int(conf * bins)


def _evaluate(samples: List[SampleEntry]) -> Dict[str, object]:
    import sys  # deferred to keep module import clean

    sys.path.insert(0, str(SRC_ROOT))
    from core.integrated_gnn_framework import IntegratedGNNFramework  # noqa: WPS433

    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger("core").setLevel(logging.WARNING)

    framework = IntegratedGNNFramework()

    results = []
    per_category: Dict[str, Dict[str, int]] = {}
    bin_counts = [{"count": 0, "sum_conf": 0.0, "sum_true": 0.0} for _ in range(10)]

    start = time.time()
    for idx, entry in enumerate(samples, start=1):
        try:
            code = entry.file_path.read_text(encoding="utf-8", errors="replace")
            analysis = framework.analyze_code(code, source_path=str(entry.file_path))
            confidence = float(analysis.get("confidence", 0.0))
            confidence = max(0.0, min(1.0, confidence))
            vulnerabilities = analysis.get("vulnerabilities_found", [])
            predicted = entry.vuln_type in vulnerabilities
        except Exception as exc:  # pragma: no cover - safety
            results.append(
                {
                    "test_name": entry.test_name,
                    "category": entry.category,
                    "vuln_type": entry.vuln_type,
                    "true_label": entry.is_vulnerable,
                    "pred_label": False,
                    "confidence": 0.0,
                    "error": str(exc),
                }
            )
            continue

        results.append(
            {
                "test_name": entry.test_name,
                "category": entry.category,
                "vuln_type": entry.vuln_type,
                "true_label": entry.is_vulnerable,
                "pred_label": predicted,
                "confidence": confidence,
            }
        )

        stats = per_category.setdefault(
            entry.vuln_type, {"count": 0, "pos": 0, "pred_pos": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
        )
        stats["count"] += 1
        if entry.is_vulnerable:
            stats["pos"] += 1
        if predicted:
            stats["pred_pos"] += 1

        if entry.is_vulnerable and predicted:
            stats["tp"] += 1
        elif entry.is_vulnerable and not predicted:
            stats["fn"] += 1
        elif not entry.is_vulnerable and predicted:
            stats["fp"] += 1
        else:
            stats["tn"] += 1

        bin_idx = _bin_index(confidence, 10)
        bin_counts[bin_idx]["count"] += 1
        bin_counts[bin_idx]["sum_conf"] += confidence
        bin_counts[bin_idx]["sum_true"] += 1.0 if entry.is_vulnerable else 0.0

        if idx == 1 or idx % 10 == 0:
            elapsed = time.time() - start
            print(f"Processed {idx}/{len(samples)} files in {elapsed:.1f}s")

    total = len(results)
    tp = sum(1 for r in results if r["true_label"] and r["pred_label"])
    fp = sum(1 for r in results if not r["true_label"] and r["pred_label"])
    tn = sum(1 for r in results if not r["true_label"] and not r["pred_label"])
    fn = sum(1 for r in results if r["true_label"] and not r["pred_label"])

    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    brier = sum((r["confidence"] - (1.0 if r["true_label"] else 0.0)) ** 2 for r in results) / total if total else 0.0

    ece = 0.0
    bins_out = []
    for idx, bucket in enumerate(bin_counts):
        count = bucket["count"]
        if count == 0:
            bins_out.append({"bin": idx, "count": 0, "avg_conf": 0.0, "accuracy": 0.0})
            continue
        avg_conf = bucket["sum_conf"] / count
        acc = bucket["sum_true"] / count
        ece += (count / total) * abs(avg_conf - acc)
        bins_out.append({"bin": idx, "count": count, "avg_conf": avg_conf, "accuracy": acc})

    return {
        "dataset": "owasp-benchmark-java-1.2",
        "total_samples": total,
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "brier": brier,
            "ece": ece,
        },
        "per_category": per_category,
        "bins": bins_out,
        "samples": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark calibration evaluation.")
    parser.add_argument("--max-per-category", type=int, default=20, help="Max samples per mapped category.")
    parser.add_argument("--seed", type=int, default=1337, help="Sampling RNG seed.")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "analysis" / "benchmark_calibration_results.json",
        help="Output JSON file.",
    )
    args = parser.parse_args()

    if not EXPECTED_CSV.exists():
        print(f"Expected CSV not found: {EXPECTED_CSV}")
        return 1

    samples = _collect_samples(args.max_per_category, args.seed)
    if not samples:
        print("No samples selected. Check dataset paths and category mapping.")
        return 1

    print(f"Selected {len(samples)} samples across {len(set(s.vuln_type for s in samples))} categories.")
    results = _evaluate(samples)
    results["sample"] = {
        "max_per_category": args.max_per_category,
        "seed": args.seed,
        "selected": len(samples),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Calibration results written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
