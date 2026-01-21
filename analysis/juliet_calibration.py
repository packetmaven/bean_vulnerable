#!/usr/bin/env python3
"""
Calibration evaluation against Juliet Java test suite (GitHub mirror).
Uses file-name labels (_bad vs _good*) and CWE-to-type mapping.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
DATASET_ROOT = REPO_ROOT / "datasets" / "juliet-test-suite"
TESTCASES_ROOT = DATASET_ROOT / "src" / "testcases"

# CWE to Bean Vulnerable detection type mapping
CWE_MAP = {
    23: "path_traversal",
    36: "path_traversal",
    78: "command_injection",
    80: "xss",
    81: "xss",
    82: "xss",
    83: "xss",
    89: "sql_injection",
    90: "ldap_injection",
    113: "http_response_splitting",
    327: "weak_crypto",
    328: "weak_crypto",
}


@dataclass
class JulietEntry:
    file_path: Path
    cwe_id: int
    vuln_type: str
    is_vulnerable: bool


def _extract_cwe_id(path: Path) -> Optional[int]:
    for part in path.parts:
        if part.startswith("CWE") and "_" in part:
            digits = part[3:].split("_", 1)[0]
            if digits.isdigit():
                return int(digits)
    return None


def _label_from_filename(filename: str) -> Optional[bool]:
    lower = filename.lower()
    if "_bad" in lower:
        return True
    if "_good" in lower:
        return False
    return None


def _iter_candidates() -> Iterable[JulietEntry]:
    for java_path in TESTCASES_ROOT.rglob("*.java"):
        name = java_path.name
        if name.endswith("_base.java"):
            continue
        label = _label_from_filename(name)
        if label is None:
            continue

        cwe_id = _extract_cwe_id(java_path)
        if cwe_id is None:
            continue
        vuln_type = CWE_MAP.get(cwe_id)
        if vuln_type is None:
            continue

        yield JulietEntry(
            file_path=java_path,
            cwe_id=cwe_id,
            vuln_type=vuln_type,
            is_vulnerable=label,
        )


def _balanced_sample(entries: List[JulietEntry], max_per_type: int, seed: int) -> List[JulietEntry]:
    rng = random.Random(seed)
    grouped: Dict[str, List[JulietEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.vuln_type, []).append(entry)

    selected: List[JulietEntry] = []
    for vuln_type in sorted(grouped.keys()):
        items = grouped[vuln_type]
        bad = [e for e in items if e.is_vulnerable]
        good = [e for e in items if not e.is_vulnerable]

        half = max_per_type // 2
        pick_bad = min(half, len(bad))
        pick_good = min(max_per_type - pick_bad, len(good))

        if pick_bad < half and len(good) > pick_good:
            pick_good = min(max_per_type - pick_bad, len(good))

        if pick_good < (max_per_type - pick_bad) and len(bad) > pick_bad:
            pick_bad = min(max_per_type - pick_good, len(bad))

        if pick_bad > 0:
            selected.extend(rng.sample(bad, pick_bad))
        if pick_good > 0:
            selected.extend(rng.sample(good, pick_good))

    return selected


def _bin_index(conf: float, bins: int) -> int:
    if conf >= 1.0:
        return bins - 1
    if conf <= 0.0:
        return 0
    return int(conf * bins)


def _evaluate(samples: List[JulietEntry]) -> Dict[str, object]:
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
                    "file": str(entry.file_path),
                    "cwe_id": entry.cwe_id,
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
                "file": str(entry.file_path),
                "cwe_id": entry.cwe_id,
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
        "dataset": "juliet-java-test-suite",
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
    parser = argparse.ArgumentParser(description="Juliet calibration evaluation.")
    parser.add_argument("--max-per-category", type=int, default=20, help="Max samples per mapped category.")
    parser.add_argument("--seed", type=int, default=1337, help="Sampling RNG seed.")
    parser.add_argument("--all", action="store_true", help="Use all labeled Juliet candidates (no sampling).")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "analysis" / "juliet_calibration_results.json",
        help="Output JSON file.",
    )
    args = parser.parse_args()

    if not TESTCASES_ROOT.exists():
        print(f"Juliet dataset not found at {TESTCASES_ROOT}")
        return 1

    entries = list(_iter_candidates())
    if not entries:
        print("No Juliet candidates found; check dataset and mapping.")
        return 1

    if args.all:
        samples = entries
    else:
        samples = _balanced_sample(entries, args.max_per_category, args.seed)
    if not samples:
        print("No samples selected; check mapping and labels.")
        return 1

    print(f"Selected {len(samples)} samples across {len(set(e.vuln_type for e in samples))} categories.")
    results = _evaluate(samples)
    results["sample"] = {
        "max_per_category": args.max_per_category,
        "seed": args.seed,
        "selected": len(samples),
        "all": bool(args.all),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Calibration results written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
