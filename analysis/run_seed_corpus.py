#!/usr/bin/env python3
"""
Deterministic seed-corpus runner using the bean-vuln CLI.
Selects files with a fixed seed, runs bean-vuln, and writes calibration-style JSON.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
import os


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "datasets"
BENCH_ROOT = DATASET_ROOT / "benchmarkjava"
JULIET_ROOT = DATASET_ROOT / "juliet-test-suite"
EXPECTED_CSV = BENCH_ROOT / "expectedresults-1.2.csv"
BENCH_JAVA_ROOT = BENCH_ROOT / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
JULIET_TESTCASES = JULIET_ROOT / "src" / "testcases"

# Map OWASP Benchmark categories to Bean Vulnerable detection types
BENCH_CATEGORY_MAP = {
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

# CWE to Bean Vulnerable detection type mapping (Juliet)
JULIET_CWE_MAP = {
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
class SeedEntry:
    file_path: Path
    vuln_type: str
    is_vulnerable: bool
    category: str


def _default_cli() -> str:
    candidate = REPO_ROOT / "venv_bean_311" / "bin" / "bean-vuln"
    if candidate.exists():
        return str(candidate)
    return "bean-vuln"


def _iter_benchmark_expected() -> Iterable[Tuple[str, str, bool]]:
    with EXPECTED_CSV.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(line for line in handle if line.strip() and not line.startswith("#"))
        for row in reader:
            if len(row) < 3:
                continue
            test_name, category, real_vuln = row[0], row[1], row[2]
            yield test_name.strip(), category.strip().lower(), real_vuln.strip().lower() == "true"


def _collect_benchmark_samples(max_per_category: int, seed: int, use_all: bool) -> List[SeedEntry]:
    grouped: Dict[str, List[SeedEntry]] = {}
    for test_name, category, is_vulnerable in _iter_benchmark_expected():
        vuln_type = BENCH_CATEGORY_MAP.get(category)
        if vuln_type is None:
            continue
        file_path = BENCH_JAVA_ROOT / f"{test_name}.java"
        if not file_path.exists():
            continue
        entry = SeedEntry(
            file_path=file_path,
            vuln_type=vuln_type,
            is_vulnerable=is_vulnerable,
            category=category,
        )
        grouped.setdefault(vuln_type, []).append(entry)

    rng = random.Random(seed)
    selected: List[SeedEntry] = []
    for vuln_type in sorted(grouped.keys()):
        items = grouped[vuln_type]
        if use_all or len(items) <= max_per_category:
            selected.extend(sorted(items, key=lambda e: e.file_path.name))
        else:
            selected.extend(sorted(rng.sample(items, max_per_category), key=lambda e: e.file_path.name))

    return selected


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


def _collect_juliet_samples(max_per_category: int, seed: int, use_all: bool) -> List[SeedEntry]:
    entries: List[SeedEntry] = []
    for java_path in JULIET_TESTCASES.rglob("*.java"):
        if java_path.name.endswith("_base.java"):
            continue
        label = _label_from_filename(java_path.name)
        if label is None:
            continue
        cwe_id = _extract_cwe_id(java_path)
        if cwe_id is None:
            continue
        vuln_type = JULIET_CWE_MAP.get(cwe_id)
        if vuln_type is None:
            continue
        entries.append(
            SeedEntry(
                file_path=java_path,
                vuln_type=vuln_type,
                is_vulnerable=label,
                category=f"cwe_{cwe_id}",
            )
        )

    if use_all:
        return sorted(entries, key=lambda e: str(e.file_path))

    rng = random.Random(seed)
    grouped: Dict[str, List[SeedEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.vuln_type, []).append(entry)

    selected: List[SeedEntry] = []
    for vuln_type in sorted(grouped.keys()):
        items = grouped[vuln_type]
        bad = [e for e in items if e.is_vulnerable]
        good = [e for e in items if not e.is_vulnerable]

        half = max_per_category // 2
        pick_bad = min(half, len(bad))
        pick_good = min(max_per_category - pick_bad, len(good))

        if pick_bad < half and len(good) > pick_good:
            pick_good = min(max_per_category - pick_bad, len(good))

        if pick_good < (max_per_category - pick_bad) and len(bad) > pick_bad:
            pick_bad = min(max_per_category - pick_good, len(bad))

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


def _run_cli(cli: str, file_path: Path, tmp_json: Path) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    cmd = [cli, str(file_path), "--summary", "--out", str(tmp_json)]
    env = dict(**os.environ)
    env.setdefault("TOKENIZERS_PARALLELISM", "false")
    completed = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if completed.returncode != 0:
        return None, completed.stderr.strip() or completed.stdout.strip()
    if not tmp_json.exists():
        return None, "CLI did not produce output JSON."
    try:
        payload = json.loads(tmp_json.read_text(encoding="utf-8"))
        if isinstance(payload, list) and payload:
            return payload[0], None
        if isinstance(payload, dict):
            return payload, None
    except Exception as exc:  # pragma: no cover - safety
        return None, str(exc)
    return None, "Unexpected output format."


def _evaluate(entries: List[SeedEntry], cli: str) -> Dict[str, object]:
    logging.getLogger().setLevel(logging.WARNING)

    results = []
    per_category: Dict[str, Dict[str, int]] = {}
    bin_counts = [{"count": 0, "sum_conf": 0.0, "sum_true": 0.0} for _ in range(10)]

    start = time.time()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for idx, entry in enumerate(entries, start=1):
            tmp_json = tmpdir_path / "result.json"
            analysis, error = _run_cli(cli, entry.file_path, tmp_json)
            if analysis is None:
                results.append(
                    {
                        "file": str(entry.file_path),
                        "category": entry.category,
                        "vuln_type": entry.vuln_type,
                        "true_label": entry.is_vulnerable,
                        "pred_label": False,
                        "confidence": 0.0,
                        "error": error,
                    }
                )
                continue

            confidence = float(analysis.get("confidence", 0.0))
            confidence = max(0.0, min(1.0, confidence))
            vulnerabilities = analysis.get("vulnerabilities_found", [])
            predicted = entry.vuln_type in vulnerabilities

            results.append(
                {
                    "file": str(entry.file_path),
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
                print(f"Processed {idx}/{len(entries)} files in {elapsed:.1f}s")

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
    parser = argparse.ArgumentParser(description="Seed corpus runner using bean-vuln CLI.")
    parser.add_argument("--dataset", choices=["benchmark", "juliet"], required=True, help="Dataset to evaluate.")
    parser.add_argument("--max-per-category", type=int, default=20, help="Max samples per mapped category.")
    parser.add_argument("--seed", type=int, default=1337, help="Sampling RNG seed.")
    parser.add_argument("--all", action="store_true", help="Use all candidates (no sampling).")
    parser.add_argument("--cli", default=_default_cli(), help="Path to bean-vuln executable.")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "analysis" / "seed_corpus_results.json",
        help="Output JSON file.",
    )
    args = parser.parse_args()

    if args.dataset == "benchmark":
        if not EXPECTED_CSV.exists():
            print(f"Benchmark dataset not found at {EXPECTED_CSV}")
            return 1
        entries = _collect_benchmark_samples(args.max_per_category, args.seed, args.all)
        dataset_name = "owasp-benchmark-java-1.2"
    else:
        if not JULIET_TESTCASES.exists():
            print(f"Juliet dataset not found at {JULIET_TESTCASES}")
            return 1
        entries = _collect_juliet_samples(args.max_per_category, args.seed, args.all)
        dataset_name = "juliet-java-test-suite"

    if not entries:
        print("No samples selected; check dataset paths or mapping.")
        return 1

    print(f"Selected {len(entries)} samples across {len(set(e.vuln_type for e in entries))} categories.")
    results = _evaluate(entries, args.cli)
    results["dataset"] = dataset_name
    results["sample"] = {
        "max_per_category": args.max_per_category,
        "seed": args.seed,
        "selected": len(entries),
        "all": bool(args.all),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Seed corpus results written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
