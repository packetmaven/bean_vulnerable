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
from typing import Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING
import os

if TYPE_CHECKING:
    from core.integrated_gnn_framework import IntegratedGNNFramework


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


def _flatten_checkpoint_args(raw: Optional[List[str]]) -> List[str]:
    if not raw:
        return []
    flattened: List[str] = []
    for item in raw:
        if not item:
            continue
        flattened.extend([part.strip() for part in str(item).split(",") if part.strip()])
    return flattened


def _ensure_cli_arg(args_list: List[str], flag: str, value: Optional[object]) -> None:
    if value is None:
        return
    if any(str(item).startswith(flag) for item in args_list):
        return
    args_list.extend([flag, str(value)])


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


def _run_cli(
    cli: str, file_path: Path, tmp_json: Path, extra_args: Optional[List[str]]
) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    cmd = [cli, str(file_path), "--summary", "--out", str(tmp_json)]
    if extra_args:
        cmd.extend(extra_args)
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


def _run_framework(
    framework: "IntegratedGNNFramework", file_path: Path
) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return None, f"Failed to read file: {exc}"

    try:
        # Reset taint tracker per file to avoid state bleed between analyses.
        if getattr(framework, "taint_tracker", None) is not None:
            from core.comprehensive_taint_tracking import ComprehensiveTaintTracker

            framework.taint_tracker = ComprehensiveTaintTracker(
                tai_e_config=getattr(framework, "tai_e_config", None)
            )
        analysis = framework.analyze_code(source_code, source_path=str(file_path))
        return analysis, None
    except Exception as exc:  # pragma: no cover - safety
        return None, str(exc)


def _evaluate(
    entries: List[SeedEntry],
    cli: str,
    extra_args: Optional[List[str]],
    runner: str,
    framework: Optional["IntegratedGNNFramework"],
) -> Dict[str, object]:
    logging.getLogger().setLevel(logging.WARNING)

    results = []
    per_category: Dict[str, Dict[str, int]] = {}
    bin_counts = [{"count": 0, "sum_conf": 0.0, "sum_true": 0.0} for _ in range(10)]

    start = time.time()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for idx, entry in enumerate(entries, start=1):
            tmp_json = tmpdir_path / "result.json"
            if runner == "framework":
                analysis, error = _run_framework(framework, entry.file_path)
            else:
                analysis, error = _run_cli(cli, entry.file_path, tmp_json, extra_args)
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
        "--cli-arg",
        action="append",
        default=[],
        help="Extra arguments to pass to bean-vuln (repeatable).",
    )
    parser.add_argument(
        "--runner",
        choices=["cli", "framework"],
        default="cli",
        help="Execution mode: CLI per file or in-process framework (faster).",
    )
    parser.add_argument(
        "--joern-timeout",
        type=int,
        default=480,
        help="Joern timeout in seconds for in-process framework runs.",
    )
    parser.add_argument(
        "--no-spatial-gnn",
        action="store_true",
        help="Disable spatial GNN for in-process framework runs.",
    )
    parser.add_argument(
        "--joern-dataflow",
        action="store_true",
        help="Enable Joern reachableByFlows dataflow extraction.",
    )
    parser.add_argument(
        "--tai-e",
        action="store_true",
        help="Enable Tai-e object-sensitive pointer analysis.",
    )
    parser.add_argument(
        "--tai-e-home",
        help="Path to Tai-e installation (or set TAI_E_HOME).",
    )
    parser.add_argument(
        "--tai-e-main",
        help="Tai-e main class (fully-qualified, must define main(String[])).",
    )
    parser.add_argument(
        "--tai-e-cs",
        default="1-obj",
        help="Tai-e context sensitivity (e.g., 1-obj, 2-obj, 1-type).",
    )
    parser.add_argument(
        "--tai-e-timeout",
        type=int,
        default=300,
        help="Tai-e pointer analysis timeout in seconds (default: 300).",
    )
    parser.add_argument(
        "--tai-e-only-app",
        action="store_true",
        default=True,
        help="Analyze application classes only (default: true).",
    )
    parser.add_argument(
        "--tai-e-all-classes",
        action="store_false",
        dest="tai_e_only_app",
        help="Include library classes in Tai-e analysis.",
    )
    parser.add_argument(
        "--tai-e-allow-phantom",
        action="store_true",
        default=True,
        help="Allow phantom references in Tai-e (default: true).",
    )
    parser.add_argument(
        "--tai-e-no-phantom",
        action="store_false",
        dest="tai_e_allow_phantom",
        help="Disable phantom references in Tai-e.",
    )
    parser.add_argument(
        "--tai-e-prepend-jvm",
        action="store_true",
        default=True,
        help="Use current JVM classpath for Tai-e (default: true).",
    )
    parser.add_argument(
        "--tai-e-no-prepend-jvm",
        action="store_false",
        dest="tai_e_prepend_jvm",
        help="Do not prepend JVM classpath in Tai-e.",
    )
    parser.add_argument(
        "--tai-e-java-version",
        type=int,
        help="Tai-e -java version (uses bundled Java libs if available).",
    )
    parser.add_argument(
        "--tai-e-classpath",
        help="Additional classpath for Tai-e compilation (javac -cp).",
    )
    parser.add_argument(
        "--tai-e-taint",
        action="store_true",
        help="Enable Tai-e taint analysis (requires taint config).",
    )
    parser.add_argument(
        "--tai-e-taint-config",
        help="Path to Tai-e taint config (file or directory).",
    )
    parser.add_argument(
        "--tai-e-soundness",
        action="store_true",
        help="Run Tai-e soundness validation using runtime logging.",
    )
    parser.add_argument(
        "--tai-e-precision-diagnose",
        action="store_true",
        help="Run heuristic precision diagnosis for Tai-e runs.",
    )
    parser.add_argument(
        "--tai-e-profile",
        action="store_true",
        help="Run Tai-e profiling harness (best-effort, optional tools).",
    )
    parser.add_argument(
        "--tai-e-profile-output",
        help="Directory (or .html file) for profiling report output.",
    )
    parser.add_argument(
        "--async-profiler-path",
        help="Path to async-profiler agent (enables CPU profiling).",
    )
    parser.add_argument(
        "--yourkit-agent-path",
        help="Path to YourKit agent (enables memory profiling).",
    )
    parser.add_argument(
        "--profile-jfr",
        action="store_true",
        help="Enable JVM Flight Recorder collection during profiling.",
    )
    parser.add_argument(
        "--profile-system",
        action="store_true",
        help="Enable system-level sampling during profiling.",
    )
    parser.add_argument(
        "--profile-heapdump",
        action="store_true",
        help="Capture a JVM heap dump during Tai-e profiling (requires jcmd).",
    )
    parser.add_argument(
        "--profile-heapdump-delay",
        type=int,
        default=5,
        help="Seconds to wait before heap dump capture (default: 5).",
    )
    parser.add_argument(
        "--profile-max-heap",
        help="Set JVM -Xmx for profiling runs (e.g. 8g).",
    )
    parser.add_argument(
        "--profile-min-heap",
        help="Set JVM -Xms for profiling runs (e.g. 2g).",
    )
    parser.add_argument(
        "--mat-path",
        help="Path to Eclipse MAT ParseHeapDump script or MAT_HOME directory.",
    )
    parser.add_argument(
        "--mat-query",
        default="suspects",
        help="MAT report to run (suspects|top_components; default: suspects).",
    )
    parser.add_argument(
        "--object-profile",
        help="Path to YourKit snapshot or CSV export for object profiling.",
    )
    parser.add_argument(
        "--object-profile-output",
        help="Path to write object profiling HTML report.",
    )
    parser.add_argument(
        "--taint-graph",
        action="store_true",
        help="Generate interactive taint flow graph HTML.",
    )
    parser.add_argument(
        "--gnn-checkpoint",
        action="append",
        help="Path to Spatial GNN checkpoint (repeatable).",
    )
    parser.add_argument(
        "--gnn-weight",
        type=float,
        default=0.6,
        help="Weight for GNN confidence in final scoring (default: 0.6).",
    )
    parser.add_argument(
        "--gnn-confidence-threshold",
        type=float,
        default=0.5,
        help="Minimum combined confidence to report a vulnerability when GNN weights are loaded.",
    )
    parser.add_argument(
        "--gnn-temperature",
        type=float,
        default=1.0,
        help="Temperature for calibrating GNN confidence (default: 1.0).",
    )
    parser.add_argument(
        "--gnn-ensemble",
        type=int,
        default=1,
        help="Number of GNN checkpoints to use in ensemble (default: 1).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "analysis" / "seed_corpus_results.json",
        help="Output JSON file.",
    )
    args = parser.parse_args()
    if args.no_spatial_gnn:
        print("⚠️ --no-spatial-gnn ignored; spatial GNN is always enabled.")
        args.no_spatial_gnn = False
    if args.tai_e_taint_config:
        args.tai_e_taint = True
    if args.tai_e_taint and not args.tai_e_taint_config:
        default_taint_config = (
            REPO_ROOT
            / "configs"
            / "tai_e"
            / "taint"
            / "web-vulnerabilities.yml"
        )
        if default_taint_config.exists():
            args.tai_e_taint_config = str(default_taint_config)
        else:
            print("⚠️ Tai-e taint enabled but no config found; skipping taint analysis.")
            args.tai_e_taint = False

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

    if args.runner == "cli":
        checkpoint_paths = _flatten_checkpoint_args(args.gnn_checkpoint)
        if checkpoint_paths and not any(str(item).startswith("--gnn-checkpoint") for item in args.cli_arg):
            for checkpoint in checkpoint_paths:
                args.cli_arg.extend(["--gnn-checkpoint", checkpoint])
        _ensure_cli_arg(args.cli_arg, "--gnn-weight", args.gnn_weight)
        _ensure_cli_arg(args.cli_arg, "--gnn-confidence-threshold", args.gnn_confidence_threshold)
        _ensure_cli_arg(args.cli_arg, "--gnn-temperature", args.gnn_temperature)
        _ensure_cli_arg(args.cli_arg, "--gnn-ensemble", args.gnn_ensemble)
        if args.joern_dataflow and "--joern-dataflow" not in args.cli_arg:
            args.cli_arg.append("--joern-dataflow")
        if args.tai_e and "--tai-e" not in args.cli_arg:
            args.cli_arg.append("--tai-e")
        _ensure_cli_arg(args.cli_arg, "--tai-e-home", args.tai_e_home)
        _ensure_cli_arg(args.cli_arg, "--tai-e-main", args.tai_e_main)
        _ensure_cli_arg(args.cli_arg, "--tai-e-cs", args.tai_e_cs)
        _ensure_cli_arg(args.cli_arg, "--tai-e-timeout", args.tai_e_timeout)
        if args.tai_e_only_app and "--tai-e-only-app" not in args.cli_arg:
            args.cli_arg.append("--tai-e-only-app")
        if not args.tai_e_only_app and "--tai-e-all-classes" not in args.cli_arg:
            args.cli_arg.append("--tai-e-all-classes")
        if args.tai_e_allow_phantom and "--tai-e-allow-phantom" not in args.cli_arg:
            args.cli_arg.append("--tai-e-allow-phantom")
        if not args.tai_e_allow_phantom and "--tai-e-no-phantom" not in args.cli_arg:
            args.cli_arg.append("--tai-e-no-phantom")
        if args.tai_e_prepend_jvm and "--tai-e-prepend-jvm" not in args.cli_arg:
            args.cli_arg.append("--tai-e-prepend-jvm")
        if not args.tai_e_prepend_jvm and "--tai-e-no-prepend-jvm" not in args.cli_arg:
            args.cli_arg.append("--tai-e-no-prepend-jvm")
        _ensure_cli_arg(args.cli_arg, "--tai-e-java-version", args.tai_e_java_version)
        _ensure_cli_arg(args.cli_arg, "--tai-e-classpath", args.tai_e_classpath)
        if args.tai_e_taint and "--tai-e-taint" not in args.cli_arg:
            args.cli_arg.append("--tai-e-taint")
        _ensure_cli_arg(args.cli_arg, "--tai-e-taint-config", args.tai_e_taint_config)
        if args.tai_e_soundness and "--tai-e-soundness" not in args.cli_arg:
            args.cli_arg.append("--tai-e-soundness")
        if args.tai_e_precision_diagnose and "--tai-e-precision-diagnose" not in args.cli_arg:
            args.cli_arg.append("--tai-e-precision-diagnose")
        if args.taint_graph and "--taint-graph" not in args.cli_arg:
            args.cli_arg.append("--taint-graph")
        if args.tai_e_profile and "--tai-e-profile" not in args.cli_arg:
            args.cli_arg.append("--tai-e-profile")
        _ensure_cli_arg(args.cli_arg, "--tai-e-profile-output", args.tai_e_profile_output)
        _ensure_cli_arg(args.cli_arg, "--async-profiler-path", args.async_profiler_path)
        _ensure_cli_arg(args.cli_arg, "--yourkit-agent-path", args.yourkit_agent_path)
        if args.profile_jfr and "--profile-jfr" not in args.cli_arg:
            args.cli_arg.append("--profile-jfr")
        if args.profile_system and "--profile-system" not in args.cli_arg:
            args.cli_arg.append("--profile-system")
        if args.profile_heapdump and "--profile-heapdump" not in args.cli_arg:
            args.cli_arg.append("--profile-heapdump")
        _ensure_cli_arg(args.cli_arg, "--profile-heapdump-delay", args.profile_heapdump_delay)
        _ensure_cli_arg(args.cli_arg, "--profile-max-heap", args.profile_max_heap)
        _ensure_cli_arg(args.cli_arg, "--profile-min-heap", args.profile_min_heap)
        _ensure_cli_arg(args.cli_arg, "--mat-path", args.mat_path)
        _ensure_cli_arg(args.cli_arg, "--mat-query", args.mat_query)
        _ensure_cli_arg(args.cli_arg, "--object-profile", args.object_profile)
        _ensure_cli_arg(args.cli_arg, "--object-profile-output", args.object_profile_output)

    framework = None
    if args.runner == "framework":
        from core.integrated_gnn_framework import IntegratedGNNFramework

        framework = IntegratedGNNFramework(
            enable_spatial_gnn=not args.no_spatial_gnn,
            joern_timeout=args.joern_timeout,
            gnn_checkpoint=_flatten_checkpoint_args(args.gnn_checkpoint),
            gnn_weight=args.gnn_weight,
            gnn_confidence_threshold=args.gnn_confidence_threshold,
            gnn_temperature=args.gnn_temperature,
            gnn_ensemble=args.gnn_ensemble,
            enable_joern_dataflow=args.joern_dataflow,
            enable_tai_e=args.tai_e,
            tai_e_home=args.tai_e_home,
            tai_e_cs=args.tai_e_cs,
            tai_e_main=args.tai_e_main,
            tai_e_timeout=args.tai_e_timeout,
            tai_e_only_app=args.tai_e_only_app,
            tai_e_allow_phantom=args.tai_e_allow_phantom,
            tai_e_prepend_jvm=args.tai_e_prepend_jvm,
            tai_e_java_version=args.tai_e_java_version,
            tai_e_classpath=args.tai_e_classpath,
            tai_e_enable_taint=args.tai_e_taint,
            tai_e_taint_config=args.tai_e_taint_config,
        )

    results = _evaluate(entries, args.cli, args.cli_arg, args.runner, framework)
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
