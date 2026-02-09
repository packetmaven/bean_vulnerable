#!/usr/bin/env python3
"""
compute_ece.py — Expected Calibration Error Analysis for bean_vulnerable

Computes calibration metrics for the GNN + heuristic ensemble pipeline,
including:
    1. Expected Calibration Error (ECE) — primary metric
    2. Maximum Calibration Error (MCE) — worst-case bin
    3. Adaptive ECE (AECE) — equal-mass binning variant
    4. Per-class calibration (safe vs vulnerable)
    5. Subgroup calibration (by graph complexity)
    6. Reliability diagram data (for visualization)
    7. Overconfidence and underconfidence decomposition
    8. Security-adjusted ECE (overconfidence weighted higher)

Research foundation:
    - Naeini et al. (AAAI 2015): "Obtaining Well Calibrated Predictions
      Using Bayesian Binning into Quantiles" — ECE definition, binning
    - Guo et al. (ICML 2017): "On Calibration of Modern Neural Networks"
      — temperature scaling, reliability diagrams
    - Minderer et al. (NeurIPS 2021): "Revisiting the Calibration of
      Modern Neural Networks" — per-class and adaptive ECE
    - Hsu et al. (ICLR 2022): "What Makes Graph Neural Networks
      Miscalibrated?" — GNN-specific calibration issues
    - Vos et al. (PMLR 2024): "Calibration techniques for node
      classification using graph neural networks" — GNN calibration methods

Usage:
    # From prediction JSON (output of inference pipeline):
    python compute_ece.py --predictions val_results.json

    # With JSON export:
    python compute_ece.py --predictions val_results.json --output calibration_report.json

    # Custom bins / thresholds:
    python compute_ece.py --predictions val_results.json --n-bins 20 --threshold 0.05

Programmatic usage:
    from compute_ece import CalibrationAnalyzer
    analyzer = CalibrationAnalyzer(n_bins=15)
    report = analyzer.compute_full_report(confidences, labels)
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

LOG = logging.getLogger(__name__)


# ======================================================================
# DATA STRUCTURES
# ======================================================================


@dataclass
class BinStats:
    """Statistics for a single calibration bin."""

    bin_lower: float
    bin_upper: float
    bin_center: float
    count: int
    avg_confidence: float
    avg_accuracy: float
    gap: float  # |avg_accuracy - avg_confidence|
    overconfident: bool  # avg_confidence > avg_accuracy
    fraction: float  # count / total_samples


@dataclass
class CalibrationReport:
    """Complete calibration analysis report."""

    # Primary metrics
    ece: float  # Expected Calibration Error (L1)
    mce: float  # Maximum Calibration Error
    ece_l2: float  # ECE with L2 norm
    adaptive_ece: float  # Equal-mass binning ECE

    # Decomposition
    overconfidence_error: float  # Contribution from overconfident bins
    underconfidence_error: float  # Contribution from underconfident bins
    overconfidence_fraction: float  # Fraction of samples in overconfident bins

    # Summary statistics
    total_samples: int
    overall_accuracy: float
    overall_avg_confidence: float
    confidence_accuracy_gap: float  # |avg_conf - accuracy|

    # Bin-level details
    bins: List[BinStats]
    n_bins_used: int  # Bins with > 0 samples
    n_bins_total: int

    # Per-class / subgroup
    per_class_ece: Optional[Dict[int, float]] = None
    subgroup_ece: Optional[Dict[str, float]] = None

    # Thresholds
    pass_fail: str = ""  # "PASS" or "FAIL"
    threshold: float = 0.10


# ======================================================================
# CORE CALIBRATION COMPUTATION
# ======================================================================


class CalibrationAnalyzer:
    """
    Computes calibration metrics for binary and multiclass predictions.

    Theory:
        ECE = Σ (|B_m| / n) * |acc(B_m) - conf(B_m)|
    """

    def __init__(
        self,
        n_bins: int = 15,
        security_overconfidence_weight: float = 2.0,
    ):
        self.n_bins = int(n_bins)
        self.security_weight = float(security_overconfidence_weight)

    # --------------------------------------------------------- ECE (L1)
    def compute_ece(
        self,
        confidences: np.ndarray,
        labels: np.ndarray,
        predictions: Optional[np.ndarray] = None,
    ) -> Tuple[float, List[BinStats]]:
        n = int(len(confidences))
        if n == 0:
            return 0.0, []

        confidences = np.clip(np.asarray(confidences, dtype=np.float64), 0.0, 1.0)
        labels = np.asarray(labels, dtype=np.int64)

        if predictions is None:
            predictions = (confidences >= 0.5).astype(int)
        else:
            predictions = np.asarray(predictions, dtype=np.int64)

        correct = (predictions == labels).astype(float)

        bin_boundaries = np.linspace(0.0, 1.0, self.n_bins + 1)
        bin_stats: List[BinStats] = []
        ece = 0.0

        for i in range(self.n_bins):
            lower = float(bin_boundaries[i])
            upper = float(bin_boundaries[i + 1])

            if i == self.n_bins - 1:
                mask = (confidences >= lower) & (confidences <= upper)
            else:
                mask = (confidences >= lower) & (confidences < upper)

            count = int(mask.sum())
            if count == 0:
                bin_stats.append(
                    BinStats(
                        bin_lower=lower,
                        bin_upper=upper,
                        bin_center=(lower + upper) / 2.0,
                        count=0,
                        avg_confidence=0.0,
                        avg_accuracy=0.0,
                        gap=0.0,
                        overconfident=False,
                        fraction=0.0,
                    )
                )
                continue

            avg_conf = float(confidences[mask].mean())
            avg_acc = float(correct[mask].mean())
            gap = abs(avg_acc - avg_conf)
            fraction = count / n

            bin_stats.append(
                BinStats(
                    bin_lower=lower,
                    bin_upper=upper,
                    bin_center=(lower + upper) / 2.0,
                    count=count,
                    avg_confidence=avg_conf,
                    avg_accuracy=avg_acc,
                    gap=gap,
                    overconfident=(avg_conf > avg_acc),
                    fraction=fraction,
                )
            )

            ece += fraction * gap

        return float(ece), bin_stats

    # --------------------------------------------------------- MCE
    @staticmethod
    def compute_mce(bin_stats: List[BinStats]) -> float:
        gaps = [b.gap for b in bin_stats if b.count > 0]
        return float(max(gaps)) if gaps else 0.0

    # --------------------------------------------------------- ECE L2
    @staticmethod
    def compute_ece_l2(bin_stats: List[BinStats]) -> float:
        total = 0.0
        for b in bin_stats:
            if b.count > 0:
                total += b.fraction * (b.gap**2)
        return float(math.sqrt(total))

    # --------------------------------------------------- Adaptive ECE
    def compute_adaptive_ece(
        self,
        confidences: np.ndarray,
        labels: np.ndarray,
        predictions: Optional[np.ndarray] = None,
    ) -> float:
        n = int(len(confidences))
        if n == 0:
            return 0.0

        confidences = np.clip(np.asarray(confidences, dtype=np.float64), 0.0, 1.0)
        labels = np.asarray(labels, dtype=np.int64)

        if predictions is None:
            predictions = (confidences >= 0.5).astype(int)
        else:
            predictions = np.asarray(predictions, dtype=np.int64)

        correct = (predictions == labels).astype(float)

        order = np.argsort(confidences)
        sorted_conf = confidences[order]
        sorted_correct = correct[order]

        bin_size = max(1, n // self.n_bins)
        ece = 0.0

        for i in range(0, n, bin_size):
            end = min(i + bin_size, n)
            bin_conf = sorted_conf[i:end]
            bin_correct = sorted_correct[i:end]
            if len(bin_conf) == 0:
                continue
            avg_conf = float(bin_conf.mean())
            avg_acc = float(bin_correct.mean())
            fraction = len(bin_conf) / n
            ece += fraction * abs(avg_acc - avg_conf)

        return float(ece)

    # ---------------------------------------- Overconfidence decomposition
    @staticmethod
    def compute_overconfidence_decomposition(
        bin_stats: List[BinStats],
    ) -> Tuple[float, float, float]:
        over_err = 0.0
        under_err = 0.0
        over_count = 0
        total_count = 0

        for b in bin_stats:
            if b.count == 0:
                continue
            total_count += b.count
            if b.overconfident:
                over_err += b.fraction * b.gap
                over_count += b.count
            else:
                under_err += b.fraction * b.gap

        over_frac = over_count / total_count if total_count > 0 else 0.0
        return float(over_err), float(under_err), float(over_frac)

    # ---------------------------------------- Security-adjusted ECE
    def compute_security_ece(self, bin_stats: List[BinStats]) -> float:
        weighted_ece = 0.0
        for b in bin_stats:
            if b.count == 0:
                continue
            weight = self.security_weight if b.overconfident else 1.0
            weighted_ece += weight * b.fraction * b.gap
        return float(weighted_ece)

    # ---------------------------------------- Per-class ECE
    def compute_per_class_ece(
        self,
        confidences: np.ndarray,
        labels: np.ndarray,
        predictions: Optional[np.ndarray] = None,
    ) -> Dict[int, float]:
        confidences = np.asarray(confidences, dtype=np.float64)
        labels = np.asarray(labels, dtype=np.int64)
        if predictions is None:
            predictions = (confidences >= 0.5).astype(int)
        else:
            predictions = np.asarray(predictions, dtype=np.int64)

        unique_classes = np.unique(labels)
        per_class: Dict[int, float] = {}
        for cls in unique_classes:
            mask = labels == cls
            if mask.sum() == 0:
                continue
            ece_val, _ = self.compute_ece(confidences[mask], labels[mask], predictions[mask])
            per_class[int(cls)] = float(ece_val)
        return per_class

    # ---------------------------------------- Subgroup ECE
    def compute_subgroup_ece(
        self,
        confidences: np.ndarray,
        labels: np.ndarray,
        subgroup_labels: np.ndarray,
        predictions: Optional[np.ndarray] = None,
    ) -> Dict[str, float]:
        confidences = np.asarray(confidences, dtype=np.float64)
        labels = np.asarray(labels, dtype=np.int64)
        subgroup_labels = np.asarray(subgroup_labels)

        if predictions is None:
            predictions = (confidences >= 0.5).astype(int)
        else:
            predictions = np.asarray(predictions, dtype=np.int64)

        unique_groups = np.unique(subgroup_labels)
        subgroup: Dict[str, float] = {}
        for group in unique_groups:
            mask = subgroup_labels == group
            if mask.sum() == 0:
                continue
            ece_val, _ = self.compute_ece(confidences[mask], labels[mask], predictions[mask])
            subgroup[str(group)] = float(ece_val)
        return subgroup

    # ---------------------------------------- Full report
    def compute_full_report(
        self,
        confidences: np.ndarray,
        labels: np.ndarray,
        predictions: Optional[np.ndarray] = None,
        subgroup_labels: Optional[np.ndarray] = None,
        threshold: float = 0.10,
    ) -> CalibrationReport:
        confidences = np.asarray(confidences, dtype=np.float64)
        labels = np.asarray(labels, dtype=np.int64)

        if predictions is None:
            predictions = (confidences >= 0.5).astype(int)
        else:
            predictions = np.asarray(predictions, dtype=np.int64)

        ece, bins = self.compute_ece(confidences, labels, predictions)
        mce = self.compute_mce(bins)
        ece_l2 = self.compute_ece_l2(bins)
        aece = self.compute_adaptive_ece(confidences, labels, predictions)

        over_err, under_err, over_frac = self.compute_overconfidence_decomposition(bins)

        n = int(len(confidences))
        accuracy = float((predictions == labels).mean()) if n > 0 else 0.0
        avg_conf = float(confidences.mean()) if n > 0 else 0.0

        per_class = self.compute_per_class_ece(confidences, labels, predictions)

        subgroup = None
        if subgroup_labels is not None:
            subgroup = self.compute_subgroup_ece(confidences, labels, subgroup_labels, predictions)

        pass_fail = "PASS" if ece <= threshold else "FAIL"
        n_bins_used = sum(1 for b in bins if b.count > 0)

        return CalibrationReport(
            ece=ece,
            mce=mce,
            ece_l2=ece_l2,
            adaptive_ece=aece,
            overconfidence_error=over_err,
            underconfidence_error=under_err,
            overconfidence_fraction=over_frac,
            total_samples=n,
            overall_accuracy=accuracy,
            overall_avg_confidence=avg_conf,
            confidence_accuracy_gap=abs(avg_conf - accuracy),
            bins=bins,
            n_bins_used=n_bins_used,
            n_bins_total=self.n_bins,
            per_class_ece=per_class,
            subgroup_ece=subgroup,
            pass_fail=pass_fail,
            threshold=float(threshold),
        )


# ======================================================================
# RELIABILITY DIAGRAM DATA (for external plotting)
# ======================================================================


def reliability_diagram_data(bins: List[BinStats]) -> Dict[str, List[float]]:
    centers = [b.bin_center for b in bins if b.count > 0]
    accs = [b.avg_accuracy for b in bins if b.count > 0]
    confs = [b.avg_confidence for b in bins if b.count > 0]
    gaps = [b.gap for b in bins if b.count > 0]
    counts = [float(b.count) for b in bins if b.count > 0]
    fracs = [b.fraction for b in bins if b.count > 0]

    return {
        "bin_centers": centers,
        "accuracies": accs,
        "confidences": confs,
        "gaps": gaps,
        "counts": counts,
        "fractions": fracs,
    }


# ======================================================================
# PRETTY PRINTING
# ======================================================================


def print_report(report: CalibrationReport):
    W = 70
    print("=" * W)
    print("CALIBRATION ANALYSIS REPORT")
    print("=" * W)

    verdict_icon = "✅" if report.pass_fail == "PASS" else "❌"
    print(
        f"\n  Verdict: {verdict_icon} {report.pass_fail} "
        f"(ECE={report.ece:.4f}, threshold={report.threshold:.2f})"
    )

    print(f"\n{'─' * W}")
    print("  PRIMARY METRICS")
    print(f"{'─' * W}")
    print(f"  ECE (L1):          {report.ece:.4f}")
    print(f"  ECE (L2):          {report.ece_l2:.4f}")
    print(f"  MCE (worst bin):   {report.mce:.4f}")
    print(f"  Adaptive ECE:      {report.adaptive_ece:.4f}")

    if report.ece < 0.05:
        interp = "Excellent — well calibrated"
    elif report.ece < 0.10:
        interp = "Good — acceptable for production"
    elif report.ece < 0.20:
        interp = "Fair — consider post-hoc calibration"
    else:
        interp = "Poor — DO NOT use confidence scores as-is"
    print(f"  Interpretation:    {interp}")

    print(f"\n{'─' * W}")
    print("  SUMMARY STATISTICS")
    print(f"{'─' * W}")
    print(f"  Total samples:     {report.total_samples}")
    print(f"  Overall accuracy:  {report.overall_accuracy:.4f}")
    print(f"  Avg confidence:    {report.overall_avg_confidence:.4f}")
    print(f"  Conf-Acc gap:      {report.confidence_accuracy_gap:.4f}")

    print(f"\n{'─' * W}")
    print("  OVERCONFIDENCE ANALYSIS (security-critical)")
    print(f"{'─' * W}")
    print(f"  Overconfidence err:  {report.overconfidence_error:.4f}")
    print(f"  Underconfidence err: {report.underconfidence_error:.4f}")
    print(f"  Overconfident frac:  {report.overconfidence_fraction:.1%}")

    if report.per_class_ece:
        print(f"\n{'─' * W}")
        print("  PER-CLASS ECE")
        print(f"{'─' * W}")
        class_names = {0: "Safe", 1: "Vulnerable"}
        for cls_id, ece_val in sorted(report.per_class_ece.items()):
            name = class_names.get(cls_id, f"Class {cls_id}")
            flag = " ⚠️" if ece_val > report.threshold else ""
            print(f"  {name} (class {cls_id}): ECE={ece_val:.4f}{flag}")

    if report.subgroup_ece:
        print(f"\n{'─' * W}")
        print("  SUBGROUP ECE (by graph complexity)")
        print(f"{'─' * W}")
        for group, ece_val in sorted(report.subgroup_ece.items()):
            flag = " ⚠️" if ece_val > report.threshold else ""
            print(f"  {group}: ECE={ece_val:.4f}{flag}")

    print(f"\n{'─' * W}")
    print("  RELIABILITY DIAGRAM DATA")
    print(f"{'─' * W}")
    print(f"  {'Bin':>12} {'Count':>7} {'Conf':>7} {'Acc':>7} {'Gap':>7} {'Over?':>6}")
    print(f"  {'─'*12} {'─'*7} {'─'*7} {'─'*7} {'─'*7} {'─'*6}")
    for b in report.bins:
        if b.count == 0:
            continue
        over = "YES" if b.overconfident else "no"
        print(
            f"  [{b.bin_lower:.2f},{b.bin_upper:.2f})"
            f" {b.count:>7} {b.avg_confidence:>7.3f} "
            f"{b.avg_accuracy:>7.3f} {b.gap:>7.4f} {over:>6}"
        )

    print(f"\n  Bins used: {report.n_bins_used}/{report.n_bins_total}")
    print()
    print("=" * W)


# ======================================================================
# CLI: Load predictions and compute ECE
# ======================================================================


def load_predictions(path: Path) -> Tuple[np.ndarray, np.ndarray, Optional[np.ndarray], Optional[np.ndarray]]:
    """
    Load predictions from JSON file.

    Supported formats:
        1) List[dict] (bean_vulnerable inference output enriched with ground truth):
            [
              {"confidence": 0.85, "ground_truth": 1, "graph_nodes": 120, ...},
              ...
            ]

        2) Dict with explicit arrays:
            {
              "predictions": [...],
              "labels": [...],
              "predicted_classes": [...],   # optional
              "subgroups": [...]            # optional
            }
    """
    with open(path, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        confidences: List[float] = []
        labels: List[int] = []
        predictions: List[int] = []
        subgroups: List[str] = []

        for item in data:
            conf = item.get("confidence", item.get("combined", 0.0))
            confidences.append(float(conf))

            label = item.get("ground_truth", item.get("label", item.get("y_binary", -1)))
            labels.append(int(label))

            pred = item.get("predicted_class", item.get("vulnerability_detected", item.get("is_vulnerable", None)))
            if pred is None:
                pred = int(float(conf) >= 0.5)
            if isinstance(pred, bool):
                pred = int(pred)
            predictions.append(int(pred))

            nodes = item.get("graph_nodes", item.get("num_nodes", None))
            if nodes is None:
                subgroups.append("unknown")
            else:
                n_nodes = int(nodes)
                if n_nodes < 50:
                    subgroups.append("small")
                elif n_nodes < 200:
                    subgroups.append("medium")
                else:
                    subgroups.append("large")

        conf_arr = np.array(confidences, dtype=np.float64)
        label_arr = np.array(labels, dtype=np.int64)
        pred_arr = np.array(predictions, dtype=np.int64)
        subgroup_arr = np.array(subgroups) if subgroups else None
        return conf_arr, label_arr, pred_arr, subgroup_arr

    if isinstance(data, dict):
        conf_arr = np.array(data["predictions"], dtype=np.float64)
        label_arr = np.array(data["labels"], dtype=np.int64)
        pred_arr = None
        if "predicted_classes" in data:
            pred_arr = np.array(data["predicted_classes"], dtype=np.int64)
        subgroup_arr = None
        if "subgroups" in data:
            subgroup_arr = np.array(data["subgroups"])
        return conf_arr, label_arr, pred_arr, subgroup_arr

    raise ValueError(f"Unexpected data format in {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute Expected Calibration Error for bean_vulnerable"
    )
    parser.add_argument("--predictions", type=str, required=True, help="Path to predictions JSON file")
    parser.add_argument("--n-bins", type=int, default=15)
    parser.add_argument("--threshold", type=float, default=0.10)
    parser.add_argument("--output", type=str, default=None, help="Save report JSON to this path")
    parser.add_argument("--security-weight", type=float, default=2.0, help="Overconfidence penalty weight")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    pred_path = Path(args.predictions)
    LOG.info("Loading predictions from %s", pred_path)
    confidences, labels, predictions, subgroups = load_predictions(pred_path)

    valid = labels >= 0
    if not bool(valid.all()):
        LOG.warning("Filtering %d samples without ground truth labels", int((~valid).sum()))
        confidences = confidences[valid]
        labels = labels[valid]
        if predictions is not None:
            predictions = predictions[valid]
        if subgroups is not None:
            subgroups = subgroups[valid]

    LOG.info("Analyzing %d samples with %d bins", int(len(confidences)), int(args.n_bins))

    analyzer = CalibrationAnalyzer(
        n_bins=args.n_bins,
        security_overconfidence_weight=args.security_weight,
    )
    report = analyzer.compute_full_report(
        confidences=confidences,
        labels=labels,
        predictions=predictions,
        subgroup_labels=subgroups,
        threshold=args.threshold,
    )

    print_report(report)

    # Security-adjusted ECE (printed + optionally exported)
    _, bins = analyzer.compute_ece(confidences, labels, predictions)
    sec_ece = analyzer.compute_security_ece(bins)
    print(f"  Security-adjusted ECE ({args.security_weight:.1f}x overconfidence): {sec_ece:.4f}")
    print()

    if args.output:
        output_path = Path(args.output)
        report_dict = asdict(report)
        report_dict["bins"] = [asdict(b) for b in report.bins]
        report_dict["security_ece"] = float(sec_ece)
        report_dict["reliability_diagram"] = reliability_diagram_data(report.bins)
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2)
        LOG.info("Report saved to %s", output_path)

    if report.pass_fail == "FAIL":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

