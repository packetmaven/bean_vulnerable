#!/usr/bin/env python3
"""
test_combine_confidence.py — Exhaustive Test Suite for Asymmetric Confidence Fusion

Validates that `_combine_confidence()` in `src/core/integrated_gnn_framework.py`
implements the security-critical invariant:

    The GNN MUST NEVER reduce vulnerability confidence below heuristic baseline.

This suite is intentionally lightweight:
- It does NOT instantiate `IntegratedGNNFramework` (would require Joern).
- It calls `_combine_confidence` as an unbound method with a tiny dummy `self`.

Run:
    python -m pytest tests/test_combine_confidence.py -v
    python -m pytest tests/test_combine_confidence.py -v -k "security"
"""

from __future__ import annotations

import logging
import math
import random
import unittest
from dataclasses import dataclass
from typing import Any, Dict, Optional


def _import_framework():
    # Prefer the "repo-root on sys.path" import style.
    try:
        from src.core.integrated_gnn_framework import IntegratedGNNFramework  # type: ignore

        return IntegratedGNNFramework
    except Exception:
        # Fallback to the "src/ on sys.path" style used by other tests.
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(repo_root / "src"))
        from core.integrated_gnn_framework import IntegratedGNNFramework  # type: ignore

        return IntegratedGNNFramework


IntegratedGNNFramework = _import_framework()

try:  # Optional: only needed for OOD branch tests
    import torch  # type: ignore

    TORCH_AVAILABLE = True
except Exception:  # pragma: no cover
    TORCH_AVAILABLE = False


LOG = logging.getLogger(__name__)


# Threshold constants (must match production logic)
STRONG_HEURISTIC = 0.70
MODERATE_HEURISTIC = 0.40
WEAK_HEURISTIC = 0.20
AGREEMENT_DELTA = 0.15
BOOST_WEIGHT = 0.30
MIN_GNN_BOOST = 0.85
GNN_OVERCONFIDENCE = 0.95


@dataclass
class MockCESCLModule:
    """Mock CESCL module for testing OOD behavior."""

    _available: bool = False
    _ood_score: float = 0.0
    _ood_threshold: float = 1.0

    def is_available(self) -> bool:
        return bool(self._available)

    def score(self, embedding, logit_probs):
        return {"ood_score": float(self._ood_score)}

    def get_ood_threshold(self, percentile: float = 95.0):
        return float(self._ood_threshold)


class _DummySelf:
    def __init__(self, cescl_module: Optional[MockCESCLModule] = None):
        self.logger = LOG
        self.cescl_module = cescl_module


def call(
    h: float,
    g_vuln: float,
    g_safe: Optional[float] = None,
    *,
    cescl: Optional[MockCESCLModule] = None,
    embedding: Any = None,
) -> Dict[str, Any]:
    """Shorthand for calling production `_combine_confidence`."""
    if g_safe is None:
        g_safe = 1.0 - g_vuln
    dummy = _DummySelf(cescl_module=cescl)
    f = IntegratedGNNFramework._combine_confidence
    return f(
        dummy,
        heuristic_confidence=h,
        gnn_binary_probs={0: g_safe, 1: g_vuln},
        gnn_embedding=embedding,
    )


class TestMonotonicity(unittest.TestCase):
    """
    CRITICAL INVARIANT: combined >= heuristic in vulnerability regimes.
    """

    def test_strong_heuristic_low_gnn_no_suppression(self):
        r = call(h=0.85, g_vuln=0.20)
        self.assertGreaterEqual(r["combined"], 0.85)
        self.assertEqual(r["source"], "heuristic_only")

    def test_strong_heuristic_close_but_lower_gnn_no_suppression(self):
        # Regression caught by monotonicity tests:
        # h=0.80, g=0.70 is within delta but must NOT reduce below 0.80.
        r = call(h=0.80, g_vuln=0.70)
        self.assertGreaterEqual(r["combined"], 0.80)
        self.assertEqual(r["source"], "heuristic_only")

    def test_moderate_heuristic_low_gnn_no_suppression(self):
        r = call(h=0.55, g_vuln=0.15)
        self.assertGreaterEqual(r["combined"], 0.55)
        self.assertEqual(r["source"], "heuristic_only")

    def test_weak_heuristic_low_gnn_no_suppression(self):
        r = call(h=0.30, g_vuln=0.40)
        self.assertGreaterEqual(r["combined"], 0.30)

    def test_near_zero_heuristic_low_gnn_no_suppression(self):
        r = call(h=0.10, g_vuln=0.50)
        self.assertGreaterEqual(r["combined"], 0.10)

    def test_monotonicity_sweep_strong(self):
        h = 0.80
        for g in [i / 20.0 for i in range(21)]:
            r = call(h=h, g_vuln=g)
            self.assertGreaterEqual(
                r["combined"],
                h - 1e-9,
                f"VIOLATION: h={h}, g={g}, combined={r['combined']}",
            )

    def test_monotonicity_sweep_moderate(self):
        h = 0.50
        for g in [i / 20.0 for i in range(21)]:
            r = call(h=h, g_vuln=g)
            self.assertGreaterEqual(
                r["combined"],
                h - 1e-9,
                f"VIOLATION: h={h}, g={g}, combined={r['combined']}",
            )


class TestAsymmetricBoost(unittest.TestCase):
    """GNN should boost only when aligned and higher (never suppress)."""

    def test_strong_heuristic_aligned_higher_gnn_boosts(self):
        r = call(h=0.75, g_vuln=0.80)
        self.assertGreater(r["combined"], 0.75)
        self.assertEqual(r["source"], "gnn_boost")

    def test_strong_heuristic_aligned_lower_gnn_does_not_boost(self):
        r = call(h=0.80, g_vuln=0.75)
        self.assertGreaterEqual(r["combined"], 0.80)
        self.assertEqual(r["source"], "heuristic_only")

    def test_moderate_heuristic_high_gnn_boosts(self):
        r = call(h=0.50, g_vuln=0.80)
        self.assertGreater(r["combined"], 0.50)
        self.assertEqual(r["source"], "gnn_boost")

    def test_boost_amount_is_bounded(self):
        r = call(h=0.50, g_vuln=0.90)
        max_boost = 0.50 + BOOST_WEIGHT * (0.90 - 0.50)
        self.assertLessEqual(r["combined"], max_boost + 1e-9)

    def test_boost_never_exceeds_one(self):
        r = call(h=0.99, g_vuln=0.99)
        self.assertLessEqual(r["combined"], 1.0)


class TestOverconfidenceDampening(unittest.TestCase):
    """GNN outputs > 0.95 should be treated as suspect and dampened."""

    def test_moderate_heuristic_overconfident_gnn_dampened(self):
        r = call(h=0.50, g_vuln=0.99)
        expected_max = 0.50 + BOOST_WEIGHT * (0.80 - 0.50)
        self.assertLessEqual(r["combined"], expected_max + 0.02)

    def test_gnn_exactly_at_overconfidence_threshold_not_dampened(self):
        r = call(h=0.50, g_vuln=GNN_OVERCONFIDENCE)
        expected = 0.50 + BOOST_WEIGHT * (GNN_OVERCONFIDENCE - 0.50)
        self.assertAlmostEqual(r["combined"], expected, places=3)

    def test_gnn_just_above_overconfidence_threshold_dampened(self):
        r = call(h=0.50, g_vuln=0.96)
        expected = 0.50 + BOOST_WEIGHT * (0.80 - 0.50)
        self.assertAlmostEqual(r["combined"], expected, places=3)


class TestOODHandling(unittest.TestCase):
    """Out-of-distribution samples should fall back to heuristic confidence."""

    def setUp(self):
        if not TORCH_AVAILABLE:
            self.skipTest("torch not available; skipping OOD branch tests.")

    def test_ood_returns_heuristic(self):
        cescl = MockCESCLModule(_available=True, _ood_score=2.0, _ood_threshold=1.0)
        r = call(h=0.60, g_vuln=0.10, cescl=cescl, embedding="dummy")
        self.assertTrue(r["ood_detected"])
        self.assertEqual(r["source"], "heuristic_only_ood")
        self.assertGreaterEqual(r["combined"], 0.60)

    def test_ood_floors_at_060(self):
        cescl = MockCESCLModule(_available=True, _ood_score=3.0, _ood_threshold=1.0)
        r = call(h=0.10, g_vuln=0.95, cescl=cescl, embedding="dummy")
        self.assertTrue(r["ood_detected"])
        self.assertGreaterEqual(r["combined"], 0.60)

    def test_not_ood_allows_normal_fusion(self):
        cescl = MockCESCLModule(_available=True, _ood_score=0.5, _ood_threshold=1.0)
        r = call(h=0.50, g_vuln=0.80, cescl=cescl, embedding="dummy")
        self.assertFalse(r["ood_detected"])
        self.assertGreater(r["combined"], 0.50)

    def test_cescl_unavailable_no_ood(self):
        cescl = MockCESCLModule(_available=False)
        r = call(h=0.50, g_vuln=0.80, cescl=cescl, embedding="dummy")
        self.assertFalse(r["ood_detected"])

    def test_no_embedding_no_ood(self):
        cescl = MockCESCLModule(_available=True, _ood_score=5.0, _ood_threshold=1.0)
        r = call(h=0.50, g_vuln=0.80, cescl=cescl, embedding=None)
        self.assertFalse(r["ood_detected"])


class TestEdgeCases(unittest.TestCase):
    """Zeros, ones, NaN, Inf, extreme values, missing keys."""

    def test_zero_heuristic_zero_gnn(self):
        r = call(h=0.0, g_vuln=0.0)
        self.assertEqual(r["combined"], 0.0)

    def test_one_heuristic_one_gnn(self):
        r = call(h=1.0, g_vuln=1.0)
        self.assertLessEqual(r["combined"], 1.0)
        self.assertGreaterEqual(r["combined"], 0.99)

    def test_nan_heuristic_returns_safe_default(self):
        r = call(h=float("nan"), g_vuln=0.80)
        self.assertEqual(r["combined"], 0.50)
        self.assertEqual(r["source"], "error_nan_heuristic")

    def test_nan_gnn_returns_heuristic(self):
        r = call(h=0.65, g_vuln=float("nan"))
        self.assertEqual(r["combined"], 0.65)
        self.assertEqual(r["source"], "heuristic_only_nan_gnn")

    def test_inf_heuristic(self):
        r = call(h=float("inf"), g_vuln=0.50)
        self.assertEqual(r["combined"], 0.50)

    def test_negative_heuristic_clamped(self):
        r = call(h=-0.10, g_vuln=0.50)
        self.assertGreaterEqual(r["combined"], 0.0)

    def test_gnn_above_one_clamped(self):
        r = call(h=0.50, g_vuln=1.50)
        self.assertLessEqual(r["combined"], 1.0)

    def test_missing_gnn_key(self):
        dummy = _DummySelf()
        f = IntegratedGNNFramework._combine_confidence
        r = f(dummy, heuristic_confidence=0.50, gnn_binary_probs={0: 0.90}, gnn_embedding=None)
        self.assertEqual(r["gnn_raw"], 0.0)
        self.assertEqual(r["combined"], 0.50)


class TestBoundaryConditions(unittest.TestCase):
    """Exact threshold transitions and agreement-delta edges."""

    def test_exactly_at_strong_threshold(self):
        r = call(h=STRONG_HEURISTIC, g_vuln=0.10)
        self.assertGreaterEqual(r["combined"], STRONG_HEURISTIC)

    def test_just_below_strong_threshold(self):
        r = call(h=0.6999, g_vuln=0.80)
        self.assertGreater(r["combined"], 0.6999)

    def test_exactly_at_moderate_threshold(self):
        r = call(h=MODERATE_HEURISTIC, g_vuln=0.10)
        self.assertGreaterEqual(r["combined"], MODERATE_HEURISTIC)

    def test_just_below_moderate_threshold(self):
        r = call(h=0.3999, g_vuln=0.90)
        self.assertEqual(r["source"], "gnn_calibrated")

    def test_exactly_at_weak_threshold(self):
        r = call(h=WEAK_HEURISTIC, g_vuln=0.10)
        self.assertGreaterEqual(r["combined"], WEAK_HEURISTIC)

    def test_just_below_weak_threshold(self):
        r = call(h=0.1999, g_vuln=0.90)
        self.assertEqual(r["source"], "gnn_only")

    def test_agreement_delta_boundary_boosts_only_when_higher(self):
        h = 0.80
        g = h + AGREEMENT_DELTA  # exactly at boundary (and higher)
        r = call(h=h, g_vuln=g)
        self.assertEqual(r["source"], "gnn_boost")

    def test_agreement_delta_boundary_lower_does_not_boost(self):
        h = 0.80
        g = h - AGREEMENT_DELTA  # exactly at boundary (but lower)
        r = call(h=h, g_vuln=g)
        self.assertEqual(r["source"], "heuristic_only")

    def test_agreement_delta_just_outside(self):
        h = 0.80
        g = h + AGREEMENT_DELTA + 0.01
        r = call(h=h, g_vuln=g)
        self.assertEqual(r["source"], "heuristic_only")


class TestPropertyBased(unittest.TestCase):
    """Random sampling of the input space to validate invariants."""

    def test_monotonicity_property_1000_samples(self):
        random.seed(42)
        violations = []
        for _ in range(1000):
            h = random.uniform(WEAK_HEURISTIC, 1.0)
            g = random.uniform(0.0, 1.0)
            r = call(h=h, g_vuln=g)
            if r["combined"] < h - 1e-9:
                violations.append(f"h={h:.4f}, g={g:.4f}, combined={r['combined']:.4f}")
        self.assertEqual(
            len(violations),
            0,
            "Monotonicity violations:\n" + "\n".join(violations[:10]),
        )

    def test_bounded_output_property(self):
        random.seed(43)
        for _ in range(1000):
            h = random.uniform(-0.5, 1.5)
            g = random.uniform(-0.5, 1.5)
            r = call(h=h, g_vuln=g)
            self.assertGreaterEqual(r["combined"], 0.0)
            self.assertLessEqual(r["combined"], 1.0)

    def test_source_field_always_present(self):
        valid_sources = {
            "heuristic_only",
            "gnn_boost",
            "gnn_calibrated",
            "gnn_only",
            "heuristic_only_ood",
            "error_nan_heuristic",
            "heuristic_only_nan_gnn",
        }
        random.seed(44)
        for _ in range(500):
            h = random.uniform(0.0, 1.0)
            g = random.uniform(0.0, 1.0)
            r = call(h=h, g_vuln=g)
            self.assertIn(r["source"], valid_sources)

    def test_heuristic_preserved_in_result(self):
        random.seed(45)
        for _ in range(500):
            h = random.uniform(0.0, 1.0)
            g = random.uniform(0.0, 1.0)
            r = call(h=h, g_vuln=g)
            self.assertAlmostEqual(r["heuristic"], max(0.0, min(1.0, h)), places=5)


class TestSecurityCriticalCVEScenarios(unittest.TestCase):
    """Regression tests modeled on real vulnerability detection scenarios."""

    def test_security_buffer_overflow_strong_heuristic_gnn_disagrees(self):
        r = call(h=0.88, g_vuln=0.25)
        self.assertGreaterEqual(r["combined"], 0.88)
        self.assertEqual(r["source"], "heuristic_only")

    def test_security_sql_injection_moderate_heuristic_gnn_confirms(self):
        r = call(h=0.55, g_vuln=0.82)
        self.assertGreater(r["combined"], 0.55)
        self.assertLessEqual(r["combined"], 0.95)

    def test_security_xss_weak_heuristic_gnn_very_confident(self):
        r = call(h=0.25, g_vuln=0.90)
        self.assertGreater(r["combined"], 0.25)
        self.assertEqual(r["source"], "gnn_calibrated")

    def test_security_novel_vuln_ood_detection(self):
        if not TORCH_AVAILABLE:
            self.skipTest("torch not available; skipping OOD branch tests.")
        cescl = MockCESCLModule(_available=True, _ood_score=3.0, _ood_threshold=1.0)
        r = call(h=0.60, g_vuln=0.95, cescl=cescl, embedding="dummy")
        self.assertTrue(r["ood_detected"])
        self.assertGreaterEqual(r["combined"], 0.60)

    def test_security_safe_code_gnn_overconfident_false_alarm(self):
        r = call(h=0.05, g_vuln=0.98)
        self.assertLessEqual(r["combined"], 0.70)

    def test_security_path_traversal_heuristic_perfect(self):
        # Strong heuristic should NOT be pulled down by a slightly-lower GNN.
        r = call(h=0.95, g_vuln=0.92)
        self.assertGreaterEqual(r["combined"], 0.95)
        self.assertEqual(r["source"], "heuristic_only")

    def test_security_both_say_safe(self):
        r = call(h=0.05, g_vuln=0.08)
        self.assertLessEqual(r["combined"], 0.10)

    def test_security_regression_original_bug(self):
        r = call(h=0.85, g_vuln=0.20)
        self.assertGreaterEqual(
            r["combined"],
            0.85,
            "REGRESSION: GNN suppressed vulnerability confidence.",
        )


class TestResultStructure(unittest.TestCase):
    def test_required_keys(self):
        r = call(h=0.50, g_vuln=0.50)
        required = {"combined", "source", "heuristic", "gnn_raw", "ood_detected"}
        self.assertTrue(required.issubset(r.keys()))

    def test_types(self):
        r = call(h=0.50, g_vuln=0.50)
        self.assertIsInstance(r["combined"], float)
        self.assertIsInstance(r["source"], str)
        self.assertIsInstance(r["heuristic"], float)
        self.assertIsInstance(r["gnn_raw"], float)
        self.assertIsInstance(r["ood_detected"], bool)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)

