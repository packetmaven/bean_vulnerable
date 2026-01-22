"""
Sink-Specific Gating and Confidence Threshold Engine
====================================================

Adaptive confidence thresholds and evidence-based gating per sink type.
Designed for Java taint evidence produced by the Bean Vulnerable pipeline.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

import json
import logging
import os
from pathlib import Path

try:
    from .sink_gating_config import PrecisionTuningConfig
    CONFIG_AVAILABLE = True
except Exception:  # pragma: no cover - optional
    PrecisionTuningConfig = None
    CONFIG_AVAILABLE = False

logger = logging.getLogger(__name__)


class EvidenceType(Enum):
    """Categories of vulnerability evidence."""

    DIRECT_TAINT_PATH = {
        "weight": 0.25,
        "description": "Direct path from source to sink",
    }
    INDIRECT_TAINT_PATH = {
        "weight": 0.15,
        "description": "Indirect path through calls/assignments",
    }
    NO_SANITIZER = {
        "weight": 0.20,
        "description": "No sanitizer detected between source and sink",
    }
    INEFFECTIVE_SANITIZER = {
        "weight": 0.15,
        "description": "Sanitizer present but ineffective for sink",
    }
    DANGEROUS_PATTERN = {
        "weight": 0.15,
        "description": "Dangerous sink pattern detected",
    }
    WEAK_VALIDATION = {
        "weight": 0.10,
        "description": "Input validation present but weak/insufficient",
    }
    MULTIPLE_PATHS = {
        "weight": 0.10,
        "description": "Multiple independent taint paths",
    }


@dataclass
class EvidenceInstance:
    """Single piece of evidence for vulnerability gating."""

    evidence_type: EvidenceType
    description: str
    confidence_score: float = 0.5
    line_number: int = 0
    code_context: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": self.evidence_type.name,
            "description": self.description,
            "confidence": float(self.confidence_score),
            "line": int(self.line_number),
            "context": self.code_context,
        }


@dataclass
class SinkSpecificGating:
    """Gating configuration for a specific sink/vulnerability type."""

    sink_name: str
    cwe_id: int

    base_threshold: float = 0.5
    direct_flow_threshold: float = 0.45
    indirect_flow_threshold: float = 0.60

    required_evidence_types: List[EvidenceType] = field(default_factory=list)
    min_evidence_count: int = 1
    evidence_weight_override: Dict[EvidenceType, float] = field(default_factory=dict)

    fp_penalty: float = 0.15
    fn_penalty: float = 0.10

    def to_dict(self) -> Dict[str, object]:
        return {
            "sink_name": self.sink_name,
            "cwe_id": self.cwe_id,
            "base_threshold": self.base_threshold,
            "direct_flow_threshold": self.direct_flow_threshold,
            "indirect_flow_threshold": self.indirect_flow_threshold,
            "min_evidence_count": self.min_evidence_count,
            "fp_penalty": self.fp_penalty,
            "fn_penalty": self.fn_penalty,
        }


class SinkGatingEngine:
    """Adaptive gating engine with sink-specific thresholds."""

    def __init__(self, config: Optional[Dict[str, object]] = None) -> None:
        self.sinks: Dict[str, SinkSpecificGating] = {}
        self.evidence_weights: Dict[str, Dict[str, object]] = {}
        self.calibration: Dict[str, float] = {
            "direct_flow_boost": 1.05,
            "indirect_flow_penalty": 0.95,
            "multiple_path_multiplier": 1.10,
            "dangerous_pattern_multiplier": 1.08,
            "weak_validation_penalty": 0.85,
        }
        self._load_config(config)

    def _load_config(self, config: Optional[Dict[str, object]]) -> None:
        if config is None:
            config = self._load_config_from_env()
        if config is None and CONFIG_AVAILABLE:
            config = PrecisionTuningConfig.export_config()

        if config:
            self.evidence_weights = config.get("evidence_weights", {}) if isinstance(config, dict) else {}
            calibration = config.get("confidence_calibration", {}) if isinstance(config, dict) else {}
            if isinstance(calibration, dict):
                for key in self.calibration:
                    if key in calibration:
                        try:
                            self.calibration[key] = float(calibration[key])
                        except Exception:
                            continue
            loaded = self._initialize_sinks_from_config(config)
            if loaded > 0:
                logger.info("Loaded sink gating config: %s sinks", loaded)
        self._initialize_default_sinks()

    def _load_config_from_env(self) -> Optional[Dict[str, object]]:
        config_path = os.getenv("BEAN_VULN_SINK_CONFIG")
        if not config_path:
            return None
        try:
            payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
            return payload
        except Exception as exc:
            logger.warning("Failed to load sink gating config: %s", exc)
            return None

    def _initialize_sinks_from_config(self, config: Dict[str, object]) -> int:
        sinks = config.get("sinks", {})
        if not isinstance(sinks, dict) or not CONFIG_AVAILABLE:
            return 0
        count = 0
        for config_name, sink_cfg in sinks.items():
            if not isinstance(sink_cfg, dict):
                continue
            sink_name = PrecisionTuningConfig.normalize_sink_name(config_name)
            if not sink_name:
                continue
            required_evidence = sink_cfg.get("required_evidence", [])
            if not isinstance(required_evidence, list):
                required_evidence = []
            required_types = []
            for item in required_evidence:
                if isinstance(item, str) and item in EvidenceType.__members__:
                    required_types.append(EvidenceType[item])

            weight_override = self._build_weight_override(config_name)
            gating = SinkSpecificGating(
                sink_name=sink_name,
                cwe_id=int(sink_cfg.get("cwe", 0) or 0),
                base_threshold=float(sink_cfg.get("base_threshold", 0.5)),
                direct_flow_threshold=float(sink_cfg.get("direct_flow_threshold", 0.45)),
                indirect_flow_threshold=float(sink_cfg.get("indirect_flow_threshold", 0.60)),
                required_evidence_types=required_types,
                min_evidence_count=int(sink_cfg.get("min_evidence_count", 1)),
                evidence_weight_override=weight_override,
                fp_penalty=float(sink_cfg.get("fp_penalty", 0.15)),
                fn_penalty=float(sink_cfg.get("fn_penalty", 0.10)),
            )
            self.register_sink(gating)
            count += 1
        return count

    def _build_weight_override(self, config_sink_name: str) -> Dict[EvidenceType, float]:
        overrides: Dict[EvidenceType, float] = {}
        if not self.evidence_weights or not isinstance(self.evidence_weights, dict):
            return overrides
        for ev_name, ev_cfg in self.evidence_weights.items():
            if ev_name not in EvidenceType.__members__:
                continue
            if not isinstance(ev_cfg, dict):
                continue
            by_sink = ev_cfg.get("by_sink", {})
            if isinstance(by_sink, dict) and config_sink_name in by_sink:
                try:
                    overrides[EvidenceType[ev_name]] = float(by_sink[config_sink_name])
                except Exception:
                    continue
        return overrides

    def _initialize_default_sinks(self) -> None:
        self.register_sink(
            SinkSpecificGating(
                sink_name="sql_injection",
                cwe_id=89,
                base_threshold=0.75,
                direct_flow_threshold=0.65,
                indirect_flow_threshold=0.80,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.20,
                fn_penalty=0.05,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="xss",
                cwe_id=79,
                base_threshold=0.70,
                direct_flow_threshold=0.60,
                indirect_flow_threshold=0.75,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.18,
                fn_penalty=0.08,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="el_injection",
                cwe_id=94,
                base_threshold=0.78,
                direct_flow_threshold=0.68,
                indirect_flow_threshold=0.82,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.20,
                fn_penalty=0.05,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="command_injection",
                cwe_id=78,
                base_threshold=0.80,
                direct_flow_threshold=0.70,
                indirect_flow_threshold=0.85,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.25,
                fn_penalty=0.02,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="path_traversal",
                cwe_id=22,
                base_threshold=0.72,
                direct_flow_threshold=0.62,
                indirect_flow_threshold=0.78,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.17,
                fn_penalty=0.07,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="ldap_injection",
                cwe_id=90,
                base_threshold=0.70,
                direct_flow_threshold=0.60,
                indirect_flow_threshold=0.75,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.16,
                fn_penalty=0.08,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="xxe",
                cwe_id=611,
                base_threshold=0.70,
                direct_flow_threshold=0.60,
                indirect_flow_threshold=0.75,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.16,
                fn_penalty=0.08,
            )
        )
        self.register_sink(
            SinkSpecificGating(
                sink_name="http_response_splitting",
                cwe_id=113,
                base_threshold=0.70,
                direct_flow_threshold=0.60,
                indirect_flow_threshold=0.75,
                required_evidence_types=[
                    EvidenceType.DIRECT_TAINT_PATH,
                    EvidenceType.NO_SANITIZER,
                    EvidenceType.DANGEROUS_PATTERN,
                ],
                min_evidence_count=2,
                fp_penalty=0.16,
                fn_penalty=0.08,
            )
        )
        logger.info("Initialized sink gating configs: %s", len(self.sinks))

    def register_sink(self, gating_config: SinkSpecificGating) -> None:
        if gating_config.sink_name in self.sinks:
            return
        self.sinks[gating_config.sink_name] = gating_config

    def evaluate_vulnerability(
        self,
        sink_name: str,
        evidence: List[EvidenceInstance],
        is_direct_flow: bool = False,
    ) -> Tuple[float, bool, Dict[str, object]]:
        gating_config = self.sinks.get(sink_name)
        if not gating_config:
            return 0.5, False, {"reason": "unknown_sink", "sink_name": sink_name}

        if not self._meets_evidence_requirements(gating_config, evidence):
            return 0.0, False, {
                "reason": "insufficient_evidence",
                "required": gating_config.min_evidence_count,
                "collected": len(evidence),
            }

        base_confidence = self._calculate_evidence_confidence(gating_config, evidence)
        adjusted_confidence = self._apply_flow_multiplier(base_confidence, is_direct_flow)
        final_confidence = self._apply_sink_adjustments(adjusted_confidence, evidence, gating_config)

        threshold = (
            gating_config.direct_flow_threshold
            if is_direct_flow
            else gating_config.indirect_flow_threshold
        )
        passes_gate = final_confidence >= threshold

        return final_confidence, passes_gate, {
            "sink_name": sink_name,
            "cwe_id": gating_config.cwe_id,
            "base_confidence": float(base_confidence),
            "adjusted_confidence": float(adjusted_confidence),
            "final_confidence": float(final_confidence),
            "threshold": float(threshold),
            "passes_gate": passes_gate,
            "flow_type": "direct" if is_direct_flow else "indirect",
            "evidence_count": len(evidence),
            "evidence_breakdown": [e.to_dict() for e in evidence],
        }

    def _meets_evidence_requirements(
        self,
        gating_config: SinkSpecificGating,
        evidence: List[EvidenceInstance],
    ) -> bool:
        if len(evidence) < gating_config.min_evidence_count:
            return False
        evidence_types = {e.evidence_type for e in evidence}
        required = set(gating_config.required_evidence_types)
        return required.issubset(evidence_types)

    def _calculate_evidence_confidence(
        self,
        gating_config: SinkSpecificGating,
        evidence: List[EvidenceInstance],
    ) -> float:
        total_weight = 0.0
        weighted_sum = 0.0
        for item in evidence:
            weight = gating_config.evidence_weight_override.get(
                item.evidence_type,
                self._get_default_weight(item.evidence_type),
            )
            weighted_sum += weight * item.confidence_score
            total_weight += weight
        if total_weight == 0.0:
            return 0.0
        return weighted_sum / total_weight

    def _get_default_weight(self, evidence_type: EvidenceType) -> float:
        if self.evidence_weights and isinstance(self.evidence_weights, dict):
            ev_cfg = self.evidence_weights.get(evidence_type.name)
            if isinstance(ev_cfg, dict) and "default_weight" in ev_cfg:
                try:
                    return float(ev_cfg["default_weight"])
                except Exception:
                    pass
        return float(evidence_type.value["weight"])

    def _apply_flow_multiplier(self, base_confidence: float, is_direct_flow: bool) -> float:
        if is_direct_flow:
            multiplier = self.calibration.get("direct_flow_boost", 1.05)
        else:
            multiplier = self.calibration.get("indirect_flow_penalty", 0.95)
        adjusted = base_confidence * multiplier
        return min(1.0, max(0.0, adjusted))

    def _apply_sink_adjustments(
        self,
        confidence: float,
        evidence: List[EvidenceInstance],
        gating_config: SinkSpecificGating,
    ) -> float:
        adjusted = confidence
        evidence_types = {e.evidence_type for e in evidence}
        if EvidenceType.MULTIPLE_PATHS in evidence_types:
            adjusted *= self.calibration.get("multiple_path_multiplier", 1.10)
        if EvidenceType.DANGEROUS_PATTERN in evidence_types:
            adjusted *= self.calibration.get("dangerous_pattern_multiplier", 1.08)
        if EvidenceType.WEAK_VALIDATION in evidence_types or EvidenceType.INEFFECTIVE_SANITIZER in evidence_types:
            adjusted *= self.calibration.get("weak_validation_penalty", 0.85)
            adjusted -= gating_config.fp_penalty
        return min(1.0, max(0.0, adjusted))

    def get_sink_config(self, sink_name: str) -> Optional[SinkSpecificGating]:
        return self.sinks.get(sink_name)

    def list_sinks(self) -> List[str]:
        return list(self.sinks.keys())

    def export_configuration(self) -> Dict[str, Dict[str, object]]:
        return {name: cfg.to_dict() for name, cfg in self.sinks.items()}


class AdaptiveThresholdCalculator:
    """Calculate adaptive thresholds based on target FP/FN rates."""

    def calculate_adaptive_threshold(
        self,
        sink_type: str,
        target_fp_rate: float = 0.05,
        target_fn_rate: float = 0.10,
    ) -> float:
        base_rates = {
            "sql_injection": 0.75,
            "xss": 0.70,
            "command_injection": 0.80,
            "path_traversal": 0.72,
            "ldap_injection": 0.70,
            "xxe": 0.70,
        }
        base_threshold = base_rates.get(sink_type, 0.70)
        fp_adjustment = -0.05 if target_fp_rate < 0.05 else 0.0
        fn_adjustment = 0.05 if target_fn_rate < 0.10 else 0.0
        threshold = base_threshold + fp_adjustment + fn_adjustment
        return max(0.0, min(1.0, threshold))
