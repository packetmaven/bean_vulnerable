"""
CESCL Inference Integration for IntegratedGNNFramework

This module provides prototype-based CESCL scoring for inference.
It is designed to be integrated into the existing IntegratedGNNFramework
without requiring a full rewrite of that file.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import torch

from .prototype_extractor import PrototypeExtractor, PrototypeScorer

LOG = logging.getLogger(__name__)


class CESCLInferenceModule:
    """
    Self-contained module for CESCL-based prototype scoring at inference.

    Lifecycle:
    1. Instantiate (no args needed)
    2. Call load_from_checkpoint() after loading model weights
    3. Call is_available() to check if prototypes were found
    4. Call score() for each inference sample
    5. Call score_batch() for batched inference
    """

    def __init__(self):
        self._scorer: Optional[PrototypeScorer] = None
        self._prototypes: Optional[Dict] = None
        self._available: bool = False
        self._cescl_config: Dict = {}

    def is_available(self) -> bool:
        return self._available

    def load_from_checkpoint(
        self,
        checkpoint: Dict,
        device: torch.device,
        temperature: Optional[float] = None,
        blend_weight: float = 0.3,
    ) -> bool:
        prototypes = checkpoint.get("class_prototypes", None) if isinstance(checkpoint, dict) else None
        if prototypes is None:
            LOG.info(
                "No class_prototypes found in checkpoint. CESCL inference DISABLED. "
                "Run `python -m src.core.prototype_extractor --checkpoint ... --data ...`."
            )
            self._available = False
            return False

        self._cescl_config = checkpoint.get("cescl_config", {}) if isinstance(checkpoint, dict) else {}
        if temperature is None:
            temperature = float(self._cescl_config.get("temperature", 0.07))

        # Move tensors to device
        for class_id in prototypes["centroids"]:
            prototypes["centroids"][class_id] = prototypes["centroids"][class_id].to(device)
        if "global_mean" in prototypes:
            prototypes["global_mean"] = prototypes["global_mean"].to(device)

        self._prototypes = prototypes
        self._scorer = PrototypeScorer(
            prototypes=prototypes,
            device=device,
            temperature=temperature,
            blend_weight=blend_weight,
        )
        self._available = True
        LOG.info(
            "CESCL inference ENABLED: %d prototypes loaded, tau=%.3f, blend=%.2f",
            len(prototypes["centroids"]),
            float(temperature),
            float(blend_weight),
        )
        return True

    def load_from_file(
        self,
        prototype_path: Path,
        device: torch.device,
        temperature: float = 0.07,
        blend_weight: float = 0.3,
    ) -> bool:
        try:
            prototypes = PrototypeExtractor.load(prototype_path, device)
        except Exception as e:
            LOG.error("Failed to load prototypes from %s: %s", prototype_path, e)
            self._available = False
            return False

        self._prototypes = prototypes
        self._scorer = PrototypeScorer(
            prototypes=prototypes,
            device=device,
            temperature=temperature,
            blend_weight=blend_weight,
        )
        self._available = True
        LOG.info("CESCL inference ENABLED from %s", prototype_path)
        return True

    def score(self, embedding: torch.Tensor, logit_probs: Optional[torch.Tensor] = None) -> Dict:
        if not self._available or self._scorer is None:
            raise RuntimeError("CESCL inference not available. Call load_from_checkpoint() first.")
        return self._scorer.score(embedding, logit_probs)

    def score_batch(
        self, embeddings: torch.Tensor, logit_probs: Optional[torch.Tensor] = None
    ) -> List[Dict]:
        if not self._available or self._scorer is None:
            raise RuntimeError("CESCL inference not available.")
        return self._scorer.score_batch(embeddings, logit_probs)

    def get_ood_threshold(self, percentile: float = 95.0) -> float:
        if self._prototypes is None:
            return float("inf")

        thresholds: List[float] = []
        z = {90.0: 1.282, 95.0: 1.645, 99.0: 2.326}.get(percentile, 1.645)
        for cid in self._prototypes["centroids"]:
            r = float(self._prototypes["radii"].get(cid, 0.0))
            s = float(self._prototypes["stds"].get(cid, 0.0))
            thresholds.append(r + z * s)

        global_std = float(self._prototypes.get("global_std", 1.0))
        ood_threshold = max(thresholds) / max(global_std, 1e-6) if thresholds else float("inf")
        LOG.info("OOD threshold (%.0fth pct): %.4f", percentile, ood_threshold)
        return ood_threshold

    def enrich_vulnerability_result(
        self,
        result: Dict,
        embedding: torch.Tensor,
        logit_probs: torch.Tensor,
    ) -> Dict:
        """
        Enrich an existing result dict with CESCL prototype scores.

        - Preserves existing confidence in `confidence_logit_only`
        - Overwrites `confidence` with blended predicted-class probability when possible
        """
        if not self._available:
            result["cescl_available"] = False
            return result

        scores = self.score(embedding, logit_probs)

        result["cescl_available"] = True
        result["cescl_prototype_probs"] = scores["prototype_probs"]
        result["cescl_distances"] = scores["prototype_distances"]
        result["cescl_ood_score"] = scores["ood_score"]
        result["cescl_calibrated_confidence"] = scores["calibrated_confidence"]

        if "blended_probs" in scores:
            result["cescl_blended_probs"] = scores["blended_probs"]
            if "confidence_logit_only" not in result:
                result["confidence_logit_only"] = result.get("confidence", 0.0)

            # Update confidence to blended probability for predicted class
            is_vuln = result.get("is_vulnerable")
            if isinstance(is_vuln, bool):
                chosen_class = 1 if is_vuln else 0
            else:
                chosen_class = int(scores.get("predicted_class_blended", scores.get("predicted_class", 1)))
            blended = scores["blended_probs"]
            if chosen_class in blended:
                result["confidence"] = float(blended[chosen_class])

        ood_threshold = self.get_ood_threshold(percentile=95.0)
        result["cescl_is_ood"] = float(scores["ood_score"]) > float(ood_threshold)
        return result

