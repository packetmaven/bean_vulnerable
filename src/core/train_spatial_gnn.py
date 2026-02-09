"""
Train Spatial GNN for Java Vulnerability Detection

Research Foundation:
- Devign (NeurIPS 2019): Multi-class vulnerability detection with GNNs
- IVDetect (ASE 2021): Graph-based vulnerability detection
- LineVul (MSR 2022): Statement-level vulnerability detection
- CESCL (NAACL-SRW 2025): Cluster-Enhanced Supervised Contrastive Learning

Fixes applied:
- Issue A: Proper CESCLLoss module wired in (cluster-tightening always active)
- Issue B: Consistent combined loss between train and validation

Training Strategy:
1. Use Juliet Test Suite + Real-world CVE dataset
2. CESCL loss with PROPER cluster-tightening via CESCLLoss module
3. Class weighting for imbalanced data (injected by train_model.py)
4. Model checkpointing on consistent combined objective
5. Reproducible with fixed seeds
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import torch
import torch.nn as nn
from torch_geometric.loader import DataLoader
from tqdm import tqdm

# Import spatial GNN model
from .spatial_gnn_enhanced import TORCH_GEOMETRIC_AVAILABLE, create_spatial_gnn_model

# Calibration + confidence-fusion integration (additive)
from .integration_calibration_into_trainer import CalibrationMixin

# Proper CESCLLoss module with cluster-tightening (Issue A)
from .losses.cescl import CESCLLoss

if not TORCH_GEOMETRIC_AVAILABLE:
    raise ImportError(
        "PyTorch Geometric is required for training. "
        "Install with: pip install torch-geometric torch-scatter torch-sparse"
    )


@dataclass
class LossConfig:
    """
    Single source of truth for loss coefficients.

    Used by BOTH train_epoch() and validate() to guarantee identical
    objective functions across phases.

    Combined loss:
        L = lambda_binary * L_bin
          + lambda_multiclass * L_multi
          + lambda_cescl * L_CESCL

    where L_CESCL = L_contrastive + alpha_cluster * L_cluster
    (computed internally by CESCLLoss module).

    Issue B fix: Before this dataclass, train used lambda_cescl=0.5
    but validation used lambda_cescl=0.0 (CESCL dropped entirely).
    Now both phases use the same LossConfig instance.
    """

    lambda_binary: float = 1.0
    lambda_multiclass: float = 1.0
    lambda_cescl: float = 0.5

    def compute_combined_loss(
        self,
        binary_loss: torch.Tensor,
        multiclass_loss: torch.Tensor,
        cescl_total_loss: torch.Tensor,
    ) -> torch.Tensor:
        """
        Compute combined loss using consistent coefficients.

        This method is the SINGLE codepath for loss combination,
        called by both train_epoch() and validate().
        """
        return (
            self.lambda_binary * binary_loss
            + self.lambda_multiclass * multiclass_loss
            + self.lambda_cescl * cescl_total_loss
        )

    def describe(self) -> str:
        return (
            f"lambda_binary={self.lambda_binary}, "
            f"lambda_multiclass={self.lambda_multiclass}, "
            f"lambda_cescl={self.lambda_cescl}"
        )


class SpatialGNNTrainer(CalibrationMixin):
    """
    Trainer for Spatial GNN with CESCL loss and research-backed best practices.

    Fixes from original:
    - Issue A: CESCLLoss module replaces ad-hoc compute_cescl_loss()
    - Issue B: LossConfig ensures identical objective in train and val
    """

    def __init__(
        self,
        model_config: Optional[Dict] = None,
        device: str = "auto",
        random_seed: int = 42,
        loss_config: Optional[LossConfig] = None,
    ):
        """
        Initialize trainer.

        Args:
            model_config: Configuration for spatial GNN model
            device: Device to use ('auto', 'cpu', 'cuda', 'mps')
            random_seed: Random seed for reproducibility
            loss_config: Loss coefficient configuration. If None, uses
                default LossConfig() with lambda_cescl=0.5.
        """
        self.random_seed = random_seed
        self._set_seeds(random_seed)

        self.device = self._setup_device(device)
        self.logger = logging.getLogger(__name__)

        # Default model config
        if model_config is None:
            model_config = {
                "node_dim": 128,
                "hidden_dim": 512,
                "num_vulnerability_types": 24,
                "num_edge_types": 13,
                "num_layers": 4,
                "num_attention_heads": 8,
                "use_codebert": True,
                "use_hierarchical_pooling": True,
                "enable_attention_visualization": True,
                "enable_counterfactual_analysis": True,
            }
        # Persist model config for checkpointing/prototype extraction (Issue E)
        self.model_config: Dict = dict(model_config)

        self.model = create_spatial_gnn_model(model_config)
        self.model = self.model.to(self.device)

        # Training hyperparameters
        self.learning_rate = 0.001
        self.weight_decay = 5e-4
        self.num_epochs = 100
        self.batch_size = 32
        self.early_stopping_patience = 10

        # ====================================================================
        # CESCL parameters (aligned with NAACL-SRW 2025)
        # ====================================================================
        self.cescl_temperature = 0.07
        self.cescl_cluster_weight = 0.5

        self.cescl_loss_fn = CESCLLoss(
            temperature=self.cescl_temperature,
            cluster_weight=self.cescl_cluster_weight,
            base_temperature=self.cescl_temperature,
        )
        self.logger.info(
            "CESCLLoss initialized: tau=%.2f, alpha=%.2f",
            self.cescl_temperature,
            self.cescl_cluster_weight,
        )

        # ====================================================================
        # Issue B: LossConfig — single source of truth for coefficients
        # ====================================================================
        self.loss_config = loss_config or LossConfig()
        self.logger.info("LossConfig: %s", self.loss_config.describe())

        # Optimizer and scheduler
        self.optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay,
        )
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer,
            mode="min",
            factor=0.5,
            patience=5,
        )

        # Classification loss functions (replaced by train_model.py with
        # class-weighted versions via Issue C)
        self.binary_criterion = nn.CrossEntropyLoss()
        self.multiclass_criterion = nn.CrossEntropyLoss()

        # Best model tracking
        self.best_val_loss = float("inf")
        self.best_model_path = None
        self.patience_counter = 0

        # Metrics history
        self.train_metrics_history: list = []
        self.val_metrics_history: list = []

    # ------------------------------------------------------------------ seeds
    def _set_seeds(self, seed: int):
        random.seed(seed)
        np.random.seed(seed)
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    # ---------------------------------------------------------------- device
    def _setup_device(self, device: str) -> torch.device:
        if device == "auto":
            if torch.cuda.is_available():
                return torch.device("cuda")
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return torch.device("mps")
            return torch.device("cpu")
        return torch.device(device)

    # ============================================================= _compute
    def _compute_all_losses(
        self, outputs: Dict[str, torch.Tensor], batch
    ) -> Dict[str, torch.Tensor]:
        """
        Compute all loss components from model outputs and batch labels.

        Issue B: This is the SINGLE codepath for loss computation,
        called by BOTH train_epoch() and validate(). Guarantees
        identical objective across phases.

        Args:
            outputs: Model forward-pass outputs dict containing:
                - binary_logits
                - multiclass_logits
                - graph_representation
            batch: PyG batch with y_binary, y_multiclass

        Returns:
            Dict with keys: combined, binary, multiclass,
                            cescl_total, cescl_contrastive, cescl_cluster
        """
        binary_loss = self.binary_criterion(outputs["binary_logits"], batch.y_binary)
        multiclass_loss = self.multiclass_criterion(
            outputs["multiclass_logits"], batch.y_multiclass
        )

        cescl_result = self.cescl_loss_fn(
            features=outputs["graph_representation"],
            labels=batch.y_binary,
            mask=None,
        )
        cescl_total = cescl_result["total_loss"]
        cescl_contrastive = cescl_result["contrastive_loss"]
        cescl_cluster = cescl_result["cluster_loss"]

        combined = self.loss_config.compute_combined_loss(
            binary_loss, multiclass_loss, cescl_total
        )

        return {
            "combined": combined,
            "binary": binary_loss,
            "multiclass": multiclass_loss,
            "cescl_total": cescl_total,
            "cescl_contrastive": cescl_contrastive,
            "cescl_cluster": cescl_cluster,
        }

    # --------------------------------------------------------------- train
    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """
        Train for one epoch.

        Returns dict with: loss, binary_loss, multiclass_loss,
            cescl_loss, cescl_contrastive, cescl_cluster
        """
        self.model.train()

        accum = {
            "loss": 0.0,
            "binary_loss": 0.0,
            "multiclass_loss": 0.0,
            "cescl_loss": 0.0,
            "cescl_contrastive": 0.0,
            "cescl_cluster": 0.0,
        }
        num_batches = 0

        for batch in tqdm(train_loader, desc="Training"):
            batch = batch.to(self.device)

            self.optimizer.zero_grad()
            outputs = self.model(
                x=batch.x,
                edge_index=batch.edge_index,
                edge_type=batch.edge_type,
                batch=batch.batch,
            )

            # Issue B: Use shared _compute_all_losses
            losses = self._compute_all_losses(outputs, batch)

            # Diagnostic
            if losses["cescl_cluster"].item() == 0.0 and batch.y_binary.size(0) > 2:
                self.logger.debug("Cluster loss zero for batch size %d", batch.y_binary.size(0))

            losses["combined"].backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()

            accum["loss"] += losses["combined"].item()
            accum["binary_loss"] += losses["binary"].item()
            accum["multiclass_loss"] += losses["multiclass"].item()
            accum["cescl_loss"] += losses["cescl_total"].item()
            accum["cescl_contrastive"] += losses["cescl_contrastive"].item()
            accum["cescl_cluster"] += losses["cescl_cluster"].item()
            num_batches += 1

        metrics = {k: v / num_batches for k, v in accum.items()}
        self.train_metrics_history.append(metrics)
        return metrics

    # ------------------------------------------------------------ validate
    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """
        Validate the model.

        Issue B FIX: Validation now computes the SAME combined loss as
        training, using self.loss_config and self._compute_all_losses().
        This ensures:
          - scheduler.step() operates on the correct objective
          - best-checkpoint selection reflects the training objective
          - early stopping triggers at the right time
        """
        self.model.eval()
        if len(val_loader) == 0:
            return {
                "loss": 0.0,
                "binary_accuracy": 0.0,
                "multiclass_accuracy": 0.0,
                "binary_loss": 0.0,
                "multiclass_loss": 0.0,
                "cescl_loss": 0.0,
                "cescl_contrastive": 0.0,
                "cescl_cluster": 0.0,
            }

        accum = {
            "loss": 0.0,
            "binary_loss": 0.0,
            "multiclass_loss": 0.0,
            "cescl_loss": 0.0,
            "cescl_contrastive": 0.0,
            "cescl_cluster": 0.0,
        }
        correct_binary = 0
        correct_multiclass = 0
        total_samples = 0

        with torch.no_grad():
            for batch in tqdm(val_loader, desc="Validating"):
                batch = batch.to(self.device)

                outputs = self.model(
                    x=batch.x,
                    edge_index=batch.edge_index,
                    edge_type=batch.edge_type,
                    batch=batch.batch,
                )

                # Issue B: SAME loss computation as train_epoch
                losses = self._compute_all_losses(outputs, batch)

                accum["loss"] += losses["combined"].item()
                accum["binary_loss"] += losses["binary"].item()
                accum["multiclass_loss"] += losses["multiclass"].item()
                accum["cescl_loss"] += losses["cescl_total"].item()
                accum["cescl_contrastive"] += losses["cescl_contrastive"].item()
                accum["cescl_cluster"] += losses["cescl_cluster"].item()

                binary_pred = outputs["binary_logits"].argmax(dim=1)
                correct_binary += (binary_pred == batch.y_binary).sum().item()

                multiclass_pred = outputs["multiclass_logits"].argmax(dim=1)
                correct_multiclass += (multiclass_pred == batch.y_multiclass).sum().item()

                total_samples += batch.y_binary.size(0)

        n = len(val_loader)
        metrics = {k: v / n for k, v in accum.items()}
        metrics["binary_accuracy"] = correct_binary / total_samples
        metrics["multiclass_accuracy"] = correct_multiclass / total_samples

        self.val_metrics_history.append(metrics)
        return metrics

    # --------------------------------------------------------- checkpoint
    def save_checkpoint(self, checkpoint_path: Path, epoch: int, metrics: Dict):
        """Save model checkpoint with full configuration metadata."""
        checkpoint = {
            "epoch": epoch,
            "model_config": self.model_config,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "scheduler_state_dict": self.scheduler.state_dict(),
            "metrics": metrics,
            "random_seed": self.random_seed,
            "cescl_config": {
                "temperature": self.cescl_temperature,
                "cluster_weight": self.cescl_cluster_weight,
                "module": "CESCLLoss",
            },
            "loss_config": {
                "lambda_binary": self.loss_config.lambda_binary,
                "lambda_multiclass": self.loss_config.lambda_multiclass,
                "lambda_cescl": self.loss_config.lambda_cescl,
            },
            "train_metrics_history": self.train_metrics_history,
            "val_metrics_history": self.val_metrics_history,
        }
        torch.save(checkpoint, checkpoint_path)
        self.logger.info("Saved checkpoint to %s", checkpoint_path)

    def load_checkpoint(self, checkpoint_path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        self.scheduler.load_state_dict(checkpoint["scheduler_state_dict"])

        if "cescl_config" in checkpoint:
            cfg = checkpoint["cescl_config"]
            self.logger.info(
                "Loaded CESCL config: tau=%s, alpha=%s",
                cfg.get("temperature"),
                cfg.get("cluster_weight"),
            )

        if "loss_config" in checkpoint:
            lc = checkpoint["loss_config"]
            self.loss_config = LossConfig(
                lambda_binary=lc.get("lambda_binary", 1.0),
                lambda_multiclass=lc.get("lambda_multiclass", 1.0),
                lambda_cescl=lc.get("lambda_cescl", 0.5),
            )
            self.logger.info("Loaded LossConfig: %s", self.loss_config.describe())

        if "train_metrics_history" in checkpoint:
            self.train_metrics_history = checkpoint["train_metrics_history"]
        if "val_metrics_history" in checkpoint:
            self.val_metrics_history = checkpoint["val_metrics_history"]

        self.logger.info("Loaded checkpoint from %s", checkpoint_path)
        return checkpoint

    # --------------------------------------------------------------- train
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        checkpoint_dir: Path,
        num_epochs: Optional[int] = None,
    ):
        """
        Full training loop.

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            checkpoint_dir: Directory to save checkpoints
            num_epochs: Number of epochs (uses self.num_epochs if None)
        """
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        num_epochs = num_epochs or self.num_epochs

        self.logger.info("Starting training on %s", self.device)
        self.logger.info("  Epochs: %d, Batch size: %d", num_epochs, self.batch_size)
        self.logger.info("  LR: %s, Weight decay: %s", self.learning_rate, self.weight_decay)
        self.logger.info(
            "  CESCL: tau=%.3f, alpha=%.2f",
            self.cescl_temperature,
            self.cescl_cluster_weight,
        )
        self.logger.info("  LossConfig: %s", self.loss_config.describe())

        for epoch in range(num_epochs):
            self.logger.info("\nEpoch %d/%d", epoch + 1, num_epochs)

            # ---- Train ----
            tm = self.train_epoch(train_loader)
            self.logger.info(
                "  Train — Loss: %.4f  Bin: %.4f  Multi: %.4f  "
                "CESCL: %.4f [C: %.4f, K: %.4f]",
                tm["loss"],
                tm["binary_loss"],
                tm["multiclass_loss"],
                tm["cescl_loss"],
                tm["cescl_contrastive"],
                tm["cescl_cluster"],
            )

            # ---- Validate ----
            if len(val_loader) == 0:
                self.logger.warning("Validation set empty; using train loss for checkpointing.")
                vm = {
                    "loss": tm["loss"],
                    "binary_accuracy": 0.0,
                    "multiclass_accuracy": 0.0,
                    "binary_loss": tm["binary_loss"],
                    "multiclass_loss": tm["multiclass_loss"],
                    "cescl_loss": tm["cescl_loss"],
                    "cescl_contrastive": tm["cescl_contrastive"],
                    "cescl_cluster": tm["cescl_cluster"],
                }
            else:
                vm = self.validate(val_loader)

            self.logger.info(
                "  Val   — Loss: %.4f  Bin: %.4f  Multi: %.4f  "
                "CESCL: %.4f [C: %.4f, K: %.4f]  "
                "BinAcc: %.4f  MultiAcc: %.4f",
                vm["loss"],
                vm.get("binary_loss", 0),
                vm.get("multiclass_loss", 0),
                vm.get("cescl_loss", 0),
                vm.get("cescl_contrastive", 0),
                vm.get("cescl_cluster", 0),
                vm["binary_accuracy"],
                vm["multiclass_accuracy"],
            )

            # Issue B: scheduler uses the FULL combined val loss
            self.scheduler.step(vm["loss"])

            # Save epoch checkpoint
            cp = checkpoint_dir / f"checkpoint_epoch_{epoch + 1}.pt"
            self.save_checkpoint(cp, epoch + 1, {**tm, **vm})

            # Issue B: early stopping uses the FULL combined val loss
            if vm["loss"] < self.best_val_loss:
                self.best_val_loss = vm["loss"]
                self.best_model_path = checkpoint_dir / "best_model.pt"
                self.save_checkpoint(self.best_model_path, epoch + 1, {**tm, **vm})
                self.patience_counter = 0
                self.logger.info("  New best model saved!")
            else:
                self.patience_counter += 1
                if self.patience_counter >= self.early_stopping_patience:
                    self.logger.info("  Early stopping after %d epochs", epoch + 1)
                    break

        self.logger.info("\nTraining complete! Best model: %s", self.best_model_path)

        # Final CESCL diagnostics
        if self.train_metrics_history:
            window = self.train_metrics_history[-10:]
            avg_cluster = np.mean([m["cescl_cluster"] for m in window])
            avg_contrast = np.mean([m["cescl_contrastive"] for m in window])
            self.logger.info("\nCESCL stats (last %d epochs):", len(window))
            self.logger.info("  Avg contrastive: %.4f", avg_contrast)
            self.logger.info("  Avg cluster:     %.4f", avg_cluster)
            self.logger.info(
                "  Cluster/Contrast ratio: %.3f", avg_cluster / (avg_contrast + 1e-6)
            )

        if self.val_metrics_history:
            window = self.val_metrics_history[-10:]
            avg_val_cescl = np.mean([m.get("cescl_loss", 0) for m in window])
            avg_train_cescl = (
                np.mean([m["cescl_loss"] for m in self.train_metrics_history[-10:]])
                if self.train_metrics_history
                else 0
            )
            self.logger.info("\nTrain/Val CESCL consistency check:")
            self.logger.info("  Avg train CESCL: %.4f", avg_train_cescl)
            self.logger.info("  Avg val CESCL:   %.4f", avg_val_cescl)
            gap = abs(avg_train_cescl - avg_val_cescl)
            if gap > 0.5:
                self.logger.warning(
                    "  Large train/val CESCL gap (%.4f) — possible overfitting", gap
                )


def create_trainer(
    model_config: Optional[Dict] = None,
    device: str = "auto",
    random_seed: int = 42,
    loss_config: Optional[LossConfig] = None,
) -> SpatialGNNTrainer:
    """
    Factory function to create a trainer.

    Args:
        model_config: Model configuration
        device: Training device
        random_seed: Random seed for reproducibility
        loss_config: Loss coefficient configuration

    Returns:
        Configured SpatialGNNTrainer instance
    """
    return SpatialGNNTrainer(
        model_config=model_config,
        device=device,
        random_seed=random_seed,
        loss_config=loss_config,
    )
