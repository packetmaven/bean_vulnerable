#!/usr/bin/env python3
"""
Train Spatial GNN for Java Vulnerability Detection

Fixes applied:
- Issue C: Class-weighted CrossEntropyLoss for imbalanced data
- Issue D: PK Batch Sampler guaranteeing class-balanced batches for CESCL

Usage:
    # 1. Prepare data
    python prepare_training_data.py --input tests/samples --output training_data

    # 2. Train model (recommended: with PK sampling and class weights)
    python train_model.py --data training_data --output models/spatial_gnn --epochs 100

    # 3. Disable PK sampling (for ablation experiments only)
    python train_model.py --data training_data --output models/spatial_gnn --no-pk-sampler

    # 4. Disable class weights (for ablation experiments only)
    python train_model.py --data training_data --output models/spatial_gnn --no-class-weights
"""

import argparse
import json
import logging
from collections import Counter
from pathlib import Path
import pickle

import torch
from torch_geometric.loader import DataLoader

from src.core.train_spatial_gnn import create_trainer
from src.core.pk_batch_sampler import PKBatchSampler

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


# ======================================================================
# Issue C: Class weight computation
# ======================================================================


def compute_class_weights(
    train_data,
    num_binary_classes: int = 2,
    num_multiclass_classes: int = 24,
):
    """
    Compute inverse-frequency class weights for imbalanced datasets.

    Formula: w_i = N / (C * n_i)
    where N = total samples, C = number of classes, n_i = samples in class i.

    Weights are normalized so that the mean of non-zero weights equals 1.0,
    which preserves loss magnitude relative to unweighted training.

    Args:
        train_data: List of PyTorch Geometric Data objects
        num_binary_classes: Number of binary classes (2: safe/vulnerable)
        num_multiclass_classes: Number of vulnerability type classes (24)

    Returns:
        Tuple of (binary_weights, multiclass_weights) as torch.Tensors
    """
    LOG.info("Computing class weights from training data...")

    binary_counts: Counter = Counter()
    multiclass_counts: Counter = Counter()

    for data in train_data:
        b = int(data.y_binary.item() if hasattr(data.y_binary, "item") else data.y_binary)
        m = int(
            data.y_multiclass.item()
            if hasattr(data.y_multiclass, "item")
            else data.y_multiclass
        )
        binary_counts[b] += 1
        multiclass_counts[m] += 1

    total = len(train_data)

    # ---- Binary weights ----
    LOG.info("Binary class distribution:")
    binary_weights = []
    for cls_id in range(num_binary_classes):
        count = binary_counts.get(cls_id, 0)
        pct = (count / total) * 100 if total > 0 else 0.0
        cls_name = "Safe" if cls_id == 0 else "Vulnerable"
        LOG.info(f"  Class {cls_id} ({cls_name}): {count} ({pct:.1f}%)")
        # For absent classes, keep 0.0 for now; we'll set a neutral weight later
        # to avoid NaNs during evaluation when a split contains unseen labels.
        binary_weights.append(total / (num_binary_classes * max(count, 1)) if count > 0 else 0.0)

    binary_weights = torch.tensor(binary_weights, dtype=torch.float32)
    nonzero_bin = binary_weights > 0
    if nonzero_bin.sum() > 0:
        binary_weights[nonzero_bin] = binary_weights[nonzero_bin] / binary_weights[nonzero_bin].mean()
    zero_bin = ~nonzero_bin
    if zero_bin.any():
        LOG.warning(
            "%d binary labels have zero samples; using neutral weight=1.0 for them",
            int(zero_bin.sum().item()),
        )
        binary_weights[zero_bin] = 1.0

    # ---- Multiclass weights ----
    LOG.info("Multiclass distribution (non-zero classes):")
    multiclass_weights = []
    for cls_id in range(num_multiclass_classes):
        count = multiclass_counts.get(cls_id, 0)
        if count > 0:
            w = total / (num_multiclass_classes * count)
            LOG.info(f"  Class {cls_id}: {count} samples")
        else:
            w = 0.0
        multiclass_weights.append(w)

    multiclass_weights = torch.tensor(multiclass_weights, dtype=torch.float32)
    nonzero = multiclass_weights > 0
    if nonzero.sum() > 0:
        multiclass_weights[nonzero] = multiclass_weights[nonzero] / multiclass_weights[
            nonzero
        ].mean()

    zero_mask = multiclass_weights == 0
    zero_classes = int(zero_mask.sum().item())
    if zero_classes > 0:
        LOG.warning("%d multiclass labels have zero samples (weight = 0.0)", zero_classes)
        # Critical: if a validation/test split contains classes unseen in training,
        # CrossEntropyLoss with reduction='mean' can become 0/0 => NaN for batches
        # where all targets have weight=0. Assign a neutral weight instead.
        multiclass_weights[zero_mask] = 1.0

    # Sanity checks
    assert torch.all(torch.isfinite(binary_weights)), "NaN/Inf in binary weights"
    assert torch.all(torch.isfinite(multiclass_weights)), "NaN/Inf in multi weights"
    assert binary_weights.sum() > 0, "All binary weights are zero"
    assert multiclass_weights.sum() > 0, "All multiclass weights are zero"

    LOG.info(
        "Binary imbalance ratio: %.2f:1",
        (binary_weights.max() / binary_weights.min()).item(),
    )
    nz = multiclass_weights[multiclass_weights > 0]
    if len(nz) > 1:
        LOG.info(
            "Multiclass imbalance ratio: %.2f:1",
            (nz.max() / nz.min()).item(),
        )

    return binary_weights, multiclass_weights


# ======================================================================
# Dataset loading
# ======================================================================


def load_dataset(data_dir: Path, split: str):
    """Load dataset from pickle file."""
    pkl_path = data_dir / f"{split}.pkl"
    if not pkl_path.exists():
        raise FileNotFoundError(f"Dataset not found: {pkl_path}")

    with open(pkl_path, "rb") as f:
        data = pickle.load(f)

    LOG.info(f"Loaded {len(data)} samples from {pkl_path}")
    return data


# ======================================================================
# Main
# ======================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Train Spatial GNN for Java vulnerability detection"
    )
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Training data directory (output of prepare_training_data.py)",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output directory for model checkpoints",
    )
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument(
        "--device",
        type=str,
        default="auto",
        help="Device: auto, cpu, cuda, mps",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--no-class-weights",
        action="store_true",
        help="Disable class weighting (not recommended)",
    )
    parser.add_argument(
        "--no-pk-sampler",
        action="store_true",
        help="Disable PK batch sampling (not recommended for CESCL)",
    )
    parser.add_argument(
        "--no-calibration",
        action="store_true",
        help="Disable calibration monitoring + fusion gate (not recommended)",
    )
    parser.add_argument(
        "--calibration-check-every",
        type=int,
        default=10,
        help="Run lightweight ECE calibration check every N epochs",
    )
    parser.add_argument(
        "--calibration-threshold",
        type=float,
        default=0.10,
        help="ECE threshold for PASS/FAIL in post-training calibration report",
    )
    parser.add_argument(
        "--pk-k",
        type=int,
        default=None,
        help="Samples per class per batch (default: batch_size // 2)",
    )

    args = parser.parse_args()

    data_dir = Path(args.data)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    LOG.info("=" * 70)
    LOG.info("Spatial GNN Training for Java Vulnerability Detection")
    LOG.info("=" * 70)
    LOG.info(f"Data:        {data_dir}")
    LOG.info(f"Output:      {output_dir}")
    LOG.info(f"Epochs:      {args.epochs}")
    LOG.info(f"Batch size:  {args.batch_size}")
    LOG.info(f"LR:          {args.lr}")
    LOG.info(f"Device:      {args.device}")
    LOG.info(f"Seed:        {args.seed}")
    LOG.info(f"Class wts:   {'OFF' if args.no_class_weights else 'ON'}")
    LOG.info(f"PK sampler:  {'OFF' if args.no_pk_sampler else 'ON'}")
    LOG.info("=" * 70)

    # ---- Load datasets ----
    LOG.info("\nLoading datasets...")
    train_data = load_dataset(data_dir, "train")
    val_data = load_dataset(data_dir, "val")
    test_data = load_dataset(data_dir, "test")

    # ---- Issue C: Compute class weights ----
    if not args.no_class_weights:
        binary_weights, multiclass_weights = compute_class_weights(train_data)
    else:
        LOG.warning("Class weighting DISABLED")
        binary_weights = None
        multiclass_weights = None

    # ================================================================
    # Issue D: PK Batch Sampler for training
    # ================================================================
    if not args.no_pk_sampler:
        # Extract binary labels for the sampler
        train_labels = []
        for data in train_data:
            lbl = int(data.y_binary.item() if hasattr(data.y_binary, "item") else data.y_binary)
            train_labels.append(lbl)

        # Determine K: samples per class per batch
        # Total batch = P * K where P = 2 (binary)
        pk_k = args.pk_k if args.pk_k is not None else args.batch_size // 2
        pk_k = max(2, pk_k)  # At least 2 per class for contrastive loss

        pk_sampler = PKBatchSampler(
            labels=train_labels,
            p=2,  # Binary: safe + vulnerable
            k=pk_k,
            seed=args.seed,
            drop_last=True,
        )

        # Log sampler statistics
        stats = pk_sampler.get_stats()
        LOG.info("\nPK Batch Sampler configured:")
        LOG.info(f"  P (classes/batch):    {stats['p']}")
        LOG.info(f"  K (samples/class):    {stats['k']}")
        LOG.info(f"  Effective batch size: {stats['batch_size']}")
        LOG.info(f"  Batches per epoch:    {stats['num_batches']}")
        LOG.info(f"  Class sizes:          {stats['class_sizes']}")
        LOG.info(f"  Imbalance ratio:      {stats['imbalance_ratio']:.2f}:1")
        LOG.info(f"  Minority oversampled: {stats['minority_oversampled']}")
        LOG.info(
            f"  Samples per epoch:    {stats['total_samples_per_epoch']} "
            f"(vs {len(train_data)} unique)"
        )

        # Create DataLoader with PK sampler
        # NOTE: batch_sampler is mutually exclusive with
        #       batch_size, shuffle, sampler, and drop_last.
        train_loader = DataLoader(train_data, batch_sampler=pk_sampler)

        # Update effective batch size for trainer metadata
        effective_batch_size = pk_sampler.batch_size
    else:
        LOG.warning(
            "PK sampling DISABLED -- batches may lack class diversity. "
            "CESCL contrastive loss may degenerate on homogeneous batches."
        )
        train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
        effective_batch_size = args.batch_size

    # Val and test loaders use standard sequential loading (no PK needed)
    val_loader = DataLoader(val_data, batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)

    LOG.info("\nData loaders ready:")
    LOG.info(f"  Train batches: {len(train_loader)}")
    LOG.info(f"  Val batches:   {len(val_loader)}")
    LOG.info(f"  Test batches:  {len(test_loader)}")

    # ---- Create trainer ----
    LOG.info("\nCreating trainer...")

    # Infer schema from loaded graphs (prevents edge-type embedding mismatches)
    all_graphs = list(train_data) + list(val_data) + list(test_data)
    inferred_node_dim = 128
    if len(train_data) > 0 and hasattr(train_data[0], "x") and train_data[0].x is not None:
        try:
            inferred_node_dim = int(train_data[0].x.size(-1))
        except Exception:
            inferred_node_dim = 128

    inferred_num_edge_types = 1
    max_edge_type = -1
    for g in all_graphs:
        if not hasattr(g, "edge_type"):
            continue
        et = getattr(g, "edge_type")
        if et is None:
            continue
        try:
            et_max = int(et.max().item())
        except Exception:
            try:
                et_max = int(max(et))
            except Exception:
                continue
        max_edge_type = max(max_edge_type, et_max)
    if max_edge_type >= 0:
        inferred_num_edge_types = max_edge_type + 1

    LOG.info(
        "Inferred graph schema: node_dim=%d, num_edge_types=%d",
        inferred_node_dim,
        inferred_num_edge_types,
    )

    model_config = {
        "node_dim": inferred_node_dim,
        "hidden_dim": 256,
        "num_vulnerability_types": 24,
        "num_edge_types": inferred_num_edge_types,
        "num_layers": 3,
        # Training defaults: keep the model lightweight + avoid HF downloads.
        # You can re-enable later if you also pass node_tokens through the trainer.
        "use_codebert": False,
        "use_hierarchical_pooling": True,
    }

    trainer = create_trainer(
        model_config=model_config,
        device=args.device,
        random_seed=args.seed,
    )

    trainer.learning_rate = args.lr
    trainer.num_epochs = args.epochs
    trainer.batch_size = effective_batch_size

    # ---- Issue C: Inject class weights ----
    if not args.no_class_weights:
        LOG.info("Injecting class-weighted loss functions...")
        bw = binary_weights.to(trainer.device)
        mw = multiclass_weights.to(trainer.device)
        trainer.binary_criterion = torch.nn.CrossEntropyLoss(weight=bw)
        trainer.multiclass_criterion = torch.nn.CrossEntropyLoss(weight=mw)
        LOG.info("  Binary CE:     weighted")
        LOG.info("  Multiclass CE: weighted")

    # Recreate optimizer with user-specified LR
    trainer.optimizer = torch.optim.Adam(
        trainer.model.parameters(),
        lr=trainer.learning_rate,
        weight_decay=trainer.weight_decay,
    )
    trainer.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        trainer.optimizer,
        mode="min",
        factor=0.5,
        patience=5,
    )

    LOG.info(f"Trainer ready on {trainer.device}")

    # ---- Train ----
    LOG.info("\nStarting training...")
    train_with_calibration_results = None
    if not args.no_calibration and hasattr(trainer, "train_with_calibration"):
        train_with_calibration_results = trainer.train_with_calibration(
            train_loader=train_loader,
            val_loader=val_loader,
            checkpoint_dir=output_dir,
            num_epochs=args.epochs,
            calibration_check_every=args.calibration_check_every,
            calibration_threshold=args.calibration_threshold,
        )
    else:
        trainer.train(
            train_loader=train_loader,
            val_loader=val_loader,
            checkpoint_dir=output_dir,
            num_epochs=args.epochs,
        )

    # Prefer evaluating the BEST checkpoint (not last epoch)
    if getattr(trainer, "best_model_path", None):
        try:
            trainer.load_checkpoint(Path(trainer.best_model_path))
        except Exception as e:
            LOG.warning("Failed to load best checkpoint for testing: %s", e)

    # ---- Test ----
    LOG.info("\nTesting final model...")
    test_metrics = trainer.validate(test_loader)
    LOG.info(f"Test Loss:            {test_metrics['loss']:.4f}")
    LOG.info(f"Test Binary Acc:      {test_metrics['binary_accuracy']:.4f}")
    LOG.info(f"Test Multiclass Acc:  {test_metrics['multiclass_accuracy']:.4f}")

    # ---- Save results ----
    results = {
        "test_metrics": test_metrics,
        "training_config": {
            "epochs": args.epochs,
            "batch_size": effective_batch_size,
            "learning_rate": args.lr,
            "device": str(trainer.device),
            "random_seed": args.seed,
            "class_weighting": not args.no_class_weights,
            "pk_sampling": not args.no_pk_sampler,
            "calibration_monitoring": not args.no_calibration,
            "calibration_check_every": args.calibration_check_every,
            "calibration_threshold": args.calibration_threshold,
        },
    }

    if train_with_calibration_results is not None:
        results["calibration"] = train_with_calibration_results.get("calibration")
        results["fusion_valid"] = train_with_calibration_results.get("fusion_valid")
        results["best_epoch"] = train_with_calibration_results.get("best_epoch")
        results["best_val_loss"] = train_with_calibration_results.get("best_val_loss")

    if not args.no_class_weights:
        results["class_weights"] = {
            "binary": binary_weights.tolist(),
            "multiclass": multiclass_weights.tolist(),
        }

    if not args.no_pk_sampler:
        results["pk_sampler"] = pk_sampler.get_stats()
        # Convert class_sizes keys to strings for JSON
        results["pk_sampler"]["class_sizes"] = {
            str(k): v for k, v in results["pk_sampler"]["class_sizes"].items()
        }

    with open(output_dir / "test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    LOG.info("\nTraining complete!")
    LOG.info(f"  Best model:    {trainer.best_model_path}")
    LOG.info(f"  Test results:  {output_dir / 'test_results.json'}")


if __name__ == "__main__":
    main()

