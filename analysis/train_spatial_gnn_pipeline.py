#!/usr/bin/env python3
"""
Reproducible Spatial GNN training pipeline.

Steps:
1) Prepare training data (Joern CPG -> PyG Data)
2) Train Spatial GNN and save checkpoints
"""
from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
from pathlib import Path
from typing import Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from prepare_training_data import prepare_dataset  # noqa: E402
from src.core.train_spatial_gnn import create_trainer  # noqa: E402


DEFAULT_MODEL_CONFIG: Dict[str, Any] = {
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


def _load_pickle(path: Path):
    with path.open("rb") as handle:
        return pickle.load(handle)


def _load_model_config(path: Optional[Path]) -> Dict[str, Any]:
    config = dict(DEFAULT_MODEL_CONFIG)
    if path is None:
        return config
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Model config must be a JSON object")
    config.update(payload)
    return config


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    parser = argparse.ArgumentParser(description="Spatial GNN training pipeline")
    parser.add_argument(
        "--input",
        type=Path,
        default=REPO_ROOT / "tests" / "samples",
        help="Input directory with Java files (default: tests/samples)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=REPO_ROOT / "training_data",
        help="Output directory for prepared data",
    )
    parser.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=REPO_ROOT / "checkpoints" / "spatial_gnn",
        help="Directory to save checkpoints",
    )
    parser.add_argument("--epochs", type=int, default=5, help="Training epochs (default: 5)")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size (default: 8)")
    parser.add_argument("--device", default="auto", help="Device: auto/cpu/cuda/mps")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of files (0 = no limit)")
    parser.add_argument("--joern-timeout", type=int, default=480, help="Joern timeout in seconds")
    parser.add_argument("--prepare-only", action="store_true", help="Only prepare training data")
    parser.add_argument("--train-only", action="store_true", help="Only train using existing data")
    parser.add_argument("--config-json", type=Path, help="Optional JSON model config override")
    args = parser.parse_args()

    if args.prepare_only and args.train_only:
        raise SystemExit("Choose only one of --prepare-only or --train-only")

    if not args.train_only:
        prepare_dataset(
            input_dir=args.input,
            output_dir=args.data_dir,
            train_split=0.7,
            val_split=0.15,
            test_split=0.15,
            timeout=args.joern_timeout,
            limit=args.limit if args.limit > 0 else None,
            seed=args.seed,
        )

    if args.prepare_only:
        return 0

    train_path = args.data_dir / "train.pkl"
    val_path = args.data_dir / "val.pkl"
    test_path = args.data_dir / "test.pkl"

    if not train_path.exists() or not val_path.exists():
        raise SystemExit(f"Missing prepared data in {args.data_dir}. Run with --prepare-only first.")

    train_data = _load_pickle(train_path)
    val_data = _load_pickle(val_path)
    test_data = _load_pickle(test_path) if test_path.exists() else []

    if not train_data:
        raise SystemExit("No training samples found after preparation.")

    try:
        from torch_geometric.loader import DataLoader
    except Exception as exc:
        raise SystemExit(f"PyTorch Geometric missing: {exc}")

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=args.batch_size, shuffle=False)

    model_config = _load_model_config(args.config_json)
    trainer = create_trainer(model_config=model_config, device=args.device, random_seed=args.seed)
    trainer.batch_size = args.batch_size

    args.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    trainer.train(train_loader, val_loader, args.checkpoint_dir, num_epochs=args.epochs)

    test_metrics = None
    if test_data:
        test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)
        test_metrics = trainer.validate(test_loader)

    summary = {
        "input_dir": str(args.input),
        "data_dir": str(args.data_dir),
        "checkpoint_dir": str(args.checkpoint_dir),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "device": str(trainer.device),
        "seed": args.seed,
        "num_train": len(train_data),
        "num_val": len(val_data),
        "num_test": len(test_data),
        "model_config": model_config,
        "best_model_path": str(trainer.best_model_path) if trainer.best_model_path else None,
        "test_metrics": test_metrics,
    }
    (args.checkpoint_dir / "training_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
