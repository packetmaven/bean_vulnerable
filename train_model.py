#!/usr/bin/env python3
"""
Train Spatial GNN for Java Vulnerability Detection

Usage:
    # 1. Prepare data
    python prepare_training_data.py --input tests/samples --output training_data
    
    # 2. Train model
    python train_model.py --data training_data --output models/spatial_gnn --epochs 100
"""

import argparse
import logging
from pathlib import Path
import pickle
import torch
from torch_geometric.loader import DataLoader
from src.core.train_spatial_gnn import create_trainer

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOG = logging.getLogger(__name__)


def load_dataset(data_dir: Path, split: str):
    """Load dataset from pickle file"""
    pkl_path = data_dir / f"{split}.pkl"
    if not pkl_path.exists():
        raise FileNotFoundError(f"Dataset not found: {pkl_path}")
    
    with open(pkl_path, 'rb') as f:
        data = pickle.load(f)
    
    LOG.info(f"Loaded {len(data)} samples from {pkl_path}")
    return data


def main():
    parser = argparse.ArgumentParser(description="Train Spatial GNN for Java vulnerability detection")
    parser.add_argument("--data", type=str, required=True, help="Training data directory (output from prepare_training_data.py)")
    parser.add_argument("--output", type=str, required=True, help="Output directory for model checkpoints")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs (default: 100)")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size (default: 32)")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate (default: 0.001)")
    parser.add_argument("--device", type=str, default='auto', help="Device: auto, cpu, cuda, mps (default: auto)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    
    args = parser.parse_args()
    
    data_dir = Path(args.data)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    LOG.info("="*60)
    LOG.info("Spatial GNN Training for Java Vulnerability Detection")
    LOG.info("="*60)
    LOG.info(f"Data directory: {data_dir}")
    LOG.info(f"Output directory: {output_dir}")
    LOG.info(f"Epochs: {args.epochs}, Batch size: {args.batch_size}, LR: {args.lr}")
    LOG.info(f"Device: {args.device}, Seed: {args.seed}")
    LOG.info("="*60)
    
    # Load datasets
    LOG.info("\n📂 Loading datasets...")
    train_data = load_dataset(data_dir, "train")
    val_data = load_dataset(data_dir, "val")
    test_data = load_dataset(data_dir, "test")
    
    # Create data loaders
    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)
    
    LOG.info(f"✅ Train batches: {len(train_loader)}, Val batches: {len(val_loader)}, Test batches: {len(test_loader)}")
    
    # Create trainer
    LOG.info("\n🔧 Creating trainer...")
    model_config = {
        'node_dim': 128,
        'hidden_dim': 256,
        'num_vulnerability_types': 24,
        'num_edge_types': 4,
        'num_layers': 3,
        'use_hierarchical': True
    }
    
    trainer = create_trainer(
        model_config=model_config,
        device=args.device,
        random_seed=args.seed
    )
    
    # Override hyperparameters if specified
    trainer.learning_rate = args.lr
    trainer.num_epochs = args.epochs
    trainer.batch_size = args.batch_size
    
    # Recreate optimizer with new learning rate
    trainer.optimizer = torch.optim.Adam(
        trainer.model.parameters(),
        lr=trainer.learning_rate,
        weight_decay=trainer.weight_decay
    )
    trainer.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        trainer.optimizer,
        mode='min',
        factor=0.5,
        patience=5
    )
    
    LOG.info(f"✅ Trainer configured: {trainer.device}")
    
    # Train model
    LOG.info("\n🚀 Starting training...")
    trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        checkpoint_dir=output_dir,
        num_epochs=args.epochs
    )
    
    # Test final model
    LOG.info("\n📊 Testing final model...")
    test_metrics = trainer.validate(test_loader)
    LOG.info(f"Test Results:")
    LOG.info(f"   Loss: {test_metrics['loss']:.4f}")
    LOG.info(f"   Binary Accuracy: {test_metrics['binary_accuracy']:.4f}")
    LOG.info(f"   Multiclass Accuracy: {test_metrics['multiclass_accuracy']:.4f}")
    
    # Save test results
    import json
    with open(output_dir / "test_results.json", 'w') as f:
        json.dump(test_metrics, f, indent=2)
    
    LOG.info(f"\n✅ Training complete! Models saved to: {output_dir}")
    LOG.info(f"   Best model: {trainer.best_model_path}")
    LOG.info(f"   Test results: {output_dir / 'test_results.json'}")


if __name__ == "__main__":
    main()

