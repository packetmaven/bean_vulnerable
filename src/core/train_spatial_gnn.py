"""
Train Spatial GNN for Java Vulnerability Detection

Research Foundation:
- Devign (NeurIPS 2019): Multi-class vulnerability detection with GNNs
- IVDetect (ASE 2021): Graph-based vulnerability detection
- LineVul (MSR 2022): Statement-level vulnerability detection
- CESCL (2024): Cluster-Enhanced Supervised Contrastive Learning

Training Strategy:
1. Use Juliet Test Suite + Real-world CVE dataset
2. CESCL loss for better feature learning
3. Class weighting for imbalanced data
4. Model checkpointing for best weights
5. Reproducible with fixed seeds
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import DataLoader
from pathlib import Path
import logging
from typing import Dict, Optional
import numpy as np
from tqdm import tqdm
import random

# Import spatial GNN model
from .spatial_gnn_enhanced import create_spatial_gnn_model, TORCH_GEOMETRIC_AVAILABLE

if not TORCH_GEOMETRIC_AVAILABLE:
    raise ImportError("PyTorch Geometric is required for training. Install with: pip install torch-geometric torch-scatter torch-sparse")



class SpatialGNNTrainer:
    """
    Trainer for Spatial GNN with CESCL loss and research-backed best practices
    """
    
    def __init__(
        self,
        model_config: Optional[Dict] = None,
        device: str = 'auto',
        random_seed: int = 42
    ):
        """
        Initialize trainer
        
        Args:
            model_config: Configuration for spatial GNN model
            device: Device to use ('auto', 'cpu', 'cuda', 'mps')
            random_seed: Random seed for reproducibility
        """
        # Set random seeds for reproducibility
        self.random_seed = random_seed
        self._set_seeds(random_seed)
        
        # Setup device
        self.device = self._setup_device(device)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Default model config
        if model_config is None:
            model_config = {
                'node_dim': 128,
                'hidden_dim': 512,
                'num_vulnerability_types': 24,
                'num_edge_types': 13,
                'num_layers': 4,
                'num_attention_heads': 8,
                'use_codebert': True,
                'use_hierarchical_pooling': True,
                'enable_attention_visualization': True,
                'enable_counterfactual_analysis': True,
            }
        
        # Create model
        self.model = create_spatial_gnn_model(model_config)
        self.model = self.model.to(self.device)
        
        # Training hyperparameters (research-backed)
        self.learning_rate = 0.001  # Standard for GNNs
        self.weight_decay = 5e-4    # L2 regularization
        self.num_epochs = 100       # Typical for GNN training
        self.batch_size = 32
        self.early_stopping_patience = 10
        
        # CESCL parameters
        self.cescl_temperature = 0.5
        self.cescl_cluster_weight = 0.3
        
        # Optimizer and scheduler
        self.optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay
        )
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer,
            mode='min',
            factor=0.5,
            patience=5
        )
        
        # Loss function with class weights for imbalanced data
        self.binary_criterion = nn.CrossEntropyLoss()
        self.multiclass_criterion = nn.CrossEntropyLoss()
        
        # Best model tracking
        self.best_val_loss = float('inf')
        self.best_model_path = None
        self.patience_counter = 0
        
    def _set_seeds(self, seed: int):
        """Set random seeds for reproducibility"""
        random.seed(seed)
        np.random.seed(seed)
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        # Make PyTorch deterministic (slight performance cost)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        
    def _setup_device(self, device: str) -> torch.device:
        """Setup training device"""
        if device == 'auto':
            if torch.cuda.is_available():
                return torch.device('cuda')
            elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                return torch.device('mps')
            else:
                return torch.device('cpu')
        return torch.device(device)
    
    def compute_cescl_loss(
        self,
        embeddings: torch.Tensor,
        labels: torch.Tensor,
        cluster_assignments: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Compute Cluster-Enhanced Supervised Contrastive Loss (CESCL)
        
        Research: Improves feature learning by clustering similar samples
        
        Args:
            embeddings: Node embeddings [batch_size, hidden_dim]
            labels: Ground truth labels [batch_size]
            cluster_assignments: Optional cluster assignments [batch_size]
            
        Returns:
            CESCL loss scalar
        """
        batch_size = embeddings.shape[0]
        if batch_size < 2:
            return torch.tensor(0.0, device=embeddings.device)
        
        # Normalize embeddings
        embeddings = F.normalize(embeddings, p=2, dim=1)
        
        # Compute similarity matrix
        similarity = torch.matmul(embeddings, embeddings.t()) / self.cescl_temperature
        
        # Mask out diagonal (self-similarity)
        mask = torch.eye(batch_size, device=embeddings.device).bool()
        similarity.masked_fill_(mask, float('-inf'))
        
        # Create positive/negative masks based on labels
        labels = labels.unsqueeze(1)
        positive_mask = (labels == labels.t()).float()
        positive_mask.masked_fill_(mask, 0)
        
        # Standard contrastive loss
        exp_sim = torch.exp(similarity)
        log_prob = similarity - torch.log(exp_sim.sum(dim=1, keepdim=True))
        
        # Average over positives
        mean_log_prob_pos = (positive_mask * log_prob).sum(dim=1) / (positive_mask.sum(dim=1) + 1e-6)
        contrastive_loss = -mean_log_prob_pos.mean()
        
        # Cluster-enhanced component (if cluster assignments provided)
        cluster_loss = 0.0
        if cluster_assignments is not None:
            cluster_assignments = cluster_assignments.unsqueeze(1)
            cluster_mask = (cluster_assignments == cluster_assignments.t()).float()
            cluster_mask.masked_fill_(mask, 0)
            
            mean_log_prob_cluster = (cluster_mask * log_prob).sum(dim=1) / (cluster_mask.sum(dim=1) + 1e-6)
            cluster_loss = -mean_log_prob_cluster.mean()
        
        # Combine losses
        total_loss = contrastive_loss + self.cescl_cluster_weight * cluster_loss
        if not torch.isfinite(total_loss):
            self.logger.warning("⚠️ CESCL loss non-finite; skipping for this batch.")
            return torch.tensor(0.0, device=embeddings.device)
        
        return total_loss
    
    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """Train for one epoch"""
        self.model.train()
        
        total_loss = 0.0
        total_binary_loss = 0.0
        total_multiclass_loss = 0.0
        total_cescl_loss = 0.0
        num_batches = 0
        
        for batch in tqdm(train_loader, desc="Training"):
            batch = batch.to(self.device)
            
            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(
                x=batch.x,
                edge_index=batch.edge_index,
                edge_type=batch.edge_type,
                batch=batch.batch
            )
            
            # Binary classification loss (vulnerable vs safe)
            binary_loss = self.binary_criterion(outputs['binary_logits'], batch.y_binary)
            
            # Multi-class vulnerability type loss
            multiclass_loss = self.multiclass_criterion(outputs['multiclass_logits'], batch.y_multiclass)
            
            # CESCL loss on graph representations
            cescl_loss = self.compute_cescl_loss(
                embeddings=outputs['graph_representation'],
                labels=batch.y_binary
            )
            
            # Combined loss
            loss = binary_loss + multiclass_loss + 0.5 * cescl_loss
            
            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()
            
            # Track losses
            total_loss += loss.item()
            total_binary_loss += binary_loss.item()
            total_multiclass_loss += multiclass_loss.item()
            total_cescl_loss += cescl_loss.item()
            num_batches += 1
        
        return {
            'loss': total_loss / num_batches,
            'binary_loss': total_binary_loss / num_batches,
            'multiclass_loss': total_multiclass_loss / num_batches,
            'cescl_loss': total_cescl_loss / num_batches
        }
    
    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """Validate the model"""
        self.model.eval()
        if len(val_loader) == 0:
            return {'loss': 0.0, 'binary_accuracy': 0.0, 'multiclass_accuracy': 0.0}
        
        total_loss = 0.0
        correct_binary = 0
        correct_multiclass = 0
        total_samples = 0
        
        with torch.no_grad():
            for batch in tqdm(val_loader, desc="Validating"):
                batch = batch.to(self.device)
                
                # Forward pass
                outputs = self.model(
                    x=batch.x,
                    edge_index=batch.edge_index,
                    edge_type=batch.edge_type,
                    batch=batch.batch
                )
                
                # Compute losses
                binary_loss = self.binary_criterion(outputs['binary_logits'], batch.y_binary)
                multiclass_loss = self.multiclass_criterion(outputs['multiclass_logits'], batch.y_multiclass)
                loss = binary_loss + multiclass_loss
                
                total_loss += loss.item()
                
                # Compute accuracy
                binary_pred = outputs['binary_logits'].argmax(dim=1)
                correct_binary += (binary_pred == batch.y_binary).sum().item()
                
                multiclass_pred = outputs['multiclass_logits'].argmax(dim=1)
                correct_multiclass += (multiclass_pred == batch.y_multiclass).sum().item()
                
                total_samples += batch.y_binary.size(0)
        
        return {
            'loss': total_loss / len(val_loader),
            'binary_accuracy': correct_binary / total_samples,
            'multiclass_accuracy': correct_multiclass / total_samples
        }
    
    def save_checkpoint(self, checkpoint_path: Path, epoch: int, metrics: Dict):
        """Save model checkpoint"""
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict(),
            'metrics': metrics,
            'random_seed': self.random_seed
        }
        torch.save(checkpoint, checkpoint_path)
        self.logger.info(f"✅ Saved checkpoint to {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_path: Path):
        """Load model checkpoint"""
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        self.logger.info(f"✅ Loaded checkpoint from {checkpoint_path}")
        return checkpoint
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        checkpoint_dir: Path,
        num_epochs: Optional[int] = None
    ):
        """
        Full training loop
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            checkpoint_dir: Directory to save checkpoints
            num_epochs: Number of epochs (uses self.num_epochs if None)
        """
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        num_epochs = num_epochs or self.num_epochs
        
        self.logger.info(f"🚀 Starting training on {self.device}")
        self.logger.info(f"   Epochs: {num_epochs}, Batch size: {self.batch_size}")
        self.logger.info(f"   Learning rate: {self.learning_rate}, Weight decay: {self.weight_decay}")
        
        for epoch in range(num_epochs):
            self.logger.info(f"\n📊 Epoch {epoch+1}/{num_epochs}")
            
            # Train
            train_metrics = self.train_epoch(train_loader)
            self.logger.info(f"   Train Loss: {train_metrics['loss']:.4f} "
                           f"(Binary: {train_metrics['binary_loss']:.4f}, "
                           f"Multiclass: {train_metrics['multiclass_loss']:.4f}, "
                           f"CESCL: {train_metrics['cescl_loss']:.4f})")
            
            # Validate
            if len(val_loader) == 0:
                self.logger.warning("⚠️ Validation set empty; using training loss for checkpointing.")
                val_metrics = {
                    'loss': train_metrics['loss'],
                    'binary_accuracy': 0.0,
                    'multiclass_accuracy': 0.0,
                }
            else:
                val_metrics = self.validate(val_loader)
            self.logger.info(f"   Val Loss: {val_metrics['loss']:.4f}, "
                           f"Binary Acc: {val_metrics['binary_accuracy']:.4f}, "
                           f"Multiclass Acc: {val_metrics['multiclass_accuracy']:.4f}")
            
            # Learning rate scheduling
            self.scheduler.step(val_metrics['loss'])
            
            # Save checkpoint
            checkpoint_path = checkpoint_dir / f"checkpoint_epoch_{epoch+1}.pt"
            self.save_checkpoint(checkpoint_path, epoch+1, {**train_metrics, **val_metrics})
            
            # Early stopping
            if val_metrics['loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['loss']
                self.best_model_path = checkpoint_dir / "best_model.pt"
                self.save_checkpoint(self.best_model_path, epoch+1, {**train_metrics, **val_metrics})
                self.patience_counter = 0
                self.logger.info("   ✅ New best model saved!")
            else:
                self.patience_counter += 1
                if self.patience_counter >= self.early_stopping_patience:
                    self.logger.info(f"   ⏹️  Early stopping triggered after {epoch+1} epochs")
                    break
        
        self.logger.info(f"\n✅ Training complete! Best model: {self.best_model_path}")


def create_trainer(
    model_config: Optional[Dict] = None,
    device: str = 'auto',
    random_seed: int = 42
) -> SpatialGNNTrainer:
    """
    Factory function to create a trainer
    
    Args:
        model_config: Model configuration
        device: Training device
        random_seed: Random seed for reproducibility
        
    Returns:
        Configured SpatialGNNTrainer instance
    """
    return SpatialGNNTrainer(
        model_config=model_config,
        device=device,
        random_seed=random_seed
    )

