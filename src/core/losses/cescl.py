"""
Cluster-Enhanced Supervised Contrastive Loss (CESCL)
Replaces BCE + SCL with improved cluster-tightening and contrastive learning
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import math
from typing import Dict, List, Any, Optional, Tuple
import logging

def cescl(z: torch.Tensor, y: torch.Tensor, τ: float = 0.07, α: float = 1.0) -> torch.Tensor:
    """
    Cluster-Enhanced SupCon Loss (NAACL-SRW 2025).
    z : [B, d] — L2-normalized embeddings  
    y : [B]    — integer labels  
    τ : temperature, α : cluster-tightening weight
    """
    # cosine similarity matrix
    sim = torch.matmul(z, z.T) / τ
    # positive mask (exclude self)
    pos_mask = (y.unsqueeze(1) == y.unsqueeze(0)).float() - torch.eye(len(y), device=y.device)
    # numerator: sum of exp(sim) over positives
    num = (pos_mask * torch.exp(sim)).sum(dim=1)
    # denominator: sum of exp(sim) over all except self
    den = (torch.exp(sim) * (1 - torch.eye(len(y), device=y.device))).sum(dim=1)
    scl_loss = -torch.log((num + 1e-9) / (den + 1e-9)).mean()

    # cluster-tightening term
    unique_labels = torch.unique(y)
    tight_loss = 0.0
    for lbl in unique_labels:
        mask = (y == lbl)
        if mask.sum() > 1:
            cluster = z[mask]
            centroid = cluster.mean(dim=0, keepdim=True)
            tight_loss += ((cluster - centroid).norm(dim=1).pow(2)).mean()
    tight_loss = tight_loss / len(unique_labels)

    return scl_loss + α * tight_loss

class CESCLLoss(nn.Module):
    """
    Cluster-Enhanced Supervised Contrastive Loss
    
    Combines:
    1. L2-normalized graph embeddings
    2. Int labels (0 safe / 1 vuln)
    3. Temperature and cluster-tightening weight
    4. Torch.unique() for centroids calculation
    5. Mask for unsupervised/[few] positives/negatives per device/device
    6. Torch.clamp(log_sum_1) + 1e-9 for numerical stability
    """
    
    def __init__(self, 
                 temperature: float = 0.07,
                 cluster_weight: float = 1.0,
                 base_temperature: float = 0.07):
        """
        Initialize CESCL Loss
        
        Args:
            temperature: Temperature parameter for contrastive learning
            cluster_weight: Weight for cluster-tightening component
            base_temperature: Base temperature for normalization
        """
        super(CESCLLoss, self).__init__()
        self.temperature = temperature
        self.cluster_weight = cluster_weight
        self.base_temperature = base_temperature
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"✅ CESCL Loss initialized: temp={temperature}, cluster_weight={cluster_weight}")
    
    def forward(self, 
                features: torch.Tensor, 
                labels: torch.Tensor,
                mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Compute CESCL loss
        
        Args:
            features: L2-normalized graph embeddings [batch_size, feature_dim]
            labels: Int labels (0 safe / 1 vuln) [batch_size]
            mask: Optional mask for unsupervised samples [batch_size]
            
        Returns:
            Dictionary containing loss components and metrics
        """
        device = features.device
        batch_size = features.shape[0]
        
        # Ensure features are L2-normalized
        features = F.normalize(features, p=2, dim=1)
        
        # Create default mask if not provided
        if mask is None:
            mask = torch.ones(batch_size, dtype=torch.bool, device=device)
        
        # Get unique labels and their centroids
        unique_labels = torch.unique(labels)
        centroids = self._compute_centroids(features, labels, unique_labels)
        
        # Compute contrastive loss component
        contrastive_loss = self._compute_contrastive_loss(features, labels, mask)
        
        # Compute cluster-tightening loss component
        cluster_loss = self._compute_cluster_tightening_loss(features, labels, centroids, mask)
        
        # Combine losses
        total_loss = contrastive_loss + self.cluster_weight * cluster_loss
        
        # Compute additional metrics
        metrics = self._compute_metrics(features, labels, centroids)
        
        return {
            'total_loss': total_loss,
            'contrastive_loss': contrastive_loss,
            'cluster_loss': cluster_loss,
            'metrics': metrics
        }
    
    def _compute_centroids(self, 
                          features: torch.Tensor, 
                          labels: torch.Tensor, 
                          unique_labels: torch.Tensor) -> torch.Tensor:
        """
        Compute cluster centroids using torch.unique()
        
        Args:
            features: Normalized features [batch_size, feature_dim]
            labels: Labels [batch_size]
            unique_labels: Unique label values
            
        Returns:
            Centroids tensor [num_classes, feature_dim]
        """
        centroids = []
        
        for label in unique_labels:
            mask = (labels == label)
            if mask.sum() > 0:
                # Compute centroid for this class
                class_features = features[mask]
                centroid = torch.mean(class_features, dim=0)
                # L2 normalize centroid
                centroid = F.normalize(centroid, p=2, dim=0)
                centroids.append(centroid)
            else:
                # Handle empty class (shouldn't happen in practice)
                centroids.append(torch.zeros(features.shape[1], device=features.device))
        
        return torch.stack(centroids)
    
    def _compute_contrastive_loss(self, 
                                 features: torch.Tensor, 
                                 labels: torch.Tensor,
                                 mask: torch.Tensor) -> torch.Tensor:
        """
        Compute supervised contrastive loss component
        
        Args:
            features: Normalized features [batch_size, feature_dim]
            labels: Labels [batch_size]
            mask: Valid sample mask [batch_size]
            
        Returns:
            Contrastive loss scalar
        """
        batch_size = features.shape[0]
        
        # Compute similarity matrix
        similarity_matrix = torch.matmul(features, features.T) / self.temperature
        
        # Create positive and negative masks
        labels_expanded = labels.unsqueeze(1)
        positive_mask = (labels_expanded == labels_expanded.T).float()
        
        # Remove self-similarity
        identity_mask = torch.eye(batch_size, device=features.device)
        positive_mask = positive_mask - identity_mask
        
        # Apply valid sample mask
        valid_mask = mask.unsqueeze(1) * mask.unsqueeze(0)
        positive_mask = positive_mask * valid_mask
        negative_mask = (1 - positive_mask - identity_mask) * valid_mask
        
        # Compute log probabilities with numerical stability
        max_sim = torch.max(similarity_matrix, dim=1, keepdim=True)[0]
        similarity_matrix_stable = similarity_matrix - max_sim
        
        # Compute denominator (sum of all similarities except self)
        exp_sim = torch.exp(similarity_matrix_stable)
        exp_sim_masked = exp_sim * (1 - identity_mask)
        
        # Add small epsilon for numerical stability
        log_sum_exp = torch.log(torch.clamp(exp_sim_masked.sum(dim=1, keepdim=True), min=1e-9))
        
        # Compute positive similarities
        positive_similarities = similarity_matrix_stable * positive_mask
        
        # Compute contrastive loss
        loss_per_sample = []
        for i in range(batch_size):
            if mask[i] and positive_mask[i].sum() > 0:
                # Get positive similarities for sample i
                pos_sims = positive_similarities[i][positive_mask[i] > 0]
                # Compute loss for each positive
                sample_losses = -pos_sims + log_sum_exp[i]
                loss_per_sample.append(sample_losses.mean())
        
        if len(loss_per_sample) > 0:
            contrastive_loss = torch.stack(loss_per_sample).mean()
        else:
            contrastive_loss = torch.tensor(0.0, device=features.device, requires_grad=True)
        
        return contrastive_loss
    
    def _compute_cluster_tightening_loss(self, 
                                       features: torch.Tensor, 
                                       labels: torch.Tensor,
                                       centroids: torch.Tensor,
                                       mask: torch.Tensor) -> torch.Tensor:
        """
        Compute cluster-tightening loss component
        
        Args:
            features: Normalized features [batch_size, feature_dim]
            labels: Labels [batch_size]
            centroids: Class centroids [num_classes, feature_dim]
            mask: Valid sample mask [batch_size]
            
        Returns:
            Cluster tightening loss scalar
        """
        cluster_losses = []
        unique_labels = torch.unique(labels)
        
        for i, label in enumerate(unique_labels):
            # Get samples for this class
            class_mask = (labels == label) & mask
            
            if class_mask.sum() > 0:
                class_features = features[class_mask]
                class_centroid = centroids[i].unsqueeze(0)
                
                # Compute distances to centroid
                distances = 1 - torch.matmul(class_features, class_centroid.T).squeeze()
                
                # Cluster tightening loss (minimize intra-class distances)
                cluster_loss = distances.mean()
                cluster_losses.append(cluster_loss)
        
        if len(cluster_losses) > 0:
            total_cluster_loss = torch.stack(cluster_losses).mean()
        else:
            total_cluster_loss = torch.tensor(0.0, device=features.device, requires_grad=True)
        
        return total_cluster_loss
    
    def _compute_metrics(self, 
                        features: torch.Tensor, 
                        labels: torch.Tensor,
                        centroids: torch.Tensor) -> Dict[str, float]:
        """
        Compute additional metrics for monitoring
        
        Args:
            features: Normalized features [batch_size, feature_dim]
            labels: Labels [batch_size]
            centroids: Class centroids [num_classes, feature_dim]
            
        Returns:
            Dictionary of metrics
        """
        with torch.no_grad():
            unique_labels = torch.unique(labels)
            
            # Compute intra-class distances
            intra_class_distances = []
            for i, label in enumerate(unique_labels):
                class_mask = (labels == label)
                if class_mask.sum() > 1:
                    class_features = features[class_mask]
                    centroid = centroids[i].unsqueeze(0)
                    distances = 1 - torch.matmul(class_features, centroid.T).squeeze()
                    intra_class_distances.append(distances.mean().item())
            
            # Compute inter-class distances
            inter_class_distances = []
            if len(centroids) > 1:
                for i in range(len(centroids)):
                    for j in range(i + 1, len(centroids)):
                        distance = 1 - torch.dot(centroids[i], centroids[j]).item()
                        inter_class_distances.append(distance)
            
            metrics = {
                'avg_intra_class_distance': np.mean(intra_class_distances) if intra_class_distances else 0.0,
                'avg_inter_class_distance': np.mean(inter_class_distances) if inter_class_distances else 0.0,
                'num_classes': len(unique_labels),
                'cluster_separation_ratio': (np.mean(inter_class_distances) / max(np.mean(intra_class_distances), 1e-6)) if intra_class_distances and inter_class_distances else 0.0
            }
            
        return metrics

class CESCLTrainer:
    """
    Trainer class for CESCL loss integration with vulnerability detection
    """
    
    def __init__(self, 
                 temperature: float = 0.07,
                 cluster_weight: float = 1.0,
                 learning_rate: float = 0.001):
        """
        Initialize CESCL trainer
        
        Args:
            temperature: Temperature parameter for contrastive learning
            cluster_weight: Weight for cluster-tightening component
            learning_rate: Learning rate for optimization
        """
        self.loss_fn = CESCLLoss(temperature=temperature, cluster_weight=cluster_weight)
        self.learning_rate = learning_rate
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"✅ CESCL Trainer initialized with lr={learning_rate}")
    
    def compute_loss(self, 
                    cpg_features: Dict[str, Any], 
                    vulnerabilities: List[str],
                    batch_size: int = 32) -> Dict[str, Any]:
        """
        Compute CESCL loss for vulnerability detection
        
        Args:
            cpg_features: CPG features from Joern analysis
            vulnerabilities: Detected vulnerability patterns
            batch_size: Batch size for processing
            
        Returns:
            Dictionary containing loss and metrics
        """
        # Convert CPG features to tensor format
        features_tensor = self._cpg_to_tensor(cpg_features, batch_size)
        
        # Create labels (0 for safe, 1 for vulnerable)
        labels_tensor = self._create_labels(vulnerabilities, batch_size)
        
        # Compute CESCL loss
        loss_result = self.loss_fn(features_tensor, labels_tensor)
        
        # Convert to standard format
        return {
            'cescl_loss': loss_result['total_loss'].item(),
            'contrastive_component': loss_result['contrastive_loss'].item(),
            'cluster_component': loss_result['cluster_loss'].item(),
            'metrics': loss_result['metrics'],
            'improved_confidence': self._compute_improved_confidence(loss_result)
        }
    
    def _cpg_to_tensor(self, cpg_features: Dict[str, Any], batch_size: int) -> torch.Tensor:
        """
        Convert CPG features to normalized tensor format
        
        Args:
            cpg_features: CPG features dictionary
            batch_size: Target batch size
            
        Returns:
            Normalized feature tensor [batch_size, feature_dim]
        """
        # Extract numerical features
        feature_values = [
            cpg_features.get('nodes', 0),
            cpg_features.get('methods', 0),
            cpg_features.get('calls', 0),
            cpg_features.get('identifiers', 0)
        ]
        
        # Normalize features
        feature_values = np.array(feature_values, dtype=np.float32)
        feature_values = feature_values / (np.linalg.norm(feature_values) + 1e-8)
        
        # Create batch by repeating and adding noise for simulation
        batch_features = []
        for i in range(batch_size):
            # Add small random noise to simulate batch diversity
            noise = np.random.normal(0, 0.01, len(feature_values))
            noisy_features = feature_values + noise
            batch_features.append(noisy_features)
        
        # Convert to tensor and normalize
        batch_features_array = np.array(batch_features)
        features_tensor = torch.tensor(batch_features_array, dtype=torch.float32)
        features_tensor = F.normalize(features_tensor, p=2, dim=1)
        
        return features_tensor
    
    def _create_labels(self, vulnerabilities: List[str], batch_size: int) -> torch.Tensor:
        """
        Create labels tensor from vulnerability detection results
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            batch_size: Target batch size
            
        Returns:
            Labels tensor [batch_size]
        """
        # Determine if vulnerable (1) or safe (0)
        is_vulnerable = 1 if len(vulnerabilities) > 0 else 0
        
        # Create batch labels with some variation for simulation
        labels = []
        for i in range(batch_size):
            if is_vulnerable:
                # Most samples are vulnerable, some safe for contrast
                label = 1 if i < batch_size * 0.8 else 0
            else:
                # Most samples are safe, some vulnerable for contrast
                label = 0 if i < batch_size * 0.8 else 1
            labels.append(label)
        
        return torch.tensor(labels, dtype=torch.long)
    
    def _compute_improved_confidence(self, loss_result: Dict[str, torch.Tensor]) -> float:
        """
        Compute improved confidence based on CESCL loss components
        
        Args:
            loss_result: Loss computation results
            
        Returns:
            Improved confidence score
        """
        # Lower loss indicates better clustering and higher confidence
        total_loss = loss_result['total_loss'].item()
        contrastive_loss = loss_result['contrastive_loss'].item()
        cluster_loss = loss_result['cluster_loss'].item()
        
        # Compute confidence based on loss components
        # Lower loss = higher confidence
        contrastive_confidence = math.exp(-contrastive_loss)
        cluster_confidence = math.exp(-cluster_loss)
        
        # Combine confidences
        improved_confidence = 0.6 * contrastive_confidence + 0.4 * cluster_confidence
        
        # Apply sigmoid to normalize to [0, 1]
        improved_confidence = 1.0 / (1.0 + math.exp(-5 * (improved_confidence - 0.5)))
        
        return improved_confidence

class GraphSAGECESCLTrainer:
    """
    GraphSAGE trainer with CESCL loss integration
    """
    
    def __init__(self, model, optimizer, device='cpu'):
        self.model = model
        self.optimizer = optimizer
        self.device = device
        self.logger = logging.getLogger(__name__)
        
    def train_one_epoch(self, dataloader, lambda_weight: float = 0.2):
        """
        Train one epoch with CESCL loss
        
        Args:
            dataloader: Training data loader
            lambda_weight: Weight for CESCL loss component
            
        Returns:
            Average loss for the epoch
        """
        self.model.train()
        total_loss = 0.0
        num_batches = 0
        
        for batch in dataloader:
            # Move batch to device
            batch = batch.to(self.device)
            
            # Forward pass
            embeddings, logits = self.model(batch.x, batch.edge_index, batch.batch)
            
            # Compute BCE loss
            bce_loss = F.binary_cross_entropy_with_logits(logits, batch.y.float())
            
            # Compute CESCL loss
            z_normalized = F.normalize(embeddings, dim=1)
            cescl_loss = cescl(z_normalized, batch.y, τ=0.07, α=1.0)
            
            # Combined loss
            total_loss_batch = bce_loss + lambda_weight * cescl_loss
            
            # Backward pass
            self.optimizer.zero_grad()
            total_loss_batch.backward()
            self.optimizer.step()
            
            total_loss += total_loss_batch.item()
            num_batches += 1
        
        return total_loss / num_batches if num_batches > 0 else 0.0
    
    def evaluate(self, dataloader):
        """
        Evaluate model on validation/test set
        
        Args:
            dataloader: Evaluation data loader
            
        Returns:
            Dictionary with evaluation metrics
        """
        self.model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in dataloader:
                batch = batch.to(self.device)
                embeddings, logits = self.model(batch.x, batch.edge_index, batch.batch)
                
                preds = torch.sigmoid(logits) > 0.5
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch.y.cpu().numpy())
        
        # Compute metrics
        from sklearn.metrics import f1_score, precision_score, recall_score
        
        f1 = f1_score(all_labels, all_preds)
        precision = precision_score(all_labels, all_preds)
        recall = recall_score(all_labels, all_preds)
        
        return {
            'f1': f1,
            'precision': precision,
            'recall': recall
        }

def test_cescl_decreases():
    """
    Unit test for CESCL to ensure it's non-negative and decreases on one gradient step
    """
    # Create test data
    z = F.normalize(torch.randn(8, 64), dim=1)
    y = torch.randint(0, 2, (8,))
    
    # Test 1: CESCL should be non-negative
    loss1 = cescl(z, y)
    assert loss1 >= 0, f"CESCL loss should be non-negative, got {loss1}"
    
    # Test 2: CESCL should decrease after gradient step
    z.requires_grad_(True)
    loss1 = cescl(z, y)
    loss1.backward()
    
    with torch.no_grad():
        z2 = z - 0.1 * z.grad
        z2_normalized = F.normalize(z2, dim=1)
        loss2 = cescl(z2_normalized, y)
    
    assert loss2 <= loss1 + 1e-6, f"CESCL loss should decrease after gradient step: {loss1} -> {loss2}"
    
    return True

def grid_search_lambda(train_loader, val_loader, model, optimizer, device='cpu'):
    """
    Perform grid search over lambda values
    
    Args:
        train_loader: Training data loader
        val_loader: Validation data loader
        model: Model to train
        optimizer: Optimizer
        device: Device to use
        
    Returns:
        Dictionary with results for each lambda
    """
    results = {}
    
    for λ in [0.1, 0.2, 0.3]:
        print(f"Testing λ={λ}")
        
        # Reset model (in practice, you'd want to reinitialize)
        trainer = GraphSAGECESCLTrainer(model, optimizer, device)
        
        # Train for a few epochs
        for epoch in range(3):
            train_loss = trainer.train_one_epoch(train_loader, lambda_weight=λ)
        
        # Evaluate
        val_metrics = trainer.evaluate(val_loader)
        val_f1 = val_metrics['f1']
        
        results[λ] = val_f1
        print(f"λ={λ} → F1={val_f1:.3f}")
    
    return results 