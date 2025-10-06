"""
Bean Vulnerable - Enhanced Spatial GNN for Java Vulnerability Detection
Research-backed heterogeneous GNN with multi-edge type support

Research Foundation (2024):
- Devign Framework: Combined AST+CFG+DFG analysis
- R-GCN: Relational Graph Convolutional Networks for heterogeneous edges
- GraphSAGE: Scalable inductive learning with neighborhood sampling
- GAT: Attention mechanisms for vulnerability-relevant feature focus
- Hierarchical Pooling: Multi-scale vulnerability pattern detection

Key Improvements:
1. Heterogeneous edge type processing (AST/CFG/DFG/PDG)
2. Relation-specific message passing
3. Multi-hop neighborhood aggregation
4. Hierarchical graph pooling for context
5. Attention-weighted vulnerability scoring
"""

import logging
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

# Check for PyTorch Geometric
try:
    import torch_geometric
    from torch_geometric.nn import GATConv, SAGEConv, GCNConv, RGCNConv
    from torch_geometric.nn import global_mean_pool, global_max_pool, global_add_pool
    from torch_geometric.nn import TopKPooling, SAGPooling
    from torch_geometric.data import Data, HeteroData, Batch
    from torch_geometric.utils import to_undirected, add_self_loops
    TORCH_GEOMETRIC_AVAILABLE = True
    logger.info("✅ PyTorch Geometric available - using advanced spatial GNN")
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False
    logger.warning("⚠️ PyTorch Geometric not available - spatial GNN disabled")


class HeterogeneousCPGProcessor(nn.Module):
    """
    Heterogeneous Code Property Graph Processor
    
    Handles multiple edge types (AST, CFG, DFG, PDG) with relation-specific
    message passing for improved vulnerability detection.
    
    Based on R-GCN (Relational Graph Convolutional Networks) and
    Devign framework for code vulnerability detection.
    """
    
    def __init__(self, 
                 node_dim: int = 128,
                 hidden_dim: int = 256,
                 num_edge_types: int = 4,  # AST, CFG, DFG, PDG
                 num_layers: int = 3,
                 num_bases: int = 8,  # For R-GCN parameter sharing
                 dropout: float = 0.1):
        super().__init__()
        
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_edge_types = num_edge_types
        self.num_layers = num_layers
        self.dropout = dropout
        
        # R-GCN layers for heterogeneous edge processing
        self.rgcn_layers = nn.ModuleList()
        
        # First layer
        self.rgcn_layers.append(
            RGCNConv(node_dim, hidden_dim, num_edge_types, num_bases=num_bases)
        )
        
        # Hidden layers
        for _ in range(num_layers - 1):
            self.rgcn_layers.append(
                RGCNConv(hidden_dim, hidden_dim, num_edge_types, num_bases=num_bases)
            )
        
        # Layer normalization
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers)
        ])
        
        # Dropout
        self.dropout_layer = nn.Dropout(dropout)
        
        # Edge type embeddings for attention weighting
        self.edge_type_embeddings = nn.Embedding(num_edge_types, hidden_dim)
        
        # Attention mechanism for edge type importance
        self.edge_attention = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_edge_types),
            nn.Softmax(dim=-1)
        )
        
        logger.info(f"✅ Heterogeneous CPG Processor: {num_layers} R-GCN layers, {num_edge_types} edge types")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_type: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, Dict[str, Any]]:
        """
        Forward pass with heterogeneous edge processing
        
        Args:
            x: Node features [num_nodes, node_dim]
            edge_index: Edge connectivity [2, num_edges]
            edge_type: Edge type indices [num_edges]
            batch: Batch assignment for nodes
            
        Returns:
            node_embeddings: Updated node features
            attention_weights: Edge type attention weights for interpretability
        """
        
        h = x
        attention_weights = {}
        
        for i, (rgcn, ln) in enumerate(zip(self.rgcn_layers, self.layer_norms)):
            # R-GCN message passing with relation-specific transformations
            h_new = rgcn(h, edge_index, edge_type)
            
            # Layer normalization
            h_new = ln(h_new)
            
            # Activation and dropout
            h_new = F.elu(h_new)
            h_new = self.dropout_layer(h_new)
            
            # Residual connection
            if h.shape[-1] == h_new.shape[-1]:
                h = h + h_new
            else:
                h = h_new
            
            # Compute edge type attention for this layer
            if i == self.num_layers - 1:  # Last layer
                # Global pooling for graph-level representation
                if batch is not None:
                    graph_repr = global_mean_pool(h, batch)
                else:
                    graph_repr = h.mean(dim=0, keepdim=True)
                
                # Compute attention over edge types
                edge_embeds = self.edge_type_embeddings.weight  # [num_edge_types, hidden_dim]
                attention_input = torch.cat([
                    graph_repr.repeat(self.num_edge_types, 1),
                    edge_embeds
                ], dim=-1)
                
                edge_attention_scores = self.edge_attention(attention_input)
                attention_weights[f'layer_{i}'] = edge_attention_scores
        
        return h, attention_weights


class GraphSAGEWithAttention(nn.Module):
    """
    GraphSAGE with GAT-style attention for scalable neighborhood aggregation
    
    Combines:
    - GraphSAGE: Inductive learning, scalable to large graphs
    - GAT: Attention mechanism for focusing on vulnerability-relevant neighbors
    """
    
    def __init__(self, 
                 input_dim: int,
                 hidden_dim: int = 256,
                 num_layers: int = 3,
                 num_heads: int = 4,
                 dropout: float = 0.1,
                 aggr: str = 'mean'):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_heads = num_heads
        self.dropout = dropout
        
        # Interleaved SAGE and GAT layers
        self.sage_layers = nn.ModuleList()
        self.gat_layers = nn.ModuleList()
        
        for i in range(num_layers):
            in_dim = input_dim if i == 0 else hidden_dim
            
            # SAGE layer for efficient aggregation
            self.sage_layers.append(
                SAGEConv(in_dim, hidden_dim, aggr=aggr)
            )
            
            # GAT layer for attention-based refinement
            self.gat_layers.append(
                GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, 
                       dropout=dropout, concat=True, add_self_loops=True)
            )
        
        # Layer normalization
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers * 2)
        ])
        
        self.dropout_layer = nn.Dropout(dropout)
        
        logger.info(f"✅ GraphSAGE+GAT: {num_layers} layers, {num_heads} attention heads")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Forward pass with interleaved SAGE and GAT"""
        
        h = x
        
        for i, (sage, gat) in enumerate(zip(self.sage_layers, self.gat_layers)):
            # SAGE: Efficient neighborhood aggregation
            h = sage(h, edge_index)
            h = self.layer_norms[i * 2](h)
            h = F.elu(h)
            h = self.dropout_layer(h)
            
            # GAT: Attention-based refinement
            h = gat(h, edge_index)
            h = self.layer_norms[i * 2 + 1](h)
            h = F.elu(h)
            h = self.dropout_layer(h)
        
        return h


class HierarchicalGraphPooling(nn.Module):
    """
    Hierarchical graph pooling for multi-scale vulnerability pattern detection
    
    Captures vulnerability patterns at multiple granularities:
    - Fine-grained: Statement/expression level
    - Mid-level: Method/function level  
    - Coarse: Class/file level
    """
    
    def __init__(self, hidden_dim: int = 256, pooling_ratio: float = 0.5):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        self.pooling_ratio = pooling_ratio
        
        # Three-level hierarchical pooling
        self.pool1 = TopKPooling(hidden_dim, ratio=pooling_ratio)
        self.pool2 = TopKPooling(hidden_dim, ratio=pooling_ratio)
        self.pool3 = TopKPooling(hidden_dim, ratio=pooling_ratio)
        
        # GNN layers between pooling operations
        self.conv1 = GCNConv(hidden_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)
        
        logger.info(f"✅ Hierarchical Pooling: 3 levels, ratio={pooling_ratio}")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Hierarchical pooling with multi-scale representations
        
        Returns dict with representations at each scale
        """
        
        # Level 1: Fine-grained (statement level)
        x1 = F.elu(self.conv1(x, edge_index))
        x1_pooled, edge_index1, _, batch1, _, _ = self.pool1(
            x1, edge_index, None, batch
        )
        level1_repr = global_mean_pool(x1_pooled, batch1)
        
        # Level 2: Mid-level (method level)
        x2 = F.elu(self.conv2(x1_pooled, edge_index1))
        x2_pooled, edge_index2, _, batch2, _, _ = self.pool2(
            x2, edge_index1, None, batch1
        )
        level2_repr = global_mean_pool(x2_pooled, batch2)
        
        # Level 3: Coarse (class/file level)
        x3 = F.elu(self.conv3(x2_pooled, edge_index2))
        x3_pooled, _, _, batch3, _, _ = self.pool3(
            x3, edge_index2, None, batch2
        )
        level3_repr = global_mean_pool(x3_pooled, batch3)
        
        return {
            'fine_grained': level1_repr,
            'mid_level': level2_repr,
            'coarse': level3_repr
        }


class SpatialGNNVulnerabilityDetector(nn.Module):
    """
    Complete Spatial GNN pipeline for Java vulnerability detection
    
    Integrates:
    1. Heterogeneous CPG processing (R-GCN)
    2. GraphSAGE+GAT hybrid for scalable attention
    3. Hierarchical pooling for multi-scale analysis
    4. Vulnerability-specific classification heads
    """
    
    def __init__(self,
                 node_dim: int = 128,
                 hidden_dim: int = 256,
                 num_vulnerability_types: int = 24,  # Based on test samples
                 num_edge_types: int = 4,
                 num_layers: int = 3,
                 use_hierarchical: bool = True):
        super().__init__()
        
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_vulnerability_types = num_vulnerability_types
        self.use_hierarchical = use_hierarchical
        
        # Stage 1: Heterogeneous edge processing
        self.hetero_processor = HeterogeneousCPGProcessor(
            node_dim=node_dim,
            hidden_dim=hidden_dim,
            num_edge_types=num_edge_types,
            num_layers=num_layers
        )
        
        # Stage 2: GraphSAGE+GAT hybrid
        self.sage_gat = GraphSAGEWithAttention(
            input_dim=hidden_dim,
            hidden_dim=hidden_dim,
            num_layers=2
        )
        
        # Stage 3: Hierarchical pooling (optional)
        if use_hierarchical:
            self.hierarchical_pool = HierarchicalGraphPooling(
                hidden_dim=hidden_dim
            )
            classifier_input_dim = hidden_dim * 3  # Concatenate all scales
        else:
            self.hierarchical_pool = None
            classifier_input_dim = hidden_dim
        
        # Stage 4: Classification heads
        # Binary vulnerability detection
        self.binary_classifier = nn.Sequential(
            nn.Linear(classifier_input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )
        
        # Multi-class vulnerability type classification
        self.multiclass_classifier = nn.Sequential(
            nn.Linear(classifier_input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 128),
            nn.ReLU(),
            nn.Linear(128, num_vulnerability_types)
        )
        
        # Confidence estimator
        self.confidence_estimator = nn.Sequential(
            nn.Linear(classifier_input_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
        
        logger.info(f"✅ Spatial GNN Vulnerability Detector initialized")
        logger.info(f"   - Heterogeneous edges: {num_edge_types} types")
        logger.info(f"   - Hierarchical pooling: {use_hierarchical}")
        logger.info(f"   - Vulnerability types: {num_vulnerability_types}")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, 
                edge_type: Optional[torch.Tensor] = None,
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Complete forward pass
        
        Returns:
            Dictionary with predictions, confidence, and attention weights
        """
        
        # Handle missing edge types (default to DFG=2)
        if edge_type is None:
            edge_type = torch.full((edge_index.shape[1],), 2, dtype=torch.long, device=x.device)
        
        # Stage 1: Heterogeneous CPG processing
        h, attention_weights = self.hetero_processor(x, edge_index, edge_type, batch)
        
        # Stage 2: GraphSAGE+GAT refinement
        h = self.sage_gat(h, edge_index, batch)
        
        # Stage 3: Hierarchical pooling and representation
        if self.use_hierarchical and batch is not None:
            multi_scale = self.hierarchical_pool(h, edge_index, batch)
            graph_repr = torch.cat([
                multi_scale['fine_grained'],
                multi_scale['mid_level'],
                multi_scale['coarse']
            ], dim=-1)
        else:
            # Simple global pooling
            if batch is not None:
                graph_repr = global_mean_pool(h, batch)
            else:
                graph_repr = h.mean(dim=0, keepdim=True)
        
        # Stage 4: Classification
        binary_logits = self.binary_classifier(graph_repr)
        multiclass_logits = self.multiclass_classifier(graph_repr)
        confidence = self.confidence_estimator(graph_repr)
        
        return {
            'binary_logits': binary_logits,
            'multiclass_logits': multiclass_logits,
            'confidence': confidence,
            'graph_representation': graph_repr,
            'attention_weights': attention_weights,
            'node_embeddings': h
        }


def create_spatial_gnn_model(config: Optional[Dict[str, Any]] = None) -> SpatialGNNVulnerabilityDetector:
    """
    Factory function to create spatial GNN model with configuration
    
    Args:
        config: Optional configuration dict with hyperparameters
        
    Returns:
        Initialized SpatialGNNVulnerabilityDetector
    """
    
    if config is None:
        config = {}
    
    model = SpatialGNNVulnerabilityDetector(
        node_dim=config.get('node_dim', 128),
        hidden_dim=config.get('hidden_dim', 256),
        num_vulnerability_types=config.get('num_vulnerability_types', 24),
        num_edge_types=config.get('num_edge_types', 4),
        num_layers=config.get('num_layers', 3),
        use_hierarchical=config.get('use_hierarchical', True)
    )
    
    logger.info("✅ Spatial GNN model created with configuration:")
    for key, value in config.items():
        logger.info(f"   - {key}: {value}")
    
    return model


# Edge type constants for CPG
EDGE_TYPE_AST = 0
EDGE_TYPE_CFG = 1
EDGE_TYPE_DFG = 2
EDGE_TYPE_PDG = 3

EDGE_TYPE_NAMES = {
    0: 'AST',
    1: 'CFG',
    2: 'DFG',
    3: 'PDG'
}

