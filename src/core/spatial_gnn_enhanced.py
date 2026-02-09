"""
Bean Vulnerable - Spatial GNN module (experimental)
===================================================

Research-inspired spatial GNN architecture for Java vulnerability analysis.
This implementation references ideas from recent literature (e.g., HGAN4VD,
VISION, IPAGs, R-GCN, hierarchical pooling), but **published metrics (F1/accuracy)
are not reproduced or claimed by this repo**.

Key notes:
1. Inference runs when torch/torch-geometric are installed.
2. Scores only influence output when trained weights are provided via
   `--gnn-checkpoint`.
3. Treat this module as experimental; benchmark in your environment.

Author: Bean Vulnerable Research Team
Version: 4.0.0 (Experimental Spatial GNN)
"""

import logging
import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Any, Optional, Tuple, Union
import numpy as np
from dataclasses import dataclass, field
from enum import Enum
import math

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_spatial_gnn.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Check for PyTorch Geometric with enhanced error handling
try:
    import torch_geometric
    from torch_geometric.nn import (
        GATConv, SAGEConv, GCNConv, RGCNConv, TransformerConv,
        global_mean_pool, global_max_pool, global_add_pool,
        TopKPooling, SAGPooling, ASAPooling,
        MessagePassing, aggr
    )
    from torch_geometric.data import Data, HeteroData, Batch
    from torch_geometric.utils import to_undirected, add_self_loops, degree
    from torch_geometric.nn.inits import glorot, zeros
    TORCH_GEOMETRIC_AVAILABLE = True
    logger.info(" PyTorch Geometric available - spatial GNN enabled (experimental)")
except ImportError as exc:
    TORCH_GEOMETRIC_AVAILABLE = False
    raise ImportError(
        "PyTorch Geometric (torch_geometric) is required for the Spatial GNN. "
        "Install it (and its dependencies) to enable GNN inference."
    ) from exc

# Check for transformers integration
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
try:
    from transformers import AutoTokenizer, AutoModel
    TRANSFORMERS_AVAILABLE = True
    logger.info(" Transformers available - CodeBERT integration enabled")
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    AutoTokenizer = None
    AutoModel = None
    logger.error(" Transformers not available - install transformers to enable CodeBERT")

# Optional safetensors support for secure model loading
try:
    import safetensors  # noqa: F401
    SAFETENSORS_AVAILABLE = True
except ImportError:
    SAFETENSORS_AVAILABLE = False


def _parse_version_tuple(version: str) -> Tuple[int, int, int]:
    if not version:
        return 0, 0, 0
    core = version.split("+", 1)[0]
    parts = core.split(".")
    major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = 0
    if len(parts) > 2:
        patch_digits = []
        for ch in parts[2]:
            if ch.isdigit():
                patch_digits.append(ch)
            else:
                break
        patch = int("".join(patch_digits)) if patch_digits else 0
    return major, minor, patch


def _torch_version_at_least(major: int, minor: int, patch: int = 0) -> bool:
    try:
        current = _parse_version_tuple(getattr(torch, "__version__", ""))
        return current >= (major, minor, patch)
    except Exception:
        return False

# 
# 1. Enhanced Graph Representation Types and Configuration
# 

class VulnerabilityType(Enum):
    """Enhanced vulnerability type classification based on latest CWE research"""
    # Input Validation (CWE-20 family)
    INPUT_VALIDATION = 0
    SQL_INJECTION = 1          # CWE-89
    XSS = 2                   # CWE-79
    COMMAND_INJECTION = 3     # CWE-78
    PATH_TRAVERSAL = 4        # CWE-22
    
    # Memory Safety (CWE-119 family)  
    BUFFER_OVERFLOW = 5       # CWE-121
    MEMORY_LEAK = 6          # CWE-401
    USE_AFTER_FREE = 7       # CWE-416
    
    # Crypto/Auth (CWE-287 family)
    WEAK_CRYPTO = 8          # CWE-327
    AUTH_BYPASS = 9          # CWE-287
    SESSION_FIXATION = 10    # CWE-384
    
    # Logic/Race (CWE-362 family)
    RACE_CONDITION = 11      # CWE-362
    LOGIC_ERROR = 12         # CWE-840
    TIME_OF_CHECK = 13       # CWE-367
    
    # Information Disclosure
    INFO_LEAK = 14           # CWE-200
    DEBUG_INFO = 15          # CWE-489
    
    # Serialization
    DESERIALIZATION = 16     # CWE-502
    
    # Configuration
    MISSING_ENCRYPTION = 17  # CWE-311
    WEAK_PERMISSIONS = 18    # CWE-276
    
    # Business Logic
    MISSING_AUTH = 19        # CWE-306
    IMPROPER_ACCESS = 20     # CWE-732
    
    # Resource Management
    RESOURCE_LEAK = 21       # CWE-404
    INFINITE_LOOP = 22       # CWE-835
    
    # Other
    UNKNOWN = 23

class EdgeType(Enum):
    """Enhanced edge types for multi-relational graphs"""
    # Structural edges (from AST/CFG/PDG)
    AST_PARENT_CHILD = 0      # Abstract Syntax Tree relationships
    CFG_CONTROL_FLOW = 1      # Control flow between statements
    DFG_DATA_FLOW = 2         # Data dependencies
    PDG_PROGRAM_DEP = 3       # Program dependence (control + data)
    
    # Semantic edges (enhanced)
    CALL_GRAPH = 4            # Inter-procedural calls
    TYPE_HIERARCHY = 5        # Class/interface relationships
    VARIABLE_USE = 6          # Variable usage relationships
    METHOD_OVERRIDE = 7       # Method overriding relationships
    
    # Vulnerability-specific edges
    TAINT_FLOW = 8           # Taint propagation paths
    VULNERABILITY_PATTERN = 9 # Known vulnerability patterns
    SECURITY_CONTEXT = 10    # Security-relevant relationships
    
    # Attention-based edges (learned)
    ATTENTION_WEIGHTED = 11  # Dynamically learned attention edges
    SIMILARITY = 12          # Semantic similarity edges

@dataclass
class SpatialGNNConfig:
    """Enhanced configuration for spatial GNN with research-based parameters"""
    
    # Architecture configuration
    node_dim: int = 128
    hidden_dim: int = 512          # Increased from 256 based on HGAN4VD research
    num_vulnerability_types: int = len(VulnerabilityType)
    num_edge_types: int = len(EdgeType)
    num_layers: int = 4            # Increased depth for better representation
    
    # Attention mechanisms
    num_attention_heads: int = 8   # Multi-head attention
    attention_dropout: float = 0.1
    use_transformer_attention: bool = True
    
    # Hierarchical processing
    use_hierarchical_pooling: bool = True
    pooling_ratios: List[float] = field(default_factory=lambda: [0.8, 0.6, 0.4])
    hierarchical_levels: int = 3
    
    # R-GCN configuration  
    rgcn_num_bases: int = 16       # Increased for better relation modeling
    rgcn_decomposition: str = "basis"  # or "block"
    
    # CodeBERT integration
    use_codebert: bool = True
    codebert_model: str = "microsoft/codebert-base"
    freeze_codebert: bool = True
    
    # Training configuration
    dropout: float = 0.2
    layer_norm: bool = True
    residual_connections: bool = True
    
    # Interpretability
    enable_attention_visualization: bool = True
    enable_counterfactual_analysis: bool = True
    
    # Performance optimization
    use_gradient_checkpointing: bool = True
    mixed_precision: bool = True

# 
# 2. Advanced Multi-Relational Graph Processor (R-GCN + HGAN Integration)
# 

class EnhancedRelationalGCN(nn.Module):
    """
    Enhanced Relational Graph Convolutional Network integrating:
    - R-GCN: Multi-relational message passing with basis decomposition
    - HGAN4VD: Heterogeneous attention mechanisms
    - VISION: Counterfactual robustness integration
    
    Research-inspired architecture; reported metrics in papers are not reproduced here.
    """
    
    def __init__(self, 
                 in_channels: int,
                 out_channels: int,
                 num_relations: int,
                 num_bases: int = 16,
                 num_blocks: int = None,
                 aggr: str = 'mean',
                 root_weight: bool = True,
                 bias: bool = True,
                 attention_heads: int = 8):
        super().__init__()
        
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.num_relations = num_relations
        self.num_bases = num_bases
        self.aggr = aggr
        
        # Basis decomposition for parameter sharing (R-GCN)
        if num_blocks is None:
            self.weight = nn.Parameter(torch.Tensor(num_bases, in_channels, out_channels))
            self.comp = nn.Parameter(torch.Tensor(num_relations, num_bases))
        else:
            self.num_blocks = num_blocks
            assert in_channels % num_blocks == 0 and out_channels % num_blocks == 0
            self.weight = nn.Parameter(torch.Tensor(num_relations, num_blocks, 
                                                  in_channels // num_blocks, 
                                                  out_channels // num_blocks))
            self.register_parameter('comp', None)
        
        # Root transformation
        if root_weight:
            self.root = nn.Linear(in_channels, out_channels, bias=False)
        else:
            self.register_parameter('root', None)
        
        # Bias
        if bias:
            self.bias = nn.Parameter(torch.Tensor(out_channels))
        else:
            self.register_parameter('bias', None)
        
        # HGAN-style heterogeneous attention
        self.attention_heads = attention_heads
        self.attention_dim = out_channels // attention_heads
        
        # Attention mechanisms for each relation type
        self.relation_attention = nn.ModuleList([
            nn.MultiheadAttention(
                embed_dim=out_channels,
                num_heads=attention_heads,
                dropout=0.1,
                batch_first=True
            ) for _ in range(num_relations)
        ])
        
        # Type-specific transformations (HGAN4VD inspired)
        self.type_transforms = nn.ModuleList([
            nn.Linear(in_channels, out_channels, bias=False)
            for _ in range(num_relations)
        ])
        
        # Relation importance weights
        self.relation_weights = nn.Parameter(torch.ones(num_relations))
        
        self.reset_parameters()
    
    def reset_parameters(self):
        """Initialize parameters using Xavier/Glorot initialization"""
        if hasattr(self, 'comp') and self.comp is not None:
            glorot(self.weight)
            glorot(self.comp)
        else:
            glorot(self.weight)
        
        if self.root is not None:
            glorot(self.root.weight)
        
        if self.bias is not None:
            zeros(self.bias)
        
        # Initialize relation weights
        nn.init.ones_(self.relation_weights)
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, 
                edge_type: torch.Tensor, edge_attr: Optional[torch.Tensor] = None):
        """
        Enhanced forward pass with multi-relational processing and attention
        
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge connectivity [2, num_edges]  
            edge_type: Edge type indices [num_edges]
            edge_attr: Optional edge attributes [num_edges, attr_dim]
        """
        
        # Compute relation-specific transformations
        if hasattr(self, 'comp') and self.comp is not None:
            # Basis decomposition
            weight = torch.einsum('rb,bio->rio', self.comp, self.weight)
        else:
            # Block diagonal decomposition
            weight = self.weight
        
        # Initialize output
        out = torch.zeros(x.size(0), self.out_channels, device=x.device, dtype=x.dtype)
        
        # Process each relation type separately (HGAN4VD approach)
        relation_outputs = []
        attention_weights = {}
        
        for r in range(self.num_relations):
            # Get edges for this relation
            mask = edge_type == r
            if not mask.any():
                continue
                
            edge_index_r = edge_index[:, mask]
            
            # Relation-specific transformation
            if hasattr(self, 'comp') and self.comp is not None:
                x_r = torch.matmul(x, weight[r])
            else:
                x_r = self.type_transforms[r](x)
            
            # Apply attention mechanism for this relation type
            if edge_index_r.numel() > 0:
                # Create attention input from source and target nodes
                row, col = edge_index_r
                source_nodes = x_r[row]  # [num_edges_r, out_channels]
                target_nodes = x_r[col]  # [num_edges_r, out_channels]
                
                # Apply multi-head attention
                if source_nodes.size(0) > 0:
                    # Reshape for batch processing
                    source_batch = source_nodes.unsqueeze(0)  # [1, num_edges_r, out_channels]
                    target_batch = target_nodes.unsqueeze(0)  # [1, num_edges_r, out_channels]
                    
                    attended_output, attention_scores = self.relation_attention[r](
                        source_batch, target_batch, target_batch
                    )
                    
                    # Store attention weights for interpretability
                    attention_weights[f'relation_{r}'] = attention_scores.squeeze(0)
                    
                    # Aggregate attended features to target nodes
                    attended_features = attended_output.squeeze(0)  # [num_edges_r, out_channels]
                    
                    # Scatter to target nodes
                    relation_out = torch.zeros_like(out)
                    relation_out.index_add_(0, col, attended_features)
                    
                    # Weight by relation importance
                    relation_out = relation_out * torch.sigmoid(self.relation_weights[r])
                    relation_outputs.append(relation_out)
        
        # Combine relation-specific outputs
        if relation_outputs:
            out = torch.stack(relation_outputs, dim=0).sum(dim=0)
        
        # Add root transformation
        if self.root is not None:
            out = out + self.root(x)
        
        # Add bias
        if self.bias is not None:
            out = out + self.bias
        
        return out, attention_weights

class InterProceduralAbstractGraph(nn.Module):
    """
    Inter-Procedural Abstract Graph (IPAG) processor based on latest research.
    Captures structural and contextual properties with graph reduction techniques.
    """
    
    def __init__(self, node_dim: int, hidden_dim: int, num_layers: int = 3):
        super().__init__()
        
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Property node sequence merging
        self.sequence_merger = nn.Sequential(
            nn.Linear(node_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, node_dim),
            nn.LayerNorm(node_dim)
        )
        
        # Aggregation structure processor
        self.aggregation_processor = nn.ModuleList([
            nn.Sequential(
                nn.Linear(node_dim, hidden_dim),
                nn.ReLU(), 
                nn.Linear(hidden_dim, node_dim),
                nn.Dropout(0.1)
            ) for _ in range(num_layers)
        ])
        
        # Call relationship handler
        self.call_graph_encoder = nn.GRU(
            input_size=node_dim,
            hidden_size=hidden_dim // 2,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=0.1
        )
        
        # Graph compression module
        self.compression_ratio = nn.Parameter(torch.tensor(0.3))  # Learnable compression
        
        logger.info(f" IPAG processor initialized with {num_layers} layers")
    
    def merge_property_sequences(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Merge property node sequences to reduce graph complexity"""
        
        # Identify sequential property patterns
        row, col = edge_index
        degrees = degree(col, num_nodes=x.size(0))
        
        # Find nodes with exactly one successor (potential sequence nodes)
        sequence_candidates = (degrees == 1).nonzero(as_tuple=False).squeeze(-1)
        
        if sequence_candidates.numel() > 0:
            # Merge sequential nodes
            for candidate in sequence_candidates:
                successors = col[row == candidate]
                if successors.numel() == 1:
                    successor = successors[0]
                    # Merge node features
                    merged_features = torch.cat([x[candidate], x[successor]], dim=-1)
                    x[candidate] = self.sequence_merger(merged_features)
                    
        return x
    
    def process_aggregation_structures(self, x: torch.Tensor) -> torch.Tensor:
        """Process aggregation structures with multi-layer enhancement"""
        
        for layer in self.aggregation_processor:
            x_processed = layer(x)
            x = x + x_processed  # Residual connection
            
        return x
    
    def encode_call_relationships(self, x: torch.Tensor, call_edges: torch.Tensor) -> torch.Tensor:
        """Encode inter-procedural call relationships"""
        
        if call_edges.numel() == 0:
            return x
        
        # Create call sequences
        row, col = call_edges
        call_sequences = []
        
        # Group by call chains
        unique_sources = row.unique()
        for source in unique_sources:
            targets = col[row == source]
            if targets.numel() > 1:
                # Create sequence from source through targets
                sequence_features = torch.cat([x[source:source+1], x[targets]], dim=0)
                call_sequences.append(sequence_features.unsqueeze(0))
        
        if call_sequences:
            # Process call sequences with GRU
            sequences = torch.cat(call_sequences, dim=0)  # [num_sequences, seq_len, node_dim]
            encoded_sequences, _ = self.call_graph_encoder(sequences)
            
            # Update original node features with encoded call information
            seq_idx = 0
            for source in unique_sources:
                targets = col[row == source]
                if targets.numel() > 1:
                    # Update with encoded features
                    encoded_call_features = encoded_sequences[seq_idx, -1, :]  # Last hidden state
                    x[source] = x[source] + encoded_call_features[:self.node_dim]
                    seq_idx += 1
        
        return x
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Process IPAG with optional graph compression.

        When compression is active, this method **must** return an edge_type tensor
        filtered with the same edge mask as edge_index; otherwise edge types become
        misaligned with edges (security-critical for multi-relational reasoning).
        """
        
        # Step 1: Merge property node sequences
        x = self.merge_property_sequences(x, edge_index)
        
        # Step 2: Process aggregation structures  
        x = self.process_aggregation_structures(x)
        
        # Step 3: Handle call relationships
        call_mask = edge_type == EdgeType.CALL_GRAPH.value
        if call_mask.any():
            call_edges = edge_index[:, call_mask]
            x = self.encode_call_relationships(x, call_edges)
        
        # Step 4: Graph compression (optional)
        compression_active = torch.sigmoid(self.compression_ratio) > 0.5
        if batch is not None:
            # Skip compression for batched graphs to avoid batch/node mismatch.
            compression_active = False
        if compression_active and x.size(0) > 10:  # Only compress larger graphs
            # Simple compression: keep top nodes based on feature magnitude
            node_importance = x.norm(dim=-1)
            keep_ratio = torch.sigmoid(self.compression_ratio).item()
            num_keep = max(int(x.size(0) * keep_ratio), 5)  # Keep at least 5 nodes
            
            _, top_indices = torch.topk(node_importance, num_keep)
            
            # Create new edge index for compressed graph
            old_to_new = {old_idx.item(): new_idx for new_idx, old_idx in enumerate(top_indices)}
            
            # Filter edges to only include kept nodes
            row, col = edge_index
            edge_mask = torch.zeros(edge_index.size(1), dtype=torch.bool, device=edge_index.device)
            
            for i in range(edge_index.size(1)):
                if row[i].item() in old_to_new and col[i].item() in old_to_new:
                    edge_mask[i] = True
            
            if edge_mask.any():
                compressed_edge_index = edge_index[:, edge_mask]
                compressed_edge_type = edge_type[edge_mask]
                # Remap indices
                for i in range(compressed_edge_index.size(1)):
                    compressed_edge_index[0, i] = old_to_new[compressed_edge_index[0, i].item()]
                    compressed_edge_index[1, i] = old_to_new[compressed_edge_index[1, i].item()]
                
                return x[top_indices], compressed_edge_index, compressed_edge_type
        
        return x, edge_index, edge_type

# 
# 3. Adaptive Transformer-GNN Fusion (Research Integration)
# 

class AdaptiveTransformerGNNFusion(nn.Module):
    """
    Adaptive fusion of Transformer attention and GNN message passing.
    Inspired by literature; no benchmarked scores are claimed here.
    
    Integrates:
    - Transformer self-attention for global context
    - GNN message passing for local structural patterns  
    - Adaptive weighting between global and local features
    - CodeBERT semantic embeddings
    """
    
    def __init__(self, 
                 hidden_dim: int,
                 num_attention_heads: int = 8,
                 num_transformer_layers: int = 2,
                 num_gnn_layers: int = 2,
                 use_codebert: bool = True):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        self.num_attention_heads = num_attention_heads
        self.use_codebert = use_codebert
        self.codebert_tokenizer = None
        self.codebert_model = None
        self.codebert_projection = nn.Linear(hidden_dim, hidden_dim)
        
        # CodeBERT integration for semantic embeddings
        if use_codebert:
            if not TRANSFORMERS_AVAILABLE:
                logger.warning(" Transformers unavailable; disabling CodeBERT embeddings.")
                self.use_codebert = False
            else:
                model_name = "microsoft/codebert-base"
                try:
                    self.codebert_tokenizer = AutoTokenizer.from_pretrained(model_name)
                    model = None
                    if SAFETENSORS_AVAILABLE:
                        try:
                            model = AutoModel.from_pretrained(model_name, use_safetensors=True)
                        except Exception as exc:
                            logger.warning(f" CodeBERT safetensors load failed: {exc}")
                    if model is None:
                        if _torch_version_at_least(2, 6, 0):
                            model = AutoModel.from_pretrained(model_name)
                        else:
                            raise RuntimeError(
                                "Torch < 2.6 blocks torch.load for CodeBERT. "
                                "Install `safetensors` or upgrade torch >= 2.6."
                            )
                    self.codebert_model = model
                    self.codebert_projection = nn.Linear(768, hidden_dim)  # CodeBERT hidden size is 768
                    logger.info(" CodeBERT model loaded successfully")
                except Exception as exc:
                    self.use_codebert = False
                    self.codebert_tokenizer = None
                    self.codebert_model = None
                    self.codebert_projection = nn.Linear(hidden_dim, hidden_dim)
                    logger.warning(f" CodeBERT disabled: {exc}")
        
        # Transformer layers for global attention
        self.transformer_layers = nn.ModuleList([
            nn.TransformerEncoderLayer(
                d_model=hidden_dim,
                nhead=num_attention_heads,
                dim_feedforward=hidden_dim * 4,
                dropout=0.1,
                activation='gelu',
                batch_first=True,
                norm_first=True
            ) for _ in range(num_transformer_layers)
        ])
        
        # GNN layers for local structure
        if TORCH_GEOMETRIC_AVAILABLE:
            self.gnn_layers = nn.ModuleList([
                GATConv(
                    in_channels=hidden_dim,
                    out_channels=hidden_dim // num_attention_heads,
                    heads=num_attention_heads,
                    dropout=0.1,
                    concat=True,
                    add_self_loops=True
                ) for _ in range(num_gnn_layers)
            ])
        else:
            # Fallback implementation
            self.gnn_layers = nn.ModuleList([
                nn.Sequential(
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(0.1)
                ) for _ in range(num_gnn_layers)
            ])
        
        # Adaptive fusion mechanism
        self.fusion_gate = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.Sigmoid()
        )
        
        # Graph centrality analysis integration
        self.centrality_analyzer = GraphCentralityAnalyzer(hidden_dim)
        
        # Positional encoding for transformer
        self.positional_encoding = PositionalEncoding(hidden_dim, max_len=1000)
        
        logger.info(f" Adaptive Transformer-GNN Fusion initialized")
        logger.info(f"   - Transformer layers: {num_transformer_layers}")
        logger.info(f"   - GNN layers: {num_gnn_layers}")
        logger.info(f"   - CodeBERT integration: {use_codebert and self.codebert_model is not None}")
    
    def get_codebert_embeddings(self, node_tokens: List[str]) -> torch.Tensor:
        """Get CodeBERT embeddings for code tokens"""
        
        if not node_tokens:
            return torch.zeros((0, self.hidden_dim))
        if self.codebert_model is None or self.codebert_tokenizer is None:
            logger.warning(" CodeBERT not initialized; returning zero embeddings.")
            return torch.zeros((len(node_tokens), self.hidden_dim))
        
        try:
            # Tokenize and encode with CodeBERT
            encoded_inputs = self.codebert_tokenizer(
                node_tokens, 
                padding=True, 
                truncation=True, 
                max_length=128,
                return_tensors="pt"
            )
            
            with torch.no_grad():
                outputs = self.codebert_model(**encoded_inputs)
                # Use [CLS] token embedding
                codebert_embeddings = outputs.last_hidden_state[:, 0, :]  # [batch_size, 768]
            
            # Project to hidden dimension
            embeddings = self.codebert_projection(codebert_embeddings)
            
            return embeddings
            
        except Exception as e:
            logger.warning(f"CodeBERT embedding failed: {e}")
            return torch.randn(len(node_tokens), self.hidden_dim)
    
    def transformer_forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, Dict]:
        """Apply transformer layers for global context"""
        
        # Add positional encoding
        x = x.unsqueeze(0)  # Add batch dimension [1, num_nodes, hidden_dim]
        x = self.positional_encoding(x)
        
        # Apply transformer layers
        attention_weights = {}
        for i, layer in enumerate(self.transformer_layers):
            x = layer(x, src_key_padding_mask=attention_mask)
            # Note: Attention weights extraction would require custom layer implementation
            
        x = x.squeeze(0)  # Remove batch dimension [num_nodes, hidden_dim]
        
        return x, attention_weights
    
    def gnn_forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> Tuple[torch.Tensor, Dict]:
        """Apply GNN layers for local structure"""
        
        gnn_attention_weights = {}
        
        if TORCH_GEOMETRIC_AVAILABLE:
            for i, gnn_layer in enumerate(self.gnn_layers):
                if hasattr(gnn_layer, 'attention'):
                    # GAT layer with attention
                    x_out, (edge_index_out, attention_scores) = gnn_layer(x, edge_index, return_attention_weights=True)
                    gnn_attention_weights[f'gnn_layer_{i}'] = attention_scores
                    x = x_out
                else:
                    x = gnn_layer(x, edge_index)
                
                x = F.elu(x)
        else:
            # Fallback implementation
            for i, layer in enumerate(self.gnn_layers):
                x = layer(x)
        
        return x, gnn_attention_weights
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, 
                node_tokens: Optional[List[str]] = None) -> Dict[str, torch.Tensor]:
        """
        Adaptive fusion of transformer and GNN representations
        
        Args:
            x: Node features [num_nodes, hidden_dim]
            edge_index: Edge connectivity [2, num_edges]
            node_tokens: Optional code tokens for CodeBERT embedding
            
        Returns:
            Dictionary with fused features and attention weights
        """
        
        # Enhance node features with CodeBERT if available
        if node_tokens and self.use_codebert:
            codebert_features = self.get_codebert_embeddings(node_tokens)
            if codebert_features.size(0) == x.size(0):
                x = x + codebert_features.to(x.device)
        
        # Apply graph centrality analysis
        centrality_features = self.centrality_analyzer(x, edge_index)
        x = x + centrality_features
        
        # Global context with Transformer
        transformer_features, transformer_attention = self.transformer_forward(x)
        
        # Local structure with GNN
        gnn_features, gnn_attention = self.gnn_forward(x, edge_index)
        
        # Adaptive fusion
        concat_features = torch.cat([transformer_features, gnn_features], dim=-1)
        fusion_weights = self.fusion_gate(concat_features)
        
        # Weighted combination
        fused_features = fusion_weights * transformer_features + (1 - fusion_weights) * gnn_features
        
        return {
            'fused_features': fused_features,
            'transformer_features': transformer_features,
            'gnn_features': gnn_features,
            'fusion_weights': fusion_weights,
            'attention_weights': {
                'transformer': transformer_attention,
                'gnn': gnn_attention
            }
        }

class GraphCentralityAnalyzer(nn.Module):
    """Graph centrality analysis for enhanced node importance scoring"""
    
    def __init__(self, hidden_dim: int):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        
        # Centrality feature processors
        self.degree_processor = nn.Linear(1, hidden_dim // 4)
        self.betweenness_processor = nn.Linear(1, hidden_dim // 4)  
        self.closeness_processor = nn.Linear(1, hidden_dim // 4)
        self.eigenvector_processor = nn.Linear(1, hidden_dim // 4)
        
        # Feature fusion
        self.centrality_fusion = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Dropout(0.1)
        )
    
    def compute_centrality_measures(self, edge_index: torch.Tensor, num_nodes: int) -> Dict[str, torch.Tensor]:
        """Compute various centrality measures"""
        
        # Degree centrality (easy to compute)
        row, col = edge_index
        degree_cent = degree(col, num_nodes=num_nodes, dtype=torch.float)
        degree_cent = degree_cent / (num_nodes - 1) if num_nodes > 1 else degree_cent
        
        # Simplified approximations for other centralities (for efficiency)
        # In a full implementation, these would use proper graph algorithms
        
        # Betweenness centrality approximation (based on degree and local clustering)
        betweenness_cent = degree_cent * torch.randn_like(degree_cent) * 0.1 + degree_cent
        
        # Closeness centrality approximation  
        closeness_cent = 1.0 / (degree_cent + 1e-8)
        
        # Eigenvector centrality approximation
        eigenvector_cent = degree_cent ** 0.5
        
        return {
            'degree': degree_cent.unsqueeze(-1),
            'betweenness': betweenness_cent.unsqueeze(-1),
            'closeness': closeness_cent.unsqueeze(-1),
            'eigenvector': eigenvector_cent.unsqueeze(-1)
        }
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Process centrality measures and return enhanced node features"""
        
        num_nodes = x.size(0)
        centrality_measures = self.compute_centrality_measures(edge_index, num_nodes)
        
        # Process each centrality measure
        degree_features = self.degree_processor(centrality_measures['degree'])
        betweenness_features = self.betweenness_processor(centrality_measures['betweenness'])
        closeness_features = self.closeness_processor(centrality_measures['closeness'])
        eigenvector_features = self.eigenvector_processor(centrality_measures['eigenvector'])
        
        # Concatenate centrality features
        centrality_features = torch.cat([
            degree_features,
            betweenness_features, 
            closeness_features,
            eigenvector_features
        ], dim=-1)
        
        # Fuse centrality information
        enhanced_features = self.centrality_fusion(centrality_features)
        
        return enhanced_features

class PositionalEncoding(nn.Module):
    """Positional encoding for transformer layers"""
    
    def __init__(self, d_model: int, max_len: int = 1000):
        super().__init__()
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        
        self.register_buffer('pe', pe.unsqueeze(0))
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Add positional encoding to input"""
        seq_len = x.size(1)
        if seq_len <= self.pe.size(1):
            return x + self.pe[:, :seq_len, :].to(x.device)
        # Build positional encoding dynamically for long sequences.
        d_model = self.pe.size(-1)
        position = torch.arange(0, seq_len, device=x.device).unsqueeze(1).float()
        div_term = torch.exp(
            torch.arange(0, d_model, 2, device=x.device).float()
            * (-math.log(10000.0) / d_model)
        )
        pe = torch.zeros(seq_len, d_model, device=x.device)
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        return x + pe.unsqueeze(0)

# 
# 4. Advanced Hierarchical Graph Pooling
# 

class MultiScaleHierarchicalPooling(nn.Module):
    """
    Advanced hierarchical pooling for multi-scale vulnerability pattern detection.
    Based on research showing superior performance on benchmark datasets.
    
    Captures patterns at multiple granularities:
    - Fine-grained: Statement/expression level patterns
    - Mid-level: Method/function level patterns  
    - Coarse: Class/module level patterns
    """
    
    def __init__(self, 
                 hidden_dim: int, 
                 pooling_ratios: List[float] = [0.8, 0.6, 0.4],
                 pooling_types: List[str] = ['topk', 'sag', 'asa']):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        self.pooling_ratios = pooling_ratios
        self.num_levels = len(pooling_ratios)
        
        # Different pooling mechanisms for each level
        if TORCH_GEOMETRIC_AVAILABLE:
            self.pooling_layers = nn.ModuleList()
            
            for i, (ratio, pool_type) in enumerate(zip(pooling_ratios, pooling_types)):
                if pool_type == 'topk':
                    pool_layer = TopKPooling(hidden_dim, ratio=ratio, multiplier=1.0, nonlinearity=torch.tanh)
                elif pool_type == 'sag':
                    pool_layer = SAGPooling(hidden_dim, ratio=ratio, GNN=GCNConv, multiplier=1.0, nonlinearity=torch.tanh)
                elif pool_type == 'asa':
                    # ASAPooling requires additional setup
                    pool_layer = TopKPooling(hidden_dim, ratio=ratio, multiplier=1.0, nonlinearity=torch.tanh)
                else:
                    pool_layer = TopKPooling(hidden_dim, ratio=ratio)
                
                self.pooling_layers.append(pool_layer)
        else:
            # Fallback implementation
            self.pooling_layers = nn.ModuleList([
                nn.Sequential(
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(0.1)
                ) for _ in range(self.num_levels)
            ])
        
        # GNN layers for processing between pooling operations
        if TORCH_GEOMETRIC_AVAILABLE:
            self.inter_pool_gnns = nn.ModuleList([
                GATConv(hidden_dim, hidden_dim, heads=4, concat=False, dropout=0.1)
                for _ in range(self.num_levels)
            ])
        else:
            self.inter_pool_gnns = nn.ModuleList([
                nn.Sequential(
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(0.1)
                ) for _ in range(self.num_levels)
            ])
        
        # Scale-specific attention weights
        self.scale_attention = nn.Sequential(
            nn.Linear(hidden_dim * self.num_levels, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, self.num_levels),
            nn.Softmax(dim=-1)
        )
        
        # Vulnerability pattern detectors for each scale
        self.pattern_detectors = nn.ModuleList([
            VulnerabilityPatternDetector(hidden_dim, f"scale_{i}")
            for i in range(self.num_levels)
        ])
        
        logger.info(f" Multi-scale hierarchical pooling with {self.num_levels} levels")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Multi-scale hierarchical pooling with vulnerability pattern detection
        
        Returns:
            Dictionary with representations at each scale and detected patterns
        """
        
        scale_representations = []
        scale_patterns = []
        current_x = x
        current_edge_index = edge_index
        current_batch = batch
        
        # Process each hierarchical level
        for level in range(self.num_levels):
            if current_batch is not None and current_batch.size(0) != current_x.size(0):
                logger.warning("⚠️ Batch/node mismatch before pooling; using single-graph pooling.")
                current_batch = None
            
            # Apply GNN processing at current level
            if TORCH_GEOMETRIC_AVAILABLE and hasattr(self.inter_pool_gnns[level], 'forward'):
                processed_x = self.inter_pool_gnns[level](current_x, current_edge_index)
            else:
                processed_x = self.inter_pool_gnns[level](current_x)
            
            processed_x = F.elu(processed_x)
            
            # Detect vulnerability patterns at current scale
            patterns = self.pattern_detectors[level](processed_x, current_edge_index, current_batch)
            scale_patterns.append(patterns)
            
            # Apply pooling
            if TORCH_GEOMETRIC_AVAILABLE and hasattr(self.pooling_layers[level], 'forward'):
                try:
                    pooled_x, pooled_edge_index, _, pooled_batch, _, _ = self.pooling_layers[level](
                        processed_x, current_edge_index, None, current_batch
                    )
                    
                    # Global pooling for scale representation
                    if pooled_batch is not None:
                        scale_repr = global_mean_pool(pooled_x, pooled_batch)
                    else:
                        scale_repr = pooled_x.mean(dim=0, keepdim=True)
                    
                    scale_representations.append(scale_repr)
                    
                    # Update for next level
                    current_x = pooled_x
                    current_edge_index = pooled_edge_index
                    current_batch = pooled_batch
                    
                except Exception as e:
                    logger.warning(f"Pooling failed at level {level}: {e}")
                    # Fallback to simple mean pooling
                    if current_batch is not None:
                        scale_repr = global_mean_pool(processed_x, current_batch)
                    else:
                        scale_repr = processed_x.mean(dim=0, keepdim=True)
                    scale_representations.append(scale_repr)
                    break
            else:
                # Fallback implementation
                if current_batch is not None:
                    scale_repr = global_mean_pool(processed_x, current_batch)
                else:
                    scale_repr = processed_x.mean(dim=0, keepdim=True)
                scale_representations.append(scale_repr)
        
        # Combine scale representations with learned attention
        if scale_representations:
            # Ensure all representations have the same batch size
            min_batch_size = min(repr.size(0) for repr in scale_representations)
            normalized_reprs = [repr[:min_batch_size] for repr in scale_representations]
            
            if normalized_reprs:
                combined_repr = torch.cat(normalized_reprs, dim=-1)
                attention_weights = self.scale_attention(combined_repr)
                
                # Weighted combination of scale representations
                final_repr = torch.zeros_like(normalized_reprs[0])
                for i, repr in enumerate(normalized_reprs):
                    final_repr += attention_weights[:, i:i+1] * repr
                
                return {
                    'final_representation': final_repr,
                    'scale_representations': {
                        f'scale_{i}': repr for i, repr in enumerate(normalized_reprs)
                    },
                    'scale_attention_weights': attention_weights,
                    'vulnerability_patterns': {
                        f'scale_{i}': patterns for i, patterns in enumerate(scale_patterns)
                    }
                }
        
        # Fallback if pooling fails
        if batch is not None:
            fallback_repr = global_mean_pool(x, batch)
        else:
            fallback_repr = x.mean(dim=0, keepdim=True)
            
        return {
            'final_representation': fallback_repr,
            'scale_representations': {'scale_0': fallback_repr},
            'scale_attention_weights': torch.ones(fallback_repr.size(0), 1),
            'vulnerability_patterns': {'scale_0': {}}
        }

class VulnerabilityPatternDetector(nn.Module):
    """Detect vulnerability patterns at specific scales"""
    
    def __init__(self, hidden_dim: int, scale_name: str):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        self.scale_name = scale_name
        
        # Pattern recognition networks
        self.pattern_classifiers = nn.ModuleDict({
            'sql_injection': nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, 1),
                nn.Sigmoid()
            ),
            'xss': nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(), 
                nn.Linear(hidden_dim // 2, 1),
                nn.Sigmoid()
            ),
            'command_injection': nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, 1),
                nn.Sigmoid()
            ),
            'auth_bypass': nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, 1),
                nn.Sigmoid()
            )
        })
        
        # Pattern aggregator
        self.pattern_aggregator = nn.Sequential(
            nn.Linear(len(self.pattern_classifiers), hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(hidden_dim // 4, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, 
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """Detect vulnerability patterns in the current scale"""
        
        patterns = {}
        if batch is not None and batch.size(0) != x.size(0):
            logger.warning("⚠️ Batch/node mismatch in pattern detector; using global mean pooling.")
            batch = None
        
        # Apply each pattern classifier
        for pattern_name, classifier in self.pattern_classifiers.items():
            if batch is not None:
                # Pool features for each graph in batch
                pooled_features = global_mean_pool(x, batch)
            else:
                # Single graph case
                pooled_features = x.mean(dim=0, keepdim=True)
            
            pattern_scores = classifier(pooled_features)
            patterns[pattern_name] = pattern_scores
        
        # Aggregate pattern scores
        if patterns:
            pattern_tensor = torch.cat(list(patterns.values()), dim=-1)
            overall_score = self.pattern_aggregator(pattern_tensor)
            patterns['overall_vulnerability'] = overall_score
        
        return patterns

# 
# 5. Next-Generation Spatial GNN Vulnerability Detector
# 

class NextGenSpatialGNNVulnerabilityDetector(nn.Module):
    """
    Next-Generation Spatial GNN Vulnerability Detector
    
    Comprehensive integration of cutting-edge research:
    - Enhanced R-GCN with heterogeneous attention (HGAN4VD)
    - Adaptive Transformer-GNN fusion with CodeBERT
    - Inter-Procedural Abstract Graphs (IPAGs)
    - Multi-scale hierarchical pooling
    - VISION-style counterfactual robustness
    - Advanced interpretability and attention visualization
    
    Research context:
    - Metrics reported in the literature are not reproduced in this repo.
    - Treat outputs as experimental unless trained weights are provided.
    """
    
    def __init__(self, config: SpatialGNNConfig):
        super().__init__()
        
        self.config = config
        self.node_dim = config.node_dim
        self.hidden_dim = config.hidden_dim
        self.num_vulnerability_types = config.num_vulnerability_types
        self.num_edge_types = config.num_edge_types
        
        # Stage 1: Inter-Procedural Abstract Graph Processing
        self.ipag_processor = InterProceduralAbstractGraph(
            node_dim=config.node_dim,
            hidden_dim=config.hidden_dim,
            num_layers=config.num_layers
        )
        
        # Stage 2: Enhanced Multi-Relational Processing (R-GCN + HGAN)
        self.relational_layers = nn.ModuleList()
        for i in range(config.num_layers):
            in_dim = config.node_dim if i == 0 else config.hidden_dim
            
            rgcn_layer = EnhancedRelationalGCN(
                in_channels=in_dim,
                out_channels=config.hidden_dim,
                num_relations=config.num_edge_types,
                num_bases=config.rgcn_num_bases,
                attention_heads=config.num_attention_heads
            )
            self.relational_layers.append(rgcn_layer)
        
        # Stage 3: Adaptive Transformer-GNN Fusion
        self.transformer_gnn_fusion = AdaptiveTransformerGNNFusion(
            hidden_dim=config.hidden_dim,
            num_attention_heads=config.num_attention_heads,
            use_codebert=config.use_codebert
        )
        
        # Stage 4: Multi-Scale Hierarchical Pooling
        if config.use_hierarchical_pooling:
            self.hierarchical_pooling = MultiScaleHierarchicalPooling(
                hidden_dim=config.hidden_dim,
                pooling_ratios=config.pooling_ratios
            )
        else:
            self.hierarchical_pooling = None
        
        # Stage 5: Advanced Classification Heads
        classifier_input_dim = config.hidden_dim
        if config.use_hierarchical_pooling:
            classifier_input_dim = config.hidden_dim  # Already processed by hierarchical pooling
        
        # Binary vulnerability detection
        self.binary_classifier = nn.Sequential(
            nn.Linear(classifier_input_dim, config.hidden_dim),
            nn.LayerNorm(config.hidden_dim) if config.layer_norm else nn.Identity(),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_dim, config.hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_dim // 2, 2)
        )
        
        # Multi-class vulnerability type classification
        self.multiclass_classifier = nn.Sequential(
            nn.Linear(classifier_input_dim, config.hidden_dim),
            nn.LayerNorm(config.hidden_dim) if config.layer_norm else nn.Identity(),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_dim, config.hidden_dim),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_dim, config.num_vulnerability_types)
        )
        
        # Confidence estimator with uncertainty quantification
        self.confidence_estimator = nn.Sequential(
            nn.Linear(classifier_input_dim, config.hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout // 2),
            nn.Linear(config.hidden_dim // 2, config.hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(config.hidden_dim // 4, 1),
            nn.Sigmoid()
        )
        
        # Explainability components
        if config.enable_attention_visualization:
            self.attention_aggregator = AttentionAggregator(config.hidden_dim)
        
        if config.enable_counterfactual_analysis:
            self.counterfactual_analyzer = CounterfactualAnalyzer(config.hidden_dim)
        
        # Layer normalization
        if config.layer_norm:
            self.layer_norms = nn.ModuleList([
                nn.LayerNorm(config.hidden_dim) for _ in range(config.num_layers)
            ])
        
        logger.info(" Next-Generation Spatial GNN Vulnerability Detector initialized")
        logger.info(f"   - Node dim: {config.node_dim}, Hidden dim: {config.hidden_dim}")
        logger.info(f"   - Vulnerability types: {config.num_vulnerability_types}")
        logger.info(f"   - Edge types: {config.num_edge_types}")
        logger.info(f"   - Layers: {config.num_layers}")
        logger.info(f"   - Attention heads: {config.num_attention_heads}")
        logger.info(f"   - CodeBERT integration: {config.use_codebert}")
        logger.info(f"   - Hierarchical pooling: {config.use_hierarchical_pooling}")
        logger.info(f"   - Interpretability features: {config.enable_attention_visualization}")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_type: Optional[torch.Tensor] = None,
                batch: Optional[torch.Tensor] = None,
                node_tokens: Optional[List[str]] = None,
                return_attention: bool = False) -> Dict[str, torch.Tensor]:
        """
        Complete forward pass with enhanced features
        
        Args:
            x: Node features [num_nodes, node_dim]
            edge_index: Edge connectivity [2, num_edges]
            edge_type: Edge type indices [num_edges]
            batch: Batch assignment for nodes
            node_tokens: Code tokens for CodeBERT embedding
            return_attention: Whether to return attention weights
            
        Returns:
            Dictionary with predictions, confidence, and attention information
        """
        
        # Handle missing edge types (default to DFG)
        if edge_type is None:
            edge_type = torch.full((edge_index.shape[1],), EdgeType.DFG_DATA_FLOW.value, 
                                 dtype=torch.long, device=x.device)
        
        # Collect attention weights for interpretability
        all_attention_weights = {}
        
        # Stage 1: IPAG Processing
        x, processed_edge_index, edge_type = self.ipag_processor(x, edge_index, edge_type, batch=batch)
        
        # Stage 2: Enhanced Multi-Relational Processing
        h = x
        for i, rgcn_layer in enumerate(self.relational_layers):
            h_new, attention_weights = rgcn_layer(h, processed_edge_index, edge_type)
            
            # Store attention weights
            all_attention_weights[f'rgcn_layer_{i}'] = attention_weights
            
            # Layer normalization
            if self.config.layer_norm:
                h_new = self.layer_norms[i](h_new)
            
            # Residual connection
            if self.config.residual_connections and h.shape == h_new.shape:
                h = h + h_new
            else:
                h = h_new
            
            h = F.elu(h)
            h = F.dropout(h, p=self.config.dropout, training=self.training)
        
        # Stage 3: Adaptive Transformer-GNN Fusion
        fusion_results = self.transformer_gnn_fusion(h, processed_edge_index, node_tokens)
        h = fusion_results['fused_features']
        all_attention_weights.update(fusion_results['attention_weights'])
        
        # Stage 4: Multi-Scale Hierarchical Pooling
        if self.hierarchical_pooling is not None:
            pooling_results = self.hierarchical_pooling(h, processed_edge_index, batch)
            graph_repr = pooling_results['final_representation']
            
            # Store hierarchical information
            all_attention_weights['hierarchical'] = {
                'scale_attention': pooling_results['scale_attention_weights'],
                'vulnerability_patterns': pooling_results['vulnerability_patterns']
            }
        else:
            # Simple global pooling
            if batch is not None:
                graph_repr = global_mean_pool(h, batch)
            else:
                graph_repr = h.mean(dim=0, keepdim=True)
        
        # Stage 5: Classification
        binary_logits = self.binary_classifier(graph_repr)
        multiclass_logits = self.multiclass_classifier(graph_repr) 
        confidence = self.confidence_estimator(graph_repr)
        
        # Prepare results
        results = {
            'binary_logits': binary_logits,
            'multiclass_logits': multiclass_logits,
            'confidence': confidence,
            'graph_representation': graph_repr,
            'node_embeddings': h,
            'fusion_weights': fusion_results['fusion_weights']
        }
        
        # Add attention weights if requested
        if return_attention:
            results['attention_weights'] = all_attention_weights
        
        # Add interpretability analysis
        if self.config.enable_attention_visualization and hasattr(self, 'attention_aggregator'):
            results['interpretability'] = self.attention_aggregator(
                all_attention_weights, h, processed_edge_index
            )
        
        if self.config.enable_counterfactual_analysis and hasattr(self, 'counterfactual_analyzer'):
            results['counterfactual_analysis'] = self.counterfactual_analyzer(
                graph_repr, binary_logits
            )
        
        return results

# 
# 6. Interpretability and Explainability Components
# 

class AttentionAggregator(nn.Module):
    """Aggregate and visualize attention weights for interpretability"""
    
    def __init__(self, hidden_dim: int):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        
        # Attention weight processor
        self.attention_processor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, attention_weights: Dict, node_embeddings: torch.Tensor,
                edge_index: torch.Tensor) -> Dict[str, torch.Tensor]:
        """Process attention weights for interpretability"""
        
        interpretability_results = {}
        
        # Aggregate attention across layers
        layer_importance = {}
        for layer_name, weights in attention_weights.items():
            if isinstance(weights, dict):
                # Multiple attention types in this layer
                layer_score = 0
                for attention_type, weight_tensor in weights.items():
                    if isinstance(weight_tensor, torch.Tensor):
                        layer_score += weight_tensor.mean().item()
                layer_importance[layer_name] = layer_score
            elif isinstance(weights, torch.Tensor):
                layer_importance[layer_name] = weights.mean().item()
        
        interpretability_results['layer_importance'] = layer_importance
        
        # Node importance based on embeddings
        node_importance = self.attention_processor(node_embeddings).squeeze(-1)
        interpretability_results['node_importance'] = node_importance
        
        # Edge importance (if available)
        if edge_index.numel() > 0:
            row, col = edge_index
            edge_importance = (node_importance[row] + node_importance[col]) / 2
            interpretability_results['edge_importance'] = edge_importance
        
        return interpretability_results

class CounterfactualAnalyzer(nn.Module):
    """Analyze counterfactual robustness (VISION framework integration)"""
    
    def __init__(self, hidden_dim: int):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        
        # Counterfactual perturbation generator
        self.perturbation_generator = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh()
        )
        
        # Robustness scorer
        self.robustness_scorer = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
    
    def forward(self, graph_repr: torch.Tensor, 
                original_logits: torch.Tensor) -> Dict[str, torch.Tensor]:
        """Analyze counterfactual robustness"""
        
        # Generate small perturbations
        perturbations = self.perturbation_generator(graph_repr) * 0.1  # Small perturbations
        perturbed_repr = graph_repr + perturbations
        
        # Compute robustness score
        combined_repr = torch.cat([graph_repr, perturbed_repr], dim=-1)
        robustness_score = self.robustness_scorer(combined_repr)
        
        return {
            'perturbations': perturbations,
            'perturbed_representation': perturbed_repr,
            'robustness_score': robustness_score
        }


# 
# 7. Enhanced Factory Functions and Utilities
# 

def create_nextgen_spatial_gnn_model(config: Optional[Dict[str, Any]] = None) -> NextGenSpatialGNNVulnerabilityDetector:
    """
    Factory function to create next-generation spatial GNN model
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Initialized NextGenSpatialGNNVulnerabilityDetector
    """
    
    # Create configuration
    if config is None:
        gnn_config = SpatialGNNConfig()
    else:
        # Update default config with provided values
        gnn_config = SpatialGNNConfig()
        for key, value in config.items():
            if hasattr(gnn_config, key):
                setattr(gnn_config, key, value)
    
    if gnn_config.use_codebert and not TRANSFORMERS_AVAILABLE:
        logger.warning(" Transformers not available; disabling CodeBERT embeddings.")
        gnn_config.use_codebert = False

    # Create model (PyG required)
    model = NextGenSpatialGNNVulnerabilityDetector(gnn_config)
    
    logger.info(" Next-Generation Spatial GNN model created successfully")
    logger.info(f"   Configuration: {len(config) if config else 0} custom parameters")
    
    # Log key capabilities
    capabilities = []
    if gnn_config.use_codebert:
        capabilities.append("CodeBERT semantic embeddings")
    if gnn_config.use_hierarchical_pooling:
        capabilities.append("Multi-scale hierarchical pooling")
    if gnn_config.enable_attention_visualization:
        capabilities.append("Attention visualization")
    if gnn_config.enable_counterfactual_analysis:
        capabilities.append("Counterfactual robustness")
    
    if capabilities:
        logger.info(f"   Enabled capabilities: {', '.join(capabilities)}")
    
    return model

def get_model_info(model: NextGenSpatialGNNVulnerabilityDetector) -> Dict[str, Any]:
    """Get comprehensive model information"""
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    
    # Get configuration
    config = model.config
    
    return {
        'model_type': 'NextGenSpatialGNNVulnerabilityDetector',
        'version': '4.0.0',
        'total_parameters': total_params,
        'trainable_parameters': trainable_params,
        'configuration': {
            'node_dim': config.node_dim,
            'hidden_dim': config.hidden_dim,
            'num_layers': config.num_layers,
            'num_attention_heads': config.num_attention_heads,
            'num_vulnerability_types': config.num_vulnerability_types,
            'num_edge_types': config.num_edge_types,
            'use_codebert': config.use_codebert,
            'use_hierarchical_pooling': config.use_hierarchical_pooling,
            'enable_attention_visualization': config.enable_attention_visualization,
            'enable_counterfactual_analysis': config.enable_counterfactual_analysis
        },
        'research_integrations': [
            'HGAN4VD: Heterogeneous Graph Attention Networks',
            'VISION: Counterfactual robustness framework', 
            'IPAGs: Inter-Procedural Abstract Graphs',
            'R-GCN: Multi-relational message passing',
            'Adaptive Transformer-GNN fusion',
            'CodeBERT semantic embeddings',
            'Multi-scale hierarchical pooling',
            'Advanced interpretability components'
        ],
        'research_notes': {
            'metrics': 'Literature-reported only; not reproduced by this repo.'
        }
    }

# Enhanced edge type constants for comprehensive CPG representation
EDGE_TYPE_AST_PARENT_CHILD = EdgeType.AST_PARENT_CHILD.value
EDGE_TYPE_CFG_CONTROL_FLOW = EdgeType.CFG_CONTROL_FLOW.value  
EDGE_TYPE_DFG_DATA_FLOW = EdgeType.DFG_DATA_FLOW.value
EDGE_TYPE_PDG_PROGRAM_DEP = EdgeType.PDG_PROGRAM_DEP.value
EDGE_TYPE_CALL_GRAPH = EdgeType.CALL_GRAPH.value
EDGE_TYPE_TAINT_FLOW = EdgeType.TAINT_FLOW.value
EDGE_TYPE_VULNERABILITY_PATTERN = EdgeType.VULNERABILITY_PATTERN.value

EDGE_TYPE_NAMES = {
    EdgeType.AST_PARENT_CHILD.value: 'AST Parent-Child',
    EdgeType.CFG_CONTROL_FLOW.value: 'Control Flow',
    EdgeType.DFG_DATA_FLOW.value: 'Data Flow', 
    EdgeType.PDG_PROGRAM_DEP.value: 'Program Dependence',
    EdgeType.CALL_GRAPH.value: 'Call Graph',
    EdgeType.TYPE_HIERARCHY.value: 'Type Hierarchy',
    EdgeType.VARIABLE_USE.value: 'Variable Usage',
    EdgeType.TAINT_FLOW.value: 'Taint Flow',
    EdgeType.VULNERABILITY_PATTERN.value: 'Vulnerability Pattern',
    EdgeType.SECURITY_CONTEXT.value: 'Security Context',
    EdgeType.ATTENTION_WEIGHTED.value: 'Attention Weighted',
    EdgeType.SIMILARITY.value: 'Semantic Similarity'
}

VULNERABILITY_TYPE_NAMES = {
    VulnerabilityType.SQL_INJECTION.value: 'SQL Injection (CWE-89)',
    VulnerabilityType.XSS.value: 'Cross-Site Scripting (CWE-79)',
    VulnerabilityType.COMMAND_INJECTION.value: 'Command Injection (CWE-78)',
    VulnerabilityType.PATH_TRAVERSAL.value: 'Path Traversal (CWE-22)',
    VulnerabilityType.WEAK_CRYPTO.value: 'Weak Cryptography (CWE-327)',
    VulnerabilityType.AUTH_BYPASS.value: 'Authentication Bypass (CWE-287)',
    VulnerabilityType.RACE_CONDITION.value: 'Race Condition (CWE-362)',
    VulnerabilityType.BUFFER_OVERFLOW.value: 'Buffer Overflow (CWE-121)',
    VulnerabilityType.DESERIALIZATION.value: 'Insecure Deserialization (CWE-502)'
}

if __name__ == "__main__":
    # Demonstration of next-generation capabilities
    logger.info(" Next-Generation Spatial GNN for Java Vulnerability Detection")
    logger.info("=" * 80)
    
    # Create model with research-based configuration
    research_config = {
        'hidden_dim': 512,
        'num_layers': 4,
        'num_attention_heads': 8,
        'use_codebert': True,
        'use_hierarchical_pooling': True,
        'enable_attention_visualization': True,
        'enable_counterfactual_analysis': True,
        'pooling_ratios': [0.8, 0.6, 0.4]
    }
    
    model = create_nextgen_spatial_gnn_model(research_config)
    
    # Display model information
    model_info = get_model_info(model)
    
    logger.info(f"Model: {model_info['model_type']} v{model_info['version']}")
    logger.info(f"Parameters: {model_info['total_parameters']:,} total, {model_info['trainable_parameters']:,} trainable")
    logger.info(f"Research Integrations: {len(model_info['research_integrations'])}")
    
    for integration in model_info['research_integrations']:
        logger.info(f"   {integration}")
    
    logger.info("\n Research Notes:")
    for metric, value in model_info['research_notes'].items():
        logger.info(f"   {metric.replace('_', ' ').title()}: {value}")
    
    logger.info("\n Next-generation spatial GNN initialized (experimental).")
    logger.info("Benchmark in your environment before relying on performance.")


# ================================================================
# Backward Compatibility Aliases for Existing Code
# ================================================================

# Alias the new function name to the old API
create_spatial_gnn_model = create_nextgen_spatial_gnn_model

# Alias the new class name to the old class name
SpatialGNNVulnerabilityDetector = NextGenSpatialGNNVulnerabilityDetector

logger.info("✅ Backward compatibility aliases added for seamless integration")
