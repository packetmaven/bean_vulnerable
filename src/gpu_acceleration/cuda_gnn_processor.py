"""
Bean Vulnerable GNN Framework - CUDA GNN Processor
NVIDIA CUDA optimized GNN processing for vulnerability detection
"""

import logging
import torch
import torch.nn as nn
import torch.nn.functional as F
try:  # optional import; module is only valid on CUDA setups with PyG
    from torch_geometric.nn import GCNConv, GATConv, SAGEConv  # type: ignore
    from torch_geometric.data import Data, Batch  # type: ignore
    _PYG_AVAILABLE = True
except Exception:  # pragma: no cover
    _PYG_AVAILABLE = False
from typing import Dict, List, Any, Optional, Tuple
import time

logger = logging.getLogger(__name__)

# Check CUDA availability
CUDA_AVAILABLE = torch.cuda.is_available()
if CUDA_AVAILABLE:
    try:
        # Check for advanced CUDA features
        import torch.cuda.amp
        AMP_AVAILABLE = True
    except ImportError:
        AMP_AVAILABLE = False
else:
    AMP_AVAILABLE = False


class CUDAOptimizedGNN(nn.Module):
    """CUDA-optimized GNN for vulnerability detection"""
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_classes: int = 2, num_layers: int = 3):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes
        self.num_layers = num_layers
        
        # Graph convolution layers
        self.convs = nn.ModuleList()
        self.convs.append(GCNConv(input_dim, hidden_dim))
        
        for _ in range(num_layers - 2):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
        
        self.convs.append(GCNConv(hidden_dim, hidden_dim))
        
        # Attention mechanism
        self.attention = GATConv(hidden_dim, hidden_dim, heads=8, concat=False)
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(hidden_dim // 2, num_classes)
        )
        
        # Batch normalization for stability
        self.batch_norms = nn.ModuleList([
            nn.BatchNorm1d(hidden_dim) for _ in range(num_layers)
        ])
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        # Graph convolutions with residual connections
        h = x
        
        for i, (conv, bn) in enumerate(zip(self.convs, self.batch_norms)):
            h_new = conv(h, edge_index)
            h_new = bn(h_new)
            h_new = F.relu(h_new)
            
            # Residual connection (if dimensions match)
            if h.shape[-1] == h_new.shape[-1]:
                h = h + h_new
            else:
                h = h_new
        
        # Attention mechanism
        h = self.attention(h, edge_index)
        
        # Global pooling
        if batch is not None:
            # Graph-level prediction
            from torch_geometric.nn import global_mean_pool
            h = global_mean_pool(h, batch)
        else:
            # Node-level prediction (take mean)
            h = h.mean(dim=0, keepdim=True)
        
        # Classification
        out = self.classifier(h)
        
        return out


class CUDAGNNProcessor:
    """CUDA-optimized GNN processor for vulnerability detection"""
    
    def __init__(self, cuda_config: Optional[Dict[str, Any]] = None):
        """
        Initialize CUDA GNN processor
        
        Args:
            cuda_config: CUDA-specific configuration
                - device_id: CUDA device ID
                - mixed_precision: Use automatic mixed precision
                - memory_fraction: GPU memory fraction to use
                - cudnn_benchmark: Enable cuDNN benchmarking
                - compile_model: Use torch.compile (PyTorch 2.0+)
        """
        if not CUDA_AVAILABLE or not _PYG_AVAILABLE:
            raise RuntimeError("CUDA/PyG not available")
        
        self.config = cuda_config or {}
        self.device_id = self.config.get('device_id', 0)
        self.mixed_precision = self.config.get('mixed_precision', AMP_AVAILABLE)
        self.memory_fraction = self.config.get('memory_fraction', 0.8)
        self.cudnn_benchmark = self.config.get('cudnn_benchmark', True)
        self.compile_model = self.config.get('compile_model', False)
        
        # Set device
        self.device = torch.device(f'cuda:{self.device_id}')
        torch.cuda.set_device(self.device)
        
        # Configure CUDA settings
        self._configure_cuda()
        
        # Initialize model
        self.model = None
        self.scaler = None
        
        if self.mixed_precision:
            self.scaler = torch.cuda.amp.GradScaler()
        
        logger.info(f"✅ CUDA GNN Processor initialized on device {self.device}")
        self._log_gpu_info()
    
    def initialize_model(self, input_dim: int, hidden_dim: int = 128, num_classes: int = 2) -> nn.Module:
        """Initialize CUDA-optimized GNN model"""
        
        self.model = CUDAOptimizedGNN(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_classes=num_classes
        ).to(self.device)
        
        # Compile model if requested (PyTorch 2.0+)
        if self.compile_model and hasattr(torch, 'compile'):
            try:
                self.model = torch.compile(self.model, mode='max-autotune')
                logger.info("Applied torch.compile optimization")
            except Exception as e:
                logger.warning(f"torch.compile failed: {e}")
        
        return self.model
    
    def process_vulnerability_batch(self, graph_batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process batch of graphs for vulnerability detection
        
        Args:
            graph_batch: List of graph dictionaries
            
        Returns:
            Batch processing results
        """
        try:
            start_time = time.time()
            
            # Convert to PyTorch Geometric format
            data_list = []
            for graph_data in graph_batch:
                data = self._convert_to_pyg_data(graph_data)
                data_list.append(data)
            
            # Create batch
            batch = Batch.from_data_list(data_list).to(self.device)
            
            # Process with model
            if self.model is None:
                # Auto-initialize model
                input_dim = batch.x.shape[1]
                self.initialize_model(input_dim)
            
            # Forward pass
            with torch.no_grad():
                if self.mixed_precision:
                    with torch.cuda.amp.autocast():
                        outputs = self.model(batch.x, batch.edge_index, batch.batch)
                else:
                    outputs = self.model(batch.x, batch.edge_index, batch.batch)
            
            # Process outputs
            probabilities = F.softmax(outputs, dim=1)
            predictions = torch.argmax(probabilities, dim=1)
            
            processing_time = time.time() - start_time
            
            return {
                'predictions': predictions.cpu().numpy(),
                'probabilities': probabilities.cpu().numpy(),
                'processing_time': processing_time,
                'batch_size': len(graph_batch),
                'throughput': len(graph_batch) / processing_time,
                'device_used': str(self.device),
                'memory_usage': self._get_memory_usage()
            }
            
        except Exception as e:
            logger.error(f"CUDA batch processing failed: {e}")
            return {
                'error': str(e),
                'device_used': str(self.device)
            }
    
    def train_model(self, train_data: List[Dict[str, Any]], val_data: List[Dict[str, Any]], 
                   epochs: int = 100, learning_rate: float = 0.001) -> Dict[str, Any]:
        """
        Train GNN model with CUDA optimizations
        
        Args:
            train_data: Training graph data
            val_data: Validation graph data
            epochs: Number of training epochs
            learning_rate: Learning rate
            
        Returns:
            Training results
        """
        try:
            # Initialize model if not done
            if self.model is None:
                sample_data = self._convert_to_pyg_data(train_data[0])
                input_dim = sample_data.x.shape[1]
                self.initialize_model(input_dim)
            
            # Set model to training mode
            self.model.train()
            
            # Initialize optimizer
            optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
            criterion = nn.CrossEntropyLoss()
            
            # Training loop
            train_losses = []
            val_accuracies = []
            
            for epoch in range(epochs):
                epoch_start = time.time()
                
                # Training phase
                self.model.train()
                total_loss = 0
                num_batches = 0
                
                # Process training data in batches
                batch_size = 32
                for i in range(0, len(train_data), batch_size):
                    batch_data = train_data[i:i + batch_size]
                    
                    # Convert to batch
                    data_list = [self._convert_to_pyg_data(d) for d in batch_data]
                    batch = Batch.from_data_list(data_list).to(self.device)
                    
                    # Forward pass
                    optimizer.zero_grad()
                    
                    if self.mixed_precision:
                        with torch.cuda.amp.autocast():
                            outputs = self.model(batch.x, batch.edge_index, batch.batch)
                            loss = criterion(outputs, batch.y)
                        
                        # Backward pass with scaling
                        self.scaler.scale(loss).backward()
                        self.scaler.step(optimizer)
                        self.scaler.update()
                    else:
                        outputs = self.model(batch.x, batch.edge_index, batch.batch)
                        loss = criterion(outputs, batch.y)
                        
                        # Backward pass
                        loss.backward()
                        optimizer.step()
                    
                    total_loss += loss.item()
                    num_batches += 1
                
                avg_loss = total_loss / num_batches
                train_losses.append(avg_loss)
                
                # Validation phase
                val_accuracy = self._validate_model(val_data)
                val_accuracies.append(val_accuracy)
                
                epoch_time = time.time() - epoch_start
                
                if epoch % 10 == 0:
                    logger.info(f"Epoch {epoch}/{epochs}: Loss={avg_loss:.4f}, "
                              f"Val Acc={val_accuracy:.4f}, Time={epoch_time:.2f}s")
            
            return {
                'train_losses': train_losses,
                'val_accuracies': val_accuracies,
                'final_val_accuracy': val_accuracies[-1],
                'best_val_accuracy': max(val_accuracies),
                'training_completed': True
            }
            
        except Exception as e:
            logger.error(f"CUDA training failed: {e}")
            return {
                'error': str(e),
                'training_completed': False
            }
    
    def _configure_cuda(self):
        """Configure CUDA settings for optimal performance"""
        
        # Set memory fraction
        torch.cuda.set_per_process_memory_fraction(self.memory_fraction, self.device)
        
        # Configure cuDNN
        torch.backends.cudnn.benchmark = self.cudnn_benchmark
        torch.backends.cudnn.enabled = True
        
        # Enable TensorFloat-32 on Ampere GPUs
        if torch.cuda.get_device_capability(self.device)[0] >= 8:
            torch.backends.cuda.matmul.allow_tf32 = True
            torch.backends.cudnn.allow_tf32 = True
        
        logger.info("CUDA configuration applied")
    
    def _convert_to_pyg_data(self, graph_data: Dict[str, Any]) -> 'Data':
        """Convert graph data to PyTorch Geometric Data format"""
        
        # Extract node features
        if 'node_features' in graph_data:
            x = torch.tensor(graph_data['node_features'], dtype=torch.float)
        else:
            # Create dummy features if not available
            num_nodes = len(graph_data.get('nodes', []))
            x = torch.randn(num_nodes, 16)  # 16-dimensional features
        
        # Extract edges
        if 'edges' in graph_data:
            edge_list = graph_data['edges']
            edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        else:
            # Create empty edge index
            edge_index = torch.empty((2, 0), dtype=torch.long)
        
        # Extract label
        if 'label' in graph_data:
            y = torch.tensor([graph_data['label']], dtype=torch.long)
        else:
            y = torch.tensor([0], dtype=torch.long)  # Default label
        
        return Data(x=x, edge_index=edge_index, y=y)
    
    def _validate_model(self, val_data: List[Dict[str, Any]]) -> float:
        """Validate model on validation data"""
        
        self.model.eval()
        correct = 0
        total = 0
        
        with torch.no_grad():
            # Process validation data in batches
            batch_size = 32
            for i in range(0, len(val_data), batch_size):
                batch_data = val_data[i:i + batch_size]
                
                # Convert to batch
                data_list = [self._convert_to_pyg_data(d) for d in batch_data]
                batch = Batch.from_data_list(data_list).to(self.device)
                
                # Forward pass
                if self.mixed_precision:
                    with torch.cuda.amp.autocast():
                        outputs = self.model(batch.x, batch.edge_index, batch.batch)
                else:
                    outputs = self.model(batch.x, batch.edge_index, batch.batch)
                
                # Calculate accuracy
                predictions = torch.argmax(outputs, dim=1)
                correct += (predictions == batch.y).sum().item()
                total += len(batch_data)
        
        return correct / total if total > 0 else 0.0
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get CUDA memory usage statistics"""
        
        return {
            'allocated': torch.cuda.memory_allocated(self.device),
            'cached': torch.cuda.memory_reserved(self.device),
            'max_allocated': torch.cuda.max_memory_allocated(self.device),
            'max_cached': torch.cuda.max_memory_reserved(self.device)
        }
    
    def _log_gpu_info(self):
        """Log GPU information"""
        
        props = torch.cuda.get_device_properties(self.device)
        logger.info(f"GPU: {props.name}")
        logger.info(f"Memory: {props.total_memory / 1024**3:.1f} GB")
        logger.info(f"Compute Capability: {props.major}.{props.minor}")
        logger.info(f"Multiprocessors: {props.multi_processor_count}")
    
    def benchmark_performance(self, sample_data: List[Dict[str, Any]], num_runs: int = 10) -> Dict[str, Any]:
        """Benchmark CUDA performance"""
        
        if self.model is None:
            sample_graph = self._convert_to_pyg_data(sample_data[0])
            input_dim = sample_graph.x.shape[1]
            self.initialize_model(input_dim)
        
        self.model.eval()
        
        # Warmup
        for _ in range(3):
            result = self.process_vulnerability_batch(sample_data[:4])
        
        # Benchmark
        times = []
        for _ in range(num_runs):
            torch.cuda.synchronize()
            start_time = time.time()
            
            result = self.process_vulnerability_batch(sample_data[:4])
            
            torch.cuda.synchronize()
            end_time = time.time()
            
            times.append(end_time - start_time)
        
        return {
            'avg_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'throughput': 4 / (sum(times) / len(times)),  # samples per second
            'memory_usage': self._get_memory_usage(),
            'device_info': {
                'name': torch.cuda.get_device_name(self.device),
                'compute_capability': torch.cuda.get_device_capability(self.device),
                'memory_total': torch.cuda.get_device_properties(self.device).total_memory
            }
        }
    
    def cleanup(self):
        """Clean up CUDA resources"""
        
        if self.model is not None:
            del self.model
            self.model = None
        
        torch.cuda.empty_cache()
        logger.info("CUDA resources cleaned up")


# CUDA configuration templates
CUDA_CONFIG_TEMPLATES = {
    'gaming_gpu': {
        'device_id': 0,
        'mixed_precision': True,
        'memory_fraction': 0.8,
        'cudnn_benchmark': True,
        'compile_model': False
    },
    'datacenter_gpu': {
        'device_id': 0,
        'mixed_precision': True,
        'memory_fraction': 0.9,
        'cudnn_benchmark': True,
        'compile_model': True
    },
    'multi_gpu': {
        'device_id': 0,
        'mixed_precision': True,
        'memory_fraction': 0.85,
        'cudnn_benchmark': True,
        'compile_model': True
    }
} 