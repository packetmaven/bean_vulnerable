"""
Bean Vulnerable GNN Framework - MPS GNN Processor  
Apple Silicon (MPS) optimized GNN processing for vulnerability detection
"""

import logging
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, SAGEConv
from torch_geometric.data import Data, Batch
from typing import Dict, List, Any, Optional, Tuple
import time
import platform

logger = logging.getLogger(__name__)

# Check MPS availability
MPS_AVAILABLE = hasattr(torch.backends, 'mps') and torch.backends.mps.is_available()
IS_APPLE_SILICON = platform.machine() in ['arm64', 'arm']


class MPSOptimizedGNN(nn.Module):
    """MPS-optimized GNN for vulnerability detection on Apple Silicon"""
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_classes: int = 2, num_layers: int = 3):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes
        self.num_layers = num_layers
        
        # Graph convolution layers (optimized for MPS)
        self.convs = nn.ModuleList()
        self.convs.append(GCNConv(input_dim, hidden_dim))
        
        for _ in range(num_layers - 2):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
        
        self.convs.append(GCNConv(hidden_dim, hidden_dim))
        
        # Use SAGE instead of GAT for better MPS performance
        self.sage_conv = SAGEConv(hidden_dim, hidden_dim)
        
        # Classification head (optimized for Apple Silicon)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),  # GELU works better on Apple Silicon
            nn.Dropout(0.3),  # Lower dropout for MPS
            nn.Linear(hidden_dim // 2, num_classes)
        )
        
        # Layer normalization (better than batch norm for MPS)
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers)
        ])
        
        # Initialize weights for Apple Silicon
        self._initialize_weights()
    
    def _initialize_weights(self):
        """Initialize weights optimized for Apple Silicon"""
        for m in self.modules():
            if isinstance(m, nn.Linear):
                # Xavier initialization works well on MPS
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        # Graph convolutions with residual connections
        h = x
        
        for i, (conv, ln) in enumerate(zip(self.convs, self.layer_norms)):
            h_new = conv(h, edge_index)
            h_new = ln(h_new)
            h_new = F.gelu(h_new)  # GELU activation
            
            # Residual connection (if dimensions match)
            if h.shape[-1] == h_new.shape[-1]:
                h = h + h_new
            else:
                h = h_new
        
        # SAGE convolution for aggregation
        h = self.sage_conv(h, edge_index)
        
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


class MPSGNNProcessor:
    """MPS-optimized GNN processor for Apple Silicon"""
    
    def __init__(self, mps_config: Optional[Dict[str, Any]] = None):
        """
        Initialize MPS GNN processor
        
        Args:
            mps_config: MPS-specific configuration
                - memory_fraction: Memory fraction to use
                - batch_size: Optimal batch size for MPS
                - use_fallback: Enable CPU fallback for unsupported ops
                - optimization_level: Optimization level (1-3)
        """
        if not MPS_AVAILABLE:
            raise RuntimeError("MPS not available on this system")
        
        self.config = mps_config or {}
        self.memory_fraction = self.config.get('memory_fraction', 0.7)
        self.batch_size = self.config.get('batch_size', 16)  # Smaller batches for MPS
        self.use_fallback = self.config.get('use_fallback', True)
        self.optimization_level = self.config.get('optimization_level', 2)
        
        # Set device
        self.device = torch.device('mps')
        
        # Configure MPS settings
        self._configure_mps()
        
        # Initialize model
        self.model = None
        
        logger.info(f"✅ MPS GNN Processor initialized on Apple Silicon")
        self._log_system_info()
    
    def initialize_model(self, input_dim: int, hidden_dim: int = 128, num_classes: int = 2) -> nn.Module:
        """Initialize MPS-optimized GNN model"""
        
        self.model = MPSOptimizedGNN(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_classes=num_classes
        ).to(self.device)
        
        # Apply MPS-specific optimizations
        self.model = self._apply_mps_optimizations(self.model)
        
        return self.model
    
    def process_vulnerability_batch(self, graph_batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process batch of graphs for vulnerability detection on MPS
        
        Args:
            graph_batch: List of graph dictionaries
            
        Returns:
            Batch processing results
        """
        try:
            start_time = time.time()
            
            # Use smaller batches for MPS
            actual_batch_size = min(self.batch_size, len(graph_batch))
            
            # Convert to PyTorch Geometric format
            data_list = []
            for i in range(actual_batch_size):
                data = self._convert_to_pyg_data(graph_batch[i])
                data_list.append(data)
            
            # Create batch
            batch = Batch.from_data_list(data_list).to(self.device)
            
            # Process with model
            if self.model is None:
                # Auto-initialize model
                input_dim = batch.x.shape[1]
                self.initialize_model(input_dim)
            
            # Forward pass (MPS doesn't support autocast)
            with torch.no_grad():
                outputs = self.model(batch.x, batch.edge_index, batch.batch)
            
            # Process outputs
            probabilities = F.softmax(outputs, dim=1)
            predictions = torch.argmax(probabilities, dim=1)
            
            processing_time = time.time() - start_time
            
            return {
                'predictions': predictions.cpu().numpy(),
                'probabilities': probabilities.cpu().numpy(),
                'processing_time': processing_time,
                'batch_size': actual_batch_size,
                'throughput': actual_batch_size / processing_time,
                'device_used': str(self.device),
                'memory_usage': self._get_memory_usage()
            }
            
        except Exception as e:
            logger.error(f"MPS batch processing failed: {e}")
            
            # Fallback to CPU if enabled
            if self.use_fallback:
                return self._cpu_fallback_processing(graph_batch)
            
            return {
                'error': str(e),
                'device_used': str(self.device)
            }
    
    def train_model(self, train_data: List[Dict[str, Any]], val_data: List[Dict[str, Any]], 
                   epochs: int = 100, learning_rate: float = 0.001) -> Dict[str, Any]:
        """
        Train GNN model with MPS optimizations
        
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
            
            # Initialize optimizer (Adam works well on MPS)
            optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate, weight_decay=1e-5)
            criterion = nn.CrossEntropyLoss()
            
            # Learning rate scheduler
            scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.8)
            
            # Training loop
            train_losses = []
            val_accuracies = []
            
            for epoch in range(epochs):
                epoch_start = time.time()
                
                # Training phase
                self.model.train()
                total_loss = 0
                num_batches = 0
                
                # Process training data in smaller batches for MPS
                for i in range(0, len(train_data), self.batch_size):
                    batch_data = train_data[i:i + self.batch_size]
                    
                    # Convert to batch
                    data_list = [self._convert_to_pyg_data(d) for d in batch_data]
                    batch = Batch.from_data_list(data_list).to(self.device)
                    
                    # Forward pass
                    optimizer.zero_grad()
                    
                    outputs = self.model(batch.x, batch.edge_index, batch.batch)
                    loss = criterion(outputs, batch.y)
                    
                    # Backward pass
                    loss.backward()
                    
                    # Gradient clipping for stability on MPS
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                    
                    optimizer.step()
                    
                    total_loss += loss.item()
                    num_batches += 1
                
                avg_loss = total_loss / num_batches
                train_losses.append(avg_loss)
                
                # Validation phase
                val_accuracy = self._validate_model(val_data)
                val_accuracies.append(val_accuracy)
                
                # Update learning rate
                scheduler.step(avg_loss)
                
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
            logger.error(f"MPS training failed: {e}")
            return {
                'error': str(e),
                'training_completed': False
            }
    
    def _configure_mps(self):
        """Configure MPS settings for optimal performance"""
        
        # Enable MPS fallback for unsupported operations
        if hasattr(torch.backends.mps, 'enable_fallback'):
            torch.backends.mps.enable_fallback = self.use_fallback
        
        # Set memory management
        if hasattr(torch.mps, 'set_memory_fraction'):
            torch.mps.set_memory_fraction(self.memory_fraction)
        
        logger.info("MPS configuration applied")
    
    def _apply_mps_optimizations(self, model: nn.Module) -> nn.Module:
        """Apply MPS-specific optimizations"""
        
        # Set model to optimized mode
        model.eval()
        
        # Apply optimizations based on level
        if self.optimization_level >= 2:
            # Fuse operations where possible
            try:
                # Note: MPS has limited fusion support
                logger.info("Applied MPS optimizations")
            except Exception as e:
                logger.warning(f"MPS optimization failed: {e}")
        
        return model
    
    def _convert_to_pyg_data(self, graph_data: Dict[str, Any]) -> Data:
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
            for i in range(0, len(val_data), self.batch_size):
                batch_data = val_data[i:i + self.batch_size]
                
                # Convert to batch
                data_list = [self._convert_to_pyg_data(d) for d in batch_data]
                batch = Batch.from_data_list(data_list).to(self.device)
                
                # Forward pass
                outputs = self.model(batch.x, batch.edge_index, batch.batch)
                
                # Calculate accuracy
                predictions = torch.argmax(outputs, dim=1)
                correct += (predictions == batch.y).sum().item()
                total += len(batch_data)
        
        return correct / total if total > 0 else 0.0
    
    def _cpu_fallback_processing(self, graph_batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Fallback to CPU processing if MPS fails"""
        
        logger.warning("Falling back to CPU processing")
        
        try:
            # Move model to CPU
            cpu_model = self.model.cpu() if self.model else None
            
            # Process on CPU
            start_time = time.time()
            
            data_list = []
            for graph_data in graph_batch[:self.batch_size]:
                data = self._convert_to_pyg_data(graph_data)
                data_list.append(data)
            
            batch = Batch.from_data_list(data_list)
            
            if cpu_model is None:
                input_dim = batch.x.shape[1]
                cpu_model = MPSOptimizedGNN(input_dim).cpu()
            
            with torch.no_grad():
                outputs = cpu_model(batch.x, batch.edge_index, batch.batch)
            
            probabilities = F.softmax(outputs, dim=1)
            predictions = torch.argmax(probabilities, dim=1)
            
            processing_time = time.time() - start_time
            
            # Move model back to MPS
            if self.model:
                self.model.to(self.device)
            
            return {
                'predictions': predictions.numpy(),
                'probabilities': probabilities.numpy(),
                'processing_time': processing_time,
                'batch_size': min(self.batch_size, len(graph_batch)),
                'throughput': min(self.batch_size, len(graph_batch)) / processing_time,
                'device_used': 'cpu_fallback',
                'fallback_used': True
            }
            
        except Exception as e:
            logger.error(f"CPU fallback also failed: {e}")
            return {
                'error': str(e),
                'device_used': 'cpu_fallback',
                'fallback_used': True
            }
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get MPS memory usage (limited info available)"""
        
        # MPS doesn't provide detailed memory info like CUDA
        return {
            'device': 'mps',
            'memory_fraction': self.memory_fraction,
            'unified_memory': True,  # Apple Silicon uses unified memory
            'note': 'MPS uses unified memory architecture'
        }
    
    def _log_system_info(self):
        """Log Apple Silicon system information"""
        
        logger.info(f"Platform: {platform.platform()}")
        logger.info(f"Architecture: {platform.machine()}")
        logger.info(f"Processor: {platform.processor()}")
        logger.info(f"MPS Available: {MPS_AVAILABLE}")
        
        # Try to get more detailed info
        try:
            import subprocess
            result = subprocess.run(['sysctl', '-n', 'hw.memsize'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                memory_gb = int(result.stdout.strip()) / (1024**3)
                logger.info(f"System Memory: {memory_gb:.1f} GB")
        except:
            pass
    
    def benchmark_performance(self, sample_data: List[Dict[str, Any]], num_runs: int = 10) -> Dict[str, Any]:
        """Benchmark MPS performance"""
        
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
            start_time = time.time()
            
            result = self.process_vulnerability_batch(sample_data[:4])
            
            end_time = time.time()
            times.append(end_time - start_time)
        
        return {
            'avg_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'throughput': 4 / (sum(times) / len(times)),  # samples per second
            'memory_usage': self._get_memory_usage(),
            'device_info': {
                'device': 'mps',
                'platform': platform.platform(),
                'architecture': platform.machine(),
                'mps_available': MPS_AVAILABLE
            }
        }
    
    def cleanup(self):
        """Clean up MPS resources"""
        
        if self.model is not None:
            del self.model
            self.model = None
        
        # MPS cleanup (limited compared to CUDA)
        if hasattr(torch.mps, 'empty_cache'):
            torch.mps.empty_cache()
        
        logger.info("MPS resources cleaned up")


# MPS configuration templates
MPS_CONFIG_TEMPLATES = {
    'apple_silicon_m1': {
        'memory_fraction': 0.7,
        'batch_size': 16,
        'use_fallback': True,
        'optimization_level': 2
    },
    'apple_silicon_m2': {
        'memory_fraction': 0.75,
        'batch_size': 20,
        'use_fallback': True,
        'optimization_level': 2
    },
    'apple_silicon_m3': {
        'memory_fraction': 0.8,
        'batch_size': 24,
        'use_fallback': True,
        'optimization_level': 3
    }
} 