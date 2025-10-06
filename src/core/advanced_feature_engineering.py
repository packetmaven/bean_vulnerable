"""
Bean Vulnerable GNN Framework - Advanced Feature Engineering
Graph Attention Networks, Temporal Graph Networks, and Multi-Scale Analysis
"""

import logging
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import networkx as nx

logger = logging.getLogger(__name__)

# Check for advanced graph libraries
try:
    import torch_geometric
    from torch_geometric.nn import GATConv, TransformerConv, GCNConv, SAGEConv
    from torch_geometric.nn import global_mean_pool, global_max_pool, global_add_pool
    from torch_geometric.data import Data, Batch
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False
    logger.warning("PyTorch Geometric not available - using simplified implementations")


class GraphAttentionNetwork(nn.Module):
    """Advanced Graph Attention Network for vulnerability detection"""
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_heads: int = 8, num_layers: int = 3, dropout: float = 0.1):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.num_layers = num_layers
        self.dropout = dropout
        
        if TORCH_GEOMETRIC_AVAILABLE:
            # Use PyTorch Geometric GAT layers
            self.gat_layers = nn.ModuleList()
            
            # First layer
            self.gat_layers.append(
                GATConv(input_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout, concat=True)
            )
            
            # Hidden layers
            for _ in range(num_layers - 2):
                self.gat_layers.append(
                    GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout, concat=True)
                )
            
            # Output layer
            self.gat_layers.append(
                GATConv(hidden_dim, hidden_dim, heads=1, dropout=dropout, concat=False)
            )
        else:
            # Simplified attention mechanism
            self.attention_layers = nn.ModuleList()
            for i in range(num_layers):
                in_dim = input_dim if i == 0 else hidden_dim
                self.attention_layers.append(
                    nn.MultiheadAttention(in_dim, num_heads, dropout=dropout, batch_first=True)
                )
        
        # Layer normalization
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim) for _ in range(num_layers)
        ])
        
        # Dropout
        self.dropout_layer = nn.Dropout(dropout)
        
        logger.info(f"✅ Graph Attention Network initialized: {num_layers} layers, {num_heads} heads")
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Forward pass through GAT layers"""
        
        if TORCH_GEOMETRIC_AVAILABLE:
            return self._forward_pyg(x, edge_index, batch)
        else:
            return self._forward_simplified(x, edge_index, batch)
    
    def _forward_pyg(self, x: torch.Tensor, edge_index: torch.Tensor, batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Forward pass using PyTorch Geometric"""
        
        h = x
        
        for i, gat_layer in enumerate(self.gat_layers):
            h_new = gat_layer(h, edge_index)
            
            # Apply layer normalization and dropout
            if i < len(self.layer_norms):
                h_new = self.layer_norms[i](h_new)
            h_new = self.dropout_layer(h_new)
            
            # Residual connection (if dimensions match)
            if h.shape[-1] == h_new.shape[-1]:
                h = h + h_new
            else:
                h = h_new
            
            h = F.elu(h)
        
        return h
    
    def _forward_simplified(self, x: torch.Tensor, edge_index: torch.Tensor, batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Simplified forward pass without PyTorch Geometric"""
        
        # Convert to sequence format for attention
        seq_len = x.shape[0]
        x_seq = x.unsqueeze(0)  # Add batch dimension
        
        h = x_seq
        
        for i, attn_layer in enumerate(self.attention_layers):
            h_new, _ = attn_layer(h, h, h)
            
            # Apply layer normalization and dropout
            if i < len(self.layer_norms):
                h_new = self.layer_norms[i](h_new)
            h_new = self.dropout_layer(h_new)
            
            # Residual connection
            if h.shape[-1] == h_new.shape[-1]:
                h = h + h_new
            else:
                h = h_new
            
            h = F.elu(h)
        
        return h.squeeze(0)  # Remove batch dimension


class TemporalGraphNetwork(nn.Module):
    """Temporal Graph Network for tracking code evolution over time"""
    
    def __init__(self, node_dim: int, edge_dim: int = 32, hidden_dim: int = 128, num_layers: int = 3):
        super().__init__()
        
        self.node_dim = node_dim
        self.edge_dim = edge_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Node evolution tracking
        self.node_rnn = nn.LSTM(node_dim, hidden_dim, num_layers, batch_first=True)
        
        # Edge evolution tracking
        self.edge_rnn = nn.LSTM(edge_dim, hidden_dim // 2, num_layers, batch_first=True)
        
        # Temporal attention
        self.temporal_attention = nn.MultiheadAttention(hidden_dim, num_heads=8, batch_first=True)
        
        # Fusion layer
        self.fusion = nn.Sequential(
            nn.Linear(hidden_dim + hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, hidden_dim)
        )
        
        logger.info(f"✅ Temporal Graph Network initialized: {num_layers} LSTM layers")
    
    def forward(self, node_sequences: torch.Tensor, edge_sequences: torch.Tensor, 
                timestamps: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Forward pass through temporal network
        
        Args:
            node_sequences: Node features over time [batch, seq_len, node_dim]
            edge_sequences: Edge features over time [batch, seq_len, edge_dim]
            timestamps: Optional timestamps for each sequence step
            
        Returns:
            Dictionary with temporal features and evolution patterns
        """
        
        # Process node evolution
        node_output, (node_hidden, _) = self.node_rnn(node_sequences)
        
        # Process edge evolution
        edge_output, (edge_hidden, _) = self.edge_rnn(edge_sequences)
        
        # Apply temporal attention
        attended_nodes, attention_weights = self.temporal_attention(node_output, node_output, node_output)
        
        # Combine node and edge features
        combined_features = torch.cat([
            attended_nodes[:, -1, :],  # Last timestep of attended nodes
            edge_output[:, -1, :]      # Last timestep of edge features
        ], dim=-1)
        
        # Fusion
        fused_features = self.fusion(combined_features)
        
        return {
            'temporal_features': fused_features,
            'node_evolution': node_output,
            'edge_evolution': edge_output,
            'attention_weights': attention_weights,
            'final_node_state': node_hidden,
            'final_edge_state': edge_hidden
        }


class MultiScaleAnalyzer:
    """Multi-scale analysis combining function, file, and project-level features"""
    
    def __init__(self, multiscale_config: Optional[Dict[str, Any]] = None):
        """
        Initialize multi-scale analyzer
        
        Args:
            multiscale_config: Configuration for multi-scale analysis
                - scales: List of scales to analyze ['function', 'file', 'project']
                - aggregation_method: Method for combining scales
                - weight_scales: Whether to weight different scales
        """
        self.config = multiscale_config or {}
        self.scales = self.config.get('scales', ['function', 'file', 'project'])
        self.aggregation_method = self.config.get('aggregation_method', 'weighted_average')
        self.weight_scales = self.config.get('weight_scales', True)
        
        # Scale-specific analyzers
        self.function_analyzer = FunctionLevelAnalyzer()
        self.file_analyzer = FileLevelAnalyzer()
        self.project_analyzer = ProjectLevelAnalyzer()
        
        # Scale weights (learned or predefined)
        self.scale_weights = {
            'function': 0.5,
            'file': 0.3,
            'project': 0.2
        }
        
        logger.info(f"✅ Multi-Scale Analyzer initialized for scales: {self.scales}")
    
    def analyze_multiscale(self, code_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform multi-scale analysis
        
        Args:
            code_data: Dictionary containing code at different scales
                - function_code: Function-level code
                - file_code: Complete file code
                - project_context: Project-level context
                
        Returns:
            Multi-scale analysis results
        """
        try:
            scale_results = {}
            scale_features = {}
            
            # Function-level analysis
            if 'function' in self.scales and 'function_code' in code_data:
                function_result = self.function_analyzer.analyze(code_data['function_code'])
                scale_results['function'] = function_result
                scale_features['function'] = function_result.get('features', [])
            
            # File-level analysis
            if 'file' in self.scales and 'file_code' in code_data:
                file_result = self.file_analyzer.analyze(code_data['file_code'])
                scale_results['file'] = file_result
                scale_features['file'] = file_result.get('features', [])
            
            # Project-level analysis
            if 'project' in self.scales and 'project_context' in code_data:
                project_result = self.project_analyzer.analyze(code_data['project_context'])
                scale_results['project'] = project_result
                scale_features['project'] = project_result.get('features', [])
            
            # Combine scales
            combined_result = self._combine_scales(scale_results, scale_features)
            
            return {
                'multiscale_analysis': combined_result,
                'individual_scales': scale_results,
                'scale_features': scale_features,
                'scale_weights': self.scale_weights,
                'aggregation_method': self.aggregation_method
            }
            
        except Exception as e:
            logger.error(f"Multi-scale analysis failed: {e}")
            return {
                'error': str(e),
                'multiscale_analysis': None
            }
    
    def _combine_scales(self, scale_results: Dict[str, Any], scale_features: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from different scales"""
        
        if self.aggregation_method == 'weighted_average':
            return self._weighted_average_combination(scale_results, scale_features)
        elif self.aggregation_method == 'max_pooling':
            return self._max_pooling_combination(scale_results, scale_features)
        elif self.aggregation_method == 'attention':
            return self._attention_combination(scale_results, scale_features)
        else:
            return self._simple_average_combination(scale_results, scale_features)
    
    def _weighted_average_combination(self, scale_results: Dict[str, Any], scale_features: Dict[str, Any]) -> Dict[str, Any]:
        """Combine scales using weighted average"""
        
        combined_confidence = 0.0
        combined_vulnerability = False
        total_weight = 0.0
        
        for scale, result in scale_results.items():
            weight = self.scale_weights.get(scale, 1.0)
            confidence = result.get('confidence', 0.0)
            vulnerability = result.get('vulnerability_detected', False)
            
            combined_confidence += weight * confidence
            if vulnerability:
                combined_vulnerability = True
            total_weight += weight
        
        if total_weight > 0:
            combined_confidence /= total_weight
        
        return {
            'combined_confidence': combined_confidence,
            'combined_vulnerability_detected': combined_vulnerability,
            'combination_method': 'weighted_average',
            'total_weight': total_weight
        }
    
    def _max_pooling_combination(self, scale_results: Dict[str, Any], scale_features: Dict[str, Any]) -> Dict[str, Any]:
        """Combine scales using max pooling"""
        
        max_confidence = 0.0
        max_scale = None
        combined_vulnerability = False
        
        for scale, result in scale_results.items():
            confidence = result.get('confidence', 0.0)
            vulnerability = result.get('vulnerability_detected', False)
            
            if confidence > max_confidence:
                max_confidence = confidence
                max_scale = scale
            
            if vulnerability:
                combined_vulnerability = True
        
        return {
            'combined_confidence': max_confidence,
            'combined_vulnerability_detected': combined_vulnerability,
            'dominant_scale': max_scale,
            'combination_method': 'max_pooling'
        }
    
    def _attention_combination(self, scale_results: Dict[str, Any], scale_features: Dict[str, Any]) -> Dict[str, Any]:
        """Combine scales using attention mechanism"""
        
        # Simplified attention - would be more sophisticated in practice
        confidences = [result.get('confidence', 0.0) for result in scale_results.values()]
        
        if not confidences:
            return self._simple_average_combination(scale_results, scale_features)
        
        # Softmax attention weights
        attention_weights = F.softmax(torch.tensor(confidences), dim=0)
        
        combined_confidence = sum(w * c for w, c in zip(attention_weights, confidences))
        combined_vulnerability = any(result.get('vulnerability_detected', False) for result in scale_results.values())
        
        return {
            'combined_confidence': float(combined_confidence),
            'combined_vulnerability_detected': combined_vulnerability,
            'attention_weights': attention_weights.tolist(),
            'combination_method': 'attention'
        }
    
    def _simple_average_combination(self, scale_results: Dict[str, Any], scale_features: Dict[str, Any]) -> Dict[str, Any]:
        """Simple average combination"""
        
        confidences = [result.get('confidence', 0.0) for result in scale_results.values()]
        combined_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        combined_vulnerability = any(result.get('vulnerability_detected', False) for result in scale_results.values())
        
        return {
            'combined_confidence': combined_confidence,
            'combined_vulnerability_detected': combined_vulnerability,
            'combination_method': 'simple_average'
        }


class FunctionLevelAnalyzer:
    """Function-level feature analysis"""
    
    def analyze(self, function_code: str) -> Dict[str, Any]:
        """Analyze function-level features"""
        
        try:
            features = []
            
            # Basic function metrics
            lines = function_code.split('\n')
            num_lines = len(lines)
            num_statements = sum(1 for line in lines if line.strip() and not line.strip().startswith('//'))
            
            # Complexity metrics
            cyclomatic_complexity = self._calculate_cyclomatic_complexity(function_code)
            nesting_depth = self._calculate_nesting_depth(function_code)
            
            # Security-relevant patterns
            sql_patterns = self._count_sql_patterns(function_code)
            input_patterns = self._count_input_patterns(function_code)
            output_patterns = self._count_output_patterns(function_code)
            
            features.extend([
                num_lines, num_statements, cyclomatic_complexity, nesting_depth,
                sql_patterns, input_patterns, output_patterns
            ])
            
            # Simple vulnerability detection
            vulnerability_score = (sql_patterns * 0.4 + input_patterns * 0.3 + output_patterns * 0.3) / 10.0
            vulnerability_detected = vulnerability_score > 0.5
            
            return {
                'features': features,
                'confidence': min(vulnerability_score, 1.0),
                'vulnerability_detected': vulnerability_detected,
                'function_metrics': {
                    'lines': num_lines,
                    'statements': num_statements,
                    'cyclomatic_complexity': cyclomatic_complexity,
                    'nesting_depth': nesting_depth
                },
                'security_patterns': {
                    'sql_patterns': sql_patterns,
                    'input_patterns': input_patterns,
                    'output_patterns': output_patterns
                }
            }
            
        except Exception as e:
            logger.error(f"Function-level analysis failed: {e}")
            return {
                'features': [0] * 7,
                'confidence': 0.0,
                'vulnerability_detected': False,
                'error': str(e)
            }
    
    def _calculate_cyclomatic_complexity(self, code: str) -> int:
        """Calculate cyclomatic complexity"""
        
        # Simplified calculation
        decision_points = 0
        decision_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', '&&', '||', '?']
        
        for keyword in decision_keywords:
            decision_points += code.lower().count(keyword)
        
        return decision_points + 1  # Base complexity
    
    def _calculate_nesting_depth(self, code: str) -> int:
        """Calculate maximum nesting depth"""
        
        max_depth = 0
        current_depth = 0
        
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _count_sql_patterns(self, code: str) -> int:
        """Count SQL-related patterns"""
        
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'UNION', 'DROP', 'CREATE']
        count = 0
        
        code_upper = code.upper()
        for keyword in sql_keywords:
            count += code_upper.count(keyword)
        
        return count
    
    def _count_input_patterns(self, code: str) -> int:
        """Count input-related patterns"""
        
        input_patterns = ['getParameter', 'readLine', 'nextLine', 'Scanner', 'BufferedReader']
        count = 0
        
        for pattern in input_patterns:
            count += code.count(pattern)
        
        return count
    
    def _count_output_patterns(self, code: str) -> int:
        """Count output-related patterns"""
        
        output_patterns = ['println', 'print', 'write', 'getWriter', 'response']
        count = 0
        
        for pattern in output_patterns:
            count += code.count(pattern)
        
        return count


class FileLevelAnalyzer:
    """File-level feature analysis"""
    
    def analyze(self, file_code: str) -> Dict[str, Any]:
        """Analyze file-level features"""
        
        try:
            features = []
            
            # File structure metrics
            lines = file_code.split('\n')
            total_lines = len(lines)
            code_lines = sum(1 for line in lines if line.strip() and not line.strip().startswith('//'))
            comment_lines = sum(1 for line in lines if line.strip().startswith('//'))
            
            # Class and method counts
            class_count = file_code.count('class ')
            method_count = file_code.count('public ') + file_code.count('private ') + file_code.count('protected ')
            
            # Import analysis
            import_count = file_code.count('import ')
            security_imports = self._count_security_imports(file_code)
            
            features.extend([
                total_lines, code_lines, comment_lines, class_count, 
                method_count, import_count, security_imports
            ])
            
            # File-level vulnerability assessment
            vulnerability_score = (security_imports * 0.5 + method_count * 0.01) / 5.0
            vulnerability_detected = vulnerability_score > 0.3
            
            return {
                'features': features,
                'confidence': min(vulnerability_score, 1.0),
                'vulnerability_detected': vulnerability_detected,
                'file_metrics': {
                    'total_lines': total_lines,
                    'code_lines': code_lines,
                    'comment_lines': comment_lines,
                    'class_count': class_count,
                    'method_count': method_count,
                    'import_count': import_count,
                    'security_imports': security_imports
                }
            }
            
        except Exception as e:
            logger.error(f"File-level analysis failed: {e}")
            return {
                'features': [0] * 7,
                'confidence': 0.0,
                'vulnerability_detected': False,
                'error': str(e)
            }
    
    def _count_security_imports(self, code: str) -> int:
        """Count security-related imports"""
        
        security_packages = [
            'java.sql', 'javax.servlet', 'java.io', 'java.net',
            'java.security', 'javax.crypto', 'java.util.regex'
        ]
        
        count = 0
        for package in security_packages:
            count += code.count(f'import {package}')
        
        return count


class ProjectLevelAnalyzer:
    """Project-level feature analysis"""
    
    def analyze(self, project_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze project-level features"""
        
        try:
            features = []
            
            # Project structure metrics
            total_files = project_context.get('total_files', 0)
            java_files = project_context.get('java_files', 0)
            dependency_count = project_context.get('dependencies', 0)
            
            # Security-related dependencies
            security_deps = self._count_security_dependencies(project_context.get('dependency_list', []))
            
            # Project complexity
            total_loc = project_context.get('total_lines_of_code', 0)
            avg_file_size = total_loc / max(java_files, 1)
            
            features.extend([
                total_files, java_files, dependency_count, security_deps, total_loc, avg_file_size
            ])
            
            # Project-level vulnerability assessment
            vulnerability_score = (security_deps * 0.3 + dependency_count * 0.01) / 3.0
            vulnerability_detected = vulnerability_score > 0.2
            
            return {
                'features': features,
                'confidence': min(vulnerability_score, 1.0),
                'vulnerability_detected': vulnerability_detected,
                'project_metrics': {
                    'total_files': total_files,
                    'java_files': java_files,
                    'dependency_count': dependency_count,
                    'security_dependencies': security_deps,
                    'total_loc': total_loc,
                    'avg_file_size': avg_file_size
                }
            }
            
        except Exception as e:
            logger.error(f"Project-level analysis failed: {e}")
            return {
                'features': [0] * 6,
                'confidence': 0.0,
                'vulnerability_detected': False,
                'error': str(e)
            }
    
    def _count_security_dependencies(self, dependencies: List[str]) -> int:
        """Count security-related dependencies"""
        
        security_keywords = [
            'security', 'crypto', 'auth', 'jwt', 'oauth', 'ssl', 'tls',
            'spring-security', 'shiro', 'bouncy', 'apache-commons'
        ]
        
        count = 0
        for dep in dependencies:
            dep_lower = dep.lower()
            for keyword in security_keywords:
                if keyword in dep_lower:
                    count += 1
                    break
        
        return count


class AdvancedFeatureEngineer:
    """Main advanced feature engineering coordinator"""
    
    def __init__(self, feature_config: Optional[Dict[str, Any]] = None):
        """Initialize advanced feature engineer"""
        
        self.config = feature_config or {}
        
        # Initialize components
        gat_config = self.config.get('gat', {})
        self.gat = GraphAttentionNetwork(
            input_dim=gat_config.get('input_dim', 128),
            hidden_dim=gat_config.get('hidden_dim', 128),
            num_heads=gat_config.get('num_heads', 8),
            num_layers=gat_config.get('num_layers', 3)
        )
        
        temporal_config = self.config.get('temporal', {})
        self.temporal_gnn = TemporalGraphNetwork(
            node_dim=temporal_config.get('node_dim', 128),
            edge_dim=temporal_config.get('edge_dim', 32),
            hidden_dim=temporal_config.get('hidden_dim', 128)
        )
        
        multiscale_config = self.config.get('multiscale', {})
        self.multiscale_analyzer = MultiScaleAnalyzer(multiscale_config)
        
        logger.info("✅ Advanced Feature Engineer initialized with GAT, Temporal GNN, and Multi-Scale Analysis")
    
    def engineer_features(self, code_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive advanced feature engineering"""
        
        try:
            start_time = datetime.now()
            
            results = {
                'timestamp': start_time.isoformat(),
                'advanced_features': {},
                'feature_engineering_time': 0.0
            }
            
            # Graph Attention Network features
            if 'graph_data' in code_data:
                gat_features = self._extract_gat_features(code_data['graph_data'])
                results['advanced_features']['gat'] = gat_features
            
            # Temporal features (if historical data available)
            if 'temporal_data' in code_data:
                temporal_features = self._extract_temporal_features(code_data['temporal_data'])
                results['advanced_features']['temporal'] = temporal_features
            
            # Multi-scale features
            multiscale_features = self.multiscale_analyzer.analyze_multiscale(code_data)
            results['advanced_features']['multiscale'] = multiscale_features
            
            # Combine all features
            combined_features = self._combine_advanced_features(results['advanced_features'])
            results['combined_features'] = combined_features
            
            # Calculate processing time
            end_time = datetime.now()
            results['feature_engineering_time'] = (end_time - start_time).total_seconds()
            
            logger.info(f"Advanced feature engineering completed in {results['feature_engineering_time']:.2f}s")
            
            return results
            
        except Exception as e:
            logger.error(f"Advanced feature engineering failed: {e}")
            return {
                'error': str(e),
                'advanced_features': {},
                'feature_engineering_time': 0.0
            }
    
    def _extract_gat_features(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features using Graph Attention Network"""
        
        try:
            # Convert graph data to tensor format
            if 'node_features' in graph_data and 'edges' in graph_data:
                node_features = torch.tensor(graph_data['node_features'], dtype=torch.float)
                edges = torch.tensor(graph_data['edges'], dtype=torch.long).t().contiguous()
                
                # Forward pass through GAT
                with torch.no_grad():
                    gat_output = self.gat(node_features, edges)
                
                # Extract attention-based features
                attention_features = {
                    'gat_node_embeddings': gat_output.numpy().tolist(),
                    'gat_graph_embedding': torch.mean(gat_output, dim=0).numpy().tolist(),
                    'attention_diversity': torch.std(gat_output).item(),
                    'node_importance_scores': torch.norm(gat_output, dim=1).numpy().tolist()
                }
                
                return attention_features
            
            return {'error': 'Insufficient graph data for GAT'}
            
        except Exception as e:
            logger.error(f"GAT feature extraction failed: {e}")
            return {'error': str(e)}
    
    def _extract_temporal_features(self, temporal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract temporal evolution features"""
        
        try:
            # Mock temporal data processing
            # In practice, this would process code evolution over time
            
            node_sequences = torch.randn(1, 5, 128)  # [batch, seq_len, node_dim]
            edge_sequences = torch.randn(1, 5, 32)   # [batch, seq_len, edge_dim]
            
            with torch.no_grad():
                temporal_output = self.temporal_gnn(node_sequences, edge_sequences)
            
            temporal_features = {
                'temporal_embedding': temporal_output['temporal_features'].numpy().tolist(),
                'evolution_trend': 'increasing',  # Would be computed from actual data
                'change_velocity': 0.5,  # Rate of change
                'stability_score': 0.8   # How stable the code is over time
            }
            
            return temporal_features
            
        except Exception as e:
            logger.error(f"Temporal feature extraction failed: {e}")
            return {'error': str(e)}
    
    def _combine_advanced_features(self, advanced_features: Dict[str, Any]) -> Dict[str, Any]:
        """Combine all advanced features into a unified representation"""
        
        combined = {
            'feature_vector': [],
            'feature_names': [],
            'feature_importance': {},
            'total_features': 0
        }
        
        # GAT features
        if 'gat' in advanced_features and 'gat_graph_embedding' in advanced_features['gat']:
            gat_embedding = advanced_features['gat']['gat_graph_embedding']
            combined['feature_vector'].extend(gat_embedding)
            combined['feature_names'].extend([f'gat_{i}' for i in range(len(gat_embedding))])
            combined['feature_importance']['gat'] = 0.4
        
        # Temporal features
        if 'temporal' in advanced_features and 'temporal_embedding' in advanced_features['temporal']:
            temporal_embedding = advanced_features['temporal']['temporal_embedding'][0]  # Take first element
            combined['feature_vector'].extend(temporal_embedding)
            combined['feature_names'].extend([f'temporal_{i}' for i in range(len(temporal_embedding))])
            combined['feature_importance']['temporal'] = 0.3
        
        # Multi-scale features
        if 'multiscale' in advanced_features:
            multiscale = advanced_features['multiscale']
            if 'multiscale_analysis' in multiscale:
                ms_analysis = multiscale['multiscale_analysis']
                combined['feature_vector'].append(ms_analysis.get('combined_confidence', 0.0))
                combined['feature_names'].append('multiscale_confidence')
                combined['feature_importance']['multiscale'] = 0.3
        
        combined['total_features'] = len(combined['feature_vector'])
        
        return combined
    
    def get_feature_statistics(self) -> Dict[str, Any]:
        """Get statistics about the feature engineering process"""
        
        return {
            'gat_parameters': sum(p.numel() for p in self.gat.parameters()),
            'temporal_parameters': sum(p.numel() for p in self.temporal_gnn.parameters()),
            'torch_geometric_available': TORCH_GEOMETRIC_AVAILABLE,
            'supported_scales': self.multiscale_analyzer.scales,
            'feature_engineering_components': ['gat', 'temporal', 'multiscale']
        }


# Configuration templates
ADVANCED_FEATURE_CONFIG_TEMPLATES = {
    'standard': {
        'gat': {
            'input_dim': 128,
            'hidden_dim': 128,
            'num_heads': 8,
            'num_layers': 3
        },
        'temporal': {
            'node_dim': 128,
            'edge_dim': 32,
            'hidden_dim': 128
        },
        'multiscale': {
            'scales': ['function', 'file', 'project'],
            'aggregation_method': 'weighted_average'
        }
    },
    'lightweight': {
        'gat': {
            'input_dim': 64,
            'hidden_dim': 64,
            'num_heads': 4,
            'num_layers': 2
        },
        'temporal': {
            'node_dim': 64,
            'edge_dim': 16,
            'hidden_dim': 64
        },
        'multiscale': {
            'scales': ['function', 'file'],
            'aggregation_method': 'simple_average'
        }
    },
    'research': {
        'gat': {
            'input_dim': 256,
            'hidden_dim': 256,
            'num_heads': 16,
            'num_layers': 4
        },
        'temporal': {
            'node_dim': 256,
            'edge_dim': 64,
            'hidden_dim': 256
        },
        'multiscale': {
            'scales': ['function', 'file', 'project'],
            'aggregation_method': 'attention'
        }
    }
} 