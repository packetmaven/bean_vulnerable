"""
Bean Vulnerable GNN Framework - OpenVINO Optimizer
Intel OpenVINO optimization for CPU and Intel GPU acceleration
"""

import logging
import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
import time
import tempfile
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Check OpenVINO availability
try:
    import openvino as ov
    from openvino.tools import mo
    OPENVINO_AVAILABLE = True
    OPENVINO_VERSION = ov.__version__
except ImportError:
    OPENVINO_AVAILABLE = False
    OPENVINO_VERSION = None
    logger.warning("OpenVINO not available - CPU optimizations will be limited")


class OpenVINOOptimizer:
    """Intel OpenVINO optimizer for GNN acceleration"""
    
    def __init__(self, openvino_config: Optional[Dict[str, Any]] = None):
        """
        Initialize OpenVINO optimizer
        
        Args:
            openvino_config: OpenVINO-specific configuration
                - device: Target device ('CPU', 'GPU', 'AUTO')
                - precision: Model precision ('FP32', 'FP16', 'INT8')
                - optimization_level: Optimization level (1-3)
                - batch_size: Batch size for optimization
                - enable_dynamic_shapes: Enable dynamic input shapes
        """
        if not OPENVINO_AVAILABLE:
            raise RuntimeError("OpenVINO not available")
        
        self.config = openvino_config or {}
        self.device = self.config.get('device', 'CPU')
        self.precision = self.config.get('precision', 'FP32')
        self.optimization_level = self.config.get('optimization_level', 2)
        self.batch_size = self.config.get('batch_size', 1)
        self.enable_dynamic_shapes = self.config.get('enable_dynamic_shapes', True)
        
        # Initialize OpenVINO core
        self.core = ov.Core()
        
        # Get available devices
        self.available_devices = self.core.available_devices
        
        # Validate device
        if self.device not in self.available_devices and self.device != 'AUTO':
            logger.warning(f"Device {self.device} not available. Available: {self.available_devices}")
            self.device = 'CPU'  # Fallback to CPU
        
        # Model storage
        self.optimized_models = {}
        self.compiled_models = {}
        
        logger.info(f"✅ OpenVINO Optimizer initialized - Device: {self.device}, Precision: {self.precision}")
        self._log_openvino_info()
    
    def optimize_model(self, pytorch_model: nn.Module, sample_input: Optional[torch.Tensor] = None) -> Any:
        """
        Optimize PyTorch model using OpenVINO
        
        Args:
            pytorch_model: PyTorch model to optimize
            sample_input: Sample input tensor for tracing
            
        Returns:
            OpenVINO compiled model
        """
        try:
            start_time = time.time()
            
            # Create sample input if not provided
            if sample_input is None:
                sample_input = torch.randn(self.batch_size, 16)  # Default input shape
            
            # Convert PyTorch model to ONNX
            onnx_path = self._convert_to_onnx(pytorch_model, sample_input)
            
            # Convert ONNX to OpenVINO IR
            ir_path = self._convert_to_openvino_ir(onnx_path)
            
            # Load and optimize model
            ov_model = self.core.read_model(ir_path)
            
            # Apply optimizations
            ov_model = self._apply_optimizations(ov_model)
            
            # Compile model
            compiled_model = self.core.compile_model(ov_model, self.device)
            
            # Store optimized model
            model_id = id(pytorch_model)
            self.optimized_models[model_id] = ov_model
            self.compiled_models[model_id] = compiled_model
            
            optimization_time = time.time() - start_time
            
            logger.info(f"Model optimization completed in {optimization_time:.2f}s")
            
            # Cleanup temporary files
            self._cleanup_temp_files([onnx_path, ir_path])
            
            return compiled_model
            
        except Exception as e:
            logger.error(f"OpenVINO optimization failed: {e}")
            return None
    
    def inference(self, compiled_model: Any, input_data: np.ndarray) -> Dict[str, Any]:
        """
        Perform inference using OpenVINO compiled model
        
        Args:
            compiled_model: OpenVINO compiled model
            input_data: Input data as numpy array
            
        Returns:
            Inference results
        """
        try:
            start_time = time.time()
            
            # Prepare input
            input_tensor = ov.Tensor(input_data.astype(np.float32))
            
            # Get input/output info
            input_layer = compiled_model.input(0)
            output_layer = compiled_model.output(0)
            
            # Create inference request
            infer_request = compiled_model.create_infer_request()
            
            # Set input
            infer_request.set_input_tensor(input_tensor)
            
            # Run inference
            infer_request.infer()
            
            # Get output
            output_tensor = infer_request.get_output_tensor()
            output_data = output_tensor.data
            
            inference_time = time.time() - start_time
            
            return {
                'output': output_data,
                'inference_time': inference_time,
                'device_used': self.device,
                'input_shape': input_data.shape,
                'output_shape': output_data.shape
            }
            
        except Exception as e:
            logger.error(f"OpenVINO inference failed: {e}")
            return {
                'error': str(e),
                'device_used': self.device
            }
    
    def benchmark_model(self, compiled_model: Any, sample_input: np.ndarray, num_runs: int = 100) -> Dict[str, Any]:
        """
        Benchmark OpenVINO model performance
        
        Args:
            compiled_model: OpenVINO compiled model
            sample_input: Sample input for benchmarking
            num_runs: Number of benchmark runs
            
        Returns:
            Benchmark results
        """
        try:
            # Warmup
            for _ in range(10):
                self.inference(compiled_model, sample_input)
            
            # Benchmark
            times = []
            for _ in range(num_runs):
                start_time = time.time()
                result = self.inference(compiled_model, sample_input)
                end_time = time.time()
                
                if 'error' not in result:
                    times.append(end_time - start_time)
            
            if not times:
                return {'error': 'No successful inference runs'}
            
            return {
                'avg_time': sum(times) / len(times),
                'min_time': min(times),
                'max_time': max(times),
                'throughput': 1.0 / (sum(times) / len(times)),
                'successful_runs': len(times),
                'total_runs': num_runs,
                'device': self.device,
                'precision': self.precision
            }
            
        except Exception as e:
            logger.error(f"OpenVINO benchmarking failed: {e}")
            return {'error': str(e)}
    
    def _convert_to_onnx(self, pytorch_model: nn.Module, sample_input: torch.Tensor) -> str:
        """Convert PyTorch model to ONNX format"""
        
        # Create temporary file
        temp_dir = tempfile.mkdtemp()
        onnx_path = os.path.join(temp_dir, 'model.onnx')
        
        # Set model to eval mode
        pytorch_model.eval()
        
        # Export to ONNX
        torch.onnx.export(
            pytorch_model,
            sample_input,
            onnx_path,
            export_params=True,
            opset_version=11,
            do_constant_folding=True,
            input_names=['input'],
            output_names=['output'],
            dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}} if self.enable_dynamic_shapes else None
        )
        
        logger.debug(f"ONNX model saved to {onnx_path}")
        return onnx_path
    
    def _convert_to_openvino_ir(self, onnx_path: str) -> str:
        """Convert ONNX model to OpenVINO IR format"""
        
        # Output directory
        output_dir = os.path.dirname(onnx_path)
        ir_path = os.path.join(output_dir, 'model.xml')
        
        try:
            # Use Model Optimizer
            ov_model = mo.convert_model(onnx_path)
            
            # Save model
            ov.save_model(ov_model, ir_path)
            
            logger.debug(f"OpenVINO IR saved to {ir_path}")
            return ir_path
            
        except Exception as e:
            logger.error(f"ONNX to OpenVINO conversion failed: {e}")
            raise
    
    def _apply_optimizations(self, ov_model: Any) -> Any:
        """Apply OpenVINO-specific optimizations"""
        
        try:
            # Apply optimizations based on level
            if self.optimization_level >= 2:
                # Enable model optimizations
                pass  # OpenVINO automatically applies optimizations
            
            if self.optimization_level >= 3:
                # Advanced optimizations
                pass  # Could include quantization, pruning, etc.
            
            logger.debug("OpenVINO optimizations applied")
            return ov_model
            
        except Exception as e:
            logger.warning(f"OpenVINO optimization failed: {e}")
            return ov_model
    
    def _cleanup_temp_files(self, file_paths: List[str]):
        """Clean up temporary files"""
        
        for file_path in file_paths:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                # Also remove .bin file for OpenVINO IR
                if file_path.endswith('.xml'):
                    bin_path = file_path.replace('.xml', '.bin')
                    if os.path.exists(bin_path):
                        os.remove(bin_path)
                
                # Remove directory if empty
                dir_path = os.path.dirname(file_path)
                if os.path.exists(dir_path) and not os.listdir(dir_path):
                    os.rmdir(dir_path)
                    
            except Exception as e:
                logger.warning(f"Failed to cleanup {file_path}: {e}")
    
    def _log_openvino_info(self):
        """Log OpenVINO system information"""
        
        logger.info(f"OpenVINO Version: {OPENVINO_VERSION}")
        logger.info(f"Available Devices: {self.available_devices}")
        
        # Get device info
        for device in self.available_devices:
            try:
                device_name = self.core.get_property(device, "FULL_DEVICE_NAME")
                logger.info(f"Device {device}: {device_name}")
            except:
                logger.info(f"Device {device}: Info not available")
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get detailed device information"""
        
        device_info = {
            'openvino_version': OPENVINO_VERSION,
            'available_devices': self.available_devices,
            'current_device': self.device,
            'precision': self.precision,
            'devices_detail': {}
        }
        
        for device in self.available_devices:
            try:
                device_detail = {
                    'full_name': self.core.get_property(device, "FULL_DEVICE_NAME"),
                    'supported_properties': []
                }
                
                # Try to get supported properties
                try:
                    supported_props = self.core.get_property(device, "SUPPORTED_PROPERTIES")
                    device_detail['supported_properties'] = list(supported_props)
                except:
                    pass
                
                device_info['devices_detail'][device] = device_detail
                
            except Exception as e:
                device_info['devices_detail'][device] = {'error': str(e)}
        
        return device_info
    
    def quantize_model(self, ov_model: Any, calibration_data: Optional[np.ndarray] = None) -> Any:
        """
        Quantize model to INT8 precision
        
        Args:
            ov_model: OpenVINO model
            calibration_data: Calibration data for quantization
            
        Returns:
            Quantized model
        """
        try:
            if self.precision != 'INT8':
                logger.warning("Quantization requested but precision is not INT8")
                return ov_model
            
            # Note: Full quantization requires additional setup
            # This is a placeholder for the quantization process
            logger.info("INT8 quantization would be applied here")
            
            return ov_model
            
        except Exception as e:
            logger.error(f"Model quantization failed: {e}")
            return ov_model
    
    def save_optimized_model(self, model_id: int, output_path: str) -> bool:
        """
        Save optimized model to disk
        
        Args:
            model_id: Model identifier
            output_path: Output file path
            
        Returns:
            Success status
        """
        try:
            if model_id not in self.optimized_models:
                logger.error(f"Model {model_id} not found")
                return False
            
            ov_model = self.optimized_models[model_id]
            ov.save_model(ov_model, output_path)
            
            logger.info(f"Model saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_optimized_model(self, model_path: str) -> Any:
        """
        Load optimized model from disk
        
        Args:
            model_path: Path to model file
            
        Returns:
            Compiled model
        """
        try:
            ov_model = self.core.read_model(model_path)
            compiled_model = self.core.compile_model(ov_model, self.device)
            
            logger.info(f"Model loaded from {model_path}")
            return compiled_model
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return None
    
    def cleanup(self):
        """Clean up OpenVINO resources"""
        
        self.optimized_models.clear()
        self.compiled_models.clear()
        
        logger.info("OpenVINO resources cleaned up")


class OpenVINOGNNWrapper:
    """Wrapper for GNN models optimized with OpenVINO"""
    
    def __init__(self, compiled_model: Any, optimizer: OpenVINOOptimizer):
        self.compiled_model = compiled_model
        self.optimizer = optimizer
    
    def predict(self, input_data: np.ndarray) -> np.ndarray:
        """Predict using OpenVINO optimized model"""
        
        result = self.optimizer.inference(self.compiled_model, input_data)
        
        if 'error' in result:
            raise RuntimeError(f"OpenVINO inference failed: {result['error']}")
        
        return result['output']
    
    def predict_batch(self, input_batch: List[np.ndarray]) -> List[np.ndarray]:
        """Predict batch using OpenVINO optimized model"""
        
        results = []
        for input_data in input_batch:
            try:
                output = self.predict(input_data)
                results.append(output)
            except Exception as e:
                logger.error(f"Batch prediction failed for sample: {e}")
                results.append(None)
        
        return results


# OpenVINO configuration templates
OPENVINO_CONFIG_TEMPLATES = {
    'cpu_optimized': {
        'device': 'CPU',
        'precision': 'FP32',
        'optimization_level': 2,
        'batch_size': 1,
        'enable_dynamic_shapes': True
    },
    'cpu_quantized': {
        'device': 'CPU',
        'precision': 'INT8',
        'optimization_level': 3,
        'batch_size': 1,
        'enable_dynamic_shapes': True
    },
    'intel_gpu': {
        'device': 'GPU',
        'precision': 'FP16',
        'optimization_level': 2,
        'batch_size': 4,
        'enable_dynamic_shapes': True
    },
    'auto_device': {
        'device': 'AUTO',
        'precision': 'FP32',
        'optimization_level': 2,
        'batch_size': 1,
        'enable_dynamic_shapes': True
    }
} 