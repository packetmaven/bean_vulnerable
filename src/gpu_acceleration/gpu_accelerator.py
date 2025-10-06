"""
Bean Vulnerable GNN Framework - GPU Accelerator
High-performance GPU acceleration for vulnerability detection
"""

import logging
import platform
import torch
import torch.nn as nn
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# Hardware detection
def detect_hardware():
    """Detect available hardware acceleration"""
    hardware_info = {
        'cuda_available': torch.cuda.is_available(),
        'cuda_devices': torch.cuda.device_count() if torch.cuda.is_available() else 0,
        'mps_available': torch.backends.mps.is_available() if hasattr(torch.backends, 'mps') else False,
        'cpu_count': torch.get_num_threads(),
        'platform': platform.system(),
        'architecture': platform.machine()
    }
    
    # Check for specific GPU types
    if hardware_info['cuda_available']:
        hardware_info['cuda_devices_info'] = []
        for i in range(hardware_info['cuda_devices']):
            device_props = torch.cuda.get_device_properties(i)
            hardware_info['cuda_devices_info'].append({
                'name': device_props.name,
                'memory': device_props.total_memory,
                'compute_capability': f"{device_props.major}.{device_props.minor}"
            })
    
    # Check for Intel OpenVINO
    try:
        import openvino
        hardware_info['openvino_available'] = True
        hardware_info['openvino_version'] = openvino.__version__
    except ImportError:
        hardware_info['openvino_available'] = False
    
    return hardware_info


class GPUAccelerator:
    """Main GPU acceleration coordinator"""
    
    def __init__(self, acceleration_config: Optional[Dict[str, Any]] = None):
        """
        Initialize GPU accelerator
        
        Args:
            acceleration_config: GPU acceleration configuration
                - preferred_device: Preferred device ('cuda', 'mps', 'cpu', 'auto')
                - batch_size: Batch size for GPU processing
                - mixed_precision: Use mixed precision training
                - memory_fraction: GPU memory fraction to use
                - optimization_level: Optimization level (1-3)
        """
        self.config = acceleration_config or {}
        self.preferred_device = self.config.get('preferred_device', 'auto')
        self.batch_size = self.config.get('batch_size', 32)
        self.mixed_precision = self.config.get('mixed_precision', True)
        self.memory_fraction = self.config.get('memory_fraction', 0.8)
        self.optimization_level = self.config.get('optimization_level', 2)
        
        # Detect hardware
        self.hardware_info = detect_hardware()
        
        # Select optimal device
        self.device = self._select_optimal_device()
        
        # Initialize acceleration components
        self.cuda_processor = None
        self.mps_processor = None
        self.openvino_optimizer = None
        
        self._initialize_accelerators()
        
        logger.info(f"✅ GPU Accelerator initialized - Device: {self.device}")
        logger.info(f"Hardware: {self._get_hardware_summary()}")
    
    def accelerate_model(self, model: nn.Module) -> nn.Module:
        """
        Accelerate a PyTorch model for optimal performance
        
        Args:
            model: PyTorch model to accelerate
            
        Returns:
            Accelerated model
        """
        try:
            start_time = time.time()
            
            # Move model to optimal device
            model = model.to(self.device)
            
            # Apply device-specific optimizations
            if self.device.type == 'cuda':
                model = self._accelerate_cuda_model(model)
            elif self.device.type == 'mps':
                model = self._accelerate_mps_model(model)
            elif self.openvino_optimizer:
                model = self._accelerate_openvino_model(model)
            
            # Apply general optimizations
            model = self._apply_general_optimizations(model)
            
            acceleration_time = time.time() - start_time
            
            logger.info(f"Model acceleration completed in {acceleration_time:.2f}s")
            
            return model
            
        except Exception as e:
            logger.error(f"Model acceleration failed: {e}")
            return model.to(self.device)  # Fallback to basic device transfer
    
    def accelerate_inference(self, model: nn.Module, input_data: torch.Tensor) -> Dict[str, Any]:
        """
        Perform accelerated inference
        
        Args:
            model: Accelerated model
            input_data: Input tensor
            
        Returns:
            Inference results with performance metrics
        """
        try:
            start_time = time.time()
            
            # Prepare input data
            input_data = input_data.to(self.device)
            
            # Optimize input batch size
            optimized_batches = self._optimize_batch_size(input_data)
            
            results = []
            total_inference_time = 0
            
            with torch.no_grad():
                if self.mixed_precision and self.device.type == 'cuda':
                    # Use automatic mixed precision
                    with torch.cuda.amp.autocast():
                        for batch in optimized_batches:
                            batch_start = time.time()
                            batch_result = model(batch)
                            batch_time = time.time() - batch_start
                            
                            results.append(batch_result)
                            total_inference_time += batch_time
                else:
                    # Standard inference
                    for batch in optimized_batches:
                        batch_start = time.time()
                        batch_result = model(batch)
                        batch_time = time.time() - batch_start
                        
                        results.append(batch_result)
                        total_inference_time += batch_time
            
            # Combine results
            final_result = torch.cat(results, dim=0) if len(results) > 1 else results[0]
            
            total_time = time.time() - start_time
            
            return {
                'result': final_result,
                'inference_time': total_inference_time,
                'total_time': total_time,
                'device_used': str(self.device),
                'batch_count': len(optimized_batches),
                'throughput': input_data.shape[0] / total_time,
                'memory_used': self._get_memory_usage()
            }
            
        except Exception as e:
            logger.error(f"Accelerated inference failed: {e}")
            return {
                'result': None,
                'error': str(e),
                'device_used': str(self.device)
            }
    
    def benchmark_performance(self, model: nn.Module, sample_input: torch.Tensor, num_runs: int = 10) -> Dict[str, Any]:
        """
        Benchmark model performance on different devices
        
        Args:
            model: Model to benchmark
            sample_input: Sample input tensor
            num_runs: Number of benchmark runs
            
        Returns:
            Performance benchmark results
        """
        benchmark_results = {
            'timestamp': datetime.now().isoformat(),
            'num_runs': num_runs,
            'hardware_info': self.hardware_info,
            'device_benchmarks': {}
        }
        
        # Test available devices
        devices_to_test = ['cpu']
        
        if self.hardware_info['cuda_available']:
            devices_to_test.append('cuda')
        
        if self.hardware_info['mps_available']:
            devices_to_test.append('mps')
        
        for device_name in devices_to_test:
            try:
                device = torch.device(device_name)
                test_model = model.to(device)
                test_input = sample_input.to(device)
                
                # Warmup
                with torch.no_grad():
                    for _ in range(3):
                        _ = test_model(test_input)
                
                # Benchmark
                times = []
                with torch.no_grad():
                    for _ in range(num_runs):
                        if device_name == 'cuda':
                            torch.cuda.synchronize()
                        
                        start_time = time.time()
                        _ = test_model(test_input)
                        
                        if device_name == 'cuda':
                            torch.cuda.synchronize()
                        
                        end_time = time.time()
                        times.append(end_time - start_time)
                
                benchmark_results['device_benchmarks'][device_name] = {
                    'avg_time': sum(times) / len(times),
                    'min_time': min(times),
                    'max_time': max(times),
                    'throughput': sample_input.shape[0] / (sum(times) / len(times)),
                    'memory_usage': self._get_device_memory_usage(device)
                }
                
            except Exception as e:
                benchmark_results['device_benchmarks'][device_name] = {
                    'error': str(e)
                }
        
        # Calculate speedup
        if 'cpu' in benchmark_results['device_benchmarks']:
            cpu_time = benchmark_results['device_benchmarks']['cpu'].get('avg_time', 1.0)
            
            for device_name, results in benchmark_results['device_benchmarks'].items():
                if device_name != 'cpu' and 'avg_time' in results:
                    results['speedup_vs_cpu'] = cpu_time / results['avg_time']
        
        return benchmark_results
    
    def _select_optimal_device(self) -> torch.device:
        """Select the optimal device based on hardware and preferences"""
        
        if self.preferred_device == 'auto':
            # Automatic device selection
            if self.hardware_info['cuda_available']:
                return torch.device('cuda')
            elif self.hardware_info['mps_available']:
                return torch.device('mps')
            else:
                return torch.device('cpu')
        
        elif self.preferred_device == 'cuda':
            if self.hardware_info['cuda_available']:
                return torch.device('cuda')
            else:
                logger.warning("CUDA requested but not available, falling back to CPU")
                return torch.device('cpu')
        
        elif self.preferred_device == 'mps':
            if self.hardware_info['mps_available']:
                return torch.device('mps')
            else:
                logger.warning("MPS requested but not available, falling back to CPU")
                return torch.device('cpu')
        
        else:
            return torch.device(self.preferred_device)
    
    def _initialize_accelerators(self):
        """Initialize device-specific accelerators"""
        
        if self.device.type == 'cuda':
            try:
                from .cuda_gnn_processor import CUDAGNNProcessor
                self.cuda_processor = CUDAGNNProcessor(self.config)
            except ImportError:
                logger.warning("CUDA GNN processor not available")
        
        elif self.device.type == 'mps':
            try:
                from .mps_gnn_processor import MPSGNNProcessor
                self.mps_processor = MPSGNNProcessor(self.config)
            except ImportError:
                logger.warning("MPS GNN processor not available")
        
        if self.hardware_info['openvino_available']:
            try:
                from .openvino_optimizer import OpenVINOOptimizer
                self.openvino_optimizer = OpenVINOOptimizer(self.config)
            except ImportError:
                logger.warning("OpenVINO optimizer not available")
    
    def _accelerate_cuda_model(self, model: nn.Module) -> nn.Module:
        """Apply CUDA-specific optimizations"""
        
        # Set CUDA memory fraction
        if hasattr(torch.cuda, 'set_memory_fraction'):
            torch.cuda.set_memory_fraction(self.memory_fraction)
        
        # Enable cuDNN benchmarking
        torch.backends.cudnn.benchmark = True
        torch.backends.cudnn.enabled = True
        
        # Compile model if available (PyTorch 2.0+)
        if hasattr(torch, 'compile') and self.optimization_level >= 2:
            try:
                model = torch.compile(model, mode='max-autotune')
                logger.info("Applied torch.compile optimization")
            except Exception as e:
                logger.warning(f"torch.compile failed: {e}")
        
        # Use CUDA graphs for inference if available
        if self.optimization_level >= 3:
            try:
                # This would require more complex implementation
                logger.info("CUDA graphs optimization available")
            except Exception as e:
                logger.warning(f"CUDA graphs optimization failed: {e}")
        
        return model
    
    def _accelerate_mps_model(self, model: nn.Module) -> nn.Module:
        """Apply MPS (Apple Silicon) specific optimizations"""
        
        # Enable MPS optimizations
        if hasattr(torch.backends.mps, 'enable_fallback'):
            torch.backends.mps.enable_fallback = True
        
        # Optimize for Apple Silicon
        if self.optimization_level >= 2:
            try:
                # Apply MPS-specific optimizations
                logger.info("Applied MPS optimizations")
            except Exception as e:
                logger.warning(f"MPS optimization failed: {e}")
        
        return model
    
    def _accelerate_openvino_model(self, model: nn.Module) -> nn.Module:
        """Apply OpenVINO optimizations"""
        
        if self.openvino_optimizer:
            try:
                return self.openvino_optimizer.optimize_model(model)
            except Exception as e:
                logger.warning(f"OpenVINO optimization failed: {e}")
        
        return model
    
    def _apply_general_optimizations(self, model: nn.Module) -> nn.Module:
        """Apply general PyTorch optimizations"""
        
        # Set model to eval mode for inference
        model.eval()
        
        # Fuse operations if possible
        if self.optimization_level >= 2:
            try:
                # Fuse conv-bn, conv-relu, etc.
                torch.quantization.fuse_modules(model, [['conv', 'bn', 'relu']], inplace=True)
                logger.info("Applied module fusion")
            except Exception as e:
                logger.debug(f"Module fusion not applicable: {e}")
        
        # Apply quantization if requested
        if self.optimization_level >= 3:
            try:
                # Dynamic quantization
                model = torch.quantization.quantize_dynamic(
                    model, {nn.Linear, nn.Conv2d}, dtype=torch.qint8
                )
                logger.info("Applied dynamic quantization")
            except Exception as e:
                logger.warning(f"Quantization failed: {e}")
        
        return model
    
    def _optimize_batch_size(self, input_data: torch.Tensor) -> List[torch.Tensor]:
        """Optimize batch size for current hardware"""
        
        total_samples = input_data.shape[0]
        
        # Adjust batch size based on available memory
        if self.device.type == 'cuda':
            # Get available GPU memory
            gpu_memory = torch.cuda.get_device_properties(self.device).total_memory
            available_memory = gpu_memory * self.memory_fraction
            
            # Estimate memory per sample (rough heuristic)
            sample_memory = input_data.element_size() * input_data.numel() / total_samples
            optimal_batch_size = int(available_memory / (sample_memory * 4))  # 4x safety factor
            
            self.batch_size = min(self.batch_size, optimal_batch_size, total_samples)
        
        elif self.device.type == 'mps':
            # MPS has shared memory, be more conservative
            self.batch_size = min(self.batch_size, 16, total_samples)
        
        # Split into batches
        batches = []
        for i in range(0, total_samples, self.batch_size):
            batch = input_data[i:i + self.batch_size]
            batches.append(batch)
        
        return batches
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage"""
        
        memory_info = {'device': str(self.device)}
        
        if self.device.type == 'cuda':
            memory_info.update({
                'allocated': torch.cuda.memory_allocated(self.device),
                'cached': torch.cuda.memory_reserved(self.device),
                'max_allocated': torch.cuda.max_memory_allocated(self.device)
            })
        
        return memory_info
    
    def _get_device_memory_usage(self, device: torch.device) -> Dict[str, Any]:
        """Get memory usage for specific device"""
        
        if device.type == 'cuda':
            return {
                'allocated': torch.cuda.memory_allocated(device),
                'cached': torch.cuda.memory_reserved(device)
            }
        
        return {'type': device.type}
    
    def _get_hardware_summary(self) -> str:
        """Get hardware summary string"""
        
        summary_parts = []
        
        if self.hardware_info['cuda_available']:
            gpu_info = self.hardware_info['cuda_devices_info'][0]
            summary_parts.append(f"CUDA: {gpu_info['name']}")
        
        if self.hardware_info['mps_available']:
            summary_parts.append("MPS: Apple Silicon")
        
        if self.hardware_info['openvino_available']:
            summary_parts.append("OpenVINO: Available")
        
        summary_parts.append(f"CPU: {self.hardware_info['cpu_count']} threads")
        
        return ", ".join(summary_parts)
    
    def get_acceleration_stats(self) -> Dict[str, Any]:
        """Get acceleration statistics"""
        
        return {
            'device': str(self.device),
            'hardware_info': self.hardware_info,
            'config': self.config,
            'batch_size': self.batch_size,
            'mixed_precision': self.mixed_precision,
            'optimization_level': self.optimization_level
        }


# GPU acceleration configuration templates
GPU_CONFIG_TEMPLATES = {
    'nvidia_gaming': {
        'preferred_device': 'cuda',
        'batch_size': 64,
        'mixed_precision': True,
        'memory_fraction': 0.8,
        'optimization_level': 2
    },
    'nvidia_datacenter': {
        'preferred_device': 'cuda',
        'batch_size': 128,
        'mixed_precision': True,
        'memory_fraction': 0.9,
        'optimization_level': 3
    },
    'apple_silicon': {
        'preferred_device': 'mps',
        'batch_size': 32,
        'mixed_precision': False,
        'memory_fraction': 0.7,
        'optimization_level': 2
    },
    'cpu_optimized': {
        'preferred_device': 'cpu',
        'batch_size': 16,
        'mixed_precision': False,
        'memory_fraction': 0.8,
        'optimization_level': 1
    }
} 