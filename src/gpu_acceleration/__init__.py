# Bean Vulnerable GNN Framework - GPU Acceleration Package
# High-performance GPU acceleration for GNN processing and vulnerability detection

from .gpu_accelerator import GPUAccelerator  # noqa: F401

# Optional processors are imported lazily to avoid hard dependency at import time.
try:  # pragma: no cover - optional
    from .cuda_gnn_processor import CUDAGNNProcessor  # noqa: F401
except Exception:  # pragma: no cover
    CUDAGNNProcessor = None  # type: ignore

try:  # pragma: no cover - optional
    from .mps_gnn_processor import MPSGNNProcessor  # noqa: F401
except Exception:  # pragma: no cover
    MPSGNNProcessor = None  # type: ignore

try:  # pragma: no cover - optional
    from .openvino_optimizer import OpenVINOOptimizer  # noqa: F401
except Exception:  # pragma: no cover
    OpenVINOOptimizer = None  # type: ignore

__all__ = [
    'GPUAccelerator',
    'CUDAGNNProcessor', 
    'MPSGNNProcessor',
    'OpenVINOOptimizer'
]

