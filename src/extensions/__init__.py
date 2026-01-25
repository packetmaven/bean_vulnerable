# Bean Vulnerable GNN Framework - Extensions Package
# AEG lite and other advanced security analysis extensions

try:
    from . import aeg_lite
except Exception:
    aeg_lite = None

from . import aeg_java_bridge

__all__ = ["aeg_lite", "aeg_java_bridge"]