# Bean Vulnerable GNN Framework - Source Package

# Import main components. Avoid importing heavy optional subpackages at module import time.
from . import core  # noqa: F401
from . import integrations  # noqa: F401

# Import CLI for direct access
try:
    from . import bean_vuln_cli
except ImportError:
    pass  # CLI may not be available in all environments

__version__ = "2.0.0"
__all__ = ["core", "integrations"]

