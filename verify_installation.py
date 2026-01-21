#!/usr/bin/env python3
"""
Lightweight installation verification for Bean Vulnerable.
Checks core imports and optional dependencies without running analysis.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
import shutil
import os

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "src"))


OPTIONAL_IMPORTS = [
    "torch",
    "torch_geometric",
    "torch_scatter",
    "torch_sparse",
    "torch_cluster",
    "torch_spline_conv",
    "transformers",
    "dgl",
    "torchdata",
    "numpy",
    "pandas",
    "yaml",
]


def _check_import(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def _joern_available() -> bool:
    return (
        shutil.which("joern") is not None
        or Path("/usr/local/bin/joern").exists()
        or Path("/opt/joern/joern-cli/joern").exists()
    )


def main() -> int:
    print("✅ Bean Vulnerable installation check")
    print(f"Python: {sys.version.split()[0]}")

    missing = []
    disable_numpy = os.environ.get("BEAN_VULN_DISABLE_NUMPY") == "1"
    for module in OPTIONAL_IMPORTS:
        if disable_numpy and module == "numpy":
            print(f"  {module:<10} SKIPPED (BEAN_VULN_DISABLE_NUMPY=1)")
            continue
        ok = _check_import(module)
        print(f"  {module:<10} {'OK' if ok else 'MISSING'}")
        if not ok:
            missing.append(module)

    try:
        from core.integrated_gnn_framework import IntegratedGNNFramework  # noqa: F401
        print("  core framework import: OK")
    except Exception as exc:
        print(f"  core framework import: FAILED ({exc})")
        return 1

    if _joern_available():
        print("  Joern: detected")
    else:
        print("  Joern: NOT detected (analysis requires Joern to be installed)")

    if missing:
        print("⚠️ Optional dependencies missing. See README for install steps.")
        if "transformers" in missing:
            print("   - transformers is required for CodeBERT embeddings (no fallback).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
