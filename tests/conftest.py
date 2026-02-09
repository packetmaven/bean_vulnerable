from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_syspath() -> None:
    """
    Ensure imports like `core.*` / `integrations.*` work in tests without requiring
    an editable install.

    This repo uses a `package_dir = src` layout (see `setup.cfg`), so adding
    `<repo_root>/src` to `sys.path` makes package imports resolve consistently.
    """
    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    if src_dir.exists() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))


_ensure_src_on_syspath()

