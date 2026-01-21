#!/usr/bin/env python3
"""
CLI smoke tests for Bean Vulnerable.
Ensures argument parsing works without executing analysis.
"""

import subprocess
import sys
from pathlib import Path


def _run_help(script_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script_path), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_help():
    repo_root = Path(__file__).resolve().parents[1]
    cli_path = repo_root / "src" / "core" / "bean_vuln_cli.py"
    result = _run_help(cli_path)
    assert result.returncode == 0
    assert "Bean Vulnerable" in (result.stdout + result.stderr)


def test_cli_enhanced_help():
    repo_root = Path(__file__).resolve().parents[1]
    cli_path = repo_root / "src" / "core" / "bean_vuln_cli_enhanced.py"
    result = _run_help(cli_path)
    assert result.returncode == 0
    assert "Bean Vulnerable" in (result.stdout + result.stderr)
