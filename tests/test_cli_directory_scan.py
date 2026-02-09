from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional


def _import_cli_module():
    """
    Import helper to keep tests resilient to different PYTHONPATH setups.
    """
    try:
        from src.core import bean_vuln_cli as cli  # type: ignore
        return cli
    except Exception:
        import core.bean_vuln_cli as cli  # type: ignore

        return cli


def test_analyze_directory_processes_all_java_files(tmp_path, monkeypatch):
    cli = _import_cli_module()

    # Intentionally out of order to validate deterministic sorting.
    (tmp_path / "b.java").write_text("public class B {}", encoding="utf-8")
    (tmp_path / "a.java").write_text("public class A {}", encoding="utf-8")

    calls = []

    def fake_analyze_path(
        source_path: Path,
        recursive: bool,
        keep_workdir: bool,
        export_dir: Optional[Path],
        cli_args: Any,
        report_dir: Optional[Path],
    ) -> Dict[str, Any]:
        calls.append(source_path.name)
        return {
            "input": str(source_path),
            "input_type": "file",
            "vulnerability_detected": source_path.name == "b.java",
            "confidence": 0.9 if source_path.name == "b.java" else 0.1,
            "cpg": {"nodes": 1, "edges": 2, "methods": 1, "calls": 0},
            "gnn_utilized": False,
        }

    monkeypatch.setattr(cli, "analyze_path", fake_analyze_path)

    result = cli.analyze_directory(tmp_path, recursive=False, cli_args=None, report_dir=None)

    assert result["dataset_type"] == "directory"
    assert result["total_files"] == 2
    assert result["processed_count"] == 2
    assert result["successful_count"] == 2
    assert len(result["results"]) == 2

    # Deterministic ordering is a stability requirement for research workflows.
    assert calls == ["a.java", "b.java"]
    assert [Path(r["input"]).name for r in result["results"]] == ["a.java", "b.java"]

    # Aggregates should remain meaningful for CLI summary output.
    assert result["vulnerability_detected"] is True
    assert result["cpg"]["nodes"] == 2
    assert result["cpg"]["edges"] == 4

