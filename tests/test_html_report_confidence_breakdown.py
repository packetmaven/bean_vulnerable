from __future__ import annotations

from pathlib import Path


def _import_report_generator():
    try:
        from src.core.html_report_generator import generate_comprehensive_html_report  # type: ignore

        return generate_comprehensive_html_report
    except Exception:
        from core.html_report_generator import generate_comprehensive_html_report  # type: ignore

        return generate_comprehensive_html_report


def test_html_report_contains_confidence_breakdown_panel(tmp_path):
    generate_comprehensive_html_report = _import_report_generator()

    java_path = tmp_path / "Sample.java"
    java_path.write_text(
        "\n".join(
            [
                "public class Sample {",
                "  static class Profile { String name; }",
                "  public void handle(String userInput) {",
                "    Profile p = new Profile();",
                "    p.name = userInput;",
                "    String safe = userInput.replace(\"<\", \"&lt;\");",
                "    System.out.println(p.name + safe);",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    report_dir = tmp_path / "report"
    report_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "input": str(java_path),
        "input_type": "file",
        "analysis_method": "test",
        "vulnerability_detected": True,
        "vulnerability_type": "xss",
        "confidence": 0.86,
        "confidence_logit_only": 0.86,
        "heuristic_confidence": 0.86,
        "gnn_confidence": 0.18,
        "gnn_confidence_logit_only": 0.05,
        "spatial_gnn": {"weights_loaded": True, "forward_called": True, "used_in_scoring": True},
        "cescl_is_ood": False,
        "cescl_ood_score": 0.12,
        "cescl_calibrated_confidence": 0.21,
        "confidence_fusion": {
            "heuristic": 0.86,
            "gnn_raw": 0.18,
            "ood_detected": False,
            "combined": 0.86,
            "source": "heuristic_only",
        },
        "confidence_fusion_logit_only": {
            "heuristic": 0.86,
            "gnn_raw": 0.05,
            "ood_detected": False,
            "combined": 0.86,
            "source": "heuristic_only",
        },
        "cpg": {"nodes": 1, "edges": 0, "methods": 0, "calls": 0},
        "taint_tracking": {
            "taint_flows": [
                {"target": "userInput", "source": "Heuristic:userInput", "is_sanitized": False},
                {"target": "p.name", "source": "userInput(field)", "is_sanitized": False},
            ],
            "tainted_variables": ["userInput"],
            "sanitized_variables": ["safe"],
            "tainted_fields": ["p.name"],
            "alias_analysis": {
                "variables_tracked": 11,
                "field_accesses": 7,
                "allocation_sites": 3,
                "must_not_alias_pairs": 0,
                "cache_size": 8,
                "refinement_iterations": 1,
            },
        },
    }

    generate_comprehensive_html_report(result, report_dir, java_path.name)

    index_path = report_dir / "index.html"
    assert index_path.exists()

    html = index_path.read_text(encoding="utf-8", errors="ignore")

    # Security-critical panel: ensures fusion evidence is visible to analysts.
    assert "Confidence breakdown" in html
    assert "Fusion source" in html
    assert "heuristic_only" in html

    # Basic sanity: metric values should render (avoid confusing all-zero dashboards).
    assert "Variables Tracked" in html
    assert ">11<" in html

