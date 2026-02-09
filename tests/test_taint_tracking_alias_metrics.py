from __future__ import annotations


def _import_tracker():
    try:
        from src.core.comprehensive_taint_tracking import ComprehensiveTaintTracker  # type: ignore

        return ComprehensiveTaintTracker
    except Exception:
        from core.comprehensive_taint_tracking import ComprehensiveTaintTracker  # type: ignore

        return ComprehensiveTaintTracker


def test_alias_metrics_do_not_count_import_or_package_lines_as_field_accesses():
    ComprehensiveTaintTracker = _import_tracker()

    code = "\n".join(
        [
            "package com.example.foo;",
            "import javax.servlet.http.HttpServletRequest;",
            "import java.util.List;",
            "public class T {",
            "  public void m(HttpServletRequest request) {",
            '    String x = request.getParameter("q");',
            "  }",
            "}",
        ]
    )

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=False,
    )
    result = tracker.analyze_java_code(code)
    alias = result.get("alias_analysis", {})

    assert int(alias.get("field_accesses", -1)) == 0


def test_alias_metrics_count_real_field_accesses():
    ComprehensiveTaintTracker = _import_tracker()

    code = "\n".join(
        [
            "package com.example;",
            "public class T {",
            "  static class Foo { int x; }",
            "  public void m() {",
            "    Foo f = new Foo();",
            "    f.x = 1;",
            "    int y = f.x;",
            "  }",
            "}",
        ]
    )

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=False,
    )
    result = tracker.analyze_java_code(code)
    alias = result.get("alias_analysis", {})

    assert int(alias.get("field_accesses", 0)) >= 1

