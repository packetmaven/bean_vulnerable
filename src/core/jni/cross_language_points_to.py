"""Heuristic cross-language points-to and call-graph reconstruction for JNI."""
from __future__ import annotations

from typing import Dict, List


class CrossLanguagePointsToAnalyzer:
    """Approximate Java<->native call edges and points-to relations."""

    def analyze(
        self,
        resolved_bindings: List[Dict[str, object]],
        dynamic_registrations: List[Dict[str, object]],
        native_ir: Dict[str, object],
    ) -> Dict[str, object]:
        call_graph: List[Dict[str, object]] = []
        java_to_native: Dict[str, List[str]] = {}
        native_to_native: Dict[str, List[str]] = {}
        native_to_java_callbacks: Dict[str, List[str]] = {}
        register_tables: Dict[str, List[str]] = {}

        functions = native_ir.get("functions", []) if isinstance(native_ir, dict) else []
        function_names = {str(func.get("name", "")) for func in functions if isinstance(func, dict)}

        for binding in resolved_bindings:
            if not isinstance(binding, dict):
                continue
            java_name = str(binding.get("java_name") or "")
            native_func = str(binding.get("native_func") or binding.get("mangled") or "")
            if not java_name or not native_func:
                continue
            java_to_native.setdefault(java_name, []).append(native_func)
            call_graph.append(
                {
                    "source": f"java:{java_name}",
                    "target": f"native:{native_func}",
                    "kind": "jni_binding",
                    "resolver": binding.get("resolver"),
                    "confidence": binding.get("confidence"),
                    "binding_type": binding.get("binding_type"),
                }
            )

        for reg in dynamic_registrations:
            if not isinstance(reg, dict):
                continue
            table = str(reg.get("table") or "unknown")
            native_symbol = str(reg.get("native_symbol") or reg.get("native_func") or "")
            if native_symbol:
                register_tables.setdefault(table, []).append(native_symbol)

        for func in functions:
            if not isinstance(func, dict):
                continue
            name = str(func.get("name") or "")
            if not name:
                continue
            native_calls = [str(c) for c in (func.get("native_calls") or []) if str(c) in function_names]
            if native_calls:
                native_to_native[name] = sorted(set(native_calls))
                for callee in native_to_native[name]:
                    call_graph.append(
                        {
                            "source": f"native:{name}",
                            "target": f"native:{callee}",
                            "kind": "native_call",
                            "resolver": "native_ir",
                            "confidence": "medium",
                            "binding_type": "native",
                        }
                    )

            callback_apis = sorted(set(str(api) for api in (func.get("callback_apis") or []) if api))
            if callback_apis:
                native_to_java_callbacks[name] = callback_apis
                for api in callback_apis:
                    call_graph.append(
                        {
                            "source": f"native:{name}",
                            "target": f"java:callback:{api}",
                            "kind": "native_to_java_callback",
                            "resolver": "jni_callback_pattern",
                            "confidence": "medium",
                            "binding_type": "invocation",
                        }
                    )

        # Deduplicate and sort deterministic output.
        unique_edges = {}
        for edge in call_graph:
            key = (
                edge.get("source"),
                edge.get("target"),
                edge.get("kind"),
                edge.get("resolver"),
            )
            unique_edges[key] = edge
        ordered_edges = sorted(
            unique_edges.values(),
            key=lambda e: (str(e.get("source")), str(e.get("target")), str(e.get("kind"))),
        )

        return {
            "backend": "heuristic-crosslang-v1",
            "jni_call_graph": ordered_edges[:1000],
            "jni_points_to": {
                "java_to_native_bindings": {k: sorted(set(v)) for k, v in java_to_native.items()},
                "native_to_native_calls": native_to_native,
                "native_to_java_callbacks": native_to_java_callbacks,
                "register_natives_tables": {k: sorted(set(v)) for k, v in register_tables.items()},
            },
            "crosslang_stats": {
                "java_to_native_edges": sum(len(v) for v in java_to_native.values()),
                "native_to_native_edges": sum(len(v) for v in native_to_native.values()),
                "native_to_java_callback_edges": sum(len(v) for v in native_to_java_callbacks.values()),
                "total_edges": len(ordered_edges),
            },
        }
