"""JNI taint engine orchestration."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from .jni_surface import JniSurfaceAnalyzer
from .native_resolver import NativeBindingResolver
from .jni_semantics import JNI_API_RULES
from .jni_register_natives import RegisterNativesParser
from .jni_invocation import JniInvocationAnalyzer
from .jni_symbol_scanner import JniSymbolScanner
from .native_ir import NativeIRBuilder
from .cross_language_points_to import CrossLanguagePointsToAnalyzer
from .native_taint_summaries import NativeTaintSummaryBuilder
from .taie_facts_ingestor import TaiEFactsIngestor
from .svf_output_adapter import SvfOutputAdapter


class JniTaintEngine:
    """Orchestrate JNI surface discovery and taint transfers."""

    def __init__(
        self,
        jni_mode: str = "heuristic",
        native_root: Optional[str] = None,
        resolve_register_natives: bool = False,
        disable_callbacks: bool = False,
        binary_path: Optional[str] = None,
        symbol_tool: Optional[str] = None,
        compile_commands_path: Optional[str] = None,
        crosslang_backend: str = "auto",
        taie_facts_path: Optional[str] = None,
        svf_output_path: Optional[str] = None,
        fail_closed: bool = False,
    ) -> None:
        self.jni_mode = jni_mode
        self.native_root = Path(native_root).expanduser() if native_root else None
        self.resolve_register_natives = resolve_register_natives
        self.disable_callbacks = disable_callbacks
        self.binary_path = Path(binary_path).expanduser() if binary_path else None
        self.symbol_tool = symbol_tool
        self.compile_commands_path = (
            Path(compile_commands_path).expanduser() if compile_commands_path else None
        )
        self.crosslang_backend = crosslang_backend
        self.taie_facts_path = Path(taie_facts_path).expanduser() if taie_facts_path else None
        self.svf_output_path = Path(svf_output_path).expanduser() if svf_output_path else None
        self.fail_closed = fail_closed
        self.surface_analyzer = JniSurfaceAnalyzer()
        self.binding_resolver = NativeBindingResolver(self.native_root)
        self.register_parser = RegisterNativesParser()
        self.invocation_analyzer = JniInvocationAnalyzer()
        self.symbol_scanner = JniSymbolScanner(symbol_tool=self.symbol_tool)
        self.native_ir_builder = NativeIRBuilder()
        self.crosslang_points_to = CrossLanguagePointsToAnalyzer()
        self.native_summary_builder = NativeTaintSummaryBuilder()
        self.taie_ingestor = TaiEFactsIngestor()
        self.svf_adapter = SvfOutputAdapter()

    def analyze(
        self,
        source_code: str,
        tainted_variables: Set[str],
    ) -> Dict[str, object]:
        result: Dict[str, object] = {
            "analysis_mode": self.jni_mode,
            "jni_methods": [],
            "jni_libraries": [],
            "resolved_bindings": [],
            "unresolved_bindings": [],
            "dynamic_registrations": [],
            "register_natives_calls": [],
            "taint_transfers": [],
            "jni_api_usage": {},
            "invocation_api_usage": {},
            "callback_api_usage": {},
            "callback_details": [],
            "symbol_scan": {},
            "binding_coverage": {},
            "native_risk_patterns": {},
            "jni_call_graph": [],
            "jni_points_to": {},
            "native_method_summaries": [],
            "crosslang_stats": {},
            "cross_language_backend_requested": self.crosslang_backend,
            "cross_language_backend": None,
            "cross_language_status": "not_run",
            "crosslang_impact": {},
            "taie_facts": {},
            "svf_output": {},
            "compile_commands_used": False,
            "errors": [],
        }

        surface = self.surface_analyzer.analyze(source_code)
        jni_methods = surface.get("jni_methods", [])
        jni_libraries = surface.get("jni_libraries", [])
        result["jni_methods"] = jni_methods
        result["jni_libraries"] = jni_libraries

        if self.native_root and self.native_root.exists():
            register_payload = self.register_parser.parse_native_root(self.native_root)
            result["dynamic_registrations"] = register_payload.get("entries", [])
            result["register_natives_calls"] = register_payload.get("registrations", [])

            invocation_payload = self.invocation_analyzer.analyze_native_root(self.native_root)
            result["invocation_api_usage"] = invocation_payload.get("invocation_api_usage", {})
            result["callback_api_usage"] = invocation_payload.get("callback_api_usage", {})
            result["callback_details"] = invocation_payload.get("callback_details", [])

            result["jni_api_usage"] = self._scan_jni_api_usage(self.native_root)
            result["native_risk_patterns"] = self._scan_native_risk_patterns(self.native_root)

        if self.binary_path:
            result["symbol_scan"] = self.symbol_scanner.scan(self.binary_path)

        if self.jni_mode in {"summary", "crosslang"} or self.resolve_register_natives:
            binding_result = self.binding_resolver.resolve(
                jni_methods,
                dynamic_bindings=result.get("dynamic_registrations", []),
                symbol_scan=result.get("symbol_scan", {}),
            )
            result["resolved_bindings"] = binding_result.get("resolved", [])
            result["unresolved_bindings"] = binding_result.get("unresolved", [])
            result["binding_coverage"] = binding_result.get("coverage", {})
        else:
            result["resolved_bindings"] = []
            result["unresolved_bindings"] = []
            result["binding_coverage"] = {}

        summary_index: Dict[str, List[Dict[str, object]]] = {}
        if self.jni_mode == "crosslang":
            self._run_cross_language_phase(result)
            if isinstance(result.get("native_method_summaries"), list):
                for summary in result["native_method_summaries"]:
                    if not isinstance(summary, dict):
                        continue
                    java_method = str(summary.get("java_method") or "")
                    if java_method:
                        summary_index.setdefault(java_method, []).append(summary)

        resolved_index = self._index_resolved_bindings(result.get("resolved_bindings", []))
        transfers = self._detect_java_transfers(
            source_code,
            jni_methods,
            tainted_variables,
            resolved_index,
            summary_index,
        )
        result["taint_transfers"] = transfers

        return result

    def _run_cross_language_phase(self, result: Dict[str, object]) -> None:
        if not self.native_root or not self.native_root.exists():
            message = "crosslang_mode_requires_native_root"
            result["errors"].append(message)
            result["cross_language_status"] = "failed"
            if self.fail_closed:
                raise RuntimeError(message)
            return

        native_ir = self.native_ir_builder.build(self.native_root, self.compile_commands_path)
        result["cross_language_backend"] = native_ir.get("backend")
        result["compile_commands_used"] = bool(native_ir.get("compile_commands_used"))
        for err in native_ir.get("errors", []) or []:
            result["errors"].append(f"native_ir:{err}")

        heuristic_payload = self.crosslang_points_to.analyze(
            resolved_bindings=result.get("resolved_bindings", []) if isinstance(result.get("resolved_bindings"), list) else [],
            dynamic_registrations=result.get("dynamic_registrations", []) if isinstance(result.get("dynamic_registrations"), list) else [],
            native_ir=native_ir,
        )
        heuristic_edges = (
            heuristic_payload.get("jni_call_graph", [])
            if isinstance(heuristic_payload.get("jni_call_graph"), list)
            else []
        )
        heuristic_points = (
            heuristic_payload.get("jni_points_to", {})
            if isinstance(heuristic_payload.get("jni_points_to"), dict)
            else {}
        )
        heuristic_stats = (
            heuristic_payload.get("crosslang_stats", {})
            if isinstance(heuristic_payload.get("crosslang_stats"), dict)
            else self._build_crosslang_stats(heuristic_points, heuristic_edges)
        )
        backend = self._select_crosslang_backend()
        taie_payload = self.taie_ingestor.load(self.taie_facts_path)
        svf_payload = self.svf_adapter.load(self.svf_output_path)
        result["taie_facts"] = {
            "loaded": bool(taie_payload.get("loaded")),
            "source_path": taie_payload.get("source_path"),
            "summary": taie_payload.get("summary", {}),
            "errors": taie_payload.get("errors", []),
        }
        result["svf_output"] = {
            "loaded": bool(svf_payload.get("loaded")),
            "source_path": svf_payload.get("source_path"),
            "summary": svf_payload.get("summary", {}),
            "errors": svf_payload.get("errors", []),
        }
        for err in taie_payload.get("errors", []) or []:
            result["errors"].append(f"taie:{err}")
        for err in svf_payload.get("errors", []) or []:
            result["errors"].append(f"svf:{err}")

        effective_backend = backend
        crosslang_status = "ok"
        using_taie_svf = backend == "taie_svf" or (
            backend == "auto" and bool(taie_payload.get("loaded")) and bool(svf_payload.get("loaded"))
        )
        if using_taie_svf:
            if not bool(taie_payload.get("loaded")) or not bool(svf_payload.get("loaded")):
                message = "crosslang_taie_svf_requested_but_facts_missing"
                result["errors"].append(message)
                if self.fail_closed:
                    result["cross_language_status"] = "failed_closed"
                    result["cross_language_backend"] = "taie_svf-v1"
                    raise RuntimeError(message)
                effective_backend = "heuristic"
                crosslang_status = "degraded_fallback"
            else:
                effective_backend = "taie_svf"
        elif backend == "auto":
            effective_backend = "heuristic"

        if effective_backend == "taie_svf":
            merged = self._merge_taie_svf_with_heuristic(heuristic_payload, taie_payload, svf_payload)
            result["cross_language_backend"] = "taie_svf-v1"
            result["cross_language_status"] = crosslang_status
            result["jni_call_graph"] = merged.get("jni_call_graph", [])
            result["jni_points_to"] = merged.get("jni_points_to", {})
            result["crosslang_stats"] = merged.get("crosslang_stats", {})
        else:
            result["cross_language_backend"] = heuristic_payload.get("backend") or result.get("cross_language_backend")
            result["cross_language_status"] = crosslang_status
            result["jni_call_graph"] = heuristic_payload.get("jni_call_graph", [])
            result["jni_points_to"] = heuristic_payload.get("jni_points_to", {})
            result["crosslang_stats"] = heuristic_payload.get("crosslang_stats", {})

        summary_payload = self.native_summary_builder.build(
            resolved_bindings=result.get("resolved_bindings", []) if isinstance(result.get("resolved_bindings"), list) else [],
            native_ir=native_ir,
            crosslang_points_to={
                "jni_points_to": result.get("jni_points_to", {}),
                "jni_call_graph": result.get("jni_call_graph", []),
            },
        )
        result["native_method_summaries"] = summary_payload.get("native_method_summaries", [])
        result["crosslang_impact"] = {"available": False}
        if effective_backend == "taie_svf":
            heuristic_summary_payload = self.native_summary_builder.build(
                resolved_bindings=result.get("resolved_bindings", []) if isinstance(result.get("resolved_bindings"), list) else [],
                native_ir=native_ir,
                crosslang_points_to={
                    "jni_points_to": heuristic_points,
                    "jni_call_graph": heuristic_edges,
                },
            )
            heuristic_summary_count = len(
                heuristic_summary_payload.get("native_method_summaries", [])
            ) if isinstance(heuristic_summary_payload.get("native_method_summaries"), list) else 0

            effective_edges = (
                result.get("jni_call_graph", [])
                if isinstance(result.get("jni_call_graph"), list)
                else []
            )
            effective_points = (
                result.get("jni_points_to", {})
                if isinstance(result.get("jni_points_to"), dict)
                else {}
            )
            effective_stats = (
                result.get("crosslang_stats", {})
                if isinstance(result.get("crosslang_stats"), dict)
                else self._build_crosslang_stats(effective_points, effective_edges)
            )
            effective_summary_count = len(result.get("native_method_summaries", [])) if isinstance(result.get("native_method_summaries"), list) else 0

            baseline_total_edges = int(heuristic_stats.get("total_edges", len(heuristic_edges)) or 0)
            effective_total_edges = int(effective_stats.get("total_edges", len(effective_edges)) or 0)
            baseline_points = int(self._count_points_to_bindings(heuristic_points) or 0)
            effective_points_count = int(self._count_points_to_bindings(effective_points) or 0)

            result["crosslang_impact"] = {
                "available": True,
                "status": "ok",
                "baseline_backend": str(heuristic_payload.get("backend") or "heuristic-crosslang-v1"),
                "effective_backend": "taie_svf-v1",
                "baseline": {
                    "jni_call_graph_edges": len(heuristic_edges),
                    "points_to_bindings": baseline_points,
                    "native_method_summaries": heuristic_summary_count,
                    "crosslang_stats": heuristic_stats,
                },
                "effective": {
                    "jni_call_graph_edges": len(effective_edges),
                    "points_to_bindings": effective_points_count,
                    "native_method_summaries": effective_summary_count,
                    "crosslang_stats": effective_stats,
                },
                "delta": {
                    "jni_call_graph_edges": len(effective_edges) - len(heuristic_edges),
                    "points_to_bindings": effective_points_count - baseline_points,
                    "native_method_summaries": effective_summary_count - heuristic_summary_count,
                    "total_edges": effective_total_edges - baseline_total_edges,
                },
            }
        elif result.get("cross_language_status") == "degraded_fallback":
            result["crosslang_impact"] = {
                "available": False,
                "status": "degraded_fallback",
                "reason": "taie_svf_artifacts_missing_fell_back_to_heuristic",
            }
        else:
            result["crosslang_impact"] = {
                "available": False,
                "status": "not_applicable",
                "reason": "effective_backend_is_heuristic",
            }

    def _select_crosslang_backend(self) -> str:
        candidate = str(self.crosslang_backend or "auto").strip().lower()
        if candidate in {"auto", "heuristic", "taie_svf"}:
            return candidate
        return "auto"

    def _merge_taie_svf_with_heuristic(
        self,
        heuristic_payload: Dict[str, object],
        taie_payload: Dict[str, object],
        svf_payload: Dict[str, object],
    ) -> Dict[str, object]:
        heuristic_edges = heuristic_payload.get("jni_call_graph", []) if isinstance(heuristic_payload.get("jni_call_graph"), list) else []
        taie_edges = taie_payload.get("call_graph", []) if isinstance(taie_payload.get("call_graph"), list) else []
        svf_edges = svf_payload.get("call_graph", []) if isinstance(svf_payload.get("call_graph"), list) else []

        merged_edges: List[Dict[str, object]] = []
        for edge in heuristic_edges + taie_edges + svf_edges:
            if not isinstance(edge, dict):
                continue
            source = str(edge.get("source") or edge.get("src") or "")
            target = str(edge.get("target") or edge.get("dst") or "")
            if not source or not target:
                continue
            merged_edges.append(
                {
                    "source": source,
                    "target": target,
                    "kind": edge.get("kind", "crosslang_edge"),
                    "resolver": edge.get("resolver", "crosslang_merge"),
                    "confidence": edge.get("confidence", "medium"),
                    "binding_type": edge.get("binding_type"),
                }
            )

        edge_unique = {}
        for edge in merged_edges:
            key = (edge.get("source"), edge.get("target"), edge.get("kind"), edge.get("resolver"))
            edge_unique[key] = edge
        ordered_edges = sorted(
            edge_unique.values(),
            key=lambda item: (str(item.get("source")), str(item.get("target")), str(item.get("kind"))),
        )

        heuristic_points = heuristic_payload.get("jni_points_to", {}) if isinstance(heuristic_payload.get("jni_points_to"), dict) else {}
        taie_points = taie_payload.get("points_to", {}) if isinstance(taie_payload.get("points_to"), dict) else {}
        svf_points = svf_payload.get("points_to", {}) if isinstance(svf_payload.get("points_to"), dict) else {}
        merged_points = self._merge_points_to_maps(heuristic_points, taie_points, svf_points)

        return {
            "jni_call_graph": ordered_edges[:2000],
            "jni_points_to": merged_points,
            "crosslang_stats": self._build_crosslang_stats(merged_points, ordered_edges),
        }

    def _merge_points_to_maps(self, *maps: Dict[str, object]) -> Dict[str, object]:
        merged: Dict[str, object] = {}
        for payload in maps:
            if not isinstance(payload, dict):
                continue
            for key, value in payload.items():
                key_s = str(key)
                if isinstance(value, dict):
                    existing = merged.get(key_s)
                    if not isinstance(existing, dict):
                        existing = {}
                    for inner_key, inner_val in value.items():
                        inner_k = str(inner_key)
                        if isinstance(inner_val, list):
                            cur = existing.get(inner_k, [])
                            if not isinstance(cur, list):
                                cur = [str(cur)]
                            cur.extend([str(item) for item in inner_val if item is not None])
                            existing[inner_k] = sorted(set(cur))
                        elif inner_val is not None:
                            cur = existing.get(inner_k, [])
                            if not isinstance(cur, list):
                                cur = [str(cur)]
                            cur.append(str(inner_val))
                            existing[inner_k] = sorted(set(cur))
                    merged[key_s] = existing
                elif isinstance(value, list):
                    cur = merged.get(key_s, [])
                    if not isinstance(cur, list):
                        cur = [str(cur)]
                    cur.extend([str(item) for item in value if item is not None])
                    merged[key_s] = sorted(set(cur))
                elif value is not None:
                    merged[key_s] = value
        return merged

    def _build_crosslang_stats(
        self, merged_points: Dict[str, object], merged_edges: List[Dict[str, object]]
    ) -> Dict[str, int]:
        java_to_native_edges = 0
        native_to_native_edges = 0
        native_to_java_callback_edges = 0
        for edge in merged_edges:
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            if source.startswith("java:") and target.startswith("native:"):
                java_to_native_edges += 1
            if source.startswith("native:") and target.startswith("native:"):
                native_to_native_edges += 1
            if source.startswith("native:") and target.startswith("java:"):
                native_to_java_callback_edges += 1
        points_bindings = self._count_points_to_bindings(merged_points)
        return {
            "java_to_native_edges": java_to_native_edges,
            "native_to_native_edges": native_to_native_edges,
            "native_to_java_callback_edges": native_to_java_callback_edges,
            "points_to_bindings": points_bindings,
            "total_edges": len(merged_edges),
        }

    def _count_points_to_bindings(self, points_map: Dict[str, object]) -> int:
        java_to_native = points_map.get("java_to_native_bindings", {})
        if not isinstance(java_to_native, dict):
            return 0
        return sum(len(v) for v in java_to_native.values() if isinstance(v, list))

    def _detect_java_transfers(
        self,
        source_code: str,
        jni_methods: Iterable[Dict[str, object]],
        tainted_variables: Set[str],
        resolved_index: Dict[str, Dict[str, object]],
        summary_index: Dict[str, List[Dict[str, object]]],
    ) -> List[Dict[str, object]]:
        transfers: List[Dict[str, object]] = []
        lines = source_code.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue
            if stripped.startswith("import ") or stripped.startswith("package "):
                continue

            for method in jni_methods:
                method_name = str(method.get("name") or "")
                if not method_name or method_name not in line:
                    continue

                # Skip native method declarations
                if re.search(rf"\bnative\b.*\b{re.escape(method_name)}\b", line):
                    continue

                # Check call site: methodName(arg1, arg2)
                call_match = re.search(rf"\b{re.escape(method_name)}\s*\(([^)]*)\)", line)
                if not call_match:
                    continue

                arg_text = call_match.group(1)
                arg_vars = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", arg_text)
                tainted_args = [v for v in arg_vars if v in tainted_variables]
                binding = resolved_index.get(method_name, {})
                signature = binding.get("signature") or self._method_param_signature(method)
                binding_type = binding.get("binding_type", "unknown")
                resolver = binding.get("resolver", "java_callsite")
                native_summaries = summary_index.get(method_name, [])
                sink_kinds: List[str] = []
                callback_apis: List[str] = []
                for summary in native_summaries:
                    if not isinstance(summary, dict):
                        continue
                    arg_to_sink = summary.get("arg_to_sink", [])
                    if isinstance(arg_to_sink, list):
                        sink_kinds.extend([str(item.get("kind")) for item in arg_to_sink if isinstance(item, dict) and item.get("kind")])
                    arg_to_callback = summary.get("arg_to_callback", [])
                    if isinstance(arg_to_callback, list):
                        callback_apis.extend([str(api) for api in arg_to_callback if api])
                sink_kinds = sorted(set(sink_kinds))
                callback_apis = sorted(set(callback_apis))

                if tainted_args:
                    transfer_entry: Dict[str, object] = {
                        "method": method_name,
                        "signature": signature,
                        "binding_type": binding_type,
                        "resolver": resolver,
                        "line": i,
                        "tainted_params": tainted_args,
                        "direction": "java_to_native",
                    }
                    if sink_kinds:
                        transfer_entry["effect"] = "arg_to_sink"
                        transfer_entry["sink_kinds"] = sink_kinds
                    transfers.append(transfer_entry)

                if tainted_args and callback_apis and not self.disable_callbacks:
                    transfers.append(
                        {
                            "method": method_name,
                            "signature": signature,
                            "binding_type": binding_type,
                            "resolver": resolver,
                            "line": i,
                            "tainted_params": tainted_args,
                            "direction": "native_callback",
                            "effect": "native_to_java_callback",
                            "callback_apis": callback_apis,
                        }
                    )

                assign_match = re.search(rf"\b(\w+)\s*=\s*{re.escape(method_name)}\s*\(", line)
                if assign_match:
                    result_var = assign_match.group(1)
                    transfers.append(
                        {
                            "method": method_name,
                            "signature": signature,
                            "binding_type": binding_type,
                            "resolver": resolver,
                            "line": i,
                            "result_var": result_var,
                            "direction": "native_to_java",
                        }
                    )

        return transfers

    def _method_param_signature(self, method: Dict[str, object]) -> str:
        params = str(method.get("params") or "").strip()
        if not params:
            return "()"
        # Display-friendly signature for edge metadata.
        param_names = []
        for chunk in params.split(","):
            token = chunk.strip()
            if not token:
                continue
            parts = token.split()
            if len(parts) >= 2:
                param_names.append(parts[-2] if parts[-1].startswith("...") else parts[0])
            else:
                param_names.append(parts[0])
        return "(" + ", ".join(param_names) + ")"

    def _index_resolved_bindings(self, resolved_bindings: object) -> Dict[str, Dict[str, object]]:
        index: Dict[str, Dict[str, object]] = {}
        if not isinstance(resolved_bindings, list):
            return index
        priority = {"register_natives": 3, "static": 2, "symbol_only": 1, "unknown": 0}
        for entry in resolved_bindings:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("java_name") or "")
            if not name:
                continue
            current = index.get(name)
            if not current:
                index[name] = entry
                continue
            cur_p = priority.get(str(current.get("binding_type", "unknown")), 0)
            new_p = priority.get(str(entry.get("binding_type", "unknown")), 0)
            if new_p >= cur_p:
                index[name] = entry
        return index

    def _scan_jni_api_usage(self, native_root: Path) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for path in native_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for api in JNI_API_RULES.keys():
                if api in text:
                    counts[api] = counts.get(api, 0) + text.count(api)
        return counts

    def _scan_native_risk_patterns(self, native_root: Path) -> Dict[str, object]:
        counts = {
            "file_io_calls": 0,
            "command_exec_calls": 0,
            "runtime_callback_calls": 0,
            "reflection_lookup_calls": 0,
            "register_natives_calls": 0,
            "suspected_resource_leaks": 0,
        }
        evidence: List[Dict[str, object]] = []
        get_string_calls = 0
        release_string_calls = 0

        for path in native_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for line_no, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                if re.search(r"\b(fopen|open|freopen|CreateFile)\b", stripped):
                    counts["file_io_calls"] += 1
                    evidence.append({"pattern": "file_io", "file": str(path), "line": line_no, "snippet": stripped[:240]})
                if re.search(r"\b(system|execve|execl|execlp|execvp|popen)\b", stripped):
                    counts["command_exec_calls"] += 1
                    evidence.append({"pattern": "command_exec", "file": str(path), "line": line_no, "snippet": stripped[:240]})
                if re.search(r"\b(CallObjectMethod|CallStaticObjectMethod|CallVoidMethod|CallStaticVoidMethod)\b", stripped):
                    counts["runtime_callback_calls"] += 1
                    evidence.append({"pattern": "native_callback", "file": str(path), "line": line_no, "snippet": stripped[:240]})
                if re.search(r"\b(FindClass|GetMethodID|GetStaticMethodID)\b", stripped):
                    counts["reflection_lookup_calls"] += 1
                    evidence.append({"pattern": "reflection_lookup", "file": str(path), "line": line_no, "snippet": stripped[:240]})
                if "RegisterNatives" in stripped:
                    counts["register_natives_calls"] += 1
                    evidence.append({"pattern": "register_natives", "file": str(path), "line": line_no, "snippet": stripped[:240]})
                if "GetStringUTFChars" in stripped:
                    get_string_calls += 1
                if "ReleaseStringUTFChars" in stripped:
                    release_string_calls += 1

        leak_gap = max(get_string_calls - release_string_calls, 0)
        counts["suspected_resource_leaks"] = leak_gap
        return {"counts": counts, "evidence": evidence[:120]}
