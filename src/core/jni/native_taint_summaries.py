"""Build caller-sensitive native taint summaries for JNI-bound methods."""
from __future__ import annotations

import re
from typing import Dict, List


class NativeTaintSummaryBuilder:
    """Generate summary-level taint effects for native JNI handlers."""

    _SINK_PATTERNS = {
        "command_exec": r"\b(system|execve|execl|execlp|execvp|popen)\s*\(",
        "file_io": r"\b(fopen|open|freopen|CreateFile)\s*\(",
        "network_io": r"\b(send|sendto|write|SSL_write|connect)\s*\(",
    }

    def build(
        self,
        resolved_bindings: List[Dict[str, object]],
        native_ir: Dict[str, object],
        crosslang_points_to: Dict[str, object],
    ) -> Dict[str, object]:
        functions = native_ir.get("functions", []) if isinstance(native_ir, dict) else []
        by_name: Dict[str, Dict[str, object]] = {}
        for func in functions:
            if isinstance(func, dict):
                name = str(func.get("name") or "")
                if name and name not in by_name:
                    by_name[name] = func

        summaries: List[Dict[str, object]] = []
        transfer_hints: List[Dict[str, object]] = []

        callback_map = {}
        if isinstance(crosslang_points_to, dict):
            pt = crosslang_points_to.get("jni_points_to", {})
            if isinstance(pt, dict):
                callback_map = pt.get("native_to_java_callbacks", {})
                if not isinstance(callback_map, dict):
                    callback_map = {}

        for binding in resolved_bindings:
            if not isinstance(binding, dict):
                continue
            java_name = str(binding.get("java_name") or "")
            native_func = str(binding.get("native_func") or "")
            if not java_name or not native_func:
                continue
            func = by_name.get(native_func)
            if not func:
                continue

            body = str(func.get("body") or "")
            params = [str(p) for p in (func.get("params") or []) if p]
            summary = {
                "java_method": java_name,
                "signature": binding.get("signature"),
                "native_func": native_func,
                "file": func.get("file"),
                "line_start": func.get("line_start"),
                "line_end": func.get("line_end"),
                "binding_type": binding.get("binding_type"),
                "resolver": binding.get("resolver"),
                "arg_to_return": False,
                "arg_to_sink": [],
                "arg_to_callback": [],
                "resource_leak_signals": 0,
            }

            for param in params:
                if re.search(rf"\breturn\s+\(?\s*{re.escape(param)}\s*\)?\s*;", body):
                    summary["arg_to_return"] = True
                    break

            for sink_kind, sink_re in self._SINK_PATTERNS.items():
                for match in re.finditer(sink_re, body):
                    line_snippet = self._line_at_offset(body, match.start())
                    tainted_params = [p for p in params if re.search(rf"\b{re.escape(p)}\b", line_snippet)]
                    summary["arg_to_sink"].append(
                        {
                            "kind": sink_kind,
                            "snippet": line_snippet[:200],
                            "tainted_params": tainted_params,
                        }
                    )

            callback_apis = callback_map.get(native_func, [])
            if isinstance(callback_apis, list):
                summary["arg_to_callback"] = sorted(set(str(api) for api in callback_apis if api))

            gets = len(re.findall(r"\bGetStringUTFChars\b", body))
            releases = len(re.findall(r"\bReleaseStringUTFChars\b", body))
            if gets > releases:
                summary["resource_leak_signals"] = gets - releases

            summaries.append(summary)

            if summary["arg_to_sink"]:
                transfer_hints.append(
                    {
                        "java_method": java_name,
                        "native_func": native_func,
                        "effect": "arg_to_sink",
                        "sink_kinds": sorted(set(item["kind"] for item in summary["arg_to_sink"])),
                    }
                )
            if summary["arg_to_callback"]:
                transfer_hints.append(
                    {
                        "java_method": java_name,
                        "native_func": native_func,
                        "effect": "native_callback",
                        "callback_apis": summary["arg_to_callback"],
                    }
                )
            if summary["arg_to_return"]:
                transfer_hints.append(
                    {
                        "java_method": java_name,
                        "native_func": native_func,
                        "effect": "arg_to_return",
                    }
                )

        index: Dict[str, List[Dict[str, object]]] = {}
        for summary in summaries:
            method = str(summary.get("java_method") or "")
            if not method:
                continue
            index.setdefault(method, []).append(summary)

        return {
            "native_method_summaries": summaries,
            "summary_index": index,
            "transfer_hints": transfer_hints,
        }

    @staticmethod
    def _line_at_offset(text: str, offset: int) -> str:
        start = text.rfind("\n", 0, offset)
        end = text.find("\n", offset)
        if start == -1:
            start = 0
        else:
            start += 1
        if end == -1:
            end = len(text)
        return text[start:end].strip()
