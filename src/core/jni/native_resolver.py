"""Native binding resolution for JNI methods."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


class NativeBindingResolver:
    """Resolve JNI native bindings using source and optional symbol evidence."""

    _NATIVE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
    _SIG_TYPE_MAP = {
        "void": "V",
        "boolean": "Z",
        "byte": "B",
        "char": "C",
        "short": "S",
        "int": "I",
        "long": "J",
        "float": "F",
        "double": "D",
        "String": "Ljava/lang/String;",
    }

    def __init__(self, native_root: Optional[Path] = None) -> None:
        self.native_root = Path(native_root) if native_root else None

    def resolve(
        self,
        jni_methods: Iterable[Dict[str, object]],
        dynamic_bindings: Optional[List[Dict[str, object]]] = None,
        symbol_scan: Optional[Dict[str, object]] = None,
    ) -> Dict[str, object]:
        resolved: List[Dict[str, object]] = []
        unresolved: List[Dict[str, object]] = []
        dynamic_bindings = dynamic_bindings or []
        symbol_scan = symbol_scan or {}
        symbol_set = set(symbol_scan.get("jni_symbols", []) or [])
        seen_signatures: Set[Tuple[str, str, str]] = set()

        dynamic_by_name: Dict[str, List[Dict[str, object]]] = {}
        for entry in dynamic_bindings:
            if not isinstance(entry, dict):
                continue
            java_name = str(entry.get("java_name") or "")
            if not java_name:
                continue
            dynamic_by_name.setdefault(java_name, []).append(entry)

        for method in jni_methods:
            name = str(method.get("name") or "")
            mangled = str(method.get("mangled_base") or "")
            signature = self._method_signature(method)
            if not name or not mangled:
                unresolved.append(
                    {
                        "java_name": name,
                        "candidate": mangled,
                        "reason": "missing_class_or_package",
                    }
                )
                continue

            found = False

            static_match = self._find_native_definition(mangled)
            if static_match:
                found = True
                entry = {
                    "java_name": name,
                    "signature": signature,
                    "mangled": mangled,
                    "native_func": mangled,
                    "binding_type": "static",
                    "resolver": "source_scan",
                    "confidence": "native_root_match",
                    "file": static_match.get("file"),
                    "line": static_match.get("line"),
                    "evidence": "native_source_definition",
                }
                key = (entry["java_name"], entry["native_func"], entry["binding_type"])
                if key not in seen_signatures:
                    resolved.append(entry)
                    seen_signatures.add(key)

            for dynamic in dynamic_by_name.get(name, []):
                found = True
                native_func = str(dynamic.get("native_symbol") or dynamic.get("native_func") or "")
                entry = {
                    "java_name": name,
                    "signature": dynamic.get("signature") or signature,
                    "mangled": mangled,
                    "native_func": native_func or str(dynamic.get("native_func") or ""),
                    "binding_type": "register_natives",
                    "resolver": "register_natives",
                    "confidence": dynamic.get("confidence", "dynamic_registration"),
                    "file": dynamic.get("file"),
                    "line": dynamic.get("line"),
                    "evidence": f"table:{dynamic.get('table')}" if dynamic.get("table") else "register_natives",
                }
                key = (entry["java_name"], str(entry["native_func"]), entry["binding_type"])
                if key not in seen_signatures:
                    resolved.append(entry)
                    seen_signatures.add(key)

            if mangled in symbol_set:
                found = True
                entry = {
                    "java_name": name,
                    "signature": signature,
                    "mangled": mangled,
                    "native_func": mangled,
                    "binding_type": "static",
                    "resolver": "symbol_table",
                    "confidence": "symbol_match",
                    "file": symbol_scan.get("binary"),
                    "line": None,
                    "evidence": "binary_symbol",
                }
                key = (entry["java_name"], entry["native_func"], entry["binding_type"])
                if key not in seen_signatures:
                    resolved.append(entry)
                    seen_signatures.add(key)

            if not found:
                unresolved.append(
                    {
                        "java_name": name,
                        "signature": signature,
                        "candidate": mangled,
                        "reason": "native_symbol_not_found",
                    }
                )

        known_methods = {str(m.get("name") or "") for m in jni_methods if isinstance(m, dict)}
        for dynamic in dynamic_bindings:
            if not isinstance(dynamic, dict):
                continue
            java_name = str(dynamic.get("java_name") or "")
            if not java_name or java_name in known_methods:
                continue
            entry = {
                "java_name": java_name,
                "signature": dynamic.get("signature"),
                "mangled": None,
                "native_func": dynamic.get("native_symbol") or dynamic.get("native_func"),
                "binding_type": "register_natives",
                "resolver": "register_natives",
                "confidence": dynamic.get("confidence", "dynamic_registration"),
                "file": dynamic.get("file"),
                "line": dynamic.get("line"),
                "evidence": "register_natives_unknown_java_decl",
            }
            key = (entry["java_name"], str(entry["native_func"]), entry["binding_type"])
            if key not in seen_signatures:
                resolved.append(entry)
                seen_signatures.add(key)

        coverage: Dict[str, int] = {}
        for entry in resolved:
            binding_type = str(entry.get("binding_type") or "unknown")
            coverage[binding_type] = coverage.get(binding_type, 0) + 1

        return {"resolved": resolved, "unresolved": unresolved, "coverage": coverage}

    def _find_native_definition(self, mangled: str) -> Optional[Dict[str, object]]:
        if not self.native_root or not self.native_root.exists():
            return None

        for path in self._iter_native_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if mangled not in text:
                continue

            for idx, line in enumerate(text.splitlines(), 1):
                if mangled in line:
                    if "JNIEXPORT" in line or "JNICALL" in line or re.search(rf"\b{re.escape(mangled)}\b", line):
                        return {"file": str(path), "line": idx}

        return None

    def _method_signature(self, method: Dict[str, object]) -> str:
        params = str(method.get("params") or "").strip()
        if not params:
            return "()"
        parts = []
        for raw in params.split(","):
            token = raw.strip()
            if not token:
                continue
            tokens = token.split()
            if len(tokens) >= 2:
                param_type = " ".join(tokens[:-1]).strip()
            else:
                param_type = tokens[0]
            parts.append(self._to_jni_type(param_type))
        return "(" + "".join(parts) + ")"

    def _to_jni_type(self, java_type: str) -> str:
        t = java_type.replace("final ", "").replace("volatile ", "").strip()
        if t.endswith("[]"):
            inner = t[:-2].strip()
            return "[" + self._to_jni_type(inner)
        if t in self._SIG_TYPE_MAP:
            return self._SIG_TYPE_MAP[t]
        if "." in t:
            return "L" + t.replace(".", "/") + ";"
        return "L" + t + ";"

    def _iter_native_files(self) -> Iterable[Path]:
        if not self.native_root:
            return []
        for ext in self._NATIVE_EXTS:
            yield from self.native_root.rglob(f"*{ext}")
