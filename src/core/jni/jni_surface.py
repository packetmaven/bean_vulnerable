"""JNI surface discovery for Java source files."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class JniMethod:
    name: str
    line: int
    params: str
    class_name: Optional[str]
    package: Optional[str]

    @property
    def mangled_base(self) -> Optional[str]:
        if not self.class_name:
            return None
        pkg = _jni_mangle(self.package or "")
        cls = _jni_mangle(self.class_name).replace("$", "_")
        if pkg:
            return f"Java_{pkg}_{cls}_{self.name}"
        return f"Java_{cls}_{self.name}"


class JniSurfaceAnalyzer:
    """Extract JNI-related declarations and library loads from Java source."""

    _PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;")
    _CLASS_RE = re.compile(r"\bclass\s+([A-Za-z0-9_]+)")
    _NATIVE_RE = re.compile(r"\bnative\s+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)")
    _LOAD_LIB_RE = re.compile(r"System\.loadLibrary\(\s*\"([^\"]+)\"\s*\)")
    _LOAD_RE = re.compile(r"System\.load\(\s*\"([^\"]+)\"\s*\)")

    def analyze(self, source_code: str) -> Dict[str, object]:
        lines = source_code.splitlines()
        package = None
        class_stack: List[Dict[str, object]] = []
        brace_depth = 0
        jni_methods: List[Dict[str, object]] = []
        jni_libraries: List[str] = []

        for i, line in enumerate(lines, 1):
            open_braces = line.count("{")
            close_braces = line.count("}")
            if package is None:
                pkg_match = self._PACKAGE_RE.match(line)
                if pkg_match:
                    package = pkg_match.group(1)

            load_match = self._LOAD_LIB_RE.search(line)
            if load_match:
                jni_libraries.append(load_match.group(1))
            load_match = self._LOAD_RE.search(line)
            if load_match:
                jni_libraries.append(load_match.group(1))

            class_match = self._CLASS_RE.search(line)
            if class_match:
                class_name = class_match.group(1)
                class_depth = brace_depth + open_braces
                class_stack.append({"name": class_name, "depth": class_depth})

            native_match = self._NATIVE_RE.search(line)
            if native_match:
                method_name = native_match.group(1)
                params = native_match.group(2)
                current_class = class_stack[-1]["name"] if class_stack else None
                jni_method = JniMethod(
                    name=method_name,
                    line=i,
                    params=params,
                    class_name=current_class,
                    package=package,
                )
                jni_methods.append(
                    {
                        "name": jni_method.name,
                        "line": jni_method.line,
                        "params": jni_method.params,
                        "class_name": jni_method.class_name,
                        "package": jni_method.package,
                        "mangled_base": jni_method.mangled_base,
                    }
                )

            brace_depth += open_braces - close_braces
            while class_stack and brace_depth < int(class_stack[-1]["depth"]):
                class_stack.pop()

        return {
            "jni_methods": jni_methods,
            "jni_libraries": sorted(set(jni_libraries)),
        }


def _jni_mangle(name: str) -> str:
    """Mangle Java identifiers for JNI symbol matching (handles underscores)."""
    if not name:
        return ""
    return name.replace("_", "_1").replace(".", "_")
