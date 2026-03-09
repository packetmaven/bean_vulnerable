"""Detection of JNI invocation API and native->Java callback API usage."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List


class JniInvocationAnalyzer:
    _NATIVE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
    _INVOCATION_APIS = (
        "JNI_CreateJavaVM",
        "JNI_GetCreatedJavaVMs",
        "AttachCurrentThread",
        "AttachCurrentThreadAsDaemon",
        "DetachCurrentThread",
        "GetEnv",
        "JNI_OnLoad",
        "JNI_OnUnload",
    )
    _CALLBACK_RE = re.compile(
        r"\b(FindClass|GetMethodID|GetStaticMethodID|GetFieldID|GetStaticFieldID|"
        r"Call(?:Static|Nonvirtual)?[A-Za-z]+Method(?:A|V)?)\b"
    )

    def analyze_native_root(self, native_root: Path) -> Dict[str, object]:
        invocation_usage: Dict[str, int] = {}
        callback_usage: Dict[str, int] = {}
        callback_details: List[Dict[str, object]] = []

        if not native_root.exists():
            return {
                "invocation_api_usage": invocation_usage,
                "callback_api_usage": callback_usage,
                "callback_details": callback_details,
            }

        for path in self._iter_native_files(native_root):
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for line_no, line in enumerate(lines, 1):
                for api in self._INVOCATION_APIS:
                    if re.search(rf"\b{re.escape(api)}\b", line):
                        invocation_usage[api] = invocation_usage.get(api, 0) + 1
                for match in self._CALLBACK_RE.finditer(line):
                    api = match.group(1)
                    callback_usage[api] = callback_usage.get(api, 0) + 1
                    callback_details.append(
                        {
                            "api": api,
                            "file": str(path),
                            "line": line_no,
                            "snippet": line.strip()[:240],
                        }
                    )

        return {
            "invocation_api_usage": invocation_usage,
            "callback_api_usage": callback_usage,
            "callback_details": callback_details,
        }

    def _iter_native_files(self, native_root: Path):
        for ext in self._NATIVE_EXTS:
            yield from native_root.rglob(f"*{ext}")
