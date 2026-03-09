"""Lightweight native IR extraction for JNI cross-language modeling."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from .jni_semantics import JNI_API_RULES


_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "typedef",
    "else",
    "do",
}

_CALLBACK_API_RE = re.compile(r"\bCall(?:Static|Nonvirtual)?[A-Za-z]+Method(?:A|V)?\b")


class NativeIRBuilder:
    """Build a regex-based IR for C/C++ JNI relevant functions."""

    _NATIVE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
    _FUNC_START_RE = re.compile(
        r"^\s*(?:static\s+)?(?:JNIEXPORT\s+\w+\s+JNICALL\s+)?[A-Za-z_][\w\s\*]*\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
    )
    _CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    _PARAM_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\[\s*\])?$")

    def build(self, native_root: Path, compile_commands_path: Optional[Path] = None) -> Dict[str, object]:
        functions: List[Dict[str, object]] = []
        translation_units: List[Dict[str, object]] = []
        errors: List[str] = []

        if not native_root.exists():
            return {
                "backend": "regex-native-ir-v1",
                "functions": functions,
                "translation_units": translation_units,
                "compile_commands_used": False,
                "errors": ["native_root_not_found"],
            }

        compile_commands_used = False
        if compile_commands_path and compile_commands_path.exists():
            try:
                translation_units = self._load_compile_commands(compile_commands_path)
                compile_commands_used = bool(translation_units)
            except Exception as exc:
                errors.append(f"compile_commands_parse_failed:{exc}")

        native_files = list(self._iter_native_files(native_root))
        if not native_files:
            errors.append("no_native_files_detected")

        for path in native_files:
            functions.extend(self._extract_functions(path))

        function_names = {str(func.get("name", "")) for func in functions}
        for func in functions:
            calls = [c for c in (func.get("calls", []) or []) if c in function_names]
            func["native_calls"] = sorted(set(calls))

        return {
            "backend": "regex-native-ir-v1",
            "functions": functions,
            "translation_units": translation_units,
            "compile_commands_used": compile_commands_used,
            "errors": errors,
        }

    def _extract_functions(self, source_path: Path) -> List[Dict[str, object]]:
        try:
            lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []

        functions: List[Dict[str, object]] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            match = self._FUNC_START_RE.match(line)
            if not match:
                i += 1
                continue
            func_name = match.group(1)
            if func_name in _KEYWORDS:
                i += 1
                continue
            params_text = match.group(2)
            start_line = i + 1
            brace_depth = line.count("{") - line.count("}")
            body_lines = [line]
            j = i + 1
            while j < len(lines) and brace_depth > 0:
                cur = lines[j]
                body_lines.append(cur)
                brace_depth += cur.count("{") - cur.count("}")
                j += 1
            end_line = j
            body = "\n".join(body_lines)
            params = self._extract_param_names(params_text)
            calls = self._extract_calls(body)
            jni_apis = sorted([api for api in JNI_API_RULES if re.search(rf"\b{re.escape(api)}\b", body)])
            callback_apis = sorted(set(_CALLBACK_API_RE.findall(body)))
            functions.append(
                {
                    "name": func_name,
                    "file": str(source_path),
                    "line_start": start_line,
                    "line_end": end_line,
                    "params": params,
                    "signature": params_text.strip(),
                    "calls": calls,
                    "jni_apis": jni_apis,
                    "callback_apis": callback_apis,
                    "body": body,
                }
            )
            i = max(j, i + 1)
        return functions

    def _extract_param_names(self, params_text: str) -> List[str]:
        params: List[str] = []
        for token in params_text.split(","):
            param = token.strip()
            if not param or param == "void":
                continue
            param = param.replace("const ", "").replace("volatile ", "")
            match = self._PARAM_NAME_RE.search(param)
            if match:
                name = match.group(1)
                if name not in _KEYWORDS:
                    params.append(name)
        return params

    def _extract_calls(self, body: str) -> List[str]:
        calls: List[str] = []
        for match in self._CALL_RE.finditer(body):
            name = match.group(1)
            if name in _KEYWORDS:
                continue
            # Exclude obvious macros/types by casing and JNIENV deref wrappers.
            if name.isupper():
                continue
            calls.append(name)
        return sorted(set(calls))

    def _load_compile_commands(self, compile_commands_path: Path) -> List[Dict[str, object]]:
        payload = json.loads(compile_commands_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            return []
        entries: List[Dict[str, object]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            directory = str(item.get("directory") or "")
            file_value = str(item.get("file") or "")
            if not directory or not file_value:
                continue
            directory_path = Path(directory).expanduser()
            if not directory_path.is_absolute():
                # Robust fallback for non-spec databases that use relative `directory`.
                directory_path = (compile_commands_path.parent / directory_path).resolve()
            file_path = directory_path / file_value if not Path(file_value).is_absolute() else Path(file_value)
            command = item.get("command")
            arguments = item.get("arguments")
            entry = {
                "directory": str(directory_path),
                "file": str(file_path.resolve()),
                "command": str(command) if isinstance(command, str) else None,
                "arguments": arguments if isinstance(arguments, list) else None,
                "output": item.get("output"),
            }
            entries.append(entry)
        # Deduplicate by source file.
        unique: Dict[str, Dict[str, object]] = {}
        for entry in entries:
            unique[str(entry["file"])] = entry
        return list(unique.values())

    def _iter_native_files(self, native_root: Path):
        seen: Set[Path] = set()
        for ext in self._NATIVE_EXTS:
            for path in native_root.rglob(f"*{ext}"):
                if path in seen:
                    continue
                seen.add(path)
                yield path
