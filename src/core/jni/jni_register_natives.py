"""Parser for JNINativeMethod tables and RegisterNatives calls."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List


class RegisterNativesParser:
    """Extract dynamic JNI registration evidence from C/C++ sources."""

    _NATIVE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")

    _TABLE_RE = re.compile(
        r"JNINativeMethod\s+(?P<table>[A-Za-z_]\w*)\s*\[\s*\d*\s*\]\s*=\s*\{(?P<body>.*?)\};",
        re.S,
    )
    _ENTRY_RE = re.compile(
        r"\{\s*\"(?P<name>[^\"]+)\"\s*,\s*\"(?P<sig>[^\"]+)\"\s*,\s*(?P<fn>[^}]+?)\s*\}",
        re.S,
    )
    _REGISTER_RE = re.compile(
        r"RegisterNatives\s*\(\s*[^,]+,\s*(?P<class_expr>[^,]+),\s*(?P<table>[A-Za-z_]\w*)\s*,",
        re.S,
    )
    _FINDCLASS_ASSIGN_RE = re.compile(
        r"(?:jclass|auto)\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\(\*?\w+\)?->)?FindClass\s*\(\s*[^,]+,\s*\"(?P<class>[^\"]+)\"\s*\)"
    )
    _FINDCLASS_INLINE_RE = re.compile(r"FindClass\s*\(\s*[^,]+,\s*\"(?P<class>[^\"]+)\"\s*\)")

    def parse_native_root(self, native_root: Path) -> Dict[str, List[Dict[str, object]]]:
        entries: List[Dict[str, object]] = []
        registrations: List[Dict[str, object]] = []
        if not native_root.exists():
            return {"entries": entries, "registrations": registrations}

        for path in self._iter_native_files(native_root):
            payload = self.parse_file(path)
            entries.extend(payload.get("entries", []))
            registrations.extend(payload.get("registrations", []))
        return {"entries": entries, "registrations": registrations}

    def parse_file(self, source_path: Path) -> Dict[str, List[Dict[str, object]]]:
        try:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return {"entries": [], "registrations": []}
        return self.parse_source(text, str(source_path))

    def parse_source(self, text: str, file_path: str) -> Dict[str, List[Dict[str, object]]]:
        class_vars: Dict[str, str] = {}
        for match in self._FINDCLASS_ASSIGN_RE.finditer(text):
            class_vars[match.group("var")] = match.group("class")

        tables: Dict[str, List[Dict[str, object]]] = {}
        for table_match in self._TABLE_RE.finditer(text):
            table_name = table_match.group("table")
            table_body = table_match.group("body")
            table_entries: List[Dict[str, object]] = []
            for entry_match in self._ENTRY_RE.finditer(table_body):
                fn_expr = self._normalize_fn_expr(entry_match.group("fn"))
                table_entries.append(
                    {
                        "java_name": entry_match.group("name"),
                        "signature": entry_match.group("sig"),
                        "native_func": fn_expr,
                        "native_symbol": self._extract_symbol(fn_expr),
                        "entry_line": self._line_no(text, table_match.start() + entry_match.start()),
                    }
                )
            tables[table_name] = table_entries

        registrations: List[Dict[str, object]] = []
        entries: List[Dict[str, object]] = []
        for reg_match in self._REGISTER_RE.finditer(text):
            table_name = reg_match.group("table")
            class_expr = reg_match.group("class_expr").strip()
            class_desc = class_vars.get(class_expr) or self._extract_inline_findclass(class_expr)
            reg_line = self._line_no(text, reg_match.start())

            registration = {
                "table": table_name,
                "class_expr": class_expr,
                "class_descriptor": class_desc,
                "registration_line": reg_line,
                "file": file_path,
            }
            registrations.append(registration)

            for entry in tables.get(table_name, []):
                entries.append(
                    {
                        **entry,
                        "binding_type": "register_natives",
                        "resolver": "register_natives",
                        "confidence": "dynamic_registration",
                        "table": table_name,
                        "class_descriptor": class_desc,
                        "registration_line": reg_line,
                        "file": file_path,
                        "line": int(entry.get("entry_line", reg_line)),
                    }
                )

        # Table entries without explicit RegisterNatives call are still useful evidence.
        registered_tables = {r.get("table") for r in registrations}
        for table_name, table_entries in tables.items():
            if table_name in registered_tables:
                continue
            for entry in table_entries:
                entries.append(
                    {
                        **entry,
                        "binding_type": "register_natives",
                        "resolver": "register_natives",
                        "confidence": "table_only",
                        "table": table_name,
                        "class_descriptor": None,
                        "registration_line": None,
                        "file": file_path,
                        "line": int(entry.get("entry_line", 0) or 0),
                    }
                )

        return {"entries": entries, "registrations": registrations}

    def _extract_inline_findclass(self, class_expr: str) -> str | None:
        match = self._FINDCLASS_INLINE_RE.search(class_expr)
        if match:
            return match.group("class")
        return None

    @staticmethod
    def _normalize_fn_expr(fn_expr: str) -> str:
        cleaned = " ".join(fn_expr.replace("\n", " ").split())
        cleaned = re.sub(r"^\(void\s*\*\)\s*", "", cleaned)
        cleaned = re.sub(r"^\((?:j?long|uintptr_t)\)\s*", "", cleaned)
        return cleaned.strip().rstrip(",")

    @staticmethod
    def _extract_symbol(fn_expr: str) -> str | None:
        # Handle simple cases: nativeFn, &nativeFn, table[0], (void*)nativeFn.
        expr = fn_expr.replace("&", " ").strip()
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?$", expr)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _line_no(text: str, offset: int) -> int:
        return text[:offset].count("\n") + 1

    def _iter_native_files(self, native_root: Path):
        for ext in self._NATIVE_EXTS:
            yield from native_root.rglob(f"*{ext}")
