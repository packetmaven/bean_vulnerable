"""Optional binary symbol scanner for JNI symbol evidence."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


class JniSymbolScanner:
    def __init__(self, symbol_tool: Optional[str] = None):
        self.symbol_tool = symbol_tool

    def scan(self, binary_path: Path) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "binary": str(binary_path),
            "symbol_tool": None,
            "symbols": [],
            "jni_symbols": [],
            "onload_symbols": [],
            "errors": [],
        }
        if not binary_path.exists():
            payload["errors"] = ["binary_not_found"]
            return payload

        tool = self._resolve_tool(self.symbol_tool)
        if not tool:
            payload["errors"] = ["symbol_tool_not_found"]
            return payload
        payload["symbol_tool"] = tool

        cmd = self._build_cmd(tool, binary_path)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
        except Exception as exc:
            payload["errors"] = [f"symbol_scan_failed:{exc}"]
            return payload

        if proc.returncode != 0 and "nm" in Path(tool).name:
            # Retry nm without -g for stripped/local symbols.
            retry = [tool, str(binary_path)]
            proc = subprocess.run(retry, capture_output=True, text=True, timeout=20, check=False)

        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip() or "unknown_error"
            payload["errors"] = [f"symbol_tool_error:{stderr[:240]}"]
            return payload

        symbols = self._parse_symbols(proc.stdout)
        jni_symbols = sorted([s for s in symbols if s.startswith("Java_")])
        onload_symbols = sorted([s for s in symbols if s.startswith("JNI_OnLoad") or s.startswith("JNI_OnUnload")])

        payload["symbols"] = symbols
        payload["jni_symbols"] = jni_symbols
        payload["onload_symbols"] = onload_symbols
        return payload

    @staticmethod
    def _resolve_tool(preferred: Optional[str]) -> Optional[str]:
        if preferred:
            if Path(preferred).exists():
                return preferred
            found = shutil.which(preferred)
            if found:
                return found
        for candidate in ("llvm-nm", "nm", "objdump", "llvm-objdump"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    @staticmethod
    def _build_cmd(tool: str, binary_path: Path) -> List[str]:
        name = Path(tool).name
        if "objdump" in name:
            return [tool, "-t", str(binary_path)]
        if "nm" in name:
            return [tool, "-g", str(binary_path)]
        return [tool, str(binary_path)]

    @staticmethod
    def _parse_symbols(output: str) -> List[str]:
        symbols: List[str] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # nm style: <addr> <type> <symbol>
            nm_match = re.match(r"^[0-9A-Fa-f]+\s+[A-Za-z]\s+([A-Za-z_]\w+)$", line)
            if nm_match:
                symbols.append(nm_match.group(1))
                continue
            # objdump style has symbol at end of line.
            obj_match = re.search(r"\b([A-Za-z_]\w+)$", line)
            if obj_match:
                symbols.append(obj_match.group(1))
        return sorted(set(symbols))
