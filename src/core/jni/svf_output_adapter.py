"""SVF output adapter for JNI cross-language analysis."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class SvfOutputAdapter:
    """Load SVF artifacts (JSON/DOT/TXT) and normalize into call-graph facts."""

    _DEFAULT_CANDIDATES = (
        "svf_output.json",
        "svf_facts.json",
        "svf_callgraph.json",
        "svf_callgraph.dot",
        "callgraph.dot",
    )
    _DOT_EDGE_RE = re.compile(r'^\s*"?(?P<src>[^"]+?)"?\s*->\s*"?(?P<dst>[^"]+?)"?\s*(?:\[.*\])?;?\s*$')
    _TXT_EDGE_RE = re.compile(r"^\s*(?P<src>[A-Za-z0-9_:$./-]+)\s*->\s*(?P<dst>[A-Za-z0-9_:$./-]+)\s*$")

    def load(self, output_path: Optional[Path]) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "loaded": False,
            "backend": "svf-adapter-v1",
            "source_path": None,
            "call_graph": [],
            "points_to": {},
            "summary": {},
            "errors": [],
        }
        if not output_path:
            return payload

        resolved = self._resolve_output_file(output_path)
        if not resolved:
            payload["errors"] = [f"svf_output_not_found:{output_path}"]
            return payload

        suffix = resolved.suffix.lower()
        if suffix == ".json":
            parsed = self._load_json(resolved)
        elif suffix == ".dot":
            parsed = self._load_dot(resolved)
        else:
            parsed = self._load_text(resolved)

        if parsed.get("errors"):
            payload["errors"] = parsed["errors"]
            return payload

        payload["loaded"] = True
        payload["source_path"] = str(resolved)
        payload["call_graph"] = parsed.get("call_graph", [])
        payload["points_to"] = parsed.get("points_to", {})
        payload["summary"] = {
            "edge_count": len(payload["call_graph"]) if isinstance(payload["call_graph"], list) else 0,
            "points_to_keys": sorted(payload["points_to"].keys()) if isinstance(payload["points_to"], dict) else [],
        }
        return payload

    def _resolve_output_file(self, output_path: Path) -> Optional[Path]:
        expanded = output_path.expanduser()
        if expanded.is_file():
            return expanded.resolve()
        if expanded.is_dir():
            for name in self._DEFAULT_CANDIDATES:
                candidate = expanded / name
                if candidate.exists() and candidate.is_file():
                    return candidate.resolve()
            files = sorted([p for p in expanded.glob("*") if p.is_file() and p.suffix.lower() in {".json", ".dot", ".txt"}])
            if files:
                return files[0].resolve()
        return None

    def _load_json(self, path: Path) -> Dict[str, object]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"errors": [f"svf_json_parse_failed:{exc}"]}

        edges: List[Dict[str, object]] = []
        points_to: Dict[str, object] = {}
        if isinstance(data, dict):
            for key in ("native_call_graph", "call_graph", "edges"):
                value = data.get(key)
                if isinstance(value, list):
                    edges = self._normalize_edges(value)
                    break
            pt = data.get("points_to")
            if isinstance(pt, dict):
                points_to = pt
        elif isinstance(data, list):
            edges = self._normalize_edges(data)
        return {"call_graph": edges, "points_to": points_to, "errors": []}

    def _load_dot(self, path: Path) -> Dict[str, object]:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as exc:
            return {"errors": [f"svf_dot_read_failed:{exc}"]}
        edges = []
        for line in lines:
            match = self._DOT_EDGE_RE.match(line.strip())
            if not match:
                continue
            edges.append({"source": match.group("src"), "target": match.group("dst")})
        return {"call_graph": self._normalize_edges(edges), "points_to": {}, "errors": []}

    def _load_text(self, path: Path) -> Dict[str, object]:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as exc:
            return {"errors": [f"svf_text_read_failed:{exc}"]}
        edges = []
        for line in lines:
            match = self._TXT_EDGE_RE.match(line.strip())
            if not match:
                continue
            edges.append({"source": match.group("src"), "target": match.group("dst")})
        return {"call_graph": self._normalize_edges(edges), "points_to": {}, "errors": []}

    def _normalize_edges(self, raw_edges: List[object]) -> List[Dict[str, object]]:
        normalized = []
        for edge in raw_edges:
            if isinstance(edge, dict):
                source = str(edge.get("source") or edge.get("src") or edge.get("caller") or "")
                target = str(edge.get("target") or edge.get("dst") or edge.get("callee") or "")
            elif isinstance(edge, (list, tuple)) and len(edge) >= 2:
                source = str(edge[0] or "")
                target = str(edge[1] or "")
            else:
                continue
            if not source or not target:
                continue
            normalized.append(
                {
                    "source": source,
                    "target": target,
                    "kind": "svf_call_graph",
                    "resolver": "svf_output",
                    "confidence": "high",
                }
            )
        unique = {}
        for edge in normalized:
            key = (edge.get("source"), edge.get("target"), edge.get("kind"))
            unique[key] = edge
        return sorted(unique.values(), key=lambda item: (str(item.get("source")), str(item.get("target"))))
