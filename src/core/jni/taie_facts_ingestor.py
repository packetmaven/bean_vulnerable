"""Tai-e fact ingestion for cross-language JNI analysis."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class TaiEFactsIngestor:
    """Load Tai-e call-graph / points-to facts from JSON artifacts."""

    _DEFAULT_CANDIDATES = (
        "taie_facts.json",
        "taie_points_to.json",
        "points_to.json",
        "call_graph.json",
        "taie_output.json",
    )

    def load(self, fact_path: Optional[Path]) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "loaded": False,
            "backend": "taie-facts-v1",
            "source_path": None,
            "call_graph": [],
            "points_to": {},
            "summary": {},
            "errors": [],
        }
        if not fact_path:
            return payload

        resolved = self._resolve_fact_file(fact_path)
        if not resolved:
            payload["errors"] = [f"taie_facts_not_found:{fact_path}"]
            return payload

        try:
            data = json.loads(resolved.read_text(encoding="utf-8"))
        except Exception as exc:
            payload["errors"] = [f"taie_facts_parse_failed:{exc}"]
            return payload

        call_graph = self._normalize_edges(data)
        points_to = self._normalize_points_to(data)
        payload["loaded"] = True
        payload["source_path"] = str(resolved)
        payload["call_graph"] = call_graph
        payload["points_to"] = points_to
        payload["summary"] = {
            "edge_count": len(call_graph),
            "points_to_keys": sorted(points_to.keys()),
            "java_to_native_bindings": len(points_to.get("java_to_native_bindings", {}))
            if isinstance(points_to.get("java_to_native_bindings", {}), dict)
            else 0,
            "native_to_java_callbacks": len(points_to.get("native_to_java_callbacks", {}))
            if isinstance(points_to.get("native_to_java_callbacks", {}), dict)
            else 0,
        }
        return payload

    def _resolve_fact_file(self, fact_path: Path) -> Optional[Path]:
        expanded = fact_path.expanduser()
        if expanded.is_file():
            return expanded.resolve()
        if expanded.is_dir():
            for name in self._DEFAULT_CANDIDATES:
                candidate = expanded / name
                if candidate.exists() and candidate.is_file():
                    return candidate.resolve()
            # fallback: choose first json in dir
            json_files = sorted([p for p in expanded.glob("*.json") if p.is_file()])
            if json_files:
                return json_files[0].resolve()
        return None

    def _normalize_edges(self, data: object) -> List[Dict[str, object]]:
        edges_raw = self._extract_edges(data)
        normalized: List[Dict[str, object]] = []
        for edge in edges_raw:
            source, target, meta = self._edge_tuple(edge)
            if not source or not target:
                continue
            normalized.append(
                {
                    "source": source,
                    "target": target,
                    "kind": "taie_call_graph",
                    "resolver": "taie_facts",
                    "confidence": "high",
                    **meta,
                }
            )
        unique = {}
        for edge in normalized:
            key = (edge.get("source"), edge.get("target"), edge.get("kind"))
            unique[key] = edge
        return sorted(unique.values(), key=lambda x: (str(x.get("source")), str(x.get("target"))))

    def _extract_edges(self, data: object) -> List[object]:
        if isinstance(data, dict):
            for key in ("call_graph", "callgraph", "edges", "calls"):
                value = data.get(key)
                if isinstance(value, list):
                    return value
            nested = data.get("pta")
            if isinstance(nested, dict):
                for key in ("call_graph", "edges"):
                    value = nested.get(key)
                    if isinstance(value, list):
                        return value
        elif isinstance(data, list):
            return data
        return []

    def _edge_tuple(self, edge: object) -> Tuple[str, str, Dict[str, object]]:
        if isinstance(edge, dict):
            source = str(edge.get("source") or edge.get("src") or edge.get("caller") or "")
            target = str(edge.get("target") or edge.get("dst") or edge.get("callee") or "")
            meta = {k: v for k, v in edge.items() if k not in {"source", "src", "caller", "target", "dst", "callee"}}
            return source, target, meta
        if isinstance(edge, (list, tuple)) and len(edge) >= 2:
            return str(edge[0] or ""), str(edge[1] or ""), {}
        return "", "", {}

    def _normalize_points_to(self, data: object) -> Dict[str, object]:
        if not isinstance(data, dict):
            return {}
        for key in ("points_to", "pta", "pointsTo"):
            value = data.get(key)
            if isinstance(value, dict):
                return self._sanitize_points_to(value)
        # Support flat payloads with direct keys.
        direct = {}
        for key in ("java_to_native_bindings", "native_to_java_callbacks", "native_aliases"):
            value = data.get(key)
            if isinstance(value, dict):
                direct[key] = value
        return self._sanitize_points_to(direct) if direct else {}

    def _sanitize_points_to(self, points_to: Dict[str, object]) -> Dict[str, object]:
        clean: Dict[str, object] = {}
        for key, value in points_to.items():
            if isinstance(value, dict):
                normalized_map: Dict[str, List[str]] = {}
                for map_key, map_val in value.items():
                    if isinstance(map_val, list):
                        normalized_map[str(map_key)] = [str(item) for item in map_val if item is not None]
                    elif map_val is not None:
                        normalized_map[str(map_key)] = [str(map_val)]
                clean[str(key)] = normalized_map
            elif isinstance(value, list):
                clean[str(key)] = [str(item) for item in value if item is not None]
            elif value is not None:
                clean[str(key)] = value
        return clean
