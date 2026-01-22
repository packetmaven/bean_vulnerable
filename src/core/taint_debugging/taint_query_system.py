"""Interactive taint flow queries based on bean-vuln results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class TaintNode:
    name: str
    taint_state: str


class TaintFlowGraph:
    def __init__(self, flows: List[Dict[str, object]]) -> None:
        self.edges: Dict[str, Set[str]] = {}
        self.reverse_edges: Dict[str, Set[str]] = {}
        self.nodes: Set[str] = set()
        self._build_graph(flows)

    def _build_graph(self, flows: List[Dict[str, object]]) -> None:
        for flow in flows:
            source = str(flow.get("source", ""))
            target = str(flow.get("target", ""))
            if not source or not target:
                continue
            self.nodes.add(source)
            self.nodes.add(target)
            self.edges.setdefault(source, set()).add(target)
            self.reverse_edges.setdefault(target, set()).add(source)

    def why_tainted(self, target: str) -> Dict[str, object]:
        if target not in self.nodes:
            return {"found": False, "reason": "target_not_in_graph"}
        sources = self._find_sources(target)
        paths = self._find_paths_from_sources(sources, target)
        return {
            "found": True,
            "target": target,
            "sources": sorted(sources),
            "paths": paths,
        }

    def why_not_tainted(self, target: str) -> Dict[str, object]:
        if target not in self.nodes:
            return {"found": False, "reason": "target_not_in_graph"}
        sources = self._find_sources(target)
        return {
            "found": True,
            "target": target,
            "sources": sorted(sources),
            "reason": "no_path_from_sources" if not sources else "taint_not_propagated",
        }

    def path_exists(self, source: str, sink: str) -> bool:
        if source not in self.nodes or sink not in self.nodes:
            return False
        visited = set()
        stack = [source]
        while stack:
            node = stack.pop()
            if node == sink:
                return True
            if node in visited:
                continue
            visited.add(node)
            stack.extend(self.edges.get(node, set()))
        return False

    def _find_sources(self, target: str) -> Set[str]:
        sources = set()
        visited = set()
        stack = [target]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            preds = self.reverse_edges.get(node, set())
            if not preds:
                sources.add(node)
                continue
            stack.extend(preds)
        return sources

    def _find_paths_from_sources(self, sources: Set[str], target: str) -> List[List[str]]:
        paths: List[List[str]] = []
        for source in sources:
            self._dfs_paths(source, target, [], paths)
        return paths

    def _dfs_paths(self, node: str, target: str, path: List[str], paths: List[List[str]]) -> None:
        path.append(node)
        if node == target:
            paths.append(list(path))
            path.pop()
            return
        for neighbor in self.edges.get(node, set()):
            if neighbor in path:
                continue
            self._dfs_paths(neighbor, target, path, paths)
        path.pop()
