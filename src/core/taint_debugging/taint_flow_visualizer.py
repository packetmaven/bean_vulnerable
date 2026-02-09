"""Generate interactive HTML for taint flow graphs."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
import json


def _ensure_node(nodes: Dict[str, Dict[str, Any]], node_id: str, meta: Optional[Dict[str, Any]] = None) -> None:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "label": node_id, "meta": {}}
    if meta:
        nodes[node_id]["meta"] = {
            **nodes[node_id].get("meta", {}),
            **meta,
        }


def _compute_paths(
    nodes: Dict[str, Dict[str, Any]],
    links: List[Dict[str, Any]],
    max_depth: int = 8,
    max_paths: int = 50,
) -> List[Dict[str, Any]]:
    roles = {n: set(nodes[n].get("meta", {}).get("roles", [])) for n in nodes}
    sources = [n for n, r in roles.items() if "source" in r]
    sinks = [n for n, r in roles.items() if "sink" in r]
    if not sources or not sinks:
        return []
    adjacency: Dict[str, List[str]] = {}
    for link in links:
        adjacency.setdefault(link["source"], []).append(link["target"])
    paths: List[Dict[str, Any]] = []

    def _dfs(path: List[str], depth: int, sink_set: Set[str]):
        if len(paths) >= max_paths:
            return
        current = path[-1]
        if current in sink_set and len(path) > 1:
            vuln_types = nodes[current].get("meta", {}).get("vuln_types", [])
            paths.append({"nodes": list(path), "vuln_types": vuln_types})
            return
        if depth >= max_depth:
            return
        for nxt in adjacency.get(current, []):
            if nxt in path:
                continue
            _dfs(path + [nxt], depth + 1, sink_set)

    sink_set = set(sinks)
    for source in sources:
        _dfs([source], 0, sink_set)
        if len(paths) >= max_paths:
            break
    return paths


def _propagate_vuln_types(
    nodes: Dict[str, Dict[str, Any]],
    links: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    node_types: Dict[str, Set[str]] = {n: set(nodes[n].get("meta", {}).get("vuln_types", [])) for n in nodes}
    incoming: Dict[str, List[str]] = {}
    for link in links:
        incoming.setdefault(link["target"], []).append(link["source"])
        if link.get("vuln_types"):
            node_types[link["target"]].update(link["vuln_types"])
    queue = [n for n, types in node_types.items() if types]
    while queue:
        current = queue.pop(0)
        for src in incoming.get(current, []):
            before = set(node_types[src])
            node_types[src].update(node_types[current])
            if node_types[src] != before:
                queue.append(src)
    for node_id, types in node_types.items():
        nodes[node_id].setdefault("meta", {})["vuln_types"] = sorted(types)
    for link in links:
        link_types = set(link.get("vuln_types", [])) | node_types.get(link["target"], set())
        link["vuln_types"] = sorted(link_types)
    vuln_types = sorted({t for types in node_types.values() for t in types})
    return links, vuln_types


def build_graph(
    flows: List[Dict[str, Any]],
    *,
    edges: Optional[List[Dict[str, Any]]] = None,
    node_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    links: List[Dict[str, Any]] = []
    meta_map = node_metadata or {}

    if edges:
        for edge in edges:
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            if not source or not target:
                continue
            _ensure_node(nodes, source, meta_map.get(source))
            _ensure_node(nodes, target, meta_map.get(target))
            links.append(
                {
                    "source": source,
                    "target": target,
                    "kind": edge.get("kind", "taint"),
                    "reason": edge.get("reason"),
                    "line": edge.get("line"),
                    "method": edge.get("method"),
                    "is_sanitized": bool(edge.get("is_sanitized", False)),
                    "vuln_types": edge.get("vuln_types", []),
                }
            )
    else:
        for flow in flows:
            source = str(flow.get("source", ""))
            target = str(flow.get("target", ""))
            if not source or not target:
                continue
            _ensure_node(nodes, source, meta_map.get(source))
            _ensure_node(nodes, target, meta_map.get(target))
            links.append(
                {
                    "source": source,
                    "target": target,
                    "kind": "taint",
                    "reason": None,
                    "line": None,
                    "method": None,
                    "is_sanitized": bool(flow.get("is_sanitized", False)),
                    "vuln_types": [],
                }
            )

    links, vuln_types = _propagate_vuln_types(nodes, links)
    paths = _compute_paths(nodes, links)

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "vuln_types": vuln_types,
        "paths": paths,
    }


def generate_html(graph: Dict[str, Any]) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Taint Flow Graph</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    html, body {{ margin: 0; padding: 0; width: 100%; height: 100%; font-family: Arial, sans-serif; }}
    body {{ overflow: hidden; }}
    .link {{ stroke: #999; stroke-opacity: 0.6; marker-end: url(#arrow); }}
    .link.sanitized {{ stroke: #27ae60; stroke-dasharray: 4 3; }}
    .node {{ fill: #3498db; stroke: #1f3b4d; stroke-width: 0.5px; }}
    .node.source {{ fill: #2ecc71; }}
    .node.sink {{ fill: #e74c3c; }}
    .node.sanitized {{ stroke: #f1c40f; stroke-width: 2px; }}
    .label {{ fill: #2c3e50; pointer-events: none; }}
    .highlight {{ stroke: #f39c12 !important; stroke-width: 2.5px; }}
    .help {{
      position: absolute;
      top: 10px;
      left: 10px;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid #e1e1e1;
      border-radius: 6px;
      padding: 8px 10px;
      font-size: 12px;
      color: #333;
      z-index: 10;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    }}
    .panel {{
      position: absolute;
      right: 10px;
      top: 10px;
      width: 320px;
      max-height: calc(100% - 20px);
      overflow: auto;
      background: rgba(255, 255, 255, 0.95);
      border: 1px solid #e1e1e1;
      border-radius: 6px;
      padding: 10px;
      font-size: 12px;
      color: #333;
      z-index: 10;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    }}
    .panel h4 {{ margin: 6px 0; }}
    .panel .path-item {{ cursor: pointer; margin: 6px 0; padding: 6px; border: 1px solid #eee; border-radius: 4px; }}
    .panel .path-item:hover {{ background: #f7f7f7; }}
    .legend {{ margin-top: 8px; }}
    .legend span {{ display: inline-block; margin-right: 8px; }}
  </style>
</head>
<body>
<div class="help">Pan: drag background • Zoom: trackpad/scroll • Drag node: move</div>
<div class="panel">
  <h4>Filters</h4>
  <div id="filters"></div>
  <h4>Multi-hop Paths</h4>
  <div id="paths"></div>
  <div class="legend">
    <h4>Legend</h4>
    <div><span style="color:#2ecc71;">●</span> Source</div>
    <div><span style="color:#e74c3c;">●</span> Sink</div>
    <div><span style="color:#f1c40f;">●</span> Sanitized</div>
  </div>
</div>
<script>
const data = {json.dumps(graph)};
let width = window.innerWidth;
let height = window.innerHeight;

const svg = d3.select("body").append("svg")
  .attr("width", "100%")
  .attr("height", "100%")
  .attr("viewBox", [0, 0, width, height])
  .style("cursor", "move");

// Arrow marker for directed edges
svg.append("defs")
  .append("marker")
  .attr("id", "arrow")
  .attr("viewBox", "0 -5 10 10")
  .attr("refX", 14)
  .attr("refY", 0)
  .attr("markerWidth", 6)
  .attr("markerHeight", 6)
  .attr("orient", "auto")
  .append("path")
  .attr("d", "M0,-5L10,0L0,5")
  .attr("fill", "#999");

// Background rect to capture zoom/pan gestures
svg.append("rect")
  .attr("width", width)
  .attr("height", height)
  .attr("fill", "white");

const g = svg.append("g");

const simulation = d3.forceSimulation(data.nodes)
  .force("link", d3.forceLink(data.links).id(d => d.id).distance(120))
  .force("charge", d3.forceManyBody().strength(-300))
  .force("center", d3.forceCenter(width / 2, height / 2));

const link = g.append("g")
  .selectAll("line")
  .data(data.links)
  .join("line")
  .attr("class", d => d.is_sanitized ? "link sanitized" : "link")
  .attr("data-key", d => `${{d.source.id || d.source}}||${{d.target.id || d.target}}`);

link.append("title").text(d => {{
  const line = d.line ? `L${{d.line}}` : "n/a";
  const method = d.method || "n/a";
  const reason = d.reason || d.kind || "taint";
  const vuln = d.vuln_types && d.vuln_types.length ? d.vuln_types.join(", ") : "n/a";
  return `reason: ${{reason}}\nline: ${{line}}\nmethod: ${{method}}\nvuln: ${{vuln}}`;
}});

const node = g.append("g")
  .selectAll("circle")
  .data(data.nodes)
  .join("circle")
  .attr("r", 6)
  .attr("class", d => {{
    const roles = (d.meta && d.meta.roles) ? d.meta.roles : [];
    const classes = ["node"];
    if (roles.includes("source")) classes.push("source");
    if (roles.includes("sink")) classes.push("sink");
    if (d.meta && d.meta.sanitized) classes.push("sanitized");
    return classes.join(" ");
  }});

const label = g.append("g")
  .selectAll("text")
  .data(data.nodes)
  .join("text")
  .text(d => {{
    const roles = (d.meta && d.meta.roles) ? d.meta.roles : [];
    const badge = roles.includes("sink") ? "[SINK] " : (roles.includes("source") ? "[SRC] " : "");
    return badge + d.label;
  }})
  .attr("font-size", 10)
  .attr("class", "label")
  .attr("dx", 10)
  .attr("dy", 3);

node.append("title").text(d => {{
  const meta = d.meta || {{}};
  const lines = (meta.lines || []).join(", ");
  const methods = (meta.methods || []).join(", ");
  const roles = (meta.roles || []).join(", ");
  const vulnTypes = (meta.vuln_types || []).join(", ");
  return `${{d.label}}\nroles: ${{roles || "n/a"}}\nlines: ${{lines || "n/a"}}\nmethods: ${{methods || "n/a"}}\nvuln: ${{vulnTypes || "n/a"}}`;
}});

// Drag behavior for nodes
const drag = d3.drag()
  .on("start", (event, d) => {{
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }})
  .on("drag", (event, d) => {{
    d.fx = event.x;
    d.fy = event.y;
  }})
  .on("end", (event, d) => {{
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }});

node.call(drag);
label.call(drag);

// Zoom/pan behavior
const zoom = d3.zoom()
  .scaleExtent([0.2, 6])
  .on("zoom", (event) => {{
    g.attr("transform", event.transform);
  }});

svg.call(zoom).on("dblclick.zoom", null);

// Filters (vulnerability type)
const filters = d3.select("#filters");
const vulnTypes = Array.from(new Set([...(data.vuln_types || []), "UNCATEGORIZED"]));
const active = new Set(vulnTypes);

function edgeHasType(edge, type) {{
  if (type === "UNCATEGORIZED") return !edge.vuln_types || edge.vuln_types.length === 0;
  return edge.vuln_types && edge.vuln_types.includes(type);
}}

filters.selectAll("div")
  .data(vulnTypes)
  .join("div")
  .each(function(type) {{
    const row = d3.select(this);
    row.append("input")
      .attr("type", "checkbox")
      .attr("checked", true)
      .on("change", function() {{
        if (this.checked) active.add(type);
        else active.delete(type);
        updateVisibility();
      }});
    row.append("span").text(" " + type);
  }});

function updateVisibility() {{
  link.style("display", d => {{
    if (active.size === 0) return null;
    return [...active].some(t => edgeHasType(d, t)) ? null : "none";
  }});

  function nodeVisible(d) {{
    if (active.size === 0) return null;
    const visibleEdge = data.links.some(e => {{
      const sourceId = e.source.id || e.source;
      const targetId = e.target.id || e.target;
      if (sourceId !== d.id && targetId !== d.id) return false;
      return [...active].some(t => edgeHasType(e, t));
    }});
    return visibleEdge ? null : "none";
  }}

  node.style("display", d => nodeVisible(d));
  label.style("display", d => nodeVisible(d));
}}

updateVisibility();

// Multi-hop paths list
const pathBox = d3.select("#paths");
const paths = data.paths || [];
if (!paths.length) {{
  pathBox.append("div").text("No source→sink paths detected.");
}} else {{
  paths.slice(0, 50).forEach((p, idx) => {{
    const vuln = (p.vuln_types && p.vuln_types.length) ? ` (${{p.vuln_types.join(", ")}})` : "";
    const text = p.nodes.join(" → ");
    pathBox.append("div")
      .attr("class", "path-item")
      .text(text + vuln)
      .on("click", () => highlightPath(p.nodes));
  }});
}}

function highlightPath(pathNodes) {{
  const edgeKeys = new Set();
  for (let i = 0; i < pathNodes.length - 1; i++) {{
    edgeKeys.add(`${{pathNodes[i]}}||${{pathNodes[i+1]}}`);
  }}
  link.classed("highlight", d => edgeKeys.has(`${{d.source.id || d.source}}||${{d.target.id || d.target}}`));
}}

simulation.on("tick", () => {{
  link
    .attr("x1", d => d.source.x)
    .attr("y1", d => d.source.y)
    .attr("x2", d => d.target.x)
    .attr("y2", d => d.target.y);

  node
    .attr("cx", d => d.x)
    .attr("cy", d => d.y);

  label
    .attr("x", d => d.x)
    .attr("y", d => d.y);
}});

// Handle window resize
window.addEventListener("resize", () => {{
  width = window.innerWidth;
  height = window.innerHeight;
  svg.attr("viewBox", [0, 0, width, height]);
  svg.select("rect").attr("width", width).attr("height", height);
  simulation.force("center", d3.forceCenter(width / 2, height / 2)).alpha(0.2).restart();
}});
</script>
</body>
</html>
"""


def write_taint_graph(output_path: Path, taint_tracking: Any) -> Path:
    if isinstance(taint_tracking, dict):
        edges = taint_tracking.get("taint_flow_edges") or []
        node_meta = taint_tracking.get("taint_node_metadata") or {}
        flows = taint_tracking.get("taint_flows") or []
    else:
        edges = []
        node_meta = {}
        flows = taint_tracking or []
    graph = build_graph(flows, edges=edges, node_metadata=node_meta)
    output_path.write_text(generate_html(graph), encoding="utf-8")
    return output_path
