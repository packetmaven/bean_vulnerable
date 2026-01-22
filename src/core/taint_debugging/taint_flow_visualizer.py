"""Generate interactive HTML for taint flow graphs."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List
import json


def build_graph(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    nodes = {}
    links = []
    for flow in flows:
        source = str(flow.get("source", ""))
        target = str(flow.get("target", ""))
        if not source or not target:
            continue
        if source not in nodes:
            nodes[source] = {"id": source, "label": source}
        if target not in nodes:
            nodes[target] = {"id": target, "label": target}
        links.append({"source": source, "target": target, "type": "taint"})
    return {"nodes": list(nodes.values()), "links": links}


def generate_html(graph: Dict[str, Any]) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Taint Flow Graph</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; }}
    .link {{ stroke: #999; stroke-opacity: 0.6; }}
    .node {{ fill: #3498db; }}
  </style>
</head>
<body>
<script>
const data = {json.dumps(graph)};
const width = window.innerWidth;
const height = window.innerHeight;
const svg = d3.select("body").append("svg")
  .attr("width", width)
  .attr("height", height);

const simulation = d3.forceSimulation(data.nodes)
  .force("link", d3.forceLink(data.links).id(d => d.id).distance(120))
  .force("charge", d3.forceManyBody().strength(-300))
  .force("center", d3.forceCenter(width / 2, height / 2));

const link = svg.append("g")
  .selectAll("line")
  .data(data.links)
  .join("line")
  .attr("class", "link");

const node = svg.append("g")
  .selectAll("circle")
  .data(data.nodes)
  .join("circle")
  .attr("r", 6)
  .attr("class", "node");

const label = svg.append("g")
  .selectAll("text")
  .data(data.nodes)
  .join("text")
  .text(d => d.label)
  .attr("font-size", 10)
  .attr("dx", 10)
  .attr("dy", 3);

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
</script>
</body>
</html>
"""


def write_taint_graph(output_path: Path, flows: List[Dict[str, Any]]) -> Path:
    graph = build_graph(flows)
    output_path.write_text(generate_html(graph), encoding="utf-8")
    return output_path
