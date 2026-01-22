"""Interactive CLI for taint flow queries."""

from __future__ import annotations

import cmd
from pathlib import Path
import json
from typing import Dict, Any

from .taint_query_system import TaintFlowGraph


def load_flows(result_path: Path) -> Dict[str, Any]:
    data = json.loads(result_path.read_text(encoding="utf-8"))
    if isinstance(data, list) and data:
        return data[0]
    if isinstance(data, dict):
        return data
    return {}


class TaintDebuggerCLI(cmd.Cmd):
    intro = (
        "bean-vuln Taint Debugger\n"
        "Commands: why_tainted <var>, why_not_tainted <var>, path <source> <sink>, quit\n"
    )
    prompt = "taint-debug> "

    def __init__(self, graph: TaintFlowGraph) -> None:
        super().__init__()
        self.graph = graph

    def do_why_tainted(self, arg: str) -> None:
        target = arg.strip()
        if not target:
            print("Usage: why_tainted <variable>")
            return
        result = self.graph.why_tainted(target)
        print(result)

    def do_why_not_tainted(self, arg: str) -> None:
        target = arg.strip()
        if not target:
            print("Usage: why_not_tainted <variable>")
            return
        result = self.graph.why_not_tainted(target)
        print(result)

    def do_path(self, arg: str) -> None:
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: path <source> <sink>")
            return
        source, sink = parts
        exists = self.graph.path_exists(source, sink)
        print({"source": source, "sink": sink, "path_exists": exists})

    def do_quit(self, arg: str) -> bool:  # type: ignore[override]
        return True


def launch_debugger(result_path: Path) -> None:
    result = load_flows(result_path)
    taint_tracking = result.get("taint_tracking", {})
    flows = taint_tracking.get("taint_flows", []) if isinstance(taint_tracking, dict) else []
    graph = TaintFlowGraph(flows)
    TaintDebuggerCLI(graph).cmdloop()


def launch_debugger_from_result(result: Dict[str, Any]) -> None:
    taint_tracking = result.get("taint_tracking", {})
    flows = taint_tracking.get("taint_flows", []) if isinstance(taint_tracking, dict) else []
    graph = TaintFlowGraph(flows)
    TaintDebuggerCLI(graph).cmdloop()
