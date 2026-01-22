Tai-e Debugging Utilities
========================

This document describes optional debugging utilities integrated into bean-vuln.
They are **best-effort** and intended for investigation workflows.

Features
--------
1) Soundness validation (runtime logging vs Tai-e points-to)
2) Precision diagnosis (heuristic source analysis)
3) Taint flow visualization (interactive HTML)
4) Interactive taint debugger (CLI)
5) Tai-e profiling harness (best-effort, optional tools)
6) Object-centric memory profiling (CSV export)

Experimental utilities
----------------------
For advanced workflows, there is a blending-config generator and a generic
delta-debugging helper under `src/core/precision_debugging/`. These are
standalone utilities and are not wired into the default CLI run.

Soundness validation
--------------------
Requires a Tai-e run that produced a points-to YAML file.

Example:

  bean-vuln tests/samples/VUL024_ExpressionLanguageInjection.java \
    --summary --out analysis/cli_el_html.json \
    --tai-e --tai-e-soundness --tai-e-java-version 8 --tai-e-no-prepend-jvm

Output:
  analysis/soundness_report_<class>.html

Notes:
- The validator uses **class-level** mapping between runtime logs and Tai-e
  points-to records. This is a coarse check intended to highlight obvious
  mismatches, not a formal proof of soundness.
- If your system JDK is newer than Java 8, use `--tai-e-java-version 8`
  and `--tai-e-no-prepend-jvm` to avoid unsupported classfile versions.
- If `TAI_E_HOME` is not set and `--tai-e-home` is not provided, the CLI
  will prompt for a JAR path when run interactively.

Precision diagnosis
-------------------
Heuristic scan of the source code for potential precision bottlenecks
(string concatenation, collections, reflection).

Example:

  --tai-e-precision-diagnose

Taint flow visualization
------------------------
Generate a D3-based HTML graph from taint flows.

Example:

  --taint-graph

Outputs:
  analysis/taint_flow_graph_<class>.html

Interactive taint debugger
--------------------------
Launch an interactive CLI to explore taint flows for a single file.

Example:

  --taint-debug

Commands:
  why_tainted <var>
  why_not_tainted <var>
  path <source> <sink>

Tai-e profiling harness
-----------------------
Runs Tai-e under optional profiling tools (async-profiler, JFR, YourKit).
If profiler agents are not available, the run still completes with a
minimal report and process-level metrics.

Example:

  --tai-e-profile --tai-e-profile-output analysis/tai_e_profiling

Optional flags:
  --async-profiler-path /path/to/libasyncProfiler.so
  --yourkit-agent-path /path/to/libyjpagent.so
  --profile-jfr
  --profile-max-heap 8g
  --profile-min-heap 2g

Object-centric memory profiling
-------------------------------
Parses a CSV export (from a profiler) to highlight memory retention
hotspots and optimization opportunities.

Example:

  --object-profile analysis/yourkit_export.csv \
  --object-profile-output analysis/object_profile.html
