"""
Comprehensive HTML Report Generator for Bean Vulnerable GNN Framework
=====================================================================

Generates professional, research-grade security analysis reports with:
- Alias Analysis v3.0 Results
- Comprehensive Taint Tracking visualization
- Triage Checklist
- Security Sinks documentation
- Interactive graph visualizations
- Research foundations and citations

Based on: OWASP Top 10 2024, CWE-20/502, Tai-e v0.4.0, FSE 2024, PLDI 2024
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import html as html_lib
import webbrowser
import shutil
import re
import json


def generate_comprehensive_html_report(result: Dict[str, Any], report_dir: Path, command_line: str = ""):
    """
    Generate comprehensive HTML security analysis report
    
    Args:
        result: Analysis result dictionary
        report_dir: Directory to save the report
        command_line: Command line used for analysis
    """
    # Copy banner image to report directory
    banner_source = Path(__file__).parent.parent.parent / 'ascii-art-text.png'
    if banner_source.exists():
        banner_dest = report_dir / 'banner.png'
        shutil.copy2(banner_source, banner_dest)
    else:
        # Fallback to banner.png if ascii-art-text.png doesn't exist
        banner_source_alt = Path(__file__).parent.parent.parent / 'banner.png'
        if banner_source_alt.exists():
            banner_dest = report_dir / 'banner.png'
            shutil.copy2(banner_source_alt, banner_dest)
    
    # Copy source Java file to report directory for easy access
    input_file = result.get('input', '')
    source_href = None
    if input_file:
        source_path = Path(input_file).expanduser()
        if source_path.exists() and source_path.suffix == '.java':
            dest_path = report_dir / source_path.name
            source_href = source_path.name
            try:
                shutil.copy2(source_path, dest_path)
            except Exception as e:
                print(f"Warning: Could not copy source file: {e}")
                try:
                    source_href = source_path.resolve().as_uri()
                except Exception:
                    source_href = None
    
    # Extract data
    taint_tracking = result.get('taint_tracking', {})
    alias_analysis = taint_tracking.get('alias_analysis', {})
    taint_assignments = taint_tracking.get('taint_assignments', {})
    sanitizer_analysis = taint_tracking.get('sanitizer_analysis', {})
    framework_sinks = result.get('framework_sinks', {}) or taint_tracking.get('framework_sinks', {})
    template_engine_analysis = result.get('template_engine_analysis', {}) or taint_tracking.get('template_engine_analysis', {})
    taint_graph = result.get('taint_graph', {}) if isinstance(result.get('taint_graph', {}), dict) else {}
    soundness_validation = result.get('soundness_validation', {}) if isinstance(result.get('soundness_validation', {}), dict) else {}
    tai_e_profiling = result.get('tai_e_profiling', {}) if isinstance(result.get('tai_e_profiling', {}), dict) else {}
    object_profile = result.get('object_profile', {}) if isinstance(result.get('object_profile', {}), dict) else {}
    
    # Extract CF-Explainer data
    cf_explanation = result.get('cf_explanation', {})
    # Show CF section if explanation exists, even if recommendations are empty
    has_cf_explanation = bool(cf_explanation and isinstance(cf_explanation, dict) and 'counterfactual_explanation' in cf_explanation)
    
    tainted_vars = taint_tracking.get('tainted_variables', [])
    sanitized_vars = taint_tracking.get('sanitized_variables', [])
    tainted_fields = taint_tracking.get('tainted_fields', [])
    taint_flows = taint_tracking.get('taint_flows', [])
    
    # Alias analysis metrics (including new object-sensitive metrics)
    variables_tracked = alias_analysis.get('variables_tracked', 0)
    allocation_sites = alias_analysis.get('allocation_sites', 0)
    field_accesses = alias_analysis.get('field_accesses', 0)
    must_not_alias_pairs = alias_analysis.get('must_not_alias_pairs', 0)
    refinement_iterations = alias_analysis.get('refinement_iterations', 0)
    cache_size = alias_analysis.get('cache_size', 0)
    variable_to_allocation_mappings = alias_analysis.get('variable_to_allocation_mappings', 0)
    library_summaries_loaded = alias_analysis.get('library_summaries_loaded', 0)
    object_sensitive_enabled = alias_analysis.get('object_sensitive_enabled', False)
    tai_e_meta = alias_analysis.get('tai_e', {}) if isinstance(alias_analysis.get('tai_e'), dict) else {}
    
    # Advanced analysis metrics (2024 research)
    implicit_flows = taint_tracking.get('implicit_flows', {})
    context_sensitive = taint_tracking.get('context_sensitive_analysis', {})
    path_sensitive = taint_tracking.get('path_sensitive_analysis', {})
    native_code = taint_tracking.get('native_code_analysis', {})
    interprocedural = taint_tracking.get('interprocedural_analysis', {})
    
    # Generate HTML
    # Build linkable DFG paths HTML if present
    dfg_paths_entries: Dict[str, List[Dict[str, str]]] = {}
    dfg_paths_file = report_dir / "dfg_paths.txt"
    implicit_vars = implicit_flows.get("variables", {}) if isinstance(implicit_flows, dict) else {}
    if dfg_paths_file.exists():
        dfg_paths_text = dfg_paths_file.read_text(encoding="utf-8", errors="ignore")
        dfg_paths_entries = _write_dfg_paths_html(report_dir, dfg_paths_text, implicit_vars)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bean Vulnerable - Security Analysis Report</title>
    {_get_css_styles()}
</head>
<body>
    {_generate_banner()}
    
    <div class="generated-timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    
    <div class="container">
        <div class="section">
            <h2 class="section-title">Security Analysis</h2>
            <div class="command-line">
                <code>{command_line if command_line else f'/opt/homebrew/bin/bean-vuln {result.get("input", "")}'}</code>
            </div>
        </div>
        
        {_generate_capabilities_section(result)}
        
        {_generate_alias_analysis_section(
            variables_tracked, field_accesses, tainted_fields, allocation_sites,
            len(tainted_vars), len(sanitized_vars), len(taint_flows),
            refinement_iterations, cache_size, must_not_alias_pairs,
            variable_to_allocation_mappings, library_summaries_loaded, object_sensitive_enabled, tai_e_meta
        )}
        
        {_generate_tainted_variables_section(tainted_vars, taint_assignments)}
        
        {_generate_tainted_fields_section(tainted_fields)}

        {_generate_sanitizer_analysis_section(sanitizer_analysis)}

        {_generate_framework_sink_section(framework_sinks)}

        {_generate_template_engine_section(template_engine_analysis)}

        {_generate_taint_graph_section(taint_graph)}

        {_generate_soundness_section(soundness_validation)}

        {_generate_profiling_section(tai_e_profiling)}

        {_generate_object_profile_section(object_profile)}
        
        {_generate_advanced_analysis_section(implicit_flows, context_sensitive, path_sensitive, native_code, interprocedural, object_sensitive_enabled, tai_e_meta, source_href)}
        
        {_generate_triage_checklist()}
        
        {_generate_badges_section(result)}
        
        {_generate_findings_section(result)}

        {_generate_aeg_lite_section(result)}

        {_generate_sink_gating_section(result)}
        
        {_generate_file_links_section(result, report_dir)}

        {_generate_dfg_paths_links_section(dfg_paths_entries, report_dir, source_href)}
        
        {_generate_graph_index_section(report_dir)}

        {_generate_cf_explainer_section(cf_explanation) if has_cf_explanation else ""}
        
        {_generate_graph_gallery_section(report_dir)}
        
        {_generate_all_artifacts_section(report_dir)}
        
        {_generate_legend_section()}
        
        {_generate_footer()}
    </div>
</body>
</html>
"""
    
    # Write report
    report_path = report_dir / "index.html"
    report_path.write_text(html_content, encoding='utf-8')
    
    # Auto-open in browser
    try:
        webbrowser.open(f"file://{report_path.absolute()}")
    except Exception:
        pass
    
    return report_path


def _escape_html(value: Any) -> str:
    if value is None:
        return ""
    return html_lib.escape(str(value))


def _render_code_block(code: Optional[str]) -> str:
    if not code:
        return "<em>No payload available.</em>"
    return f"<pre class=\"aeg-code\"><code>{_escape_html(code)}</code></pre>"


def _write_dfg_paths_html(
    report_dir: Path,
    dfg_paths_text: str,
    implicit_vars: Optional[Dict[str, List[str]]] = None
) -> Dict[str, List[Dict[str, str]]]:
    lines = dfg_paths_text.splitlines()
    taint_entries: List[Dict[str, str]] = []
    implicit_entries: List[Dict[str, str]] = []

    # Parse existing entries from the text file
    for idx, line in enumerate(lines, 1):
        flow_match = re.match(r'^(?:TAINT )?FLOW (\d+):\s*(.*)', line)
        if flow_match:
            flow_id = flow_match.group(1)
            taint_entries.append({
                "anchor": f"taint-flow-{flow_id}",
                "label": line,
                "line": str(idx),
            })
        implicit_match = re.match(r'^IMPLICIT FLOW (\d+):\s*(.*)', line)
        if implicit_match:
            flow_id = implicit_match.group(1)
            implicit_entries.append({
                "anchor": f"implicit-flow-{flow_id}",
                "label": line,
                "line": str(idx),
            })

    # If implicit flows are missing in the text file, append derived entries for HTML
    if not implicit_entries and implicit_vars:
        lines.extend([
            "",
            "═══════════════════════════════════════════════════════════════",
            "  IMPLICIT FLOWS SUMMARY (derived)",
            "═══════════════════════════════════════════════════════════════",
            "",
        ])
        for idx, (target, controls) in enumerate(implicit_vars.items(), 1):
            control_text = ", ".join(controls) if controls else "control-dependent"
            line = f"IMPLICIT FLOW {idx}: {target} <- {control_text}"
            implicit_entries.append({
                "anchor": f"implicit-flow-{idx}",
                "label": line,
                "line": str(len(lines) + 1),
            })
            lines.append(line)
        lines.append("")

    # Build HTML with line numbers and anchors
    html_lines: List[str] = []
    for idx, line in enumerate(lines, 1):
        anchor_tags = []
        flow_match = re.match(r'^(?:TAINT )?FLOW (\d+):', line)
        if flow_match:
            anchor_tags.append(f'<a id="taint-flow-{flow_match.group(1)}"></a>')
        implicit_match = re.match(r'^IMPLICIT FLOW (\d+):', line)
        if implicit_match:
            anchor_tags.append(f'<a id="implicit-flow-{implicit_match.group(1)}"></a>')
        anchor_html = "".join(anchor_tags)
        html_lines.append(
            "<div class=\"dfg-line\" id=\"L{line_no}\">"
            "{anchors}<span class=\"dfg-lno\">{line_no:>4}</span> "
            "<span class=\"dfg-text\">{text}</span></div>".format(
                line_no=idx,
                anchors=anchor_html,
                text=_escape_html(line),
            )
        )

    lines_html = "\n".join(html_lines)
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DFG Paths</title>
  <style>
    body {{ font-family: "Segoe UI", Arial, sans-serif; background: #f5f7fa; color: #2c3e50; padding: 24px; }}
    .header {{ margin-bottom: 16px; }}
    .header a {{ color: #3498db; text-decoration: none; font-weight: 600; }}
    .dfg-container {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; }}
    .dfg-line {{ font-family: "Menlo", "Monaco", monospace; font-size: 13px; line-height: 1.5; white-space: pre-wrap; }}
    .dfg-lno {{ color: #95a5a6; display: inline-block; width: 42px; text-align: right; margin-right: 10px; }}
    .dfg-text {{ color: #2c3e50; }}
  </style>
</head>
<body>
  <div class="header">
    <a href="index.html">← Back to report</a>
  </div>
  <div class="dfg-container">
    {lines_html}
  </div>
</body>
</html>
"""

    output_path = report_dir / "dfg_paths.html"
    output_path.write_text(html_content, encoding="utf-8")

    return {"taint": taint_entries, "implicit": implicit_entries}


def _generate_dfg_paths_links_section(
    paths_entries: Dict[str, List[Dict[str, str]]],
    report_dir: Path,
    source_href: Optional[str] = None
) -> str:
    if not paths_entries:
        return ""
    taint_entries = paths_entries.get("taint", [])
    implicit_entries = paths_entries.get("implicit", [])
    if not taint_entries and not implicit_entries:
        return ""

    index_by_base: Dict[str, Dict[str, Any]] = {}
    index_path = report_dir / "graph_index.json"
    if index_path.exists():
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                for entry in payload:
                    if not isinstance(entry, dict):
                        continue
                    base = entry.get("base")
                    if base:
                        index_by_base[str(base)] = entry
        except Exception:
            index_by_base = {}

    def _line_range_for_base(base: str) -> str:
        entry = index_by_base.get(base, {})
        start_line = entry.get("start_line")
        end_line = entry.get("end_line")
        if isinstance(start_line, int) and start_line > 0:
            if isinstance(end_line, int) and end_line > 0 and end_line != start_line:
                return f"L{start_line}–{end_line}"
            return f"L{start_line}"
        return ""

    def _format_graph_links(label: str, files: List[Path], max_items: int = 5) -> str:
        if not files:
            return ""
        items = []
        for graph_path in files[:max_items]:
            graph_name = graph_path.name
            base = graph_path.stem[len(label.lower()) + 1 :] if graph_path.stem.startswith(label.lower()) else graph_path.stem.split("_", 1)[-1]
            line_range = _line_range_for_base(base)
            range_text = f' <span style="color: #7f8c8d;">({line_range})</span>' if line_range else ""
            items.append(f'<a href="{_escape_html(graph_name)}">{_escape_html(graph_name)}</a>{range_text}')
        suffix = ""
        if len(files) > max_items:
            suffix = f" +{len(files) - max_items} more"
        return f"{label}: " + ", ".join(items) + suffix

    dfg_files = sorted(report_dir.glob("dfg_*.png"))
    pdg_files = sorted(report_dir.glob("pdg_*.png"))
    cfg_files = sorted(report_dir.glob("cfg_*.png"))

    taint_graph_links = " · ".join(filter(None, [
        _format_graph_links("DFG", dfg_files),
        _format_graph_links("PDG", pdg_files),
    ]))
    implicit_graph_links = " · ".join(filter(None, [
        _format_graph_links("CFG", cfg_files),
        _format_graph_links("PDG", pdg_files),
    ]))

    source_link = f'<a href="{_escape_html(source_href)}">source</a>' if source_href else ""
    graph_link = '<a href="#graph-gallery">graphs</a>'
    index_link = '<a href="#graph-index">graph index</a>'
    link_parts = [part for part in (source_link, graph_link, index_link) if part]
    extra_links = " | ".join(link_parts)
    extra_suffix = f' <span style="color: #7f8c8d;">({extra_links})</span>' if extra_links else ""

    html = """
    <div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🔗 DFG Paths</h3>
        <p style="margin-bottom: 6px; color: #6c7a89;">
            Links jump into <code>dfg_paths.html</code> at the relevant path entry.
        </p>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Taint flows map to <strong>DFG/PDG</strong> (data dependencies). Implicit flows map to <strong>CFG/PDG</strong> (control dependencies).
        </p>
    """
    if taint_entries:
        html += """
        <h4 style="margin-top: 12px;">Taint flows <span style="color: #7f8c8d; font-weight: normal;">(DFG/PDG)</span></h4>
        <ul style="list-style: none; padding-left: 0;">
        """
        for entry in taint_entries:
            label = _escape_html(entry.get("label", ""))
            anchor = entry.get("anchor", "")
            graph_suffix = f' <span style="color: #7f8c8d;">[{taint_graph_links}]</span>' if taint_graph_links else ""
            html += f'            <li style="margin: 6px 0;"><a href="dfg_paths.html#{anchor}">{label}</a>{extra_suffix}{graph_suffix}</li>\n'
        html += """
        </ul>
        """
    if implicit_entries:
        html += """
        <h4 style="margin-top: 12px;">Implicit flows <span style="color: #7f8c8d; font-weight: normal;">(CFG/PDG)</span></h4>
        <ul style="list-style: none; padding-left: 0;">
        """
        for entry in implicit_entries:
            label = _escape_html(entry.get("label", ""))
            anchor = entry.get("anchor", "")
            graph_suffix = f' <span style="color: #7f8c8d;">[{implicit_graph_links}]</span>' if implicit_graph_links else ""
            html += f'            <li style="margin: 6px 0;"><a href="dfg_paths.html#{anchor}">{label}</a>{extra_suffix}{graph_suffix}</li>\n'
        html += """
        </ul>
        """
    html += """
    </div>
    """
    return html


def _get_css_styles() -> str:
    """Get comprehensive CSS styles"""
    return """<style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #2c3e50;
        }
        
        .banner {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .banner img {
            max-width: 600px;
            width: 100%;
            height: auto;
        }
        
        .generated-timestamp {
            text-align: center;
            color: white;
            font-size: 14px;
            margin-bottom: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section-title {
            font-size: 32px;
            color: #34495e;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .command-line {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
        }
        
        .capabilities-list {
            list-style: none;
            padding-left: 0;
        }
        
        .capabilities-list li {
            padding: 8px 0;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .capabilities-list li strong {
            color: #2c3e50;
        }
        
        .alias-header {
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 5px solid #4caf50;
        }
        
        .alias-header h3 {
            color: #2e7d32;
            font-size: 24px;
            margin-bottom: 10px;
        }
        
        .alias-header p {
            color: #558b2f;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .metric-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
        }
        
        .metric-icon {
            font-size: 24px;
            margin-bottom: 10px;
        }
        
        .metric-label {
            font-size: 12px;
            font-weight: bold;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .metric-value {
            font-size: 36px;
            font-weight: bold;
            color: #2c3e50;
            margin: 10px 0;
        }
        
        .metric-description {
            font-size: 12px;
            color: #95a5a6;
        }
        
        .performance-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin: 20px 0;
        }
        
        .performance-box {
            background: #fff9e6;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #f39c12;
        }
        
        .performance-box h4 {
            color: #e67e22;
            margin-bottom: 15px;
        }
        
        .performance-box p {
            margin: 8px 0;
            color: #7f8c8d;
        }
        
        .performance-box strong {
            color: #2c3e50;
        }
        
        .tainted-box {
            background: #ffe6e6;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #e74c3c;
            margin: 20px 0;
        }
        
        .tainted-box h4 {
            color: #c0392b;
            margin-bottom: 15px;
        }
        
        .tainted-list {
            list-style: none;
            padding: 0;
        }
        
        .tainted-list li {
            padding: 8px 12px;
            margin: 5px 0;
            background: white;
            border-radius: 4px;
            border-left: 3px solid #e74c3c;
        }
        
        .tainted-list code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #c0392b;
        }
        
        .tainted-list small {
            color: #7f8c8d;
            font-size: 11px;
        }
        
        .research-note {
            background: #e3f2fd;
            padding: 12px;
            border-radius: 4px;
            border-left: 3px solid #2196f3;
            margin-top: 15px;
            font-size: 13px;
            color: #1565c0;
        }
        
        .triage-checklist {
            background: #fff8e1;
            padding: 25px;
            border-radius: 8px;
            border-left: 5px solid #ffc107;
            margin: 30px 0;
        }
        
        .triage-checklist h3 {
            color: #f57c00;
            margin-bottom: 15px;
        }
        
        .triage-checklist ol {
            padding-left: 25px;
        }
        
        .triage-checklist li {
            padding: 8px 0;
            color: #5d4037;
        }
        
        .badges-section {
            background: #fffbea;
            padding: 25px;
            border-radius: 8px;
            margin: 30px 0;
        }
        
        .badges-section h3 {
            color: #f39c12;
            margin-bottom: 20px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            margin: 0 5px;
            color: white;
        }
        
        .badge-vuln { background: #e74c3c; }
        .badge-dfg-paths { background: #3498db; }
        .badge-dfg-dot { background: #9b59b6; }
        .badge-dfg-png { background: #f39c12; }
        
        .sink-list {
            list-style: none;
            padding: 0;
        }
        
        .sink-list li {
            padding: 10px;
            margin: 5px 0;
            background: #f8f9fa;
            border-left: 3px solid #e74c3c;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        
        .sink-list li code {
            color: #c0392b;
        }
        
        .graudit-info {
            background: #e8f5e9;
            padding: 15px;
            border-radius: 4px;
            border-left: 3px solid #4caf50;
            margin: 15px 0;
        }
        
        .graudit-info code {
            background: #c8e6c9;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .graph-gallery {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }
        
        .graph-card {
            background: white;
            border: 2px solid #ecf0f1;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .graph-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.15);
        }
        
        .graph-card-header {
            background: #f8f9fa;
            padding: 15px;
            border-bottom: 2px solid #ecf0f1;
        }
        
        .graph-card-header h4 {
            margin: 8px 0 0 0;
            color: #2c3e50;
            font-size: 14px;
        }
        
        .graph-card-description {
            padding: 12px 15px;
            color: #7f8c8d;
            font-size: 13px;
            background: #fafbfc;
        }
        
        .graph-preview {
            padding: 15px;
            background: white;
            text-align: center;
            min-height: 200px;
            max-height: 420px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: auto;
        }
        
        .graph-preview img {
            max-width: none;
            max-height: none;
            cursor: pointer;
            border-radius: 4px;
            transition: opacity 0.2s;
        }
        
        .graph-preview img:hover {
            opacity: 0.8;
        }

        .aeg-summary {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 12px;
        }

        .aeg-badge {
            background: #eef2ff;
            border-radius: 12px;
            padding: 4px 10px;
            font-size: 12px;
        }

        .aeg-card {
            background: #fafafa;
            border: 1px solid #e1e1e1;
            border-radius: 8px;
            padding: 12px;
            margin-top: 12px;
        }

        .aeg-meta {
            color: #7f8c8d;
            font-size: 12px;
            margin-bottom: 8px;
        }

        .aeg-code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 12px;
            line-height: 1.5;
        }

        details.aeg-details summary {
            cursor: pointer;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .graph-card-footer {
            padding: 15px;
            background: #f8f9fa;
            border-top: 1px solid #ecf0f1;
            text-align: center;
        }
        
        .download-btn {
            display: inline-block;
            padding: 8px 16px;
            margin: 4px;
            border-radius: 5px;
            text-decoration: none;
            color: white;
            font-size: 12px;
            font-weight: bold;
            transition: opacity 0.2s;
        }
        
        .download-btn:hover {
            opacity: 0.8;
        }
        
        .download-cfg { background: #3498db; }
        .download-dfg { background: #9b59b6; }
        .download-pdg { background: #f39c12; }
        .download-dot { background: #95a5a6; }
        
        .badge-cfg { background: #3498db; }
        .badge-dfg { background: #9b59b6; }
        .badge-pdg { background: #f39c12; }
        .badge-dfg-paths { background: #3498db; }
        .badge-dfg-dot { background: #9b59b6; }
        .badge-cfg-dot { background: #3498db; }
        .badge-cfg-png { background: #3498db; }
        .badge-pdg-dot { background: #f39c12; }
        .badge-pdg-png { background: #f39c12; }
        .badge-dfg-png { background: #9b59b6; }
        
        .artifacts-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .artifact-item {
            background: #f8f9fa;
            padding: 12px 15px;
            border-radius: 6px;
            border-left: 3px solid #3498db;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .artifact-item a {
            color: #2c3e50;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        
        .artifact-item a:hover {
            color: #3498db;
            text-decoration: underline;
        }
        
        .legend-box {
            background: #f0f8ff;
            padding: 25px;
            border-radius: 8px;
            border-left: 5px solid #3498db;
        }
        
        .legend-list {
            list-style: none;
            padding: 0;
        }
        
        .legend-list li {
            margin: 15px 0;
            padding: 15px;
            background: white;
            border-radius: 6px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.05);
        }
        
        .legend-list ul {
            margin: 10px 0 0 20px;
            padding-left: 0;
        }
        
        .legend-list ul li {
            margin: 5px 0;
            padding: 5px 0;
            background: none;
            box-shadow: none;
            border-left: 2px solid #3498db;
            padding-left: 15px;
        }
        
        .footer {
            text-align: center;
            padding: 30px 0;
            border-top: 2px solid #ecf0f1;
            margin-top: 50px;
            color: #7f8c8d;
        }
        
        .footer small {
            font-size: 12px;
            line-height: 1.6;
        }
        
        /* CF-Explainer Section Styles */
        .recommendation-item {
            display: flex;
            align-items: flex-start;
            padding: 15px;
            background: white;
            border-radius: 8px;
            margin-bottom: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            transition: all 0.3s ease;
        }
        
        .recommendation-item:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .recommendation-item .badge {
            margin-right: 15px;
            min-width: 50px;
            text-align: center;
            font-weight: bold;
            flex-shrink: 0;
        }
        
        .recommendation-text {
            flex: 1;
            line-height: 1.6;
            color: #2c3e50;
        }
        
        .badge-success {
            background: linear-gradient(135deg, #27ae60, #2ecc71);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .badge-info {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .badge-warning {
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .badge-default {
            background: linear-gradient(135deg, #95a5a6, #7f8c8d);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .recommendations-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
    </style>"""


def _generate_banner() -> str:
    """Generate banner section"""
    return """<div class="banner">
        <img src="banner.png" alt="Bean Vulnerable" onerror="this.style.display='none'">
    </div>"""


def _generate_capabilities_section(result: Dict[str, Any]) -> str:
    """Generate Advanced Analysis Capabilities section"""
    spatial = result.get("spatial_gnn", {}) if isinstance(result.get("spatial_gnn", {}), dict) else {}
    gnn_enabled = bool(spatial.get("enabled", False))
    gnn_forward = bool(result.get("gnn_utilized") or spatial.get("forward_called"))
    gnn_weighted = bool(spatial.get("used_in_scoring", False))

    if gnn_weighted:
        gnn_status = "enabled (weighted in scoring)"
    elif gnn_forward:
        gnn_status = "inference executed (untrained)"
    elif gnn_enabled:
        gnn_status = "initialized (no inference executed)"
    else:
        gnn_status = "disabled"

    cf_explanation = result.get("cf_explanation")
    cf_enabled = bool(
        cf_explanation
        and isinstance(cf_explanation, dict)
        and cf_explanation.get("counterfactual_explanation")
    )
    cf_status = "generated for this report" if cf_enabled else "not generated (flag disabled or no findings)"

    joern_dataflow = result.get("joern_dataflow") or result.get("taint_tracking", {}).get("joern_dataflow")
    joern_status = "enabled (reachableByFlows metrics)" if joern_dataflow else "not available"

    analysis_config = result.get("analysis_config", {}) if isinstance(result.get("analysis_config", {}), dict) else {}
    sink_preset = analysis_config.get("sink_signature_preset") or result.get("sink_signature_preset")
    if sink_preset:
        sink_status = f"{_escape_html(sink_preset)} (reserved; no effect in this build)"
    else:
        sink_status = "default (no preset)"

    alias_analysis = result.get("taint_tracking", {}).get("alias_analysis", {}) or {}
    object_sensitive = bool(alias_analysis.get("object_sensitive_enabled"))
    tai_e_meta = alias_analysis.get("tai_e", {}) if isinstance(alias_analysis.get("tai_e"), dict) else {}
    tai_e_cs = tai_e_meta.get("cs")
    if object_sensitive:
        alias_status = f"Tai-e object-sensitive analysis ({tai_e_cs or 'obj'})"
    else:
        alias_status = "Heuristic field-sensitive analysis (assignment + allocation sites)"

    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">Advanced Analysis Capabilities</h3>
        <ul class="capabilities-list">
            <li><strong>Multi-Graph Analysis</strong>: CFG/DFG/PDG generation when HTML report is enabled</li>
            <li><strong>GNN Processing</strong>: {gnn_status}</li>
            <li><strong>Alias Analysis</strong>: {alias_status}</li>
            <li><strong>Counterfactual Explanations</strong>: {cf_status}</li>
            <li><strong>Joern Dataflow</strong>: {joern_status}</li>
            <li><strong>Sink Signature Preset</strong>: {sink_status}</li>
            <li><strong>Graph Visualizations</strong>: PNG/SVG exports when Graphviz is available</li>
        </ul>
    </div>"""


def _generate_alias_analysis_section(variables_tracked, field_accesses, tainted_fields, allocation_sites,
                                     tainted_vars_count, sanitized_vars_count, taint_flows_count,
                                     refinement_iterations, cache_size, must_not_alias_pairs, 
                                     variable_to_allocation_mappings=0, library_summaries_loaded=0,
                                     object_sensitive_enabled=False, tai_e_meta: Optional[Dict[str, Any]] = None) -> str:
    """Generate Alias Analysis v3.0 Results section with Object-Sensitive Analysis"""
    converged = "✓ Converged" if refinement_iterations > 0 else "Not run"
    tai_e_meta = tai_e_meta if isinstance(tai_e_meta, dict) else {}
    tai_e_enabled = bool(tai_e_meta.get("enabled"))
    tai_e_errors = tai_e_meta.get("errors") if isinstance(tai_e_meta.get("errors"), list) else []

    if object_sensitive_enabled:
        obj_sensitive_status = "✅ Enabled"
    elif tai_e_enabled:
        obj_sensitive_status = "❌ Failed (see Tai-e logs)" if tai_e_errors else "❌ Failed"
    else:
        obj_sensitive_status = "N/A (not enabled)"
    cache_label = f"{cache_size} cache entries" if cache_size > 0 else "N/A"
    mapping_label = str(variable_to_allocation_mappings) if variable_to_allocation_mappings is not None else "N/A"
    library_label = str(library_summaries_loaded) if library_summaries_loaded is not None else "N/A"
    obj_header = "Tai-e" if tai_e_enabled or object_sensitive_enabled else "Tai-e (not enabled)"
    synthetic_entry = bool(tai_e_meta.get("synthetic_entrypoint"))
    if object_sensitive_enabled:
        accuracy_gain = "+3-5% precision (literature estimate)"
        obj_note = (
            "Object-sensitive analysis uses allocation sites as context to distinguish objects created at different "
            "program points, improving must-not-alias precision."
        )
        if synthetic_entry:
            obj_note += " Entry point was auto-generated for coverage."
        research_note = (
            "Tai-e (context-sensitive pointer analysis), FSE 2024 (batch query ideas), "
            "PLDI 2024 (refinement strategies)"
        )
    elif tai_e_enabled:
        accuracy_gain = "N/A (failed)"
        obj_note = "Tai-e execution failed in this run. Review Tai-e output logs for details."
        research_note = (
            "Tai-e (context-sensitive pointer analysis), FSE 2024 (batch query ideas), "
            "PLDI 2024 (refinement strategies)"
        )
    else:
        accuracy_gain = "N/A (not enabled)"
        obj_note = "Object-sensitive analysis was not run. Enable Tai-e to compute these metrics."
        research_note = "FSE 2024 (batch query ideas), PLDI 2024 (refinement strategies)"

    object_sensitive_block = ""
    if object_sensitive_enabled or tai_e_enabled:
        object_sensitive_block = f"""
            <div class="performance-box">
                <h4>🎯 Object-Sensitive Analysis ({obj_header})</h4>
                <p><strong>Status:</strong> {obj_sensitive_status}</p>
                <p><strong>Allocation Site Mappings:</strong> {mapping_label} tracked</p>
                <p><strong>JDK/Library Summaries:</strong> {library_label} loaded</p>
                <p><strong>Accuracy Gain:</strong> {accuracy_gain}</p>
                <p>{obj_note}</p>
            </div>"""
    
    return f"""<div class="section">
        <div class="alias-header">
            <h3>🔬 Alias Analysis v3.0 Results</h3>
            <p>Enhanced precision alias tracking with field-sensitivity, cache reuse, and iterative refinement.</p>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-icon">📊</div>
                <div class="metric-label">Variables Tracked</div>
                <div class="metric-value">{variables_tracked}</div>
                <div class="metric-description">Total program variables</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-icon">🔄</div>
                <div class="metric-label">Field Accesses</div>
                <div class="metric-value">{field_accesses}</div>
                <div class="metric-description">Object field operations</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-icon">🚨</div>
                <div class="metric-label">Tainted Fields</div>
                <div class="metric-value">{len(tainted_fields)}</div>
                <div class="metric-description">Fields with untrusted data</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-icon">🏭</div>
                <div class="metric-label">Allocation Sites</div>
                <div class="metric-value">{allocation_sites}</div>
                <div class="metric-description">new Object() locations</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-icon">🔓</div>
                <div class="metric-label">Tainted Variables</div>
                <div class="metric-value">{tainted_vars_count}</div>
                <div class="metric-description">Heuristic sources (OWASP/CWE-inspired)</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-icon">✅</div>
                <div class="metric-label">Sanitized Variables</div>
                <div class="metric-value">{sanitized_vars_count}</div>
                <div class="metric-description">Validated/encoded variables</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-icon">🔄</div>
                <div class="metric-label">Taint Flows</div>
                <div class="metric-value">{taint_flows_count}</div>
                <div class="metric-description">Propagation paths tracked</div>
            </div>
        </div>
        
        <div class="performance-grid">
            <div class="performance-box">
                <h4>⚙️ Refinement & Cache Performance</h4>
                <p><strong>Refinement Iterations:</strong> {refinement_iterations} {converged}</p>
                <p><strong>Alias Cache:</strong> {cache_label}</p>
                <p><strong>Processing Mode:</strong> Sequential (optimal for fast queries)</p>
                <p><strong>Must-Alias Pairs:</strong> N/A (not computed)</p>
                <p><strong>Must-NOT-Alias:</strong> {must_not_alias_pairs} proven non-aliases</p>
            </div>
            
            {object_sensitive_block}
            
            <div class="performance-box">
                <h4>💡 Performance Note</h4>
                <p>Sequential mode used: For fast alias queries (microseconds each), threading overhead (~1-2ms per thread) dominates the actual computation. Sequential processing is optimal for these queries.</p>
                <p><strong>FSE 2024 context:</strong> The 3-10x parallel speedup applies to expensive pointer analyses (milliseconds per query), not hash table lookups. The framework automatically selects the optimal execution mode.</p>
            </div>
        </div>
        
        <div class="research-note">
            <strong>Research references (background):</strong> {research_note}
        </div>
    </div>"""


def _generate_tainted_variables_section(tainted_vars: List[str], taint_assignments: Dict[str, str]) -> str:
    """Generate Tainted Variables section"""
    if not tainted_vars:
        return ""
    
    tainted_list_html = ""
    for var in tainted_vars:
        source = taint_assignments.get(var, "Heuristic taint source")
        tainted_list_html += f"<li><code>{var}</code> - <small>{source}</small></li>"
    
    return f"""<div class="section">
        <div class="tainted-box">
            <h4>🔓 Potentially Tainted Variables (Heuristic Sources)</h4>
            <p>The following variables were marked tainted by heuristic and conservative rules; verify actual input sources:</p>
            <ul class="tainted-list">
                {tainted_list_html}
            </ul>
            <div class="research-note">
                <strong>Note:</strong> Heuristic taint rules are inspired by OWASP/CWE source patterns; not every marked variable is guaranteed to be user-controlled.
            </div>
        </div>
    </div>"""


def _generate_advanced_analysis_section(implicit_flows, context_sensitive, path_sensitive, native_code, interprocedural, object_sensitive_enabled: bool = False, tai_e_meta: Optional[Dict[str, Any]] = None, source_href: Optional[str] = None) -> str:
    """Generate Advanced Analysis section with heuristic signals"""
    
    implicit_count = implicit_flows.get('count', 0)
    implicit_vars = implicit_flows.get('variables', {})
    
    contexts_tracked = context_sensitive.get('contexts_tracked', 0)
    k_cfa = context_sensitive.get('k_cfa_limit', 0)
    
    branching_points = path_sensitive.get('branching_points', 0)
    feasible_paths = path_sensitive.get('feasible_paths', 0)
    infeasible_paths = path_sensitive.get('infeasible_paths', 0)
    branching_details = path_sensitive.get('branching_details', []) if isinstance(path_sensitive, dict) else []
    feasible_details = path_sensitive.get('feasible_details', []) if isinstance(path_sensitive, dict) else []
    infeasible_details = path_sensitive.get('infeasible_details', []) if isinstance(path_sensitive, dict) else []
    
    native_methods = native_code.get('jni_methods', 0)
    native_transfers = native_code.get('taint_transfers', 0)
    loaded_libs = native_code.get('loaded_libraries', [])
    
    methods_analyzed = interprocedural.get('methods_analyzed', 0)
    methods_with_tainted = interprocedural.get('methods_with_tainted_params', 0)
    
    implicit_has_data = isinstance(implicit_flows, dict) and (
        "count" in implicit_flows or "variables" in implicit_flows
    )
    context_has_data = isinstance(context_sensitive, dict) and (
        "contexts_tracked" in context_sensitive or "k_cfa_limit" in context_sensitive
    )
    path_has_data = isinstance(path_sensitive, dict) and any(
        key in path_sensitive for key in ("branching_points", "feasible_paths", "infeasible_paths")
    )
    native_has_data = isinstance(native_code, dict) and any(
        key in native_code for key in ("jni_methods", "taint_transfers")
    )
    inter_has_data = isinstance(interprocedural, dict) and (
        "methods_analyzed" in interprocedural or "methods_with_tainted_params" in interprocedural
    )

    implicit_enabled = implicit_flows.get("enabled") if isinstance(implicit_flows, dict) else None
    if implicit_enabled is None:
        implicit_enabled = implicit_has_data
    implicit_label = "Disabled" if not implicit_enabled else (
        "Heuristic" if implicit_count else "Enabled (0)"
    )
    context_label = "Heuristic (k-CFA)" if contexts_tracked else ("Enabled (k-CFA)" if context_has_data else "Disabled")
    if object_sensitive_enabled:
        context_label = f"{context_label} + Tai-e"
    path_enabled = path_sensitive.get("enabled") if isinstance(path_sensitive, dict) else None
    if path_enabled is None:
        path_enabled = path_has_data
    path_label = "Disabled" if not path_enabled else (
        "Experimental" if (branching_points or feasible_paths or infeasible_paths) else "Enabled (0)"
    )
    native_enabled = native_code.get("enabled") if isinstance(native_code, dict) else None
    if native_enabled is None:
        native_enabled = native_has_data
    native_label = "Disabled" if not native_enabled else (
        "Experimental" if (native_methods or native_transfers) else "Enabled (0)"
    )
    inter_label = "Heuristic" if methods_analyzed else ("Enabled (0)" if inter_has_data else "Disabled")

    tai_e_meta = tai_e_meta if isinstance(tai_e_meta, dict) else {}
    tai_e_enabled = bool(tai_e_meta.get("enabled"))
    tai_e_errors = tai_e_meta.get("errors") if isinstance(tai_e_meta.get("errors"), list) else []
    synthetic_entry = bool(tai_e_meta.get("synthetic_entrypoint"))

    if object_sensitive_enabled:
        advanced_note = "Heuristic signals plus Tai-e pointer analysis metrics (object-sensitive) were available in this run."
        if synthetic_entry:
            advanced_note += " Entry point was auto-generated for coverage."
    elif tai_e_enabled:
        if tai_e_errors:
            advanced_note = "Tai-e was enabled but failed; showing heuristic signals only."
        else:
            advanced_note = "Tai-e was enabled but did not report object-sensitive metrics; showing heuristic signals only."
    else:
        advanced_note = "Heuristic signals only; enable Tai-e to add object-sensitive pointer metrics."

    html = f"""
    <div class="section" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
        <h2 style="color: white; margin-bottom: 15px;">🔬 Advanced Taint Analysis</h2>
        <p style="color: #f0f0f0; margin-bottom: 20px;">{advanced_note}</p>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
"""
    
    # Implicit Flows
    html += f"""
            <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <h4 style="color: #ffd700; margin: 0 0 10px 0;">⚡ Implicit Flows</h4>
                <div style="font-size: 32px; font-weight: bold; margin: 10px 0;">{implicit_count}</div>
                <div style="font-size: 14px; color: #e0e0e0;">Control dependencies tracked</div>
                <div style="font-size: 12px; color: #b0b0b0; margin-top: 5px;">{implicit_label}</div>
            </div>
"""
    
    # Context-Sensitive
    html += f"""
            <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <h4 style="color: #00ff88; margin: 0 0 10px 0;">🎯 Context-Sensitive</h4>
                <div style="font-size: 32px; font-weight: bold; margin: 10px 0;">{contexts_tracked}</div>
                <div style="font-size: 14px; color: #e0e0e0;">Calling contexts (k={k_cfa})</div>
                <div style="font-size: 12px; color: #b0b0b0; margin-top: 5px;">{context_label}</div>
            </div>
"""
    
    # Path-Sensitive
    html += f"""
            <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <h4 style="color: #ff6b6b; margin: 0 0 10px 0;">🛤️ Path-Sensitive</h4>
                <div style="font-size: 32px; font-weight: bold; margin: 10px 0;">{feasible_paths}/{branching_points}</div>
                <div style="font-size: 14px; color: #e0e0e0;">Feasible paths / branches</div>
                <div style="font-size: 12px; color: #b0b0b0; margin-top: 5px;">{path_label}</div>
            </div>
"""
    
    # Native Code
    html += f"""
            <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <h4 style="color: #4ecdc4; margin: 0 0 10px 0;">🔧 Native (JNI)</h4>
                <div style="font-size: 32px; font-weight: bold; margin: 10px 0;">{native_transfers}/{native_methods}</div>
                <div style="font-size: 14px; color: #e0e0e0;">Taint transfers / methods</div>
                <div style="font-size: 12px; color: #b0b0b0; margin-top: 5px;">{native_label}</div>
            </div>
"""
    
    # Interprocedural
    html += f"""
            <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <h4 style="color: #ffa500; margin: 0 0 10px 0;">🔗 Interprocedural</h4>
                <div style="font-size: 32px; font-weight: bold; margin: 10px 0;">{methods_with_tainted}/{methods_analyzed}</div>
                <div style="font-size: 14px; color: #e0e0e0;">Methods with taint / total</div>
                <div style="font-size: 12px; color: #b0b0b0; margin-top: 5px;">{inter_label}</div>
            </div>
"""
    
    html += """
        </div>
    </div>
"""
    
    # Detailed sections if data exists
    if implicit_vars:
        html += """
        <div class="section">
            <h3>⚡ Implicit Flow Details</h3>
            <p>Variables tainted via heuristic control-dependency signals:</p>
            <ul style="list-style: none; padding-left: 0;">
"""
        for var, deps in implicit_vars.items():
            html += f'                <li style="margin: 5px 0;"><code>{var}</code> ← controlled by <code>{", ".join(deps)}</code></li>\n'
        html += """
            </ul>
        </div>
"""
    
    path_details_available = bool(branching_details or feasible_details or infeasible_details)
    if path_details_available:
        source_link = f'<a href="{_escape_html(source_href)}">source</a>' if source_href else ""
        link_parts = [source_link, '<a href="#graph-gallery">graphs</a>']
        link_parts = [part for part in link_parts if part]
        link_html = " | ".join(link_parts)
        link_suffix = f' <span style="color: #b0b0b0;">({link_html})</span>' if link_html else ""

        html += """
        <div class="section">
            <h3>🛤️ Path-Sensitive Details</h3>
            <p>Branching lines are correlated with CFG/PDG nodes. Use the graph gallery to trace control-flow and reachability.</p>
        """
        if branching_details:
            html += """
            <h4 style="margin-top: 12px;">Branching points</h4>
            <ul style="list-style: none; padding-left: 0;">
            """
            for detail in branching_details:
                line = detail.get("line", "?")
                branch_type = _escape_html(detail.get("type", "branch"))
                condition = _escape_html(detail.get("condition", ""))
                html += f'                <li style="margin: 6px 0;"><code>L{line}</code> {branch_type} <code>{condition}</code>{link_suffix}</li>\n'
            html += """
            </ul>
            """
        if feasible_details:
            html += """
            <h4 style="margin-top: 12px;">Feasible paths</h4>
            <ul style="list-style: none; padding-left: 0;">
            """
            for detail in feasible_details:
                line = detail.get("line", "?")
                condition = _escape_html(detail.get("condition", ""))
                reason = _escape_html(detail.get("reason", "heuristic"))
                html += f'                <li style="margin: 6px 0;"><code>L{line}</code> <code>{condition}</code> <span style="color: #7f8c8d;">({reason})</span>{link_suffix}</li>\n'
            html += """
            </ul>
            """
        if infeasible_details:
            html += """
            <h4 style="margin-top: 12px;">Infeasible paths</h4>
            <ul style="list-style: none; padding-left: 0;">
            """
            for detail in infeasible_details:
                line = detail.get("line", "?")
                condition = _escape_html(detail.get("condition", ""))
                reason = _escape_html(detail.get("reason", "heuristic"))
                html += f'                <li style="margin: 6px 0;"><code>L{line}</code> <code>{condition}</code> <span style="color: #7f8c8d;">({reason})</span>{link_suffix}</li>\n'
            html += """
            </ul>
            """
        html += """
        </div>
        """
    
    if loaded_libs:
        html += f"""
        <div class="section">
            <h3>🔧 Native Libraries Loaded</h3>
            <ul>
                {"".join(f'<li><code>{lib}</code></li>' for lib in loaded_libs)}
            </ul>
        </div>
"""
    
    return html


def _generate_tainted_fields_section(tainted_fields: List[str]) -> str:
    """Generate Tainted Fields section"""
    if not tainted_fields:
        return ""
    
    fields_html = "".join([f"<li><code>{field}</code></li>" for field in tainted_fields])
    
    return f"""<div class="section">
        <div class="tainted-box">
            <h4>⚠️ Tainted Fields Detected</h4>
            <p>The following object fields contain untrusted data:</p>
            <ul class="tainted-list">
                {fields_html}
            </ul>
        </div>
    </div>"""


def _generate_sanitizer_analysis_section(sanitizer_analysis: Dict[str, Any]) -> str:
    """Generate sanitizer detection/validation section."""
    if not sanitizer_analysis:
        return ""

    effectiveness = sanitizer_analysis.get("effectiveness_by_sink", {}) if isinstance(sanitizer_analysis, dict) else {}
    by_sink = sanitizer_analysis.get("by_sink", {}) if isinstance(sanitizer_analysis, dict) else {}
    detected = sanitizer_analysis.get("detected", []) if isinstance(sanitizer_analysis, dict) else []

    rows = []
    for sink_name, score in effectiveness.items():
        details = by_sink.get(sink_name, {})
        recommendation = details.get("recommendation", "")
        has_required = details.get("has_required", False)
        status = "STRONG" if has_required else "WEAK"
        status_color = "#27ae60" if has_required else "#f39c12"
        rows.append(f"""
        <tr>
            <td><code>{sink_name}</code></td>
            <td>{score:.2f}</td>
            <td style="color:{status_color}; font-weight:600;">{status}</td>
            <td>{recommendation}</td>
        </tr>
        """)

    rows_html = "\n".join(rows) if rows else ""
    detected_html = ""
    if detected:
        sample = detected[:6]
        detected_html = "<ul>" + "".join(
            f"<li><code>{item.get('name')}</code> @ L{item.get('line')}</li>" for item in sample
        ) + "</ul>"

    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧼 Sanitizer Analysis</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Pattern-based sanitizer detection with sink-specific effectiveness scoring.
        </p>
        <div style="overflow-x: auto; margin-bottom: 16px;">
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <thead>
                    <tr style="background: #f5f7fa; text-align: left;">
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Sink</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Effectiveness</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Strength</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        {f"<div><strong>Detected Sanitizers (sample):</strong>{detected_html}</div>" if detected_html else ""}
    </div>"""


def _generate_framework_sink_section(framework_sinks: Dict[str, Any]) -> str:
    """Generate framework sink detection section."""
    if not framework_sinks:
        return ""

    matches = framework_sinks.get("matches", [])
    frameworks = framework_sinks.get("frameworks", [])
    unsafe_hits = framework_sinks.get("unsafe_hits_by_vuln", {})
    safe_hits = framework_sinks.get("safe_hits_by_vuln", {})
    autoescape_disabled = framework_sinks.get("autoescape_disabled", {})

    if not matches:
        return ""

    match_rows = []
    for match in matches[:10]:
        sink_name = match.get("sink_name", "unknown")
        framework = match.get("framework", "unknown")
        vuln_type = match.get("vuln_type", "unknown")
        line = match.get("line", 0)
        safe_variant = match.get("safe_variant")
        status = "SAFE" if safe_variant is True else ("UNSAFE" if safe_variant is False else "UNKNOWN")
        status_color = "#27ae60" if safe_variant is True else ("#e74c3c" if safe_variant is False else "#95a5a6")
        match_rows.append(f"""
        <tr>
            <td>{framework}</td>
            <td><code>{sink_name}</code></td>
            <td><code>{vuln_type}</code></td>
            <td>L{line}</td>
            <td style="color:{status_color}; font-weight:600;">{status}</td>
        </tr>
        """)

    summary_lines = []
    for vuln_type, count in unsafe_hits.items():
        summary_lines.append(f"<li><code>{vuln_type}</code>: unsafe={count}, safe={safe_hits.get(vuln_type, 0)}</li>")
    summary_html = "<ul>" + "".join(summary_lines) + "</ul>" if summary_lines else ""

    autoescape_lines = []
    for vuln_type, count in autoescape_disabled.items():
        autoescape_lines.append(f"<li><code>{vuln_type}</code>: autoescape disabled ({count})</li>")
    autoescape_html = "<ul>" + "".join(autoescape_lines) + "</ul>" if autoescape_lines else ""

    frameworks_text = ", ".join(frameworks) if frameworks else "Unknown"

    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🏢 Framework Sink Detection</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Detected framework-specific sinks for enterprise Java stacks. Frameworks: {frameworks_text}
        </p>
        {summary_html}
        {autoescape_html}
        <div style="overflow-x: auto; margin-top: 16px;">
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <thead>
                    <tr style="background: #f5f7fa; text-align: left;">
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Framework</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Sink</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Vuln Type</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Line</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Safety</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(match_rows)}
                </tbody>
            </table>
        </div>
    </div>"""


def _generate_template_engine_section(template_engine_analysis: Dict[str, Any]) -> str:
    """Generate template engine auto-escaping analysis section."""
    if not template_engine_analysis:
        return ""

    engines = template_engine_analysis.get("engines", [])
    configs = template_engine_analysis.get("configs", [])
    autoescape = template_engine_analysis.get("autoescape", {})
    unsafe_variants = template_engine_analysis.get("unsafe_variants", [])
    safety_scores = template_engine_analysis.get("safety_scores", {})

    if not engines:
        return ""

    rows = []
    for config in configs:
        engine = config.get("engine", "unknown")
        mode = config.get("auto_escape", "unknown")
        confidence = config.get("confidence", 0.0)
        score = safety_scores.get(engine, 0.0)
        status_color = "#27ae60" if mode == "enabled" else ("#f39c12" if mode == "selective" else "#e74c3c")
        rows.append(f"""
        <tr>
            <td><code>{engine}</code></td>
            <td style="color:{status_color}; font-weight:600;">{mode}</td>
            <td>{score:.2f}</td>
            <td>{confidence:.2f}</td>
        </tr>
        """)

    unsafe_preview = ""
    if unsafe_variants:
        unsafe_preview = "<ul>" + "".join(
            f"<li><code>{item.get('engine')}</code> @ L{item.get('line')} — {item.get('snippet')}</li>"
            for item in unsafe_variants[:5]
        ) + "</ul>"

    autoescape_summary = ""
    if isinstance(autoescape, dict):
        autoescape_summary = (
            f"<p><strong>Auto-escape enabled:</strong> {', '.join(autoescape.get('enabled', [])) or 'none'}</p>"
            f"<p><strong>Auto-escape disabled:</strong> {', '.join(autoescape.get('disabled', [])) or 'none'}</p>"
            f"<p><strong>Auto-escape selective:</strong> {', '.join(autoescape.get('selective', [])) or 'none'}</p>"
        )

    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧩 Template Engine Analysis</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Auto-escaping and safe/unsafe variant detection for Java template engines.
        </p>
        {autoescape_summary}
        <div style="overflow-x: auto; margin-top: 16px;">
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <thead>
                    <tr style="background: #f5f7fa; text-align: left;">
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Engine</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Auto-escape</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Safety Score</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        {f"<div><strong>Unsafe variants (sample):</strong>{unsafe_preview}</div>" if unsafe_preview else ""}
    </div>"""
def _generate_triage_checklist() -> str:
    """Generate Triage Checklist section"""
    return """<div class="section">
        <div class="triage-checklist">
            <h3>📋 Triage Checklist</h3>
            <ol>
                <li>Open <em>graph</em> (PNG)</li>
                <li>Confirm sink (badges/tags) - Check if detected vulnerabilities match known security sinks</li>
                <li>Read <em>paths</em> (DFG evidence)</li>
                <li>Jump to <em>method:line</em> in source</li>
                <li>Decide: exploitability, patch, or deeper analysis</li>
            </ol>
        </div>
    </div>"""


def _generate_taint_graph_section(taint_graph: Dict[str, Any]) -> str:
    if not taint_graph or not taint_graph.get("path"):
        return ""
    path = taint_graph.get("path")
    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🕸️ Taint Flow Graph</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Interactive taint flow visualization generated from heuristic taint flows.
        </p>
        <p><a href="{path}">Open taint flow graph</a></p>
    </div>"""


def _generate_soundness_section(soundness_validation: Dict[str, Any]) -> str:
    if not soundness_validation or not soundness_validation.get("report_path"):
        return ""
    status = "✅ Completed" if soundness_validation.get("success") else "⚠️ Failed"
    report_path = soundness_validation.get("report_path")
    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧪 Tai-e Soundness Validation</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Runtime value logging compared against Tai-e points-to results (class-level mapping).
        </p>
        <p><strong>Status:</strong> {status}</p>
        <p><a href="{report_path}">Open soundness report</a></p>
    </div>"""


def _generate_badges_section(result: Dict[str, Any]) -> str:
    """Generate Understanding Badges & Tags section"""
    spatial = result.get("spatial_gnn", {}) if isinstance(result.get("spatial_gnn", {}), dict) else {}
    gnn_weighted = bool(spatial.get("used_in_scoring", False))
    gnn_forward = bool(result.get("gnn_utilized") or spatial.get("forward_called"))
    analysis_method = str(result.get("analysis_method", "")).lower()
    fusion = result.get("confidence_fusion", {}) if isinstance(result.get("confidence_fusion", {}), dict) else {}
    fusion_source = str(fusion.get("source", "") or "").strip()
    analysis_config = result.get("analysis_config", {}) if isinstance(result.get("analysis_config", {}), dict) else {}
    sink_preset = analysis_config.get("sink_signature_preset") or result.get("sink_signature_preset")
    if sink_preset:
        preset_note = (
            f"Sink signature preset requested: <code>{_escape_html(sink_preset)}</code>. "
            "This build records the request; preset integration is pending."
        )
    else:
        preset_note = "Sink signature preset not requested; default sink registry is used."

    if fusion_source:
        if fusion_source == "heuristic_only":
            vuln_desc = "The analysis identified a security issue with a confidence score (heuristics dominated; GNN did not increase confidence)"
        elif fusion_source == "heuristic_only_ood":
            vuln_desc = "The analysis identified a security issue with a confidence score (CESCL flagged OOD; heuristics used as a safety fallback)"
        elif fusion_source in {"gnn_boost", "gnn_calibrated", "gnn_only"}:
            vuln_desc = f"The analysis identified a security issue with a confidence score (asymmetric fusion: {fusion_source})"
        else:
            vuln_desc = f"The analysis identified a security issue with a confidence score (fusion: {fusion_source})"
    elif gnn_weighted:
        vuln_desc = "The analysis (GNN-weighted) identified a security issue with a confidence score"
    elif gnn_forward:
        vuln_desc = "The analysis identified a security issue (GNN inference executed but untrained)"
    elif "heuristic" in analysis_method:
        vuln_desc = "The heuristic analysis identified a security issue with a confidence score"
    else:
        vuln_desc = "The analysis identified a security issue with a confidence score"

    return f"""<div class="section">
        <div class="badges-section">
            <h3>🏷️ Understanding Badges & Tags</h3>
            
            <h4 style="margin-top: 20px;">💡 What the Badges Mean:</h4>
            <ul style="list-style: none; padding: 0;">
                <li style="margin: 10px 0;"><span class="badge badge-vuln">VULN</span> <strong>- Vulnerability Detected</strong>: {vuln_desc}</li>
                <li style="margin: 10px 0;"><span class="badge badge-dfg-paths">DFG PATHS</span> <strong>- Taint Flow Paths</strong>: Text file showing taint flow evidence to sinks</li>
                <li style="margin: 10px 0;"><span class="badge badge-dfg-dot">DFG DOT</span> <strong>- Graph Description</strong>: DOT format graph for Graphviz visualization</li>
                <li style="margin: 10px 0;"><span class="badge badge-dfg-png">DFG PNG</span> <strong>- Visual Graph</strong>: Rendered image showing the data flow graph</li>
            </ul>
            
            <h4 style="margin-top: 30px;">🎯 What "Confirm Sink" Means:</h4>
            <p style="margin-bottom: 15px;"><strong>Security sinks</strong> are dangerous functions where untrusted data should not flow. When you see a vulnerability badge, check if it corresponds to a real security sink:</p>
            <ul class="sink-list">
                <li><code>Runtime.exec()</code>, <code>ProcessBuilder</code> → Command Injection</li>
                <li><code>Statement.execute()</code> → SQL Injection</li>
                <li><code>ObjectInputStream.readObject()</code> → Deserialization</li>
                <li><code>URL.openConnection()</code> → SSRF/HTTP attacks</li>
                <li><code>Files.write()</code>, <code>FileOutputStream</code> → Path Traversal</li>
                <li><code>Class.forName()</code>, <code>Method.invoke()</code> → Reflection Injection</li>
            </ul>
            <p style="margin-top: 15px;">The <strong>method:line</strong> links show exactly where these sinks are called in your code.</p>
            
            <h4 style="margin-top: 30px;">🔍 Sink Signature Presets:</h4>
            <div class="graudit-info">
                <p>{preset_note}</p>
            </div>
        </div>
    </div>"""


def _generate_findings_section(result: Dict[str, Any]) -> str:
    """Generate Findings section"""
    vuln_status = "🚨 VULNERABLE" if result.get('vulnerability_detected') else "✅ SAFE"
    vuln_class = "vulnerable" if result.get('vulnerability_detected') else "safe"
    confidence = result.get('confidence', 0.0)
    vuln_type = result.get('vulnerability_type', 'None')
    vuln_list = result.get('vulnerabilities_found', []) or []
    if not isinstance(vuln_list, list):
        vuln_list = []
    detected_badges = ""
    if vuln_list:
        badge_items = "".join(
            f"<span class=\"badge badge-info\" style=\"margin-right: 6px;\">{_escape_html(v)}</span>"
            for v in vuln_list
        )
        detected_badges = f"""
        <div style="margin-top: 16px;">
            <div class="metric-label">All detected types</div>
            <div>{badge_items}</div>
        </div>
        """

    joern_dataflow = result.get("joern_dataflow") or result.get("taint_tracking", {}).get("joern_dataflow")
    flows_by_sink = joern_dataflow.get("flows_by_sink", {}) if isinstance(joern_dataflow, dict) else {}
    total_flows = 0
    if isinstance(flows_by_sink, dict):
        for payload in flows_by_sink.values():
            if isinstance(payload, dict):
                total_flows += int(payload.get("flows", 0) or 0)
    joern_flow_display = str(total_flows) if flows_by_sink else "n/a"
    joern_flow_note = "reachableByFlows total" if flows_by_sink else "enable --joern-dataflow"

    advanced_taint = result.get("advanced_taint", {})
    if not isinstance(advanced_taint, dict):
        advanced_taint = {}
    taint_tracking = result.get("taint_tracking", {})
    if not isinstance(taint_tracking, dict):
        taint_tracking = {}

    implicit_summary = advanced_taint.get("implicit_flows", {})
    path_summary = advanced_taint.get("path_sensitive", {})
    native_summary = advanced_taint.get("native_jni", {})
    advanced_available = bool(advanced_taint)
    if not advanced_available:
        implicit_summary = taint_tracking.get("implicit_flows", {})
        path_summary = taint_tracking.get("path_sensitive_analysis", {})
        native_summary = taint_tracking.get("native_code_analysis", {})
        advanced_available = any(
            isinstance(payload, dict) and payload
            for payload in (implicit_summary, path_summary, native_summary)
        )

    implicit_count = int(implicit_summary.get("count", 0) or 0) if isinstance(implicit_summary, dict) else 0
    feasible_paths = int(path_summary.get("feasible_paths", 0) or 0) if isinstance(path_summary, dict) else 0
    jni_methods = int(native_summary.get("jni_methods", 0) or 0) if isinstance(native_summary, dict) else 0
    jni_transfers = int(native_summary.get("taint_transfers", 0) or 0) if isinstance(native_summary, dict) else 0

    implicit_value = str(implicit_count) if advanced_available else "n/a"
    path_value = str(feasible_paths) if advanced_available else "n/a"
    jni_value = str(jni_transfers) if advanced_available else "n/a"
    implicit_note = "count" if advanced_available else "enable --implicit-flows"
    path_note = "feasible paths" if advanced_available else "enable --path-sensitive"
    jni_note = f"methods: {jni_methods}" if advanced_available else "enable --native-jni"

    # --- Confidence / calibration breakdown (GNN + CESCL + fusion) ---
    heuristic_conf = result.get("heuristic_confidence")
    gnn_conf = result.get("gnn_confidence")
    gnn_conf_logit = result.get("gnn_confidence_logit_only")
    combined_logit_only = result.get("confidence_logit_only")

    fusion = result.get("confidence_fusion", {}) if isinstance(result.get("confidence_fusion", {}), dict) else {}
    fusion_source = fusion.get("source")
    fusion_ood = fusion.get("ood_detected")

    cescl_available = bool(result.get("cescl_available", False))
    cescl_ood_score = result.get("cescl_ood_score")
    cescl_is_ood = result.get("cescl_is_ood")
    cescl_cal = result.get("cescl_calibrated_confidence")

    def _fmt(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            try:
                return f"{float(v):.4f}"
            except Exception:
                return _escape_html(v)
        if v is None:
            return "n/a"
        return _escape_html(v)

    confidence_breakdown = f"""
        <details class="performance-box" style="margin-top: 18px;">
            <summary style="cursor: pointer; color: #3498db; font-weight: 600;">Confidence breakdown (heuristic / GNN / CESCL / fusion)</summary>
            <div style="margin-top: 12px;">
                <table class="sink-table" style="width: 100%;">
                    <tr><th style="text-align:left;">Signal</th><th style="text-align:left;">Value</th><th style="text-align:left;">Notes</th></tr>
                    <tr><td>Final confidence (combined)</td><td>{_fmt(confidence)}</td><td>Used for thresholding / report verdict</td></tr>
                    <tr><td>Final confidence (logit-only)</td><td>{_fmt(combined_logit_only)}</td><td>Combined before CESCL prototype blending</td></tr>
                    <tr><td>Heuristic confidence</td><td>{_fmt(heuristic_conf)}</td><td>Pattern + taint evidence baseline</td></tr>
                    <tr><td>GNN confidence (final)</td><td>{_fmt(gnn_conf)}</td><td>May include CESCL blended probs when available</td></tr>
                    <tr><td>GNN confidence (logit-only)</td><td>{_fmt(gnn_conf_logit)}</td><td>Softmax(binary_logits / temperature)</td></tr>
                    <tr><td>Fusion source</td><td>{_fmt(fusion_source)}</td><td>Asymmetric policy: boost allowed, suppression forbidden</td></tr>
                    <tr><td>Fusion OOD detected</td><td>{_fmt(fusion_ood)}</td><td>Uses CESCL OOD if prototypes + embedding available</td></tr>
                    <tr><td>CESCL available</td><td>{_fmt(cescl_available)}</td><td>Loaded from checkpoint prototypes</td></tr>
                    <tr><td>CESCL OOD score</td><td>{_fmt(cescl_ood_score)}</td><td>Higher means further from all prototypes</td></tr>
                    <tr><td>CESCL is OOD</td><td>{_fmt(cescl_is_ood)}</td><td>OOD gate used to avoid unsafe GNN reliance</td></tr>
                    <tr><td>CESCL calibrated confidence</td><td>{_fmt(cescl_cal)}</td><td>Geometry-based confidence from prototype distance</td></tr>
                </table>
            </div>
        </details>
    """
    
    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">📊 Findings</h3>
        <div class="metrics-grid" style="grid-template-columns: repeat(4, 1fr);">
            <div class="metric-card">
                <div class="metric-label">Vulnerability Status</div>
                <div class="metric-value" style="color: {'#e74c3c' if vuln_class == 'vulnerable' else '#27ae60'};">{vuln_status}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Confidence</div>
                <div class="metric-value">{confidence:.1%}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Vulnerability Type</div>
                <div class="metric-value" style="font-size: 18px;">{vuln_type}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Joern Flows</div>
                <div class="metric-value">{joern_flow_display}</div>
                <div class="metric-description">{joern_flow_note}</div>
            </div>
        </div>
        <div style="margin-top: 16px;">
            <div class="metric-label" style="margin-bottom: 8px;">Advanced Taint Summary</div>
            <div class="metrics-grid" style="grid-template-columns: repeat(3, 1fr);">
                <div class="metric-card">
                    <div class="metric-label">Implicit Flows</div>
                    <div class="metric-value">{implicit_value}</div>
                    <div class="metric-description">{implicit_note}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Path Feasible</div>
                    <div class="metric-value">{path_value}</div>
                    <div class="metric-description">{path_note}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">JNI Transfers</div>
                    <div class="metric-value">{jni_value}</div>
                    <div class="metric-description">{jni_note}</div>
                </div>
            </div>
        </div>
        {detected_badges}
        {confidence_breakdown}
    </div>"""


def _generate_aeg_lite_section(result: Dict[str, Any]) -> str:
    """Render AEG-Lite Java PoC/Patch payloads when available."""
    aeg = result.get("aeg_lite_java")
    if not isinstance(aeg, dict):
        return ""

    if not aeg.get("success", False):
        error_text = _escape_html(aeg.get("error", "AEG-Lite Java analysis failed."))
        return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧪 AEG-Lite Java (PoCs & Patches)</h3>
        <div class="aeg-card">
            <div class="aeg-meta">Status: failed</div>
            <p style="color: #c0392b;">{error_text}</p>
        </div>
    </div>"""

    report = aeg.get("report", {})
    if not isinstance(report, dict):
        return ""

    classes_analyzed = report.get("classes_analyzed", 0)
    vuln_count = report.get("vulnerability_count", len(report.get("vulnerabilities", []) or []))
    poc_count = report.get("poc_count", 0)
    patch_count = report.get("patch_count", 0)
    analysis_method = _escape_html(aeg.get("analysis_method", "asm_bytecode"))

    pocs = report.get("pocs") or []
    patches = report.get("patches") or []

    poc_blocks = ""
    if pocs:
        for poc in pocs:
            poc_id = _escape_html(poc.get("id", "unknown"))
            vuln_id = _escape_html(poc.get("vulnerability_id", ""))
            poc_type = _escape_html(poc.get("type", "unknown"))
            status = _escape_html(poc.get("status", "UNKNOWN"))
            layer1 = poc.get("layer1")
            layer2 = poc.get("layer2")
            layer3 = poc.get("layer3")
            code = poc.get("code") or poc.get("poc_code") or poc.get("code_preview")
            layer_meta = f"layers: {layer1}/{layer2}/{layer3}" if layer1 is not None else ""
            poc_blocks += f"""
            <details class="aeg-details aeg-card">
                <summary>PoC <code>{poc_id}</code> — {poc_type} ({status})</summary>
                <div class="aeg-meta">{layer_meta} {f"· vuln {vuln_id}" if vuln_id else ""}</div>
                {_render_code_block(code)}
            </details>
            """
    else:
        poc_blocks = "<div class=\"aeg-card\"><em>No PoC payloads available.</em></div>"

    patch_blocks = ""
    if patches:
        for patch in patches:
            vuln_id = _escape_html(patch.get("vulnerability_id", "unknown"))
            patch_type = _escape_html(patch.get("type", "unknown"))
            template_id = _escape_html(patch.get("template_id", ""))
            status = _escape_html(patch.get("status", "UNKNOWN"))
            layer1 = patch.get("layer1")
            layer2 = patch.get("layer2")
            layer3 = patch.get("layer3")
            vulnerable_code = patch.get("vulnerable_code") or patch.get("vulnerable_preview")
            patched_code = patch.get("patched_code") or patch.get("patched_preview")
            layer_meta = f"layers: {layer1}/{layer2}/{layer3}" if layer1 is not None else ""
            patch_blocks += f"""
            <details class="aeg-details aeg-card">
                <summary>Patch <code>{vuln_id}</code> — {patch_type} ({status})</summary>
                <div class="aeg-meta">{layer_meta} {f"· template {template_id}" if template_id else ""}</div>
                <div style="margin-bottom: 10px;"><strong>Vulnerable code</strong></div>
                {_render_code_block(vulnerable_code)}
                <div style="margin-top: 10px; margin-bottom: 10px;"><strong>Patched code</strong></div>
                {_render_code_block(patched_code)}
            </details>
            """
    else:
        patch_blocks = "<div class=\"aeg-card\"><em>No patch payloads available.</em></div>"

    enhanced = report.get("enhanced", {})
    enhanced_section = ""
    if isinstance(enhanced, dict) and (
        enhanced.get("patches") or enhanced.get("ensemble") or enhanced.get("method_counts")
    ):
        enhanced_patches = enhanced.get("patches") or []
        enhanced_ensemble = enhanced.get("ensemble") or []
        method_counts = enhanced.get("method_counts") or {}
        enhanced_patch_count = enhanced.get("patch_count", len(enhanced_patches))
        enhanced_patch_success = enhanced.get("patch_success_count", 0)

        method_badges = ""
        if isinstance(method_counts, dict):
            for method, count in method_counts.items():
                method_badges += f"<span class=\"aeg-badge\">{_escape_html(str(method))}: {count}</span>"

        enhanced_patch_blocks = ""
        if enhanced_patches:
            for patch in enhanced_patches:
                cwe = _escape_html(patch.get("cwe", "unknown"))
                patch_type = _escape_html(patch.get("type", "unknown"))
                status = "PASS" if patch.get("success", False) else "FAIL"
                line = patch.get("line")
                message = _escape_html(patch.get("message", ""))
                patched_code = patch.get("patched_code")
                meta = []
                if line:
                    meta.append(f"line {line}")
                if message:
                    meta.append(message)
                meta_text = " · ".join(meta)
                enhanced_patch_blocks += f"""
                <details class="aeg-details aeg-card">
                    <summary>Enhanced Patch <code>{cwe}</code> — {patch_type} ({status})</summary>
                    <div class="aeg-meta">{meta_text}</div>
                    <div style="margin-top: 10px; margin-bottom: 10px;"><strong>Patched code</strong></div>
                    {_render_code_block(patched_code)}
                </details>
                """
        else:
            enhanced_patch_blocks = "<div class=\"aeg-card\"><em>No enhanced patches available.</em></div>"

        enhanced_findings = ""
        if enhanced_ensemble:
            rows = []
            for finding in enhanced_ensemble:
                cwe = _escape_html(finding.get("cwe", ""))
                ftype = _escape_html(finding.get("type", ""))
                confidence = finding.get("confidence")
                confidence_text = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "n/a"
                evidence = _escape_html(finding.get("evidence", ""))
                rows.append(f"<li><strong>{cwe}</strong> {ftype} — {confidence_text} · {evidence}</li>")
            enhanced_findings = "<ul>" + "\n".join(rows) + "</ul>"
        else:
            enhanced_findings = "<em>No enhanced findings available.</em>"

        enhanced_section = f"""
        <div style="margin-top: 24px;">
            <h4 style="margin-bottom: 8px;">Enhanced Source Scan (AST + Semantic + Taint)</h4>
            <div class="aeg-summary">
                {method_badges}
                <span class="aeg-badge">enhanced patches: {enhanced_patch_count}</span>
                <span class="aeg-badge">enhanced patch success: {enhanced_patch_success}</span>
            </div>
            <div style="margin-top: 12px;">
                <h5 style="margin-bottom: 6px;">Enhanced findings</h5>
                {enhanced_findings}
            </div>
            <div style="margin-top: 16px;">
                <h5 style="margin-bottom: 6px;">Enhanced patches</h5>
                {enhanced_patch_blocks}
            </div>
        </div>
        """

    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧪 AEG-Lite Java (PoCs & Patches)</h3>
        <div class="aeg-summary">
            <span class="aeg-badge">method: {analysis_method}</span>
            <span class="aeg-badge">classes: {classes_analyzed}</span>
            <span class="aeg-badge">vulns: {vuln_count}</span>
            <span class="aeg-badge">pocs: {poc_count}</span>
            <span class="aeg-badge">patches: {patch_count}</span>
        </div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">PoC payloads</h4>
            {poc_blocks}
        </div>
        <div style="margin-top: 20px;">
            <h4 style="margin-bottom: 8px;">Patch payloads</h4>
            {patch_blocks}
        </div>
        {enhanced_section}
    </div>"""


def _generate_sink_gating_section(result: Dict[str, Any]) -> str:
    """Generate sink-specific gating section."""
    gating = result.get("taint_gating", {})
    decisions = gating.get("decisions", [])
    if not decisions:
        return ""

    rows = []
    for decision in decisions:
        vuln = decision.get("vulnerability", "unknown")
        passed = decision.get("passed", False)
        confidence = decision.get("confidence", 0.0) or 0.0
        threshold = decision.get("threshold")
        evidence_types = decision.get("evidence_types", [])
        flow_type = decision.get("flow_type", "unknown")

        status = "ALLOW (KEEP)" if passed else "BLOCK (DROP)"
        status_color = "#27ae60" if passed else "#e74c3c"
        evidence_text = ", ".join(evidence_types) if evidence_types else "none"
        threshold_text = f"{threshold:.2f}" if isinstance(threshold, (int, float)) else "-"

        breakdown_html = ""
        details = decision.get("details") if isinstance(decision.get("details"), dict) else {}
        breakdown = details.get("evidence_breakdown", []) if isinstance(details.get("evidence_breakdown"), list) else []
        if breakdown:
            breakdown_items = []
            for entry in breakdown:
                ev_type = _escape_html(entry.get("type", ""))
                description = _escape_html(entry.get("description", ""))
                confidence = entry.get("confidence")
                weight = entry.get("weight")
                weight_source = entry.get("weight_source", "")
                line = entry.get("line")
                context = _escape_html(entry.get("context", ""))
                parts = [ev_type] if ev_type else []
                if isinstance(weight, (int, float)):
                    weight_text = f"w={weight:.2f}"
                    if weight_source:
                        weight_text += f" ({_escape_html(weight_source)})"
                    parts.append(weight_text)
                if isinstance(confidence, (int, float)):
                    parts.append(f"c={confidence:.2f}")
                if isinstance(line, int) and line > 0:
                    parts.append(f"line {line}")
                summary = " · ".join(parts)
                if description:
                    summary = f"{summary} — {description}" if summary else description
                if context:
                    summary += f" <span style=\"color: #7f8c8d;\">{context}</span>"
                breakdown_items.append(f"<li style=\"margin: 4px 0;\">{summary}</li>")
            breakdown_html = """
            <details style="margin-top: 6px;">
                <summary style="cursor: pointer; color: #3498db;">Evidence breakdown (weights + confidence)</summary>
                <ul style="margin: 8px 0 0 16px; padding: 0;">
                    {items}
                </ul>
            </details>
            """.format(items="".join(breakdown_items))

        rows.append(f"""
        <tr>
            <td><code>{vuln}</code></td>
            <td>{flow_type}</td>
            <td>{confidence:.2f}</td>
            <td>{threshold_text}</td>
            <td style="color:{status_color}; font-weight:600;">{status}</td>
            <td style="max-width: 420px; word-wrap: break-word;">{evidence_text}{breakdown_html}</td>
        </tr>
        """)

    rows_html = "\n".join(rows)
    return f"""<div class="section">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧪 Sink-Specific Gating</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Evidence-based gating per sink (taint flow + sanitizer checks). Decision indicates
            whether the vulnerability is kept or dropped after gating.
        </p>
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <thead>
                    <tr style="background: #f5f7fa; text-align: left;">
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Sink</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Flow</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Confidence</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Threshold</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Decision</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>"""

def _generate_file_links_section(result: Dict[str, Any], report_dir: Path) -> str:
    """Generate file links row (VULN status | filename | confidence | paths | CFG | DFG | source)"""
    input_file = result.get('input', '')
    if not input_file:
        return ""
    
    input_path = Path(input_file).expanduser()
    filename = input_path.name
    
    # Vulnerability status badge
    is_vulnerable = result.get('vulnerability_detected', False)
    vuln_badge = '<span style="background: #e74c3c; color: white; padding: 6px 12px; border-radius: 4px; font-weight: bold; font-size: 14px;">VULN</span>' if is_vulnerable else '<span style="background: #27ae60; color: white; padding: 6px 12px; border-radius: 4px; font-weight: bold; font-size: 14px;">SAFE</span>'
    
    # Confidence score
    confidence = result.get('confidence', 0.0)
    
    # Check for available artifacts
    links = []
    
    # DFG Paths link
    dfg_paths = report_dir / 'dfg_paths.txt'
    if dfg_paths.exists():
        links.append('<a href="dfg_paths.txt" style="color: #3498db; text-decoration: none; font-weight: 500;">paths</a>')
    
    # CFG link
    cfg_files = list(report_dir.glob('cfg_slice*.png'))
    if cfg_files:
        links.append('<a href="#graph-gallery" style="color: #3498db; text-decoration: none; font-weight: 500;">CFG</a>')
    
    # DFG link
    dfg_files = list(report_dir.glob('dfg_slice*.png'))
    if dfg_files:
        links.append('<a href="#graph-gallery" style="color: #3498db; text-decoration: none; font-weight: 500;">DFG</a>')
    
    # Source link (file should be copied to report directory)
    source_href = None
    source_file = report_dir / filename
    if source_file.exists() and source_file.suffix == '.java':
        source_href = filename
    elif input_path.exists() and input_path.suffix == '.java':
        try:
            source_href = input_path.resolve().as_uri()
        except Exception:
            source_href = None
    if source_href:
        links.append(f'<a href="{_escape_html(source_href)}" style="color: #3498db; text-decoration: none; font-weight: 500;">source</a>')
    else:
        links.append('<span style="color: #95a5a6; font-style: italic;">source</span>')
    
    links_html = ' | '.join(links) if links else ''
    
    return f"""<div class="section">
        <div style="background: #ffffff; padding: 15px 20px; border-radius: 8px; border: 1px solid #e0e0e0; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 20px;">
                <div style="display: flex; align-items: center; gap: 20px;">
                    <div>{vuln_badge}</div>
                    <div>
                        <strong style="color: #2c3e50; font-size: 16px; display: block;">{filename}</strong>
                        <span style="color: #7f8c8d; font-size: 13px;">Confidence: {confidence:.3f}</span>
                    </div>
                </div>
                <div style="font-size: 15px; color: #3498db;">
                    {links_html}
                </div>
            </div>
        </div>
    </div>"""


def _generate_cf_explainer_section(cf_explanation: Dict[str, Any]) -> str:
    """
    Generate CF-Explainer (Counterfactual Explanation) section with remediation guidance
    """
    if not cf_explanation:
        return ""
    
    recommendations = cf_explanation.get('practical_recommendations', [])
    guidance = cf_explanation.get('developer_guidance', '')
    cf_preview = ''
    
    # Get counterfactual code preview if available
    if 'counterfactual_explanation' in cf_explanation:
        cf_data = cf_explanation['counterfactual_explanation']
        cf_preview = cf_data.get('counterfactual_preview', '')
    
    # Enhanced metadata if available
    enhanced_meta = cf_explanation.get('enhanced_metadata', {})
    vuln_patterns = enhanced_meta.get('vulnerability_patterns', [])
    
    # Build recommendations HTML
    recs_html = ""
    if recommendations and len(recommendations) > 0:
        recs_items = []
        for i, rec in enumerate(recommendations, 1):
            # Color code based on content
            if '✅' in rec or 'Use' in rec or 'Replace' in rec:
                badge_class = 'badge-success'
                icon = '✅'
            elif '📚' in rec or 'Reference' in rec:
                badge_class = 'badge-info'
                icon = '📚'
            elif '🔒' in rec or 'Secure' in rec:
                badge_class = 'badge-warning'
                icon = '🔒'
            else:
                badge_class = 'badge-default'
                icon = '💡'
            
            # Clean up the recommendation text
            clean_rec = rec.replace('✅', '').replace('📚', '').replace('🔒', '').strip()
            
            recs_items.append(f"""
            <div class="recommendation-item">
                <span class="badge {badge_class}">{icon} {i}</span>
                <div class="recommendation-text">{clean_rec}</div>
            </div>
            """)
        
        recs_html = f"""
        <div class="cf-recommendations">
            <h3 style="color: #2c3e50; margin-bottom: 15px; display: flex; align-items: center;">
                <span style="font-size: 1.3em; margin-right: 10px;">📋</span>
                Security Remediation Recommendations
            </h3>
            <div class="recommendations-list">
                {''.join(recs_items)}
            </div>
        </div>
        """
    else:
        # Show message when no recommendations available
        cf_data = cf_explanation.get('counterfactual_explanation', {})
        summary = cf_data.get('minimal_change_summary', 'Analyzing vulnerability patterns...')
        recs_html = f"""
        <div class="cf-recommendations">
            <h3 style="color: #2c3e50; margin-bottom: 15px; display: flex; align-items: center;">
                <span style="font-size: 1.3em; margin-right: 10px;">🔍</span>
                Counterfactual Analysis Status
            </h3>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db;">
                <p style="margin: 0; color: #2c3e50;">{summary}</p>
                <p style="margin: 10px 0 0 0; color: #7f8c8d; font-size: 0.9em;">
                    💡 The CF-Explainer is analyzing the vulnerability to generate specific remediation recommendations.
                </p>
            </div>
        </div>
        """
    
    # Build guidance HTML
    guidance_html = ""
    if guidance:
        # Handle guidance as either string or dict
        if isinstance(guidance, dict):
            guidance_text = guidance.get('summary', '') or str(guidance)
        else:
            guidance_text = str(guidance) if guidance else ''
        
        # Split guidance into paragraphs if it contains newlines
        guidance_parts = guidance_text.split('\n\n') if '\n\n' in guidance_text else [guidance_text]
        
        guidance_items = []
        for part in guidance_parts:
            if part.strip():
                # Highlight confidence percentages and line numbers
                highlighted = part
                # Highlight "line X" references
                highlighted = highlighted.replace('line ', '<strong style="color: #e74c3c;">line </strong>')
                # Highlight confidence percentages
                import re
                highlighted = re.sub(r'(\d+\.\d+%)', r'<strong style="color: #27ae60;">\1</strong>', highlighted)
                
                guidance_items.append(f'<p style="margin: 10px 0; line-height: 1.6;">{highlighted}</p>')
        
        guidance_html = f"""
        <div class="cf-guidance" style="margin-top: 25px;">
            <h3 style="color: #2c3e50; margin-bottom: 15px; display: flex; align-items: center;">
                <span style="font-size: 1.3em; margin-right: 10px;">🔧</span>
                Developer Guidance
            </h3>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db;">
                {''.join(guidance_items)}
            </div>
        </div>
        """
    
    # Build counterfactual code preview HTML
    cf_code_html = ""
    if cf_preview:
        # Limit preview length
        preview_text = cf_preview[:1000] + "..." if len(cf_preview) > 1000 else cf_preview
        
        cf_code_html = f"""
        <div class="cf-code-preview" style="margin-top: 25px;">
            <h3 style="color: #2c3e50; margin-bottom: 15px; display: flex; align-items: center;">
                <span style="font-size: 1.3em; margin-right: 10px;">🔍</span>
                Secure Code Example
            </h3>
            <div style="background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 8px; overflow-x: auto;">
                <pre style="margin: 0; font-family: 'Monaco', 'Menlo', 'Courier New', monospace; font-size: 13px; line-height: 1.5;"><code>{preview_text}</code></pre>
            </div>
            <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px; font-style: italic;">
                ℹ️ This is an automated counterfactual code example showing recommended security fixes.
            </p>
        </div>
        """
    
    # Build vulnerability patterns summary if available
    vuln_summary_html = ""
    if vuln_patterns:
        pattern_items = []
        for vuln in vuln_patterns[:5]:  # Show top 5
            cwe_id = vuln.get('cwe_id', 'Unknown')
            description = vuln.get('description', 'Security issue')
            line = vuln.get('line', 0)
            confidence = vuln.get('confidence', 0.0)
            severity = vuln.get('severity', 'MEDIUM')
            
            severity_colors = {
                'HIGH': '#e74c3c',
                'CRITICAL': '#c0392b',
                'MEDIUM': '#f39c12',
                'LOW': '#95a5a6'
            }
            severity_color = severity_colors.get(severity, '#95a5a6')
            
            pattern_items.append(f"""
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #fff; border-radius: 6px; margin-bottom: 10px; border-left: 4px solid {severity_color};">
                <div>
                    <strong style="color: #2c3e50;">{cwe_id}</strong>: {description}
                    <br>
                    <small style="color: #7f8c8d;">Line {line} | Confidence: {confidence*100:.1f}%</small>
                </div>
                <span class="badge" style="background: {severity_color}; color: white; padding: 5px 12px; border-radius: 12px; font-size: 0.85em;">{severity}</span>
            </div>
            """)
        
        vuln_summary_html = f"""
        <div class="vuln-patterns-summary" style="margin-top: 25px;">
            <h3 style="color: #2c3e50; margin-bottom: 15px; display: flex; align-items: center;">
                <span style="font-size: 1.3em; margin-right: 10px;">🎯</span>
                Detected Vulnerability Patterns
            </h3>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                {''.join(pattern_items)}
            </div>
        </div>
        """
    
    return f"""
    <div class="section" id="cf-explainer" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px; margin: 30px 0; box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);">
        <div style="background: white; padding: 30px; border-radius: 10px;">
            <h2 class="section-title" style="color: #2c3e50; margin-bottom: 20px; display: flex; align-items: center;">
                <span style="font-size: 1.5em; margin-right: 15px;">💡</span>
                Counterfactual Explanation & Security Remediation
                <span class="badge badge-success" style="margin-left: 15px; font-size: 0.6em; padding: 5px 15px;">Enhanced CF-Explainer</span>
            </h2>
            
            <div class="alert alert-info" style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin-bottom: 25px; border-radius: 6px;">
                <strong>ℹ️ About Counterfactual Explanations:</strong>
                This section provides research-grade vulnerability remediation guidance generated by our enhanced CF-Explainer.
                It answers: <em>"What is the minimal change needed to make this code secure?"</em>
            </div>
            
            {vuln_summary_html}
            
            {recs_html}
            
            {guidance_html}
            
            {cf_code_html}
            
            <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 6px;">
                <strong>⚠️ Important:</strong> While these recommendations are based on advanced analysis and research-grade patterns,
                always review and test security fixes in your specific context before deploying to production.
            </div>
        </div>
    </div>
    """


def _generate_profiling_section(tai_e_profiling: Dict[str, Any]) -> str:
    if not tai_e_profiling:
        return ""
    status = "✅ Completed" if tai_e_profiling.get("success") else "⚠️ Failed"
    report_path = tai_e_profiling.get("report_path")
    heapdump_path = tai_e_profiling.get("heapdump_path")
    mat_csv_path = tai_e_profiling.get("mat_csv_path")
    mat_report_path = tai_e_profiling.get("mat_report_path")
    object_profile_report = tai_e_profiling.get("object_profile_report")
    summary = tai_e_profiling.get("summary", {}) if isinstance(tai_e_profiling.get("summary", {}), dict) else {}
    elapsed = summary.get("elapsed_time")
    errors = tai_e_profiling.get("errors") or []
    error_html = ""
    if errors:
        error_html = "<p><strong>Errors:</strong> " + ", ".join(errors) + "</p>"
    link_html = f'<p><a href="{report_path}">Open profiling report</a></p>' if report_path else "<p>Report not generated.</p>"
    elapsed_html = f"<p><strong>Elapsed:</strong> {elapsed:.2f}s</p>" if elapsed is not None else ""
    heapdump_html = f"<p><strong>Heap dump:</strong> <a href=\"{heapdump_path}\">{heapdump_path}</a></p>" if heapdump_path else ""
    mat_html = ""
    if mat_report_path:
        mat_html = f"<p><strong>MAT report:</strong> <a href=\"{mat_report_path}\">{mat_report_path}</a></p>"
    elif mat_csv_path:
        mat_html = f"<p><strong>MAT CSV:</strong> <a href=\"{mat_csv_path}\">{mat_csv_path}</a></p>"
    object_profile_html = (
        f"<p><strong>Object profile:</strong> <a href=\"{object_profile_report}\">{object_profile_report}</a></p>"
        if object_profile_report else ""
    )
    return f"""
    <div class="section">
        <h4>🧪 Tai-e Profiling</h4>
        <p><strong>Status:</strong> {status}</p>
        {elapsed_html}
        {error_html}
        {link_html}
        {heapdump_html}
        {mat_html}
        {object_profile_html}
    </div>
    """


def _generate_object_profile_section(object_profile: Dict[str, Any]) -> str:
    if not object_profile:
        return ""
    status = "✅ Completed" if object_profile.get("success") else "⚠️ Failed"
    report_path = object_profile.get("report_path")
    error = object_profile.get("error")
    error_html = f"<p><strong>Error:</strong> {error}</p>" if error else ""
    link_html = f'<p><a href="{report_path}">Open object profiling report</a></p>' if report_path else "<p>Report not generated.</p>"
    return f"""
    <div class="section">
        <h4>🧠 Object-Centric Memory Profiling</h4>
        <p><strong>Status:</strong> {status}</p>
        {error_html}
        {link_html}
    </div>
    """

def _generate_graph_gallery_section(report_dir: Path) -> str:
    """Generate Graph Gallery section with grid layout - auto-discovers all graph files"""
    graph_cards = []
    
    # Auto-discover all PNG graph files (excluding banner.png)
    png_files = sorted([f for f in report_dir.glob('*.png') if f.name != 'banner.png'])
    
    for png_path in png_files:
        png_file = png_path.name
        
        # Determine graph type and description from filename
        if png_file.startswith('cfg_'):
            badge_class, badge_text = 'cfg', 'CFG'
            description = 'Control Flow Graph (execution paths)'
            dot_file = png_file.replace('.png', '.dot')
        elif png_file.startswith('dfg_'):
            badge_class, badge_text = 'dfg', 'DFG'
            description = 'Data Flow Graph (taint propagation)'
            dot_file = png_file.replace('.png', '.dot')
        elif png_file.startswith('pdg_'):
            badge_class, badge_text = 'pdg', 'PDG'
            description = 'Program Dependence Graph (CFG + DDG combined)'
            dot_file = png_file.replace('.png', '.dot')
        else:
            # Unknown graph type, skip
            continue
        
        dot_path = report_dir / dot_file
        svg_file = png_file.replace('.png', '.svg')
        svg_path = report_dir / svg_file

        download_buttons = f'<a href="{png_file}" download class="download-btn download-{badge_class}">📥 Download {badge_text}</a>'
        if svg_path.exists():
            download_buttons += f' <a href="{svg_file}" download class="download-btn download-{badge_class}">📥 Download {badge_text} SVG</a>'
        if dot_path.exists():
            download_buttons += f' <a href="{dot_file}" download class="download-btn download-dot">📥 Download DOT</a>'

        preview_src = svg_file if svg_path.exists() else png_file
        
        graph_cards.append(f"""
            <div class="graph-card">
                <div class="graph-card-header">
                    <span class="badge badge-{badge_class}">{badge_text}</span>
                    <h4>{png_file}</h4>
                </div>
                <div class="graph-card-description">{description}</div>
                <div class="graph-preview">
                    <img src="{preview_src}" alt="{description}" onclick="window.open('{preview_src}', '_blank')">
                </div>
                <div class="graph-card-footer">
                    {download_buttons}
                </div>
            </div>
            """)
    
    if not graph_cards:
        return """<div class="section" id="graph-gallery">
        <h2 class="section-title">📊 Graph Gallery</h2>
        <p style="color: #7f8c8d; padding: 20px; background: #f8f9fa; border-radius: 8px;">
            <em>No graph visualizations available. Use <code>--export-dfg</code>, <code>--export-cfg</code>, or <code>--export-pdg</code> to generate graphs.</em>
        </p>
    </div>"""
    
    return f"""<div class="section" id="graph-gallery">
        <h2 class="section-title">📊 Graph Gallery</h2>
        <div class="graph-gallery">
            {''.join(graph_cards)}
        </div>
    </div>"""


def _generate_all_artifacts_section(report_dir: Path) -> str:
    """Generate All Artifacts section with badges - auto-discovers all artifacts"""
    artifacts = []
    
    # Auto-discover all artifact files (DOT, PNG, TXT, excluding banner and index.html)
    all_files = sorted([f for f in report_dir.glob('*') 
                       if f.is_file() and f.name not in ['banner.png', 'index.html']])
    
    for file_path in all_files:
        filename = file_path.name
        
        # Determine badge text and class based on file extension and prefix
        if filename.endswith('.dot'):
            if filename.startswith('pdg_'):
                badge_text, badge_class = 'PDG DOT', 'pdg-dot'
            elif filename.startswith('cfg_'):
                badge_text, badge_class = 'CFG DOT', 'cfg-dot'
            elif filename.startswith('dfg_'):
                badge_text, badge_class = 'DFG DOT', 'dfg-dot'
            else:
                badge_text, badge_class = 'DOT', 'dot'
        elif filename.endswith('.png'):
            if filename.startswith('pdg_'):
                badge_text, badge_class = 'PDG PNG', 'pdg-png'
            elif filename.startswith('cfg_'):
                badge_text, badge_class = 'CFG PNG', 'cfg-png'
            elif filename.startswith('dfg_'):
                badge_text, badge_class = 'DFG PNG', 'dfg-png'
            else:
                badge_text, badge_class = 'PNG', 'png'
        elif filename.endswith('.txt'):
            badge_text, badge_class = 'TXT', 'txt'
        elif filename.endswith('.svg'):
            badge_text, badge_class = 'SVG', 'svg'
        else:
            badge_text, badge_class = 'FILE', 'file'
        
        artifacts.append(f"""
            <div class="artifact-item">
                <span class="badge badge-{badge_class}">{badge_text}</span>
                <a href="{filename}" download>{filename}</a>
            </div>
            """)
    
    if not artifacts:
        return ""
    
    return f"""<div class="section">
        <h2 class="section-title">📦 All Artifacts</h2>
        <div class="artifacts-list">
            {''.join(artifacts)}
        </div>
    </div>"""


def _generate_graph_index_section(report_dir: Path) -> str:
    """Generate method-to-graph index for CFG/DFG/PDG files."""
    graph_files = {"cfg": {}, "dfg": {}, "pdg": {}}
    for prefix in graph_files:
        for png_path in report_dir.glob(f"{prefix}_*.png"):
            base = png_path.stem[len(prefix) + 1 :]
            graph_files[prefix][base] = png_path.name

    all_bases = set().union(*[set(items.keys()) for items in graph_files.values()])
    if not all_bases:
        return ""

    index_by_base: Dict[str, Dict[str, Any]] = {}
    index_path = report_dir / "graph_index.json"
    if index_path.exists():
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                for entry in payload:
                    if not isinstance(entry, dict):
                        continue
                    base = entry.get("base")
                    if base:
                        index_by_base[str(base)] = entry
        except Exception:
            index_by_base = {}

    def sort_key(base: str) -> tuple:
        match = re.match(r"^(\d+)_", base)
        idx = int(match.group(1)) if match else 9999
        method_label = re.sub(r"^\d+_", "", base)
        return (idx, method_label)

    rows = []
    for base in sorted(all_bases, key=sort_key):
        method_label = re.sub(r"^\d+_", "", base)
        index_meta = index_by_base.get(base, {})
        if index_meta.get("method"):
            method_label = str(index_meta.get("method"))
        start_line = index_meta.get("start_line")
        end_line = index_meta.get("end_line")
        if isinstance(start_line, int) and start_line > 0:
            if isinstance(end_line, int) and end_line > 0 and end_line != start_line:
                line_range = f"{start_line}–{end_line}"
            else:
                line_range = str(start_line)
        else:
            line_range = "—"
        cfg = graph_files["cfg"].get(base)
        dfg = graph_files["dfg"].get(base)
        pdg = graph_files["pdg"].get(base)
        cfg_link = f'<a href="{_escape_html(cfg)}">{_escape_html(cfg)}</a>' if cfg else "—"
        dfg_link = f'<a href="{_escape_html(dfg)}">{_escape_html(dfg)}</a>' if dfg else "—"
        pdg_link = f'<a href="{_escape_html(pdg)}">{_escape_html(pdg)}</a>' if pdg else "—"
        rows.append(
            f"<tr>"
            f"<td><code>{_escape_html(method_label)}</code></td>"
            f"<td>{_escape_html(line_range)}</td>"
            f"<td>{cfg_link}</td>"
            f"<td>{dfg_link}</td>"
            f"<td>{pdg_link}</td>"
            f"</tr>"
        )

    rows_html = "\n".join(rows)
    return f"""<div class="section" id="graph-index">
        <h3 style="color: #2c3e50; font-size: 20px; margin-bottom: 15px;">🧭 Graph Index (by method)</h3>
        <p style="margin-bottom: 12px; color: #6c7a89;">
            Graph filenames encode the method name (sanitized). Use this index to pick the exact CFG/DFG/PDG for a method.
        </p>
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <thead>
                    <tr style="background: #f5f7fa; text-align: left;">
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Method</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">Line range</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">CFG</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">DFG</th>
                        <th style="padding: 10px; border-bottom: 1px solid #e0e0e0;">PDG</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>"""


def _generate_legend_section() -> str:
    """Generate Legend section explaining graph types and color coding"""
    return """<div class="section">
        <h2 class="section-title">📖 Graph Legend & Color Guide</h2>
        
        <div class="legend-box" style="background: #ffffff; padding: 25px; border-radius: 8px; border: 1px solid #e0e0e0; margin-bottom: 20px;">
            <h3 style="color: #2c3e50; margin-bottom: 20px; font-size: 18px;">🎨 Visual Elements</h3>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px;">
                
                <!-- Tainted Nodes -->
                <div style="padding: 15px; background: #f8f4ff; border-left: 4px solid #9370DB; border-radius: 4px;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <div style="width: 50px; height: 35px; background: #E6E6FA; border: 3px solid #9370DB; border-radius: 4px;"></div>
                        <strong style="color: #7d3c98;">Tainted Nodes</strong>
                    </div>
                    <p style="color: #666; font-size: 13px; margin: 0;">Variables/data containing untrusted input that could lead to vulnerabilities</p>
                </div>
                
                <!-- Data Flow -->
                <div style="padding: 15px; background: #fff5f5; border-left: 4px solid #DC143C; border-radius: 4px;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <div style="width: 50px; height: 3px; background: transparent; border-top: 3px dashed #DC143C;"></div>
                        <strong style="color: #c0392b;">Data Flow (DDG)</strong>
                    </div>
                    <p style="color: #666; font-size: 13px; margin: 0;">Red dotted lines show how data dependencies flow between statements</p>
                </div>
                
                <!-- Control Flow -->
                <div style="padding: 15px; background: #f0f8ff; border-left: 4px solid #0055A4; border-radius: 4px;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <div style="width: 50px; height: 3px; background: #0055A4;"></div>
                        <strong style="color: #004080;">Control Flow (CDG/CFG)</strong>
                    </div>
                    <p style="color: #666; font-size: 13px; margin: 0;">French blue solid lines show program execution order and control dependencies</p>
                </div>
                
                <!-- AST Structure -->
                <div style="padding: 15px; background: #f8f8f8; border-left: 4px solid #B0B0B0; border-radius: 4px;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <div style="width: 50px; height: 3px; background: #B0B0B0;"></div>
                        <strong style="color: #666;">AST Structure</strong>
                    </div>
                    <p style="color: #666; font-size: 13px; margin: 0;">Gray solid lines show abstract syntax tree relationships between code elements</p>
                </div>
                
            </div>
            
            <h3 style="color: #2c3e50; margin-bottom: 15px; margin-top: 30px; font-size: 18px;">📊 Graph Types</h3>
            
            <ul class="legend-list" style="list-style: none; padding: 0;">
                <li style="margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
                    <strong style="color: #e67e22; font-size: 16px;">PDG (Program Dependence Graph)</strong>
                    <p style="margin: 8px 0 0 0; color: #555; line-height: 1.6;">
                        The most comprehensive view combining <strong>control flow (French blue)</strong> and <strong>data dependencies (red dotted)</strong>. 
                        Shows both how the program executes and how data moves between statements. Use this to trace vulnerability paths.
                    </p>
                </li>
                
                <li style="margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
                    <strong style="color: #9b59b6; font-size: 16px;">DFG (Data Flow Graph)</strong>
                    <p style="margin: 8px 0 0 0; color: #555; line-height: 1.6;">
                        Shows data dependencies between variables and expressions. Includes AST structure (gray),
                        control flow (French blue), and data dependencies (red dotted).
                        The <code style="background: #e8e8e8; padding: 2px 6px; border-radius: 3px;">dfg_paths.txt</code>
                        file summarizes taint-flow evidence used in gating decisions.
                    </p>
                </li>
                
                <li style="padding: 15px; background: #f8f9fa; border-radius: 6px;">
                    <strong style="color: #3498db; font-size: 16px;">CFG (Control Flow Graph)</strong>
                    <p style="margin: 8px 0 0 0; color: #555; line-height: 1.6;">
                        Shows execution paths through the program with <strong style="color: #0055A4;">French blue lines</strong>. 
                        Each node represents a statement or basic block. Use this to understand branching logic and reachable code paths.
                    </p>
                </li>
            </ul>
        </div>
        
        <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; border-radius: 4px; margin-top: 15px;">
            <strong style="color: #856404;">💡 Analysis Tip:</strong>
            <p style="color: #856404; margin: 8px 0 0 0;">
                Follow <span style="color: #DC143C; font-weight: bold;">red dotted data-dependency lines</span>
                from untrusted sources toward sink calls, and correlate with
                <code style="background: #fff3cd; padding: 2px 6px; border-radius: 3px;">dfg_paths.txt</code>
                for taint-flow evidence.
            </p>
        </div>
    </div>"""


def _generate_footer() -> str:
    """Generate footer section"""
    return """<div class="footer">
        <small>
            Generated by <strong>Bean Vulnerable GNN Framework v2.0.0</strong><br>
            Research references (inspiration; not all integrations enabled): OWASP Top 10 2024, CWE-20/CWE-502, Tai-e pointer analysis, FSE/PLDI alias-analysis literature, Seneca (arXiv 2023)<br>
            Features used in this report depend on enabled flags (e.g., GNN inference, counterfactuals, Joern dataflow)
        </small>
    </div>"""

