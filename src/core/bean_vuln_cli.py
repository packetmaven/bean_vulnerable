#!/usr/bin/env python3
"""
Bean Vulnerable Framework - Enhanced CLI with Fixed Edge Extraction
================================================================
Comprehensive fix for edge data extraction from analysis results
"""

import argparse
import json
import sys
import time
import tempfile
import shutil
import subprocess
import os
import webbrowser
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Union, Optional
import logging
import asyncio

from core.soundness_testing.runner import run_soundness_validation
from core.precision_debugging.diagnosis import analyze_source
from core.taint_debugging.taint_flow_visualizer import write_taint_graph
from core.taint_debugging.interactive_cli import launch_debugger_from_result
from core.performance.profiling_harness import ProfilingConfiguration, MultiLayerProfiler
from core.performance.object_profiler import ObjectCentricProfiler

# Setup logging
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

REPORT_DIR_MARKER = ".bean_vuln_report"

EDGE_STYLE_MAP = {
    "AST": {"color": "#9e9e9e", "style": "solid"},
    "CFG": {"color": "#0055A4", "style": "solid"},
    "DFG": {"color": "#DC143C", "style": "dotted"},
    "DDG": {"color": "#DC143C", "style": "dotted"},
    "CDG": {"color": "#0055A4", "style": "dashed"},
    "CALL": {"color": "#2E7D32", "style": "solid"},
}


def _resolve_tai_e_jar(candidate: Optional[str]) -> Optional[Path]:
    if not candidate:
        return None
    path = Path(candidate).expanduser()
    if not path.exists():
        return None
    if path.is_file() and path.suffix == ".jar":
        return path
    jars = sorted(path.rglob("tai-e-all*.jar"))
    if jars:
        return jars[0]
    jars = sorted(path.rglob("*.jar"))
    return jars[0] if jars else None


def _maybe_prompt_tai_e_home(args: argparse.Namespace) -> None:
    if not args.tai_e:
        return
    candidate = args.tai_e_home or os.getenv("TAI_E_HOME")
    jar_path = _resolve_tai_e_jar(candidate)
    if jar_path:
        if not args.tai_e_home:
            args.tai_e_home = str(jar_path)
        return
    if not sys.stdin.isatty():
        return
    try:
        user_input = input(
            "TAI_E_HOME not set or jar not found. "
            "Enter path to tai-e-all.jar (or directory): "
        ).strip()
    except EOFError:
        return
    if not user_input:
        return
    jar_path = _resolve_tai_e_jar(user_input)
    args.tai_e_home = str(jar_path) if jar_path else user_input

EDGE_LABEL_RE = re.compile(r'label\s*=\s*"([A-Z]+):')


def _colorize_dot_file(dot_path: Path) -> None:
    try:
        content = dot_path.read_text(encoding="utf-8")
    except Exception:
        return

    updated_lines = []
    changed = False
    for line in content.splitlines():
        match = EDGE_LABEL_RE.search(line)
        if match and "color=" not in line:
            edge_type = match.group(1)
            style = EDGE_STYLE_MAP.get(edge_type)
            if style and "]" in line:
                attrs = [
                    f'color="{style["color"]}"',
                    f'fontcolor="{style["color"]}"',
                    f'style="{style["style"]}"',
                    "penwidth=1.4",
                ]
                head, tail = line.rsplit("]", 1)
                line = f"{head}, {', '.join(attrs)} ]{tail}"
                changed = True
        updated_lines.append(line)

    if changed:
        dot_path.write_text("\n".join(updated_lines), encoding="utf-8")

def _format_gnn_status(result: Dict[str, Any], gnn_enabled_flag: Optional[bool] = None) -> str:
    spatial = result.get("spatial_gnn", {}) if isinstance(result.get("spatial_gnn", {}), dict) else {}
    analysis_method = result.get("analysis_method", "")
    gnn_conf = result.get("gnn_confidence")
    forward_called = bool(result.get("gnn_utilized", False) or spatial.get("forward_called", False))
    used_in_scoring = bool(spatial.get("used_in_scoring", False))
    enabled = bool(spatial.get("enabled", False))

    if used_in_scoring or analysis_method == "gnn_inference_with_heuristic":
        status = "weighted"
    elif forward_called or analysis_method == "gnn_inference_untrained":
        status = "untrained (forward ok)"
    elif enabled:
        status = "enabled"
    else:
        status = "disabled"

    if status.startswith("weighted") and isinstance(gnn_conf, (int, float)):
        return f"{status} ({gnn_conf:.3f})"
    return status

def _is_unsafe_report_dir(report_dir: Path) -> bool:
    """Block obvious destructive paths."""
    resolved = report_dir.resolve()
    unsafe = {Path("/").resolve(), Path.home().resolve(), Path.cwd().resolve()}
    return resolved in unsafe

def _prepare_report_dir(report_dir: Path) -> Path:
    """
    Prepare (and safely reset) report directory using a marker file.
    Refuses to delete directories without the marker to prevent accidents.
    """
    resolved = report_dir.expanduser().resolve()
    if _is_unsafe_report_dir(resolved):
        raise ValueError(f"Refusing to use unsafe report directory: {resolved}")
    if resolved.exists() and resolved.is_symlink():
        raise ValueError(f"Refusing to use symlinked report directory: {resolved}")

    marker = resolved / REPORT_DIR_MARKER
    if resolved.exists():
        if not marker.exists():
            raise ValueError(
                f"Refusing to delete existing directory without marker: {resolved}. "
                f"Create a dedicated report dir or add {REPORT_DIR_MARKER} to allow cleanup."
            )
        shutil.rmtree(resolved)

    resolved.mkdir(parents=True, exist_ok=True)
    marker.write_text("Bean Vulnerable report directory marker.\n", encoding="utf-8")
    return resolved

# Import the framework
try:
    from src.core.integrated_gnn_framework import IntegratedGNNFramework
    from src.integrations.vul4j_parser import FixedVul4JParser
except ImportError as e:
    try:
        from core.integrated_gnn_framework import IntegratedGNNFramework
        from integrations.vul4j_parser import FixedVul4JParser
    except ImportError as e2:
        # Add parent directory to path for direct script execution
        parent_dir = Path(__file__).resolve().parent.parent.parent
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))
        try:
            from src.core.integrated_gnn_framework import IntegratedGNNFramework
            from src.integrations.vul4j_parser import FixedVul4JParser
        except ImportError as e3:
            print(f"❌ Import error: {e3}")
            sys.exit(1)

# Initialize framework
fw = None  # Will be initialized in main() with CLI flags
try:
    vul4j_parser = FixedVul4JParser()
except:
    vul4j_parser = None
    LOG.warning("VUL4J parser not available")

def extract_edge_data_comprehensive(analysis_result: Any) -> Dict[str, int]:
    """
    Comprehensive edge data extraction from analysis results.
    Handles all possible data structures and edge storage locations.
    
    Args:
        analysis_result: Analysis result from the framework (object or dict)
        
    Returns:
        Dictionary with node_count, edge_count, and other metrics
    """
    metrics = {
        'node_count': 0,
        'edge_count': 0,
        'method_count': 0,
        'call_count': 0,
        'cfg_count': 0
    }
    
    try:
        LOG.debug("🔍 Extracting edge data from analysis result")
        
        # Strategy 1: Handle AnalysisResult object
        if hasattr(analysis_result, '__dict__'):
            LOG.debug("📊 Processing AnalysisResult object")
            
            # Extract technical details
            tech_details = getattr(analysis_result, 'technical_details', {})
            
            # Try multiple possible edge data locations
            edge_sources = [
                ('cpg_edges', tech_details),
                ('edge_count', tech_details),
                ('num_edges', tech_details),
                ('total_edges', tech_details),
                ('graph_edges', tech_details)
            ]
            
            for key, source in edge_sources:
                if isinstance(source, dict) and key in source:
                    metrics['edge_count'] = source[key]
                    LOG.debug(f"✅ Found edge count in tech_details.{key}: {metrics['edge_count']}")
                    break
            
            # If still no edges, check object attributes
            if metrics['edge_count'] == 0:
                for attr in ['cpg_edges', 'edge_count', 'num_edges', 'graph_edges']:
                    if hasattr(analysis_result, attr):
                        value = getattr(analysis_result, attr, 0)
                        if isinstance(value, (int, float)):
                            metrics['edge_count'] = int(value)
                            LOG.debug(f"✅ Found edge count in attribute {attr}: {metrics['edge_count']}")
                            break
                        elif isinstance(value, list):
                            metrics['edge_count'] = len(value)
                            LOG.debug(f"✅ Calculated edge count from attribute {attr} list: {metrics['edge_count']}")
                            break
            
            # Check CPG data structure
            cpg_data = getattr(analysis_result, 'cpg', {})
            if isinstance(cpg_data, dict):
                # Extract from CPG edges list
                if 'edges' in cpg_data:
                    edges = cpg_data['edges']
                    if isinstance(edges, list):
                        metrics['edge_count'] = len(edges)
                        LOG.debug(f"✅ Calculated edge count from CPG edges list: {metrics['edge_count']}")
                    elif isinstance(edges, int):
                        metrics['edge_count'] = edges
                        LOG.debug(f"✅ Found edge count in CPG edges int: {metrics['edge_count']}")
                
                # Extract node count
                if 'nodes' in cpg_data:
                    nodes = cpg_data['nodes']
                    if isinstance(nodes, list):
                        metrics['node_count'] = len(nodes)
                    elif isinstance(nodes, int):
                        metrics['node_count'] = nodes
            
            # Extract other metrics (check both CPG and technical_details)
            if isinstance(cpg_data, dict):
                metrics['method_count'] = cpg_data.get('methods', cpg_data.get('method_count', 0))
                metrics['call_count'] = cpg_data.get('calls', cpg_data.get('call_count', 0))
                metrics['cfg_count'] = cpg_data.get('cfg', cpg_data.get('cfg_count', metrics['method_count']))
            
            metrics['node_count'] = metrics['node_count'] or tech_details.get('cpg_nodes', 
                                   getattr(analysis_result, 'cpg_nodes', 0))
            metrics['method_count'] = metrics['method_count'] or tech_details.get('method_count', 
                                    getattr(analysis_result, 'method_count', 0))
            metrics['call_count'] = metrics['call_count'] or tech_details.get('call_count', 
                                  getattr(analysis_result, 'call_count', 0))
            
        # Strategy 2: Handle dictionary result
        elif isinstance(analysis_result, dict):
            LOG.debug("📊 Processing dictionary result")
            
            # Check technical_details
            tech_details = analysis_result.get('technical_details', {})
            
            # Extract edge count from various possible locations
            edge_locations = [
                ('cpg_edges', tech_details),
                ('edge_count', tech_details),
                ('num_edges', tech_details),
                ('graph_edges', tech_details),
                ('cpg_edges', analysis_result),
                ('edge_count', analysis_result),
                ('num_edges', analysis_result),
                ('graph_edges', analysis_result)
            ]
            
            for key, source in edge_locations:
                if isinstance(source, dict) and key in source:
                    value = source[key]
                    if isinstance(value, (int, float)):
                        metrics['edge_count'] = int(value)
                        LOG.debug(f"✅ Found edge count in {key}: {metrics['edge_count']}")
                        break
                    elif isinstance(value, list):
                        metrics['edge_count'] = len(value)
                        LOG.debug(f"✅ Calculated edge count from {key} list: {metrics['edge_count']}")
                        break
            
            # Check CPG data
            cpg_data = analysis_result.get('cpg', {})
            if isinstance(cpg_data, dict):
                if 'edges' in cpg_data:
                    edges = cpg_data['edges']
                    if isinstance(edges, list):
                        metrics['edge_count'] = len(edges)
                        LOG.debug(f"✅ Calculated edge count from dict CPG edges: {metrics['edge_count']}")
                    elif isinstance(edges, int):
                        metrics['edge_count'] = edges
                
                # Extract other metrics from CPG
                if 'nodes' in cpg_data:
                    nodes = cpg_data['nodes']
                    metrics['node_count'] = len(nodes) if isinstance(nodes, list) else nodes
                
                # Extract methods and calls from CPG (key fix!)
                metrics['method_count'] = cpg_data.get('methods', cpg_data.get('method_count', 0))
                metrics['call_count'] = cpg_data.get('calls', cpg_data.get('call_count', 0))
                metrics['cfg_count'] = cpg_data.get('cfg', cpg_data.get('cfg_count', metrics['method_count']))
                
            # Extract from top level (fallback)
            metrics['node_count'] = metrics['node_count'] or analysis_result.get('node_count', 
                                   tech_details.get('cpg_nodes', 0))
            metrics['method_count'] = metrics['method_count'] or analysis_result.get('method_count', 
                                    tech_details.get('method_count', 0))
            metrics['call_count'] = metrics['call_count'] or analysis_result.get('call_count', 
                                  tech_details.get('call_count', 0))
        
        # Strategy 3: Deep inspection for edge arrays
        if metrics['edge_count'] == 0:
            LOG.debug("🔍 Deep inspection for edge arrays")
            edge_arrays = []
            
            # Recursively search for edge arrays
            def find_edge_arrays(obj, path=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_path = f"{path}.{key}" if path else key
                        if key in ['edges', 'edge_list', 'graph_edges', 'cfg_edges']:
                            if isinstance(value, list):
                                edge_arrays.append((new_path, len(value)))
                        find_edge_arrays(value, new_path)
                elif isinstance(obj, list) and len(obj) > 0:
                    # Check if this looks like an edge list
                    sample = obj[0]
                    if isinstance(sample, dict) and any(k in sample for k in ['source', 'target', 'src', 'dst', 'from', 'to']):
                        edge_arrays.append((path, len(obj)))
            
            find_edge_arrays(analysis_result)
            
            if edge_arrays:
                # Use the largest edge array found
                best_path, best_count = max(edge_arrays, key=lambda x: x[1])
                metrics['edge_count'] = best_count
                LOG.debug(f"✅ Found edge array at {best_path}: {best_count} edges")
        
        LOG.info(f"📊 Extracted metrics: {metrics}")
        return metrics
        
    except Exception as e:
        LOG.error(f"❌ Edge extraction failed: {e}")
        return metrics

def analyze_path(
    p: Path,
    recursive: bool,
    keep: bool,
    export_dir: Path = None,
    cli_args: Optional[argparse.Namespace] = None,
    report_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Enhanced path analysis with comprehensive edge extraction.
    """
    if p.is_file() and p.suffix == ".java":
        # Single Java file analysis
        LOG.info(f"🔍 Analyzing single Java file: {p}")
        
        try:
            # Read source code
            source_code = p.read_text(encoding='utf-8', errors='ignore')
            
            # Run analysis (analyze_code is synchronous, not async)
            analysis_result = fw.analyze_code(
                source_code=source_code,
                source_path=str(p)
            )
            
            # Extract comprehensive metrics
            metrics = extract_edge_data_comprehensive(analysis_result)
            
            # Build result dictionary with proper edge data
            if hasattr(analysis_result, '__dict__'):
                tech_details = getattr(analysis_result, 'technical_details', {})
                
                result = {
                    'vulnerability_detected': getattr(analysis_result, 'vulnerability_detected', False),
                    'confidence': float(getattr(analysis_result, 'confidence', 0.0)),
                    'vulnerability_type': getattr(analysis_result, 'vulnerability_type', 'Unknown'),
                    'severity': getattr(analysis_result, 'severity', 'LOW'),
                    'explanation': getattr(analysis_result, 'explanation', ''),
                    'technical_details': {
                        **tech_details,
                        'cpg_nodes': metrics['node_count'],
                        'cpg_edges': metrics['edge_count'],  # FIXED: Ensure this key exists
                        'method_count': metrics['method_count'],
                        'call_count': metrics['call_count']
                    },
                    'processing_time': getattr(analysis_result, 'processing_time', 0.0),
                    'model_version': getattr(analysis_result, 'model_version', '1.0.0'),
                    'analysis_method': getattr(analysis_result, 'analysis_method', 'pattern_heuristic_with_uncertainty'),
                    'cpg': {
                        'nodes': metrics['node_count'],
                        'edges': metrics['edge_count'],  # FIXED: Use extracted edge count
                        'methods': metrics['method_count'],
                        'calls': metrics['call_count']
                    },
                    'gnn_utilized': getattr(analysis_result, 'gnn_utilized', False)
                        }
            else:
                # Handle dictionary results
                result = dict(analysis_result) if isinstance(analysis_result, dict) else {}

                # Prefer existing CPG counts if present and non-zero; otherwise fill from metrics
                existing_cpg = result.get('cpg', {}) if isinstance(result.get('cpg', {}), dict) else {}
                nodes_existing = int(existing_cpg.get('nodes', 0) or 0)
                edges_existing = int(existing_cpg.get('edges', 0) or 0)
                methods_existing = int(existing_cpg.get('methods', 0) or 0)
                calls_existing = int(existing_cpg.get('calls', 0) or 0)

                cpg_nodes = nodes_existing if nodes_existing > 0 else metrics['node_count']
                cpg_edges = edges_existing if edges_existing > 0 else metrics['edge_count']
                cpg_methods = methods_existing if methods_existing > 0 else metrics['method_count']
                cpg_calls = calls_existing if calls_existing > 0 else metrics['call_count']

                result['cpg'] = {
                    'nodes': cpg_nodes,
                    'edges': cpg_edges,
                    'methods': cpg_methods,
                    'calls': cpg_calls,
                }

                # Ensure technical_details has edge data (do not overwrite existing non-zero values)
                tech = result.get('technical_details') or {}
                if not isinstance(tech, dict):
                    tech = {}
                tech.setdefault('cpg_nodes', cpg_nodes)
                tech.setdefault('cpg_edges', cpg_edges)
                tech.setdefault('method_count', cpg_methods)
                tech.setdefault('call_count', cpg_calls)
                result['technical_details'] = tech
            
            if cli_args:
                _apply_debug_utilities(result, p, cli_args, report_dir)
            return result
            
        except Exception as e:
            LOG.error(f"❌ Analysis failed for {p}: {e}")
            return {
                'vulnerability_detected': False,
                'confidence': 0.0,
                'error': str(e),
                'cpg': {'nodes': 0, 'edges': 0, 'methods': 0, 'calls': 0}
            }
    
    elif p.is_file() and p.suffix == ".csv" and "vul4j" in p.name.lower():
        # VUL4J CSV analysis
        return analyze_vul4j_csv(p)
    
    elif p.is_dir():
        # Directory analysis
        LOG.info(f"🔍 Analyzing directory: {p}")
        return analyze_directory(p, recursive, cli_args, report_dir)
    
    else:
        LOG.error(f"❌ Unsupported file type: {p}")
        return {
            'vulnerability_detected': False,
            'confidence': 0.0,
            'error': f'Unsupported file type: {p.suffix}',
            'cpg': {'nodes': 0, 'edges': 0, 'methods': 0, 'calls': 0}
        }

def analyze_vul4j_csv(csv_path: Path) -> Dict[str, Any]:
    """
    Enhanced VUL4J CSV analysis with comprehensive edge extraction.
    """
    if not vul4j_parser:
        return {
            'vulnerability_detected': False,
            'confidence': 0.0,
            'error': 'VUL4J parser not available',
            'cpg': {'nodes': 0, 'edges': 0, 'methods': 0, 'calls': 0}
        }
    
    LOG.info(f"📊 VUL4J Dataset: {len(vul4j_parser.available_vulnerabilities)} vulnerabilities found")
    
    results = []
    processed_count = 0
    successful_count = 0
    total_nodes = 0
    total_edges = 0
    
    # Process a sample of vulnerabilities
    sample_ids = vul4j_parser.available_vulnerabilities[:2]  # Process first 2 for demo
    
    for vul_id in sample_ids:
        LOG.info(f"🔍 Processing {vul_id}")
        
        try:
            # Get vulnerability info
            vuln_info = vul4j_parser.get_vulnerability_info(vul_id)
            LOG.info(f"   ✅ Found vulnerability info for {vul_id}")
            
            # Analyze with framework
            analysis_result = fw.analyze_code(f"// VUL4J {vul_id} analysis")
            
            # Extract comprehensive metrics
            metrics = extract_edge_data_comprehensive(analysis_result)
            
            # Handle result object properly
            if hasattr(analysis_result, '__dict__'):
                result_dict = {
                    'vulnerability_id': vul_id,
                    'cve_id': vuln_info.get('cve_id', ''),
                    'repository': vuln_info.get('repo_slug', ''),
                    'vulnerability_detected': str(getattr(analysis_result, 'vulnerability_detected', False)),
                    'confidence': getattr(analysis_result, 'confidence', 0.0),
                    'analysis_method': getattr(analysis_result, 'analysis_method', 'vul4j_real_analysis'),
                    'cpg': {
                        'nodes': metrics['node_count'],
                        'edges': metrics['edge_count'],  # FIXED: Use extracted metrics
                        'methods': metrics['method_count'],
                        'calls': metrics['call_count']
                    },
                    'gnn_utilized': getattr(analysis_result, 'gnn_utilized', False),
                    'processing_time': getattr(analysis_result, 'processing_time', 0.0),
                    'vuln_info': vuln_info
                }
            else:
                result_dict = dict(analysis_result) if isinstance(analysis_result, dict) else {}
                result_dict.update({
                    'vulnerability_id': vul_id,
                    'cpg': {
                        'nodes': metrics['node_count'],
                        'edges': metrics['edge_count'],  # FIXED: Use extracted metrics
                        'methods': metrics['method_count'],
                        'calls': metrics['call_count']
                    }
                })
            
            results.append(result_dict)
            successful_count += 1
            total_nodes += metrics['node_count']
            total_edges += metrics['edge_count']
            
        except Exception as e:
            LOG.error(f"❌ Failed to analyze {vul_id}: {e}")
            continue
        
        processed_count += 1
    
    avg_confidence = sum(r.get('confidence', 0) for r in results) / len(results) if results else 0
    gnn_used = sum(1 for r in results if r.get('gnn_utilized'))
    gnn_rate = (gnn_used / len(results)) if results else 0.0
    
    LOG.info(f"   📊 VUL4J Dataset: {len(vul4j_parser.available_vulnerabilities)} total, "
             f"{processed_count} processed, {successful_count} successful")
    LOG.info(f"   📊 Avg Confidence: {avg_confidence:.3f}, Total Nodes: {total_nodes}, "
             f"Total Edges: {total_edges}, GNN Rate: {gnn_rate * 100:.1f}%")
    
    return {
        'dataset_type': 'vul4j_csv',
        'total_vulnerabilities': len(vul4j_parser.available_vulnerabilities),
        'processed_count': processed_count,
        'successful_count': successful_count,
        'results': results,
        'summary': {
            'vulnerabilities_detected': successful_count,
            'average_confidence': avg_confidence,
            'total_nodes': total_nodes,
            'total_edges': total_edges,  # FIXED: Include total edges
            'gnn_utilization_rate': gnn_rate
        }
    }

def analyze_directory(
    dir_path: Path,
    recursive: bool,
    cli_args: Optional[argparse.Namespace] = None,
    report_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Enhanced directory analysis with edge extraction.
    """
    LOG.info(f"🔍 Analyzing directory: {dir_path} (recursive: {recursive})")
    
    pattern = "**/*.java" if recursive else "*.java"
    java_files = list(dir_path.glob(pattern))
    
    if not java_files:
        return {
            'vulnerability_detected': False,
            'confidence': 0.0,
            'error': 'No Java files found',
            'cpg': {'nodes': 0, 'edges': 0, 'methods': 0, 'calls': 0}
        }
    
    # Analyze first file or combine all files
    first_file = java_files[0]
    return analyze_path(first_file, False, False, None, cli_args, report_dir)


def _apply_debug_utilities(
    result: Dict[str, Any],
    source_path: Path,
    cli_args: argparse.Namespace,
    report_dir: Optional[Path],
) -> None:
    taint_tracking = result.get("taint_tracking", {}) if isinstance(result.get("taint_tracking", {}), dict) else {}

    if cli_args.taint_graph:
        flows = taint_tracking.get("taint_flows", [])
        if flows:
            if cli_args.taint_graph_output:
                output_path = Path(cli_args.taint_graph_output).expanduser()
            elif report_dir:
                output_path = report_dir / f"taint_flow_graph_{source_path.stem}.html"
            else:
                output_path = Path("analysis") / f"taint_flow_graph_{source_path.stem}.html"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            write_taint_graph(output_path, flows)
            if report_dir and output_path.is_absolute() and report_dir in output_path.parents:
                rel_path = output_path.relative_to(report_dir)
                result["taint_graph"] = {"path": str(rel_path)}
            else:
                result["taint_graph"] = {"path": str(output_path)}

    if cli_args.tai_e_soundness:
        alias_analysis = taint_tracking.get("alias_analysis", {})
        tai_e_meta = alias_analysis.get("tai_e", {}) if isinstance(alias_analysis, dict) else {}
        points_to_file = tai_e_meta.get("points_to_file")
        if points_to_file:
            output_base = (
                Path(cli_args.tai_e_soundness_output).expanduser()
                if cli_args.tai_e_soundness_output
                else (report_dir or Path("analysis"))
            )
            report_output = output_base if output_base.suffix == ".html" else output_base / f"soundness_report_{source_path.stem}.html"
            report_output.parent.mkdir(parents=True, exist_ok=True)
            report = run_soundness_validation(
                source_path=source_path,
                points_to_file=Path(points_to_file),
                classpath=cli_args.tai_e_classpath,
                output_dir=report_output.parent,
                report_path=report_output,
            )
            report_path = report.report_path
            if report_dir and report_path and Path(report_path).is_absolute() and report_dir in Path(report_path).parents:
                report_path = str(Path(report_path).relative_to(report_dir))
            result["soundness_validation"] = {
                "success": report.success,
                "report_path": report_path,
                "error": report.error,
                "summary": report.report,
            }

    if cli_args.tai_e_precision_diagnose:
        source_code = source_path.read_text(encoding="utf-8", errors="ignore")
        diagnosis = analyze_source(source_code)
        result["precision_diagnosis"] = diagnosis.to_dict()

    if cli_args.taint_debug:
        if cli_args.input and len(cli_args.input) == 1:
            launch_debugger_from_result(result)

    if cli_args.tai_e_profile:
        source_code = source_path.read_text(encoding="utf-8", errors="ignore")
        output_base = (
            Path(cli_args.tai_e_profile_output).expanduser()
            if cli_args.tai_e_profile_output
            else (report_dir or (Path("analysis") / "tai_e_profiling"))
        )
        output_dir = output_base.parent if output_base.suffix == ".html" else output_base
        output_dir.mkdir(parents=True, exist_ok=True)
        profiling_config = ProfilingConfiguration(
            enable_cpu_profiling=bool(cli_args.async_profiler_path),
            enable_memory_profiling=bool(cli_args.yourkit_agent_path),
            enable_tai_e_profiling=False,
            enable_system_profiling=cli_args.profile_system,
            enable_jfr=cli_args.profile_jfr,
            async_profiler_path=Path(cli_args.async_profiler_path).expanduser() if cli_args.async_profiler_path else None,
            yourkit_agent_path=Path(cli_args.yourkit_agent_path).expanduser() if cli_args.yourkit_agent_path else None,
            max_heap=cli_args.profile_max_heap,
            min_heap=cli_args.profile_min_heap,
            output_dir=output_dir,
        )
        profiler = MultiLayerProfiler(profiling_config)
        profile_results = profiler.profile_tai_e_analysis(
            source_code=source_code,
            source_path=str(source_path),
            tai_e_home=cli_args.tai_e_home,
            tai_e_config={
                "main_class": cli_args.tai_e_main,
                "cs": cli_args.tai_e_cs,
                "timeout": cli_args.tai_e_timeout,
                "only_app": cli_args.tai_e_only_app,
                "allow_phantom": cli_args.tai_e_allow_phantom,
                "prepend_jvm": cli_args.tai_e_prepend_jvm,
                "java_version": cli_args.tai_e_java_version,
                "classpath": cli_args.tai_e_classpath,
                "taint_config": cli_args.tai_e_taint_config if cli_args.tai_e_taint else None,
            },
        )
        report_path = profile_results.get("profiling_report")
        if report_path and output_base.suffix == ".html" and report_path != str(output_base):
            try:
                Path(report_path).replace(output_base)
                report_path = str(output_base)
            except Exception:
                pass
        if report_dir and report_path and Path(report_path).is_absolute() and report_dir in Path(report_path).parents:
            report_path = str(Path(report_path).relative_to(report_dir))
        result["tai_e_profiling"] = {
            "success": profile_results.get("return_code") == 0 and not profile_results.get("errors"),
            "report_path": report_path,
            "errors": profile_results.get("errors"),
            "summary": {
                "elapsed_time": profile_results.get("elapsed_time"),
                "return_code": profile_results.get("return_code"),
                "process_metrics": profile_results.get("process_metrics"),
            },
            "output_dir": profile_results.get("tai_e_output_dir"),
        }

    if cli_args.object_profile:
        snapshot_path = Path(cli_args.object_profile).expanduser()
        output_base = (
            Path(cli_args.object_profile_output).expanduser()
            if cli_args.object_profile_output
            else (report_dir or Path("analysis"))
        )
        report_output = output_base if output_base.suffix == ".html" else output_base / f"object_profile_{source_path.stem}.html"
        report_output.parent.mkdir(parents=True, exist_ok=True)
        try:
            profiler = ObjectCentricProfiler(snapshot_path)
            report = profiler.generate_optimization_report(report_output)
            report_path = str(report_output)
            if report_dir and report_output.is_absolute() and report_dir in report_output.parents:
                report_path = str(report_output.relative_to(report_dir))
            result["object_profile"] = {
                "success": True,
                "report_path": report_path,
                "summary": report,
            }
        except Exception as exc:
            result["object_profile"] = {
                "success": False,
                "error": str(exc),
            }

def _write_dfg_paths_file(analysis_result: Dict[str, Any], report_dir: Path) -> None:
    """
    Write dfg_paths.txt file containing Joern reachableByFlows data 
    AND framework's taint tracking results.
    
    Args:
        analysis_result: Analysis result dictionary from framework
        report_dir: Directory where report files are written
    """
    report_dir.mkdir(parents=True, exist_ok=True)
    
    content = "═══════════════════════════════════════════════════════════════\n"
    content += "  DATA FLOW PATHS ANALYSIS (Joern reachableByFlows)\n"
    content += "═══════════════════════════════════════════════════════════════\n\n"

    joern_dataflow = analysis_result.get("joern_dataflow", {}) or {}
    flows_by_sink = joern_dataflow.get("flows_by_sink", {}) if isinstance(joern_dataflow, dict) else {}
    if isinstance(flows_by_sink, dict) and flows_by_sink:
        total_flows = 0
        content += "[✓] Joern reachableByFlows summary\n\n"
        for sink_name, payload in flows_by_sink.items():
            if not isinstance(payload, dict):
                continue
            flows = int(payload.get("flows", 0) or 0)
            sources = int(payload.get("sources", 0) or 0)
            sinks = int(payload.get("sinks", 0) or 0)
            total_flows += flows
            content += "──────────────────────────────────────────────────────────────\n"
            content += f"SINK TYPE: {sink_name}\n"
            content += f"Sources: {sources} | Sinks: {sinks} | Reachable Flows: {flows}\n"
            content += "──────────────────────────────────────────────────────────────\n\n"
        content += f"Total reachable flows: {total_flows}\n\n"
    else:
        content += "[!] No Joern reachableByFlows data available for this file\n\n"

    content += "═══════════════════════════════════════════════════════════════\n"
    content += f"Analysis completed. Output: {report_dir}/dfg_paths.txt\n"
    content += "═══════════════════════════════════════════════════════════════\n"
    
    # Append framework's taint tracking results
    taint_tracking = analysis_result.get('taint_tracking', {})
    taint_flows = taint_tracking.get('taint_flows', [])
    
    if taint_flows:
        content += "\n\n"
        content += "═══════════════════════════════════════════════════════════════\n"
        content += "  FRAMEWORK TAINT TRACKING (Bean Vulnerable Analysis)\n"
        content += "═══════════════════════════════════════════════════════════════\n\n"
        content += f"[✓] Found {len(taint_flows)} taint flow(s) from sources\n\n"
        
        for i, flow in enumerate(taint_flows, 1):
            target = flow.get('target', 'unknown')
            source = flow.get('source', 'unknown')
            is_sanitized = flow.get('is_sanitized', False)
            implicit = flow.get('implicit_flow', False)
            
            content += f"──────────────────────────────────────────────────────────────\n"
            content += f"TAINT FLOW {i}: {target}\n"
            content += f"Source: {source}\n"
            content += f"Sanitized: {'Yes' if is_sanitized else 'No'}\n"
            content += f"Implicit Flow: {'Yes' if implicit else 'No'}\n"
            content += f"──────────────────────────────────────────────────────────────\n\n"
        
        content += "═══════════════════════════════════════════════════════════════\n"
        content += f"Analysis completed. Total taint flows: {len(taint_flows)}\n"
        content += "═══════════════════════════════════════════════════════════════\n"
    
    # Write to file
    (report_dir / 'dfg_paths.txt').write_text(content, encoding='utf-8')
    LOG.info(f"📄 Generated dfg_paths.txt with {len(taint_flows)} taint flows")

def main():
    """
    Enhanced main function with comprehensive edge extraction.
    """
    ap = argparse.ArgumentParser(
        prog="bean-vuln",
        description="Bean Vulnerable Framework - Heuristic analysis (GNN modules experimental)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    ap.add_argument("input", nargs="+", 
                    help="Java files, directories, or VUL4J CSV files to analyze")
    ap.add_argument("-r", "--recursive", action="store_true",
                    help="Scan directories recursively")
    ap.add_argument("-o", "--out", 
                    help="Output JSON file path")
    ap.add_argument("--summary", action="store_true",
                    help="Print summary for each input")
    ap.add_argument("--html-report",
                    help="Generate HTML report in specified directory (auto-opens in browser)")
    ap.add_argument("--export-cpg",
                    help="Export CPG files to directory")
    ap.add_argument("--export-dfg", action="store_true",
                    help="Export DFG (Data Flow Graph) visualizations")
    ap.add_argument("--export-cfg", action="store_true",
                    help="Export CFG (Control Flow Graph) visualizations")
    ap.add_argument("--export-pdg", action="store_true",
                    help="Export PDG (Program Dependence Graph) visualizations")
    ap.add_argument("--verbose", action="store_true",
                    help="Enable verbose logging")
    ap.add_argument("--keep-workdir", action="store_true",
                    help="Keep temporary directories")
    ap.add_argument("--ensemble", action="store_true",
                    help="Enable ensemble methods (experimental; no trained GNN weights yet)")
    ap.add_argument("--advanced-features", action="store_true",
                    help="Enable advanced feature engineering (experimental; not used in scoring)")
    ap.add_argument("--spatial-gnn", action="store_true", default=True,
                    help="Enable spatial GNN inference (default; requires torch + torch-geometric)")
    ap.add_argument("--no-spatial-gnn", action="store_false", dest="spatial_gnn",
                    help="Deprecated: spatial GNN is always enabled")
    ap.add_argument("--gnn-checkpoint",
                    action="append",
                    help="Path to Spatial GNN checkpoint (trained weights for inference)")
    ap.add_argument("--gnn-weight", type=float, default=0.6,
                    help="Weight for GNN confidence in final scoring (default: 0.6)")
    ap.add_argument("--gnn-confidence-threshold", type=float, default=0.5,
                    help="Minimum combined confidence to report a vulnerability when GNN weights are loaded")
    ap.add_argument("--gnn-temperature", type=float, default=1.0,
                    help="Temperature for calibrating GNN confidence (default: 1.0)")
    ap.add_argument("--gnn-ensemble", type=int, default=1,
                    help="Number of GNN checkpoints to use in ensemble (default: 1)")
    ap.add_argument("--joern-dataflow", action="store_true",
                    help="Enable Joern reachableByFlows dataflow extraction for gating")
    ap.add_argument("--joern-timeout", type=int, default=480, metavar="SECONDS",
                    help="Timeout for Joern operations in seconds (default: 480, use higher values for training data preparation)")
    ap.add_argument("--tai-e", action="store_true",
                    help="Enable Tai-e object-sensitive pointer analysis (requires Tai-e installed)")
    ap.add_argument("--tai-e-home",
                    help="Path to Tai-e installation (or set TAI_E_HOME)")
    ap.add_argument("--tai-e-main",
                    help="Tai-e main class (fully-qualified, must define main(String[]))")
    ap.add_argument("--tai-e-cs", default="1-obj",
                    help="Tai-e context sensitivity (e.g., 1-obj, 2-obj, 1-type)")
    ap.add_argument("--tai-e-timeout", type=int, default=300,
                    help="Tai-e pointer analysis timeout in seconds (default: 300)")
    ap.add_argument("--tai-e-only-app", action="store_true", default=True,
                    help="Analyze application classes only (default: true)")
    ap.add_argument("--tai-e-all-classes", action="store_false", dest="tai_e_only_app",
                    help="Include library classes in Tai-e analysis")
    ap.add_argument("--tai-e-allow-phantom", action="store_true", default=True,
                    help="Allow phantom references in Tai-e (default: true)")
    ap.add_argument("--tai-e-no-phantom", action="store_false", dest="tai_e_allow_phantom",
                    help="Disable phantom references in Tai-e")
    ap.add_argument("--tai-e-prepend-jvm", action="store_true", default=True,
                    help="Use current JVM classpath for Tai-e (default: true)")
    ap.add_argument("--tai-e-no-prepend-jvm", action="store_false", dest="tai_e_prepend_jvm",
                    help="Do not prepend JVM classpath in Tai-e")
    ap.add_argument("--tai-e-java-version", type=int,
                    help="Tai-e -java version (uses bundled Java libs if available)")
    ap.add_argument("--tai-e-classpath",
                    help="Additional classpath for Tai-e compilation (javac -cp)")
    ap.add_argument("--tai-e-taint", action="store_true",
                    help="Enable Tai-e taint analysis (requires taint config)")
    ap.add_argument("--tai-e-taint-config",
                    help="Path to Tai-e taint config (file or directory)")
    ap.add_argument("--tai-e-soundness", action="store_true",
                    help="Run Tai-e soundness validation using runtime logging")
    ap.add_argument("--tai-e-soundness-output",
                    help="Path to write Tai-e soundness HTML report")
    ap.add_argument("--taint-graph", action="store_true",
                    help="Generate interactive taint flow graph HTML")
    ap.add_argument("--taint-graph-output",
                    help="Path to write taint flow graph HTML")
    ap.add_argument("--taint-debug", action="store_true",
                    help="Launch interactive taint debugger (single input only)")
    ap.add_argument("--tai-e-precision-diagnose", action="store_true",
                    help="Run heuristic precision diagnosis for Tai-e runs")
    ap.add_argument("--tai-e-profile", action="store_true",
                    help="Run Tai-e profiling harness (best-effort, optional tools)")
    ap.add_argument("--tai-e-profile-output",
                    help="Directory (or .html file) for profiling report output")
    ap.add_argument("--async-profiler-path",
                    help="Path to async-profiler agent (enables CPU profiling)")
    ap.add_argument("--yourkit-agent-path",
                    help="Path to YourKit agent (enables memory profiling)")
    ap.add_argument("--profile-jfr", action="store_true",
                    help="Enable JVM Flight Recorder collection during profiling")
    ap.add_argument("--profile-system", action="store_true",
                    help="Enable system-level sampling during profiling")
    ap.add_argument("--profile-max-heap",
                    help="Set JVM -Xmx for profiling runs (e.g. 8g)")
    ap.add_argument("--profile-min-heap",
                    help="Set JVM -Xms for profiling runs (e.g. 2g)")
    ap.add_argument("--object-profile",
                    help="Path to YourKit snapshot or CSV export for object profiling")
    ap.add_argument("--object-profile-output",
                    help="Path to write object profiling HTML report")
    ap.add_argument("--explain", action="store_true",
                    help="Generate counterfactual explanations (minimal code changes to remove vulnerabilities)")
    ap.add_argument("--comprehensive", action="store_true",
                    help="Run full analysis with all features (ensemble + advanced-features + spatial-gnn + explain)")
    
    args = ap.parse_args()
    if args.tai_e_taint_config:
        args.tai_e_taint = True
    if args.tai_e_taint and not args.tai_e_taint_config:
        default_taint_config = (
            Path(__file__).resolve().parents[2]
            / "configs"
            / "tai_e"
            / "taint"
            / "web-vulnerabilities.yml"
        )
        if default_taint_config.exists():
            args.tai_e_taint_config = str(default_taint_config)
        else:
            LOG.warning("Tai-e taint enabled but no config found; skipping taint analysis.")
            args.tai_e_taint = False
    _maybe_prompt_tai_e_home(args)
    if not args.spatial_gnn:
        LOG.warning("⚠️ Ignoring --no-spatial-gnn; spatial GNN is always enabled.")
        args.spatial_gnn = True
    
    # Handle --comprehensive flag
    if args.comprehensive:
        LOG.info("🎯 Comprehensive mode enabled: ensemble + advanced-features + spatial-gnn + explain")
        args.ensemble = True
        args.advanced_features = True
        args.spatial_gnn = True
        args.explain = True
    
    # Initialize framework with CLI flags
    global fw
    fw = IntegratedGNNFramework(
        enable_ensemble=args.ensemble,
        enable_advanced_features=args.advanced_features,
        enable_spatial_gnn=args.spatial_gnn,
        enable_explanations=args.explain,
        joern_timeout=args.joern_timeout,
        gnn_checkpoint=args.gnn_checkpoint,
        gnn_weight=args.gnn_weight,
        gnn_confidence_threshold=args.gnn_confidence_threshold,
        gnn_temperature=args.gnn_temperature,
        gnn_ensemble=args.gnn_ensemble,
        enable_joern_dataflow=args.joern_dataflow,
        enable_tai_e=args.tai_e,
        tai_e_home=args.tai_e_home,
        tai_e_cs=args.tai_e_cs,
        tai_e_main=args.tai_e_main,
        tai_e_timeout=args.tai_e_timeout,
        tai_e_only_app=args.tai_e_only_app,
        tai_e_allow_phantom=args.tai_e_allow_phantom,
        tai_e_prepend_jvm=args.tai_e_prepend_jvm,
        tai_e_java_version=args.tai_e_java_version,
        tai_e_classpath=args.tai_e_classpath,
        tai_e_enable_taint=args.tai_e_taint,
        tai_e_taint_config=args.tai_e_taint_config,
    )
    
    # Setup HTML report directory
    if args.html_report:
        try:
            report_dir = _prepare_report_dir(Path(args.html_report))
        except ValueError as exc:
            LOG.error(str(exc))
            sys.exit(2)
        LOG.info(f"📁 HTML report directory: {report_dir}")
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        LOG.setLevel(logging.DEBUG)
    
    export_dir = Path(args.export_cpg).expanduser() if args.export_cpg else None
    if export_dir:
        export_dir.mkdir(parents=True, exist_ok=True)
    
    analysis_caption = "heuristic-only"
    if getattr(fw, "spatial_gnn_model", None):
        analysis_caption = "heuristic + GNN (untrained)"
        if getattr(fw, "gnn_weights_loaded", False):
            analysis_caption = "heuristic + GNN (weighted)"
    print(f"🎯 Bean Vulnerable Framework - CLI Analysis ({analysis_caption})")
    print(f"📁 Analyzing {len(args.input)} input(s)...")
    print("=" * 60)
    
    results = []
    start_time = time.time()
    
    for i, raw_input in enumerate(args.input, 1):
        p = Path(raw_input).expanduser().resolve()
        
        if not p.exists():
            print(f"❌ Input {i}: {p} not found")
            continue
            
        print(f"🔍 Input {i}: {p}")
                
                # Analyze with enhanced edge extraction
        result = analyze_path(
            p,
            args.recursive,
            args.keep_workdir,
            export_dir,
            args,
            report_dir if args.html_report else None,
        )
        
        # Export graphs if requested OR if HTML report is requested (auto-enable all graphs)
        # Research: Comprehensive visualization is essential for vulnerability analysis (ACM 2024)
        auto_enable_graphs = args.html_report and not (args.export_dfg or args.export_cfg or args.export_pdg)
        if auto_enable_graphs:
            LOG.info("📊 Auto-enabling all graphs (CFG+DFG+PDG) for HTML report...")
            args.export_dfg = args.export_cfg = args.export_pdg = True
        
        if args.html_report and (args.export_dfg or args.export_cfg or args.export_pdg):
            report_dir = Path(args.html_report).expanduser()
            LOG.info(f"🎨 Generating comprehensive graphs for {p.name}...")
            
            try:
                # Use the COMPREHENSIVE Joern script for detailed graphs
                script_path = Path(__file__).parent.parent.parent / "comprehensive_graphs.sc"
                env = os.environ.copy()
                env['SOURCE_FILE'] = str(p.absolute())
                env['OUTPUT_DIR'] = str(report_dir.absolute())
                
                LOG.info(f"📊 Running comprehensive graph generation (all methods, interprocedural)...")
                # Run Joern script in an isolated workspace
                with tempfile.TemporaryDirectory() as joern_workdir:
                    graph_result = subprocess.run(
                        ['/usr/local/bin/joern', '--script', str(script_path)],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=120,
                        cwd=joern_workdir,
                    )
                if graph_result.stdout:
                    LOG.debug(f"Joern output: {graph_result.stdout}")
                if graph_result.stderr:
                    LOG.warning(f"Joern warnings: {graph_result.stderr}")
                
                # Convert ALL .dot files to PNG and SVG (auto-discover)
                dot_files = list(report_dir.glob('*.dot'))
                for dot_file in dot_files:
                    _colorize_dot_file(dot_file)
                LOG.info(f"🎨 Converting {len(dot_files)} DOT files to PNG/SVG...")
                
                for dot_file in dot_files:
                    graph_name = dot_file.stem  # filename without extension
                    
                    # PNG conversion
                    png_file = report_dir / f"{graph_name}.png"
                    if not png_file.exists() or png_file.stat().st_size == 0:
                        try:
                            subprocess.run(['dot', '-Tpng', str(dot_file), '-o', str(png_file)], timeout=30, check=True)
                            LOG.debug(f"  ✓ {graph_name}.png")
                        except:
                            try:
                                subprocess.run(['/opt/homebrew/bin/dot', '-Tpng', str(dot_file), '-o', str(png_file)], timeout=30, check=True)
                                LOG.debug(f"  ✓ {graph_name}.png")
                            except Exception as e:
                                LOG.warning(f"  ✗ Failed to convert {graph_name}.dot to PNG: {e}")
                    
                    # SVG conversion
                    svg_file = report_dir / f"{graph_name}.svg"
                    if not svg_file.exists() or svg_file.stat().st_size == 0:
                        try:
                            subprocess.run(['dot', '-Tsvg', str(dot_file), '-o', str(svg_file)], timeout=30, check=True)
                        except:
                            try:
                                subprocess.run(['/opt/homebrew/bin/dot', '-Tsvg', str(dot_file), '-o', str(svg_file)], timeout=30, check=True)
                            except:
                                pass
                
                LOG.info(f"✅ Graphs exported to {report_dir}")
            except Exception as e:
                LOG.error(f"Failed to export graphs: {e}")
        
        # Extract metrics for summary
        cpg_data = result.get('cpg', {})
        node_count = cpg_data.get('nodes', 0)
        edge_count = cpg_data.get('edges', 0)  # FIXED: This should now show real edge count
        confidence = result.get('confidence', 0.0)
        vulnerable = result.get('vulnerability_detected', False)
        gnn_used = bool(result.get('gnn_utilized', False))
        
        if args.summary:
            vuln_status = "🚨" if vulnerable else "✅"
            heuristic_conf = result.get("heuristic_confidence")
            if not isinstance(heuristic_conf, (int, float)):
                heuristic_conf = confidence
            gnn_status = _format_gnn_status(result, gnn_enabled_flag=args.spatial_gnn)
            print(
                f"   {vuln_status} Nodes: {node_count}, Edges: {edge_count}, "
                f"Heuristic: {heuristic_conf:.3f}, GNN: {gnn_status}, "
                f"Final: {confidence:.3f}, Vulnerable: {vulnerable}"
            )
        
        # Add metadata
        result.update({
            'input': str(p),
            'input_type': 'file' if p.is_file() else 'directory'
        })
        
        results.append(result)
    
    total_time = time.time() - start_time
    
    print("=" * 60)
    print(f"⏱️  Total analysis time: {total_time:.2f}s")
    print(f"📊 Processed {len(results)} input(s)")
    
    # Generate HTML report if requested
    if args.html_report and results:
        LOG.info("📝 Generating HTML report...")
        try:
            from src.core.html_report_generator import generate_comprehensive_html_report
        except ImportError:
            from core.html_report_generator import generate_comprehensive_html_report
        
        command_line = f"bean-vuln {' '.join(args.input)}"
        if args.summary:
            command_line += " --summary"
        if args.html_report:
            command_line += f" --html-report {args.html_report}"
        
        # Generate dfg_paths.txt with framework's taint flows
        report_dir = Path(args.html_report)
        _write_dfg_paths_file(results[0], report_dir)
        
        report_path = generate_comprehensive_html_report(results[0], Path(args.html_report), command_line)
        LOG.info(f"✅ HTML report generated: {report_path}")
        
        # Auto-open in browser
        try:
            webbrowser.open(f"file://{report_path.absolute()}")
            LOG.info("🌐 Report opened in browser")
        except Exception as e:
            LOG.warning(f"Could not auto-open browser: {e}")
    
    # Generate final output
    output_data = results
    
    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        print(f"📄 Results saved to: {output_path}")
    else:
        print("📄 JSON Results:")
        print(json.dumps(output_data, indent=2, default=str))


if __name__ == "__main__":
    main()


