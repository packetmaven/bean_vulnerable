#!/usr/bin/env python3

"""
Bean Vulnerable Framework - Enhanced CLI (experimental stubs)
==========================================================================================

Experimental stubs for concolic execution, RL path prioritization, and GNN modules; not integrated into scoring.
Based on analysis of 400+ Java vulnerability discovery research papers (2024-2025).

Key Enhancements:
- Static heuristic analysis baseline (no trained GNN inference)
- Hybrid concolic execution for logic bug detection (stub)
- Reinforcement learning path exploration (stub)
- Property-based testing integration (stub)
- Advanced dynamic taint tracking (experimental)
- Spatial GNN module initialization (experimental)
- Multi-dataset support and evaluation
Version: 2.0.0 (Enhanced)
"""

import argparse
import json
import sys
import time
import tempfile
import shutil
import subprocess
import os
import re
import asyncio
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Union, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import random
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing

from core.soundness_testing.runner import run_soundness_validation
from core.taint_debugging.taint_flow_visualizer import write_taint_graph
from core.taint_debugging.interactive_cli import launch_debugger_from_result
from core.precision_debugging.diagnosis import analyze_source
from core.performance.profiling_harness import ProfilingConfiguration, MultiLayerProfiler
from core.performance.object_profiler import ObjectCentricProfiler

try:
    from extensions.aeg_java_bridge import run_aeg_lite_java
    AEG_LITE_JAVA_AVAILABLE = True
except Exception:
    run_aeg_lite_java = None
    AEG_LITE_JAVA_AVAILABLE = False

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bean_vulnerable.log'),
        logging.StreamHandler()
    ]
)
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

# Import enhanced framework components
try:
    from src.core.integrated_gnn_framework import IntegratedGNNFramework
    from src.integrations.vul4j_parser import FixedVul4JParser
except ImportError as e:
    try:
        from core.integrated_gnn_framework import IntegratedGNNFramework
        from integrations.vul4j_parser import FixedVul4JParser
    except ImportError as e2:
        # Add parent directory to path for direct script execution
        import sys
        from pathlib import Path
        parent_dir = Path(__file__).resolve().parent.parent.parent
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))
        try:
            from src.core.integrated_gnn_framework import IntegratedGNNFramework
            from src.integrations.vul4j_parser import FixedVul4JParser
        except ImportError as e3:
            LOG.error(f"Enhanced framework components not found: {e3}")
            LOG.info("Please ensure you're running from the repository root or PYTHONPATH is set")
            sys.exit(1)

# Analysis mode enumeration
class AnalysisMode(Enum):
    STATIC_ONLY = "static"
    DYNAMIC_ONLY = "dynamic"
    HYBRID = "hybrid"
    CONCOLIC = "concolic"
    PROPERTY_BASED = "property"
    COMPREHENSIVE = "comprehensive"

@dataclass
class AnalysisConfiguration:
    """Enhanced analysis configuration with research-based optimizations"""
    mode: AnalysisMode
    enable_concolic: bool = False
    enable_rl_prioritization: bool = False  
    enable_property_testing: bool = False
    enable_taint_tracking: bool = False
    enable_ensemble_gnn: bool = False
    max_exploration_depth: int = 50
    concolic_timeout: int = 300
    rl_episodes: int = 100
    property_test_rounds: int = 1000
    parallel_workers: int = multiprocessing.cpu_count()
    
@dataclass  
class VulnerabilityResult:
    """Enhanced vulnerability result with detailed metadata"""
    vulnerability_detected: bool
    confidence: float
    vulnerability_type: str
    severity: str
    explanation: str
    detection_method: str  # NEW: track which method found it
    analysis_time: float
    graph_metrics: Dict[str, int]
    logic_flaws: List[Dict] = None      # NEW: logic vulnerabilities
    taint_flows: List[Dict] = None      # NEW: taint tracking results  
    property_violations: List[Dict] = None  # NEW: property test failures
    concolic_paths: List[Dict] = None   # NEW: symbolic execution paths
    confidence_breakdown: Dict[str, float] = None  # NEW: per-method confidence

class EnhancedPathExplorer:
    """
    Reinforcement Learning-based path exploration for intelligent vulnerability discovery.
    Based on recent research in RL-guided symbolic execution and path prioritization.
    """
    
    def __init__(self, exploration_budget: int = 1000):
        self.exploration_budget = exploration_budget
        self.path_history = []
        self.vulnerability_discoveries = []
        self.q_table = {}  # Simple Q-learning for path selection
        self.epsilon = 0.1  # Exploration rate
        self.learning_rate = 0.01
        self.discount_factor = 0.95
        
    def extract_path_features(self, path_info: Dict) -> List[float]:
        """Extract 128-dimensional feature vector for path prioritization"""
        features = [
            path_info.get('depth', 0),
            path_info.get('branch_count', 0), 
            path_info.get('loop_count', 0),
            path_info.get('method_call_count', 0),
            path_info.get('has_sensitive_operations', 0),
            path_info.get('complexity_score', 0),
            len(self.path_history),  # Historical context
            len(self.vulnerability_discoveries),  # Success history
        ]
        # Pad to 128 dimensions with normalized values
        features.extend([0.0] * (128 - len(features)))
        return features
    
    def select_next_path(self, available_paths: List[Dict]) -> Dict:
        """RL-based path selection using epsilon-greedy strategy"""
        if not available_paths:
            return None
            
        if random.random() < self.epsilon:
            # Exploration: random selection
            selected_path = random.choice(available_paths)
            LOG.debug("RL Explorer: Random path selection (exploration)")
        else:
            # Exploitation: select best known path
            best_path = None
            best_score = float('-inf')
            
            for path in available_paths:
                features = self.extract_path_features(path)
                path_key = str(hash(str(features[:8])))  # Use first 8 features as key
                score = self.q_table.get(path_key, 0.0)
                
                if score > best_score:
                    best_score = score
                    best_path = path
                    
            selected_path = best_path or available_paths[0]
            LOG.debug(f"RL Explorer: Best path selected with score {best_score}")
        
        # Record path selection
        self.path_history.append(selected_path)
        return selected_path
    
    def update_policy(self, path: Dict, reward: float):
        """Update Q-table based on vulnerability discovery results"""
        features = self.extract_path_features(path)
        path_key = str(hash(str(features[:8])))
        
        current_q = self.q_table.get(path_key, 0.0)
        self.q_table[path_key] = current_q + self.learning_rate * reward
        
        if reward > 0:
            self.vulnerability_discoveries.append({
                'path': path,
                'reward': reward,
                'timestamp': datetime.now()
            })
            LOG.info(f"RL Explorer: Policy updated with reward {reward}")

class PropertyBasedTester:
    """
    Property-based testing for security invariants and business logic validation.
    Inspired by jqwik and modern property-based testing research.
    """
    
    def __init__(self):
        self.security_properties = {}
        self.test_results = []
        
    def define_security_properties(self, java_code: str) -> Dict[str, Any]:
        """Define security properties that must hold for all execution paths"""
        properties = {
            'authorization_check': {
                'description': 'All privileged operations must have authorization checks',
                'pattern': r'(delete|admin|sensitive).*\([^)]*\)',
                'requires_auth': r'(auth|permission|check)',
                'severity': 'HIGH'
            },
            'input_validation': {
                'description': 'All user inputs must be validated and sanitized', 
                'pattern': r'(request\.getParameter|input|user)',
                'requires_validation': r'(validate|sanitize|escape)',
                'severity': 'HIGH'
            },
            'sql_injection_prevention': {
                'description': 'Database queries must use parameterized statements',
                'pattern': r'(Statement|createStatement)',
                'avoid_concat': r'\+.*["\']',
                'severity': 'CRITICAL'
            },
            'crypto_strength': {
                'description': 'Cryptographic operations must use strong algorithms',
                'pattern': r'(Cipher|MessageDigest|KeyGenerator)',
                'weak_algorithms': r'(DES|MD5|SHA1)',
                'severity': 'MEDIUM'
            }
        }
        
        self.security_properties = properties
        return properties
    
    async def validate_properties(self, java_code: str, properties: Dict) -> List[Dict]:
        """Validate security properties using automated test generation"""
        violations = []
        
        for prop_name, prop_spec in properties.items():
            try:
                # Simulate property-based test execution
                violation_found = await self._test_property(java_code, prop_spec)
                
                if violation_found:
                    violations.append({
                        'property': prop_name,
                        'description': prop_spec['description'],
                        'severity': prop_spec['severity'],
                        'violation_type': violation_found['type'],
                        'evidence': violation_found['evidence'],
                        'suggested_fix': violation_found.get('fix', 'Manual review required')
                    })
                    
            except Exception as e:
                LOG.warning(f"Property validation failed for {prop_name}: {e}")
                
        return violations
    
    async def _test_property(self, java_code: str, prop_spec: Dict) -> Optional[Dict]:
        """Execute property-based tests for a specific security property"""
        import re
        
        # Pattern-based property checking (simplified implementation)
        if 'pattern' in prop_spec and 'requires_auth' in prop_spec:
            # Authorization property test
            sensitive_ops = re.findall(prop_spec['pattern'], java_code, re.IGNORECASE)
            if sensitive_ops:
                auth_checks = re.findall(prop_spec['requires_auth'], java_code, re.IGNORECASE)
                if len(auth_checks) < len(sensitive_ops):
                    return {
                        'type': 'missing_authorization',
                        'evidence': f"Found {len(sensitive_ops)} sensitive operations but only {len(auth_checks)} auth checks",
                        'fix': 'Add authorization checks before sensitive operations'
                    }
        
        # SQL injection property test  
        if 'avoid_concat' in prop_spec:
            concat_patterns = re.findall(prop_spec['avoid_concat'], java_code)
            stmt_patterns = re.findall(prop_spec['pattern'], java_code, re.IGNORECASE)
            if concat_patterns and stmt_patterns:
                return {
                    'type': 'sql_injection_risk',
                    'evidence': f"Found string concatenation in SQL context: {concat_patterns[:3]}",
                    'fix': 'Use PreparedStatement with parameterized queries'
                }
                
        return None

def extract_edge_data_comprehensive(analysis_result: Any) -> Dict[str, int]:
    """
    Enhanced edge data extraction with support for new graph types and analysis results.
    Handles hybrid analysis results from multiple detection methods.
    """
    metrics = {
        'node_count': 0,
        'edge_count': 0, 
        'method_count': 0,
        'call_count': 0,
        'cfg_count': 0,
        'dfg_edges': 0,      # NEW: Data flow edges
        'cdg_edges': 0,      # NEW: Control dependency edges  
        'pdg_edges': 0,      # NEW: Program dependency edges
        'taint_flows': 0,    # NEW: Taint flow count
        'symbolic_paths': 0,  # NEW: Symbolic execution paths
    }
    
    try:
        LOG.debug("🔍 Enhanced edge data extraction from analysis result")
        
        # Handle enhanced result objects with multiple analysis methods
        if hasattr(analysis_result, '__dict__'):
            tech_details = getattr(analysis_result, 'technical_details', {})
            
            # Extract traditional metrics
            for key in ['cpg_edges', 'edge_count', 'num_edges', 'graph_edges']:
                if key in tech_details:
                    metrics['edge_count'] = tech_details[key]
                    break
            
            # Extract enhanced metrics from hybrid analysis
            hybrid_results = getattr(analysis_result, 'hybrid_results', {})
            if hybrid_results:
                metrics['taint_flows'] = hybrid_results.get('taint_flow_count', 0)
                metrics['symbolic_paths'] = hybrid_results.get('symbolic_path_count', 0)
                
                # Graph-specific edge counts
                graph_metrics = hybrid_results.get('graph_metrics', {})
                metrics['dfg_edges'] = graph_metrics.get('data_flow_edges', 0)
                metrics['cdg_edges'] = graph_metrics.get('control_dependency_edges', 0) 
                metrics['pdg_edges'] = graph_metrics.get('program_dependency_edges', 0)
            
            # Extract from CPG data structure
            cpg_data = getattr(analysis_result, 'cpg', {})
            if isinstance(cpg_data, dict):
                metrics['node_count'] = cpg_data.get('nodes', 0) if isinstance(cpg_data.get('nodes'), int) else len(cpg_data.get('nodes', []))
                metrics['edge_count'] = metrics['edge_count'] or cpg_data.get('edges', 0)
                metrics['method_count'] = cpg_data.get('methods', 0)
                metrics['call_count'] = cpg_data.get('calls', 0)
                
        # Handle enhanced dictionary results
        elif isinstance(analysis_result, dict):
            # Standard metrics extraction
            tech_details = analysis_result.get('technical_details', {})
            cpg_data = analysis_result.get('cpg', {})
            
            # Extract CPG metrics
            if cpg_data:
                metrics['node_count'] = cpg_data.get('nodes', 0)
                metrics['edge_count'] = cpg_data.get('edges', 0)
                metrics['method_count'] = cpg_data.get('methods', 0)
                metrics['call_count'] = cpg_data.get('calls', 0)
                metrics['dfg_edges'] = cpg_data.get('dfg', 0)
            
            # Fallback to technical_details
            if not metrics['edge_count']:
                metrics['edge_count'] = (
                    tech_details.get('cpg_edges') or
                    analysis_result.get('edge_count', 0)
                )
            
            # Extract taint tracking metrics
            taint_tracking = analysis_result.get('taint_tracking', {})
            if taint_tracking:
                metrics['taint_flows'] = taint_tracking.get('taint_flows_count', 0)
            
            # Enhanced metrics from hybrid analysis
            if 'hybrid_analysis' in analysis_result:
                hybrid_data = analysis_result['hybrid_analysis']
                metrics.update({
                    'taint_flows': hybrid_data.get('taint_flows', metrics['taint_flows']),
                    'symbolic_paths': hybrid_data.get('symbolic_paths', 0),
                    'dfg_edges': hybrid_data.get('dfg_edges', metrics['dfg_edges']),
                    'cdg_edges': hybrid_data.get('cdg_edges', 0),
                    'pdg_edges': hybrid_data.get('pdg_edges', 0)
                })
        
        # Calculate total enhanced edge count
        total_enhanced_edges = (
            metrics['edge_count'] + metrics['dfg_edges'] + 
            metrics['cdg_edges'] + metrics['pdg_edges']
        )
        
        if total_enhanced_edges > metrics['edge_count']:
            metrics['edge_count'] = total_enhanced_edges
            
        LOG.info(f"📊 Enhanced metrics extracted: {metrics}")
        return metrics
        
    except Exception as e:
        LOG.error(f"❌ Enhanced edge extraction failed: {e}")
        return metrics

async def analyze_path_enhanced(p: Path, config: AnalysisConfiguration, 
                               fw: Any, hybrid_analyzer: Optional[Any] = None) -> Tuple[VulnerabilityResult, Dict[str, Any]]:
    """
    Enhanced path analysis (experimental stub).
    Hybrid dynamic testing, concolic execution, and RL path exploration are
    simulated placeholders and do not invoke real engines.
    """
    if not p.exists():
        error_result = VulnerabilityResult(
            vulnerability_detected=False,
            confidence=0.0,
            vulnerability_type="FileNotFound", 
            severity="ERROR",
            explanation=f"File not found: {p}",
            detection_method="filesystem_check",
            analysis_time=0.0,
            graph_metrics={'nodes': 0, 'edges': 0}
        )
        return error_result, {}
    
    start_time = time.time()
    LOG.info(f"🔍 Enhanced analysis starting: {p.name}")
    
    try:
        # Initialize components based on configuration
        results = {}
        detection_methods = []
        
        # Phase 1: Static heuristic analysis (baseline)
        if config.mode in [AnalysisMode.STATIC_ONLY, AnalysisMode.HYBRID, AnalysisMode.COMPREHENSIVE]:
            LOG.info("📊 Running static heuristic analysis (no trained GNN inference)...")
            if p.suffix == ".java":
                source_code = p.read_text(encoding='utf-8', errors='ignore')
                static_result = fw.analyze_code(source_code=source_code, source_path=str(p))
                LOG.debug(f"Static result keys: {static_result.keys() if isinstance(static_result, dict) else 'not a dict'}")
                LOG.debug(f"Vulnerability detected: {static_result.get('vulnerability_detected', 'N/A')}")
                LOG.debug(f"Confidence: {static_result.get('confidence', 'N/A')}")
                LOG.debug(f"Type: {static_result.get('vulnerability_type', 'N/A')}")
                results['static_heuristic'] = static_result
                detection_methods.append("static_heuristic")
        
        # Phase 2: Hybrid Dynamic Analysis
        if hybrid_analyzer and config.mode in [AnalysisMode.HYBRID, AnalysisMode.COMPREHENSIVE]:
            LOG.info("🔄 Running hybrid dynamic analysis...")
            try:
                hybrid_result = await hybrid_analyzer.detect_logic_vulnerabilities(str(p))
                results['hybrid'] = hybrid_result
                detection_methods.append("hybrid_dynamic")
            except Exception as e:
                LOG.warning(f"Hybrid analysis failed: {e}")
        
        # Phase 3: Property-Based Testing
        if config.enable_property_testing and config.mode in [AnalysisMode.PROPERTY_BASED, AnalysisMode.COMPREHENSIVE]:
            LOG.info("🧪 Running property-based testing...")
            property_tester = PropertyBasedTester()
            if p.suffix == ".java":
                source_code = p.read_text(encoding='utf-8', errors='ignore')
                properties = property_tester.define_security_properties(source_code)
                property_violations = await property_tester.validate_properties(source_code, properties)
                results['property'] = {'violations': property_violations}
                detection_methods.append("property_based")
        
        # Phase 4: Enhanced Path Exploration with RL
        if config.enable_rl_prioritization:
            LOG.info("🤖 Running RL-guided path exploration...")
            path_explorer = EnhancedPathExplorer()
            # Simulate path exploration (would integrate with actual symbolic execution)
            mock_paths = [
                {'depth': i*5, 'branch_count': i*2, 'complexity_score': i*10} 
                for i in range(1, 6)
            ]
            best_path = path_explorer.select_next_path(mock_paths)
            if best_path:
                results['rl_exploration'] = {'selected_path': best_path}
                detection_methods.append("rl_guided")
        
        # Consolidate results
        LOG.info(f"🔄 Consolidating results from {len(detection_methods)} methods: {detection_methods}")
        LOG.debug(f"Results keys: {results.keys()}")
        final_result = consolidate_analysis_results(results, detection_methods)
        final_result.analysis_time = time.time() - start_time
        LOG.info(f"✅ Final result: vuln={final_result.vulnerability_detected}, conf={final_result.confidence:.3f}")
        
        # Extract enhanced metrics
        enhanced_metrics = extract_edge_data_comprehensive(results.get('static_heuristic', {}))
        final_result.graph_metrics = enhanced_metrics
        
        LOG.info(f"✅ Enhanced analysis completed in {final_result.analysis_time:.2f}s")
        
        # Return both the enhanced result and the original framework result for HTML report
        original_framework_result = results.get('static_heuristic', {})
        return final_result, original_framework_result
        
    except Exception as e:
        LOG.error(f"❌ Enhanced analysis failed for {p}: {e}")
        error_result = VulnerabilityResult(
            vulnerability_detected=False,
            confidence=0.0,
            vulnerability_type="AnalysisError",
            severity="ERROR", 
            explanation=str(e),
            detection_method="error_handling",
            analysis_time=time.time() - start_time,
            graph_metrics={'nodes': 0, 'edges': 0}
        )
        return error_result, {}

def _apply_debug_utilities_enhanced(
    fw_result: Dict[str, Any],
    source_path: Path,
    cli_args: argparse.Namespace,
    report_dir: Optional[Path],
) -> None:
    if not isinstance(fw_result, dict):
        return
    taint_tracking = fw_result.get("taint_tracking", {}) if isinstance(fw_result.get("taint_tracking", {}), dict) else {}

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
                fw_result["taint_graph"] = {"path": str(output_path.relative_to(report_dir))}
            else:
                fw_result["taint_graph"] = {"path": str(output_path)}

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
            fw_result["soundness_validation"] = {
                "success": report.success,
                "report_path": report_path,
                "error": report.error,
                "summary": report.report,
            }

    if cli_args.tai_e_precision_diagnose:
        source_code = source_path.read_text(encoding="utf-8", errors="ignore")
        fw_result["precision_diagnosis"] = analyze_source(source_code).to_dict()

    if cli_args.taint_debug:
        if cli_args.input and len(cli_args.input) == 1:
            launch_debugger_from_result(fw_result)

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
            enable_heapdump=cli_args.profile_heapdump,
            async_profiler_path=Path(cli_args.async_profiler_path).expanduser() if cli_args.async_profiler_path else None,
            yourkit_agent_path=Path(cli_args.yourkit_agent_path).expanduser() if cli_args.yourkit_agent_path else None,
            max_heap=cli_args.profile_max_heap,
            min_heap=cli_args.profile_min_heap,
            heapdump_delay_seconds=cli_args.profile_heapdump_delay,
            mat_path=Path(cli_args.mat_path).expanduser() if cli_args.mat_path else None,
            mat_query=cli_args.mat_query,
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
        heapdump_path = profile_results.get("heapdump_path")
        mat_csv_path = profile_results.get("mat_csv_path")
        mat_report_path = profile_results.get("mat_report_path")
        object_profile_report = profile_results.get("object_profile_report")
        if report_path and output_base.suffix == ".html" and report_path != str(output_base):
            try:
                Path(report_path).replace(output_base)
                report_path = str(output_base)
            except Exception:
                pass
        if report_dir:
            if report_path and Path(report_path).is_absolute() and report_dir in Path(report_path).parents:
                report_path = str(Path(report_path).relative_to(report_dir))
            if heapdump_path and Path(heapdump_path).is_absolute() and report_dir in Path(heapdump_path).parents:
                heapdump_path = str(Path(heapdump_path).relative_to(report_dir))
            if mat_csv_path and Path(mat_csv_path).is_absolute() and report_dir in Path(mat_csv_path).parents:
                mat_csv_path = str(Path(mat_csv_path).relative_to(report_dir))
            if mat_report_path and Path(mat_report_path).is_absolute() and report_dir in Path(mat_report_path).parents:
                mat_report_path = str(Path(mat_report_path).relative_to(report_dir))
            if object_profile_report and Path(object_profile_report).is_absolute() and report_dir in Path(object_profile_report).parents:
                object_profile_report = str(Path(object_profile_report).relative_to(report_dir))
        fw_result["tai_e_profiling"] = {
            "success": profile_results.get("return_code") == 0 and not profile_results.get("errors"),
            "report_path": report_path,
            "heapdump_path": heapdump_path,
            "mat_csv_path": mat_csv_path,
            "mat_report_path": mat_report_path,
            "object_profile_report": object_profile_report,
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
            fw_result["object_profile"] = {
                "success": True,
                "report_path": report_path,
                "summary": report,
            }
        except Exception as exc:
            fw_result["object_profile"] = {
                "success": False,
                "error": str(exc),
            }

def consolidate_analysis_results(results: Dict[str, Any], methods: List[str]) -> VulnerabilityResult:
    """
    Consolidate results from multiple analysis methods into a unified result.
    Implements ensemble decision making with confidence weighting.
    """
    LOG.info(f"🔧 consolidate_analysis_results called with methods={methods}, results keys={list(results.keys())}")
    
    # Method confidence weights based on research effectiveness
    method_weights = {
        'static_heuristic': 1.0,  # Use full weight for static analysis when it's the only method
        'hybrid_dynamic': 0.4, 
        'property_based': 0.2,
        'rl_guided': 0.1
    }
    
    vulnerability_votes = []
    confidence_scores = []
    explanations = []
    vulnerability_types = set()
    severities = []
    
    # Collect votes from each method
    LOG.info(f"🔍 Starting to process {len(methods)} methods")
    for method in methods:
        if method not in results:
            LOG.warning(f"Method {method} not in results")
            continue
            
        result = results[method]
        weight = method_weights.get(method, 0.1)
        
        LOG.info(f"📋 Processing method: {method}, result type: {type(result)}")
        
        if isinstance(result, dict):
            vuln_detected = result.get('vulnerability_detected', False)
            confidence = result.get('confidence', 0.0)
            vuln_type = result.get('vulnerability_type', 'Unknown')
            
            LOG.info(f"  📊 vuln_detected={vuln_detected}, confidence={confidence}, type={vuln_type}")
            
            # Map severity
            if vuln_detected and vuln_type != 'Unknown':
                severity = 'HIGH'  # Default for detected vulnerabilities
            else:
                severity = 'LOW'
            
            # Build explanation from vulnerabilities found
            vulns_found = result.get('vulnerabilities_found', [])
            if vulns_found:
                explanation = f"Detected: {', '.join(vulns_found)}"
            else:
                explanation = f"Confidence: {confidence:.3f}"
        else:
            # Handle object results
            vuln_detected = getattr(result, 'vulnerability_detected', False)
            confidence = getattr(result, 'confidence', 0.0)
            vuln_type = getattr(result, 'vulnerability_type', 'Unknown')
            severity = getattr(result, 'severity', 'LOW')
            explanation = getattr(result, 'explanation', '')
        
        if vuln_detected:
            LOG.debug(f"  Adding to votes: weight={weight}, confidence={confidence}")
            vulnerability_votes.append(weight)
            confidence_scores.append(confidence)
            vulnerability_types.add(vuln_type)
            severities.append(severity)
            explanations.append(f"[{method}] {explanation}")
        else:
            LOG.debug(f"  Skipping - no vulnerability detected")
    
    # Ensemble decision making
    final_vulnerability = len(vulnerability_votes) > 0
    final_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
    final_type = list(vulnerability_types)[0] if vulnerability_types else "Unknown"
    final_severity = max(severities, key=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index) if severities else "LOW"
    final_explanation = " | ".join(explanations) if explanations else "No vulnerabilities detected"
    
    # Create enhanced result with method breakdown
    confidence_breakdown = {method: confidence_scores[i] if i < len(confidence_scores) else 0.0 
                           for i, method in enumerate(methods)}
    
    return VulnerabilityResult(
        vulnerability_detected=final_vulnerability,
        confidence=final_confidence, 
        vulnerability_type=final_type,
        severity=final_severity,
        explanation=final_explanation,
        detection_method="ensemble_" + "_".join(methods),
        analysis_time=0.0,  # Set by caller
        graph_metrics={},   # Set by caller
        confidence_breakdown=confidence_breakdown,
        logic_flaws=results.get('hybrid', {}).get('logic_bugs', []),
        taint_flows=results.get('hybrid', {}).get('taint_flows', []),
        property_violations=results.get('property', {}).get('violations', []),
        concolic_paths=results.get('hybrid', {}).get('symbolic_paths', [])
    )

def initialize_framework(args) -> Tuple[Any, Optional[Any]]:
    """Initialize the enhanced framework with configuration-based component loading"""
    
    try:
        # Initialize core analysis framework
        fw = IntegratedGNNFramework(
            enable_ensemble=args.ensemble or args.comprehensive,
            enable_advanced_features=args.advanced_features or args.comprehensive,
            enable_spatial_gnn=args.spatial_gnn or args.comprehensive,
            enable_explanations=args.explain or args.comprehensive,
            joern_timeout=args.joern_timeout,
            gnn_checkpoint=args.gnn_checkpoint,
            gnn_weight=args.gnn_weight,
            gnn_confidence_threshold=args.gnn_confidence_threshold,
            gnn_temperature=args.gnn_temperature,
            gnn_ensemble=args.gnn_ensemble,
            enable_joern_dataflow=args.joern_dataflow,
            enable_implicit_flows=args.implicit_flows,
            enable_path_sensitive=args.path_sensitive,
            enable_native_jni=args.native_jni,
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
        
        # Initialize hybrid analyzer if advanced features are enabled
        hybrid_analyzer = None
        if args.hybrid_analysis or args.comprehensive:
            try:
                # Placeholder for actual hybrid analyzer
                class MockHybridAnalyzer:
                    async def detect_logic_vulnerabilities(self, path: str):
                        return {
                            'logic_bugs': [],
                            'taint_flows': [],
                            'symbolic_paths': []
                        }
                
                hybrid_analyzer = MockHybridAnalyzer()
                LOG.warning("⚠️ Hybrid analyzer initialized (experimental stub, no real engine)")
            except Exception as e:
                LOG.warning(f"Hybrid analyzer initialization failed: {e}")
                hybrid_analyzer = None
        
        return fw, hybrid_analyzer
        
    except Exception as e:
        LOG.error(f"Framework initialization failed: {e}")
        raise

def _write_dfg_paths_file(analysis_result: Dict[str, Any], report_dir: Path) -> None:
    """
    Write dfg_paths.txt file containing framework's taint tracking results.
    
    Args:
        analysis_result: Analysis result dictionary from framework
        report_dir: Directory where report files are written
    """
    report_dir.mkdir(parents=True, exist_ok=True)
    
    # Start with header
    content = "═══════════════════════════════════════════════════════════════\n"
    content += "  DATA FLOW PATHS ANALYSIS (Bean Vulnerable Framework)\n"
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
    
    # Get taint tracking results
    taint_tracking = analysis_result.get('taint_tracking', {})
    taint_flows = taint_tracking.get('taint_flows', [])
    tainted_vars = taint_tracking.get('tainted_variables', [])
    
    if taint_flows:
        content += f"[✓] Found {len(taint_flows)} taint flow(s)\n\n"
        
        for i, flow in enumerate(taint_flows, 1):
            content += f"──────────────────────────────────────────────────────────────\n"
            content += f"FLOW {i}: {flow.get('source', 'Unknown')} → {flow.get('sink', 'Unknown')}\n"
            content += f"Variable: {flow.get('variable', 'N/A')}\n"
            if 'line' in flow:
                content += f"Line: {flow['line']}\n"
            content += f"──────────────────────────────────────────────────────────────\n\n"
    else:
        content += "[!] No taint flows detected\n\n"
    
    # Add tainted variables summary
    if tainted_vars:
        content += "\n═══════════════════════════════════════════════════════════════\n"
        content += "  TAINTED VARIABLES SUMMARY\n"
        content += "═══════════════════════════════════════════════════════════════\n\n"
        for var in tainted_vars:
            content += f"  • {var}\n"
        content += "\n"
    
    content += "═══════════════════════════════════════════════════════════════\n"
    content += f"Analysis completed. Output: {report_dir}/dfg_paths.txt\n"
    content += "═══════════════════════════════════════════════════════════════\n"
    
    # Write file
    dfg_paths_file = report_dir / 'dfg_paths.txt'
    dfg_paths_file.write_text(content, encoding='utf-8')
    LOG.debug(f"📝 Written dfg_paths.txt with {len(taint_flows)} flows")


def main():
    """Enhanced main function with comprehensive analysis modes and research-based optimizations"""
    
    # Enhanced argument parser with new research-based options
    ap = argparse.ArgumentParser(
        prog="bean-vuln-enhanced",
        description="Bean Vulnerable Framework - Enhanced CLI (experimental features)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Core arguments
    ap.add_argument("input", nargs="+", help="Java files, directories, or dataset files to analyze")
    ap.add_argument("-o", "--out", help="Output JSON file path")
    ap.add_argument("--summary", action="store_true", help="Print detailed summary for each input")
    ap.add_argument("--html-report", help="Generate enhanced HTML report with visualizations")
    ap.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    # Analysis mode selection
    ap.add_argument("--mode", choices=[mode.value for mode in AnalysisMode], 
                   default=AnalysisMode.STATIC_ONLY.value,
                   help="Analysis mode selection (default: static)")
    
    # Enhanced analysis options (research-based)
    ap.add_argument("--hybrid-analysis", action="store_true",
                   help="Enable hybrid analysis (experimental stub; no real engines)")
    ap.add_argument("--rl-prioritization", action="store_true", 
                   help="Enable RL path prioritization (experimental stub)")
    ap.add_argument("--property-testing", action="store_true",
                   help="Enable property-based testing (experimental stub)")
    ap.add_argument("--taint-tracking", action="store_true",
                   help="Enable advanced dynamic taint tracking")
    ap.add_argument("--ensemble-gnn", action="store_true",
                   help="Enable ensemble mode (experimental; no trained GNN inference)")
    
    # Performance and resource options
    ap.add_argument("--max-depth", type=int, default=50,
                   help="Maximum exploration depth for dynamic analysis")
    ap.add_argument("--timeout", type=int, default=300,
                   help="Analysis timeout per file (seconds)")
    ap.add_argument("--parallel", type=int, default=multiprocessing.cpu_count(),
                   help="Number of parallel analysis workers")
    
    # Graph export options (for HTML report compatibility)
    ap.add_argument("--export-dfg", action="store_true",
                   help="Export Data Flow Graphs")
    ap.add_argument("--export-cfg", action="store_true",
                   help="Export Control Flow Graphs")
    ap.add_argument("--export-pdg", action="store_true",
                   help="Export Program Dependence Graphs")
    
    # Legacy compatibility options
    ap.add_argument("--ensemble", action="store_true", help="Enable ensemble methods")
    ap.add_argument("--advanced-features", action="store_true", help="Enable advanced features")
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
    ap.add_argument("--aeg-lite-java", action="store_true",
                    help="Run experimental AEG-Lite Java bytecode analyzer (ASM-based)")
    ap.add_argument("--aeg-java-home",
                    help="JAVA_HOME override for AEG-Lite Java analyzer")
    ap.add_argument("--aeg-lite-pocs", action="store_true",
                    help="Generate PoCs in AEG-Lite Java analyzer")
    ap.add_argument("--aeg-lite-patches", action="store_true",
                    help="Generate patches in AEG-Lite Java analyzer")
    ap.add_argument("--aeg-lite-enhanced-scan", action="store_true",
                    help="Run enhanced source scanner (pattern/AST/semantic/taint) via AEG-Lite Java")
    ap.add_argument("--aeg-lite-enhanced-patches", action="store_true",
                    help="Generate enhanced template patches (implies --aeg-lite-enhanced-scan)")
    ap.add_argument("--joern-dataflow", action="store_true",
                    help="Enable Joern reachableByFlows dataflow extraction for gating")
    ap.add_argument("--explain", action="store_true", help="Generate explanations")
    ap.add_argument("--comprehensive", action="store_true", 
                   help="Enable all advanced features (hybrid + RL + property testing)")
    ap.add_argument("--joern-timeout", type=int, default=480, help="Joern operation timeout")
    ap.add_argument("--sink-signature-preset",
                    help="Reserved: record a sink signature preset request (e.g., graudit-java). No effect in this build.")
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
    ap.add_argument("--implicit-flows", dest="implicit_flows", action="store_true", default=True,
                    help="Enable implicit flow tracking (default: enabled)")
    ap.add_argument("--no-implicit-flows", dest="implicit_flows", action="store_false",
                    help="Disable implicit flow tracking")
    ap.add_argument("--path-sensitive", dest="path_sensitive", action="store_true", default=True,
                    help="Enable path-sensitive analysis (default: enabled)")
    ap.add_argument("--no-path-sensitive", dest="path_sensitive", action="store_false",
                    help="Disable path-sensitive analysis")
    ap.add_argument("--native-jni", dest="native_jni", action="store_true", default=True,
                    help="Enable native (JNI) taint tracking (default: enabled)")
    ap.add_argument("--no-native-jni", dest="native_jni", action="store_false",
                    help="Disable native (JNI) taint tracking")
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
    ap.add_argument("--profile-heapdump", action="store_true",
                    help="Capture a JVM heap dump during Tai-e profiling (requires jcmd)")
    ap.add_argument("--profile-heapdump-delay", type=int, default=5,
                    help="Seconds to wait before heap dump capture (default: 5)")
    ap.add_argument("--profile-max-heap",
                    help="Set JVM -Xmx for profiling runs (e.g. 8g)")
    ap.add_argument("--profile-min-heap",
                    help="Set JVM -Xms for profiling runs (e.g. 2g)")
    ap.add_argument("--mat-path",
                    help="Path to Eclipse MAT ParseHeapDump script or MAT_HOME directory")
    ap.add_argument("--mat-query", default="suspects",
                    help="MAT report to run (suspects|top_components; default: suspects)")
    ap.add_argument("--object-profile",
                    help="Path to YourKit snapshot or CSV export for object profiling")
    ap.add_argument("--object-profile-output",
                    help="Path to write object profiling HTML report")
    # Dataset and evaluation options
    ap.add_argument("--dataset", choices=['vul4j', 'bigvul', 'devign', 'diversevul'], 
                   help="Specify dataset for evaluation")
    ap.add_argument("--benchmark", action="store_true",
                   help="Run comprehensive benchmark evaluation")
    
    args = ap.parse_args()
    if args.html_report and not args.joern_dataflow:
        args.joern_dataflow = True
    if not args.spatial_gnn:
        LOG.warning("⚠️ Ignoring --no-spatial-gnn; spatial GNN is always enabled.")
        args.spatial_gnn = True
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
    
    # Configure comprehensive mode
    if args.comprehensive:
        args.hybrid_analysis = True
        args.rl_prioritization = True  
        args.property_testing = True
        args.taint_tracking = True
        args.ensemble_gnn = True
        args.ensemble = True
        args.advanced_features = True
        args.spatial_gnn = True
        args.explain = True

    if args.hybrid_analysis or args.rl_prioritization or args.property_testing or args.taint_tracking:
        LOG.warning(
            "⚠️ Experimental features enabled: hybrid/RL/property testing are stubs and "
            "do not run real dynamic or symbolic engines yet."
        )
    
    # Create analysis configuration
    config = AnalysisConfiguration(
        mode=AnalysisMode(args.mode),
        enable_concolic=args.hybrid_analysis,
        enable_rl_prioritization=args.rl_prioritization,
        enable_property_testing=args.property_testing, 
        enable_taint_tracking=args.taint_tracking,
        enable_ensemble_gnn=args.ensemble_gnn,
        max_exploration_depth=args.max_depth,
        concolic_timeout=args.timeout,
        parallel_workers=args.parallel
    )
    
    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        LOG.setLevel(logging.DEBUG)
    
    # Initialize enhanced framework
    LOG.info("🚀 Bean Vulnerable Enhanced Framework - Initializing...")
    fw, hybrid_analyzer = initialize_framework(args)
    
    # Display configuration
    print("🎯 Bean Vulnerable Enhanced Framework v2.0")
    print("=" * 60)
    print(f"📊 Analysis Mode: {config.mode.value.upper()}")
    print(f"🔄 Hybrid Analysis: {'✅' if config.enable_concolic else '❌'}")
    print(f"🤖 RL Path Priority: {'✅' if config.enable_rl_prioritization else '❌'}")
    print(f"🧪 Property Testing: {'✅' if config.enable_property_testing else '❌'}")
    print(f"🌊 Taint Tracking: ✅ (Always Enabled)")  # Taint tracking is always on
    print(f"⚡ Parallel Workers: {config.parallel_workers}")
    print("=" * 60)
    
    # Process inputs
    results = []
    framework_results = []  # Store original framework results for HTML report
    start_time = time.time()
    debug_report_dir = Path(args.html_report).expanduser() if args.html_report else None
    
    async def process_inputs():
        """Async processing of multiple inputs with enhanced analysis"""
        tasks = []
        
        for i, raw_input in enumerate(args.input, 1):
            p = Path(raw_input).expanduser().resolve()
            if not p.exists():
                print(f"❌ Input {i}: {p} not found")
                continue
                
            print(f"🔍 Input {i}/{len(args.input)}: {p.name}")
            
            # Create analysis task
            task = analyze_path_enhanced(p, config, fw, hybrid_analyzer)
            tasks.append(task)
        
        # Execute analysis tasks
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
        return []
    
    # Run analysis
    try:
        analysis_results = asyncio.run(process_inputs())
        
        # Process results
        for i, result_tuple in enumerate(analysis_results):
            if isinstance(result_tuple, Exception):
                LOG.error(f"Analysis failed for input {i+1}: {result_tuple}")
                continue
            
            # Unpack the tuple (VulnerabilityResult, framework_result)
            if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                result, fw_result = result_tuple
                framework_results.append(fw_result)
            elif isinstance(result_tuple, VulnerabilityResult):
                # Fallback for old format
                result = result_tuple
                fw_result = {}
                framework_results.append(fw_result)
            else:
                LOG.error(f"Unexpected result type: {type(result_tuple)}")
                continue
                
            if isinstance(result, VulnerabilityResult):
                source_path = Path(args.input[i]).expanduser().resolve() if i < len(args.input) else None
                if source_path and framework_results:
                    _apply_debug_utilities_enhanced(
                        framework_results[-1],
                        source_path,
                        args,
                        debug_report_dir,
                    )
                # Display summary if requested
                if args.summary:
                    print(f"  📊 Result Summary:")
                    print(f"    🎯 Vulnerable: {result.vulnerability_detected}")
                    print(f"    📈 Confidence: {result.confidence:.3f}")
                    print(f"    🏷️  Type: {result.vulnerability_type}")
                    print(f"    ⚠️  Severity: {result.severity}")
                    print(f"    🔍 Method: {result.detection_method}")
                    print(f"    ⏱️  Time: {result.analysis_time:.2f}s")
                    
                    # Enhanced metrics display
                    if result.graph_metrics:
                        metrics = result.graph_metrics
                        print(f"    📊 Graph: {metrics.get('node_count', 0)} nodes, {metrics.get('edge_count', 0)} edges")
                        if metrics.get('taint_flows', 0) > 0:
                            print(f"    🌊 Taint Flows: {metrics.get('taint_flows', 0)}")
                        if metrics.get('symbolic_paths', 0) > 0:
                            print(f"    🔀 Symbolic Paths: {metrics.get('symbolic_paths', 0)}")
                    
                    # Display CF-Explainer recommendations if available
                    if fw_result and 'cf_explanation' in fw_result:
                        cf_exp = fw_result['cf_explanation']
                        print(f"\n  💡 Counterfactual Explanation:")
                        
                        # Show practical recommendations
                        recommendations = cf_exp.get('practical_recommendations', [])
                        if recommendations:
                            print(f"    📋 Recommendations:")
                            for i, rec in enumerate(recommendations[:3], 1):  # Show first 3
                                print(f"       {i}. {rec}")
                            if len(recommendations) > 3:
                                print(f"       ... and {len(recommendations) - 3} more")
                        
                        # Show developer guidance (first 200 chars)
                        guidance = cf_exp.get('developer_guidance', '')
                        if guidance:
                            guidance_preview = guidance[:200] + "..." if len(guidance) > 200 else guidance
                            print(f"    🔧 Guidance: {guidance_preview}")
                
                # Convert to dict for JSON serialization
                result_dict = {
                    'input': str(args.input[i]) if i < len(args.input) else 'unknown',
                    'vulnerability_detected': result.vulnerability_detected,
                    'confidence': result.confidence,
                    'vulnerability_type': result.vulnerability_type,
                    'severity': result.severity,
                    'explanation': result.explanation,
                    'detection_method': result.detection_method,
                    'analysis_time': result.analysis_time,
                    'graph_metrics': result.graph_metrics,
                    'enhanced_results': {
                        'logic_flaws': result.logic_flaws or [],
                        'taint_flows': result.taint_flows or [],
                        'property_violations': result.property_violations or [],
                        'concolic_paths': result.concolic_paths or [],
                        'confidence_breakdown': result.confidence_breakdown or {}
                    }
                }
                sink_preset = getattr(args, "sink_signature_preset", None)
                if sink_preset:
                    result_dict.setdefault("analysis_config", {})["sink_signature_preset"] = sink_preset
                if isinstance(fw_result, dict):
                    result_dict.setdefault("taint_tracking", fw_result.get("taint_tracking", {}))
                    result_dict.setdefault("joern_dataflow", fw_result.get("joern_dataflow", {}))
                    result_dict.setdefault("framework_sinks", fw_result.get("framework_sinks", {}))
                    result_dict.setdefault("template_engine_analysis", fw_result.get("template_engine_analysis", {}))
                    result_dict.setdefault("taint_gating", fw_result.get("taint_gating", {}))
                    result_dict.setdefault("evidence", fw_result.get("evidence", {}))
                    result_dict.setdefault("technical_details", fw_result.get("technical_details", {}))
                    result_dict.setdefault("cpg", fw_result.get("cpg", {}))
                    if "taint_graph" in fw_result:
                        result_dict["taint_graph"] = fw_result["taint_graph"]
                    if "soundness_validation" in fw_result:
                        result_dict["soundness_validation"] = fw_result["soundness_validation"]
                    if "tai_e_profiling" in fw_result:
                        result_dict["tai_e_profiling"] = fw_result["tai_e_profiling"]
                    if "object_profile" in fw_result:
                        result_dict["object_profile"] = fw_result["object_profile"]
                    if "cf_explanation" in fw_result:
                        result_dict["cf_explanation"] = fw_result["cf_explanation"]
                taint_tracking = result_dict.get("taint_tracking", {}) if isinstance(result_dict.get("taint_tracking", {}), dict) else {}
                implicit = taint_tracking.get("implicit_flows", {}) if isinstance(taint_tracking.get("implicit_flows", {}), dict) else {}
                path_sensitive = taint_tracking.get("path_sensitive_analysis", {}) if isinstance(taint_tracking.get("path_sensitive_analysis", {}), dict) else {}
                native_jni = taint_tracking.get("native_code_analysis", {}) if isinstance(taint_tracking.get("native_code_analysis", {}), dict) else {}
                context_sensitive = taint_tracking.get("context_sensitive_analysis", {}) if isinstance(taint_tracking.get("context_sensitive_analysis", {}), dict) else {}
                interprocedural = taint_tracking.get("interprocedural_analysis", {}) if isinstance(taint_tracking.get("interprocedural_analysis", {}), dict) else {}
                result_dict["advanced_taint"] = {
                    "implicit_flows": {
                        "enabled": bool(implicit.get("enabled", False)),
                        "count": int(implicit.get("count", 0) or 0),
                    },
                    "path_sensitive": {
                        "enabled": bool(path_sensitive.get("enabled", False)),
                        "branching_points": int(path_sensitive.get("branching_points", 0) or 0),
                        "feasible_paths": int(path_sensitive.get("feasible_paths", 0) or 0),
                        "infeasible_paths": int(path_sensitive.get("infeasible_paths", 0) or 0),
                    },
                    "native_jni": {
                        "enabled": bool(native_jni.get("enabled", False)),
                        "jni_methods": int(native_jni.get("jni_methods", 0) or 0),
                        "taint_transfers": int(native_jni.get("taint_transfers", 0) or 0),
                    },
                    "context_sensitive": {
                        "contexts_tracked": int(context_sensitive.get("contexts_tracked", 0) or 0),
                        "k_cfa_limit": int(context_sensitive.get("k_cfa_limit", 0) or 0),
                    },
                    "interprocedural": {
                        "methods_analyzed": int(interprocedural.get("methods_analyzed", 0) or 0),
                        "methods_with_tainted_params": int(interprocedural.get("methods_with_tainted_params", 0) or 0),
                    },
                }
                if args.aeg_lite_java and source_path and source_path.suffix == ".java":
                    if not AEG_LITE_JAVA_AVAILABLE or not run_aeg_lite_java:
                        result_dict["aeg_lite_java"] = {
                            "success": False,
                            "error": "AEG-Lite Java bridge unavailable.",
                            "analysis_method": "asm_bytecode",
                        }
                    else:
                        enhanced_scan = getattr(args, "aeg_lite_enhanced_scan", False)
                        enhanced_patches = getattr(args, "aeg_lite_enhanced_patches", False)
                        if enhanced_patches:
                            enhanced_scan = True
                        result_dict["aeg_lite_java"] = run_aeg_lite_java(
                            source_path,
                            java_home=getattr(args, "aeg_java_home", None),
                            generate_pocs=getattr(args, "aeg_lite_pocs", False),
                            generate_patches=getattr(args, "aeg_lite_patches", False),
                            use_joern=getattr(args, "joern_dataflow", False),
                            enhanced_scan=enhanced_scan,
                            enhanced_patches=enhanced_patches,
                        )
                    if isinstance(fw_result, dict):
                        fw_result["aeg_lite_java"] = result_dict.get("aeg_lite_java")
                results.append(result_dict)
    
    except Exception as e:
        LOG.error(f"Analysis execution failed: {e}")
        sys.exit(1)
    
    total_time = time.time() - start_time
    
    # Results summary  
    print("=" * 60)
    print(f"⏱️  Total Analysis Time: {total_time:.2f}s")
    print(f"📊 Processed Inputs: {len(results)}")
    if results:
        vulnerable_count = sum(1 for r in results if r.get('vulnerability_detected', False))
        print(f"🚨 Vulnerabilities Found: {vulnerable_count}/{len(results)}")
        
        # Method effectiveness summary
        methods = set()
        for r in results:
            if 'detection_method' in r:
                methods.add(r['detection_method'])
        print(f"🔍 Detection Methods Used: {', '.join(methods)}")
    
    # Auto-enable graphs for HTML report
    if args.html_report and not (args.export_dfg or args.export_cfg or args.export_pdg):
        LOG.info("📊 Auto-enabling all graphs (CFG+DFG+PDG) for HTML report...")
        args.export_dfg = args.export_cfg = args.export_pdg = True
    
    # Generate graphs using Joern comprehensive script
    if args.html_report and (args.export_dfg or args.export_cfg or args.export_pdg) and args.input:
        try:
            report_dir = _prepare_report_dir(Path(args.html_report))
        except ValueError as exc:
            LOG.error(str(exc))
            sys.exit(2)
        
        # Get source file path
        source_path = Path(args.input[0]).expanduser().resolve()
        if source_path.exists() and source_path.suffix == '.java':
            LOG.info(f"🎨 Generating comprehensive graphs for {source_path.name}...")
            
            try:
                # Use the COMPREHENSIVE Joern script for detailed graphs
                script_path = Path(__file__).parent.parent.parent / "comprehensive_graphs.sc"
                env = os.environ.copy()
                env['SOURCE_FILE'] = str(source_path.absolute())
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
                
                # Convert ALL .dot files to PNG and SVG
                dot_files = list(report_dir.glob('*.dot'))
                for dot_file in dot_files:
                    _colorize_dot_file(dot_file)
                LOG.info(f"🎨 Converting {len(dot_files)} DOT files to PNG/SVG...")
                
                for dot_file in dot_files:
                    graph_name = dot_file.stem
                    
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
                import traceback
                traceback.print_exc()
    
    # Generate HTML report if requested
    if args.html_report and results:
        LOG.info("📝 Generating enhanced HTML report...")
        try:
            try:
                from src.core.html_report_generator import generate_comprehensive_html_report
            except ImportError:
                from core.html_report_generator import generate_comprehensive_html_report
            
            # Build command line string
            command_line = f"bean-vuln-enhanced {' '.join(args.input)}"
            if args.summary:
                command_line += " --summary"
            if args.html_report:
                command_line += f" --html-report {args.html_report}"
            if args.comprehensive:
                command_line += " --comprehensive"
            
            # Report directory already created and cleaned during graph generation
            report_dir = Path(args.html_report).expanduser()
            report_dir.mkdir(parents=True, exist_ok=True)
            
            # Write dfg_paths.txt file with taint flows
            if framework_results and framework_results[0]:
                _write_dfg_paths_file(framework_results[0], report_dir)
            
            # Generate HTML report using first result
            if framework_results and framework_results[0]:
                # Use the original framework result for HTML generation
                LOG.info(f"📊 Using framework result with keys: {framework_results[0].keys()}")
                report_path = generate_comprehensive_html_report(
                    framework_results[0], 
                    report_dir, 
                    command_line
                )
                LOG.info(f"✅ Enhanced HTML report generated: {report_path}")
                
                # Auto-open in browser with absolute path
                try:
                    import platform
                    # Convert to absolute path for Chrome compatibility
                    absolute_path = report_path.absolute() if hasattr(report_path, 'absolute') else Path(report_path).absolute()
                    
                    # Use macOS 'open' command which properly handles file:// URLs in Chrome
                    if platform.system() == 'Darwin':
                        subprocess.run(['open', str(absolute_path)], check=False)
                        LOG.info(f"🌐 Opening report in default browser: {absolute_path}")
                    else:
                        # Fallback to webbrowser for other platforms
                        import webbrowser
                        file_url = f"file://{absolute_path}"
                        webbrowser.open(file_url)
                        LOG.info(f"🌐 Opening report in browser: {file_url}")
                except Exception as e:
                    LOG.warning(f"Could not auto-open browser: {e}")
            else:
                LOG.error("❌ No framework results available for HTML report generation")
        except Exception as e:
            LOG.error(f"HTML report generation failed: {e}")
            import traceback
            traceback.print_exc()
    
    # Output results to JSON file
    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        enhanced_output = {
            'metadata': {
                'version': '2.0.0-enhanced',
                'analysis_mode': config.mode.value,
                'total_time': total_time,
                'configuration': {
                    'hybrid_analysis': config.enable_concolic,
                    'rl_prioritization': config.enable_rl_prioritization,
                    'property_testing': config.enable_property_testing,
                    'taint_tracking': config.enable_taint_tracking,
                    'parallel_workers': config.parallel_workers
                }
            },
            'results': results
        }
        
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(enhanced_output, f, indent=2, default=str)
        print(f"📄 Enhanced results saved to: {output_path}")
    elif not args.html_report:  # Only print JSON if no HTML report
        print("📄 Enhanced JSON Results:")
        print(json.dumps({'results': results}, indent=2, default=str))

if __name__ == "__main__":
    main()
