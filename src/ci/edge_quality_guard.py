#!/usr/bin/env python3
"""
Edge Quality Guard for Bean Vulnerable GNN Framework
Provides CI/CD integration with exploitability telemetry and quality metrics
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib

LOG = logging.getLogger(__name__)

class EdgeQualityGuard:
    """
    Quality guard for CI/CD pipelines with AEG lite telemetry integration.
    Validates analysis results and emits comprehensive telemetry.
    """
    
    def __init__(self, project_name: str = "bean_vulnerable", telemetry_dir: str = "telemetry"):
        self.project_name = project_name
        self.telemetry_dir = Path(telemetry_dir)
        self.telemetry_dir.mkdir(exist_ok=True)
        self.session_id = self._generate_session_id()
        
        LOG.info(f"✅ EdgeQualityGuard initialized for {project_name}")
        LOG.info(f"📊 Telemetry directory: {self.telemetry_dir}")
        LOG.info(f"🔑 Session ID: {self.session_id}")
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        timestamp = str(int(time.time()))
        content = f"{self.project_name}-{timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def validate_analysis_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate analysis result and check quality thresholds.
        
        Args:
            result: Analysis result from Bean Vulnerable framework
            
        Returns:
            Validation result with quality metrics
        """
        validation = {
            'session_id': self.session_id,
            'timestamp': datetime.utcnow().isoformat(),
            'valid': True,
            'quality_score': 0.0,
            'issues': [],
            'metrics': {},
            'recommendations': []
        }
        
        try:
            # Basic validation checks
            if not isinstance(result, dict):
                validation['valid'] = False
                validation['issues'].append("Result is not a dictionary")
                return validation
            
            # Check for required fields
            required_fields = ['vulnerability_detected', 'confidence']
            for field in required_fields:
                if field not in result:
                    validation['issues'].append(f"Missing required field: {field}")
                    validation['valid'] = False
            
            # Validate confidence score
            if 'confidence' in result:
                confidence = result['confidence']
                if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
                    validation['issues'].append(f"Invalid confidence score: {confidence}")
                    validation['valid'] = False
                else:
                    validation['metrics']['confidence'] = confidence
            
            # Validate CPG metrics
            if 'cpg' in result:
                cpg = result['cpg']
                validation['metrics']['cpg_nodes'] = cpg.get('nodes', 0)
                validation['metrics']['cpg_edges'] = cpg.get('edges', 0)
                
                # Quality checks for CPG
                if cpg.get('nodes', 0) < 10:
                    validation['issues'].append("CPG has very few nodes (< 10)")
                    validation['recommendations'].append("Consider analyzing larger code samples")
                
                if cpg.get('edges', 0) < 5:
                    validation['issues'].append("CPG has very few edges (< 5)")
                    validation['recommendations'].append("Check CPG generation quality")
            
            # Validate GNN utilization
            if 'gnn_utilized' in result:
                validation['metrics']['gnn_utilized'] = result['gnn_utilized']
                if not result['gnn_utilized']:
                    validation['recommendations'].append(
                        "Consider enabling GNN inference with trained weights for impact"
                    )
            
            # Validate uncertainty metrics
            if 'uncertainty_metrics' in result:
                uncertainty = result['uncertainty_metrics']
                validation['metrics']['uncertainty_level'] = uncertainty.get('uncertainty_category', 'unknown')
                validation['metrics']['prediction_reliability'] = uncertainty.get('prediction_reliability', 'unknown')
                
                # High uncertainty warning
                if uncertainty.get('total_uncertainty', 0) > 0.5:
                    validation['issues'].append("High prediction uncertainty detected")
                    validation['recommendations'].append("Consider manual review for high-uncertainty predictions")
            
            # Calculate overall quality score
            quality_factors = []
            
            # Confidence factor (0.0-1.0)
            if 'confidence' in validation['metrics']:
                quality_factors.append(validation['metrics']['confidence'])
            
            # GNN utilization factor
            if validation['metrics'].get('gnn_utilized', False):
                quality_factors.append(0.8)
            else:
                quality_factors.append(0.4)
            
            # CPG quality factor
            cpg_nodes = validation['metrics'].get('cpg_nodes', 0)
            cpg_quality = min(1.0, cpg_nodes / 100.0)  # Normalize to 100 nodes
            quality_factors.append(cpg_quality)
            
            # Issue penalty
            issue_penalty = max(0.0, 1.0 - (len(validation['issues']) * 0.2))
            quality_factors.append(issue_penalty)
            
            # Calculate weighted average
            validation['quality_score'] = sum(quality_factors) / len(quality_factors) if quality_factors else 0.0
            
            LOG.info(f"📊 Validation complete: quality={validation['quality_score']:.3f}, issues={len(validation['issues'])}")
            
        except Exception as e:
            LOG.error(f"❌ Validation failed: {e}")
            validation['valid'] = False
            validation['issues'].append(f"Validation error: {str(e)}")
        
        return validation
    
    def emit_telemetry(self, 
                      validation_result: Dict[str, Any], 
                      extra_telemetry: Optional[Dict[str, Any]] = None) -> None:
        """
        Emit telemetry data including exploitability metrics.
        
        Args:
            validation_result: Result from validate_analysis_result
            extra_telemetry: Additional telemetry data (e.g., AEG lite results)
        """
        try:
            telemetry = {
                'session_id': self.session_id,
                'project': self.project_name,
                'timestamp': datetime.utcnow().isoformat(),
                'validation': validation_result,
                'system_info': self._get_system_info()
            }
            
            # Add extra telemetry (AEG lite results, etc.)
            if extra_telemetry:
                telemetry['extensions'] = extra_telemetry
                
                # Extract key exploitability metrics
                if 'aeg_lite_results' in extra_telemetry:
                    aeg_results = extra_telemetry['aeg_lite_results']
                    if 'patch_ranking' in aeg_results and aeg_results['patch_ranking']:
                        best_patch = aeg_results['patch_ranking'][0]
                        telemetry['exploitability'] = {
                            'feasible': best_patch.get('exploit_feasible', False),
                            'cvss_like': best_patch.get('cvss_like', 0.0),
                            'path_length': best_patch.get('path_length', 0),
                            'patch_diff': best_patch.get('patch_diff', 0.0)
                        }
                
                # Extract AEG analysis metrics
                if 'aeg_analysis' in extra_telemetry:
                    aeg_analysis = extra_telemetry['aeg_analysis']
                    telemetry['exploitability'] = {
                        'feasible': aeg_analysis.get('feasible', False),
                        'score': aeg_analysis.get('exploitability_score', 0.0),
                        'confidence': aeg_analysis.get('confidence', 0.0),
                        'method': aeg_analysis.get('analysis_method', 'unknown')
                    }
            
            # Write telemetry to file
            telemetry_file = self.telemetry_dir / f"telemetry_{self.session_id}_{int(time.time())}.json"
            with open(telemetry_file, 'w') as f:
                json.dump(telemetry, f, indent=2, default=str)
            
            LOG.info(f"📊 Telemetry emitted: {telemetry_file}")
            
            # Also write to latest.json for easy access
            latest_file = self.telemetry_dir / "latest.json"
            with open(latest_file, 'w') as f:
                json.dump(telemetry, f, indent=2, default=str)
            
        except Exception as e:
            LOG.error(f"❌ Failed to emit telemetry: {e}")
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for telemetry"""
        import platform
        import sys
        
        return {
            'python_version': sys.version,
            'platform': platform.platform(),
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def check_quality_gates(self, validation_result: Dict[str, Any]) -> bool:
        """
        Check if analysis passes quality gates for CI/CD.
        
        Args:
            validation_result: Result from validate_analysis_result
            
        Returns:
            True if quality gates pass, False otherwise
        """
        if not validation_result['valid']:
            LOG.warning("❌ Quality gate failed: Invalid analysis result")
            return False
        
        # Quality score threshold
        if validation_result['quality_score'] < 0.6:
            LOG.warning(f"❌ Quality gate failed: Low quality score ({validation_result['quality_score']:.3f} < 0.6)")
            return False
        
        # Critical issues check
        critical_issues = [issue for issue in validation_result['issues'] 
                          if 'confidence' in issue.lower() or 'missing' in issue.lower()]
        if critical_issues:
            LOG.warning(f"❌ Quality gate failed: Critical issues found: {critical_issues}")
            return False
        
        LOG.info(f"✅ Quality gates passed: score={validation_result['quality_score']:.3f}")
        return True
    
    def generate_report(self, validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive quality report from multiple validation results.
        
        Args:
            validation_results: List of validation results
            
        Returns:
            Comprehensive report with statistics and recommendations
        """
        if not validation_results:
            return {'error': 'No validation results provided'}
        
        report = {
            'session_id': self.session_id,
            'project': self.project_name,
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_analyses': len(validation_results),
                'valid_analyses': sum(1 for r in validation_results if r['valid']),
                'average_quality': sum(r['quality_score'] for r in validation_results) / len(validation_results),
                'quality_gate_passes': sum(1 for r in validation_results if self.check_quality_gates(r))
            },
            'metrics': {
                'confidence_scores': [r['metrics'].get('confidence', 0) for r in validation_results],
                'gnn_utilization_rate': sum(1 for r in validation_results 
                                          if r['metrics'].get('gnn_utilized', False)) / len(validation_results),
                'average_cpg_nodes': sum(r['metrics'].get('cpg_nodes', 0) for r in validation_results) / len(validation_results),
                'average_cpg_edges': sum(r['metrics'].get('cpg_edges', 0) for r in validation_results) / len(validation_results)
            },
            'issues': {
                'total_issues': sum(len(r['issues']) for r in validation_results),
                'common_issues': self._find_common_issues(validation_results),
                'recommendations': self._aggregate_recommendations(validation_results)
            }
        }
        
        # Add exploitability statistics if available
        exploitable_count = 0
        cvss_scores = []
        
        for result in validation_results:
            if 'extensions' in result and 'exploitability' in result['extensions']:
                exp = result['extensions']['exploitability']
                if exp.get('feasible', False):
                    exploitable_count += 1
                if 'cvss_like' in exp:
                    cvss_scores.append(exp['cvss_like'])
        
        if cvss_scores:
            report['exploitability'] = {
                'exploitable_samples': exploitable_count,
                'exploitability_rate': exploitable_count / len(validation_results),
                'average_cvss': sum(cvss_scores) / len(cvss_scores),
                'max_cvss': max(cvss_scores),
                'min_cvss': min(cvss_scores)
            }
        
        return report
    
    def _find_common_issues(self, validation_results: List[Dict[str, Any]]) -> List[str]:
        """Find issues that appear in multiple validation results"""
        issue_counts = {}
        for result in validation_results:
            for issue in result['issues']:
                issue_counts[issue] = issue_counts.get(issue, 0) + 1
        
        # Return issues that appear in at least 20% of results
        threshold = max(1, len(validation_results) * 0.2)
        return [issue for issue, count in issue_counts.items() if count >= threshold]
    
    def _aggregate_recommendations(self, validation_results: List[Dict[str, Any]]) -> List[str]:
        """Aggregate recommendations from multiple validation results"""
        all_recommendations = []
        for result in validation_results:
            all_recommendations.extend(result.get('recommendations', []))
        
        # Return unique recommendations
        return list(set(all_recommendations)) 