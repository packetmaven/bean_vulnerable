"""
Bean Vulnerable GNN Framework - CI/CD Integration
Integrates with CI/CD pipelines for automated vulnerability detection
"""

import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class CICDIntegration:
    """Integration with CI/CD pipelines for automated vulnerability scanning"""
    
    def __init__(self, cicd_config: Optional[Dict[str, Any]] = None):
        """
        Initialize CI/CD integration
        
        Args:
            cicd_config: Configuration for CI/CD integration
                - type: CI/CD type ('jenkins', 'github_actions', 'gitlab_ci', 'azure_devops', 'generic')
                - fail_on_vulnerability: Fail build on vulnerability detection
                - severity_threshold: Minimum severity to fail build
                - output_format: Output format ('json', 'junit', 'sarif', 'text')
                - report_path: Path to save reports
                - exclude_patterns: File patterns to exclude from scanning
        """
        self.config = cicd_config or {}
        self.cicd_type = self.config.get('type', 'generic')
        self.fail_on_vulnerability = self.config.get('fail_on_vulnerability', True)
        self.severity_threshold = self.config.get('severity_threshold', 0.7)
        self.output_format = self.config.get('output_format', 'json')
        self.report_path = Path(self.config.get('report_path', 'bean_vulnerable_report'))
        self.exclude_patterns = self.config.get('exclude_patterns', [])
        
        # Detect CI/CD environment if not specified
        if self.cicd_type == 'generic':
            self.cicd_type = self._detect_cicd_environment()
        
        logger.info(f"✅ CI/CD Integration initialized for {self.cicd_type}")
    
    def run_pipeline_scan(self, source_paths: List[str]) -> Dict[str, Any]:
        """
        Run vulnerability scan for CI/CD pipeline
        
        Args:
            source_paths: List of source code paths to scan
            
        Returns:
            Dict containing scan results and pipeline status
        """
        scan_results = {
            'pipeline_status': 'success',
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'cicd_type': self.cicd_type,
            'total_files_scanned': 0,
            'vulnerabilities_found': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'files_with_vulnerabilities': [],
            'scan_summary': {},
            'reports_generated': []
        }
        
        try:
            # Scan all source paths
            all_results = []
            
            for source_path in source_paths:
                path_results = self._scan_path(source_path)
                all_results.extend(path_results)
            
            # Process results
            scan_results['total_files_scanned'] = len(all_results)
            
            for result in all_results:
                if result.get('vulnerability_detected', False):
                    scan_results['vulnerabilities_found'] += 1
                    
                    # Count by severity
                    confidence = result.get('confidence', 0.0)
                    if confidence >= 0.9:
                        scan_results['critical_vulnerabilities'] += 1
                    elif confidence >= 0.7:
                        scan_results['high_vulnerabilities'] += 1
                    elif confidence >= 0.5:
                        scan_results['medium_vulnerabilities'] += 1
                    else:
                        scan_results['low_vulnerabilities'] += 1
                    
                    scan_results['files_with_vulnerabilities'].append({
                        'file': result.get('input', 'unknown'),
                        'vulnerabilities': result.get('vulnerabilities_found', []),
                        'confidence': confidence
                    })
            
            # Generate reports
            self._generate_reports(all_results, scan_results)
            
            # Determine pipeline status
            if self.fail_on_vulnerability and self._should_fail_build(scan_results):
                scan_results['pipeline_status'] = 'failed'
                scan_results['failure_reason'] = 'Vulnerabilities detected above threshold'
            
            # Set CI/CD specific outputs
            self._set_cicd_outputs(scan_results)
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Pipeline scan failed: {e}")
            scan_results['pipeline_status'] = 'error'
            scan_results['error_message'] = str(e)
            return scan_results
    
    def generate_security_gate_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate security gate report for CI/CD pipeline
        
        Args:
            scan_results: Results from pipeline scan
            
        Returns:
            Security gate report
        """
        gate_report = {
            'security_gate_status': 'passed',
            'gate_timestamp': datetime.utcnow().isoformat() + 'Z',
            'rules_evaluated': [],
            'violations': [],
            'recommendations': []
        }
        
        # Evaluate security gate rules
        rules = [
            {
                'name': 'No Critical Vulnerabilities',
                'condition': scan_results['critical_vulnerabilities'] == 0,
                'severity': 'critical',
                'description': 'Build must not contain critical vulnerabilities'
            },
            {
                'name': 'High Vulnerability Limit',
                'condition': scan_results['high_vulnerabilities'] <= 5,
                'severity': 'high',
                'description': 'Build must not contain more than 5 high-severity vulnerabilities'
            },
            {
                'name': 'Total Vulnerability Limit',
                'condition': scan_results['vulnerabilities_found'] <= 10,
                'severity': 'medium',
                'description': 'Build must not contain more than 10 total vulnerabilities'
            }
        ]
        
        for rule in rules:
            rule_result = {
                'rule_name': rule['name'],
                'passed': rule['condition'],
                'severity': rule['severity'],
                'description': rule['description']
            }
            
            gate_report['rules_evaluated'].append(rule_result)
            
            if not rule['condition']:
                gate_report['security_gate_status'] = 'failed'
                gate_report['violations'].append(rule_result)
        
        # Generate recommendations
        if scan_results['vulnerabilities_found'] > 0:
            gate_report['recommendations'].extend([
                'Review and fix detected vulnerabilities before deployment',
                'Run Bean Vulnerable with --enhanced-cf flag for remediation suggestions',
                'Consider implementing security code review process'
            ])
        
        return gate_report
    
    def _detect_cicd_environment(self) -> str:
        """Detect CI/CD environment from environment variables"""
        
        # GitHub Actions
        if os.getenv('GITHUB_ACTIONS'):
            return 'github_actions'
        
        # GitLab CI
        if os.getenv('GITLAB_CI'):
            return 'gitlab_ci'
        
        # Jenkins
        if os.getenv('JENKINS_URL') or os.getenv('BUILD_NUMBER'):
            return 'jenkins'
        
        # Azure DevOps
        if os.getenv('AZURE_HTTP_USER_AGENT') or os.getenv('TF_BUILD'):
            return 'azure_devops'
        
        # Travis CI
        if os.getenv('TRAVIS'):
            return 'travis_ci'
        
        # CircleCI
        if os.getenv('CIRCLECI'):
            return 'circleci'
        
        # Bitbucket Pipelines
        if os.getenv('BITBUCKET_BUILD_NUMBER'):
            return 'bitbucket'
        
        return 'generic'
    
    def _scan_path(self, source_path: str) -> List[Dict[str, Any]]:
        """Scan a single source path"""
        results = []
        source_path = Path(source_path)
        
        if source_path.is_file():
            # Single file
            if self._should_scan_file(source_path):
                result = self._scan_single_file(source_path)
                if result:
                    results.append(result)
        else:
            # Directory
            for file_path in source_path.rglob('*'):
                if file_path.is_file() and self._should_scan_file(file_path):
                    result = self._scan_single_file(file_path)
                    if result:
                        results.append(result)
        
        return results
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned"""
        
        # Check file extension
        supported_extensions = {'.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.rb', '.go', '.cpp', '.c', '.cs'}
        if file_path.suffix.lower() not in supported_extensions:
            return False
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if file_path.match(pattern):
                return False
        
        # Skip common non-source directories
        skip_dirs = {'node_modules', '.git', '__pycache__', 'target', 'build', 'dist', '.gradle'}
        if any(part in skip_dirs for part in file_path.parts):
            return False
        
        return True
    
    def _scan_single_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Scan a single file using Bean Vulnerable framework"""
        try:
            # This would integrate with the main Bean Vulnerable framework
            # For now, return a mock result
            return {
                'input': str(file_path),
                'vulnerability_detected': False,  # Would be actual result
                'confidence': 0.0,
                'vulnerabilities_found': [],
                'scan_timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return None
    
    def _should_fail_build(self, scan_results: Dict[str, Any]) -> bool:
        """Determine if build should fail based on scan results"""
        
        # Check critical vulnerabilities
        if scan_results['critical_vulnerabilities'] > 0:
            return True
        
        # Check high vulnerabilities above threshold
        if scan_results['high_vulnerabilities'] > 0 and self.severity_threshold <= 0.7:
            return True
        
        # Check medium vulnerabilities above threshold
        if scan_results['medium_vulnerabilities'] > 0 and self.severity_threshold <= 0.5:
            return True
        
        return False
    
    def _generate_reports(self, scan_results: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Generate various report formats"""
        
        # Ensure report directory exists
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        
        if self.output_format == 'json':
            self._generate_json_report(scan_results, summary)
        elif self.output_format == 'junit':
            self._generate_junit_report(scan_results, summary)
        elif self.output_format == 'sarif':
            self._generate_sarif_report(scan_results, summary)
        elif self.output_format == 'text':
            self._generate_text_report(scan_results, summary)
        
        # Always generate JSON for programmatic access
        if self.output_format != 'json':
            self._generate_json_report(scan_results, summary)
    
    def _generate_json_report(self, scan_results: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Generate JSON report"""
        report_file = self.report_path.with_suffix('.json')
        
        report = {
            'summary': summary,
            'detailed_results': scan_results,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'framework': 'bean_vulnerable_gnn',
            'version': '1.0.0'
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        summary['reports_generated'].append(str(report_file))
        logger.info(f"JSON report generated: {report_file}")
    
    def _generate_junit_report(self, scan_results: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Generate JUnit XML report"""
        report_file = self.report_path.with_suffix('.xml')
        
        # Create JUnit XML structure
        junit_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="BeanVulnerable" tests="{summary['total_files_scanned']}" failures="{summary['vulnerabilities_found']}" errors="0" time="0">
"""
        
        for result in scan_results:
            file_path = result.get('input', 'unknown')
            vuln_detected = result.get('vulnerability_detected', False)
            
            if vuln_detected:
                vulnerabilities = result.get('vulnerabilities_found', [])
                confidence = result.get('confidence', 0.0)
                
                junit_xml += f"""  <testcase name="{file_path}" classname="VulnerabilityDetection">
    <failure message="Vulnerabilities detected: {', '.join(vulnerabilities)}" type="SecurityVulnerability">
      File: {file_path}
      Confidence: {confidence}
      Vulnerabilities: {', '.join(vulnerabilities)}
    </failure>
  </testcase>
"""
            else:
                junit_xml += f"""  <testcase name="{file_path}" classname="VulnerabilityDetection"/>
"""
        
        junit_xml += "</testsuite>"
        
        with open(report_file, 'w') as f:
            f.write(junit_xml)
        
        summary['reports_generated'].append(str(report_file))
        logger.info(f"JUnit report generated: {report_file}")
    
    def _generate_sarif_report(self, scan_results: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Generate SARIF report"""
        report_file = self.report_path.with_suffix('.sarif')
        
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Bean Vulnerable GNN Framework",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/bean-vulnerable/framework"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for result in scan_results:
            if result.get('vulnerability_detected', False):
                file_path = result.get('input', 'unknown')
                vulnerabilities = result.get('vulnerabilities_found', [])
                confidence = result.get('confidence', 0.0)
                
                for vuln in vulnerabilities:
                    sarif_result = {
                        "ruleId": vuln.upper(),
                        "message": {
                            "text": f"Potential {vuln.replace('_', ' ').title()} vulnerability detected"
                        },
                        "level": "error" if confidence >= 0.7 else "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": file_path
                                    }
                                }
                            }
                        ],
                        "properties": {
                            "confidence": confidence,
                            "framework": "bean_vulnerable_gnn"
                        }
                    }
                    
                    sarif_report["runs"][0]["results"].append(sarif_result)
        
        with open(report_file, 'w') as f:
            json.dump(sarif_report, f, indent=2)
        
        summary['reports_generated'].append(str(report_file))
        logger.info(f"SARIF report generated: {report_file}")
    
    def _generate_text_report(self, scan_results: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Generate text report"""
        report_file = self.report_path.with_suffix('.txt')
        
        with open(report_file, 'w') as f:
            f.write("Bean Vulnerable GNN Framework - Security Scan Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Scan Timestamp: {summary['scan_timestamp']}\n")
            f.write(f"CI/CD Platform: {summary['cicd_type']}\n")
            f.write(f"Total Files Scanned: {summary['total_files_scanned']}\n")
            f.write(f"Vulnerabilities Found: {summary['vulnerabilities_found']}\n\n")
            
            f.write("Severity Breakdown:\n")
            f.write(f"  Critical: {summary['critical_vulnerabilities']}\n")
            f.write(f"  High: {summary['high_vulnerabilities']}\n")
            f.write(f"  Medium: {summary['medium_vulnerabilities']}\n")
            f.write(f"  Low: {summary['low_vulnerabilities']}\n\n")
            
            if summary['files_with_vulnerabilities']:
                f.write("Files with Vulnerabilities:\n")
                f.write("-" * 30 + "\n")
                
                for file_info in summary['files_with_vulnerabilities']:
                    f.write(f"File: {file_info['file']}\n")
                    f.write(f"Confidence: {file_info['confidence']:.3f}\n")
                    f.write(f"Vulnerabilities: {', '.join(file_info['vulnerabilities'])}\n\n")
        
        summary['reports_generated'].append(str(report_file))
        logger.info(f"Text report generated: {report_file}")
    
    def _set_cicd_outputs(self, scan_results: Dict[str, Any]):
        """Set CI/CD specific outputs and environment variables"""
        
        if self.cicd_type == 'github_actions':
            self._set_github_actions_outputs(scan_results)
        elif self.cicd_type == 'gitlab_ci':
            self._set_gitlab_ci_outputs(scan_results)
        elif self.cicd_type == 'jenkins':
            self._set_jenkins_outputs(scan_results)
        elif self.cicd_type == 'azure_devops':
            self._set_azure_devops_outputs(scan_results)
    
    def _set_github_actions_outputs(self, scan_results: Dict[str, Any]):
        """Set GitHub Actions outputs"""
        try:
            # Set step outputs
            if 'GITHUB_OUTPUT' in os.environ:
                with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                    f.write(f"vulnerabilities_found={scan_results['vulnerabilities_found']}\n")
                    f.write(f"critical_vulnerabilities={scan_results['critical_vulnerabilities']}\n")
                    f.write(f"pipeline_status={scan_results['pipeline_status']}\n")
            
            # Set step summary
            if 'GITHUB_STEP_SUMMARY' in os.environ:
                with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
                    f.write("## Bean Vulnerable Security Scan Results\n\n")
                    f.write(f"- **Total Files Scanned**: {scan_results['total_files_scanned']}\n")
                    f.write(f"- **Vulnerabilities Found**: {scan_results['vulnerabilities_found']}\n")
                    f.write(f"- **Critical**: {scan_results['critical_vulnerabilities']}\n")
                    f.write(f"- **High**: {scan_results['high_vulnerabilities']}\n")
                    f.write(f"- **Medium**: {scan_results['medium_vulnerabilities']}\n")
                    f.write(f"- **Low**: {scan_results['low_vulnerabilities']}\n")
                    
        except Exception as e:
            logger.error(f"Error setting GitHub Actions outputs: {e}")
    
    def _set_gitlab_ci_outputs(self, scan_results: Dict[str, Any]):
        """Set GitLab CI outputs"""
        try:
            # GitLab CI doesn't have direct output mechanism, but we can use artifacts
            # and environment variables for next stages
            pass
        except Exception as e:
            logger.error(f"Error setting GitLab CI outputs: {e}")
    
    def _set_jenkins_outputs(self, scan_results: Dict[str, Any]):
        """Set Jenkins outputs"""
        try:
            # Jenkins can read from properties files
            properties_file = Path('bean_vulnerable.properties')
            with open(properties_file, 'w') as f:
                f.write(f"VULNERABILITIES_FOUND={scan_results['vulnerabilities_found']}\n")
                f.write(f"CRITICAL_VULNERABILITIES={scan_results['critical_vulnerabilities']}\n")
                f.write(f"PIPELINE_STATUS={scan_results['pipeline_status']}\n")
                
        except Exception as e:
            logger.error(f"Error setting Jenkins outputs: {e}")
    
    def _set_azure_devops_outputs(self, scan_results: Dict[str, Any]):
        """Set Azure DevOps outputs"""
        try:
            # Azure DevOps logging commands
            print(f"##vso[task.setvariable variable=vulnerabilities_found;isOutput=true]{scan_results['vulnerabilities_found']}")
            print(f"##vso[task.setvariable variable=critical_vulnerabilities;isOutput=true]{scan_results['critical_vulnerabilities']}")
            print(f"##vso[task.setvariable variable=pipeline_status;isOutput=true]{scan_results['pipeline_status']}")
            
        except Exception as e:
            logger.error(f"Error setting Azure DevOps outputs: {e}")


# Example CI/CD configuration templates
CICD_CONFIG_TEMPLATES = {
    'github_actions': {
        'type': 'github_actions',
        'fail_on_vulnerability': True,
        'severity_threshold': 0.7,
        'output_format': 'sarif',
        'report_path': 'security-report'
    },
    'gitlab_ci': {
        'type': 'gitlab_ci',
        'fail_on_vulnerability': True,
        'severity_threshold': 0.7,
        'output_format': 'json',
        'report_path': 'security-report'
    },
    'jenkins': {
        'type': 'jenkins',
        'fail_on_vulnerability': False,
        'severity_threshold': 0.6,
        'output_format': 'junit',
        'report_path': 'security-report'
    }
} 