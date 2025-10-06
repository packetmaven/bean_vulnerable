"""
Bean Vulnerable GNN Framework - SonarQube Integration
Integration with SonarQube for comprehensive static analysis
"""

import logging
import requests
import json
import time
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class SonarQubeIntegration:
    """Integration with SonarQube static analysis platform"""
    
    def __init__(self, sonar_config: Optional[Dict[str, Any]] = None):
        """
        Initialize SonarQube integration
        
        Args:
            sonar_config: SonarQube configuration
                - server_url: SonarQube server URL
                - token: Authentication token
                - project_key: Project key for analysis
                - quality_gate: Quality gate to check
                - timeout: Analysis timeout in seconds
        """
        self.config = sonar_config or {}
        self.server_url = self.config.get('server_url', 'http://localhost:9000')
        self.token = self.config.get('token', '')
        self.project_key = self.config.get('project_key', 'bean_vulnerable_analysis')
        self.quality_gate = self.config.get('quality_gate', 'Sonar way')
        self.timeout = self.config.get('timeout', 300)
        
        # API endpoints
        self.api_base = f"{self.server_url}/api"
        
        # Headers for API requests
        self.headers = {
            'Authorization': f'Bearer {self.token}' if self.token else '',
            'Content-Type': 'application/json'
        }
        
        logger.info(f"✅ SonarQube Integration initialized for {self.server_url}")
    
    def analyze_code(self, source_code: str, file_path: Optional[str] = None, 
                    language: str = 'java') -> Dict[str, Any]:
        """
        Analyze source code using SonarQube
        
        Args:
            source_code: Source code to analyze
            file_path: Optional file path
            language: Programming language
            
        Returns:
            SonarQube analysis results
        """
        try:
            start_time = time.time()
            
            # Create temporary project structure
            temp_dir = self._create_temp_project(source_code, file_path, language)
            
            # Run SonarQube analysis
            analysis_result = self._run_sonar_scanner(temp_dir)
            
            if analysis_result['success']:
                # Get analysis results from server
                issues = self._get_project_issues()
                metrics = self._get_project_metrics()
                quality_gate_status = self._get_quality_gate_status()
                
                result = {
                    'success': True,
                    'analysis_time': time.time() - start_time,
                    'sonarqube_results': {
                        'issues': issues,
                        'metrics': metrics,
                        'quality_gate': quality_gate_status,
                        'project_key': self.project_key,
                        'server_url': self.server_url
                    },
                    'vulnerability_summary': self._extract_vulnerability_summary(issues),
                    'bean_vulnerable_format': self._convert_to_bean_format(issues, metrics)
                }
            else:
                result = {
                    'success': False,
                    'error': analysis_result.get('error', 'SonarQube analysis failed'),
                    'sonarqube_results': None
                }
            
            # Cleanup
            self._cleanup_temp_project(temp_dir)
            
            return result
            
        except Exception as e:
            logger.error(f"SonarQube analysis failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'sonarqube_results': None
            }
    
    def _create_temp_project(self, source_code: str, file_path: Optional[str], language: str) -> str:
        """Create temporary project structure for SonarQube analysis"""
        
        temp_dir = tempfile.mkdtemp(prefix='bean_sonar_')
        
        # Determine file extension
        if language == 'java':
            extension = '.java'
            filename = 'AnalysisTarget.java'
        elif language == 'python':
            extension = '.py'
            filename = 'analysis_target.py'
        elif language == 'javascript':
            extension = '.js'
            filename = 'analysis_target.js'
        else:
            extension = '.txt'
            filename = 'analysis_target.txt'
        
        # Use provided file path or generate one
        if file_path:
            filename = Path(file_path).name
        
        # Create source file
        source_file = Path(temp_dir) / filename
        source_file.write_text(source_code, encoding='utf-8')
        
        # Create sonar-project.properties
        sonar_props = f"""
sonar.projectKey={self.project_key}
sonar.projectName=Bean Vulnerable Analysis
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.language={language}
sonar.java.source=11
sonar.java.target=11
"""
        
        props_file = Path(temp_dir) / 'sonar-project.properties'
        props_file.write_text(sonar_props.strip(), encoding='utf-8')
        
        logger.debug(f"Created temporary SonarQube project in {temp_dir}")
        return temp_dir
    
    def _run_sonar_scanner(self, project_dir: str) -> Dict[str, Any]:
        """Run SonarQube scanner on the project"""
        
        try:
            # Check if sonar-scanner is available
            scanner_cmd = self._find_sonar_scanner()
            if not scanner_cmd:
                return {
                    'success': False,
                    'error': 'SonarQube scanner not found. Please install sonar-scanner.'
                }
            
            # Prepare scanner command
            cmd = [
                scanner_cmd,
                f'-Dsonar.host.url={self.server_url}',
                f'-Dsonar.projectBaseDir={project_dir}'
            ]
            
            if self.token:
                cmd.append(f'-Dsonar.login={self.token}')
            
            # Run scanner
            logger.info("Running SonarQube scanner...")
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                logger.info("SonarQube analysis completed successfully")
                return {
                    'success': True,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                logger.error(f"SonarQube scanner failed: {result.stderr}")
                return {
                    'success': False,
                    'error': f'Scanner failed with code {result.returncode}: {result.stderr}',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'SonarQube analysis timed out after {self.timeout} seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Scanner execution failed: {str(e)}'
            }
    
    def _find_sonar_scanner(self) -> Optional[str]:
        """Find SonarQube scanner executable"""
        
        # Common scanner locations
        scanner_names = ['sonar-scanner', 'sonar-scanner.bat']
        
        for name in scanner_names:
            try:
                result = subprocess.run(['which', name], capture_output=True, text=True)
                if result.returncode == 0:
                    return name
            except:
                pass
        
        # Check common installation paths
        common_paths = [
            '/usr/local/bin/sonar-scanner',
            '/opt/sonar-scanner/bin/sonar-scanner',
            'C:\\sonar-scanner\\bin\\sonar-scanner.bat'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _get_project_issues(self) -> List[Dict[str, Any]]:
        """Get issues for the analyzed project"""
        
        try:
            url = f"{self.api_base}/issues/search"
            params = {
                'componentKeys': self.project_key,
                'types': 'VULNERABILITY,BUG,CODE_SMELL,SECURITY_HOTSPOT',
                'ps': 500  # Page size
            }
            
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('issues', [])
            else:
                logger.error(f"Failed to get issues: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting project issues: {e}")
            return []
    
    def _get_project_metrics(self) -> Dict[str, Any]:
        """Get metrics for the analyzed project"""
        
        try:
            url = f"{self.api_base}/measures/component"
            params = {
                'component': self.project_key,
                'metricKeys': 'ncloc,complexity,coverage,duplicated_lines_density,violations,bugs,vulnerabilities,security_hotspots,code_smells'
            }
            
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                component = data.get('component', {})
                measures = component.get('measures', [])
                
                metrics = {}
                for measure in measures:
                    metric_key = measure.get('metric')
                    value = measure.get('value', '0')
                    metrics[metric_key] = value
                
                return metrics
            else:
                logger.error(f"Failed to get metrics: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting project metrics: {e}")
            return {}
    
    def _get_quality_gate_status(self) -> Dict[str, Any]:
        """Get quality gate status for the project"""
        
        try:
            url = f"{self.api_base}/qualitygates/project_status"
            params = {'projectKey': self.project_key}
            
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('projectStatus', {})
            else:
                logger.error(f"Failed to get quality gate status: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting quality gate status: {e}")
            return {}
    
    def _extract_vulnerability_summary(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract vulnerability summary from SonarQube issues"""
        
        summary = {
            'total_issues': len(issues),
            'vulnerabilities': 0,
            'security_hotspots': 0,
            'bugs': 0,
            'code_smells': 0,
            'by_severity': {'BLOCKER': 0, 'CRITICAL': 0, 'MAJOR': 0, 'MINOR': 0, 'INFO': 0},
            'vulnerability_types': {}
        }
        
        for issue in issues:
            issue_type = issue.get('type', 'UNKNOWN')
            severity = issue.get('severity', 'INFO')
            rule = issue.get('rule', '')
            
            # Count by type
            if issue_type == 'VULNERABILITY':
                summary['vulnerabilities'] += 1
            elif issue_type == 'SECURITY_HOTSPOT':
                summary['security_hotspots'] += 1
            elif issue_type == 'BUG':
                summary['bugs'] += 1
            elif issue_type == 'CODE_SMELL':
                summary['code_smells'] += 1
            
            # Count by severity
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            # Count vulnerability types
            if issue_type in ['VULNERABILITY', 'SECURITY_HOTSPOT']:
                if rule not in summary['vulnerability_types']:
                    summary['vulnerability_types'][rule] = 0
                summary['vulnerability_types'][rule] += 1
        
        return summary
    
    def _convert_to_bean_format(self, issues: List[Dict[str, Any]], metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Convert SonarQube results to Bean Vulnerable format"""
        
        # Map SonarQube findings to Bean Vulnerable vulnerability types
        vulnerability_mapping = {
            'squid:S2077': 'sql_injection',
            'squid:S2078': 'ldap_injection', 
            'squid:S5131': 'xss',
            'squid:S4507': 'command_injection',
            'squid:S2083': 'path_traversal',
            'squid:S2068': 'hardcoded_credentials',
            'squid:S4790': 'weak_crypto',
            'squid:S5542': 'csrf'
        }
        
        bean_vulnerabilities = []
        total_confidence = 0.0
        
        for issue in issues:
            if issue.get('type') in ['VULNERABILITY', 'SECURITY_HOTSPOT']:
                rule = issue.get('rule', '')
                severity = issue.get('severity', 'INFO')
                
                # Map to Bean Vulnerable type
                bean_type = vulnerability_mapping.get(rule, 'unknown_vulnerability')
                
                # Calculate confidence based on SonarQube severity
                confidence = self._severity_to_confidence(severity)
                total_confidence += confidence
                
                if bean_type != 'unknown_vulnerability':
                    bean_vulnerabilities.append(bean_type)
        
        # Remove duplicates
        bean_vulnerabilities = list(set(bean_vulnerabilities))
        
        # Calculate overall confidence
        if bean_vulnerabilities:
            avg_confidence = total_confidence / len(issues) if issues else 0.0
        else:
            avg_confidence = 0.0
        
        return {
            'vulnerability_detected': len(bean_vulnerabilities) > 0,
            'vulnerabilities_found': bean_vulnerabilities,
            'confidence': min(avg_confidence, 1.0),
            'sonarqube_confidence': avg_confidence,
            'total_sonar_issues': len(issues),
            'analysis_method': 'sonarqube_integration',
            'quality_metrics': {
                'lines_of_code': int(metrics.get('ncloc', 0)),
                'complexity': int(metrics.get('complexity', 0)),
                'violations': int(metrics.get('violations', 0)),
                'bugs': int(metrics.get('bugs', 0)),
                'vulnerabilities': int(metrics.get('vulnerabilities', 0)),
                'security_hotspots': int(metrics.get('security_hotspots', 0))
            }
        }
    
    def _severity_to_confidence(self, severity: str) -> float:
        """Convert SonarQube severity to confidence score"""
        
        severity_map = {
            'BLOCKER': 0.95,
            'CRITICAL': 0.85,
            'MAJOR': 0.70,
            'MINOR': 0.50,
            'INFO': 0.30
        }
        
        return severity_map.get(severity, 0.30)
    
    def _cleanup_temp_project(self, temp_dir: str):
        """Clean up temporary project directory"""
        
        try:
            import shutil
            shutil.rmtree(temp_dir)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup temporary directory {temp_dir}: {e}")
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection to SonarQube server"""
        
        try:
            url = f"{self.api_base}/system/status"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'status': data.get('status', 'UNKNOWN'),
                    'version': data.get('version', 'UNKNOWN'),
                    'server_url': self.server_url
                }
            else:
                return {
                    'success': False,
                    'error': f'Server returned status {response.status_code}',
                    'server_url': self.server_url
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'server_url': self.server_url
            }
    
    def get_available_rules(self, language: str = 'java') -> List[Dict[str, Any]]:
        """Get available SonarQube rules for a language"""
        
        try:
            url = f"{self.api_base}/rules/search"
            params = {
                'languages': language,
                'types': 'VULNERABILITY,SECURITY_HOTSPOT',
                'ps': 500
            }
            
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('rules', [])
            else:
                logger.error(f"Failed to get rules: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting available rules: {e}")
            return []


# Configuration templates
SONARQUBE_CONFIG_TEMPLATES = {
    'local': {
        'server_url': 'http://localhost:9000',
        'token': '',
        'project_key': 'bean_vulnerable_local',
        'quality_gate': 'Sonar way',
        'timeout': 300
    },
    'cloud': {
        'server_url': 'https://sonarcloud.io',
        'token': 'your_sonarcloud_token',
        'project_key': 'your_org_bean_vulnerable',
        'quality_gate': 'Sonar way',
        'timeout': 600
    },
    'enterprise': {
        'server_url': 'https://your-sonarqube-server.com',
        'token': 'your_enterprise_token',
        'project_key': 'bean_vulnerable_enterprise',
        'quality_gate': 'Custom Quality Gate',
        'timeout': 900
    }
} 