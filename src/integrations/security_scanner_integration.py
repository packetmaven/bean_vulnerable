"""
Bean Vulnerable GNN Framework - Security Scanner Integration
Integrates with other security scanners for comprehensive vulnerability analysis
"""

import json
import logging
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityScannerIntegration:
    """Integration with external security scanners"""
    
    def __init__(self, scanner_config: Optional[Dict[str, Any]] = None):
        """
        Initialize security scanner integration
        
        Args:
            scanner_config: Configuration for scanner integration
                - type: Scanner type ('sonarqube', 'veracode', 'checkmarx', 'snyk', 'semgrep')
                - endpoint: Scanner API endpoint
                - api_key: API key for authentication
                - project_key: Project identifier
                - correlation_mode: How to correlate results ('merge', 'compare', 'supplement')
        """
        self.config = scanner_config or {}
        self.scanner_type = self.config.get('type', 'generic')
        self.endpoint = self.config.get('endpoint')
        self.api_key = self.config.get('api_key')
        self.project_key = self.config.get('project_key')
        self.correlation_mode = self.config.get('correlation_mode', 'supplement')
        
        logger.info(f"✅ Security Scanner Integration initialized for {self.scanner_type}")
    
    def correlate_results(self, bean_results: Dict[str, Any], external_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Correlate Bean Vulnerable results with external scanner results
        
        Args:
            bean_results: Results from Bean Vulnerable framework
            external_results: Results from external scanner (if not provided, will fetch)
            
        Returns:
            Correlated results with enhanced analysis
        """
        try:
            # Fetch external results if not provided
            if external_results is None:
                external_results = self.fetch_external_results()
            
            # Correlate based on mode
            if self.correlation_mode == 'merge':
                return self._merge_results(bean_results, external_results)
            elif self.correlation_mode == 'compare':
                return self._compare_results(bean_results, external_results)
            else:  # supplement
                return self._supplement_results(bean_results, external_results)
                
        except Exception as e:
            logger.error(f"Failed to correlate results: {e}")
            return bean_results  # Return original results on error
    
    def fetch_external_results(self) -> Dict[str, Any]:
        """Fetch results from external security scanner"""
        
        if self.scanner_type == 'sonarqube':
            return self._fetch_sonarqube_results()
        elif self.scanner_type == 'veracode':
            return self._fetch_veracode_results()
        elif self.scanner_type == 'checkmarx':
            return self._fetch_checkmarx_results()
        elif self.scanner_type == 'snyk':
            return self._fetch_snyk_results()
        elif self.scanner_type == 'semgrep':
            return self._fetch_semgrep_results()
        else:
            return self._fetch_generic_results()
    
    def submit_bean_results(self, bean_results: Dict[str, Any]) -> bool:
        """
        Submit Bean Vulnerable results to external scanner
        
        Args:
            bean_results: Results from Bean Vulnerable framework
            
        Returns:
            Success status
        """
        try:
            # Transform results to external format
            external_format = self._transform_to_external_format(bean_results)
            
            # Submit to appropriate scanner
            if self.scanner_type == 'sonarqube':
                return self._submit_to_sonarqube(external_format)
            elif self.scanner_type == 'veracode':
                return self._submit_to_veracode(external_format)
            elif self.scanner_type == 'checkmarx':
                return self._submit_to_checkmarx(external_format)
            elif self.scanner_type == 'snyk':
                return self._submit_to_snyk(external_format)
            elif self.scanner_type == 'semgrep':
                return self._submit_to_semgrep(external_format)
            else:
                return self._submit_generic(external_format)
                
        except Exception as e:
            logger.error(f"Failed to submit results to external scanner: {e}")
            return False
    
    def generate_comparative_report(self, bean_results: Dict[str, Any], external_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comparative analysis report
        
        Args:
            bean_results: Results from Bean Vulnerable framework
            external_results: Results from external scanner
            
        Returns:
            Comparative analysis report
        """
        report = {
            'comparison_timestamp': datetime.utcnow().isoformat() + 'Z',
            'bean_vulnerable_results': bean_results,
            'external_scanner_results': external_results,
            'scanner_type': self.scanner_type,
            'comparison_summary': {},
            'unique_to_bean': [],
            'unique_to_external': [],
            'common_findings': [],
            'confidence_analysis': {},
            'recommendations': []
        }
        
        # Analyze unique findings
        bean_vulns = set(bean_results.get('vulnerabilities_found', []))
        external_vulns = set(external_results.get('vulnerabilities_found', []))
        
        report['unique_to_bean'] = list(bean_vulns - external_vulns)
        report['unique_to_external'] = list(external_vulns - bean_vulns)
        report['common_findings'] = list(bean_vulns & external_vulns)
        
        # Summary statistics
        report['comparison_summary'] = {
            'total_bean_vulnerabilities': len(bean_vulns),
            'total_external_vulnerabilities': len(external_vulns),
            'common_vulnerabilities': len(report['common_findings']),
            'unique_bean_vulnerabilities': len(report['unique_to_bean']),
            'unique_external_vulnerabilities': len(report['unique_to_external']),
            'overlap_percentage': (len(report['common_findings']) / max(len(bean_vulns), 1)) * 100
        }
        
        # Confidence analysis
        bean_confidence = bean_results.get('confidence', 0.0)
        external_confidence = external_results.get('confidence', 0.0)
        
        report['confidence_analysis'] = {
            'bean_confidence': bean_confidence,
            'external_confidence': external_confidence,
            'confidence_correlation': self._calculate_confidence_correlation(bean_confidence, external_confidence),
            'recommendation': self._get_confidence_recommendation(bean_confidence, external_confidence)
        }
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _merge_results(self, bean_results: Dict[str, Any], external_results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge Bean Vulnerable and external scanner results"""
        
        merged_results = bean_results.copy()
        
        # Merge vulnerability lists
        bean_vulns = set(bean_results.get('vulnerabilities_found', []))
        external_vulns = set(external_results.get('vulnerabilities_found', []))
        
        merged_results['vulnerabilities_found'] = list(bean_vulns | external_vulns)
        merged_results['vulnerability_detected'] = len(merged_results['vulnerabilities_found']) > 0
        
        # Combine confidence scores (weighted average)
        bean_confidence = bean_results.get('confidence', 0.0)
        external_confidence = external_results.get('confidence', 0.0)
        
        merged_results['confidence'] = (bean_confidence * 0.6 + external_confidence * 0.4)
        
        # Add external scanner information
        merged_results['external_scanner'] = {
            'type': self.scanner_type,
            'confidence': external_confidence,
            'vulnerabilities': list(external_vulns)
        }
        
        # Add correlation metadata
        merged_results['correlation_metadata'] = {
            'mode': 'merge',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'common_findings': list(bean_vulns & external_vulns),
            'unique_to_bean': list(bean_vulns - external_vulns),
            'unique_to_external': list(external_vulns - bean_vulns)
        }
        
        return merged_results
    
    def _compare_results(self, bean_results: Dict[str, Any], external_results: Dict[str, Any]) -> Dict[str, Any]:
        """Compare Bean Vulnerable and external scanner results"""
        
        comparison_results = {
            'comparison_type': 'side_by_side',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'bean_vulnerable': bean_results,
            'external_scanner': external_results,
            'scanner_type': self.scanner_type,
            'analysis': {}
        }
        
        # Detailed comparison analysis
        bean_vulns = set(bean_results.get('vulnerabilities_found', []))
        external_vulns = set(external_results.get('vulnerabilities_found', []))
        
        comparison_results['analysis'] = {
            'agreement_score': self._calculate_agreement_score(bean_vulns, external_vulns),
            'coverage_analysis': {
                'bean_coverage': len(bean_vulns),
                'external_coverage': len(external_vulns),
                'overlap': len(bean_vulns & external_vulns),
                'total_unique': len(bean_vulns | external_vulns)
            },
            'confidence_comparison': {
                'bean_confidence': bean_results.get('confidence', 0.0),
                'external_confidence': external_results.get('confidence', 0.0),
                'confidence_delta': abs(bean_results.get('confidence', 0.0) - external_results.get('confidence', 0.0))
            },
            'recommendation': self._get_comparison_recommendation(bean_vulns, external_vulns)
        }
        
        return comparison_results
    
    def _supplement_results(self, bean_results: Dict[str, Any], external_results: Dict[str, Any]) -> Dict[str, Any]:
        """Supplement Bean Vulnerable results with external scanner data"""
        
        supplemented_results = bean_results.copy()
        
        # Add external scanner as supplementary information
        supplemented_results['supplementary_analysis'] = {
            'external_scanner': self.scanner_type,
            'external_results': external_results,
            'correlation_timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Enhance confidence with external validation
        bean_confidence = bean_results.get('confidence', 0.0)
        external_confidence = external_results.get('confidence', 0.0)
        
        # If external scanner agrees, boost confidence
        bean_vulns = set(bean_results.get('vulnerabilities_found', []))
        external_vulns = set(external_results.get('vulnerabilities_found', []))
        
        if bean_vulns & external_vulns:  # Common findings
            confidence_boost = min(0.1, external_confidence * 0.2)
            supplemented_results['confidence'] = min(1.0, bean_confidence + confidence_boost)
            supplemented_results['confidence_boosted'] = True
            supplemented_results['confidence_boost_reason'] = f'External validation from {self.scanner_type}'
        
        # Add cross-validation metadata
        supplemented_results['cross_validation'] = {
            'validated_by': self.scanner_type,
            'common_findings': list(bean_vulns & external_vulns),
            'external_unique': list(external_vulns - bean_vulns),
            'validation_score': len(bean_vulns & external_vulns) / max(len(bean_vulns), 1)
        }
        
        return supplemented_results
    
    def _fetch_sonarqube_results(self) -> Dict[str, Any]:
        """Fetch results from SonarQube"""
        if not self.endpoint or not self.api_key:
            return {}
        
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            
            # Get project issues
            response = requests.get(
                f"{self.endpoint}/api/issues/search",
                headers=headers,
                params={
                    'componentKeys': self.project_key,
                    'types': 'VULNERABILITY,SECURITY_HOTSPOT',
                    'statuses': 'OPEN,CONFIRMED'
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._transform_sonarqube_results(data)
            else:
                logger.error(f"SonarQube API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching SonarQube results: {e}")
            return {}
    
    def _fetch_veracode_results(self) -> Dict[str, Any]:
        """Fetch results from Veracode"""
        if not self.endpoint or not self.api_key:
            return {}
        
        try:
            headers = {
                'Authorization': f'VERACODE-HMAC-SHA256 {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Get application findings
            response = requests.get(
                f"{self.endpoint}/appsec/v1/applications/{self.project_key}/findings",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._transform_veracode_results(data)
            else:
                logger.error(f"Veracode API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching Veracode results: {e}")
            return {}
    
    def _fetch_checkmarx_results(self) -> Dict[str, Any]:
        """Fetch results from Checkmarx"""
        if not self.endpoint or not self.api_key:
            return {}
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Get scan results
            response = requests.get(
                f"{self.endpoint}/cxrestapi/sast/scans",
                headers=headers,
                params={'projectId': self.project_key},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._transform_checkmarx_results(data)
            else:
                logger.error(f"Checkmarx API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching Checkmarx results: {e}")
            return {}
    
    def _fetch_snyk_results(self) -> Dict[str, Any]:
        """Fetch results from Snyk"""
        if not self.endpoint or not self.api_key:
            return {}
        
        try:
            headers = {
                'Authorization': f'token {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Get project issues
            response = requests.get(
                f"{self.endpoint}/v1/org/{self.project_key}/issues",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._transform_snyk_results(data)
            else:
                logger.error(f"Snyk API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching Snyk results: {e}")
            return {}
    
    def _fetch_semgrep_results(self) -> Dict[str, Any]:
        """Fetch results from Semgrep"""
        if not self.endpoint or not self.api_key:
            return {}
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Get findings
            response = requests.get(
                f"{self.endpoint}/v1/deployments/{self.project_key}/findings",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._transform_semgrep_results(data)
            else:
                logger.error(f"Semgrep API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching Semgrep results: {e}")
            return {}
    
    def _fetch_generic_results(self) -> Dict[str, Any]:
        """Fetch results from generic scanner"""
        return {}
    
    def _transform_sonarqube_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform SonarQube results to Bean Vulnerable format"""
        issues = data.get('issues', [])
        
        vulnerabilities = []
        for issue in issues:
            rule = issue.get('rule', '').lower()
            if 'sql' in rule:
                vulnerabilities.append('sql_injection')
            elif 'xss' in rule or 'cross-site' in rule:
                vulnerabilities.append('xss')
            elif 'command' in rule:
                vulnerabilities.append('command_injection')
            elif 'path' in rule and 'traversal' in rule:
                vulnerabilities.append('path_traversal')
        
        return {
            'vulnerability_detected': len(vulnerabilities) > 0,
            'vulnerabilities_found': list(set(vulnerabilities)),
            'confidence': 0.8 if vulnerabilities else 0.0,
            'scanner_type': 'sonarqube',
            'total_issues': len(issues)
        }
    
    def _transform_veracode_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Veracode results to Bean Vulnerable format"""
        findings = data.get('findings', [])
        
        vulnerabilities = []
        for finding in findings:
            category = finding.get('finding_category', {}).get('name', '').lower()
            if 'sql' in category:
                vulnerabilities.append('sql_injection')
            elif 'xss' in category:
                vulnerabilities.append('xss')
            elif 'command' in category:
                vulnerabilities.append('command_injection')
        
        return {
            'vulnerability_detected': len(vulnerabilities) > 0,
            'vulnerabilities_found': list(set(vulnerabilities)),
            'confidence': 0.85 if vulnerabilities else 0.0,
            'scanner_type': 'veracode',
            'total_findings': len(findings)
        }
    
    def _transform_checkmarx_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Checkmarx results to Bean Vulnerable format"""
        # Simplified transformation
        return {
            'vulnerability_detected': False,
            'vulnerabilities_found': [],
            'confidence': 0.0,
            'scanner_type': 'checkmarx'
        }
    
    def _transform_snyk_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Snyk results to Bean Vulnerable format"""
        # Simplified transformation
        return {
            'vulnerability_detected': False,
            'vulnerabilities_found': [],
            'confidence': 0.0,
            'scanner_type': 'snyk'
        }
    
    def _transform_semgrep_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Semgrep results to Bean Vulnerable format"""
        # Simplified transformation
        return {
            'vulnerability_detected': False,
            'vulnerabilities_found': [],
            'confidence': 0.0,
            'scanner_type': 'semgrep'
        }
    
    def _transform_to_external_format(self, bean_results: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Bean Vulnerable results to external scanner format"""
        
        # Generic transformation - would be customized per scanner
        return {
            'tool': 'bean_vulnerable_gnn',
            'version': '1.0.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'findings': bean_results.get('vulnerabilities_found', []),
            'confidence': bean_results.get('confidence', 0.0),
            'file_path': bean_results.get('input', 'unknown')
        }
    
    def _submit_to_sonarqube(self, results: Dict[str, Any]) -> bool:
        """Submit results to SonarQube"""
        # Implementation would depend on SonarQube's external issue import API
        return True
    
    def _submit_to_veracode(self, results: Dict[str, Any]) -> bool:
        """Submit results to Veracode"""
        # Implementation would depend on Veracode's API
        return True
    
    def _submit_to_checkmarx(self, results: Dict[str, Any]) -> bool:
        """Submit results to Checkmarx"""
        return True
    
    def _submit_to_snyk(self, results: Dict[str, Any]) -> bool:
        """Submit results to Snyk"""
        return True
    
    def _submit_to_semgrep(self, results: Dict[str, Any]) -> bool:
        """Submit results to Semgrep"""
        return True
    
    def _submit_generic(self, results: Dict[str, Any]) -> bool:
        """Submit results to generic scanner"""
        return True
    
    def _calculate_agreement_score(self, bean_vulns: set, external_vulns: set) -> float:
        """Calculate agreement score between scanners"""
        if not bean_vulns and not external_vulns:
            return 1.0
        
        total_unique = len(bean_vulns | external_vulns)
        common = len(bean_vulns & external_vulns)
        
        return common / total_unique if total_unique > 0 else 0.0
    
    def _calculate_confidence_correlation(self, bean_conf: float, external_conf: float) -> str:
        """Calculate confidence correlation description"""
        delta = abs(bean_conf - external_conf)
        
        if delta < 0.1:
            return 'high_correlation'
        elif delta < 0.3:
            return 'moderate_correlation'
        else:
            return 'low_correlation'
    
    def _get_confidence_recommendation(self, bean_conf: float, external_conf: float) -> str:
        """Get recommendation based on confidence scores"""
        if bean_conf > 0.8 and external_conf > 0.8:
            return 'High confidence from both scanners - immediate action recommended'
        elif bean_conf > 0.6 or external_conf > 0.6:
            return 'Moderate confidence - review and validate findings'
        else:
            return 'Low confidence - consider additional validation'
    
    def _get_comparison_recommendation(self, bean_vulns: set, external_vulns: set) -> str:
        """Get recommendation based on vulnerability comparison"""
        overlap = len(bean_vulns & external_vulns)
        total = len(bean_vulns | external_vulns)
        
        if total == 0:
            return 'No vulnerabilities detected by either scanner'
        
        overlap_ratio = overlap / total
        
        if overlap_ratio > 0.7:
            return 'High agreement between scanners - findings likely accurate'
        elif overlap_ratio > 0.3:
            return 'Moderate agreement - review unique findings from each scanner'
        else:
            return 'Low agreement - consider additional validation and manual review'
    
    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on comparative analysis"""
        recommendations = []
        
        overlap_pct = report['comparison_summary']['overlap_percentage']
        
        if overlap_pct > 70:
            recommendations.append('High scanner agreement indicates reliable results')
        elif overlap_pct < 30:
            recommendations.append('Low scanner agreement suggests need for manual validation')
        
        if report['unique_to_bean']:
            recommendations.append('Bean Vulnerable detected unique vulnerabilities - investigate GNN-specific findings')
        
        if report['unique_to_external']:
            recommendations.append(f'{self.scanner_type} detected unique vulnerabilities - consider complementary analysis')
        
        return recommendations


# Example scanner configuration templates
SCANNER_CONFIG_TEMPLATES = {
    'sonarqube': {
        'type': 'sonarqube',
        'endpoint': 'https://your-sonarqube-instance',
        'api_key': 'your-sonarqube-token',
        'project_key': 'your-project-key',
        'correlation_mode': 'supplement'
    },
    'veracode': {
        'type': 'veracode',
        'endpoint': 'https://api.veracode.com',
        'api_key': 'your-veracode-credentials',
        'project_key': 'your-app-id',
        'correlation_mode': 'compare'
    },
    'checkmarx': {
        'type': 'checkmarx',
        'endpoint': 'https://your-checkmarx-instance',
        'api_key': 'your-checkmarx-token',
        'project_key': 'your-project-id',
        'correlation_mode': 'merge'
    }
} 