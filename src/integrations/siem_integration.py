"""
Bean Vulnerable GNN Framework - SIEM Integration
Integrates with Security Information and Event Management (SIEM) systems
"""

import json
import logging
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class SIEMIntegration:
    """Integration with SIEM systems for vulnerability detection alerts"""
    
    def __init__(self, siem_config: Optional[Dict[str, Any]] = None):
        """
        Initialize SIEM integration
        
        Args:
            siem_config: Configuration for SIEM system
                - type: SIEM type ('splunk', 'elastic', 'qradar', 'sentinel', 'generic')
                - endpoint: SIEM API endpoint
                - api_key: API key for authentication
                - index: Index/database name
                - source: Source identifier
        """
        self.config = siem_config or {}
        self.siem_type = self.config.get('type', 'generic')
        self.endpoint = self.config.get('endpoint')
        self.api_key = self.config.get('api_key')
        self.index = self.config.get('index', 'bean_vulnerable')
        self.source = self.config.get('source', 'bean_vulnerable_framework')
        
        logger.info(f"✅ SIEM Integration initialized for {self.siem_type}")
    
    def send_vulnerability_alert(self, vulnerability_result: Dict[str, Any]) -> bool:
        """
        Send vulnerability detection result to SIEM system
        
        Args:
            vulnerability_result: Vulnerability analysis result from Bean Vulnerable
            
        Returns:
            bool: Success status
        """
        try:
            # Transform result to SIEM format
            siem_event = self._transform_to_siem_format(vulnerability_result)
            
            # Send to appropriate SIEM
            if self.siem_type == 'splunk':
                return self._send_to_splunk(siem_event)
            elif self.siem_type == 'elastic':
                return self._send_to_elasticsearch(siem_event)
            elif self.siem_type == 'qradar':
                return self._send_to_qradar(siem_event)
            elif self.siem_type == 'sentinel':
                return self._send_to_sentinel(siem_event)
            else:
                return self._send_generic(siem_event)
                
        except Exception as e:
            logger.error(f"Failed to send vulnerability alert to SIEM: {e}")
            return False
    
    def send_batch_alerts(self, vulnerability_results: List[Dict[str, Any]]) -> int:
        """
        Send multiple vulnerability alerts in batch
        
        Args:
            vulnerability_results: List of vulnerability analysis results
            
        Returns:
            int: Number of successfully sent alerts
        """
        success_count = 0
        
        for result in vulnerability_results:
            if self.send_vulnerability_alert(result):
                success_count += 1
                
        logger.info(f"Sent {success_count}/{len(vulnerability_results)} alerts to SIEM")
        return success_count
    
    def _transform_to_siem_format(self, vulnerability_result: Dict[str, Any]) -> Dict[str, Any]:
        """Transform vulnerability result to SIEM event format"""
        
        # Extract key information
        vuln_detected = vulnerability_result.get('vulnerability_detected', False)
        confidence = vulnerability_result.get('confidence', 0.0)
        vulnerabilities = vulnerability_result.get('vulnerabilities_found', [])
        file_path = vulnerability_result.get('input', 'unknown')
        
        # Create SIEM event
        siem_event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source': self.source,
            'event_type': 'vulnerability_detection',
            'severity': self._calculate_severity(confidence, vulnerabilities),
            'vulnerability_detected': vuln_detected,
            'confidence_score': confidence,
            'file_path': file_path,
            'vulnerabilities_found': vulnerabilities,
            'detection_method': 'bean_vulnerable_gnn',
            'framework_version': '1.0.0'
        }
        
        # Add CPG information if available
        if 'cpg' in vulnerability_result:
            cpg = vulnerability_result['cpg']
            siem_event.update({
                'code_nodes': cpg.get('nodes', 0),
                'code_edges': cpg.get('edges', 0),
                'code_methods': cpg.get('methods', 0),
                'code_calls': cpg.get('calls', 0)
            })
        
        # Add AEG analysis if available
        if 'aeg_analysis' in vulnerability_result:
            aeg = vulnerability_result['aeg_analysis']
            siem_event.update({
                'exploitability_score': aeg.get('exploitability_score', 0.0),
                'exploit_feasible': aeg.get('feasible', False),
                'analysis_method': aeg.get('analysis_method', 'unknown')
            })
        
        # Add quality validation if available
        if 'quality_validation' in vulnerability_result:
            quality = vulnerability_result['quality_validation']
            siem_event.update({
                'quality_score': quality.get('quality_score', 0.0),
                'quality_issues': quality.get('issues', [])
            })
        
        return siem_event
    
    def _calculate_severity(self, confidence: float, vulnerabilities: List[str]) -> str:
        """Calculate event severity based on confidence and vulnerability types"""
        
        # High-risk vulnerability types
        high_risk_vulns = ['sql_injection', 'command_injection', 'xss', 'xxe', 'deserialization']
        
        # Check for high-risk vulnerabilities
        has_high_risk = any(vuln.lower() in high_risk_vulns for vuln in vulnerabilities)
        
        if confidence >= 0.8 and has_high_risk:
            return 'critical'
        elif confidence >= 0.7 or has_high_risk:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _send_to_splunk(self, event: Dict[str, Any]) -> bool:
        """Send event to Splunk HEC (HTTP Event Collector)"""
        if not self.endpoint or not self.api_key:
            logger.warning("Splunk endpoint or API key not configured")
            return False
            
        try:
            headers = {
                'Authorization': f'Splunk {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'index': self.index,
                'source': self.source,
                'event': event
            }
            
            response = requests.post(
                f"{self.endpoint}/services/collector/event",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.debug("Successfully sent event to Splunk")
                return True
            else:
                logger.error(f"Splunk API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to Splunk: {e}")
            return False
    
    def _send_to_elasticsearch(self, event: Dict[str, Any]) -> bool:
        """Send event to Elasticsearch"""
        if not self.endpoint:
            logger.warning("Elasticsearch endpoint not configured")
            return False
            
        try:
            headers = {'Content-Type': 'application/json'}
            
            if self.api_key:
                headers['Authorization'] = f'ApiKey {self.api_key}'
            
            # Use timestamp for document ID
            doc_id = f"bean_vuln_{int(time.time() * 1000)}"
            
            response = requests.post(
                f"{self.endpoint}/{self.index}/_doc/{doc_id}",
                headers=headers,
                json=event,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                logger.debug("Successfully sent event to Elasticsearch")
                return True
            else:
                logger.error(f"Elasticsearch API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to Elasticsearch: {e}")
            return False
    
    def _send_to_qradar(self, event: Dict[str, Any]) -> bool:
        """Send event to IBM QRadar"""
        if not self.endpoint or not self.api_key:
            logger.warning("QRadar endpoint or API key not configured")
            return False
            
        try:
            headers = {
                'SEC': self.api_key,
                'Content-Type': 'application/json',
                'Version': '12.0'
            }
            
            # QRadar custom event format
            qradar_event = {
                'magnitude': self._severity_to_magnitude(event.get('severity', 'low')),
                'event_name': 'Bean Vulnerable Detection',
                'description': f"Vulnerability detected in {event.get('file_path', 'unknown')}",
                'custom_properties': event
            }
            
            response = requests.post(
                f"{self.endpoint}/api/siem/events",
                headers=headers,
                json=qradar_event,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                logger.debug("Successfully sent event to QRadar")
                return True
            else:
                logger.error(f"QRadar API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to QRadar: {e}")
            return False
    
    def _send_to_sentinel(self, event: Dict[str, Any]) -> bool:
        """Send event to Microsoft Sentinel"""
        if not self.endpoint or not self.api_key:
            logger.warning("Sentinel endpoint or API key not configured")
            return False
            
        try:
            headers = {
                'Authorization': f'SharedKey {self.api_key}',
                'Content-Type': 'application/json',
                'Log-Type': 'BeanVulnerable'
            }
            
            response = requests.post(
                f"{self.endpoint}/api/logs",
                headers=headers,
                json=[event],  # Sentinel expects array
                timeout=30
            )
            
            if response.status_code == 200:
                logger.debug("Successfully sent event to Sentinel")
                return True
            else:
                logger.error(f"Sentinel API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to Sentinel: {e}")
            return False
    
    def _send_generic(self, event: Dict[str, Any]) -> bool:
        """Send event to generic webhook/API endpoint"""
        if not self.endpoint:
            logger.warning("Generic endpoint not configured")
            return False
            
        try:
            headers = {'Content-Type': 'application/json'}
            
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = requests.post(
                self.endpoint,
                headers=headers,
                json=event,
                timeout=30
            )
            
            if response.status_code in [200, 201, 202]:
                logger.debug("Successfully sent event to generic endpoint")
                return True
            else:
                logger.error(f"Generic API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to generic endpoint: {e}")
            return False
    
    def _severity_to_magnitude(self, severity: str) -> int:
        """Convert severity to QRadar magnitude (1-10)"""
        severity_map = {
            'critical': 10,
            'high': 8,
            'medium': 6,
            'low': 4
        }
        return severity_map.get(severity.lower(), 4)
    
    def test_connection(self) -> bool:
        """Test connection to SIEM system"""
        try:
            test_event = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'source': self.source,
                'event_type': 'connection_test',
                'message': 'Bean Vulnerable Framework SIEM integration test'
            }
            
            return self.send_vulnerability_alert({'test': True})
            
        except Exception as e:
            logger.error(f"SIEM connection test failed: {e}")
            return False


# Example configuration templates
SIEM_CONFIG_TEMPLATES = {
    'splunk': {
        'type': 'splunk',
        'endpoint': 'https://your-splunk-instance:8088',
        'api_key': 'your-hec-token',
        'index': 'security',
        'source': 'bean_vulnerable'
    },
    'elastic': {
        'type': 'elastic',
        'endpoint': 'https://your-elasticsearch-cluster:9200',
        'api_key': 'your-api-key',
        'index': 'security-vulnerabilities',
        'source': 'bean_vulnerable'
    },
    'qradar': {
        'type': 'qradar',
        'endpoint': 'https://your-qradar-instance',
        'api_key': 'your-sec-token',
        'source': 'bean_vulnerable'
    },
    'sentinel': {
        'type': 'sentinel',
        'endpoint': 'https://your-workspace.ods.opinsights.azure.com',
        'api_key': 'your-shared-key',
        'source': 'bean_vulnerable'
    }
} 