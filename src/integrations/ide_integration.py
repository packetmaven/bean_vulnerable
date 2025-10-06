"""
Bean Vulnerable GNN Framework - IDE Integration
Integrates with popular IDEs for real-time vulnerability detection
"""

import json
import logging
import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class IDEIntegration:
    """Integration with IDEs for real-time vulnerability detection"""
    
    def __init__(self, ide_config: Optional[Dict[str, Any]] = None):
        """
        Initialize IDE integration
        
        Args:
            ide_config: Configuration for IDE integration
                - type: IDE type ('vscode', 'intellij', 'eclipse', 'vim', 'emacs')
                - port: Port for IDE communication
                - auto_scan: Enable automatic scanning on file save
                - real_time: Enable real-time analysis
                - severity_threshold: Minimum severity to report
        """
        self.config = ide_config or {}
        self.ide_type = self.config.get('type', 'generic')
        self.port = self.config.get('port', 8765)
        self.auto_scan = self.config.get('auto_scan', True)
        self.real_time = self.config.get('real_time', False)
        self.severity_threshold = self.config.get('severity_threshold', 0.5)
        
        self.server_socket = None
        self.running = False
        self.connections = []
        
        logger.info(f"✅ IDE Integration initialized for {self.ide_type}")
    
    def start_server(self) -> bool:
        """Start IDE communication server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            # Start server thread
            server_thread = threading.Thread(target=self._server_loop, daemon=True)
            server_thread.start()
            
            logger.info(f"IDE server started on port {self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start IDE server: {e}")
            return False
    
    def stop_server(self):
        """Stop IDE communication server"""
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
            
        for conn in self.connections:
            conn.close()
        
        self.connections.clear()
        logger.info("IDE server stopped")
    
    def send_vulnerability_notification(self, file_path: str, vulnerability_result: Dict[str, Any]) -> bool:
        """
        Send vulnerability notification to IDE
        
        Args:
            file_path: Path to the analyzed file
            vulnerability_result: Vulnerability analysis result
            
        Returns:
            bool: Success status
        """
        try:
            # Transform result to IDE format
            ide_notification = self._transform_to_ide_format(file_path, vulnerability_result)
            
            # Send to appropriate IDE
            if self.ide_type == 'vscode':
                return self._send_to_vscode(ide_notification)
            elif self.ide_type == 'intellij':
                return self._send_to_intellij(ide_notification)
            elif self.ide_type == 'eclipse':
                return self._send_to_eclipse(ide_notification)
            else:
                return self._send_generic_ide(ide_notification)
                
        except Exception as e:
            logger.error(f"Failed to send IDE notification: {e}")
            return False
    
    def register_file_watcher(self, callback: Callable[[str], None]) -> bool:
        """
        Register file watcher for automatic scanning
        
        Args:
            callback: Callback function to call when file changes
            
        Returns:
            bool: Success status
        """
        try:
            if self.auto_scan:
                watcher_thread = threading.Thread(
                    target=self._file_watcher_loop, 
                    args=(callback,), 
                    daemon=True
                )
                watcher_thread.start()
                logger.info("File watcher registered")
                return True
            else:
                logger.info("Auto-scan disabled, file watcher not started")
                return False
                
        except Exception as e:
            logger.error(f"Failed to register file watcher: {e}")
            return False
    
    def _server_loop(self):
        """Main server loop for handling IDE connections"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.connections.append(conn)
                
                # Handle connection in separate thread
                conn_thread = threading.Thread(
                    target=self._handle_connection, 
                    args=(conn, addr), 
                    daemon=True
                )
                conn_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Server error: {e}")
                break
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle individual IDE connection"""
        logger.info(f"IDE connected from {addr}")
        
        try:
            while self.running:
                data = conn.recv(1024)
                if not data:
                    break
                    
                # Process IDE request
                try:
                    request = json.loads(data.decode('utf-8'))
                    response = self._process_ide_request(request)
                    
                    conn.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    error_response = {
                        'error': 'Invalid JSON format',
                        'status': 'error'
                    }
                    conn.send(json.dumps(error_response).encode('utf-8'))
                    
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            conn.close()
            if conn in self.connections:
                self.connections.remove(conn)
            logger.info(f"IDE disconnected from {addr}")
    
    def _process_ide_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process request from IDE"""
        request_type = request.get('type', 'unknown')
        
        if request_type == 'analyze_file':
            file_path = request.get('file_path')
            if file_path:
                # This would integrate with the main Bean Vulnerable framework
                return {
                    'status': 'success',
                    'message': f'Analysis queued for {file_path}',
                    'request_id': str(int(time.time()))
                }
            else:
                return {
                    'status': 'error',
                    'message': 'Missing file_path parameter'
                }
                
        elif request_type == 'get_status':
            return {
                'status': 'success',
                'server_status': 'running',
                'connections': len(self.connections),
                'auto_scan': self.auto_scan
            }
            
        elif request_type == 'configure':
            # Update configuration
            config_updates = request.get('config', {})
            self.config.update(config_updates)
            return {
                'status': 'success',
                'message': 'Configuration updated',
                'config': self.config
            }
            
        else:
            return {
                'status': 'error',
                'message': f'Unknown request type: {request_type}'
            }
    
    def _transform_to_ide_format(self, file_path: str, vulnerability_result: Dict[str, Any]) -> Dict[str, Any]:
        """Transform vulnerability result to IDE notification format"""
        
        vuln_detected = vulnerability_result.get('vulnerability_detected', False)
        confidence = vulnerability_result.get('confidence', 0.0)
        vulnerabilities = vulnerability_result.get('vulnerabilities_found', [])
        
        # Create IDE notification
        ide_notification = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'file_path': file_path,
            'vulnerability_detected': vuln_detected,
            'confidence': confidence,
            'severity': self._calculate_severity(confidence, vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'framework': 'bean_vulnerable_gnn',
            'version': '1.0.0'
        }
        
        # Add diagnostic information for IDEs
        diagnostics = []
        
        if vuln_detected and confidence >= self.severity_threshold:
            for vuln in vulnerabilities:
                diagnostic = {
                    'message': f'Potential {vuln.replace("_", " ").title()} vulnerability detected',
                    'severity': self._severity_to_diagnostic_level(confidence),
                    'source': 'bean_vulnerable',
                    'code': vuln.upper(),
                    'confidence': confidence
                }
                
                # Add line/column information if available
                if 'line_number' in vulnerability_result:
                    diagnostic['line'] = vulnerability_result['line_number']
                if 'column' in vulnerability_result:
                    diagnostic['column'] = vulnerability_result['column']
                
                diagnostics.append(diagnostic)
        
        ide_notification['diagnostics'] = diagnostics
        
        return ide_notification
    
    def _calculate_severity(self, confidence: float, vulnerabilities: List[str]) -> str:
        """Calculate severity level for IDE display"""
        high_risk_vulns = ['sql_injection', 'command_injection', 'xss', 'xxe']
        has_high_risk = any(vuln.lower() in high_risk_vulns for vuln in vulnerabilities)
        
        if confidence >= 0.8 and has_high_risk:
            return 'error'
        elif confidence >= 0.6 or has_high_risk:
            return 'warning'
        else:
            return 'info'
    
    def _severity_to_diagnostic_level(self, confidence: float) -> str:
        """Convert confidence to IDE diagnostic level"""
        if confidence >= 0.8:
            return 'error'
        elif confidence >= 0.6:
            return 'warning'
        else:
            return 'info'
    
    def _send_to_vscode(self, notification: Dict[str, Any]) -> bool:
        """Send notification to VS Code via Language Server Protocol"""
        try:
            # VS Code LSP format
            lsp_notification = {
                'jsonrpc': '2.0',
                'method': 'textDocument/publishDiagnostics',
                'params': {
                    'uri': f"file://{notification['file_path']}",
                    'diagnostics': notification['diagnostics']
                }
            }
            
            # Send to connected VS Code instances
            for conn in self.connections:
                try:
                    conn.send(json.dumps(lsp_notification).encode('utf-8'))
                except:
                    pass
                    
            return True
            
        except Exception as e:
            logger.error(f"Error sending to VS Code: {e}")
            return False
    
    def _send_to_intellij(self, notification: Dict[str, Any]) -> bool:
        """Send notification to IntelliJ IDEA"""
        try:
            # IntelliJ inspection format
            intellij_notification = {
                'type': 'inspection_result',
                'file': notification['file_path'],
                'inspections': []
            }
            
            for diagnostic in notification['diagnostics']:
                inspection = {
                    'severity': diagnostic['severity'].upper(),
                    'message': diagnostic['message'],
                    'line': diagnostic.get('line', 1),
                    'column': diagnostic.get('column', 1),
                    'inspection_class': 'BeanVulnerableInspection'
                }
                intellij_notification['inspections'].append(inspection)
            
            # Send to connected IntelliJ instances
            for conn in self.connections:
                try:
                    conn.send(json.dumps(intellij_notification).encode('utf-8'))
                except:
                    pass
                    
            return True
            
        except Exception as e:
            logger.error(f"Error sending to IntelliJ: {e}")
            return False
    
    def _send_to_eclipse(self, notification: Dict[str, Any]) -> bool:
        """Send notification to Eclipse IDE"""
        try:
            # Eclipse marker format
            eclipse_notification = {
                'type': 'problem_markers',
                'resource': notification['file_path'],
                'markers': []
            }
            
            for diagnostic in notification['diagnostics']:
                marker = {
                    'type': 'org.eclipse.core.resources.problemmarker',
                    'severity': 2 if diagnostic['severity'] == 'error' else 1,
                    'message': diagnostic['message'],
                    'line_number': diagnostic.get('line', 1),
                    'source_id': 'bean_vulnerable'
                }
                eclipse_notification['markers'].append(marker)
            
            # Send to connected Eclipse instances
            for conn in self.connections:
                try:
                    conn.send(json.dumps(eclipse_notification).encode('utf-8'))
                except:
                    pass
                    
            return True
            
        except Exception as e:
            logger.error(f"Error sending to Eclipse: {e}")
            return False
    
    def _send_generic_ide(self, notification: Dict[str, Any]) -> bool:
        """Send notification to generic IDE"""
        try:
            # Generic format
            generic_notification = {
                'type': 'vulnerability_notification',
                'data': notification
            }
            
            # Send to all connected IDEs
            for conn in self.connections:
                try:
                    conn.send(json.dumps(generic_notification).encode('utf-8'))
                except:
                    pass
                    
            return True
            
        except Exception as e:
            logger.error(f"Error sending to generic IDE: {e}")
            return False
    
    def _file_watcher_loop(self, callback: Callable[[str], None]):
        """File watcher loop for automatic scanning"""
        # This is a simplified file watcher
        # In production, you'd use a proper file system watcher library
        watched_files = set()
        
        while self.running:
            try:
                # Check for file changes
                # This would be replaced with proper file system events
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"File watcher error: {e}")
                break
    
    def generate_ide_plugin_config(self) -> Dict[str, Any]:
        """Generate configuration for IDE plugins"""
        return {
            'bean_vulnerable': {
                'server_host': 'localhost',
                'server_port': self.port,
                'auto_scan': self.auto_scan,
                'real_time': self.real_time,
                'severity_threshold': self.severity_threshold,
                'supported_languages': ['java', 'python', 'javascript', 'typescript'],
                'scan_on_save': True,
                'show_confidence': True,
                'enable_quick_fixes': True
            }
        }


# Example IDE configuration templates
IDE_CONFIG_TEMPLATES = {
    'vscode': {
        'type': 'vscode',
        'port': 8765,
        'auto_scan': True,
        'real_time': True,
        'severity_threshold': 0.5
    },
    'intellij': {
        'type': 'intellij',
        'port': 8766,
        'auto_scan': True,
        'real_time': False,
        'severity_threshold': 0.6
    },
    'eclipse': {
        'type': 'eclipse',
        'port': 8767,
        'auto_scan': True,
        'real_time': False,
        'severity_threshold': 0.5
    }
} 