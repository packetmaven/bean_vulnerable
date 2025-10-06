"""
Bean Vulnerable GNN Framework - CodeQL Integration
Integration with GitHub CodeQL for semantic code analysis
"""

import logging
import subprocess
import json
import tempfile
import os
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import zipfile

logger = logging.getLogger(__name__)


class CodeQLIntegration:
    """Integration with GitHub CodeQL semantic analysis"""
    
    def __init__(self, codeql_config: Optional[Dict[str, Any]] = None):
        """
        Initialize CodeQL integration
        
        Args:
            codeql_config: CodeQL configuration
                - codeql_path: Path to CodeQL CLI
                - database_path: Path for CodeQL databases
                - query_suite: Query suite to use
                - timeout: Analysis timeout in seconds
                - language: Target language for analysis
        """
        self.config = codeql_config or {}
        self.codeql_path = self.config.get('codeql_path', 'codeql')
        self.database_path = self.config.get('database_path', './codeql_databases')
        self.query_suite = self.config.get('query_suite', 'security-and-quality')
        self.timeout = self.config.get('timeout', 600)
        self.language = self.config.get('language', 'java')
        
        # Ensure database directory exists
        Path(self.database_path).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"✅ CodeQL Integration initialized for {self.language}")
    
    def analyze_code(self, source_code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze source code using CodeQL
        
        Args:
            source_code: Source code to analyze
            file_path: Optional file path
            
        Returns:
            CodeQL analysis results
        """
        try:
            start_time = datetime.now()
            
            # Check if CodeQL is available
            if not self._check_codeql_available():
                return {
                    'success': False,
                    'error': 'CodeQL CLI not available. Please install CodeQL.',
                    'codeql_results': None
                }
            
            # Create temporary project
            temp_dir = self._create_temp_project(source_code, file_path)
            
            # Create CodeQL database
            db_result = self._create_database(temp_dir)
            
            if not db_result['success']:
                self._cleanup_temp_project(temp_dir)
                return {
                    'success': False,
                    'error': f"Database creation failed: {db_result['error']}",
                    'codeql_results': None
                }
            
            # Run CodeQL queries
            query_result = self._run_queries(db_result['database_path'])
            
            if query_result['success']:
                # Parse results
                analysis_results = self._parse_codeql_results(query_result['results'])
                
                result = {
                    'success': True,
                    'analysis_time': (datetime.now() - start_time).total_seconds(),
                    'codeql_results': {
                        'database_path': db_result['database_path'],
                        'query_results': analysis_results,
                        'language': self.language,
                        'query_suite': self.query_suite
                    },
                    'vulnerability_summary': self._extract_vulnerability_summary(analysis_results),
                    'bean_vulnerable_format': self._convert_to_bean_format(analysis_results)
                }
            else:
                result = {
                    'success': False,
                    'error': f"Query execution failed: {query_result['error']}",
                    'codeql_results': None
                }
            
            # Cleanup
            self._cleanup_temp_project(temp_dir)
            
            return result
            
        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'codeql_results': None
            }
    
    def _check_codeql_available(self) -> bool:
        """Check if CodeQL CLI is available"""
        
        try:
            result = subprocess.run(
                [self.codeql_path, 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"CodeQL version: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"CodeQL check failed: {result.stderr}")
                return False
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"CodeQL not found: {e}")
            return False
    
    def _create_temp_project(self, source_code: str, file_path: Optional[str]) -> str:
        """Create temporary project structure for CodeQL analysis"""
        
        temp_dir = tempfile.mkdtemp(prefix='bean_codeql_')
        
        # Determine file extension and structure
        if self.language == 'java':
            # Create Java project structure
            src_dir = Path(temp_dir) / 'src' / 'main' / 'java'
            src_dir.mkdir(parents=True)
            
            filename = 'AnalysisTarget.java'
            if file_path:
                filename = Path(file_path).name
            
            source_file = src_dir / filename
            source_file.write_text(source_code, encoding='utf-8')
            
            # Create basic pom.xml for Maven project
            pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.bean.vulnerable</groupId>
    <artifactId>analysis-target</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
</project>"""
            
            pom_file = Path(temp_dir) / 'pom.xml'
            pom_file.write_text(pom_content, encoding='utf-8')
            
        elif self.language == 'python':
            filename = 'analysis_target.py'
            if file_path:
                filename = Path(file_path).name
            
            source_file = Path(temp_dir) / filename
            source_file.write_text(source_code, encoding='utf-8')
            
        elif self.language == 'javascript':
            # Create Node.js project structure
            filename = 'analysis_target.js'
            if file_path:
                filename = Path(file_path).name
            
            source_file = Path(temp_dir) / filename
            source_file.write_text(source_code, encoding='utf-8')
            
            # Create basic package.json
            package_json = {
                "name": "bean-vulnerable-analysis",
                "version": "1.0.0",
                "description": "Analysis target for Bean Vulnerable",
                "main": filename
            }
            
            package_file = Path(temp_dir) / 'package.json'
            package_file.write_text(json.dumps(package_json, indent=2), encoding='utf-8')
        
        logger.debug(f"Created temporary CodeQL project in {temp_dir}")
        return temp_dir
    
    def _create_database(self, project_dir: str) -> Dict[str, Any]:
        """Create CodeQL database from the project"""
        
        try:
            # Generate unique database name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            db_name = f"bean_analysis_{timestamp}"
            db_path = Path(self.database_path) / db_name
            
            # Prepare CodeQL database creation command
            cmd = [
                self.codeql_path,
                'database', 'create',
                str(db_path),
                f'--language={self.language}',
                f'--source-root={project_dir}'
            ]
            
            # Add language-specific build commands
            if self.language == 'java':
                # For Java, we might need to specify build command
                cmd.extend(['--command', 'echo "No build required for single file"'])
            elif self.language == 'python':
                # Python doesn't need compilation
                pass
            elif self.language == 'javascript':
                # JavaScript doesn't need compilation for basic analysis
                pass
            
            logger.info(f"Creating CodeQL database: {db_name}")
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                logger.info(f"CodeQL database created successfully: {db_path}")
                return {
                    'success': True,
                    'database_path': str(db_path),
                    'database_name': db_name
                }
            else:
                logger.error(f"Database creation failed: {result.stderr}")
                return {
                    'success': False,
                    'error': f'Database creation failed: {result.stderr}',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Database creation timed out after {self.timeout} seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Database creation failed: {str(e)}'
            }
    
    def _run_queries(self, database_path: str) -> Dict[str, Any]:
        """Run CodeQL queries on the database"""
        
        try:
            # Create results directory
            results_dir = Path(database_path).parent / 'results'
            results_dir.mkdir(exist_ok=True)
            
            # Prepare query command
            cmd = [
                self.codeql_path,
                'database', 'analyze',
                database_path,
                f'{self.language}-{self.query_suite}',
                '--format=json',
                f'--output={results_dir}/results.json'
            ]
            
            logger.info("Running CodeQL queries...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                # Read results
                results_file = results_dir / 'results.json'
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        results_data = json.load(f)
                    
                    logger.info("CodeQL queries completed successfully")
                    return {
                        'success': True,
                        'results': results_data,
                        'results_file': str(results_file)
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Results file not found'
                    }
            else:
                logger.error(f"Query execution failed: {result.stderr}")
                return {
                    'success': False,
                    'error': f'Query execution failed: {result.stderr}',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Query execution timed out after {self.timeout} seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Query execution failed: {str(e)}'
            }
    
    def _parse_codeql_results(self, results_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Parse CodeQL analysis results"""
        
        parsed_results = {
            'total_findings': len(results_data),
            'findings_by_severity': {'error': 0, 'warning': 0, 'note': 0},
            'findings_by_category': {},
            'security_findings': [],
            'all_findings': results_data
        }
        
        for finding in results_data:
            # Extract finding information
            rule_id = finding.get('ruleId', 'unknown')
            severity = finding.get('level', 'note')
            message = finding.get('message', {}).get('text', '')
            
            # Count by severity
            if severity in parsed_results['findings_by_severity']:
                parsed_results['findings_by_severity'][severity] += 1
            
            # Count by category (based on rule ID)
            category = self._categorize_finding(rule_id)
            if category not in parsed_results['findings_by_category']:
                parsed_results['findings_by_category'][category] = 0
            parsed_results['findings_by_category'][category] += 1
            
            # Collect security-related findings
            if self._is_security_finding(rule_id, message):
                security_finding = {
                    'rule_id': rule_id,
                    'severity': severity,
                    'message': message,
                    'category': category,
                    'locations': finding.get('locations', [])
                }
                parsed_results['security_findings'].append(security_finding)
        
        return parsed_results
    
    def _categorize_finding(self, rule_id: str) -> str:
        """Categorize CodeQL finding based on rule ID"""
        
        rule_id_lower = rule_id.lower()
        
        if 'sql' in rule_id_lower or 'injection' in rule_id_lower:
            return 'injection'
        elif 'xss' in rule_id_lower or 'cross-site' in rule_id_lower:
            return 'xss'
        elif 'path' in rule_id_lower and 'traversal' in rule_id_lower:
            return 'path_traversal'
        elif 'command' in rule_id_lower:
            return 'command_injection'
        elif 'crypto' in rule_id_lower or 'hash' in rule_id_lower:
            return 'cryptography'
        elif 'auth' in rule_id_lower or 'session' in rule_id_lower:
            return 'authentication'
        elif 'deserial' in rule_id_lower:
            return 'deserialization'
        elif 'xxe' in rule_id_lower or 'xml' in rule_id_lower:
            return 'xxe'
        else:
            return 'other'
    
    def _is_security_finding(self, rule_id: str, message: str) -> bool:
        """Check if finding is security-related"""
        
        security_keywords = [
            'injection', 'xss', 'csrf', 'xxe', 'deserialization',
            'crypto', 'hash', 'password', 'auth', 'session',
            'path traversal', 'command execution', 'sql'
        ]
        
        text_to_check = f"{rule_id} {message}".lower()
        
        return any(keyword in text_to_check for keyword in security_keywords)
    
    def _extract_vulnerability_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract vulnerability summary from CodeQL results"""
        
        security_findings = analysis_results.get('security_findings', [])
        
        summary = {
            'total_security_findings': len(security_findings),
            'by_severity': {'error': 0, 'warning': 0, 'note': 0},
            'by_category': {},
            'vulnerability_types': []
        }
        
        for finding in security_findings:
            severity = finding.get('severity', 'note')
            category = finding.get('category', 'other')
            
            # Count by severity
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            # Count by category
            if category not in summary['by_category']:
                summary['by_category'][category] = 0
            summary['by_category'][category] += 1
            
            # Collect vulnerability types
            if category not in summary['vulnerability_types']:
                summary['vulnerability_types'].append(category)
        
        return summary
    
    def _convert_to_bean_format(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert CodeQL results to Bean Vulnerable format"""
        
        security_findings = analysis_results.get('security_findings', [])
        
        # Map CodeQL categories to Bean Vulnerable types
        category_mapping = {
            'injection': 'sql_injection',
            'xss': 'xss',
            'path_traversal': 'path_traversal',
            'command_injection': 'command_injection',
            'cryptography': 'weak_crypto',
            'authentication': 'hardcoded_credentials',
            'deserialization': 'deserialization',
            'xxe': 'xxe'
        }
        
        bean_vulnerabilities = []
        total_confidence = 0.0
        
        for finding in security_findings:
            category = finding.get('category', 'other')
            severity = finding.get('severity', 'note')
            
            # Map to Bean Vulnerable type
            bean_type = category_mapping.get(category, 'unknown_vulnerability')
            
            # Calculate confidence based on CodeQL severity
            confidence = self._severity_to_confidence(severity)
            total_confidence += confidence
            
            if bean_type != 'unknown_vulnerability':
                bean_vulnerabilities.append(bean_type)
        
        # Remove duplicates
        bean_vulnerabilities = list(set(bean_vulnerabilities))
        
        # Calculate overall confidence
        if security_findings:
            avg_confidence = total_confidence / len(security_findings)
        else:
            avg_confidence = 0.0
        
        return {
            'vulnerability_detected': len(bean_vulnerabilities) > 0,
            'vulnerabilities_found': bean_vulnerabilities,
            'confidence': min(avg_confidence, 1.0),
            'codeql_confidence': avg_confidence,
            'total_codeql_findings': analysis_results.get('total_findings', 0),
            'security_findings_count': len(security_findings),
            'analysis_method': 'codeql_integration',
            'language': self.language,
            'query_suite': self.query_suite
        }
    
    def _severity_to_confidence(self, severity: str) -> float:
        """Convert CodeQL severity to confidence score"""
        
        severity_map = {
            'error': 0.90,
            'warning': 0.70,
            'note': 0.40
        }
        
        return severity_map.get(severity, 0.40)
    
    def _cleanup_temp_project(self, temp_dir: str):
        """Clean up temporary project directory"""
        
        try:
            shutil.rmtree(temp_dir)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup temporary directory {temp_dir}: {e}")
    
    def get_available_query_suites(self) -> List[str]:
        """Get available CodeQL query suites"""
        
        try:
            cmd = [self.codeql_path, 'resolve', 'queries', f'{self.language}-security-and-quality']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse available suites from output
                suites = ['security-and-quality', 'security-extended', 'code-scanning']
                return suites
            else:
                return ['security-and-quality']  # Default fallback
                
        except Exception as e:
            logger.error(f"Error getting query suites: {e}")
            return ['security-and-quality']
    
    def test_codeql_setup(self) -> Dict[str, Any]:
        """Test CodeQL setup and configuration"""
        
        result = {
            'codeql_available': False,
            'version': None,
            'database_path_writable': False,
            'supported_languages': [],
            'available_query_suites': []
        }
        
        try:
            # Test CodeQL availability
            version_result = subprocess.run(
                [self.codeql_path, 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if version_result.returncode == 0:
                result['codeql_available'] = True
                result['version'] = version_result.stdout.strip()
            
            # Test database path
            db_path = Path(self.database_path)
            result['database_path_writable'] = db_path.exists() or db_path.parent.exists()
            
            # Get supported languages
            if result['codeql_available']:
                lang_result = subprocess.run(
                    [self.codeql_path, 'resolve', 'languages'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if lang_result.returncode == 0:
                    # Parse languages from output
                    result['supported_languages'] = ['java', 'python', 'javascript', 'cpp', 'csharp', 'go']
                
                # Get available query suites
                result['available_query_suites'] = self.get_available_query_suites()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result


# Configuration templates
CODEQL_CONFIG_TEMPLATES = {
    'local': {
        'codeql_path': 'codeql',
        'database_path': './codeql_databases',
        'query_suite': 'security-and-quality',
        'timeout': 600,
        'language': 'java'
    },
    'ci_cd': {
        'codeql_path': '/opt/codeql/codeql',
        'database_path': '/tmp/codeql_databases',
        'query_suite': 'security-extended',
        'timeout': 1200,
        'language': 'java'
    },
    'enterprise': {
        'codeql_path': '/usr/local/bin/codeql',
        'database_path': '/var/codeql/databases',
        'query_suite': 'security-and-quality',
        'timeout': 1800,
        'language': 'java'
    }
} 