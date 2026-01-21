#!/usr/bin/env python3
"""
Basic tests for Bean Vulnerable GNN Framework
"""

import unittest
import sys
import os
import shutil
from pathlib import Path

# Avoid NumPy import issues in test environments
os.environ.setdefault("BEAN_VULN_DISABLE_NUMPY", "1")

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.integrated_gnn_framework import IntegratedGNNFramework, JoernIntegrator, VulnerabilityDetector

def _joern_available() -> bool:
    return (
        shutil.which("joern") is not None or
        Path("/usr/local/bin/joern").exists() or
        Path("/opt/joern/joern-cli/joern").exists()
    )


class TestJoernIntegrator(unittest.TestCase):
    """Test Joern integration"""
    
    def setUp(self):
        if not _joern_available():
            self.skipTest("Joern not installed; skipping Joern integration tests.")
        self.integrator = JoernIntegrator()
    
    def test_joern_detection(self):
        """Test Joern path detection"""
        # Should not raise exception
        self.assertIsNotNone(self.integrator)
    
    def test_cpg_generation(self):
        """Test CPG generation with simple Java code"""
        java_code = """
        public class Test {
            public void method() {
                System.out.println("Hello");
            }
        }
        """
        result = self.integrator.generate_cpg(java_code)
        
        self.assertIn('cpg', result)
        self.assertIn('nodes', result['cpg'])
        self.assertIn('methods', result['cpg'])
        self.assertIn('calls', result['cpg'])


class TestVulnerabilityDetector(unittest.TestCase):
    """Test vulnerability detection"""
    
    def setUp(self):
        self.detector = VulnerabilityDetector()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        vulnerable_code = """
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        executeQuery(query);
        """
        patterns = self.detector.detect_patterns(vulnerable_code)
        self.assertIn('sql_injection', patterns)
    
    def test_command_injection_detection(self):
        """Test command injection pattern detection"""
        vulnerable_code = """
        Runtime.getRuntime().exec("ping " + userInput);
        """
        patterns = self.detector.detect_patterns(vulnerable_code)
        self.assertIn('command_injection', patterns)
    
    def test_safe_code_detection(self):
        """Test that safe code doesn't trigger false positives"""
        safe_code = """
        public void safeMethod() {
            System.out.println("This is safe");
        }
        """
        patterns = self.detector.detect_patterns(safe_code)
        self.assertEqual(len(patterns), 0)


class TestIntegratedGNNFramework(unittest.TestCase):
    """Test integrated framework"""
    
    def setUp(self):
        if not _joern_available():
            self.skipTest("Joern not installed; skipping integrated framework tests.")
        self.framework = IntegratedGNNFramework()
    
    def test_framework_initialization(self):
        """Test framework initializes correctly"""
        self.assertIsNotNone(self.framework.joern_integrator)
        self.assertIsNotNone(self.framework.vulnerability_detector)
    
    def test_sql_injection_analysis(self):
        """Test complete analysis of SQL injection"""
        vulnerable_code = """
        public class SQLInjectionTest {
            public void vulnerableMethod(String userId) {
                String query = "SELECT * FROM users WHERE id = '" + userId + "'";
                executeQuery(query);
            }
            
            private void executeQuery(String query) {
                System.out.println("Executing: " + query);
            }
        }
        """
        result = self.framework.analyze_code(vulnerable_code)
        
        self.assertTrue(result['vulnerability_detected'])
        self.assertEqual(result['vulnerability_type'], 'sql_injection')
        self.assertGreater(result['confidence'], 0.5)
        spatial_meta = result.get('spatial_gnn', {})
        self.assertTrue(result['gnn_utilized'])
        if spatial_meta.get('weights_loaded'):
            self.assertTrue(spatial_meta.get('used_in_scoring', False))
        else:
            self.assertFalse(spatial_meta.get('used_in_scoring', False))
    
    def test_safe_code_analysis(self):
        """Test analysis of safe code"""
        safe_code = """
        public class SafeCode {
            public void safeMethod() {
                System.out.println("This is safe");
            }
        }
        """
        result = self.framework.analyze_code(safe_code)
        
        self.assertFalse(result['vulnerability_detected'])
        self.assertEqual(result['vulnerability_type'], 'none')


if __name__ == '__main__':
    unittest.main()

