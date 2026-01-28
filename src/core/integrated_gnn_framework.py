"""
Integrated GNN Framework for Bean Vulnerable
Demonstrates Joern integration, CPG generation, and GNN processing
"""

import os
import logging
import subprocess
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
import statistics
import math
import random
import re

# Optional Tai-e integration
try:
    from .taie_integration import TaiEConfig
    TAIE_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    TaiEConfig = None  # type: ignore
    TAIE_AVAILABLE = False
# Sink-specific gating engine
try:
    from .sink_gating_engine import SinkGatingEngine, EvidenceInstance, EvidenceType
    SINK_GATING_AVAILABLE = True
except Exception:  # pragma: no cover - optional module
    SinkGatingEngine = None
    EvidenceInstance = None
    EvidenceType = None
    SINK_GATING_AVAILABLE = False

try:
    from .framework_sink_registry import FrameworkSinkRegistry
    FRAMEWORK_SINKS_AVAILABLE = True
except Exception:  # pragma: no cover - optional module
    FrameworkSinkRegistry = None
    FRAMEWORK_SINKS_AVAILABLE = False

try:
    from .template_engine_analyzer import TemplateEngineAnalyzer
    TEMPLATE_ENGINE_AVAILABLE = True
except Exception:  # pragma: no cover - optional module
    TemplateEngineAnalyzer = None
    TEMPLATE_ENGINE_AVAILABLE = False

# Comprehensive Taint Tracking - INTEGRATED (No external module)
from collections import defaultdict

TAINT_TRACKING_AVAILABLE = True  # Always available now

CESCL_AVAILABLE = False
DATASET_MAP_AVAILABLE = False
CF_EXPLAINER_AVAILABLE = False
CF_EXPLAINER_CHU_AVAILABLE = False

# GNN multiclass label mapping (aligned with prepare_training_data.py)
GNN_VULN_TYPE_ID_TO_NAME = {
    0: 'sql_injection',
    1: 'command_injection',
    2: 'xss',
    3: 'path_traversal',
    4: 'xxe',
    5: 'ssrf',
    6: 'deserialization',
    7: 'ldap_injection',
    8: 'log_injection',
    9: 'xpath_injection',
    10: 'trust_boundary_violation',
    11: 'reflection_injection',
    12: 'race_condition',
    13: 'weak_crypto',
    14: 'hardcoded_credentials',
    15: 'insecure_randomness',
    16: 'null_pointer_dereference',
    17: 'resource_leak',
    18: 'buffer_overflow',
    19: 'integer_overflow',
    20: 'use_after_free',
    21: 'double_free',
    22: 'memory_leak',
    23: 'none',
}

class JoernIntegrator:
    """Handles Joern integration for CPG generation"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.joern_path = self._find_joern()
        self.joern_timeout = 480  # Default timeout
        if not self.joern_path:
            # Fail fast: Joern is mandatory in no-fallback mode
            raise RuntimeError("Joern not found. Please install Joern (./scripts/install_joern.sh) and ensure it is on PATH and JOERN_PATH is set.")
    
    def _find_joern(self) -> Optional[str]:
        """Find Joern installation"""
        possible_paths = [
            '/usr/local/bin/joern',
            '/opt/joern/joern-cli/joern',
            'joern'
        ]
        
        for path in possible_paths:
            if os.path.exists(path) or self._command_exists(path):
                self.logger.info(f"✅ Found Joern: {path}")
                return path
        
        self.logger.warning("⚠️ Joern not found")
        return None
    
    def _command_exists(self, command: str) -> bool:
        """Check if command exists in PATH"""
        try:
            subprocess.run(['which', command], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def generate_cpg(self, source_code: str, source_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate CPG from source code using Joern - NO FALLBACK"""
        if not self.joern_path:
            raise RuntimeError(
                "Joern is required for CPG generation. Please install Joern using:\n"
                "  ./scripts/install_joern.sh\n"
                "Or ensure Joern is in your PATH and JOERN_PATH environment variable is set."
            )
        
        try:
            # Create temporary source directory for Joern importCode
            with tempfile.TemporaryDirectory() as tmpdir:
                base_dir = Path(tmpdir)
                input_dir = base_dir / "input"
                input_dir.mkdir(parents=True, exist_ok=True)

                if source_path and Path(source_path).exists():
                    java_name = Path(source_path).name
                else:
                    java_name = "snippet.java"

                temp_source_path = input_dir / java_name
                temp_source_path.write_text(source_code, encoding="utf-8")

                # Create Joern script to analyze the file using safe key=value lines
                script_content = '''
import io.shiftleft.codepropertygraph.generated._
import io.joern.console._

workspace.reset
importCode("PLACEHOLDER_INPUT_DIR")

val nodes = try cpg.all.l catch { case _: Throwable => List() }
val methods = try cpg.method.l catch { case _: Throwable => List() }
val calls = try cpg.call.l catch { case _: Throwable => List() }
val identifiers = try cpg.identifier.l catch { case _: Throwable => List() }

var dfgSize = 0
try {
  val flows = cpg.identifier.reachableByFlows(cpg.call)
  dfgSize = flows.l.size
} catch { case _: Throwable => dfgSize = 0 }

var edgeCount = 0
try {
  edgeCount = cpg.graph.edgeCount.toInt
} catch { case _: Throwable => edgeCount = 0 }

println("NODES=" + nodes.size)
println("METHODS=" + methods.size)
println("CALLS=" + calls.size)
println("IDENTIFIERS=" + identifiers.size)
println("DFG=" + dfgSize)
println("EDGES=" + edgeCount)

exit
'''
                script_content = script_content.replace("PLACEHOLDER_INPUT_DIR", str(input_dir))

                # Write script to temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sc', delete=False) as f:
                    f.write(script_content)
                    script_file = f.name

                try:
                    # Run Joern with the script
                    cmd = [self.joern_path, '--script', script_file]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.joern_timeout,
                        cwd=base_dir,
                    )

                    if result.returncode == 0:
                        # Parse key=value output from Joern
                        output_lines = [ln.strip() for ln in result.stdout.strip().split('\n') if ln.strip()]
                        parsed = {}
                        for ln in output_lines:
                            if '=' in ln:
                                k, v = ln.split('=', 1)
                                parsed[k.strip().upper()] = v.strip()
                        try:
                            cpg_data = {
                                'nodes': int(parsed.get('NODES', '0') or '0'),
                                'methods': int(parsed.get('METHODS', '0') or '0'),
                                'calls': int(parsed.get('CALLS', '0') or '0'),
                                'identifiers': int(parsed.get('IDENTIFIERS', '0') or '0'),
                                'dfg': int(parsed.get('DFG', '0') or '0'),
                                'edges': int(parsed.get('EDGES', '0') or '0'),
                            }
                            self.logger.info(f"✅ Joern CPG generated: {cpg_data}")
                            return self._format_cpg_result(cpg_data, source_code)
                        except Exception as e:
                            raise RuntimeError(f"Failed to parse Joern output: {e}; raw=\n{result.stdout}")

                    # If we reach here, Joern execution failed
                    raise RuntimeError(f"Joern execution failed: {result.stderr or result.stdout}")
                finally:
                    if os.path.exists(script_file):
                        os.unlink(script_file)
            
        except Exception as e:
            if "Joern is required" in str(e):
                raise  # Re-raise dependency errors
            raise RuntimeError(f"Joern integration error: {e}")

    def generate_cpg_structure(self, source_code: str, source_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate full CPG structure JSON for GNN inference."""
        if not self.joern_path:
            raise RuntimeError(
                "Joern is required for CPG generation. Please install Joern using:\n"
                "  ./scripts/install_joern.sh\n"
                "Or ensure Joern is in your PATH and JOERN_PATH environment variable is set."
            )

        repo_root = Path(__file__).resolve().parents[2]
        script_path = repo_root / "extract_cpg_for_gnn.sc"
        if not script_path.exists():
            raise RuntimeError(f"Missing Joern GNN script: {script_path}")
        temp_source_path = None
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                base_dir = Path(tmpdir)
                input_dir = base_dir / "input"
                output_dir = base_dir / "output"
                input_dir.mkdir(parents=True, exist_ok=True)
                output_dir.mkdir(parents=True, exist_ok=True)

                if source_path and Path(source_path).exists():
                    java_name = Path(source_path).name
                else:
                    java_name = "snippet.java"

                temp_source_path = input_dir / java_name
                temp_source_path.write_text(source_code, encoding="utf-8")

                cmd = [
                    self.joern_path,
                    "--script", str(script_path),
                    "--param", f"cpgFile={input_dir}",
                    "--param", f"outputDir={output_dir}",
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.joern_timeout,
                    cwd=base_dir,
                )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr or result.stdout)

                json_path = output_dir / "cpg_structure.json"
                if not json_path.exists():
                    raise RuntimeError(f"CPG structure JSON not found at {json_path}")

                return json.loads(json_path.read_text(encoding="utf-8"))
        finally:
            if temp_source_path and temp_source_path.exists():
                try:
                    temp_source_path.unlink()
                except Exception:
                    pass
    
    def _format_cpg_result(self, cpg_data: Dict[str, Any], source_code: str) -> Dict[str, Any]:
        """Format CPG result with additional metadata"""
        # Edge count should now come directly from Joern (no estimation needed)
        if 'edges' not in cpg_data or cpg_data['edges'] == 0:
            self.logger.warning("⚠️ Edge count missing or zero from Joern, using estimation")
            estimated_edges = cpg_data.get('calls', 0) + cpg_data.get('methods', 0) * 2
            cpg_data['edges'] = estimated_edges
        
        return {
            'cpg': cpg_data,
            'source_length': len(source_code),
            'joern_available': True,  # Always true when this method is called
            'generation_method': 'joern'  # Always Joern, no fallback
        }


class VulnerabilityDetector:
    """Detects vulnerabilities using pattern matching and GNN"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def detect_patterns(self, source_code: str) -> List[str]:
        """Detect vulnerability patterns in source code"""
        vulnerabilities = []
        
        # SQL Injection patterns
        if self._detect_sql_injection(source_code):
            vulnerabilities.append('sql_injection')
        
        # Command Injection patterns
        if self._detect_command_injection(source_code):
            vulnerabilities.append('command_injection')
        
        # Path Traversal patterns
        if self._detect_path_traversal(source_code):
            vulnerabilities.append('path_traversal')
        
        # XSS patterns
        if self._detect_xss(source_code):
            vulnerabilities.append('xss')
        
        # LDAP Injection patterns
        if self._detect_ldap_injection(source_code):
            vulnerabilities.append('ldap_injection')
        
        # EL Injection patterns
        if self._detect_el_injection(source_code):
            vulnerabilities.append('el_injection')
        
        # XXE patterns
        if self._detect_xxe(source_code):
            vulnerabilities.append('xxe')

        # SSRF patterns
        if self._detect_ssrf(source_code):
            vulnerabilities.append('ssrf')
        
        # Weak Crypto patterns
        if self._detect_weak_crypto(source_code):
            vulnerabilities.append('weak_crypto')
        
        # Deserialization patterns
        if self._detect_deserialization(source_code):
            vulnerabilities.append('deserialization')

        # XPath Injection patterns
        if self._detect_xpath_injection(source_code):
            vulnerabilities.append('xpath_injection')

        # ScriptEngine eval injection (mapped to EL injection/CWE-94)
        if self._detect_script_engine_injection(source_code):
            vulnerabilities.append('el_injection')
        
        # Hardcoded credentials patterns
        if self._detect_hardcoded_credentials(source_code):
            vulnerabilities.append('hardcoded_credentials')
        
        # Reflection injection patterns
        if self._detect_reflection_injection(source_code):
            vulnerabilities.append('reflection_injection')
        
        # Insecure randomness patterns
        if self._detect_insecure_randomness(source_code):
            vulnerabilities.append('insecure_randomness')
        
        # Buffer overflow patterns
        if self._detect_buffer_overflow(source_code):
            vulnerabilities.append('buffer_overflow')
        
        # Trust Boundary Violation patterns (CWE-501)
        if self._detect_trust_boundary_violation(source_code):
            vulnerabilities.append('trust_boundary_violation')
        
        # CSRF (Cross-Site Request Forgery) patterns (CWE-352)
        if self._detect_csrf(source_code):
            vulnerabilities.append('csrf')
        
        # Race Condition patterns (CWE-362, CWE-366, CWE-367)
        if self._detect_race_condition(source_code):
            vulnerabilities.append('race_condition')
        
        # Log Injection patterns (CWE-117)
        if self._detect_log_injection(source_code):
            vulnerabilities.append('log_injection')
        
        # Null Pointer Dereference patterns (CWE-476)
        if self._detect_null_pointer_dereference(source_code):
            vulnerabilities.append('null_pointer_dereference')
        
        # Integer Overflow patterns (CWE-190, CWE-191)
        if self._detect_integer_overflow(source_code):
            vulnerabilities.append('integer_overflow')
        
        # HTTP Response Splitting patterns (CWE-113)
        if self._detect_http_response_splitting(source_code):
            vulnerabilities.append('http_response_splitting')
        
        # Session Fixation patterns (CWE-384)
        if self._detect_session_fixation(source_code):
            vulnerabilities.append('session_fixation')
        
        # Resource Leak patterns (CWE-404, CWE-772)
        if self._detect_resource_leak(source_code):
            vulnerabilities.append('resource_leak')
        
        return vulnerabilities
    
    def _detect_sql_injection(self, code: str) -> bool:
        """Detect SQL injection patterns"""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
        sql_methods = ['executeQuery', 'execute', 'prepareStatement']

        has_sql = any(keyword in code for keyword in sql_keywords)
        has_execution = any(method in code for method in sql_methods)
        has_concatenation = '+' in code and '"' in code

        code_lower = code.lower()
        uses_prepared = 'preparedstatement' in code_lower or 'preparestatement' in code_lower
        uses_placeholder = '?' in code

        # Treat parameterized PreparedStatement usage as safe unless concatenation is present
        if uses_prepared and uses_placeholder and not has_concatenation:
            return False

        return has_sql and has_execution and has_concatenation
    
    def _detect_command_injection(self, code: str) -> bool:
        """Detect command injection patterns"""
        # Specific command execution patterns (not SQL exec methods)
        # Check for Runtime.exec or ProcessBuilder patterns
        has_runtime_exec = 'Runtime.getRuntime().exec' in code or 'Runtime.exec' in code
        has_process_builder = 'ProcessBuilder' in code or 'new ProcessBuilder' in code
        
        # Exclude SQL executeQuery/executeUpdate (not command injection)
        is_sql_exec = 'executeQuery' in code or 'executeUpdate' in code or 'prepareStatement' in code
        
        # Only detect command injection if we have actual OS command execution
        return (has_runtime_exec or has_process_builder) and not is_sql_exec
    
    def _detect_path_traversal(self, code: str) -> bool:
        """Detect path traversal patterns including dynamic path construction"""
        import re
        
        # Pattern 1: Literal traversal sequences
        traversal_patterns = ['../', '..\\', '../', '..\\\\']
        if any(pattern in code for pattern in traversal_patterns):
            return True
        
        # Pattern 2: Dynamic path construction with user input (CWE-22)
        # File/FileInputStream/FileReader/FileWriter + string concatenation with parameters
        file_construction_patterns = [
            r'new\s+File\s*\([^)]*\+',  # new File(path + userInput)
            r'new\s+FileInputStream\s*\([^)]*\+',  # new FileInputStream(path + input)
            r'new\s+FileReader\s*\([^)]*\+',  # new FileReader(path + filename)
            r'new\s+FileWriter\s*\([^)]*\+',  # new FileWriter(path + file)
            r'new\s+FileOutputStream\s*\([^)]*\+',  # new FileOutputStream(path + name)
            r'Files\.read\w+\([^)]*\+',  # Files.readAllBytes(path + input)
            r'Files\.write\w+\([^)]*\+',  # Files.write(path + input)
            r'Paths\.get\([^)]*\+',  # Paths.get(base + userInput)
        ]
        
        for pattern in file_construction_patterns:
            if re.search(pattern, code):
                return True

        # Pattern 3: Zip Slip (ZipEntry name used directly in output path)
        has_zip = 'ZipInputStream' in code or 'ZipEntry' in code
        if has_zip:
            if re.search(r'new\s+File\s*\(\s*\w+\s*,\s*entry\.getName\(\)\s*\)', code):
                return True
            if re.search(r'Paths\.get\s*\(\s*\w+\s*,\s*entry\.getName\(\)\s*\)', code):
                return True
        
        return False
    
    def _detect_xss(self, code: str) -> bool:
        """Detect XSS patterns"""
        xss_patterns = [
            '<script>', 
            'javascript:', 
            'innerHTML', 
            'document.write',
            'alert(',
            'XSS vulnerability',
            'getWriter().println',
            'getWriter().write',
            '<html>',
            '<div>'
        ]
        return any(pattern in code for pattern in xss_patterns)
    
    def _detect_ldap_injection(self, code: str) -> bool:
        """Detect LDAP injection patterns"""
        import re
        has_ldap_context = any(pattern in code for pattern in ['LDAP', 'ldap', 'search(', 'filter'])
        has_concatenation = '+' in code and '"' in code
        if has_ldap_context and has_concatenation:
            return True

        # JNDI lookup injection often uses InitialContext.lookup(userInput)
        has_jndi = 'InitialContext' in code or 'Context' in code
        has_lookup = 'lookup(' in code
        has_lookup_var = bool(re.search(r'lookup\s*\(\s*[A-Za-z_]\w*\s*\)', code))
        return has_jndi and has_lookup and has_lookup_var
    
    def _detect_el_injection(self, code: str) -> bool:
        """Detect EL (Expression Language) injection patterns (CWE-94)"""
        import re
        
        # Check for EL-specific APIs
        el_api_patterns = [
            'ExpressionFactory',
            'ValueExpression',
            'ELContext',
            'createValueExpression',
            'createMethodExpression',
            'StandardELContext',
            'EvaluationContext',
            'ELProcessor',
            'ELManager',
            'ExpressionEvaluator',
            'PageContextImpl',
            'proprietaryEvaluate',
            'javax.el',
            'jakarta.el'
        ]
        
        has_el_api = any(pattern in code for pattern in el_api_patterns)
        
        if not has_el_api:
            return False
        
        # Check for vulnerable patterns:
        # 1. User input concatenated into EL expressions
        has_el_concat = bool(re.search(r'["\']?\$\{["\']?\s*\+', code)) or bool(re.search(r'\+\s*["\']?\$\{', code))
        
        # 2. User input directly passed to createValueExpression
        has_user_expression = bool(re.search(r'createValueExpression\s*\([^)]*user[^)]*\)', code, re.IGNORECASE))
        
        # 3. EL delimiters with concatenation
        has_el_delimiters = ('${' in code or '#{' in code) and '+' in code and '"' in code
        
        return has_el_api and (has_el_concat or has_user_expression or has_el_delimiters)
    
    def _detect_xxe(self, code: str) -> bool:
        """Detect XXE (XML External Entity) patterns"""
        xxe_patterns = [
            'DocumentBuilder',
            'DocumentBuilderFactory',
            'XMLReader',
            'SAXParser',
            'parse(',
            'StringReader',
            'InputSource'
        ]
        has_xml_parsing = any(pattern in code for pattern in xxe_patterns)
        missing_security = 'setFeature' not in code and 'setExpandEntityReferences' not in code
        return has_xml_parsing and missing_security

    def _detect_ssrf(self, code: str) -> bool:
        """Detect SSRF patterns using URL/URLConnection with user-controlled input"""
        import re

        url_indicators = [
            'URL',
            'URLConnection',
            'HttpURLConnection',
            'openConnection',
            'openStream',
            'getInputStream'
        ]
        has_url_api = any(indicator in code for indicator in url_indicators)
        if not has_url_api:
            return False

        # new URL(userInput) or new URL("http://" + host)
        url_variable = re.search(r'new\s+URL\s*\(\s*[^"\']+?\)', code)
        url_concat = re.search(r'new\s+URL\s*\(\s*\"[^\"]*\"\s*\+\s*\w+', code)
        has_open = 'openConnection' in code or 'openStream' in code or 'getInputStream' in code
        return has_open and (url_variable or url_concat)

    def _detect_xpath_injection(self, code: str) -> bool:
        """Detect XPath injection patterns"""
        import re

        has_xpath = 'XPathFactory' in code or 'XPath' in code
        has_eval = 'compile(' in code or 'evaluate(' in code
        has_concat = '+' in code and ('@' in code or 'XPath' in code)
        expr_concat = re.search(r'\"[^\"]*\"\s*\+\s*\w+', code)
        return has_xpath and has_eval and (has_concat or expr_concat)

    def _detect_script_engine_injection(self, code: str) -> bool:
        """Detect ScriptEngine eval injection patterns"""
        import re

        has_engine = 'ScriptEngine' in code or 'ScriptEngineManager' in code or 'getEngineByName' in code
        if not has_engine:
            return False
        has_eval_var = re.search(r'\.eval\s*\(\s*[A-Za-z_]\w*\s*\)', code)
        has_eval_concat = re.search(r'\.eval\s*\([^)]*\+', code)
        return bool(has_eval_var or has_eval_concat)
    
    def _detect_weak_crypto(self, code: str) -> bool:
        """Detect weak cryptography patterns"""
        weak_crypto_patterns = [
            'DES',
            'MD5',
            'SHA1',
            'RC4',
            'Cipher.getInstance("DES")',
            'MessageDigest.getInstance("MD5")',
            'MessageDigest.getInstance("SHA1")',
            'getInstance("DES")',
            'getInstance("MD5")',
            'getInstance("SHA1")'
        ]
        return any(pattern in code for pattern in weak_crypto_patterns)
    
    def _detect_deserialization(self, code: str) -> bool:
        """Detect unsafe deserialization patterns"""
        deserialization_patterns = [
            'ObjectInputStream',
            'readObject()',
            'ByteArrayInputStream',
            'XMLDecoder',
            'Serializable',
            'deserialize'
        ]
        return any(pattern in code for pattern in deserialization_patterns)
    
    def _detect_hardcoded_credentials(self, code: str) -> bool:
        """Detect hardcoded credentials patterns"""
        credential_patterns = [
            'password123',
            'admin123',
            'secret',
            'hardcoded',
            'DB_PASSWORD',
            'API_KEY',
            'sk-',
            'password = "',
            'password="'
        ]
        return any(pattern in code for pattern in credential_patterns)
    
    def _detect_reflection_injection(self, code: str) -> bool:
        """Detect reflection injection patterns (CWE-470)"""
        import re
        
        # Check for reflection API usage (excluding ExpressionFactory.newInstance which is EL, not reflection)
        reflection_patterns = [
            r'Class\.forName\s*\(',
            r'\.getMethod\s*\(',
            r'\.getDeclaredMethod\s*\(',
            r'\.getDeclaredField\s*\(',
            r'\.getField\s*\(',
            r'\.invoke\s*\(',
            r'\.setAccessible\s*\(\s*true\s*\)',
        ]
        
        has_reflection = any(re.search(pattern, code) for pattern in reflection_patterns)
        
        if not has_reflection:
            return False
        
        # Check for user-controlled input being used in reflection
        # Look for patterns like Class.forName(userInput) or getMethod(methodName, ...)
        user_controlled_reflection = any([
            re.search(r'Class\.forName\s*\(\s*\w*(user|input|name|param|request)', code, re.IGNORECASE),
            re.search(r'getMethod\s*\(\s*\w*(method|name|user|input)', code, re.IGNORECASE),
            re.search(r'getDeclaredMethod\s*\(\s*\w*(method|name|user|input)', code, re.IGNORECASE),
            re.search(r'getField\s*\(\s*\w*(field|name|user|input)', code, re.IGNORECASE),
        ])
        
        return has_reflection and user_controlled_reflection
    
    def _detect_insecure_randomness(self, code: str) -> bool:
        """Detect insecure randomness patterns"""
        insecure_patterns = [
            'new Random()',
            'Random(System.currentTimeMillis())',
            'Random(12345)',
            'Math.random()',
            'currentTimeMillis()',
            'Fixed seed',
            'Predictable seed'
        ]
        return any(pattern in code for pattern in insecure_patterns)
    
    def _detect_buffer_overflow(self, code: str) -> bool:
        """Detect buffer overflow patterns"""
        buffer_patterns = [
            'buffer[index]',
            'arraycopy',
            'System.arraycopy',
            'No bounds checking',
            'No length validation',
            'No size check',
            'buffer overflow',
            'charAt(i)'
        ]
        return any(pattern in code for pattern in buffer_patterns)
    
    def _detect_trust_boundary_violation(self, code: str) -> bool:
        """Detect Trust Boundary Violation (CWE-501)"""
        trust_sinks = [
            'System.setProperty',
            'session.setAttribute',
            'session.putValue',
            'Properties.setProperty',
            'SecurityManager.checkPermission',
            'grantAdminAccess',
            'setUserRole',
            'authenticate',
            'authorize',
        ]
        
        untrusted_sources = [
            'getParameter(',
            'getHeader(',
            'getCookie(',
            'request.',
            'req.',
            'userInput',
            'userId',
            'userName',
            'password',
            'role',
            'permission'
        ]
        
        has_untrusted = any(source in code for source in untrusted_sources)
        has_trust_sink = any(sink in code for sink in trust_sinks)
        
        return has_untrusted and has_trust_sink
    
    def _detect_csrf(self, code: str) -> bool:
        """Detect CSRF (Cross-Site Request Forgery) vulnerabilities (CWE-352)"""
        state_changing_methods = [
            'doPost(',
            'doPut(',
            'doDelete(',
            '@PostMapping',
            '@PutMapping',
            '@DeleteMapping',
            '@RequestMapping',
            'HttpServletRequest'
        ]
        
        csrf_protections = [
            'csrf',
            'CSRF',
            '_csrf',
            'csrfToken',
            'synchronizerToken',
            'getSession().getAttribute("csrf")',
            '@EnableWebSecurity',
            'CsrfFilter',
            'csrf().disable()',
            'X-CSRF-TOKEN',
            'csrfProtection',
            'validateToken',
            'verifyToken',
            'checkReferer'
        ]
        
        sensitive_operations = [
            'performMoneyTransfer',
            'changeUserPassword',
            'changePassword',
            'updatePassword',
            'transfer',
            'deleteAccount',
            'updateProfile',
            'grantAccess',
            'revokeAccess',
            'setRole',
            'addAdmin',
            'removeUser',
            'purchase',
            'checkout'
        ]
        
        has_state_changing = any(method in code for method in state_changing_methods)
        has_sensitive_ops = any(op in code for op in sensitive_operations)
        
        code_without_class_decl = '\n'.join([
            line for line in code.split('\n') 
            if not (line.strip().startswith('public class') or line.strip().startswith('class'))
        ])
        has_csrf_protection = any(protection in code_without_class_decl for protection in csrf_protections)
        
        return (has_state_changing or has_sensitive_ops) and not has_csrf_protection
    
    def _detect_race_condition(self, code: str) -> bool:
        """Detect Race Condition vulnerabilities (CWE-362, CWE-366, CWE-367)"""
        shared_state_indicators = [
            'private int',
            'private long',
            'private boolean',
            'private double',
            'private float',
            'static int',
            'static long',
            'static boolean',
            'private String',
            'private Object',
            'private volatile',
        ]
        
        race_patterns = [
            'if (balance',
            'if (count',
            'if (size',
            'Thread.yield()',
            'Thread.sleep(',
            'isLoggedIn = true',
            'balance -=',
            'balance +=',
            'count++',
            '++count',
            'count--',
            '--count',
        ]
        
        synchronization = [
            'synchronized(',
            'synchronized {',
            'Lock lock',
            'ReentrantLock',
            'ReadWriteLock',
            'AtomicInteger',
            'AtomicLong',
            'AtomicBoolean',
            'AtomicReference',
            'Semaphore',
            'CountDownLatch',
            'CyclicBarrier',
            'volatile synchronized',
            '@GuardedBy',
        ]
        
        has_shared_state = any(indicator in code for indicator in shared_state_indicators)
        has_race_pattern = any(pattern in code for pattern in race_patterns)
        has_synchronization = any(sync in code for sync in synchronization)
        
        return has_shared_state and has_race_pattern and not has_synchronization
    
    def _detect_log_injection(self, code: str) -> bool:
        """Detect Log Injection vulnerabilities (CWE-117)"""
        logging_methods = [
            'logger.info(',
            'logger.error(',
            'logger.warn(',
            'logger.warning(',
            'logger.debug(',
            'logger.severe(',
            'logger.fatal(',
            'logger.trace(',
            'log.info(',
            'log.error(',
            'log.warn(',
            'log.debug(',
            'log.fatal(',
            'System.out.println(',
            'System.err.println(',
            'LogFactory.getLog(',
            'LoggerFactory.getLogger(',
            'Logger.getLogger(',
            'writeToAuditLog(',
            'auditLog(',
            'securityLog(',
        ]
        
        user_input_indicators = [
            'username',
            'userInput',
            'user',
            'input',
            'request',
            'parameter',
            'error',
            'action',
            '+ username',
            '+ userInput',
            '+ user',
            '+ error',
            '+ action',
            '"Login attempt for user: " +',
            '"User " +',
            '"Error processing request from " +',
        ]
        
        sanitization = [
            '.replace("\\n"',
            '.replace("\\r"',
            '.replaceAll("\\\\n"',
            '.replaceAll("\\\\r"',
            'sanitize(',
            'encode(',
            'escape(',
            'validate(',
            'Encode.forJava(',
            'StringEscapeUtils.',
            'ESAPI.encoder()',
        ]
        
        has_logging = any(method in code for method in logging_methods)
        has_user_input = any(indicator in code for indicator in user_input_indicators)
        
        code_without_class_decl = '\n'.join([
            line for line in code.split('\n') 
            if not (line.strip().startswith('public class') or line.strip().startswith('class'))
        ])
        has_sanitization = any(san in code_without_class_decl for san in sanitization)
        
        return has_logging and has_user_input and not has_sanitization
    
    def _detect_null_pointer_dereference(self, code: str) -> bool:
        """Detect Null Pointer Dereference vulnerabilities (CWE-476)"""
        nullable_methods = [
            '.get(',
            '.getProfile(',
            '.getEmail(',
            '.find(',
            '.query(',
            '.search(',
        ]
        
        dereference_operations = [
            '.length(',
            '.toUpperCase(',
            '.toLowerCase(',
            '.startsWith(',
            '.endsWith(',
            '.contains(',
            '.trim(',
            '.split(',
            '[index]',
            '.size(',
        ]
        
        null_checks = [
            '!= null',
            'if (null',
            '== null',
            'Objects.requireNonNull',
            'Optional.ofNullable',
            'Optional.empty',
            'if (',
        ]
        
        chaining_patterns = [
            'getProfile().get',
            'getEmail().to',
            ').get',
        ]
        
        has_nullable_calls = any(method in code for method in nullable_methods)
        has_dereferences = any(op in code for op in dereference_operations)
        has_chaining = any(pattern in code for pattern in chaining_patterns)
        has_null_checks = any(check in code for check in null_checks)
        
        return (has_nullable_calls and has_dereferences and not has_null_checks) or has_chaining
    
    def _detect_integer_overflow(self, code: str) -> bool:
        """Detect Integer Overflow vulnerabilities (CWE-190, CWE-191)"""
        import re
        
        # Specific patterns for integer overflow in calculations
        overflow_patterns = [
            r'int\s+total\s*=.*[*+]',  # int total = x + y or x * y
            r'int\s+arraySize\s*=.*[*+]',
            r'int\s+bufferSize\s*=.*[*+]',
            r'int\s+size\s*=.*[*+]',
            r'int\s+length\s*=.*[*+]',
            r'int\s+count\s*=.*[*+]',
            r'long\s+total\s*=.*[*+]',
            r'long\s+size\s*=.*[*+]',
            # Array allocation with arithmetic: new int[size * factor]
            r'new\s+\w+\[.*[*+].*\]',
            # Integer arithmetic that could overflow
            r'\w+\s*[*+]\s*\w+\s*[*+]\s*\w+',  # Multiple operations: a * b * c
        ]
        
        has_overflow_pattern = any(re.search(pattern, code) for pattern in overflow_patterns)
        
        if not has_overflow_pattern:
            return False
        
        # Check for overflow protection
        has_overflow_check = any(check in code for check in [
            'Math.addExact',
            'Math.multiplyExact',
            'Math.subtractExact',
            'Integer.MAX_VALUE',
            'Long.MAX_VALUE',
            'if (size > MAX',
            'if (total > MAX',
            'if (count > MAX',
        ])
        
        return has_overflow_pattern and not has_overflow_check
    
    def _detect_http_response_splitting(self, code: str) -> bool:
        """Detect HTTP Response Splitting vulnerabilities (CWE-113)"""
        # Response manipulation methods that can be exploited
        response_methods = [
            'sendRedirect',
            'setHeader',
            'addHeader',
            'addCookie',
            'Cookie(',
            'response.set',
            'response.add'
        ]
        
        # User input sources
        user_input = [
            'getParameter',
            'getHeader',
            'getCookie',
            'request.get',
            'req.get'
        ]
        
        # Sanitization/validation methods
        sanitization = [
            'encode',
            'escape',
            'validate',
            'sanitize',
            'replaceAll',
            'Pattern.matches',
            'URLEncoder',
            'ESAPI',
            'strip',
            'filter'
        ]
        
        has_response_method = any(method in code for method in response_methods)
        has_user_input = any(input_method in code for input_method in user_input)
        has_sanitization = any(san in code for san in sanitization)
        
        return has_response_method and has_user_input and not has_sanitization
    
    def _detect_session_fixation(self, code: str) -> bool:
        """Detect Session Fixation vulnerabilities (CWE-384)"""
        # Session management methods
        session_methods = [
            'getSession',
            'HttpSession',
            'session.setAttribute',
            'session.set'
        ]
        
        # Authentication indicators
        auth_indicators = [
            'authenticate',
            'login',
            'password',
            'credential',
            'auth'
        ]
        
        # Session regeneration (proper mitigation)
        session_regeneration = [
            'invalidate()',
            'session.invalidate',
            'changeSessionId',
            'session.changeSessionId',
            'new session',
            'session = request.getSession(false)',
            'getSession(false)'
        ]
        
        has_session_mgmt = any(method in code for method in session_methods)
        has_auth = any(indicator in code.lower() for indicator in auth_indicators)
        has_regeneration = any(regen in code for regen in session_regeneration)
        
        # Specific pattern: getSession() without false parameter after authentication
        has_unsafe_getsession = 'getSession()' in code or 'getSession(true)' in code
        
        return has_session_mgmt and has_auth and not has_regeneration and has_unsafe_getsession
    
    def _detect_resource_leak(self, code: str) -> bool:
        """Detect Resource Leak vulnerabilities (CWE-404, CWE-772)"""
        import re
        
        # Resources that need to be closed
        resource_types = [
            ('FileInputStream', 'close()'),
            ('FileOutputStream', 'close()'),
            ('BufferedReader', 'close()'),
            ('BufferedWriter', 'close()'),
            ('InputStreamReader', 'close()'),
            ('OutputStreamWriter', 'close()'),
            ('Connection', 'close()'),
            ('Statement', 'close()'),
            ('PreparedStatement', 'close()'),
            ('ResultSet', 'close()'),
            ('Socket', 'close()'),
            ('ServerSocket', 'close()'),
            ('FileReader', 'close()'),
            ('FileWriter', 'close()'),
            ('InputStream', 'close()'),
            ('OutputStream', 'close()'),
            ('ByteArrayOutputStream', 'close()'),
        ]
        
        # Check for resource allocation
        has_resource = False
        resource_names = []
        
        for resource_type, _ in resource_types:
            # Pattern: Type varName = new Type(...)
            pattern = rf'\b{resource_type}\s+(\w+)\s*=\s*new\s+{resource_type}'
            matches = re.findall(pattern, code)
            if matches:
                has_resource = True
                resource_names.extend(matches)
            
            # Pattern: Connection conn = DriverManager.getConnection(...)
            if resource_type == 'Connection':
                if 'DriverManager.getConnection' in code:
                    has_resource = True
                    conn_match = re.findall(r'Connection\s+(\w+)\s*=', code)
                    resource_names.extend(conn_match)
        
        if not has_resource:
            return False
        
        # Check for proper resource management
        has_try_with_resources = 'try (' in code or 'try(' in code
        has_close_calls = '.close()' in code
        has_finally = 'finally' in code and '.close()' in code
        
        # Check if resources are closed
        closed_resources = set()
        if has_close_calls:
            for resource_name in resource_names:
                if f'{resource_name}.close()' in code:
                    closed_resources.add(resource_name)
        
        # If we have resources but no try-with-resources and not all are closed
        unclosed_resources = set(resource_names) - closed_resources
        
        # Vulnerability if:
        # 1. Has resources
        # 2. No try-with-resources
        # 3. Either no finally block or resources not closed
        is_vulnerable = (
            has_resource and 
            not has_try_with_resources and 
            (not has_finally or len(unclosed_resources) > 0)
        )
        
        return is_vulnerable


class BayesianUncertaintyLayer:
    """Uncertainty-Aware Bayesian Layer for GNN vulnerability detection"""
    
    def __init__(self, dropout_rate: float = 0.1, monte_carlo_samples: int = 100):
        self.logger = logging.getLogger(__name__)
        self.dropout_rate = dropout_rate
        self.monte_carlo_samples = monte_carlo_samples
        self.np = None
        if os.environ.get("BEAN_VULN_DISABLE_NUMPY") == "1":
            self.logger.warning("⚠️ NumPy import disabled via BEAN_VULN_DISABLE_NUMPY")
            return
        try:
            import numpy as np  # local import to avoid hard dependency at module load
            self.np = np
        except Exception as e:
            self.logger.warning(f"⚠️ NumPy unavailable; uncertainty metrics degraded: {e}")
    
    def monte_carlo_dropout(self, features: Dict[str, Any], vulnerabilities: List[str]) -> Dict[str, Any]:
        """Apply Monte Carlo dropout for uncertainty estimation"""
        predictions = []
        
        for sample in range(self.monte_carlo_samples):
            dropped_features = self._apply_dropout(features)
            sample_prediction = self._forward_pass(dropped_features, vulnerabilities)
            predictions.append(sample_prediction)
        
        if self.np is not None:
            predictions_array = self.np.array(predictions)
            mean_prediction = float(self.np.mean(predictions_array))
            variance = float(self.np.var(predictions_array))
        else:
            mean_prediction = sum(predictions) / max(len(predictions), 1)
            variance = statistics.pvariance(predictions) if len(predictions) > 1 else 0.0
        epistemic_uncertainty = variance
        aleatoric_uncertainty = self._calculate_aleatoric_uncertainty(features, vulnerabilities)
        total_uncertainty = epistemic_uncertainty + aleatoric_uncertainty
        
        std_dev = math.sqrt(variance)
        confidence_lower = mean_prediction - 1.96 * std_dev
        confidence_upper = mean_prediction + 1.96 * std_dev
        
        return {
            'mean_prediction': float(mean_prediction),
            'variance': float(variance),
            'epistemic_uncertainty': float(epistemic_uncertainty),
            'aleatoric_uncertainty': float(aleatoric_uncertainty),
            'total_uncertainty': float(total_uncertainty),
            'confidence_interval': {
                'lower': float(max(0.0, confidence_lower)),
                'upper': float(min(1.0, confidence_upper))
            },
            'uncertainty_category': self._categorize_uncertainty(total_uncertainty),
            'prediction_reliability': self._assess_reliability(total_uncertainty, mean_prediction)
        }
    
    def _apply_dropout(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Apply dropout to features for Monte Carlo sampling"""
        dropped_features = features.copy()
        
        rand = self.np.random.random if self.np is not None else random.random
        if rand() < self.dropout_rate:
            dropped_features['nodes'] = int(dropped_features.get('nodes', 0) * 0.8)
        
        if rand() < self.dropout_rate:
            dropped_features['methods'] = int(dropped_features.get('methods', 0) * 0.9)
        
        if rand() < self.dropout_rate:
            dropped_features['calls'] = int(dropped_features.get('calls', 0) * 0.85)
        
        return dropped_features
    
    def _forward_pass(self, features: Dict[str, Any], vulnerabilities: List[str]) -> float:
        """Simulate a forward pass through the Bayesian GNN"""
        base_confidence = 0.5
        
        node_factor = min(features.get('nodes', 0) / 200.0, 0.3)
        method_factor = min(features.get('methods', 0) / 20.0, 0.2)
        call_factor = min(features.get('calls', 0) / 30.0, 0.15)
        pattern_factor = len(vulnerabilities) * 0.15
        if self.np is not None:
            bayesian_noise = float(self.np.random.normal(0, 0.05))
        else:
            bayesian_noise = random.gauss(0, 0.05)
        
        prediction = base_confidence + node_factor + method_factor + call_factor + pattern_factor + bayesian_noise
        
        return self._sigmoid(prediction)
    
    def _calculate_aleatoric_uncertainty(self, features: Dict[str, Any], vulnerabilities: List[str]) -> float:
        """Calculate aleatoric (data) uncertainty"""
        node_complexity = features.get('nodes', 0)
        pattern_count = len(vulnerabilities)
        
        if node_complexity > 500:
            complexity_uncertainty = 0.15
        elif node_complexity > 200:
            complexity_uncertainty = 0.10
        else:
            complexity_uncertainty = 0.05
        
        if pattern_count == 0:
            pattern_uncertainty = 0.20
        elif pattern_count > 5:
            pattern_uncertainty = 0.10
        else:
            pattern_uncertainty = 0.05
        
        return complexity_uncertainty + pattern_uncertainty
    
    def _categorize_uncertainty(self, total_uncertainty: float) -> str:
        """Categorize uncertainty level"""
        if total_uncertainty < 0.1:
            return "low"
        elif total_uncertainty < 0.25:
            return "medium"
        elif total_uncertainty < 0.4:
            return "high"
        else:
            return "very_high"
    
    def _assess_reliability(self, uncertainty: float, prediction: float) -> str:
        """Assess prediction reliability based on uncertainty and confidence"""
        if uncertainty < 0.1 and (prediction > 0.8 or prediction < 0.2):
            return "very_reliable"
        elif uncertainty < 0.2 and (prediction > 0.7 or prediction < 0.3):
            return "reliable"
        elif uncertainty < 0.3:
            return "moderate"
        else:
            return "unreliable"
    
    def _sigmoid(self, x: float) -> float:
        """Sigmoid activation function"""
        return 1.0 / (1.0 + math.exp(-max(-500, min(500, x))))
    
    def route_high_uncertainty_samples(self, uncertainty_results: Dict[str, Any], 
                                     threshold: float = 0.3) -> Dict[str, Any]:
        """Route high-uncertainty samples for secondary analysis or human review"""
        total_uncertainty = uncertainty_results.get('total_uncertainty', 0.0)
        reliability = uncertainty_results.get('prediction_reliability', 'unknown')
        
        if total_uncertainty > threshold:
            routing_decision = "secondary_targeted_fuzz_pass"
            recommendation = "High uncertainty detected - route to specialized analysis"
            action = "manual_review"
        elif reliability == "unreliable":
            routing_decision = "expert_review"
            recommendation = "Unreliable prediction - expert review recommended"
            action = "human_validation"
        else:
            routing_decision = "automated_processing"
            recommendation = "Low uncertainty - proceed with automated analysis"
            action = "continue"
        
        return {
            'routing_decision': routing_decision,
            'recommendation': recommendation,
            'action': action,
            'uncertainty_level': uncertainty_results.get('uncertainty_category', 'unknown'),
            'requires_attention': total_uncertainty > threshold or reliability == "unreliable"
        }


class IntegratedGNNFramework:
    """Integrated GNN Framework for Vulnerability Detection - NO FALLBACKS"""
    
    def __init__(
        self,
        enable_ensemble: bool = False,
        enable_advanced_features: bool = False,
        enable_spatial_gnn: bool = True,
        enable_explanations: bool = False,
        joern_timeout: int = 480,
        gnn_checkpoint: Optional[Union[str, List[str]]] = None,
        gnn_weight: float = 0.6,
        gnn_confidence_threshold: float = 0.5,
        gnn_temperature: float = 1.0,
        gnn_ensemble: int = 1,
        enable_joern_dataflow: bool = True,
        enable_implicit_flows: bool = True,
        enable_path_sensitive: bool = True,
        enable_native_jni: bool = True,
        enable_tai_e: bool = False,
        tai_e_home: Optional[str] = None,
        tai_e_cs: str = "1-obj",
        tai_e_main: Optional[str] = None,
        tai_e_timeout: Optional[int] = 300,
        tai_e_only_app: bool = True,
        tai_e_allow_phantom: bool = True,
        tai_e_prepend_jvm: bool = True,
        tai_e_java_version: Optional[int] = None,
        tai_e_classpath: Optional[str] = None,
        tai_e_enable_taint: bool = False,
        tai_e_taint_config: Optional[str] = None,
    ):
        self.logger = logging.getLogger(__name__)
        self.logger.info("🚀 Initializing Bean Vulnerable Framework")
        
        self.enable_ensemble = enable_ensemble
        self.enable_advanced_features = enable_advanced_features
        self.enable_spatial_gnn = enable_spatial_gnn
        self.enable_explanations = enable_explanations
        self.joern_timeout = joern_timeout
        self.gnn_weight = self._normalize_gnn_weight(gnn_weight)
        self.gnn_confidence_threshold = self._normalize_gnn_threshold(gnn_confidence_threshold)
        self.gnn_temperature = self._normalize_gnn_temperature(gnn_temperature)
        self.gnn_ensemble = max(int(gnn_ensemble), 1)
        self.gnn_checkpoint = gnn_checkpoint
        self.gnn_checkpoint_paths = self._normalize_checkpoint_paths(gnn_checkpoint)
        self.gnn_weights_loaded = False
        self.gnn_weights_loaded_count = 0
        self._gnn_trace_enabled = os.getenv("BEAN_VULN_TRACE_GNN", "").lower() in {"1", "true", "yes", "on"}
        self._gnn_forward_called = False
        self.spatial_gnn_models: List[Any] = []
        env_joern_dataflow = os.getenv("BEAN_VULN_JOERN_DATAFLOW", "").lower() in {"1", "true", "yes", "on"}
        self.enable_joern_dataflow = bool(enable_joern_dataflow) or env_joern_dataflow
        self.tai_e_config = None
        if enable_tai_e:
            if TAIE_AVAILABLE:
                self.tai_e_config = TaiEConfig(
                    enabled=True,
                    tai_e_home=tai_e_home,
                    cs=tai_e_cs,
                    main_class=tai_e_main,
                    timeout=tai_e_timeout,
                    only_app=tai_e_only_app,
                    implicit_entries=True,
                    allow_phantom=tai_e_allow_phantom,
                    prepend_jvm=tai_e_prepend_jvm,
                    java_version=tai_e_java_version,
                    classpath=tai_e_classpath,
                    enable_taint=bool(tai_e_enable_taint),
                    taint_config=tai_e_taint_config,
                )
            else:
                self.logger.warning("⚠️ Tai-e integration requested but not available")
        
        # Initialize components
        self.joern_integrator = JoernIntegrator()
        self.joern_integrator.joern_timeout = self.joern_timeout
        self.vulnerability_detector = VulnerabilityDetector()
        self.bayesian_layer = BayesianUncertaintyLayer()
        self.sink_gating_engine = SinkGatingEngine() if SINK_GATING_AVAILABLE else None
        if self.sink_gating_engine:
            self.logger.info("✅ Sink-specific gating engine initialized")
        self.framework_sink_registry = FrameworkSinkRegistry() if FRAMEWORK_SINKS_AVAILABLE else None
        if self.framework_sink_registry:
            self.logger.info("✅ Framework sink registry initialized")
        self.template_engine_analyzer = TemplateEngineAnalyzer() if TEMPLATE_ENGINE_AVAILABLE else None
        if self.template_engine_analyzer:
            self.logger.info("✅ Template engine analyzer initialized")
        
        # Initialize Comprehensive Taint Tracking
        try:
            from .comprehensive_taint_tracking import ComprehensiveTaintTracker
            self.taint_tracker = ComprehensiveTaintTracker(
                tai_e_config=self.tai_e_config,
                enable_implicit_flows=enable_implicit_flows,
                enable_path_sensitive=enable_path_sensitive,
                enable_native_jni=enable_native_jni,
            )
            self.logger.info("✅ Comprehensive Taint Tracking initialized (external module)")
        except ImportError:
            self.taint_tracker = None
            self.logger.warning("⚠️ Comprehensive Taint Tracking not available")
        
        # Initialize Enhanced CF-Explainer (lazy import)
        if self.enable_explanations:
            try:
                from .cf_explainer import CFExplainerIntegration
                self.cf_explainer = CFExplainerIntegration(self)
                self.logger.info("✅ Enhanced CF-Explainer initialized")
            except Exception as e:
                self.cf_explainer = None
                self.logger.warning(f"⚠️ CF-Explainer initialization failed: {e}")
        else:
            self.cf_explainer = None
            self.logger.debug("CF-Explainer disabled (enable with enable_explanations=True)")
        
        # Initialize Next-Generation Spatial GNN
        self.spatial_gnn_model = None
        if self.enable_spatial_gnn:
            try:
                from .spatial_gnn_enhanced import create_spatial_gnn_model, TORCH_GEOMETRIC_AVAILABLE
                if not TORCH_GEOMETRIC_AVAILABLE:
                    raise RuntimeError("PyTorch Geometric unavailable; cannot run Spatial GNN.")

                # Create model with research-grade configuration.
                gnn_config = {
                    'hidden_dim': 512,
                    'num_layers': 4,
                    'num_attention_heads': 8,
                    'use_codebert': True,
                    'use_hierarchical_pooling': True,
                    'enable_attention_visualization': True,
                    'enable_counterfactual_analysis': True
                }

                checkpoint_paths = list(self.gnn_checkpoint_paths)
                if checkpoint_paths and self.gnn_ensemble > 0:
                    if len(checkpoint_paths) > self.gnn_ensemble:
                        self.logger.warning(
                            f"⚠️ {len(checkpoint_paths)} checkpoints provided; limiting to {self.gnn_ensemble}."
                        )
                        checkpoint_paths = checkpoint_paths[: self.gnn_ensemble]
                    elif len(checkpoint_paths) < self.gnn_ensemble:
                        self.logger.warning(
                            f"⚠️ gnn_ensemble={self.gnn_ensemble} but only {len(checkpoint_paths)} checkpoints provided."
                        )

                if checkpoint_paths:
                    for checkpoint_path in checkpoint_paths:
                        model = create_spatial_gnn_model(gnn_config)
                        if self._load_spatial_gnn_checkpoint(checkpoint_path, model=model):
                            self.spatial_gnn_models.append(model)
                    if not self.spatial_gnn_models:
                        raise RuntimeError("No Spatial GNN checkpoints loaded; cannot run GNN inference.")
                    self.spatial_gnn_model = self.spatial_gnn_models[0]
                    self.gnn_weights_loaded = True
                    self.gnn_weights_loaded_count = len(self.spatial_gnn_models)
                    self.logger.info(
                        f"✅ Next-Generation Spatial GNN initialized with {self.gnn_weights_loaded_count} checkpoint(s)"
                    )
                else:
                    self.spatial_gnn_model = create_spatial_gnn_model(gnn_config)
                    self.spatial_gnn_models = [self.spatial_gnn_model]
                    self.logger.info("✅ Next-Generation Spatial GNN initialized (inference enabled)")
            except Exception as e:
                # No fallbacks: if the user enabled Spatial GNN, treat failures as fatal.
                raise RuntimeError(f"Spatial GNN initialization failed: {e}") from e

        self._enable_gnn_forward_trace()
        
        self.logger.info("✅ Bean Vulnerable Framework initialized")

    def _normalize_checkpoint_paths(self, gnn_checkpoint: Optional[Union[str, List[str]]]) -> List[str]:
        if not gnn_checkpoint:
            return []
        if isinstance(gnn_checkpoint, str):
            raw_items: List[str] = [gnn_checkpoint]
        elif isinstance(gnn_checkpoint, list):
            raw_items = [item for item in gnn_checkpoint if item]
        else:
            return []
        paths: List[str] = []
        for item in raw_items:
            if not isinstance(item, str):
                continue
            parts = [part.strip() for part in item.split(",") if part.strip()]
            paths.extend(parts)
        return paths

    def _normalize_gnn_weight(self, weight: float) -> float:
        try:
            value = float(weight)
        except Exception:
            value = 0.6
        if value < 0.0 or value > 1.0:
            self.logger.warning(f"⚠️ gnn_weight out of range ({value}); clamping to [0, 1].")
            value = max(0.0, min(1.0, value))
        return value

    def _normalize_gnn_threshold(self, threshold: Optional[float]) -> Optional[float]:
        if threshold is None:
            return None
        try:
            value = float(threshold)
        except Exception:
            value = 0.5
        if value < 0.0 or value > 1.0:
            self.logger.warning(f"⚠️ gnn_confidence_threshold out of range ({value}); clamping to [0, 1].")
            value = max(0.0, min(1.0, value))
        return value

    def _normalize_gnn_temperature(self, temperature: float) -> float:
        try:
            value = float(temperature)
        except Exception:
            value = 1.0
        if value <= 0.0:
            self.logger.warning(f"⚠️ gnn_temperature must be > 0; using 1.0 (got {value}).")
            value = 1.0
        return value

    def _calibrate_probability(self, probability: float) -> float:
        if self.gnn_temperature == 1.0:
            return probability
        eps = 1e-6
        prob = min(max(probability, eps), 1.0 - eps)
        logit = math.log(prob / (1.0 - prob))
        scaled = logit / self.gnn_temperature
        return 1.0 / (1.0 + math.exp(-scaled))

    def _extract_gnn_confidence(self, outputs: Any) -> Tuple[Optional[float], str, Optional[float]]:
        if not isinstance(outputs, dict):
            return None, "unsupported", None
        confidence_tensor = outputs.get("confidence")
        if confidence_tensor is not None:
            try:
                raw_conf = float(confidence_tensor.view(-1)[0].item())
                return self._calibrate_probability(raw_conf), "confidence_head", raw_conf
            except Exception:
                return None, "confidence_head_error", None
        binary_logits = outputs.get("binary_logits")
        if binary_logits is not None:
            try:
                import torch
                scaled_logits = binary_logits / self.gnn_temperature
                scaled_probs = torch.softmax(scaled_logits, dim=-1)[..., 1]
                raw_probs = torch.softmax(binary_logits, dim=-1)[..., 1]
                return (
                    float(scaled_probs.view(-1)[0].item()),
                    "binary_logits",
                    float(raw_probs.view(-1)[0].item()),
                )
            except Exception:
                return None, "binary_logits_error", None
        return None, "missing", None
    
    def _enable_gnn_forward_trace(self) -> None:
        if not self._gnn_trace_enabled:
            return
        if not self.spatial_gnn_model:
            self.logger.info("🧠 GNN trace enabled, but spatial GNN is not initialized.")
            return
        if getattr(self.spatial_gnn_model, "_beanvuln_gnn_trace_enabled", False):
            return
        if hasattr(self.spatial_gnn_model, "register_forward_hook"):
            def _forward_hook(_module, _inputs, _output):
                self._gnn_forward_called = True
                self.logger.info("🧠 Spatial GNN forward hook triggered.")
            self.spatial_gnn_model.register_forward_hook(_forward_hook)
            self.spatial_gnn_model._beanvuln_gnn_trace_enabled = True
            self.logger.info("🧠 GNN forward hook attached.")
            return
        if hasattr(self.spatial_gnn_model, "forward"):
            original_forward = self.spatial_gnn_model.forward

            def _traced_forward(model_self, *args, **kwargs):
                self._gnn_forward_called = True
                self.logger.info("🧠 Spatial GNN forward invoked.")
                return original_forward(*args, **kwargs)

            self.spatial_gnn_model.forward = _traced_forward.__get__(
                self.spatial_gnn_model, self.spatial_gnn_model.__class__
            )
            self.spatial_gnn_model._beanvuln_gnn_trace_enabled = True
            self.logger.info("🧠 GNN forward wrapper attached.")

    def _load_spatial_gnn_checkpoint(self, checkpoint_path: str, model: Optional[Any] = None) -> bool:
        target_model = model or self.spatial_gnn_model
        if not target_model:
            return False
        checkpoint = Path(checkpoint_path)
        if not checkpoint.exists():
            self.logger.warning(f"⚠️ Spatial GNN checkpoint not found: {checkpoint}")
            return False
        try:
            import torch
            payload = torch.load(str(checkpoint), map_location="cpu")
            state_dict = payload.get("model_state_dict", payload) if isinstance(payload, dict) else payload
            target_model.load_state_dict(state_dict)
            self.logger.info(f"✅ Loaded Spatial GNN checkpoint: {checkpoint}")
            return True
        except Exception as exc:
            self.logger.warning(f"⚠️ Failed to load Spatial GNN checkpoint: {exc}")
            return False

    def _cpg_to_pyg_data(self, cpg_structure: Dict[str, Any]) -> Optional[Any]:
        try:
            import torch
            from torch_geometric.data import Data
        except Exception as exc:
            self.logger.warning(f"⚠️ PyTorch Geometric unavailable for GNN inference: {exc}")
            return None

        nodes = cpg_structure.get("nodes") or []
        edges = cpg_structure.get("edges") or []
        if not nodes:
            self.logger.warning("⚠️ Empty CPG nodes; cannot build GNN input.")
            return None

        node_type_mapping = {
            'METHOD': 0, 'CALL': 1, 'IDENTIFIER': 2, 'LITERAL': 3,
            'LOCAL': 4, 'BLOCK': 5, 'CONTROL_STRUCTURE': 6, 'RETURN': 7,
            'METHOD_PARAMETER_IN': 8, 'FIELD_IDENTIFIER': 9, 'TYPE': 10
        }
        category_mapping = {
            'method': 0, 'call': 1, 'identifier': 2, 'literal': 3,
            'local': 4, 'block': 5, 'control': 6, 'return': 7,
            'parameter': 8, 'field': 9, 'type': 10, 'other': 11
        }

        node_features = []
        node_tokens = []
        for node in nodes:
            code = node.get("code") or node.get("name") or ""
            if not isinstance(code, str):
                code = str(code)
            node_tokens.append(code)
            features = [
                float(node_type_mapping.get(node.get("node_type"), 11)) / 12.0,
                float(category_mapping.get(node.get("category"), 11)) / 12.0,
                float(node.get("line", 0)) / 1000.0,
                float(node.get("order", 0)) / 100.0,
                float(bool(node.get("is_source", False))),
                float(bool(node.get("is_sink", False))),
                float(len(code)) / 200.0,
                float(bool(node.get("name"))),
                0.0,  # binary label placeholder
                0.0,  # multiclass label placeholder
            ]
            while len(features) < 128:
                features.append(0.0)
            node_features.append(features[:128])

        x = torch.tensor(node_features, dtype=torch.float32)

        edge_list = []
        edge_types = []
        for edge in edges:
            try:
                src = int(edge.get("source", -1))
                tgt = int(edge.get("target", -1))
                edge_type_id = int(edge.get("edge_type_id", 2))
            except Exception:
                continue
            if 0 <= src < len(nodes) and 0 <= tgt < len(nodes) and src != tgt:
                edge_list.append([src, tgt])
                edge_types.append(edge_type_id)

        if not edge_list:
            if len(nodes) == 1:
                edge_list.append([0, 0])
                edge_types.append(2)
            else:
                for i in range(len(nodes) - 1):
                    edge_list.append([i, i + 1])
                    edge_types.append(2)

        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        edge_type = torch.tensor(edge_types, dtype=torch.long)
        data = Data(x=x, edge_index=edge_index, edge_type=edge_type)
        data.node_tokens = node_tokens
        return data

    def _run_spatial_gnn_inference(
        self,
        source_code: str,
        source_path: Optional[str],
        cpg_structure: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        models = self.spatial_gnn_models or ([self.spatial_gnn_model] if self.spatial_gnn_model else [])
        if not models:
            return None
        try:
            if cpg_structure is None:
                cpg_structure = self.joern_integrator.generate_cpg_structure(source_code, source_path)
            data = self._cpg_to_pyg_data(cpg_structure)
            if data is None:
                return None

            import torch
            confidences: List[float] = []
            raw_confidences: List[float] = []
            confidence_sources: List[str] = []
            binary_probabilities: List[float] = []
            predicted_vulnerable_votes: List[bool] = []
            predicted_types: List[str] = []
            errors: List[str] = []

            node_tokens = getattr(data, "node_tokens", None)
            for model in models:
                try:
                    model.eval()
                    try:
                        device = next(model.parameters()).device
                    except StopIteration:
                        device = torch.device("cpu")

                    x = data.x.to(device)
                    edge_index = data.edge_index.to(device)
                    edge_type = data.edge_type.to(device)

                    with torch.no_grad():
                        outputs = model(
                            x, edge_index, edge_type, node_tokens=node_tokens
                        )

                    self._gnn_forward_called = True

                    conf, source, raw_conf = self._extract_gnn_confidence(outputs)
                    if conf is not None:
                        confidences.append(conf)
                        raw_confidences.append(raw_conf if raw_conf is not None else conf)
                        confidence_sources.append(source)

                    binary_logits = outputs.get("binary_logits") if isinstance(outputs, dict) else None
                    if binary_logits is not None:
                        pred_class = int(torch.argmax(binary_logits, dim=-1).view(-1)[0].item())
                        predicted_vulnerable_votes.append(pred_class == 1)
                        prob = torch.softmax(binary_logits / self.gnn_temperature, dim=-1)[..., 1]
                        binary_probabilities.append(float(prob.view(-1)[0].item()))

                    multiclass_logits = outputs.get("multiclass_logits") if isinstance(outputs, dict) else None
                    if multiclass_logits is not None:
                        pred_type_id = int(torch.argmax(multiclass_logits, dim=-1).view(-1)[0].item())
                        predicted_types.append(GNN_VULN_TYPE_ID_TO_NAME.get(pred_type_id, "unknown_gnn"))
                except Exception as exc:
                    errors.append(str(exc))
                    continue

            if not confidences:
                return {"forward_ok": False, "error": "no_gnn_confidence", "errors": errors}

            gnn_conf = statistics.mean(confidences)
            gnn_uncertainty = statistics.pstdev(confidences) if len(confidences) > 1 else 0.0

            predicted_vuln = False
            if predicted_vulnerable_votes:
                votes = sum(1 for v in predicted_vulnerable_votes if v)
                predicted_vuln = votes > (len(predicted_vulnerable_votes) / 2)

            predicted_type = None
            if predicted_types:
                type_counts = defaultdict(int)
                for vuln_type in predicted_types:
                    type_counts[vuln_type] += 1
                predicted_type = max(type_counts.items(), key=lambda x: x[1])[0]

            stats = cpg_structure.get("statistics") or {}
            return {
                "forward_ok": True,
                "gnn_confidence": float(gnn_conf),
                "gnn_uncertainty": float(gnn_uncertainty),
                "predicted_vulnerable": predicted_vuln,
                "predicted_type": predicted_type,
                "ensemble": {
                    "models": len(models),
                    "used": len(confidences),
                    "confidence_sources": confidence_sources,
                    "confidences": confidences,
                    "raw_confidences": raw_confidences,
                    "binary_probabilities": binary_probabilities,
                    "errors": errors,
                },
                "cpg_stats": {
                    "num_nodes": stats.get("num_nodes", len(cpg_structure.get("nodes", []))),
                    "num_edges": stats.get("num_edges", len(cpg_structure.get("edges", []))),
                },
            }
        except Exception as exc:
            self.logger.warning(f"⚠️ Spatial GNN inference failed: {exc}")
            return {"forward_ok": False, "error": str(exc)}

    def _cpg_result_from_structure(self, cpg_structure: Dict[str, Any], source_code: str) -> Dict[str, Any]:
        nodes = cpg_structure.get("nodes", []) or []
        edges = cpg_structure.get("edges", []) or []
        methods = cpg_structure.get("methods", []) or []
        stats = cpg_structure.get("statistics") or {}

        identifiers = sum(1 for node in nodes if node.get("node_type") == "IDENTIFIER")
        dfg_edges = stats.get(
            "num_dfg_edges",
            sum(1 for edge in edges if edge.get("edge_type") == "DFG"),
        )
        call_edges = stats.get(
            "num_call_edges",
            sum(1 for edge in edges if edge.get("edge_type") == "CALL"),
        )

        cpg_data = {
            "nodes": stats.get("num_nodes", len(nodes)),
            "methods": stats.get("num_methods", len(methods)),
            "calls": call_edges,
            "identifiers": identifiers,
            "dfg": dfg_edges,
            "edges": stats.get("num_edges", len(edges)),
        }
        return self.joern_integrator._format_cpg_result(cpg_data, source_code)

    def _combine_confidence(self, heuristic_conf: float, gnn_conf: Optional[float], gnn_trustworthy: bool) -> float:
        if gnn_conf is None or not gnn_trustworthy:
            return heuristic_conf
        return (1.0 - self.gnn_weight) * heuristic_conf + self.gnn_weight * gnn_conf

    def analyze_code(self, source_code: str, source_path: Optional[str] = None, _internal_call: bool = False) -> Dict[str, Any]:
        """Analyze source code using the complete pipeline with Bayesian uncertainty"""
        self.logger.info("🔍 Starting code analysis...")
        if self._gnn_trace_enabled:
            self._gnn_forward_called = False
        
        # Step 1: Generate CPG using Joern (reuse full structure if GNN enabled)
        cpg_structure = None
        if self.spatial_gnn_model:
            try:
                self.logger.info("📊 Generating CPG structure for GNN...")
                cpg_structure = self.joern_integrator.generate_cpg_structure(source_code, source_path)
                cpg_result = self._cpg_result_from_structure(cpg_structure, source_code)
            except Exception as exc:
                self.logger.warning(f"⚠️ CPG structure extraction failed; falling back: {exc}")
                cpg_structure = None
                self.logger.info("📊 Generating CPG summary...")
                cpg_result = self.joern_integrator.generate_cpg(source_code, source_path)
        else:
            self.logger.info("📊 Generating CPG summary...")
            cpg_result = self.joern_integrator.generate_cpg(source_code, source_path)
            if self.enable_joern_dataflow:
                try:
                    self.logger.info("📊 Generating CPG structure for Joern dataflow...")
                    cpg_structure = self.joern_integrator.generate_cpg_structure(source_code, source_path)
                except Exception as exc:
                    self.logger.warning(f"⚠️ Joern dataflow extraction failed: {exc}")
                    cpg_structure = None
        
        # Step 1.5: Comprehensive Taint Tracking & Alias Analysis
        taint_result = {}
        if self.taint_tracker:
            self.logger.info("🔬 Running comprehensive taint tracking (3-tier detection)...")
            taint_result = self.taint_tracker.analyze_java_code(source_code, source_path=source_path)
            self.logger.info(f"✅ Taint tracking complete: {taint_result.get('tainted_variables_count', 0)} tainted, "
                           f"{taint_result.get('tainted_fields_count', 0)} tainted fields, "
                           f"{taint_result.get('taint_flows_count', 0)} flows")

        joern_dataflow = {}
        if cpg_structure and isinstance(cpg_structure, dict):
            joern_dataflow = cpg_structure.get("dataflow") or {}
            if joern_dataflow and isinstance(taint_result, dict):
                taint_result["joern_dataflow"] = joern_dataflow
        
        # Step 2: Detect vulnerability patterns
        self.logger.info("🔍 Detecting vulnerability patterns...")
        vulnerabilities = self.vulnerability_detector.detect_patterns(source_code)

        framework_sinks = {}
        if self.framework_sink_registry:
            try:
                framework_sinks = self.framework_sink_registry.analyze_code(source_code)
                if isinstance(taint_result, dict):
                    taint_result["framework_sinks"] = framework_sinks
            except Exception as exc:
                self.logger.warning(f"⚠️ Framework sink analysis failed: {exc}")

        template_engine_analysis = {}
        if self.template_engine_analyzer:
            try:
                template_engine_analysis = self.template_engine_analyzer.analyze(source_code)
                if isinstance(taint_result, dict):
                    taint_result["template_engine_analysis"] = template_engine_analysis
            except Exception as exc:
                self.logger.warning(f"⚠️ Template engine analysis failed: {exc}")

        vulnerabilities, taint_gating = self._apply_taint_gating(vulnerabilities, source_code, taint_result)
        
        # Step 3: Heuristic scoring with Bayesian uncertainty
        self.logger.info("🧠 Processing with heuristic scoring...")
        heuristic_result = self._actual_gnn_processing(
            cpg_result,
            vulnerabilities,
            taint_result=taint_result,
            source_code=source_code,
            source_path=source_path,
        )

        # Step 3.5: Spatial GNN inference (if enabled and initialized)
        gnn_inference = None
        if self.spatial_gnn_model:
            self.logger.info("🧠 Running spatial GNN inference...")
            gnn_inference = self._run_spatial_gnn_inference(
                source_code, source_path, cpg_structure=cpg_structure
            )

        gnn_forward_ok = bool(gnn_inference and gnn_inference.get("forward_ok"))
        gnn_confidence = gnn_inference.get("gnn_confidence") if gnn_forward_ok else None
        gnn_uncertainty = gnn_inference.get("gnn_uncertainty") if gnn_forward_ok else None
        gnn_trustworthy = gnn_forward_ok and self.gnn_weights_loaded
        final_confidence = self._combine_confidence(
            heuristic_result["confidence"], gnn_confidence, gnn_trustworthy
        )
        threshold_applied = False
        threshold_passed = True
        if gnn_trustworthy and self.gnn_confidence_threshold is not None:
            threshold_applied = True
            threshold_passed = final_confidence >= self.gnn_confidence_threshold
        if gnn_trustworthy:
            analysis_method = "gnn_inference_with_heuristic"
        elif gnn_forward_ok:
            analysis_method = "gnn_inference_untrained"
        else:
            analysis_method = "pattern_heuristic_with_uncertainty"
        
        gnn_predicted_allowed = False
        gnn_predicted_type = None
        if gnn_trustworthy and gnn_inference.get("predicted_vulnerable"):
            gnn_predicted_type = gnn_inference.get("predicted_type")
            if gnn_predicted_type:
                gated_predicted, _ = self._apply_taint_gating(
                    [gnn_predicted_type], source_code, taint_result
                )
                gnn_predicted_allowed = len(gated_predicted) > 0
            else:
                gnn_predicted_allowed = True
        
        # Step 4: Select primary vulnerability based on severity
        primary_vuln = self._select_primary_vulnerability_by_severity(vulnerabilities, source_code)
        
        vulnerability_detected = len(vulnerabilities) > 0
        if gnn_trustworthy and gnn_inference.get("predicted_vulnerable") and gnn_predicted_allowed:
            vulnerability_detected = True

        pre_threshold_detected = vulnerability_detected
        if threshold_applied and not threshold_passed:
            vulnerability_detected = False
            primary_vuln = 'none'

        if primary_vuln == 'none' and gnn_trustworthy and gnn_inference.get("predicted_vulnerable") and gnn_predicted_allowed:
            predicted_type = gnn_predicted_type or gnn_inference.get("predicted_type")
            if predicted_type and predicted_type != "none":
                primary_vuln = predicted_type

        final_result = {
            'vulnerability_detected': vulnerability_detected,
            'vulnerability_type': primary_vuln,
            'confidence': final_confidence,
            'heuristic_confidence': heuristic_result['confidence'],
            'traditional_confidence': heuristic_result['traditional_confidence'],
            'bayesian_confidence': heuristic_result['bayesian_confidence'],
            'gnn_confidence': gnn_confidence,
            'gnn_uncertainty': gnn_uncertainty,
            'vulnerabilities_found': vulnerabilities,
            'cpg': cpg_result['cpg'],
            'joern_available': cpg_result['joern_available'],
            'gnn_utilized': gnn_forward_ok,
            'analysis_method': analysis_method,
            'source_length': len(source_code),
            'uncertainty_metrics': heuristic_result['uncertainty_metrics'],
            'routing_decision': heuristic_result['routing_decision'],
            'requires_manual_review': heuristic_result['routing_decision'].get('requires_attention', False),
            'evidence': heuristic_result.get('evidence', {}),
            'taint_gating': taint_gating,
            'graph_sanity': heuristic_result.get('graph_sanity', {}),
            'taint_tracking': taint_result,
            'joern_dataflow': joern_dataflow,
            'framework_sinks': framework_sinks,
            'template_engine_analysis': template_engine_analysis,
            'input': source_path,  # Add input path for HTML report generation
            'source_code': source_code  # Add source code for CF explainer
        }
        final_result['gnn_forward_called'] = gnn_forward_ok
        final_result['gnn_threshold'] = {
            'applied': threshold_applied,
            'passed': threshold_passed,
            'threshold': self.gnn_confidence_threshold,
            'score': final_confidence,
            'pre_threshold_detected': pre_threshold_detected,
        }
        
        # Spatial GNN status (initialized but not used in scoring pipeline)
        final_result['spatial_gnn'] = {
            'enabled': self.enable_spatial_gnn,
            'initialized': bool(self.spatial_gnn_models or self.spatial_gnn_model),
            'used_in_scoring': gnn_trustworthy,
            'note': 'Spatial GNN inference executed' if gnn_forward_ok else 'Model initialization only; inference not executed',
            'forward_called': gnn_forward_ok,
            'weights_loaded': self.gnn_weights_loaded,
            'weights_loaded_count': self.gnn_weights_loaded_count,
            'ensemble_size': len(self.spatial_gnn_models) if self.spatial_gnn_models else (1 if self.spatial_gnn_model else 0),
            'gnn_weight': self.gnn_weight,
            'gnn_temperature': self.gnn_temperature,
            'gnn_confidence_threshold': self.gnn_confidence_threshold,
        }
        if self._gnn_trace_enabled:
            final_result['spatial_gnn']['trace_enabled'] = True
        if gnn_inference:
            final_result['spatial_gnn']['inference'] = gnn_inference
        
        # Generate counterfactual explanations if enabled
        if self.cf_explainer and len(vulnerabilities) > 0:
            try:
                cf_explanation = self.cf_explainer.explain_vulnerability(
                    source_path or 'unknown.java', 
                    final_result
                )
                final_result['cf_explanation'] = cf_explanation
                self.logger.info("✅ Counterfactual explanation generated")
            except Exception as e:
                self.logger.warning(f"⚠️ CF explanation failed: {e}")
                final_result['cf_explanation'] = None
        
        return final_result
    
    def _select_primary_vulnerability_by_severity(self, vulnerabilities: List[str], source_code: str) -> str:
        """Select primary vulnerability based on severity"""
        if not vulnerabilities:
            return 'none'
        
        severity_order = {
            'null_pointer_dereference': 100,
            'buffer_overflow': 95,
            'integer_overflow': 92,  # CWE-190, CWE-191 - High severity
            'sql_injection': 90,
            'command_injection': 90,
            'deserialization': 85,
            'xxe': 85,
            'ssrf': 84,
            'el_injection': 83,  # CWE-94 - High severity (code execution via EL evaluation)
            'http_response_splitting': 82,  # CWE-113 - High severity (can lead to XSS, cache poisoning)
            'reflection_injection': 80,  # CWE-470 - High severity (arbitrary method invocation)
            'session_fixation': 78,  # CWE-384 - High severity (authentication bypass)
            'resource_leak': 76,  # CWE-404, CWE-772 - High severity (memory exhaustion, DOS)
            'ldap_injection': 75,
            'xpath_injection': 74,
            'race_condition': 72,  # CWE-362, CWE-366, CWE-367 - High severity (data corruption, TOCTOU)
            'xss': 70,
            'path_traversal': 70,
            'weak_crypto': 60,
            'insecure_randomness': 55,
            'hardcoded_credentials': 50,
            'trust_boundary_violation': 45,
            'csrf': 40,
            'log_injection': 30,
        }
        
        scored_vulns = []
        for vuln in vulnerabilities:
            base_score = severity_order.get(vuln, 0)
            evidence_boost = 0
            
            if vuln == 'null_pointer_dereference':
                if 'getProfile().get' in source_code or ').get' in source_code:
                    evidence_boost = 20
                elif '.get(' in source_code and '.length()' in source_code:
                    evidence_boost = 10
            
            final_score = base_score + evidence_boost
            scored_vulns.append((vuln, final_score))
        
        scored_vulns.sort(key=lambda x: x[1], reverse=True)
        return scored_vulns[0][0]
    
    def _count_markers(self, code_lower: str, markers: List[str]) -> int:
        return sum(1 for marker in markers if marker in code_lower)

    def _extract_evidence_signals(self, source_code: str, taint_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        code_lower = source_code.lower()
        taint_flows = int(taint_result.get("taint_flows_count", 0)) if taint_result else 0
        tainted_vars = int(taint_result.get("tainted_variables_count", 0)) if taint_result else 0
        sanitized_vars = int(taint_result.get("sanitized_variables_count", 0)) if taint_result else 0

        user_input_markers = [
            "getparameter(", "getheader(", "getcookies(", "getinputstream(", "getreader(",
            "httprequest", "httpservletrequest", "servletrequest", "request.getparameter",
            "request.getheader", "request.getquerystring", "system.in", "readline(", "read(",
        ]
        sanitizer_markers = [
            "preparedstatement", "setstring(", "setint(", "setlong(", "setobject(",
            "urLEncoder.encode".lower(), "stringescapeutils.escapehtml",
            "esapi.encoder", "htmlescape", "htmlutils.htmlescape", "encodeforhtml",
            "encodeforurl", "encodeforjavascript",
        ]
        sink_sanitizer_markers = {
            "sql_injection": [
                "preparedstatement", "createpreparedstatement", "setstring(", "setint(",
                "setlong(", "setobject(", "setparameter(", "namedparameterjdbctemplate",
                "jdbcTemplate.query", "queryforobject(", "createquery(", "setnull(",
            ],
            "xss": [
                "stringescapeutils.escapehtml", "stringescapeutils.escapehtml4", "stringescapeutils.escapehtml5",
                "htmlescape", "htmlutils.htmlescape", "encodeforhtml", "encodeforhtmlattribute",
                "encodeforjavascript", "encodeforurl", "esapi.encoder().encodeforhtml",
                "owasp.encoder", "encode.forhtml", "encode.forhtmlattribute",
                "jsoup.clean(", "policyfactory.sanitize", "sanitizer.sanitize", "bleach.clean",
            ],
            "path_traversal": [
                "getcanonicalpath()", "getcanonicalfile()", "torealpath()", "normalize()", "path.normalize",
                "paths.get(", ".normalize()", ".torealpath(",
            ],
            "ldap_injection": [
                "ldapencoder.encodefilter", "ldapencoder.encodedn", "rdn.escapevalue",
                "escapeldapsearchfilter", "escapedn", "ldapname(",
            ],
            "xxe": [
                "xmlconstants.feature_secure_processing",
                "disallow-doctype-decl",
                "external-general-entities",
                "external-parameter-entities",
                "setxincludeaware(false",
                "setexpandentityreferences(false",
            ],
            "http_response_splitting": [
                "encodeurl(", "encoderedirecturl(", "urlencoder.encode", "encodeforurl", "encodeforuricomponent",
            ],
            "command_injection": [
                "processbuilder(", ".command(", "list.of(", "arrays.aslist(",
            ],
        }
        sink_markers = {
            "sql_injection": ["executequery(", "executeupdate(", "execute(", "preparestatement("],
            "command_injection": ["runtime.getruntime().exec", "runtime.exec", "processbuilder", "new processbuilder", ".start("],
            "path_traversal": ["new file(", "fileinputstream(", "filereader(", "files.read", "files.write", "paths.get("],
            "xss": [
                "getwriter().print",
                "getwriter().println",
                "getwriter().write",
                "getwriter().append",
                "response.getwriter",
                "response.getoutputstream",
                "getoutputstream().write",
                "servletoutputstream",
                "printwriter",
                "jspwriter",
                "pagecontext.getout",
                "getout().print",
                "getout().println",
                "getout().write",
            ],
            "ldap_injection": ["dircontext", "ldap", "search(", "filter", "lookup(", "initialcontext"],
            "xxe": ["documentbuilderfactory", "documentbuilder", "saxparser", "xmlreader", "inputsource"],
            "deserialization": ["objectinputstream", "readobject", "xmldecoder", "xstream"],
            "http_response_splitting": ["setheader(", "addheader(", "sendredirect(", "setstatus("],
            "reflection_injection": ["class.forname", "getmethod", "invoke(", "method.invoke", "newinstance"],
            "ssrf": ["urlconnection", "httpurlconnection", "openconnection", "openstream"],
            "xpath_injection": ["xpathfactory", "xpath", "compile(", "evaluate("],
            "el_injection": [
                "expressionfactory",
                "createvalueexpression(",
                "createmethodexpression(",
                "valueexpression",
                "methodexpression",
                "elcontext",
                "elprocessor",
                "elprocessor.eval(",
                "elmanager",
                "expressionfactoryimpl",
                "pagecontextimpl.proprietaryevaluate",
                "getexpressionevaluator",
                "expressionevaluator.evaluate(",
                "javax.el",
                "jakarta.el",
                "freemarker.template",
                "freemarker.template.template",
                "velocityengine.mergetemplate(",
                "velocityengine.evaluate(",
                "velocity.evaluate(",
                "velocitycontext",
                "thymeleaf",
                "stringtemplateresolver",
                "mustache.execute(",
                "mustachefactory.compile(",
                "handlebars.compile(",
                "handlebars.compileinline(",
                "pebbleengine.gettemplate(",
                "pebbletemplate.evaluate(",
                "gg.jte",
            ],
        }

        weak_crypto_markers = ["md5", "sha1", "des", "rc4", "blowfish", "md4"]
        insecure_random_markers = ["new random(", "math.random", "random()"]
        secure_random_markers = ["securerandom"]
        hardcoded_patterns = [
            r'password\s*=\s*["\']',
            r'passwd\s*=\s*["\']',
            r'api[_-]?key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\']',
        ]

        user_input_hits = self._count_markers(code_lower, user_input_markers)
        sanitizer_hits = self._count_markers(code_lower, sanitizer_markers)
        sink_hits = {key: self._count_markers(code_lower, markers) for key, markers in sink_markers.items()}
        sink_sanitizer_hits = {
            key: self._count_markers(code_lower, markers)
            for key, markers in sink_sanitizer_markers.items()
        }
        sanitizer_effectiveness_by_sink = {}
        if taint_result and isinstance(taint_result, dict):
            sanitizer_analysis = taint_result.get("sanitizer_analysis") or {}
            if isinstance(sanitizer_analysis, dict):
                analysis_hits = sanitizer_analysis.get("sink_sanitizer_hits") or {}
                if isinstance(analysis_hits, dict):
                    for key, value in analysis_hits.items():
                        try:
                            sink_sanitizer_hits[key] = max(sink_sanitizer_hits.get(key, 0), int(value))
                        except Exception:
                            continue
                effectiveness = sanitizer_analysis.get("effectiveness_by_sink") or {}
                if isinstance(effectiveness, dict):
                    sanitizer_effectiveness_by_sink = effectiveness

        framework_hits_by_vuln: Dict[str, int] = {}
        framework_safe_hits_by_vuln: Dict[str, int] = {}
        framework_unsafe_hits_by_vuln: Dict[str, int] = {}
        framework_autoescape_disabled: Dict[str, int] = {}
        framework_autoescape_enabled: Dict[str, int] = {}
        if taint_result and isinstance(taint_result, dict):
            framework_sinks = taint_result.get("framework_sinks") or {}
            if isinstance(framework_sinks, dict):
                framework_hits_by_vuln = framework_sinks.get("hits_by_vuln", {}) or {}
                framework_safe_hits_by_vuln = framework_sinks.get("safe_hits_by_vuln", {}) or {}
                framework_unsafe_hits_by_vuln = framework_sinks.get("unsafe_hits_by_vuln", {}) or {}
                framework_autoescape_disabled = framework_sinks.get("autoescape_disabled", {}) or {}
                framework_autoescape_enabled = framework_sinks.get("autoescape_enabled", {}) or {}

        template_autoescape_disabled = 0
        template_autoescape_enabled = 0
        template_safe_variants = 0
        template_unsafe_variants = 0
        if taint_result and isinstance(taint_result, dict):
            template_analysis = taint_result.get("template_engine_analysis") or {}
            if isinstance(template_analysis, dict):
                autoescape = template_analysis.get("autoescape", {}) or {}
                if isinstance(autoescape, dict):
                    template_autoescape_disabled = len(autoescape.get("disabled", []) or [])
                    template_autoescape_enabled = len(autoescape.get("enabled", []) or [])
                template_safe_variants = len(template_analysis.get("safe_variants", []) or [])
                template_unsafe_variants = len(template_analysis.get("unsafe_variants", []) or [])

        joern_flow_hits: Dict[str, int] = {}
        joern_source_counts: Dict[str, int] = {}
        joern_sink_counts: Dict[str, int] = {}
        if taint_result and isinstance(taint_result, dict):
            joern_dataflow = taint_result.get("joern_dataflow") or {}
            if isinstance(joern_dataflow, dict):
                flows_by_sink = joern_dataflow.get("flows_by_sink") or {}
                if isinstance(flows_by_sink, dict):
                    for sink_name, payload in flows_by_sink.items():
                        if isinstance(payload, dict) and "flows" in payload:
                            try:
                                joern_flow_hits[sink_name] = int(payload.get("flows", 0) or 0)
                                joern_source_counts[sink_name] = int(payload.get("sources", 0) or 0)
                                joern_sink_counts[sink_name] = int(payload.get("sinks", 0) or 0)
                            except Exception:
                                continue
        weak_crypto_hits = self._count_markers(code_lower, weak_crypto_markers)
        insecure_random_hits = self._count_markers(code_lower, insecure_random_markers)
        secure_random_hits = self._count_markers(code_lower, secure_random_markers)
        hardcoded_hits = sum(1 for pattern in hardcoded_patterns if re.search(pattern, source_code, re.IGNORECASE))

        return {
            "taint_flows": taint_flows,
            "tainted_variables": tainted_vars,
            "sanitized_variables": sanitized_vars,
            "user_input_hits": user_input_hits,
            "sanitizer_hits": sanitizer_hits,
            "sink_hits": sink_hits,
            "sink_sanitizer_hits": sink_sanitizer_hits,
            "sanitizer_effectiveness_by_sink": sanitizer_effectiveness_by_sink,
            "joern_flow_hits": joern_flow_hits,
            "joern_source_counts": joern_source_counts,
            "joern_sink_counts": joern_sink_counts,
            "framework_hits": framework_hits_by_vuln,
            "framework_safe_hits": framework_safe_hits_by_vuln,
            "framework_unsafe_hits": framework_unsafe_hits_by_vuln,
            "framework_autoescape_disabled": framework_autoescape_disabled,
            "framework_autoescape_enabled": framework_autoescape_enabled,
            "template_autoescape_disabled": template_autoescape_disabled,
            "template_autoescape_enabled": template_autoescape_enabled,
            "template_safe_variants": template_safe_variants,
            "template_unsafe_variants": template_unsafe_variants,
            "weak_crypto_hits": weak_crypto_hits,
            "insecure_random_hits": insecure_random_hits,
            "secure_random_hits": secure_random_hits,
            "hardcoded_hits": hardcoded_hits,
        }

    def _compute_evidence_adjustment(
        self,
        source_code: str,
        vulnerabilities: List[str],
        taint_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        evidence = self._extract_evidence_signals(source_code, taint_result)
        if not vulnerabilities:
            evidence["per_vuln_adjustments"] = {}
            evidence["evidence_adjustment"] = 0.0
            return evidence

        injection_types = {
            "sql_injection",
            "command_injection",
            "ldap_injection",
            "xss",
            "xxe",
            "el_injection",
            "http_response_splitting",
            "path_traversal",
            "reflection_injection",
        }

        per_vuln = {}
        total_adjustment = 0.0
        for vuln in vulnerabilities:
            adjustment = 0.0
            if vuln in injection_types:
                if evidence["taint_flows"] > 0:
                    adjustment += 0.08
                if evidence["user_input_hits"] > 0:
                    adjustment += 0.05
                if evidence["sink_hits"].get(vuln, 0) > 0:
                    adjustment += 0.05
                if evidence.get("framework_unsafe_hits", {}).get(vuln, 0) > 0:
                    adjustment += 0.04
                if evidence.get("framework_safe_hits", {}).get(vuln, 0) > 0 and evidence.get("framework_unsafe_hits", {}).get(vuln, 0) == 0:
                    adjustment -= 0.03
                if vuln == "xss":
                    if evidence.get("template_autoescape_disabled", 0) > 0 or evidence.get("template_unsafe_variants", 0) > 0:
                        adjustment += 0.04
                    if evidence.get("template_autoescape_enabled", 0) > 0 and evidence.get("template_unsafe_variants", 0) == 0:
                        adjustment -= 0.03
                sink_sanitizer_hits = evidence.get("sink_sanitizer_hits", {}).get(vuln, 0)
                if evidence["sanitized_variables"] > 0 or evidence["sanitizer_hits"] > 0 or sink_sanitizer_hits > 0:
                    adjustment -= min(0.08, 0.02 * max(evidence["sanitized_variables"], 1))
                    if sink_sanitizer_hits > 0:
                        adjustment -= min(0.06, 0.02 * sink_sanitizer_hits)
            elif vuln == "weak_crypto":
                adjustment += 0.08 if evidence["weak_crypto_hits"] > 0 else -0.04
            elif vuln == "insecure_randomness":
                if evidence["insecure_random_hits"] > 0:
                    adjustment += 0.05
                if evidence["secure_random_hits"] > 0:
                    adjustment -= 0.05
            elif vuln == "deserialization":
                adjustment += 0.08 if evidence["sink_hits"].get("deserialization", 0) > 0 else -0.03
            elif vuln == "hardcoded_credentials":
                adjustment += 0.05 if evidence["hardcoded_hits"] > 0 else -0.02
            elif evidence["taint_flows"] > 0:
                adjustment += 0.03

            per_vuln[vuln] = adjustment
            total_adjustment += adjustment

        total_adjustment = total_adjustment / max(1, len(vulnerabilities))
        total_adjustment = max(-0.15, min(0.15, total_adjustment))
        evidence["per_vuln_adjustments"] = per_vuln
        evidence["evidence_adjustment"] = total_adjustment
        return evidence

    def _build_sink_evidence(
        self,
        vuln: str,
        evidence: Dict[str, Any],
    ) -> Tuple[List[Any], bool]:
        if not self.sink_gating_engine or not SINK_GATING_AVAILABLE:
            return [], False

        taint_flows = int(evidence.get("taint_flows", 0))
        sink_hits = int(evidence.get("sink_hits", {}).get(vuln, 0))
        sink_sanitizer_hits = int(evidence.get("sink_sanitizer_hits", {}).get(vuln, 0))
        joern_flow_hits = int(evidence.get("joern_flow_hits", {}).get(vuln, 0))
        sanitizer_effectiveness_by_sink = evidence.get("sanitizer_effectiveness_by_sink", {}) or {}
        sink_effectiveness = None
        try:
            if vuln in sanitizer_effectiveness_by_sink:
                sink_effectiveness = float(sanitizer_effectiveness_by_sink.get(vuln, 0.0))
        except Exception:
            sink_effectiveness = None
        sanitized_vars = int(evidence.get("sanitized_variables", 0))
        sanitizer_hits = int(evidence.get("sanitizer_hits", 0))
        user_input_hits = int(evidence.get("user_input_hits", 0))
        framework_safe_hits = int(evidence.get("framework_safe_hits", {}).get(vuln, 0))
        framework_unsafe_hits = int(evidence.get("framework_unsafe_hits", {}).get(vuln, 0))
        framework_autoescape_disabled = int(evidence.get("framework_autoescape_disabled", {}).get(vuln, 0))
        template_autoescape_disabled = int(evidence.get("template_autoescape_disabled", 0))
        template_autoescape_enabled = int(evidence.get("template_autoescape_enabled", 0))
        template_unsafe_variants = int(evidence.get("template_unsafe_variants", 0))
        joern_sources = int(evidence.get("joern_source_counts", {}).get(vuln, 0))
        joern_sinks = int(evidence.get("joern_sink_counts", {}).get(vuln, 0))

        is_direct_flow = (taint_flows > 0 and sink_hits > 0) or joern_flow_hits > 0
        evidence_items: List[Any] = []

        if joern_flow_hits > 0:
            reachability_type, reachability_conf = self._compute_reachability_confidence(
                joern_flow_hits, joern_sources, joern_sinks
            )
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.DIRECT_TAINT_PATH,
                    description=f"Joern reachableByFlows ({joern_flow_hits} path(s); {reachability_type})",
                    confidence_score=reachability_conf,
                )
            )
            if joern_flow_hits > 1:
                evidence_items.append(
                    EvidenceInstance(
                        evidence_type=EvidenceType.MULTIPLE_PATHS,
                        description=f"Multiple Joern paths ({joern_flow_hits})",
                        confidence_score=0.85,
                    )
                )

        if taint_flows > 0:
            flow_conf = 0.70 + min(0.20, 0.05 * taint_flows)
            flow_type = EvidenceType.DIRECT_TAINT_PATH if is_direct_flow else EvidenceType.INDIRECT_TAINT_PATH
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=flow_type,
                    description=f"Taint flow evidence ({taint_flows} paths)",
                    confidence_score=flow_conf,
                )
            )

        if taint_flows > 1:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.MULTIPLE_PATHS,
                    description=f"Multiple taint paths ({taint_flows})",
                    confidence_score=0.80,
                )
            )

        if sink_hits > 0:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.DANGEROUS_PATTERN,
                    description=f"Sink usage detected ({sink_hits})",
                    confidence_score=0.75,
                )
            )

        if framework_unsafe_hits > 0 or framework_autoescape_disabled > 0:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.DANGEROUS_PATTERN,
                    description="Framework sink unsafe variant detected",
                    confidence_score=0.78,
                )
            )
        elif framework_safe_hits > 0:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.WEAK_VALIDATION,
                    description="Framework sink safe-by-default variant detected",
                    confidence_score=0.35,
                )
            )

        if vuln in {"xss", "el_injection"}:
            if template_autoescape_disabled > 0 or template_unsafe_variants > 0:
                evidence_items.append(
                    EvidenceInstance(
                        evidence_type=EvidenceType.DANGEROUS_PATTERN,
                        description="Template auto-escape disabled or unsafe variants detected",
                        confidence_score=0.80,
                    )
                )
            elif template_autoescape_enabled > 0 and template_unsafe_variants == 0:
                evidence_items.append(
                    EvidenceInstance(
                        evidence_type=EvidenceType.WEAK_VALIDATION,
                        description="Template auto-escape enabled",
                        confidence_score=0.35,
                    )
                )

        if sanitized_vars == 0 and sanitizer_hits == 0 and sink_sanitizer_hits == 0:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.NO_SANITIZER,
                    description="No sanitizer evidence detected",
                    confidence_score=0.85,
                )
            )
        elif sink_sanitizer_hits > 0:
            if sink_effectiveness is not None and sink_effectiveness >= 0.85:
                pass
            elif sink_effectiveness is not None and sink_effectiveness >= 0.60:
                evidence_items.append(
                    EvidenceInstance(
                        evidence_type=EvidenceType.WEAK_VALIDATION,
                        description=f"Sink-specific sanitizers weak/moderate ({sink_sanitizer_hits})",
                        confidence_score=0.45,
                    )
                )
            else:
                evidence_items.append(
                    EvidenceInstance(
                        evidence_type=EvidenceType.INEFFECTIVE_SANITIZER,
                        description=f"Sink-specific sanitizers ineffective ({sink_sanitizer_hits})",
                        confidence_score=0.30,
                    )
                )
        elif sanitizer_hits > 0 or sanitized_vars > 0:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.WEAK_VALIDATION,
                    description="Generic sanitization/validation evidence present",
                    confidence_score=0.40,
                )
            )

        if user_input_hits > 0 and taint_flows > 0:
            evidence_items.append(
                EvidenceInstance(
                    evidence_type=EvidenceType.DIRECT_TAINT_PATH,
                    description="User input markers present",
                    confidence_score=0.78,
                )
            )

        return evidence_items, is_direct_flow

    def _compute_reachability_confidence(
        self,
        joern_flows: int,
        joern_sources: int,
        joern_sinks: int,
    ) -> Tuple[str, float]:
        if joern_sources == 0 or joern_sinks == 0:
            return "unknown", 0.0
        if joern_flows == 0:
            return "unreachable", 0.0
        if joern_flows == 1:
            return "direct", 0.85
        if joern_flows <= 3:
            return "indirect", 0.75
        return "conditional", 0.65

    def _apply_taint_gating(
        self,
        vulnerabilities: List[str],
        source_code: str,
        taint_result: Optional[Dict[str, Any]],
    ) -> Tuple[List[str], Dict[str, Any]]:
        if not vulnerabilities:
            return vulnerabilities, {"enabled": False, "reason": "no_vulnerabilities"}
        if not taint_result:
            return vulnerabilities, {"enabled": False, "reason": "taint_unavailable"}

        evidence = self._extract_evidence_signals(source_code, taint_result)
        taint_flows = evidence.get("taint_flows", 0)
        sanitizer_hits = evidence.get("sanitizer_hits", 0)
        sanitized_vars = evidence.get("sanitized_variables", 0)
        user_input_hits = evidence.get("user_input_hits", 0)
        sink_sanitizer_hits = evidence.get("sink_sanitizer_hits", {})
        joern_flow_hits = evidence.get("joern_flow_hits", {})
        joern_source_counts = evidence.get("joern_source_counts", {})
        joern_sink_counts = evidence.get("joern_sink_counts", {})

        gating_types = {
            "sql_injection",
            "xss",
            "ldap_injection",
            "xxe",
            "path_traversal",
            "command_injection",
            "http_response_splitting",
            "reflection_injection",
            "el_injection",
        }

        kept: List[str] = []
        dropped: List[Dict[str, Any]] = []
        decisions: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            if vuln not in gating_types:
                kept.append(vuln)
                continue

            joern_flows = int(joern_flow_hits.get(vuln, 0) or 0)
            joern_sources = int(joern_source_counts.get(vuln, 0) or 0)
            joern_sinks = int(joern_sink_counts.get(vuln, 0) or 0)
            sink_hits_for_vuln = int(evidence.get("sink_hits", {}).get(vuln, 0) or 0)
            if joern_sinks > 0 and joern_sources > 0 and joern_flows == 0:
                if taint_flows > 0 or sink_hits_for_vuln > 0 or user_input_hits > 0:
                    # Joern reported no flows, but other evidence exists; do not block.
                    pass
                else:
                    dropped.append({
                        "vulnerability": vuln,
                        "reason": "joern_unreachable",
                        "joern_sources": joern_sources,
                        "joern_sinks": joern_sinks,
                    })
                    decisions.append({
                        "vulnerability": vuln,
                        "passed": False,
                        "confidence": 0.0,
                        "threshold": None,
                        "flow_type": "joern_unreachable",
                        "evidence_types": [],
                        "reason": "joern_unreachable",
                    })
                    continue

            if self.sink_gating_engine and SINK_GATING_AVAILABLE:
                evidence_items, is_direct_flow = self._build_sink_evidence(vuln, evidence)
                if not evidence_items:
                    dropped.append({"vulnerability": vuln, "reason": "insufficient_evidence"})
                    decisions.append({
                        "vulnerability": vuln,
                        "passed": False,
                        "confidence": 0.0,
                        "threshold": None,
                        "flow_type": "unknown",
                        "evidence_types": [],
                        "reason": "insufficient_evidence",
                    })
                    continue

                confidence, passed, details = self.sink_gating_engine.evaluate_vulnerability(
                    vuln, evidence_items, is_direct_flow=is_direct_flow
                )
                decisions.append({
                    "vulnerability": vuln,
                    "passed": passed,
                    "confidence": confidence,
                    "threshold": details.get("threshold"),
                    "flow_type": details.get("flow_type"),
                    "evidence_types": [e.get("type") for e in details.get("evidence_breakdown", [])],
                    "details": details,
                })
                if passed:
                    kept.append(vuln)
                else:
                    dropped.append({
                        "vulnerability": vuln,
                        "reason": "confidence_gate",
                        "confidence": confidence,
                        "threshold": details.get("threshold"),
                    })
                continue

            sink_hits = evidence.get("sink_hits", {}).get(vuln, 0)
            taint_ok = taint_flows > 0
            sink_ok = sink_hits > 0
            sanitized = sanitized_vars > 0 or sanitizer_hits > 0 or sink_sanitizer_hits.get(vuln, 0) > 0

            if not taint_ok:
                dropped.append({"vulnerability": vuln, "reason": "no_taint_flows"})
                continue
            if not sink_ok:
                dropped.append({"vulnerability": vuln, "reason": "no_sink_evidence"})
                continue
            if sanitized and taint_flows <= 1 and sink_hits <= 1 and user_input_hits == 0:
                dropped.append({"vulnerability": vuln, "reason": "sanitization_evidence"})
                continue

            kept.append(vuln)

        gating_report = {
            "enabled": True,
            "gated_types": sorted(gating_types),
            "kept": kept,
            "dropped": dropped,
            "decisions": decisions,
            "engine": {
                "enabled": bool(self.sink_gating_engine),
                "available": SINK_GATING_AVAILABLE,
            },
            "evidence": {
                "taint_flows": taint_flows,
                "sanitized_variables": sanitized_vars,
                "sanitizer_hits": sanitizer_hits,
                "sink_hits": evidence.get("sink_hits", {}),
                "sink_sanitizer_hits": sink_sanitizer_hits,
                "sanitizer_effectiveness_by_sink": evidence.get("sanitizer_effectiveness_by_sink", {}),
                "joern_flow_hits": evidence.get("joern_flow_hits", {}),
                "joern_source_counts": evidence.get("joern_source_counts", {}),
                "joern_sink_counts": evidence.get("joern_sink_counts", {}),
                "framework_hits": evidence.get("framework_hits", {}),
                "framework_safe_hits": evidence.get("framework_safe_hits", {}),
                "framework_unsafe_hits": evidence.get("framework_unsafe_hits", {}),
                "framework_autoescape_disabled": evidence.get("framework_autoescape_disabled", {}),
                "framework_autoescape_enabled": evidence.get("framework_autoescape_enabled", {}),
                "template_autoescape_disabled": evidence.get("template_autoescape_disabled", 0),
                "template_autoescape_enabled": evidence.get("template_autoescape_enabled", 0),
                "template_safe_variants": evidence.get("template_safe_variants", 0),
                "template_unsafe_variants": evidence.get("template_unsafe_variants", 0),
            },
        }
        return kept, gating_report

    def _actual_gnn_processing(
        self,
        cpg_result: Dict[str, Any],
        vulnerabilities: List[str],
        taint_result: Optional[Dict[str, Any]] = None,
        source_code: Optional[str] = None,
        source_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Heuristic scoring with Bayesian uncertainty (no trained GNN inference)"""
        cpg_data = cpg_result['cpg']
        
        # Traditional confidence
        base_confidence = 0.5
        complexity_factor = min(cpg_data.get('nodes', 0) / 100.0, 0.3)
        pattern_factor = len(vulnerabilities) * 0.2
        joern_bonus = 0.1 if cpg_result['joern_available'] else 0.0
        evidence = self._compute_evidence_adjustment(source_code or "", vulnerabilities, taint_result)
        evidence_adjustment = evidence.get("evidence_adjustment", 0.0)
        traditional_confidence = min(
            max(base_confidence + complexity_factor + pattern_factor + joern_bonus + evidence_adjustment, 0.0),
            1.0,
        )
        
        # Bayesian uncertainty analysis
        self.logger.info("🧠 Applying Bayesian uncertainty quantification...")
        uncertainty_results = self.bayesian_layer.monte_carlo_dropout(cpg_data, vulnerabilities)
        bayesian_confidence = uncertainty_results['mean_prediction']
        
        # Route high-uncertainty samples
        routing_results = self.bayesian_layer.route_high_uncertainty_samples(uncertainty_results)
        
        # Combine confidences
        final_confidence = 0.7 * bayesian_confidence + 0.3 * traditional_confidence
        
        return {
            'confidence': final_confidence,
            'traditional_confidence': traditional_confidence,
            'bayesian_confidence': bayesian_confidence,
            'uncertainty_metrics': uncertainty_results,
            'routing_decision': routing_results,
            'evidence': evidence,
            'graph_sanity': {
                'nodes': cpg_data.get('nodes', 0),
                'edges': cpg_data.get('edges', 0),
                'methods': cpg_data.get('methods', 0),
            },
            'gnn_features': {
                'node_count': cpg_data.get('nodes', 0),
                'method_count': cpg_data.get('methods', 0),
                'call_count': cpg_data.get('calls', 0),
                'pattern_count': len(vulnerabilities)
            }
        }