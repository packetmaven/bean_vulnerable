"""
Advanced Sanitizer Detection and Validation (Java)
==================================================

Pattern-based sanitizer detection with sink-specific effectiveness scoring.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import logging
import re
from typing import Dict, Optional

try:
    from .sink_gating_config import PrecisionTuningConfig
    CONFIG_AVAILABLE = True
except Exception:  # pragma: no cover - optional
    PrecisionTuningConfig = None
    CONFIG_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class SanitizerPattern:
    """Pattern for detecting a sanitizer call."""

    name: str
    patterns: List[str]
    keywords: List[str]
    cwe_list: List[int]
    effectiveness: float
    false_positive_risk: float

    def matches(self, code_line: str) -> bool:
        if any(keyword in code_line for keyword in self.keywords):
            return True
        for pattern in self.patterns:
            if re.search(pattern, code_line, re.IGNORECASE):
                return True
        return False


class JavaSanitizerDatabase:
    """Sanitizer pattern database tailored for Java."""

    def __init__(self) -> None:
        self.patterns: Dict[str, SanitizerPattern] = {}
        self._build_database()

    def _build_database(self) -> None:
        self.register(
            SanitizerPattern(
                name="HTML Entity Escaping",
                patterns=[
                    r"stringescapeutils\.escapehtml4\s*\(",
                    r"stringescapeutils\.escapehtml5\s*\(",
                    r"htmlutils\.htmlescape\s*\(",
                    r"encode\.forhtml\s*\(",
                    r"encode\.forhtmlattribute\s*\(",
                    r"esapi\.encoder\(\)\.encodeforhtml",
                ],
                keywords=[
                    "escapeHtml4",
                    "escapeHtml5",
                    "htmlEscape",
                    "Encode.forHtml",
                    "Encode.forHtmlAttribute",
                ],
                cwe_list=[79, 80],
                effectiveness=0.92,
                false_positive_risk=0.03,
            )
        )
        self.register(
            SanitizerPattern(
                name="HTML Sanitization (Allowlist)",
                patterns=[
                    r"jsoup\.clean\s*\(",
                    r"policyfactory\.sanitize\s*\(",
                ],
                keywords=["Jsoup.clean", "PolicyFactory.sanitize"],
                cwe_list=[79],
                effectiveness=0.94,
                false_positive_risk=0.02,
            )
        )
        self.register(
            SanitizerPattern(
                name="URL Encoding",
                patterns=[
                    r"urlencoder\.encode\s*\(",
                    r"encode\.foruri\s*\(",
                    r"encode\.foruricomponent\s*\(",
                ],
                keywords=["URLEncoder.encode", "Encode.forUri", "Encode.forUriComponent"],
                cwe_list=[601, 20],
                effectiveness=0.88,
                false_positive_risk=0.05,
            )
        )
        self.register(
            SanitizerPattern(
                name="SQL Parameterization",
                patterns=[
                    r"\.setstring\s*\(",
                    r"\.setint\s*\(",
                    r"\.setlong\s*\(",
                    r"\.setobject\s*\(",
                    r"\.setboolean\s*\(",
                    r"\.setdouble\s*\(",
                    r"\.setfloat\s*\(",
                    r"\.setshort\s*\(",
                    r"\.setbigdecimal\s*\(",
                    r"\.settimestamp\s*\(",
                    r"\.setparameter\s*\(",
                    r"namedparameterjdbctemplate",
                ],
                keywords=[
                    "setString",
                    "setInt",
                    "setLong",
                    "setObject",
                    "setBoolean",
                    "setDouble",
                    "setFloat",
                    "setShort",
                    "setBigDecimal",
                    "setTimestamp",
                    "setParameter",
                ],
                cwe_list=[89],
                effectiveness=0.95,
                false_positive_risk=0.02,
            )
        )
        self.register(
            SanitizerPattern(
                name="Path Normalization",
                patterns=[
                    r"getcanonicalpath\s*\(",
                    r"getcanonicalfile\s*\(",
                    r"torealpath\s*\(",
                    r"\.normalize\s*\(",
                ],
                keywords=["getCanonicalPath", "getCanonicalFile", "toRealPath", "normalize"],
                cwe_list=[22],
                effectiveness=0.93,
                false_positive_risk=0.04,
            )
        )
        self.register(
            SanitizerPattern(
                name="LDAP Escaping",
                patterns=[
                    r"ldapencoder\.encodefilter\s*\(",
                    r"rdn\.escapevalue\s*\(",
                    r"escapeldapsearchfilter\s*\(",
                ],
                keywords=["LdapEncoder.encodeFilter", "Rdn.escapeValue", "escapeLdapSearchFilter"],
                cwe_list=[90],
                effectiveness=0.88,
                false_positive_risk=0.06,
            )
        )
        self.register(
            SanitizerPattern(
                name="XXE Hardening",
                patterns=[
                    r"xmlconstants\.feature_secure_processing",
                    r"disallow-doctype-decl",
                    r"external-general-entities",
                    r"external-parameter-entities",
                    r"setxincludeaware\s*\(\s*false",
                    r"setexpandentityreferences\s*\(\s*false",
                ],
                keywords=["FEATURE_SECURE_PROCESSING", "disallow-doctype-decl"],
                cwe_list=[611],
                effectiveness=0.90,
                false_positive_risk=0.05,
            )
        )
        self.register(
            SanitizerPattern(
                name="Command Argument List",
                patterns=[
                    r"new\s+processbuilder\s*\(",
                    r"\.command\s*\(",
                    r"list\.of\s*\(",
                    r"arrays\.aslist\s*\(",
                ],
                keywords=["ProcessBuilder", ".command(", "List.of", "Arrays.asList"],
                cwe_list=[78],
                effectiveness=0.82,
                false_positive_risk=0.08,
            )
        )
        self.register(
            SanitizerPattern(
                name="Input Validation",
                patterns=[
                    r"\.matches\s*\(",
                    r"\.startswith\s*\(",
                    r"\.endswith\s*\(",
                    r"\.contains\s*\(",
                ],
                keywords=["matches(", "startsWith", "endsWith", "contains("],
                cwe_list=[20],
                effectiveness=0.70,
                false_positive_risk=0.12,
            )
        )

        logger.info("Initialized Java sanitizer database with %s patterns", len(self.patterns))

    def register(self, pattern: SanitizerPattern) -> None:
        self.patterns[pattern.name] = pattern

    def detect_sanitizers(self, code_line: str) -> List[Tuple[SanitizerPattern, float]]:
        detected: List[Tuple[SanitizerPattern, float]] = []
        for pattern in self.patterns.values():
            if pattern.matches(code_line):
                confidence = max(0.05, 1.0 - pattern.false_positive_risk)
                detected.append((pattern, confidence))
        return detected


class SinkSpecificSanitizerValidator:
    """Validate sanitizer suitability for specific sinks."""

    SANITIZER_MAPPING = {
        "sql_injection": {
            "required": ["SQL Parameterization"],
            "acceptable": ["Input Validation"],
            "ineffective": ["HTML Entity Escaping", "URL Encoding"],
        },
        "xss": {
            "required": ["HTML Entity Escaping", "HTML Sanitization (Allowlist)"],
            "acceptable": ["Input Validation"],
            "ineffective": ["SQL Parameterization", "Path Normalization"],
        },
        "command_injection": {
            "required": ["Input Validation", "Command Argument List"],
            "acceptable": [],
            "ineffective": ["SQL Parameterization"],
        },
        "path_traversal": {
            "required": ["Path Normalization", "Input Validation"],
            "acceptable": [],
            "ineffective": [],
        },
        "ldap_injection": {
            "required": ["LDAP Escaping", "Input Validation"],
            "acceptable": [],
            "ineffective": [],
        },
        "xxe": {
            "required": ["XXE Hardening"],
            "acceptable": ["Input Validation"],
            "ineffective": [],
        },
        "http_response_splitting": {
            "required": ["URL Encoding", "Input Validation"],
            "acceptable": [],
            "ineffective": [],
        },
    }

    @staticmethod
    def validate_sanitizer_for_sink(sink_type: str, sanitizer_names: List[str]) -> Dict[str, object]:
        mapping = SinkSpecificSanitizerValidator.SANITIZER_MAPPING.get(sink_type, {})
        required = mapping.get("required", [])
        acceptable = mapping.get("acceptable", [])
        ineffective = mapping.get("ineffective", [])

        has_required = any(name in sanitizer_names for name in required)
        has_acceptable = any(name in sanitizer_names for name in acceptable)
        has_ineffective = any(name in sanitizer_names for name in ineffective)

        effectiveness_score = 0.0
        recommendation = "No appropriate sanitizers detected"
        if has_required:
            effectiveness_score = 0.95
            recommendation = "Appropriate sanitizers detected"
        elif has_acceptable:
            effectiveness_score = 0.60
            recommendation = "Weak sanitizers detected, consider stronger controls"

        if has_ineffective:
            effectiveness_score = max(0.0, effectiveness_score - 0.30)
            recommendation += " (ineffective sanitizers detected)"

        if CONFIG_AVAILABLE and PrecisionTuningConfig:
            best = 0.0
            for sanitizer in sanitizer_names:
                best = max(best, PrecisionTuningConfig.get_sanitizer_effectiveness(sink_type, sanitizer))
            if best > 0.0:
                effectiveness_score = best

        return {
            "sink_type": sink_type,
            "sanitizers_provided": sanitizer_names,
            "has_required": has_required,
            "has_acceptable": has_acceptable,
            "has_ineffective": has_ineffective,
            "effectiveness_score": effectiveness_score,
            "recommendation": recommendation,
        }


class JavaSanitizerAnalyzer:
    """Analyze sanitizer usage and placement across the file."""

    SINK_MARKERS = {
        "sql_injection": ["executequery(", "executeupdate(", "execute(", "preparestatement("],
        "command_injection": ["runtime.getruntime().exec", "runtime.exec", "processbuilder", ".start("],
        "path_traversal": ["new file(", "fileinputstream(", "filereader(", "files.read", "files.write", "paths.get("],
        "xss": ["getwriter()", "printwriter", "jspwriter", "response.getwriter"],
        "ldap_injection": ["dircontext", "ldap", "search(", "filter"],
        "xxe": ["documentbuilderfactory", "saxparser", "xmlreader", "inputsource"],
        "http_response_splitting": ["setheader(", "addheader(", "sendredirect(", "setstatus("],
    }

    def __init__(self, lines: List[str]) -> None:
        self.lines = lines
        self.database = JavaSanitizerDatabase()

    def analyze(self) -> Dict[str, object]:
        detected = []
        sink_lines = self._collect_sink_lines()

        for idx, line in enumerate(self.lines, 1):
            matches = self.database.detect_sanitizers(line)
            for pattern, confidence in matches:
                detected.append(
                    {
                        "name": pattern.name,
                        "line": idx,
                        "confidence": confidence,
                        "effectiveness": pattern.effectiveness,
                        "cwe_list": pattern.cwe_list,
                        "context": line.strip(),
                    }
                )

        by_sink: Dict[str, Dict[str, object]] = {}
        sink_sanitizer_hits: Dict[str, int] = {}
        effectiveness_by_sink: Dict[str, float] = {}
        placement_risk_by_sink: Dict[str, str] = {}

        for sink, markers in self.SINK_MARKERS.items():
            sanitizer_names = [item["name"] for item in detected]
            validation = SinkSpecificSanitizerValidator.validate_sanitizer_for_sink(sink, sanitizer_names)
            by_sink[sink] = validation
            sink_sanitizer_hits[sink] = len(sanitizer_names)
            effectiveness_by_sink[sink] = float(validation.get("effectiveness_score", 0.0))
            placement_risk_by_sink[sink] = self._estimate_placement_risk(sink, sink_lines, detected)

        if CONFIG_AVAILABLE and PrecisionTuningConfig:
            for sink, names in sink_sanitizer_hits.items():
                if names <= 0:
                    continue
                best = 0.0
                for sanitizer in [item["name"] for item in detected]:
                    best = max(best, PrecisionTuningConfig.get_sanitizer_effectiveness(sink, sanitizer))
                if best > 0.0:
                    effectiveness_by_sink[sink] = best

        return {
            "detected": detected,
            "by_sink": by_sink,
            "sink_sanitizer_hits": sink_sanitizer_hits,
            "effectiveness_by_sink": effectiveness_by_sink,
            "placement_risk_by_sink": placement_risk_by_sink,
            "bytecode_verification": {
                "enabled": False,
                "reason": "bytecode verification not configured",
            },
        }

    def _collect_sink_lines(self) -> Dict[str, List[int]]:
        sink_lines: Dict[str, List[int]] = {key: [] for key in self.SINK_MARKERS}
        for idx, line in enumerate(self.lines, 1):
            lower = line.lower()
            for sink, markers in self.SINK_MARKERS.items():
                if any(marker in lower for marker in markers):
                    sink_lines[sink].append(idx)
        return sink_lines

    def _estimate_placement_risk(
        self,
        sink: str,
        sink_lines: Dict[str, List[int]],
        detected: List[Dict[str, object]],
    ) -> str:
        if not sink_lines.get(sink):
            return "UNKNOWN"
        earliest_sink = min(sink_lines[sink])
        for sanitizer in detected:
            if sanitizer.get("line", 0) < earliest_sink:
                return "LOW"
        return "HIGH"
