"""
Framework-Specific Sink Detection for Java
==========================================

Detects enterprise framework sinks and safe/unsafe variants in Java source.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import logging
import re

logger = logging.getLogger(__name__)


class Framework(Enum):
    """Supported Java frameworks/engines."""

    SPRING_MVC = "Spring MVC"
    SPRING_SECURITY = "Spring Security"
    JSP = "JSP"
    JSF = "JSF"
    THYMELEAF = "Thymeleaf"
    FREEMARKER = "FreeMarker"
    VELOCITY = "Velocity"


@dataclass
class FrameworkSink:
    """Framework sink metadata."""

    sink_name: str
    framework: Framework
    sink_type: str
    vuln_type: str
    cwe_id: int
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    is_safe_by_default: bool = False
    requires_escaping: bool = True
    execution_context: str = ""
    encoding_context: str = ""
    patterns: List[str] = field(default_factory=list)
    safe_patterns: List[str] = field(default_factory=list)
    unsafe_patterns: List[str] = field(default_factory=list)
    autoescape_enable_patterns: List[str] = field(default_factory=list)
    autoescape_disable_patterns: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class FrameworkSinkMatch:
    """Detected sink match."""

    sink_name: str
    framework: Framework
    sink_type: str
    vuln_type: str
    cwe_id: int
    line: int
    context: str
    is_safe_variant: Optional[bool]
    confidence: float
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "sink_name": self.sink_name,
            "framework": self.framework.value,
            "sink_type": self.sink_type,
            "vuln_type": self.vuln_type,
            "cwe_id": self.cwe_id,
            "line": self.line,
            "context": self.context,
            "safe_variant": self.is_safe_variant,
            "confidence": self.confidence,
            "notes": self.notes,
        }


class FrameworkSinkRegistry:
    """Registry and detection for framework-specific sinks."""

    def __init__(self) -> None:
        self.sinks: List[FrameworkSink] = []
        self._build_registry()

    def _build_registry(self) -> None:
        self._register_spring_mvc_sinks()
        self._register_spring_security_sinks()
        self._register_jsp_sinks()
        self._register_jsf_sinks()
        self._register_thymeleaf_sinks()
        self._register_freemarker_sinks()
        self._register_velocity_sinks()
        logger.info("Registered %s framework sinks", len(self.sinks))

    def _register_spring_mvc_sinks(self) -> None:
        self.sinks.extend(
            [
                FrameworkSink(
                    sink_name="Model.addAttribute",
                    framework=Framework.SPRING_MVC,
                    sink_type="HTML",
                    vuln_type="xss",
                    cwe_id=79,
                    class_name="org.springframework.ui.Model",
                    method_name="addAttribute",
                    is_safe_by_default=False,
                    requires_escaping=True,
                    execution_context="HTML",
                    patterns=[r"\.addAttribute\s*\("],
                    notes="View rendering depends on template engine auto-escaping.",
                ),
                FrameworkSink(
                    sink_name="ModelAndView.addObject",
                    framework=Framework.SPRING_MVC,
                    sink_type="HTML",
                    vuln_type="xss",
                    cwe_id=79,
                    class_name="org.springframework.web.servlet.ModelAndView",
                    method_name="addObject",
                    is_safe_by_default=False,
                    requires_escaping=True,
                    execution_context="HTML",
                    patterns=[r"ModelAndView\s*\(", r"\.addObject\s*\("],
                ),
                FrameworkSink(
                    sink_name="RedirectView.setUrl",
                    framework=Framework.SPRING_MVC,
                    sink_type="URL",
                    vuln_type="http_response_splitting",
                    cwe_id=601,
                    class_name="org.springframework.web.servlet.view.RedirectView",
                    method_name="setUrl",
                    is_safe_by_default=False,
                    requires_escaping=True,
                    execution_context="URL",
                    patterns=[r"RedirectView\s*\(", r"\.setUrl\s*\("],
                    notes="Validate redirect targets against allowlist.",
                ),
                FrameworkSink(
                    sink_name="JdbcTemplate.queryForObject",
                    framework=Framework.SPRING_MVC,
                    sink_type="SQL",
                    vuln_type="sql_injection",
                    cwe_id=89,
                    class_name="org.springframework.jdbc.core.JdbcTemplate",
                    method_name="queryForObject",
                    is_safe_by_default=False,
                    requires_escaping=False,
                    execution_context="SQL",
                    patterns=[
                        r"jdbcTemplate\.queryForObject\s*\(",
                        r"jdbcTemplate\.update\s*\(",
                        r"jdbcTemplate\.batchUpdate\s*\(",
                    ],
                    notes="Use parameterized queries.",
                ),
            ]
        )

    def _register_spring_security_sinks(self) -> None:
        self.sinks.append(
            FrameworkSink(
                sink_name="SecurityContextHolder.getContext",
                framework=Framework.SPRING_SECURITY,
                sink_type="HTML",
                vuln_type="xss",
                cwe_id=79,
                class_name="org.springframework.security.core.context.SecurityContextHolder",
                method_name="getContext",
                is_safe_by_default=False,
                requires_escaping=True,
                execution_context="HTML",
                patterns=[r"SecurityContextHolder\.getContext\s*\("],
                notes="Principal data must be escaped on output.",
            )
        )

    def _register_jsp_sinks(self) -> None:
        self.sinks.extend(
            [
                FrameworkSink(
                    sink_name="JSP c:out",
                    framework=Framework.JSP,
                    sink_type="HTML",
                    vuln_type="xss",
                    cwe_id=79,
                    is_safe_by_default=True,
                    requires_escaping=False,
                    execution_context="HTML",
                    encoding_context="HTML",
                    patterns=[r"<c:out\b"],
                    safe_patterns=[r'escapeXml\s*=\s*"?true"?', r"<c:out\b(?![^>]*escapeXml)"],
                    unsafe_patterns=[r'escapeXml\s*=\s*"?false"?'],
                    notes="Safe by default unless escapeXml=false.",
                ),
                FrameworkSink(
                    sink_name="JSP EL output",
                    framework=Framework.JSP,
                    sink_type="HTML",
                    vuln_type="xss",
                    cwe_id=79,
                    is_safe_by_default=False,
                    requires_escaping=True,
                    execution_context="HTML",
                    patterns=[r"\$\{param\.", r"\$\{requestScope\."],
                    notes="Prefer c:out for auto-escaping.",
                ),
                FrameworkSink(
                    sink_name="ELProcessor.eval",
                    framework=Framework.JSP,
                    sink_type="CODE_INJECTION",
                    vuln_type="el_injection",
                    cwe_id=94,
                    class_name="javax.el.ELProcessor",
                    method_name="eval",
                    is_safe_by_default=False,
                    requires_escaping=True,
                    execution_context="EL",
                    patterns=[
                        r"ELProcessor\s*\(",
                        r"\.eval\s*\(",
                        r"ExpressionFactory\.createValueExpression\s*\(",
                        r"ExpressionFactory\.createMethodExpression\s*\(",
                    ],
                    notes="Never evaluate untrusted EL expressions.",
                ),
            ]
        )

    def _register_jsf_sinks(self) -> None:
        self.sinks.append(
            FrameworkSink(
                sink_name="JSF h:outputText",
                framework=Framework.JSF,
                sink_type="HTML",
                vuln_type="xss",
                cwe_id=79,
                is_safe_by_default=True,
                requires_escaping=False,
                execution_context="HTML",
                patterns=[r"<h:outputText\b"],
                safe_patterns=[r'escape\s*=\s*"?true"?', r"<h:outputText\b(?![^>]*escape)"],
                unsafe_patterns=[r'escape\s*=\s*"?false"?'],
                notes="Safe by default unless escape=false.",
            )
        )

    def _register_thymeleaf_sinks(self) -> None:
        self.sinks.append(
            FrameworkSink(
                sink_name="Thymeleaf th:text/th:utext",
                framework=Framework.THYMELEAF,
                sink_type="HTML",
                vuln_type="xss",
                cwe_id=79,
                is_safe_by_default=True,
                requires_escaping=False,
                execution_context="HTML",
                encoding_context="HTML",
                patterns=[r"th:text\s*=", r"th:utext\s*="],
                safe_patterns=[r"th:text\s*="],
                unsafe_patterns=[r"th:utext\s*="],
                notes="th:text escapes, th:utext outputs raw HTML.",
            )
        )

    def _register_freemarker_sinks(self) -> None:
        self.sinks.append(
            FrameworkSink(
                sink_name="FreeMarker Template.process",
                framework=Framework.FREEMARKER,
                sink_type="HTML",
                vuln_type="xss",
                cwe_id=79,
                is_safe_by_default=False,
                requires_escaping=True,
                execution_context="HTML",
                patterns=[r"\.process\s*\(", r"getTemplate\s*\("],
                autoescape_enable_patterns=[
                    r"setOutputFormat\s*\(\s*HTMLOutputFormat\.INSTANCE",
                    r"setAutoEscapingPolicy",
                ],
                autoescape_disable_patterns=[r"setOutputFormat\s*\(\s*PlainTextOutputFormat"],
                notes="Escaping depends on output format configuration.",
            )
        )

    def _register_velocity_sinks(self) -> None:
        self.sinks.append(
            FrameworkSink(
                sink_name="VelocityEngine.evaluate/mergeTemplate",
                framework=Framework.VELOCITY,
                sink_type="HTML",
                vuln_type="xss",
                cwe_id=79,
                is_safe_by_default=False,
                requires_escaping=True,
                execution_context="HTML",
                patterns=[r"Velocity\.evaluate\s*\(", r"mergeTemplate\s*\(", r"velocityEngine\.evaluate\s*\("],
                safe_patterns=[r"#escape\b", r"EscapeTool"],
                notes="Velocity does not auto-escape; use #escape or EscapeTool.",
            )
        )

    def analyze_code(self, source_code: str) -> Dict[str, object]:
        lines = source_code.splitlines()
        matches: List[FrameworkSinkMatch] = []
        frameworks = set()

        hits_by_vuln: Dict[str, int] = {}
        safe_hits_by_vuln: Dict[str, int] = {}
        unsafe_hits_by_vuln: Dict[str, int] = {}
        autoescape_enabled: Dict[str, int] = {}
        autoescape_disabled: Dict[str, int] = {}

        for idx, line in enumerate(lines, 1):
            for sink in self.sinks:
                if not self._matches_any(line, sink.patterns):
                    continue

                is_safe_variant: Optional[bool] = None
                if sink.unsafe_patterns and self._matches_any(line, sink.unsafe_patterns):
                    is_safe_variant = False
                elif sink.safe_patterns and self._matches_any(line, sink.safe_patterns):
                    is_safe_variant = True
                elif sink.is_safe_by_default:
                    is_safe_variant = True

                confidence = 0.65
                if is_safe_variant is not None:
                    confidence += 0.10

                matches.append(
                    FrameworkSinkMatch(
                        sink_name=sink.sink_name,
                        framework=sink.framework,
                        sink_type=sink.sink_type,
                        vuln_type=sink.vuln_type,
                        cwe_id=sink.cwe_id,
                        line=idx,
                        context=line.strip(),
                        is_safe_variant=is_safe_variant,
                        confidence=confidence,
                        notes=sink.notes,
                    )
                )

                frameworks.add(sink.framework.value)
                hits_by_vuln[sink.vuln_type] = hits_by_vuln.get(sink.vuln_type, 0) + 1
                if is_safe_variant is True:
                    safe_hits_by_vuln[sink.vuln_type] = safe_hits_by_vuln.get(sink.vuln_type, 0) + 1
                if is_safe_variant is False:
                    unsafe_hits_by_vuln[sink.vuln_type] = unsafe_hits_by_vuln.get(sink.vuln_type, 0) + 1

        for sink in self.sinks:
            if sink.autoescape_enable_patterns and self._matches_any(source_code, sink.autoescape_enable_patterns):
                autoescape_enabled[sink.vuln_type] = autoescape_enabled.get(sink.vuln_type, 0) + 1
            if sink.autoescape_disable_patterns and self._matches_any(source_code, sink.autoescape_disable_patterns):
                autoescape_disabled[sink.vuln_type] = autoescape_disabled.get(sink.vuln_type, 0) + 1

        return {
            "frameworks": sorted(frameworks),
            "matches": [match.to_dict() for match in matches],
            "hits_by_vuln": hits_by_vuln,
            "safe_hits_by_vuln": safe_hits_by_vuln,
            "unsafe_hits_by_vuln": unsafe_hits_by_vuln,
            "autoescape_enabled": autoescape_enabled,
            "autoescape_disabled": autoescape_disabled,
        }

    @staticmethod
    def _matches_any(text: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        return False
