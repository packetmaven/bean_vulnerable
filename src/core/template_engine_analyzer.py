"""
Template Engine Analyzer (Java)
===============================

Detects template engine auto-escaping configuration and safe/unsafe variants.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple
import logging
import re

logger = logging.getLogger(__name__)


class AutoEscapeMode(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"
    SELECTIVE = "selective"


@dataclass
class TemplateEngineConfig:
    engine_name: str
    language: str
    auto_escape: AutoEscapeMode
    default_encoding: str = "UTF-8"
    supports_context_aware_encoding: bool = False
    configuration_line: str = ""
    configuration_line_number: int = 0
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "engine": self.engine_name,
            "language": self.language,
            "auto_escape": self.auto_escape.value,
            "encoding": self.default_encoding,
            "context_aware": self.supports_context_aware_encoding,
            "confidence": self.confidence,
            "configuration_line": self.configuration_line,
            "configuration_line_number": self.configuration_line_number,
        }


class TemplateEngineAnalyzer:
    """Analyze template engine configurations and variants in Java code."""

    AUTOESCAPE_PATTERNS = {
        "Thymeleaf": {
            "enabled": [r"th:text="],
            "disabled": [r"th:utext="],
        },
        "FreeMarker": {
            "enabled": [
                r"setOutputFormat\s*\(\s*HTMLOutputFormat\.INSTANCE",
                r"setAutoEscapingPolicy\s*\(\s*Configuration\.ENABLE_IF_SUPPORTED",
            ],
            "disabled": [
                r"setOutputFormat\s*\(\s*PlainTextOutputFormat",
                r"setAutoEscapingPolicy\s*\(\s*Configuration\.DISABLE",
            ],
        },
        "Velocity": {
            "enabled": [
                r"EscapeTool",
                r"EscapeHtmlReference",
                r"eventhandler\.referenceinsertion\.class",
            ],
            "disabled": [r"Velocity\.evaluate\s*\(", r"mergeTemplate\s*\("],
        },
        "JSP": {
            "enabled": [r"<c:out\b(?![^>]*escapeXml\s*=\s*\"?false\"?)"],
            "disabled": [r"escapeXml\s*=\s*\"?false\"?", r"out\.print", r"JspWriter"],
        },
        "JSF": {
            "enabled": [r"<h:outputText\b(?![^>]*escape\s*=\s*\"?false\"?)"],
            "disabled": [r"escape\s*=\s*\"?false\"?"],
        },
    }

    ENGINE_USAGE_PATTERNS = {
        "Thymeleaf": [r"SpringTemplateEngine", r"TemplateEngine", r"th:text=", r"th:utext="],
        "FreeMarker": [r"freemarker", r"Configuration\s*\(", r"getTemplate\s*\(", r"\.process\s*\("],
        "Velocity": [r"VelocityEngine", r"Velocity\.evaluate\s*\(", r"mergeTemplate\s*\("],
        "JSP": [r"<%@\s*page", r"<c:out\b", r"JspWriter", r"pageContext\.getOut"],
        "JSF": [r"<h:outputText\b", r"FacesContext", r"UIComponent"],
    }

    def analyze(self, code: str) -> Dict[str, object]:
        engines = self._detect_engines(code)
        configs: List[TemplateEngineConfig] = []
        safe_variants: List[Dict[str, object]] = []
        unsafe_variants: List[Dict[str, object]] = []

        for engine in engines:
            config = self._analyze_autoescape_config(code, engine)
            configs.append(config)
            safe, unsafe = self._analyze_safe_variants(code, engine)
            safe_variants.extend(safe)
            unsafe_variants.extend(unsafe)

        autoescape = {
            "enabled": [c.engine_name for c in configs if c.auto_escape == AutoEscapeMode.ENABLED],
            "disabled": [c.engine_name for c in configs if c.auto_escape == AutoEscapeMode.DISABLED],
            "unknown": [c.engine_name for c in configs if c.auto_escape == AutoEscapeMode.UNKNOWN],
            "selective": [c.engine_name for c in configs if c.auto_escape == AutoEscapeMode.SELECTIVE],
        }

        safety_scores = {
            c.engine_name: self._compute_safety_score(
                c, self._count_engine_variants(safe_variants, c.engine_name),
                self._count_engine_variants(unsafe_variants, c.engine_name)
            )
            for c in configs
        }

        return {
            "engines": engines,
            "configs": [c.to_dict() for c in configs],
            "autoescape": autoescape,
            "safe_variants": safe_variants,
            "unsafe_variants": unsafe_variants,
            "safety_scores": safety_scores,
        }

    def _detect_engines(self, code: str) -> List[str]:
        detected = []
        for engine, patterns in self.ENGINE_USAGE_PATTERNS.items():
            if any(re.search(pattern, code) for pattern in patterns):
                detected.append(engine)
        return sorted(set(detected))

    def _analyze_autoescape_config(self, code: str, engine: str) -> TemplateEngineConfig:
        patterns = self.AUTOESCAPE_PATTERNS.get(engine, {})
        for pattern in patterns.get("enabled", []):
            match = re.search(pattern, code)
            if match:
                return TemplateEngineConfig(
                    engine_name=engine,
                    language="Java",
                    auto_escape=AutoEscapeMode.ENABLED,
                    configuration_line=match.group(0),
                    configuration_line_number=code[:match.start()].count("\n") + 1,
                    confidence=0.95,
                    supports_context_aware_encoding=True,
                )

        for pattern in patterns.get("disabled", []):
            match = re.search(pattern, code)
            if match:
                return TemplateEngineConfig(
                    engine_name=engine,
                    language="Java",
                    auto_escape=AutoEscapeMode.DISABLED,
                    configuration_line=match.group(0),
                    configuration_line_number=code[:match.start()].count("\n") + 1,
                    confidence=0.85,
                    supports_context_aware_encoding=True,
                )

        default_config = {
            "Thymeleaf": AutoEscapeMode.ENABLED,
            "FreeMarker": AutoEscapeMode.UNKNOWN,
            "Velocity": AutoEscapeMode.DISABLED,
            "JSP": AutoEscapeMode.SELECTIVE,
            "JSF": AutoEscapeMode.SELECTIVE,
        }
        return TemplateEngineConfig(
            engine_name=engine,
            language="Java",
            auto_escape=default_config.get(engine, AutoEscapeMode.UNKNOWN),
            confidence=0.60,
            supports_context_aware_encoding=True,
        )

    def _analyze_safe_variants(self, code: str, engine: str) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
        safe: List[Dict[str, object]] = []
        unsafe: List[Dict[str, object]] = []

        def _record(match: re.Match, is_safe: bool) -> None:
            item = {
                "engine": engine,
                "line": code[:match.start()].count("\n") + 1,
                "snippet": match.group(0),
                "safe": is_safe,
            }
            if is_safe:
                safe.append(item)
            else:
                unsafe.append(item)

        if engine == "Thymeleaf":
            for match in re.finditer(r"th:text=\"[^\"]*\"", code):
                _record(match, True)
            for match in re.finditer(r"th:utext=\"[^\"]*\"", code):
                _record(match, False)
        elif engine == "JSP":
            for match in re.finditer(r"<c:out[^>]*>", code):
                if re.search(r"escapeXml\s*=\s*\"?false\"?", match.group(0)):
                    _record(match, False)
                else:
                    _record(match, True)
        elif engine == "JSF":
            for match in re.finditer(r"<h:outputText[^>]*>", code):
                if re.search(r"escape\s*=\s*\"?false\"?", match.group(0)):
                    _record(match, False)
                else:
                    _record(match, True)
        elif engine == "FreeMarker":
            for match in re.finditer(r"\$\{[^}]+\}", code):
                if "|?html" in match.group(0).lower():
                    _record(match, True)
                else:
                    _record(match, False)
        elif engine == "Velocity":
            for match in re.finditer(r"#escape\([^)]*\)", code):
                _record(match, True)
            for match in re.finditer(r"\$\{[^}]+\}", code):
                _record(match, False)

        return safe, unsafe

    @staticmethod
    def _count_engine_variants(variants: List[Dict[str, object]], engine: str) -> int:
        return sum(1 for item in variants if item.get("engine") == engine)

    @staticmethod
    def _compute_safety_score(
        config: TemplateEngineConfig,
        safe_count: int,
        unsafe_count: int,
    ) -> float:
        score = 0.5
        if config.auto_escape == AutoEscapeMode.ENABLED:
            score = 0.85
        elif config.auto_escape == AutoEscapeMode.DISABLED:
            score = 0.30
        elif config.auto_escape == AutoEscapeMode.UNKNOWN:
            score = 0.50
        elif config.auto_escape == AutoEscapeMode.SELECTIVE:
            score = 0.60

        total = safe_count + unsafe_count
        if total > 0:
            safe_ratio = safe_count / total
            score = score * 0.7 + safe_ratio * 0.3
        return min(1.0, max(0.0, score))
