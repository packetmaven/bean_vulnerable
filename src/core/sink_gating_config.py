"""
Configuration and Tuning for Sink-Specific Gating
=================================================

Source of truth for sink thresholds, sanitizer effectiveness, and evidence weights.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, Optional


class PrecisionTuningConfig:
    """
    Master configuration for precision tuning.
    """

    SINK_NAME_ALIASES = {
        "SQL_QUERY": "sql_injection",
        "HTML_OUTPUT": "xss",
        "COMMAND_EXEC": "command_injection",
        "PATH_TRAVERSAL": "path_traversal",
        "URL_REDIRECT": "url_redirect",
        "FILE_OPERATION": "file_operation",
        "XPATH_QUERY": "xpath_injection",
        "LDAP_QUERY": "ldap_injection",
        "XXE": "xxe",
        "HTTP_RESPONSE_SPLITTING": "http_response_splitting",
        "EL_INJECTION": "el_injection",
    }

    SANITIZER_NAME_ALIASES = {
        "HTML Entity Escaping": "HTML_ESCAPING",
        "HTML Sanitization (Allowlist)": "BLEACH_SANITIZATION",
        "URL Encoding": "URL_ENCODING",
        "SQL Parameterization": "SQL_PARAMETERIZATION",
        "Path Normalization": "PATH_NORMALIZATION",
        "Input Validation": "INPUT_VALIDATION",
        "Regular Expression Validation": "REGEX_VALIDATION",
        "Command Argument List": "ARGS_LIST",
        "LDAP Escaping": "LDAP_ESCAPE",
        "XXE Hardening": "XXE_HARDENING",
    }

    # SINK-SPECIFIC GATING THRESHOLDS
    SINK_GATING_THRESHOLDS = {
        "SQL_QUERY": {
            "cwe": 89,
            "base_threshold": 0.75,
            "direct_flow_threshold": 0.65,
            "indirect_flow_threshold": 0.80,
            "description": "SQL Injection - CWE-89",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.20,
            "fn_penalty": 0.05,
            "enforcement": "STRICT",
            "notes": "Highest precision requirement - parameterization non-negotiable",
        },
        "HTML_OUTPUT": {
            "cwe": 79,
            "base_threshold": 0.70,
            "direct_flow_threshold": 0.60,
            "indirect_flow_threshold": 0.75,
            "description": "Cross-Site Scripting (XSS) - CWE-79",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.18,
            "fn_penalty": 0.08,
            "enforcement": "STRICT",
            "notes": "Context-aware encoding required",
        },
        "COMMAND_EXEC": {
            "cwe": 78,
            "base_threshold": 0.80,
            "direct_flow_threshold": 0.70,
            "indirect_flow_threshold": 0.85,
            "description": "OS Command Injection - CWE-78",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.25,
            "fn_penalty": 0.02,
            "enforcement": "STRICTEST",
            "notes": "shell=False and args list required",
        },
        "PATH_TRAVERSAL": {
            "cwe": 22,
            "base_threshold": 0.72,
            "direct_flow_threshold": 0.62,
            "indirect_flow_threshold": 0.78,
            "description": "Path Traversal - CWE-22",
            "required_evidence": ["DIRECT_TAINT_PATH", "DANGEROUS_PATTERN"],
            "min_evidence_count": 2,
            "fp_penalty": 0.17,
            "fn_penalty": 0.07,
            "enforcement": "STRICT",
            "notes": "realpath/abspath normalization required",
        },
        "URL_REDIRECT": {
            "cwe": 601,
            "base_threshold": 0.65,
            "direct_flow_threshold": 0.55,
            "indirect_flow_threshold": 0.70,
            "description": "URL Redirection - CWE-601",
            "required_evidence": ["DIRECT_TAINT_PATH"],
            "min_evidence_count": 1,
            "fp_penalty": 0.15,
            "fn_penalty": 0.10,
            "enforcement": "MODERATE",
            "notes": "Whitelist validation strongly recommended",
        },
        "FILE_OPERATION": {
            "cwe": 434,
            "base_threshold": 0.60,
            "direct_flow_threshold": 0.50,
            "indirect_flow_threshold": 0.68,
            "description": "Unrestricted Upload - CWE-434",
            "required_evidence": ["DIRECT_TAINT_PATH"],
            "min_evidence_count": 1,
            "fp_penalty": 0.12,
            "fn_penalty": 0.12,
            "enforcement": "MODERATE",
            "notes": "File type validation and path normalization",
        },
        "XPATH_QUERY": {
            "cwe": 643,
            "base_threshold": 0.70,
            "direct_flow_threshold": 0.60,
            "indirect_flow_threshold": 0.75,
            "description": "XPath Injection - CWE-643",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.16,
            "fn_penalty": 0.08,
            "enforcement": "STRICT",
            "notes": "Similar to SQL injection risks",
        },
        "LDAP_QUERY": {
            "cwe": 90,
            "base_threshold": 0.70,
            "direct_flow_threshold": 0.60,
            "indirect_flow_threshold": 0.75,
            "description": "LDAP Injection - CWE-90",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.16,
            "fn_penalty": 0.08,
            "enforcement": "STRICT",
            "notes": "Similar to SQL injection risks",
        },
        "XXE": {
            "cwe": 611,
            "base_threshold": 0.70,
            "direct_flow_threshold": 0.60,
            "indirect_flow_threshold": 0.75,
            "description": "XML External Entity - CWE-611",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.16,
            "fn_penalty": 0.08,
            "enforcement": "STRICT",
            "notes": "Secure processing features required",
        },
        "HTTP_RESPONSE_SPLITTING": {
            "cwe": 113,
            "base_threshold": 0.70,
            "direct_flow_threshold": 0.60,
            "indirect_flow_threshold": 0.75,
            "description": "HTTP Response Splitting - CWE-113",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER"],
            "min_evidence_count": 2,
            "fp_penalty": 0.16,
            "fn_penalty": 0.08,
            "enforcement": "STRICT",
            "notes": "Header encoding required",
        },
        "EL_INJECTION": {
            "cwe": 94,
            "base_threshold": 0.78,
            "direct_flow_threshold": 0.68,
            "indirect_flow_threshold": 0.82,
            "description": "Expression Language Injection - CWE-94",
            "required_evidence": ["DIRECT_TAINT_PATH", "NO_SANITIZER", "DANGEROUS_PATTERN"],
            "min_evidence_count": 2,
            "fp_penalty": 0.20,
            "fn_penalty": 0.05,
            "enforcement": "STRICT",
            "notes": "User-controlled EL expressions require strict gating",
        },
    }

    # SANITIZER EFFECTIVENESS SCORES
    SANITIZER_EFFECTIVENESS = {
        ("SQL_QUERY", "SQL_PARAMETERIZATION"): 0.98,
        ("SQL_QUERY", "INPUT_VALIDATION"): 0.65,
        ("SQL_QUERY", "CONTEXT_AWARE_ENCODING"): 0.40,
        ("HTML_OUTPUT", "HTML_ESCAPING"): 0.95,
        ("HTML_OUTPUT", "CONTEXT_AWARE_ENCODING"): 0.93,
        ("HTML_OUTPUT", "INPUT_VALIDATION"): 0.60,
        ("HTML_OUTPUT", "BLEACH_SANITIZATION"): 0.94,
        ("URL_REDIRECT", "INPUT_VALIDATION"): 0.88,
        ("URL_REDIRECT", "URL_ENCODING"): 0.70,
        ("URL_REDIRECT", "REGEX_VALIDATION"): 0.80,
        ("COMMAND_EXEC", "INPUT_VALIDATION"): 0.80,
        ("COMMAND_EXEC", "TYPE_SAFE_LANGUAGE_FEATURE"): 0.85,
        ("COMMAND_EXEC", "ARGS_LIST"): 0.92,
        ("PATH_TRAVERSAL", "PATH_NORMALIZATION"): 0.96,
        ("PATH_TRAVERSAL", "INPUT_VALIDATION"): 0.75,
        ("PATH_TRAVERSAL", "REGEX_VALIDATION"): 0.70,
        ("XPATH_QUERY", "INPUT_VALIDATION"): 0.80,
        ("XPATH_QUERY", "XPATH_ESCAPE"): 0.93,
        ("LDAP_QUERY", "INPUT_VALIDATION"): 0.85,
        ("LDAP_QUERY", "LDAP_ESCAPE"): 0.94,
        ("JSON_OUTPUT", "CONTEXT_AWARE_ENCODING"): 0.90,
        ("JSON_OUTPUT", "JSON_DUMPS"): 0.88,
        ("XXE", "XXE_HARDENING"): 0.90,
        ("HTTP_RESPONSE_SPLITTING", "URL_ENCODING"): 0.85,
    }

    # EVIDENCE WEIGHTING
    EVIDENCE_WEIGHTS = {
        "DIRECT_TAINT_PATH": {
            "default_weight": 0.25,
            "by_sink": {
                "SQL_QUERY": 0.30,
                "HTML_OUTPUT": 0.25,
                "COMMAND_EXEC": 0.35,
                "PATH_TRAVERSAL": 0.28,
            },
        },
        "INDIRECT_TAINT_PATH": {
            "default_weight": 0.15,
            "by_sink": {},
        },
        "NO_SANITIZER": {
            "default_weight": 0.20,
            "by_sink": {
                "SQL_QUERY": 0.25,
                "HTML_OUTPUT": 0.22,
                "COMMAND_EXEC": 0.25,
                "PATH_TRAVERSAL": 0.20,
            },
        },
        "INEFFECTIVE_SANITIZER": {
            "default_weight": 0.15,
            "by_sink": {},
        },
        "DANGEROUS_PATTERN": {
            "default_weight": 0.15,
            "by_sink": {
                "PATH_TRAVERSAL": 0.20,
                "SQL_QUERY": 0.12,
            },
        },
        "WEAK_VALIDATION": {
            "default_weight": 0.10,
            "by_sink": {},
        },
        "MULTIPLE_PATHS": {
            "default_weight": 0.10,
            "by_sink": {},
        },
    }

    # FALSE POSITIVE / FALSE NEGATIVE TUNING
    FP_FN_TUNING = {
        "strategy": "balanced",
        "description": "Balance between false positives and false negatives",
        "presets": {
            "conservative": {
                "target_fp_rate": 0.01,
                "target_fn_rate": 0.20,
                "use_case": "Low noise, high confidence required",
            },
            "balanced": {
                "target_fp_rate": 0.05,
                "target_fn_rate": 0.10,
                "use_case": "Default production setting",
            },
            "sensitive": {
                "target_fp_rate": 0.15,
                "target_fn_rate": 0.02,
                "use_case": "High sensitivity, accept more manual review",
            },
        },
    }

    # CONFIDENCE CALIBRATION
    CONFIDENCE_CALIBRATION = {
        "temperature": 1.0,
        "direct_flow_boost": 1.05,
        "indirect_flow_penalty": 0.95,
        "multiple_path_multiplier": 1.10,
        "dangerous_pattern_multiplier": 1.08,
        "weak_validation_penalty": 0.85,
    }

    @classmethod
    def normalize_sink_name(cls, sink_name: str) -> str:
        if sink_name in cls.SINK_NAME_ALIASES:
            return cls.SINK_NAME_ALIASES[sink_name]
        if sink_name.lower() in cls.SINK_NAME_ALIASES.values():
            return sink_name.lower()
        return sink_name.lower()

    @classmethod
    def config_sink_name(cls, sink_name: str) -> str:
        for config_name, internal in cls.SINK_NAME_ALIASES.items():
            if internal == sink_name:
                return config_name
        return sink_name.upper()

    @classmethod
    def normalize_sanitizer_name(cls, sanitizer_name: str) -> str:
        return cls.SANITIZER_NAME_ALIASES.get(sanitizer_name, sanitizer_name.upper())

    @classmethod
    def get_sink_config(cls, sink_name: str) -> Dict[str, Any]:
        config_key = cls.config_sink_name(cls.normalize_sink_name(sink_name))
        return cls.SINK_GATING_THRESHOLDS.get(config_key, {})

    @classmethod
    def get_sanitizer_effectiveness(cls, sink_type: str, sanitizer_type: str) -> float:
        config_sink = cls.config_sink_name(cls.normalize_sink_name(sink_type))
        sanitizer_key = cls.normalize_sanitizer_name(sanitizer_type)
        return cls.SANITIZER_EFFECTIVENESS.get((config_sink, sanitizer_key), 0.0)

    @classmethod
    def export_config(cls) -> Dict[str, Any]:
        return {
            "sinks": cls.SINK_GATING_THRESHOLDS,
            "sanitizer_effectiveness": {
                f"{sink}::{sanitizer}": score
                for (sink, sanitizer), score in cls.SANITIZER_EFFECTIVENESS.items()
            },
            "evidence_weights": cls.EVIDENCE_WEIGHTS,
            "fp_fn_tuning": cls.FP_FN_TUNING,
            "confidence_calibration": cls.CONFIDENCE_CALIBRATION,
        }

    @classmethod
    def save_to_json(cls, output_path: str) -> None:
        config = cls.export_config()
        Path(output_path).write_text(json.dumps(config, indent=2), encoding="utf-8")

    @classmethod
    def load_from_json(cls, config_path: str) -> Dict[str, Any]:
        return json.loads(Path(config_path).read_text(encoding="utf-8"))

    @classmethod
    def load_effectiveness_from_json(cls, config: Dict[str, Any]) -> Dict[tuple, float]:
        output: Dict[tuple, float] = {}
        raw = config.get("sanitizer_effectiveness", {})
        if not isinstance(raw, dict):
            return output
        for key, value in raw.items():
            if not isinstance(key, str):
                continue
            if "::" not in key:
                continue
            sink, sanitizer = key.split("::", 1)
            try:
                output[(sink, sanitizer)] = float(value)
            except Exception:
                continue
        return output
