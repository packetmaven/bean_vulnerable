"""Soundness validation comparing Tai-e points-to with runtime logs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
import json
import re

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:  # pragma: no cover
    yaml = None
    YAML_AVAILABLE = False

POINTER_RE = re.compile(r"<([^:>]+):")


@dataclass
class SoundnessReport:
    soundness_rate: float
    total_variables_checked: int
    unsound_variables: int
    unsoundness_cases: List[Dict[str, Any]]
    mapping_strategy: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "soundness_rate": self.soundness_rate,
            "total_variables_checked": self.total_variables_checked,
            "unsound_variables": self.unsound_variables,
            "unsoundness_cases": self.unsoundness_cases,
            "mapping_strategy": self.mapping_strategy,
        }


class SoundnessValidator:
    """Best-effort soundness validator using runtime logs and Tai-e points-to dump."""

    def __init__(self, points_to_file: Path, value_log_file: Path) -> None:
        self.points_to_file = points_to_file
        self.value_log_file = value_log_file
        self.dynamic_logs = self._load_value_logs(value_log_file)

    def validate_points_to_sets(self) -> SoundnessReport:
        dynamic_points = self._compute_dynamic_points()
        static_points = self._extract_static_points_to()

        unsound_cases: List[Dict[str, Any]] = []
        for key, entry in dynamic_points.items():
            dynamic_class = entry.get("class_name")
            static_objects = static_points.get(key)
            if static_objects is None:
                unsound_cases.append({
                    "type": "missing_variable",
                    "location": key,
                    "dynamic_class": dynamic_class,
                })
                continue
            if not dynamic_class:
                continue
            if not any(dynamic_class in obj for obj in static_objects):
                unsound_cases.append({
                    "type": "unsound_points_to",
                    "location": key,
                    "dynamic_class": dynamic_class,
                    "static_objects": list(static_objects),
                })

        total = len(dynamic_points)
        unsound = len(unsound_cases)
        soundness_rate = 1.0 - (unsound / total) if total else 1.0

        return SoundnessReport(
            soundness_rate=soundness_rate,
            total_variables_checked=total,
            unsound_variables=unsound,
            unsoundness_cases=unsound_cases,
            mapping_strategy="method+var (class-name match)",
        )

    def generate_html_report(self, output_path: Path) -> SoundnessReport:
        report = self.validate_points_to_sets()
        output_path.write_text(self._render_html(report), encoding="utf-8")
        return report

    def _load_value_logs(self, log_file: Path) -> List[Dict[str, Any]]:
        if not log_file.exists():
            return []
        data = json.loads(log_file.read_text(encoding="utf-8"))
        return data.get("value_logs", [])

    def _compute_dynamic_points(self) -> Dict[str, Dict[str, Optional[str]]]:
        points = {}
        for entry in self.dynamic_logs:
            location = entry.get("location", "unknown")
            var_name = entry.get("var", "unknown")
            if var_name == "__soundness__":
                continue
            value = entry.get("value", "")
            class_name = None
            if isinstance(value, str) and "@" in value:
                class_name = value.split("@", 1)[0]
            method_key = location.split(":", 1)[0]
            key = f"{method_key}:{var_name}"
            points[key] = {"class_name": class_name, "value": value}
        return points

    def _extract_static_points_to(self) -> Dict[str, Set[str]]:
        if not self.points_to_file.exists():
            return {}
        text = self.points_to_file.read_text(encoding="utf-8", errors="ignore")
        if YAML_AVAILABLE:
            try:
                payload = yaml.safe_load(text)
                return self._walk_payload_for_points(payload)
            except Exception:
                pass
        return self._parse_points_to_text(text)

    def _walk_payload_for_points(self, payload: Any) -> Dict[str, Set[str]]:
        results: Dict[str, Set[str]] = {}
        if not isinstance(payload, dict):
            return results
        variables = payload.get("variables", {})
        if not isinstance(variables, dict):
            return results
        for method_sig, entries in variables.items():
            if not isinstance(entries, list):
                continue
            method_key = self._normalize_method_signature(method_sig)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                var_name = entry.get("var")
                if not var_name:
                    continue
                objects: Set[str] = set()
                for pts_entry in entry.get("pts", []) or []:
                    if isinstance(pts_entry, dict):
                        for obj in pts_entry.get("objects", []) or []:
                            objects.add(str(obj))
                results[f"{method_key}:{var_name}"] = objects
        return results

    def _parse_points_to_text(self, text: str) -> Dict[str, Set[str]]:
        results: Dict[str, Set[str]] = {}
        current_method = None
        current_var = None
        for line in text.splitlines():
            method_match = re.match(r"^\s*'?(<[^>]+>)'?:\s*$", line)
            if method_match:
                current_method = self._normalize_method_signature(method_match.group(1))
                current_var = None
                continue
            var_match = re.match(r"^\s*-\s+var:\s+\"?([^\"\\n]+)\"?", line)
            if var_match and current_method:
                current_var = var_match.group(1).strip()
                results[f"{current_method}:{current_var}"] = set()
                continue
            obj_match = re.match(r"^\s*-\s+\"(.+)\"$", line)
            if obj_match and current_method and current_var:
                results[f"{current_method}:{current_var}"].add(obj_match.group(1))
        return results

    def _normalize_method_signature(self, signature: str) -> str:
        match = re.match(r"<([^:>]+):\s+[^\s]+\s+([^\(]+)\(", signature)
        if match:
            return f"{match.group(1)}.{match.group(2)}"
        return signature.strip("<>")

    def _render_html(self, report: SoundnessReport) -> str:
        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Tai-e Soundness Validation</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    .summary {{ background: #f4f4f4; padding: 12px; border-radius: 6px; }}
    .case {{ border-left: 3px solid #e74c3c; padding: 8px; margin: 8px 0; background: #fff7f7; }}
  </style>
</head>
<body>
  <h1>Soundness Validation Report</h1>
  <div class="summary">
    <p><strong>Soundness rate:</strong> {report.soundness_rate:.2%}</p>
    <p><strong>Total variables checked:</strong> {report.total_variables_checked}</p>
    <p><strong>Unsound cases:</strong> {report.unsound_variables}</p>
    <p><strong>Mapping strategy:</strong> {report.mapping_strategy}</p>
  </div>
  <h2>Unsoundness Cases</h2>
  {"".join(f'<div class="case">{case}</div>' for case in report.unsoundness_cases) if report.unsoundness_cases else "<p>None detected.</p>"}
</body>
</html>
"""
