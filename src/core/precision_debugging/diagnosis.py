"""Heuristic precision diagnosis for Tai-e timeouts or failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
import re


@dataclass
class PrecisionDiagnosis:
    summary: Dict[str, int]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {"summary": self.summary, "recommendations": self.recommendations}


def analyze_source(source_code: str) -> PrecisionDiagnosis:
    summary = {
        "string_concat": len(re.findall(r'".*"\s*\+', source_code)),
        "collection_ops": len(re.findall(r'\b(List|Map|Set|ArrayList|HashMap)\b', source_code)),
        "reflection_calls": len(re.findall(r'\bClass\.forName\b|\bMethod\.invoke\b', source_code)),
        "loops": len(re.findall(r'\bfor\b|\bwhile\b', source_code)),
    }

    recommendations: List[str] = []
    if summary["string_concat"] > 5:
        recommendations.append(
            "High string concatenation count; consider merging string objects in Tai-e."
        )
    if summary["collection_ops"] > 10:
        recommendations.append(
            "Heavy collection usage; consider reducing context sensitivity or using summaries."
        )
    if summary["reflection_calls"] > 0:
        recommendations.append(
            "Reflection detected; enable reflection-inference for Tai-e if available."
        )
    if not recommendations:
        recommendations.append(
            "No dominant bottlenecks detected; consider reducing context sensitivity (1-obj or ci)."
        )

    return PrecisionDiagnosis(summary=summary, recommendations=recommendations)
