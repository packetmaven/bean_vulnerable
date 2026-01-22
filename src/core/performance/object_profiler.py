"""Object-centric memory profiling helpers (best-effort)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import csv
import logging

logger = logging.getLogger(__name__)


@dataclass
class ObjectProfile:
    allocation_site: str
    class_name: str
    count: int
    total_size_bytes: int
    retention_path: List[str]
    cache_misses: int


class ObjectCentricProfiler:
    def __init__(self, snapshot_or_csv: Path) -> None:
        self.snapshot = snapshot_or_csv
        self.object_profiles: List[ObjectProfile] = []

    def analyze_object_retention(self) -> Tuple[List[ObjectProfile], List[Dict[str, str]]]:
        if not self.snapshot.exists():
            raise FileNotFoundError(str(self.snapshot))

        csv_path = self._resolve_csv_path()
        if not csv_path:
            return [], [{"type": "missing_csv", "description": "No CSV export provided"}]

        self.object_profiles = self._parse_retained_memory(csv_path)
        return self.object_profiles, self._identify_optimization_opportunities()

    def _resolve_csv_path(self) -> Optional[Path]:
        if self.snapshot.suffix.lower() == ".csv":
            return self.snapshot
        return None

    def _parse_retained_memory(self, csv_file: Path) -> List[ObjectProfile]:
        profiles: List[ObjectProfile] = []
        with csv_file.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                class_name = (
                    row.get("Class")
                    or row.get("Class Name")
                    or row.get("Class name")
                    or row.get("class")
                    or ""
                )
                count = self._parse_int(row.get("Count") or row.get("Objects") or row.get("count"))
                size = self._parse_int(
                    row.get("Retained Size")
                    or row.get("Retained Heap")
                    or row.get("Retained Size (bytes)")
                    or row.get("Retained")
                    or row.get("Size")
                    or row.get("Shallow Heap")
                )
                profiles.append(
                    ObjectProfile(
                        allocation_site=row.get("Allocation Site", ""),
                        class_name=class_name,
                        count=count,
                        total_size_bytes=size,
                        retention_path=[],
                        cache_misses=0,
                    )
                )
        return profiles

    def _parse_int(self, value: Optional[str]) -> int:
        if value is None:
            return 0
        text = str(value).strip().replace(",", "")
        if not text:
            return 0
        try:
            return int(float(text))
        except Exception:
            return 0

    def _identify_optimization_opportunities(self) -> List[Dict[str, str]]:
        opportunities: List[Dict[str, str]] = []
        string_objects = [p for p in self.object_profiles if "String" in p.class_name]
        if len(string_objects) > 1000:
            total = sum(p.total_size_bytes for p in string_objects)
            opportunities.append({
                "type": "excessive_strings",
                "description": f"{len(string_objects)} String objects consuming {total / 1024 / 1024:.1f} MB",
                "recommendation": "Consider enabling merge-string-objects in Tai-e config",
            })

        collections = [
            p for p in self.object_profiles
            if any(token in p.class_name for token in ["ArrayList", "HashMap", "HashSet"])
        ]
        if collections:
            opportunities.append({
                "type": "collection_overhead",
                "description": f"{len(collections)} collection objects detected",
                "recommendation": "Consider reducing context depth for collection-heavy code",
            })

        return opportunities

    def generate_optimization_report(self, output_path: Path) -> Dict[str, object]:
        profiles, opportunities = self.analyze_object_retention()
        report = {
            "total_objects_profiled": len(profiles),
            "total_memory_mb": sum(p.total_size_bytes for p in profiles) / 1024 / 1024,
            "optimization_opportunities": opportunities,
        }
        output_path.write_text(self._generate_html_report(report), encoding="utf-8")
        return report

    def _generate_html_report(self, report: Dict[str, object]) -> str:
        return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Memory Optimization Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    .opportunity {{ margin: 12px 0; padding: 12px; border-left: 4px solid #ff9800; background: #fff3e0; }}
  </style>
</head>
<body>
  <h1>Memory Optimization Report</h1>
  <p><strong>Total Objects:</strong> {report['total_objects_profiled']}</p>
  <p><strong>Total Memory:</strong> {report['total_memory_mb']:.1f} MB</p>
  <p><strong>Opportunities:</strong> {len(report['optimization_opportunities'])}</p>
  <h2>Optimization Opportunities</h2>
  {self._render_opportunities(report['optimization_opportunities'])}
</body>
</html>
"""

    def _render_opportunities(self, opportunities: List[Dict[str, str]]) -> str:
        if not opportunities:
            return "<p>No opportunities detected.</p>"
        rows = []
        for idx, opp in enumerate(opportunities, 1):
            rows.append(
                f"<div class='opportunity'><h3>{idx}. {opp['type']}</h3>"
                f"<p>{opp['description']}</p>"
                f"<p><strong>Recommendation:</strong> {opp['recommendation']}</p></div>"
            )
        return "\n".join(rows)
