"""Blended analysis config generation from concrete traces (experimental)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Optional
import json


@dataclass(frozen=True)
class ProgramLocation:
    file: str
    line: int
    method: str

    def __str__(self) -> str:
        return f"{self.file}:{self.method}:{self.line}"


class BlendedAnalysisPoster:
    """Generate a blending configuration from concrete traces."""

    def __init__(self, concrete_traces_file: Path) -> None:
        self.concrete_traces = self._load_traces(concrete_traces_file)
        self.blend_locations: Set[ProgramLocation] = set()

    def _load_traces(self, trace_file: Path) -> Dict[str, Dict[str, List[str]]]:
        data = json.loads(trace_file.read_text(encoding="utf-8"))
        return data.get("locations", {})

    def enable_blending_at(self, location: ProgramLocation) -> None:
        self.blend_locations.add(location)

    def generate_config(self, output_path: Path) -> Path:
        config = {
            "analysis": "pta",
            "blended_locations": [
                {
                    "file": loc.file,
                    "line": loc.line,
                    "method": loc.method,
                    "concrete_values": self.concrete_traces.get(str(loc), {}).get("values", []),
                }
                for loc in sorted(self.blend_locations, key=str)
            ],
        }
        output_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return output_path
