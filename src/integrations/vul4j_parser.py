from typing import Dict, List


class FixedVul4JParser:
    """Minimal stub parser used by the CLI for demo runs.

    Provides a small list of vulnerability IDs and basic metadata lookup.
    """

    def __init__(self) -> None:
        # Provide a tiny demo set; real implementation would parse a CSV/database
        self.available_vulnerabilities: List[str] = [
            "VUL4J-0001",
            "VUL4J-0002",
            "VUL4J-0003",
        ]

    def get_vulnerability_info(self, vul_id: str) -> Dict[str, str]:
        # Return minimal fields consumed by the CLI
        return {
            "cve_id": f"CVE-DEMO-{vul_id[-4:]}",
            "repo_slug": "demo/repo",
        }


