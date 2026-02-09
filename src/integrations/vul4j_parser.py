from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# NOTE:
# This module intentionally has **no** heavy dependencies (no pandas, no GitPython).
# It is used by the CLI to display dataset metadata and by training data-prep code
# to map Vul4J metadata into Bean Vulnerable's 24-type taxonomy.


# ---------------------------------------------------------------------------
# Vul4J record model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Vul4JRecord:
    vul_id: str
    cve_id: str
    cwe_id: str
    cwe_name: str
    repo_slug: str
    human_patch: str
    build_system: str = ""
    compliance_level: str = ""
    failing_tests: str = ""
    compile_cmd: str = ""
    test_all_cmd: str = ""
    test_cmd: str = ""
    cmd_options: str = ""
    failing_module: str = ""
    src: str = ""
    test: str = ""
    warning: str = ""


def _repo_root() -> Path:
    # /.../src/integrations/vul4j_parser.py -> repo root is parents[2]
    return Path(__file__).resolve().parents[2]


def default_vul4j_csv_path() -> Path:
    return _repo_root() / "tests" / "vul4j" / "dataset" / "vul4j_dataset.csv"


def normalize_cwe_id(cwe_id: str) -> Optional[int]:
    """
    Normalize CWE IDs like 'CWE-611' / '611' -> 611.
    Returns None when missing/unparseable (e.g. 'Not Mapping').
    """
    if not cwe_id:
        return None
    s = str(cwe_id).strip()
    if not s or s.lower() in {"none", "not mapping", "not_mapping", "n/a"}:
        return None
    m = re.search(r"(\d+)", s)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


_CWE_TO_BEAN_TYPE: Dict[int, str] = {
    # High-signal, common security CWEs
    22: "PATH_TRAVERSAL",
    78: "COMMAND_INJECTION",
    79: "XSS",
    89: "SQL_INJECTION",
    502: "DESERIALIZATION",
    611: "XXE",
    643: "XPATH_INJECTION",
    90: "LDAP_INJECTION",
    327: "WEAK_CRYPTO",
    321: "HARDCODED_CREDENTIALS",  # hard-coded crypto key
    338: "INSECURE_RANDOM",
    330: "INSECURE_RANDOM",  # use of insufficiently random values
    476: "NULL_DEREFERENCE",
    772: "RESOURCE_LEAK",
    # Broad-but-usable bucket for “input validation / access control”
    20: "TRUST_BOUNDARY_VIOLATION",
    264: "TRUST_BOUNDARY_VIOLATION",  # deprecated category; still used in older CVEs
}


def parse_human_patch_commit_hash(human_patch: str) -> Optional[str]:
    """
    Extract the git commit hash from Vul4J's `human_patch` column.

    Examples:
      - 'https://github.com/apache/xmlgraphics-batik/commit/<hash>' -> <hash>
      - '<hash1>..<hash2>' -> <hash2> (Vul4J convention)
    """
    if not human_patch:
        return None
    s = str(human_patch).strip()
    if not s:
        return None
    last = s.rstrip("/").split("/")[-1]
    if ".." in last:
        last = last.split("..")[-1].strip()
    # Defensive: allow 7+ hex chars (short hashes) up to full 40
    if re.fullmatch(r"[0-9a-fA-F]{7,40}", last):
        return last
    return None


def map_vul4j_to_bean_vuln_type(
    *,
    cwe_id: str,
    cwe_name: str,
    repo_slug: str = "",
    cve_id: str = "",
) -> Optional[str]:
    """
    Map Vul4J metadata into Bean Vulnerable's 24-type taxonomy.

    Returns a canonical Bean vuln type name like 'XXE' or 'SQL_INJECTION',
    or None if the record can't be mapped confidently.
    """
    name = (cwe_name or "").strip().lower()
    slug = (repo_slug or "").strip().lower()

    # Repo-specific high-confidence mapping (kept minimal).
    # Some Vul4J rows use coarse CWEs like CWE-20; override those when the repo is known.
    if "fastjson" in slug:
        # Fastjson CVEs are overwhelmingly deserialization-related in practice.
        return "DESERIALIZATION"

    # CWE numeric mapping wins when present
    cwe_num = normalize_cwe_id(cwe_id)
    if cwe_num is not None and cwe_num in _CWE_TO_BEAN_TYPE:
        return _CWE_TO_BEAN_TYPE[cwe_num]

    # Heuristics for common “Not Mapping” entries / coarse CWEs
    if "xxe" in name or "xml external entity" in name:
        return "XXE"
    if "path traversal" in name or "pathname" in name:
        return "PATH_TRAVERSAL"
    if "sql injection" in name:
        return "SQL_INJECTION"
    if "command injection" in name or "os command" in name:
        return "COMMAND_INJECTION"
    if "cross-site scripting" in name or "xss" in name:
        return "XSS"
    if "deserial" in name:
        return "DESERIALIZATION"
    if "ldap" in name:
        return "LDAP_INJECTION"
    if "xpath" in name:
        return "XPATH_INJECTION"
    if "ssrf" in name or "server-side request" in name:
        return "SSRF"
    if "hard-coded" in name and ("key" in name or "credential" in name or "password" in name):
        return "HARDCODED_CREDENTIALS"
    if "crypt" in name and ("weak" in name or "broken" in name or "insufficient" in name):
        return "WEAK_CRYPTO"
    if "random" in name and ("insufficient" in name or "predictable" in name or "weak" in name):
        return "INSECURE_RANDOM"
    if "null pointer" in name or "null dereference" in name:
        return "NULL_DEREFERENCE"
    if "resource leak" in name:
        return "RESOURCE_LEAK"

    _ = cve_id  # reserved for future CVE-specific mapping
    return None


# ---------------------------------------------------------------------------
# CSV-backed dataset loader (lightweight)
# ---------------------------------------------------------------------------


class Vul4JDataset:
    def __init__(self, csv_path: Path):
        self.csv_path = Path(csv_path)
        self._records: Dict[str, Vul4JRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Vul4J CSV not found: {self.csv_path}")
        with self.csv_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                vul_id = (row.get("vul_id") or "").strip()
                if not vul_id:
                    continue
                rec = Vul4JRecord(
                    vul_id=vul_id,
                    cve_id=(row.get("cve_id") or "").strip(),
                    cwe_id=(row.get("cwe_id") or "").strip(),
                    cwe_name=(row.get("cwe_name") or "").strip(),
                    repo_slug=(row.get("repo_slug") or "").strip(),
                    human_patch=(row.get("human_patch") or "").strip(),
                    build_system=(row.get("build_system") or "").strip(),
                    compliance_level=(row.get("compliance_level") or "").strip(),
                    failing_tests=(row.get("failing_tests") or "").strip(),
                    compile_cmd=(row.get("compile_cmd") or "").strip(),
                    test_all_cmd=(row.get("test_all_cmd") or "").strip(),
                    test_cmd=(row.get("test_cmd") or "").strip(),
                    cmd_options=(row.get("cmd_options") or "").strip(),
                    failing_module=(row.get("failing_module") or "").strip(),
                    src=(row.get("src") or "").strip(),
                    test=(row.get("test") or "").strip(),
                    warning=(row.get("warning") or "").strip(),
                )
                self._records[vul_id] = rec

    @staticmethod
    def _sort_key(vul_id: str):
        m = re.search(r"(\d+)$", vul_id)
        # Python 3 cannot compare `int` and `str` during sorting.
        # Return a uniform tuple key so all items are comparable.
        if m:
            return (0, int(m.group(1)))
        return (1, vul_id)

    def iter_records(self) -> Iterable[Vul4JRecord]:
        for vul_id in sorted(self._records.keys(), key=self._sort_key):
            yield self._records[vul_id]

    @property
    def available_vulnerabilities(self) -> List[str]:
        return sorted(self._records.keys(), key=self._sort_key)

    def get(self, vul_id: str) -> Optional[Vul4JRecord]:
        return self._records.get(vul_id)


# ---------------------------------------------------------------------------
# Backward-compatible CLI parser (keeps existing import path + class name)
# ---------------------------------------------------------------------------


class FixedVul4JParser:
    """
    CSV-backed Vul4J parser used by the CLI.

    Kept under the historical name `FixedVul4JParser` to avoid breaking the CLI.
    """

    def __init__(self, csv_path: Optional[str] = None) -> None:
        self.csv_path = Path(csv_path) if csv_path else default_vul4j_csv_path()
        try:
            self.dataset = Vul4JDataset(self.csv_path)
            self.available_vulnerabilities = self.dataset.available_vulnerabilities
        except Exception:
            # Ultra-safe fallback: preserve old demo behavior if CSV missing
            self.dataset = None
            self.available_vulnerabilities = ["VUL4J-0001", "VUL4J-0002", "VUL4J-0003"]

    def get_vulnerability_info(self, vul_id: str) -> Dict[str, str]:
        if self.dataset is None:
            return {"cve_id": f"CVE-DEMO-{vul_id[-4:]}", "repo_slug": "demo/repo"}
        rec = self.dataset.get(vul_id)
        if rec is None:
            return {"cve_id": "", "repo_slug": ""}
        return {
            "vul_id": rec.vul_id,
            "cve_id": rec.cve_id,
            "cwe_id": rec.cwe_id,
            "cwe_name": rec.cwe_name,
            "repo_slug": rec.repo_slug,
            "human_patch": rec.human_patch,
            "human_patch_commit": parse_human_patch_commit_hash(rec.human_patch) or "",
            "build_system": rec.build_system,
            "compliance_level": rec.compliance_level,
        }


