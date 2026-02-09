from __future__ import annotations

from types import SimpleNamespace

import pytest

try:
    from src.integrations.vul4j_parser import (  # type: ignore
        map_vul4j_to_bean_vuln_type,
        normalize_cwe_id,
        parse_human_patch_commit_hash,
    )
except Exception:  # pragma: no cover - supports PYTHONPATH=src style
    from integrations.vul4j_parser import (  # type: ignore
        map_vul4j_to_bean_vuln_type,
        normalize_cwe_id,
        parse_human_patch_commit_hash,
    )


def test_normalize_cwe_id():
    assert normalize_cwe_id("CWE-611") == 611
    assert normalize_cwe_id("611") == 611
    assert normalize_cwe_id("Not Mapping") is None
    assert normalize_cwe_id("") is None
    assert normalize_cwe_id("  ") is None


def test_parse_human_patch_commit_hash():
    url = "https://github.com/apache/xmlgraphics-batik/commit/660ef628d637af636ea113243fe73f170ac43958"
    assert (
        parse_human_patch_commit_hash(url)
        == "660ef628d637af636ea113243fe73f170ac43958"
    )
    assert parse_human_patch_commit_hash("abc1234..deadbeef") == "deadbeef"
    assert parse_human_patch_commit_hash("") is None


def test_map_vul4j_to_bean_vuln_type():
    assert (
        map_vul4j_to_bean_vuln_type(
            cwe_id="CWE-611",
            cwe_name="Improper Restriction of XML External Entity Reference",
            repo_slug="apache/batik",
            cve_id="CVE-2017-5662",
        )
        == "XXE"
    )
    assert (
        map_vul4j_to_bean_vuln_type(
            cwe_id="CWE-22",
            cwe_name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            repo_slug="apache/jspwiki",
            cve_id="CVE-2019-12402",
        )
        == "PATH_TRAVERSAL"
    )
    assert (
        map_vul4j_to_bean_vuln_type(
            cwe_id="Not Mapping",
            cwe_name="Improper Restriction of XML External Entity Reference",
            repo_slug="apache/camel",
            cve_id="CVE-2015-0263",
        )
        == "XXE"
    )
    # Repo override: fastjson is strongly deserialization-associated in practice
    assert (
        map_vul4j_to_bean_vuln_type(
            cwe_id="CWE-20",
            cwe_name="Improper Input Validation",
            repo_slug="alibaba/fastjson",
            cve_id="CVE-2017-18349",
        )
        == "DESERIALIZATION"
    )


def test_group_split_keeps_vul4j_pairs_together():
    # Only run when the heavy deps exist (prepare_training_data imports them).
    pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")

    # `prepare_training_data.py` lives at repo root; add it to sys.path defensively.
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    import prepare_training_data as ptd  # type: ignore

    samples = [
        SimpleNamespace(group_id="VUL4J-1", kind="vuln"),
        SimpleNamespace(group_id="VUL4J-1", kind="fix"),
        SimpleNamespace(group_id="VUL4J-2", kind="vuln"),
        SimpleNamespace(group_id="VUL4J-2", kind="fix"),
        SimpleNamespace(group_id="VUL4J-3", kind="vuln"),
    ]

    train, val, test, meta = ptd._split_dataset(
        samples,
        train_split=0.6,
        val_split=0.2,
        test_split=0.2,
        seed=123,
        group_attr="group_id",
    )

    train_groups = {s.group_id for s in train}
    val_groups = {s.group_id for s in val}
    test_groups = {s.group_id for s in test}

    assert train_groups.isdisjoint(val_groups)
    assert train_groups.isdisjoint(test_groups)
    assert val_groups.isdisjoint(test_groups)
    assert train_groups | val_groups | test_groups == {"VUL4J-1", "VUL4J-2", "VUL4J-3"}
    assert meta["split_strategy"].startswith("group_by_")

    for gid, expected_size in [("VUL4J-1", 2), ("VUL4J-2", 2), ("VUL4J-3", 1)]:
        counts = [
            sum(1 for s in split if s.group_id == gid) for split in (train, val, test)
        ]
        assert sorted(counts) == [0, 0, expected_size]

