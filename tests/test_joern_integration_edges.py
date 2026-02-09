from __future__ import annotations

import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Dict

import pytest


def _joern_available() -> bool:
    return (
        shutil.which("joern") is not None
        or Path("/usr/local/bin/joern").exists()
        or Path("/opt/joern/joern-cli/joern").exists()
    )


@pytest.fixture(scope="session")
def _sqlinj_sample() -> tuple[Path, str]:
    repo_root = Path(__file__).resolve().parents[1]
    sample_path = repo_root / "tests" / "samples" / "RealVuln_001_SQLInjection.java"
    if not sample_path.exists():
        pytest.skip(f"Sample missing: {sample_path}")
    return sample_path, sample_path.read_text(encoding="utf-8", errors="ignore")


@pytest.fixture(scope="session")
def joern_cpg_structure_sqlinj(_sqlinj_sample: tuple[Path, str]) -> Dict[str, Any]:
    if not _joern_available():
        pytest.skip("Joern not installed; skipping Joern integration test.")

    sample_path, code = _sqlinj_sample

    try:
        from src.core.integrated_gnn_framework import JoernIntegrator  # type: ignore
    except Exception:
        from core.integrated_gnn_framework import JoernIntegrator  # type: ignore

    ji = JoernIntegrator()
    # Keep this generous to avoid flakiness on slower machines.
    ji.joern_timeout = 240
    return ji.generate_cpg_structure(code, str(sample_path))


def test_joern_cpg_structure_emits_expected_edge_types(joern_cpg_structure_sqlinj: Dict[str, Any]) -> None:
    cpg = joern_cpg_structure_sqlinj
    nodes = cpg.get("nodes") or []
    edges = cpg.get("edges") or []
    stats = cpg.get("statistics") or {}

    assert isinstance(nodes, list) and len(nodes) > 0
    assert isinstance(edges, list) and len(edges) > 0
    assert int(stats.get("num_nodes", -1)) == len(nodes)
    assert int(stats.get("num_edges", -1)) == len(edges)

    by_type = Counter(e.get("edge_type") for e in edges)
    by_id = Counter(int(e.get("edge_type_id")) for e in edges if "edge_type_id" in e)

    # We rely on these five edge families as the baseline multi-relational graph.
    for key in ("AST", "CFG", "DFG", "CDG", "CALL"):
        assert by_type.get(key, 0) > 0, f"missing edge_type={key} in Joern export"

    # Edge type IDs must remain stable; GNN depends on this mapping.
    expected_id_map = {"AST": 0, "CFG": 1, "DFG": 2, "CDG": 3, "CALL": 4}
    assert set(by_id.keys()).issuperset(set(expected_id_map.values()))

    # Every edge must have a consistent (edge_type -> edge_type_id) mapping.
    for edge in edges:
        et = edge.get("edge_type")
        if et in expected_id_map:
            assert int(edge.get("edge_type_id")) == expected_id_map[et]
        src = int(edge.get("source", -1))
        tgt = int(edge.get("target", -1))
        assert 0 <= src < len(nodes)
        assert 0 <= tgt < len(nodes)
        # The GNN path currently drops self-edges; treat them as a regression.
        assert src != tgt

    # Statistics should agree with the actual edge list.
    assert int(stats.get("num_ast_edges", -1)) == by_id[0] == by_type["AST"]
    assert int(stats.get("num_cfg_edges", -1)) == by_id[1] == by_type["CFG"]
    assert int(stats.get("num_dfg_edges", -1)) == by_id[2] == by_type["DFG"]
    assert int(stats.get("num_cdg_edges", -1)) == by_id[3] == by_type["CDG"]
    assert int(stats.get("num_call_edges", -1)) == by_id[4] == by_type["CALL"]
    assert int(stats.get("num_edges", -1)) == (
        int(stats.get("num_ast_edges", 0) or 0)
        + int(stats.get("num_cfg_edges", 0) or 0)
        + int(stats.get("num_dfg_edges", 0) or 0)
        + int(stats.get("num_cdg_edges", 0) or 0)
        + int(stats.get("num_call_edges", 0) or 0)
    )

    # Dataflow summary should exist (reachableByFlows aggregation).
    dataflow = cpg.get("dataflow")
    assert isinstance(dataflow, dict)
    assert "sources" in dataflow
    flows_by_sink = dataflow.get("flows_by_sink")
    assert isinstance(flows_by_sink, dict) and len(flows_by_sink) > 0


def test_joern_structure_to_pyg_preserves_edge_distribution(joern_cpg_structure_sqlinj: Dict[str, Any]) -> None:
    torch = pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")

    try:
        from src.core.integrated_gnn_framework import IntegratedGNNFramework  # type: ignore
    except Exception:
        from core.integrated_gnn_framework import IntegratedGNNFramework  # type: ignore

    cpg = joern_cpg_structure_sqlinj
    edges = cpg.get("edges") or []
    expected_by_id = Counter(int(e.get("edge_type_id")) for e in edges if "edge_type_id" in e)

    fw = IntegratedGNNFramework(enable_spatial_gnn=False)
    data = fw._cpg_to_pyg_data(cpg)
    assert data is not None

    assert int(data.x.shape[0]) == int(cpg.get("statistics", {}).get("num_nodes", data.x.shape[0]))
    assert int(data.edge_index.shape[1]) == len(edges)
    assert int(data.edge_type.shape[0]) == len(edges)

    unique_ids, counts = torch.unique(data.edge_type, return_counts=True)
    pyg_by_id = {int(k.item()): int(v.item()) for k, v in zip(unique_ids, counts)}

    for k, v in expected_by_id.items():
        assert pyg_by_id.get(int(k), 0) == int(v)

