from __future__ import annotations

import pytest


def test_ipag_compression_preserves_edge_type_alignment():
    torch = pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")

    try:
        from src.core.spatial_gnn_enhanced import EdgeType, InterProceduralAbstractGraph  # type: ignore
    except Exception:
        from core.spatial_gnn_enhanced import EdgeType, InterProceduralAbstractGraph  # type: ignore

    # Build a graph large enough to trigger compression (>10 nodes) with a known
    # kept-set (top-6 by norm), and *interleave* edges so the kept edges are NOT
    # a prefix of the edge list (this would break naive slicing).
    num_nodes = 12
    node_dim = 8
    hidden_dim = 16

    ipag = InterProceduralAbstractGraph(node_dim=node_dim, hidden_dim=hidden_dim, num_layers=1)
    # Default compression_ratio=0.3 -> sigmoid ~0.574, so keep int(12*0.574)=6 nodes.
    ipag.compression_ratio.data = torch.tensor(0.3)

    x = torch.zeros((num_nodes, node_dim), dtype=torch.float32)
    # Nodes 0..5 dominate topk; nodes 6..11 are tiny.
    for i in range(num_nodes):
        x[i, 0] = float(100 - i) if i < 6 else 1.0

    # Edge list interleaves kept-only edges with edges touching dropped nodes.
    edges = [
        (0, 6, EdgeType.AST_PARENT_CHILD.value),   # dropped
        (0, 1, EdgeType.CFG_CONTROL_FLOW.value),   # kept
        (1, 7, EdgeType.DFG_DATA_FLOW.value),      # dropped
        (1, 2, EdgeType.PDG_PROGRAM_DEP.value),    # kept
        (8, 2, EdgeType.CALL_GRAPH.value),         # dropped
        (2, 3, EdgeType.DFG_DATA_FLOW.value),      # kept
        (3, 9, EdgeType.AST_PARENT_CHILD.value),   # dropped
        (3, 4, EdgeType.CFG_CONTROL_FLOW.value),   # kept
        (10, 11, EdgeType.CALL_GRAPH.value),       # dropped
        (4, 5, EdgeType.CALL_GRAPH.value),         # kept
    ]

    edge_index = torch.tensor([[s for s, _, _ in edges], [t for _, t, _ in edges]], dtype=torch.long)
    edge_type = torch.tensor([et for _, _, et in edges], dtype=torch.long)

    # Compression should keep nodes {0..5} and only edges fully inside that set.
    expected_mask = torch.tensor([(s < 6 and t < 6) for s, t, _ in edges], dtype=torch.bool)
    expected_edge_type = edge_type[expected_mask]

    x_out, edge_index_out, edge_type_out = ipag(x, edge_index, edge_type, batch=None)

    assert edge_index_out.shape[1] == edge_type_out.shape[0]
    assert edge_type_out.tolist() == expected_edge_type.tolist()

