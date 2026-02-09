"""
Loss functions for Bean Vulnerable vulnerability detection

Available losses:
- CESCLLoss: Cluster-Enhanced Supervised Contrastive Loss (NAACL-SRW 2025)
- cescl: Standalone function for CESCL computation
"""

from .cescl import CESCLLoss, cescl, CESCLTrainer, GraphSAGECESCLTrainer

__all__ = [
    "CESCLLoss",
    "cescl",
    "CESCLTrainer",
    "GraphSAGECESCLTrainer",
]

