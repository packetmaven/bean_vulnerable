"""
Prototype Extractor for CESCL-based Inference

Extracts class centroids and per-class statistics from a trained Spatial GNN
model, enabling prototype-based confidence scoring at inference time.

Research Foundation:
- Snell et al. (NeurIPS 2017): "Prototypical Networks for Few-shot Learning"
  — embedding-mean prototypes for distance-based classification
- Yang et al. (ICML 2018): "Robust and Efficient Post-hoc Calibration"
  — calibration via distance-to-prototype
- Ren et al. (NeurIPS 2018): "Meta-Learning for Semi-Supervised Few-Shot
  Classification" — soft assignment with class-radius normalization

Why prototype-based inference matters for vulnerability detection:
1. Softmax overconfidence: Standard logit->softmax can produce 0.99+
   confidence even for inputs far from training distribution.
2. OOD detection: If a graph embedding is far from ALL centroids,
   it's likely an unseen vulnerability type or benign pattern not
   in training data. Prototype distance flags this naturally.
3. Calibration: Cosine distance to centroid provides a geometric
   calibration signal independent of the classifier head.
4. Explainability: "This sample is 0.12 cosine-distance from the
   'buffer_overflow' centroid" is more interpretable than logit scores.

Usage:
    # After training:
    python -m src.core.prototype_extractor \
        --checkpoint models/spatial_gnn/best_model.pt \
        --data training_data \
        --output models/spatial_gnn/prototypes.pt

    # Or inject into the checkpoint (single-file deployment):
    python -m src.core.prototype_extractor \
        --checkpoint models/spatial_gnn/best_model.pt \
        --data training_data
"""

from __future__ import annotations

import argparse
import logging
import pickle
import re
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

import numpy as np
import torch
import torch.nn.functional as F
from tqdm import tqdm

if TYPE_CHECKING:  # pragma: no cover
    from torch_geometric.loader import DataLoader

LOG = logging.getLogger(__name__)


class PrototypeExtractor:
    """
    Extracts class prototypes (centroids) from a trained model's embedding space.

    All distances/radii/std are computed in **cosine-distance** space:
        d_cos(x, c) = 1 - cos_sim(x, c) = 1 - <x, c>
    where x and c are L2-normalized vectors.
    """

    def __init__(
        self,
        model: torch.nn.Module,
        device: torch.device,
        label_field: str = "y_binary",
    ):
        self.model = model
        self.device = device
        self.label_field = label_field

    @torch.no_grad()
    def extract(
        self,
        data_loader: "DataLoader",
        normalize: bool = True,
    ) -> Dict[str, object]:
        """
        Extract class prototypes from the provided data loader.

        Returns:
            Dict with:
                'centroids':    {class_id: Tensor[embed_dim]}
                'radii':        {class_id: float}
                'stds':         {class_id: float}
                'counts':       {class_id: int}
                'embed_dim':    int
                'label_field':  str
                'normalized':   bool
                'global_mean':  Tensor[embed_dim]  (normalized if normalize=True)
                'global_std':   float              (std of cosine distances to global_mean)
        """
        self.model.eval()

        class_embeddings: Dict[int, List[torch.Tensor]] = {}
        all_embeddings: List[torch.Tensor] = []

        for batch in tqdm(data_loader, desc="Extracting embeddings"):
            batch = batch.to(self.device)

            outputs = self.model(
                x=batch.x,
                edge_index=batch.edge_index,
                edge_type=batch.edge_type,
                batch=batch.batch,
            )

            embeddings = outputs["graph_representation"]  # [batch, dim]
            if normalize:
                embeddings = F.normalize(embeddings, p=2, dim=1)

            labels = getattr(batch, self.label_field)

            for i in range(int(embeddings.size(0))):
                emb = embeddings[i].detach().cpu()
                label = int(labels[i].item())
                class_embeddings.setdefault(label, []).append(emb)
                all_embeddings.append(emb)

        if not all_embeddings:
            raise ValueError("No embeddings extracted — is the data loader empty?")

        all_stacked = torch.stack(all_embeddings)  # [N, dim]
        embed_dim = int(all_stacked.shape[1])

        # Global stats: cosine distance to global mean direction
        global_mean = all_stacked.mean(dim=0)
        if normalize:
            global_mean = F.normalize(global_mean, p=2, dim=0)
        global_sims = torch.matmul(all_stacked, global_mean)
        global_dists = 1.0 - global_sims
        global_std = float(global_dists.std().item()) if all_stacked.size(0) > 1 else 0.0

        centroids: Dict[int, torch.Tensor] = {}
        radii: Dict[int, float] = {}
        stds: Dict[int, float] = {}
        counts: Dict[int, int] = {}

        for class_id in sorted(class_embeddings.keys()):
            embs = torch.stack(class_embeddings[class_id])  # [n_c, dim]
            n_c = int(embs.shape[0])

            centroid = embs.mean(dim=0)
            if normalize:
                centroid = F.normalize(centroid, p=2, dim=0)

            sims = torch.matmul(embs, centroid)
            dists = 1.0 - sims
            radius = float(dists.mean().item())
            std = float(dists.std().item()) if n_c > 1 else 0.0

            centroids[class_id] = centroid
            radii[class_id] = radius
            stds[class_id] = std
            counts[class_id] = n_c

            LOG.info("Class %d: n=%d, radius=%.4f, std=%.4f", class_id, n_c, radius, std)

        LOG.info(
            "Extracted %d prototypes, embed_dim=%d, global_std=%.4f",
            len(centroids),
            embed_dim,
            global_std,
        )

        return {
            "centroids": centroids,
            "radii": radii,
            "stds": stds,
            "counts": counts,
            "embed_dim": embed_dim,
            "label_field": self.label_field,
            "normalized": normalize,
            "global_mean": global_mean,
            "global_std": global_std,
        }

    @staticmethod
    def save(prototypes: Dict, path: Path) -> None:
        path = Path(path)
        torch.save(prototypes, path)
        LOG.info("Saved prototypes to %s", path)

    @staticmethod
    def load(path: Path, device: torch.device = torch.device("cpu")) -> Dict:
        path = Path(path)
        prototypes = torch.load(path, map_location=device)

        for class_id in prototypes["centroids"]:
            prototypes["centroids"][class_id] = prototypes["centroids"][class_id].to(device)
        if "global_mean" in prototypes:
            prototypes["global_mean"] = prototypes["global_mean"].to(device)

        LOG.info(
            "Loaded %d prototypes from %s (embed_dim=%d)",
            len(prototypes["centroids"]),
            path,
            int(prototypes.get("embed_dim", -1)),
        )
        return prototypes

    @staticmethod
    def inject_into_checkpoint(
        checkpoint_path: Path,
        prototypes: Dict,
        output_path: Optional[Path] = None,
    ) -> None:
        output_path = output_path or checkpoint_path
        checkpoint_path = Path(checkpoint_path)
        checkpoint = torch.load(checkpoint_path, map_location="cpu")
        if not isinstance(checkpoint, dict):
            raise ValueError("Checkpoint must be a dict to inject prototypes.")
        checkpoint["class_prototypes"] = prototypes
        torch.save(checkpoint, output_path)
        LOG.info("Injected %d prototypes into %s", len(prototypes["centroids"]), output_path)


class PrototypeScorer:
    """
    Prototype-based CESCL scoring at inference time.

    Produces:
    - prototype probabilities (temperature-softmax over cosine similarities)
    - cosine distances to prototypes
    - OOD score (min distance / global_std)
    - calibrated confidence (sigmoid of z-score: (radius - dist) / std)
    - blended probabilities (optional): (1-a)*logit + a*proto, a = blend_weight
    """

    def __init__(
        self,
        prototypes: Dict,
        device: torch.device,
        temperature: float = 0.07,
        blend_weight: float = 0.3,
    ):
        self.device = device
        self.temperature = float(temperature)
        self.blend_weight = float(blend_weight)
        self.normalized = bool(prototypes.get("normalized", True))

        self.class_ids = sorted(int(cid) for cid in prototypes["centroids"].keys())
        self.centroid_matrix = torch.stack(
            [prototypes["centroids"][cid].to(device) for cid in self.class_ids]
        )  # [C, d]

        self.radii = {cid: float(prototypes["radii"].get(cid, 0.0)) for cid in self.class_ids}
        self.stds = {cid: float(prototypes["stds"].get(cid, 0.0)) for cid in self.class_ids}
        self.global_std = float(prototypes.get("global_std", 1.0))

        LOG.info(
            "PrototypeScorer initialized: %d classes, tau=%.3f, blend=%.2f",
            len(self.class_ids),
            self.temperature,
            self.blend_weight,
        )

    def score(self, embedding: torch.Tensor, logit_probs: Optional[torch.Tensor] = None) -> Dict[str, object]:
        if embedding.dim() == 1:
            embedding = embedding.unsqueeze(0)
        embedding = embedding.to(self.device)
        if self.normalized:
            embedding = F.normalize(embedding, p=2, dim=1)

        # similarities: [C]
        similarities = torch.matmul(embedding, self.centroid_matrix.T).squeeze(0)
        distances = 1.0 - similarities

        proto_logits = similarities / max(self.temperature, 1e-6)
        proto_probs = torch.softmax(proto_logits, dim=0)

        min_distance = float(distances.min().item())
        ood_score = min_distance / max(self.global_std, 1e-6)

        pred_idx = int(proto_probs.argmax().item())
        pred_class = int(self.class_ids[pred_idx])
        pred_distance = float(distances[pred_idx].item())
        pred_radius = float(self.radii.get(pred_class, 0.0))
        pred_std = float(self.stds.get(pred_class, 0.0))

        if pred_std > 1e-6:
            z_score = (pred_radius - pred_distance) / pred_std
        else:
            z_score = 1.0 if pred_distance <= pred_radius else -1.0
        calibrated_conf = float(torch.sigmoid(torch.tensor(z_score)).item())

        proto_probs_dict = {cid: float(proto_probs[i].item()) for i, cid in enumerate(self.class_ids)}
        dist_dict = {cid: float(distances[i].item()) for i, cid in enumerate(self.class_ids)}

        out: Dict[str, object] = {
            "prototype_probs": proto_probs_dict,
            "prototype_distances": dist_dict,
            "ood_score": ood_score,
            "calibrated_confidence": calibrated_conf,
            "predicted_class": pred_class,
        }

        if logit_probs is not None:
            lp = logit_probs.to(self.device)
            if lp.dim() > 1:
                lp = lp.squeeze(0)

            blended: Dict[int, float] = {}
            for i, cid in enumerate(self.class_ids):
                if int(cid) < int(lp.size(0)):
                    blended[int(cid)] = (1.0 - self.blend_weight) * float(lp[int(cid)].item()) + self.blend_weight * float(
                        proto_probs[i].item()
                    )
                else:
                    blended[int(cid)] = float(proto_probs[i].item())

            pred_blended = max(blended, key=blended.get)
            out["blended_probs"] = blended
            out["predicted_class_blended"] = int(pred_blended)
            out["blended_confidence"] = float(blended[pred_blended])

        return out

    def score_batch(
        self, embeddings: torch.Tensor, logit_probs: Optional[torch.Tensor] = None
    ) -> List[Dict]:
        results: List[Dict] = []
        for i in range(int(embeddings.size(0))):
            lp = logit_probs[i] if logit_probs is not None else None
            results.append(self.score(embeddings[i], lp))
        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract class prototypes from trained Spatial GNN")
    parser.add_argument("--checkpoint", type=str, required=True, help="Path to trained model checkpoint (best_model.pt)")
    parser.add_argument("--data", type=str, required=True, help="Training data directory (for embedding extraction)")
    parser.add_argument("--output", type=str, default=None, help="Output path for prototypes (default: inject into checkpoint)")
    parser.add_argument(
        "--label-field",
        type=str,
        default="y_binary",
        choices=["y_binary", "y_multiclass"],
        help="Which label to build prototypes for",
    )
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--device", type=str, default="auto")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    # Setup device
    if args.device == "auto":
        if torch.cuda.is_available():
            device = torch.device("cuda")
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = torch.device("mps")
        else:
            device = torch.device("cpu")
    else:
        device = torch.device(args.device)

    checkpoint_path = Path(args.checkpoint)
    checkpoint = torch.load(checkpoint_path, map_location=device)
    if not isinstance(checkpoint, dict):
        raise ValueError("Checkpoint must be a dict produced by train_spatial_gnn.py")
    epoch = int(checkpoint.get("epoch", -1))
    LOG.info("Loaded checkpoint from %s (epoch %s)", checkpoint_path, epoch)

    # Recreate model with the exact training config if present
    from .spatial_gnn_enhanced import create_spatial_gnn_model

    state_dict = checkpoint.get("model_state_dict")
    if state_dict is None:
        raise ValueError("Checkpoint missing model_state_dict")

    model_config = checkpoint.get("model_config")
    if not isinstance(model_config, dict):
        # Backward-compat: older checkpoints may not include `model_config`.
        model_config = {
            "node_dim": 128,
            "hidden_dim": 256,
            "num_vulnerability_types": 24,
            "num_edge_types": 5,
            "num_layers": 3,
            "use_hierarchical_pooling": True,
        }

        if isinstance(state_dict, dict):
            inferred: Dict[str, object] = {}
            try:
                keys = list(state_dict.keys())

                inferred["use_codebert"] = any(
                    k.startswith("transformer_gnn_fusion.codebert_model") for k in keys
                )
                inferred["use_hierarchical_pooling"] = any(k.startswith("hierarchical_pooling.") for k in keys)
                inferred["enable_attention_visualization"] = any(k.startswith("attention_aggregator.") for k in keys)
                inferred["enable_counterfactual_analysis"] = any(k.startswith("counterfactual_analyzer.") for k in keys)

                # hidden_dim + num_vulnerability_types from final multiclass linear layer
                last_mc = None
                last_idx = -1
                for k in keys:
                    m = re.match(r"^multiclass_classifier\.(\d+)\.weight$", k)
                    if not m:
                        continue
                    t = state_dict.get(k)
                    if not isinstance(t, torch.Tensor) or t.dim() != 2:
                        continue
                    idx = int(m.group(1))
                    if idx > last_idx:
                        last_idx = idx
                        last_mc = t
                if last_mc is not None:
                    inferred["num_vulnerability_types"] = int(last_mc.size(0))
                    inferred["hidden_dim"] = int(last_mc.size(1))

                root_w = state_dict.get("relational_layers.0.root.weight")
                if isinstance(root_w, torch.Tensor) and root_w.dim() == 2:
                    inferred["node_dim"] = int(root_w.size(1))

                comp = state_dict.get("relational_layers.0.comp")
                if isinstance(comp, torch.Tensor) and comp.dim() == 2:
                    inferred["num_edge_types"] = int(comp.size(0))
                else:
                    rel_w = state_dict.get("relational_layers.0.relation_weights")
                    if isinstance(rel_w, torch.Tensor) and rel_w.dim() == 1:
                        inferred["num_edge_types"] = int(rel_w.numel())

                layer_idxs = set()
                for k in keys:
                    m = re.match(r"^relational_layers\.(\d+)\.", k)
                    if m:
                        layer_idxs.add(int(m.group(1)))
                if layer_idxs:
                    inferred["num_layers"] = int(max(layer_idxs) + 1)
            except Exception as exc:  # pragma: no cover - best-effort inference
                LOG.warning("Failed to infer model_config from checkpoint state_dict: %s", exc)
                inferred = {}

            if inferred:
                model_config.update({k: v for k, v in inferred.items() if v is not None})
                LOG.info("Inferred model_config from checkpoint: %s", inferred)

    model = create_spatial_gnn_model(model_config)
    model.load_state_dict(state_dict)
    model = model.to(device)
    model.eval()

    # Load training data
    data_dir = Path(args.data)
    train_pkl = data_dir / "train.pkl"
    with open(train_pkl, "rb") as f:
        train_data = pickle.load(f)
    LOG.info("Loaded %d training samples", len(train_data))

    # Import DataLoader lazily (keeps module importable without PyG)
    from torch_geometric.loader import DataLoader

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=False)

    extractor = PrototypeExtractor(model, device, label_field=args.label_field)
    prototypes = extractor.extract(train_loader, normalize=True)

    if args.output:
        output_path = Path(args.output)
        PrototypeExtractor.save(prototypes, output_path)
    else:
        PrototypeExtractor.inject_into_checkpoint(checkpoint_path, prototypes)

    LOG.info("Prototype extraction complete.")

    print("\n" + "=" * 60)
    print("PROTOTYPE SUMMARY")
    print("=" * 60)
    for cid in sorted(prototypes["centroids"].keys()):
        print(
            f"  Class {cid}: n={prototypes['counts'][cid]}, "
            f"radius={prototypes['radii'][cid]:.4f}, std={prototypes['stds'][cid]:.4f}"
        )
    print(f"\n  Embedding dim: {prototypes['embed_dim']}")
    print(f"  Global std:    {prototypes['global_std']:.4f}")
    print(f"  Label field:   {prototypes['label_field']}")
    print("=" * 60)


if __name__ == "__main__":
    main()

