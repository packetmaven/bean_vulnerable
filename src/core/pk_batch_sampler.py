"""
PK Batch Sampler for Balanced Contrastive Learning

Guarantees every batch contains at least K samples from each of P classes,
which is a hard requirement for non-degenerate Supervised Contrastive Loss
and CESCL (Cluster-Enhanced Supervised Contrastive Loss).

Research Foundation:
- Hermans et al. (arXiv 2017): "In Defense of the Triplet Loss for Person
  Re-Identification" -- introduced PK sampling for metric learning
- Khosla et al. (NeurIPS 2020): "Supervised Contrastive Learning" --
  showed that batch composition critically affects SupCon loss quality
- Schroff et al. (CVPR 2015): "FaceNet" -- demonstrated that semi-hard
  negative mining requires guaranteed class diversity per batch

Why this matters for bean_vulnerable:
- Without PK sampling, a batch drawn via shuffle=True from an imbalanced
  dataset (e.g., 80% safe / 20% vulnerable) has a non-trivial probability
  of containing ZERO positive (vulnerable) samples.
- When a batch has only one class present, the CESCL positive mask is all-zero
  and the contrastive term degenerates to 0 (no learning signal).
- The cluster-tightening term also degenerates because torch.unique(labels)
  returns only one label and there is no inter-class separation to learn.
- PK sampling eliminates this failure mode entirely.

Integration:
    This module is imported by train_model.py and replaces the default
    shuffle=True DataLoader with a PK-sampled DataLoader.
"""

import random
import math
from collections import defaultdict
from typing import Iterator, List, Optional

from torch.utils.data import Sampler


class PKBatchSampler(Sampler[List[int]]):
    """
    Batch sampler that yields batches of exactly P*K indices,
    with K indices from each of P distinct classes.

    For binary vulnerability detection (P=2):
        Each batch contains K safe samples + K vulnerable samples.
        Total batch size = 2*K.

    Sampling strategy:
        - Majority class: sampled WITHOUT replacement across the epoch,
          then reshuffled when exhausted.
        - Minority class: sampled WITH replacement if the class has fewer
          than K samples, otherwise without replacement and recycled.
        - This ensures every majority-class sample is seen ~once per epoch
          while minority-class samples are oversampled to fill K slots.

    Args:
        labels: List of integer class labels, one per dataset sample.
                Must align with dataset indexing (labels[i] is the class
                of dataset[i]).
        p: Number of distinct classes per batch. For binary vuln detection
           this is 2.  For multiclass, set to the number of classes you
           want represented in each batch.
        k: Number of samples per class per batch. Total batch size = P*K.
        seed: Random seed for reproducibility. If None, uses system entropy.
        drop_last: If True (default), drop the final batch if it would be
                   incomplete.  Recommended for contrastive losses.

    Example:
        >>> labels = [int(d.y_binary) for d in train_data]
        >>> sampler = PKBatchSampler(labels, p=2, k=16, seed=42)
        >>> loader = DataLoader(train_data, batch_sampler=sampler)
        >>> for batch in loader:
        ...     assert batch.y_binary.unique().numel() >= 2
    """

    def __init__(
        self,
        labels: List[int],
        p: int = 2,
        k: int = 16,
        seed: Optional[int] = None,
        drop_last: bool = True,
    ):
        if not labels:
            raise ValueError("labels must be a non-empty list")
        if p < 2:
            raise ValueError(f"p must be >= 2 for contrastive learning, got {p}")
        if k < 1:
            raise ValueError(f"k must be >= 1, got {k}")

        self.labels = labels
        self.p = p
        self.k = k
        self.drop_last = drop_last
        self.rng = random.Random(seed)

        # Build class -> [indices] mapping
        self.label_to_indices: dict = defaultdict(list)
        for idx, label in enumerate(labels):
            self.label_to_indices[int(label)].append(idx)

        # Validate: we need at least P classes with at least 1 sample
        available_classes = [
            cls
            for cls, indices in self.label_to_indices.items()
            if len(indices) > 0
        ]
        if len(available_classes) < p:
            raise ValueError(
                f"Need at least {p} classes with samples, "
                f"but only {len(available_classes)} classes found: "
                f"{available_classes}"
            )

        # Select which P classes to use (for binary, this is just [0, 1])
        self.active_classes = sorted(available_classes)[:p]

        # Warn about small classes
        for cls in self.active_classes:
            n = len(self.label_to_indices[cls])
            if n < k:
                # Will use with-replacement sampling for this class
                import logging

                logging.getLogger(__name__).warning(
                    "Class %d has only %d samples (< k=%d). "
                    "Will oversample with replacement.",
                    cls,
                    n,
                    k,
                )

        # Compute epoch length: enough batches to see all majority-class samples
        max_class_size = max(len(self.label_to_indices[cls]) for cls in self.active_classes)
        self._num_batches = max(1, math.ceil(max_class_size / k))

    def __iter__(self) -> Iterator[List[int]]:
        """
        Yield batches of P*K indices.

        Algorithm:
        1. For each active class, create a shuffled pool of indices.
        2. For each batch, draw K indices from each class's pool.
        3. When a class's pool is exhausted, reshuffle and restart
           (with-replacement semantics over the epoch boundary).
        4. Concatenate the P groups of K indices into one batch.
        5. Shuffle the batch so classes are interleaved (prevents
           any ordering bias in the GNN message passing).
        """
        # Create per-class index pools
        pools: dict = {}
        for cls in self.active_classes:
            indices = list(self.label_to_indices[cls])
            self.rng.shuffle(indices)
            pools[cls] = indices

        # Track position in each pool
        positions: dict = {cls: 0 for cls in self.active_classes}

        batches_yielded = 0
        while batches_yielded < self._num_batches:
            batch_indices: List[int] = []

            for cls in self.active_classes:
                pool = pools[cls]
                pos = positions[cls]
                selected: List[int] = []

                if len(pool) == 0:
                    # Degenerate: class has no samples (should not happen
                    # given __init__ validation, but handle defensively)
                    continue

                if len(pool) >= self.k:
                    # Normal case: draw K without replacement from pool
                    for _ in range(self.k):
                        if pos >= len(pool):
                            # Pool exhausted, reshuffle
                            self.rng.shuffle(pool)
                            pos = 0
                        selected.append(pool[pos])
                        pos += 1
                else:
                    # Small class: draw K with replacement
                    selected = self.rng.choices(pool, k=self.k)
                    pos = 0  # Reset (not meaningful for choices())

                positions[cls] = pos
                batch_indices.extend(selected)

            # Verify batch has correct size
            expected_size = self.p * self.k
            if len(batch_indices) < expected_size:
                if self.drop_last:
                    break
                # Pad if not dropping (not recommended for contrastive)

            # Shuffle within batch to interleave classes
            self.rng.shuffle(batch_indices)

            yield batch_indices
            batches_yielded += 1

    def __len__(self) -> int:
        """Number of batches per epoch."""
        return self._num_batches

    @property
    def batch_size(self) -> int:
        """Effective batch size (P * K)."""
        return self.p * self.k

    def get_stats(self) -> dict:
        """Return sampler statistics for logging."""
        class_sizes = {cls: len(self.label_to_indices[cls]) for cls in self.active_classes}
        min_class = min(class_sizes.values())
        max_class = max(class_sizes.values())
        return {
            "p": self.p,
            "k": self.k,
            "batch_size": self.batch_size,
            "num_batches": self._num_batches,
            "active_classes": self.active_classes,
            "class_sizes": class_sizes,
            "imbalance_ratio": max_class / max(min_class, 1),
            "minority_oversampled": any(
                len(self.label_to_indices[cls]) < self.k for cls in self.active_classes
            ),
            "total_samples_per_epoch": self._num_batches * self.p * self.k,
        }

