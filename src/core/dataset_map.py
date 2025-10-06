"""
Dataset-Map + Active Learning for Bad-Seed Pruning
Implements dataset quality assessment and active learning for vulnerability detection
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass
from sklearn.metrics import pairwise_distances
from sklearn.cluster import KMeans
import json

@dataclass
class DatasetMapMetrics:
    """Metrics for dataset quality assessment"""
    confidence: float
    variability: float
    correctness: float
    data_map_score: float
    pruning_recommendation: str
    active_learning_priority: float

class DatasetMapAnalyzer:
    """
    Dataset-Map analyzer for identifying bad seeds and active learning candidates
    Based on dataset cartography principles
    """
    
    def __init__(self, 
                 confidence_threshold: float = 0.7,
                 variability_threshold: float = 0.3,
                 correctness_threshold: float = 0.8):
        """
        Initialize Dataset-Map analyzer
        
        Args:
            confidence_threshold: Threshold for high-confidence samples
            variability_threshold: Threshold for high-variability samples
            correctness_threshold: Threshold for correctness assessment
        """
        self.confidence_threshold = confidence_threshold
        self.variability_threshold = variability_threshold
        self.correctness_threshold = correctness_threshold
        self.logger = logging.getLogger(__name__)
        
        # Track sample statistics over training epochs
        self.sample_confidences = {}
        self.sample_correctness = {}
        self.sample_losses = {}
        
        self.logger.info(f"✅ Dataset-Map analyzer initialized")
    
    def update_sample_statistics(self, 
                               sample_ids: List[str],
                               predictions: torch.Tensor,
                               labels: torch.Tensor,
                               losses: torch.Tensor,
                               epoch: int):
        """
        Update sample statistics for dataset mapping
        
        Args:
            sample_ids: List of sample identifiers
            predictions: Model predictions [batch_size, num_classes]
            labels: Ground truth labels [batch_size]
            losses: Sample losses [batch_size]
            epoch: Current training epoch
        """
        confidences = torch.max(F.softmax(predictions, dim=1), dim=1)[0]
        correct = (torch.argmax(predictions, dim=1) == labels).float()
        
        for i, sample_id in enumerate(sample_ids):
            if sample_id not in self.sample_confidences:
                self.sample_confidences[sample_id] = []
                self.sample_correctness[sample_id] = []
                self.sample_losses[sample_id] = []
            
            self.sample_confidences[sample_id].append(confidences[i].item())
            self.sample_correctness[sample_id].append(correct[i].item())
            self.sample_losses[sample_id].append(losses[i].item())
    
    def compute_dataset_map(self, sample_ids: Optional[List[str]] = None) -> Dict[str, DatasetMapMetrics]:
        """
        Compute dataset map metrics for all samples
        
        Args:
            sample_ids: Optional list of specific sample IDs to analyze
            
        Returns:
            Dictionary mapping sample IDs to DatasetMapMetrics
        """
        if sample_ids is None:
            sample_ids = list(self.sample_confidences.keys())
        
        dataset_map = {}
        
        for sample_id in sample_ids:
            if sample_id not in self.sample_confidences:
                continue
                
            confidences = np.array(self.sample_confidences[sample_id])
            correctness_values = np.array(self.sample_correctness[sample_id])
            losses = np.array(self.sample_losses[sample_id])
            
            # Compute metrics
            mean_confidence = np.mean(confidences)
            variability = np.std(confidences)
            mean_correctness = np.mean(correctness_values)
            
            # Dataset map score (combines confidence and variability)
            data_map_score = self._compute_data_map_score(mean_confidence, variability, mean_correctness)
            
            # Pruning recommendation
            pruning_recommendation = self._get_pruning_recommendation(
                mean_confidence, variability, mean_correctness
            )
            
            # Active learning priority
            active_learning_priority = self._compute_active_learning_priority(
                mean_confidence, variability, mean_correctness
            )
            
            dataset_map[sample_id] = DatasetMapMetrics(
                confidence=mean_confidence,
                variability=variability,
                correctness=mean_correctness,
                data_map_score=data_map_score,
                pruning_recommendation=pruning_recommendation,
                active_learning_priority=active_learning_priority
            )
        
        return dataset_map
    
    def _compute_data_map_score(self, confidence: float, variability: float, correctness: float) -> float:
        """
        Compute overall data map score
        
        Args:
            confidence: Mean confidence score
            variability: Confidence variability
            correctness: Mean correctness
            
        Returns:
            Combined data map score
        """
        # High confidence + low variability + high correctness = good sample
        # Low confidence + high variability + low correctness = bad sample
        score = (confidence * 0.4) + ((1 - variability) * 0.3) + (correctness * 0.3)
        return score
    
    def _get_pruning_recommendation(self, confidence: float, variability: float, correctness: float) -> str:
        """
        Get pruning recommendation based on dataset map metrics
        
        Args:
            confidence: Mean confidence score
            variability: Confidence variability
            correctness: Mean correctness
            
        Returns:
            Pruning recommendation string
        """
        if correctness < 0.3 and confidence < 0.5:
            return "prune_bad_seed"
        elif correctness < 0.5 and variability > 0.5:
            return "prune_noisy"
        elif confidence > 0.9 and correctness > 0.9 and variability < 0.1:
            return "keep_easy"
        elif confidence < 0.6 and variability > 0.3:
            return "active_learning_candidate"
        else:
            return "keep_normal"
    
    def _compute_active_learning_priority(self, confidence: float, variability: float, correctness: float) -> float:
        """
        Compute active learning priority score
        
        Args:
            confidence: Mean confidence score
            variability: Confidence variability
            correctness: Mean correctness
            
        Returns:
            Active learning priority score (higher = more priority)
        """
        # High variability + medium confidence = high priority for active learning
        # Low confidence + high variability = potential mislabeling
        if variability > 0.4 and 0.3 < confidence < 0.7:
            return 0.9  # High priority
        elif variability > 0.3 and correctness < 0.6:
            return 0.7  # Medium-high priority
        elif confidence < 0.5:
            return 0.5  # Medium priority
        else:
            return 0.1  # Low priority
    
    def prune_bad_seeds(self, dataset_map: Dict[str, DatasetMapMetrics], 
                       prune_ratio: float = 0.1) -> Tuple[List[str], List[str]]:
        """
        Prune bad seeds from dataset based on dataset map
        
        Args:
            dataset_map: Dataset map metrics
            prune_ratio: Ratio of samples to prune
            
        Returns:
            Tuple of (samples_to_keep, samples_to_prune)
        """
        # Sort samples by data map score (lower = worse)
        sorted_samples = sorted(
            dataset_map.items(), 
            key=lambda x: x[1].data_map_score
        )
        
        # Determine number of samples to prune
        total_samples = len(sorted_samples)
        num_to_prune = int(total_samples * prune_ratio)
        
        # Identify samples to prune
        samples_to_prune = []
        samples_to_keep = []
        
        for i, (sample_id, metrics) in enumerate(sorted_samples):
            if i < num_to_prune or metrics.pruning_recommendation in ["prune_bad_seed", "prune_noisy"]:
                samples_to_prune.append(sample_id)
            else:
                samples_to_keep.append(sample_id)
        
        self.logger.info(f"📊 Pruning {len(samples_to_prune)}/{total_samples} samples ({len(samples_to_prune)/total_samples*100:.1f}%)")
        
        return samples_to_keep, samples_to_prune
    
    def select_active_learning_candidates(self, 
                                        dataset_map: Dict[str, DatasetMapMetrics],
                                        num_candidates: int = 50) -> List[str]:
        """
        Select candidates for active learning
        
        Args:
            dataset_map: Dataset map metrics
            num_candidates: Number of candidates to select
            
        Returns:
            List of sample IDs for active learning
        """
        # Sort by active learning priority (higher = more priority)
        sorted_samples = sorted(
            dataset_map.items(),
            key=lambda x: x[1].active_learning_priority,
            reverse=True
        )
        
        # Select top candidates
        candidates = [sample_id for sample_id, _ in sorted_samples[:num_candidates]]
        
        self.logger.info(f"🎯 Selected {len(candidates)} active learning candidates")
        
        return candidates
    
    def generate_report(self, dataset_map: Dict[str, DatasetMapMetrics]) -> Dict[str, Any]:
        """
        Generate comprehensive dataset quality report
        
        Args:
            dataset_map: Dataset map metrics
            
        Returns:
            Report dictionary with statistics and recommendations
        """
        if not dataset_map:
            return {"error": "No dataset map data available"}
        
        # Compute statistics
        confidences = [m.confidence for m in dataset_map.values()]
        variabilities = [m.variability for m in dataset_map.values()]
        correctness_values = [m.correctness for m in dataset_map.values()]
        data_map_scores = [m.data_map_score for m in dataset_map.values()]
        
        # Count recommendations
        recommendations = [m.pruning_recommendation for m in dataset_map.values()]
        recommendation_counts = {}
        for rec in recommendations:
            recommendation_counts[rec] = recommendation_counts.get(rec, 0) + 1
        
        # Compute percentiles
        confidence_percentiles = np.percentile(confidences, [25, 50, 75])
        variability_percentiles = np.percentile(variabilities, [25, 50, 75])
        correctness_percentiles = np.percentile(correctness_values, [25, 50, 75])
        
        report = {
            "total_samples": len(dataset_map),
            "confidence_stats": {
                "mean": np.mean(confidences),
                "std": np.std(confidences),
                "percentiles": {
                    "25th": confidence_percentiles[0],
                    "50th": confidence_percentiles[1],
                    "75th": confidence_percentiles[2]
                }
            },
            "variability_stats": {
                "mean": np.mean(variabilities),
                "std": np.std(variabilities),
                "percentiles": {
                    "25th": variability_percentiles[0],
                    "50th": variability_percentiles[1],
                    "75th": variability_percentiles[2]
                }
            },
            "correctness_stats": {
                "mean": np.mean(correctness_values),
                "std": np.std(correctness_values),
                "percentiles": {
                    "25th": correctness_percentiles[0],
                    "50th": correctness_percentiles[1],
                    "75th": correctness_percentiles[2]
                }
            },
            "data_map_score_stats": {
                "mean": np.mean(data_map_scores),
                "std": np.std(data_map_scores),
                "min": np.min(data_map_scores),
                "max": np.max(data_map_scores)
            },
            "pruning_recommendations": recommendation_counts,
            "quality_assessment": self._assess_dataset_quality(dataset_map)
        }
        
        return report
    
    def _assess_dataset_quality(self, dataset_map: Dict[str, DatasetMapMetrics]) -> Dict[str, Any]:
        """
        Assess overall dataset quality
        
        Args:
            dataset_map: Dataset map metrics
            
        Returns:
            Quality assessment dictionary
        """
        total_samples = len(dataset_map)
        
        # Count different types of samples
        bad_seeds = sum(1 for m in dataset_map.values() 
                       if m.pruning_recommendation == "prune_bad_seed")
        noisy_samples = sum(1 for m in dataset_map.values() 
                          if m.pruning_recommendation == "prune_noisy")
        easy_samples = sum(1 for m in dataset_map.values() 
                         if m.pruning_recommendation == "keep_easy")
        active_learning_candidates = sum(1 for m in dataset_map.values() 
                                       if m.pruning_recommendation == "active_learning_candidate")
        
        # Overall quality score
        quality_score = np.mean([m.data_map_score for m in dataset_map.values()])
        
        # Quality assessment
        if quality_score > 0.8:
            quality_level = "excellent"
        elif quality_score > 0.6:
            quality_level = "good"
        elif quality_score > 0.4:
            quality_level = "fair"
        else:
            quality_level = "poor"
        
        return {
            "overall_quality_score": quality_score,
            "quality_level": quality_level,
            "bad_seeds_ratio": bad_seeds / total_samples,
            "noisy_samples_ratio": noisy_samples / total_samples,
            "easy_samples_ratio": easy_samples / total_samples,
            "active_learning_candidates_ratio": active_learning_candidates / total_samples,
            "recommendations": {
                "prune_bad_seeds": bad_seeds > 0,
                "apply_active_learning": active_learning_candidates > total_samples * 0.1,
                "data_augmentation_needed": easy_samples < total_samples * 0.3
            }
        }

class ActiveLearningStrategy:
    """
    Active learning strategy for vulnerability detection
    """
    
    def __init__(self, 
                 strategy: str = "uncertainty_sampling",
                 batch_size: int = 10):
        """
        Initialize active learning strategy
        
        Args:
            strategy: Active learning strategy ("uncertainty_sampling", "diversity_sampling", "hybrid")
            batch_size: Number of samples to select per iteration
        """
        self.strategy = strategy
        self.batch_size = batch_size
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"✅ Active learning strategy initialized: {strategy}")
    
    def select_samples(self, 
                      unlabeled_samples: List[str],
                      model_predictions: Dict[str, torch.Tensor],
                      features: Dict[str, torch.Tensor],
                      dataset_map: Dict[str, DatasetMapMetrics]) -> List[str]:
        """
        Select samples for active learning
        
        Args:
            unlabeled_samples: List of unlabeled sample IDs
            model_predictions: Model predictions for each sample
            features: Feature representations for each sample
            dataset_map: Dataset map metrics
            
        Returns:
            List of selected sample IDs
        """
        if self.strategy == "uncertainty_sampling":
            return self._uncertainty_sampling(unlabeled_samples, model_predictions)
        elif self.strategy == "diversity_sampling":
            return self._diversity_sampling(unlabeled_samples, features)
        elif self.strategy == "hybrid":
            return self._hybrid_sampling(unlabeled_samples, model_predictions, features, dataset_map)
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")
    
    def _uncertainty_sampling(self, 
                            unlabeled_samples: List[str],
                            model_predictions: Dict[str, torch.Tensor]) -> List[str]:
        """
        Select samples with highest prediction uncertainty
        
        Args:
            unlabeled_samples: List of unlabeled sample IDs
            model_predictions: Model predictions for each sample
            
        Returns:
            List of selected sample IDs
        """
        uncertainties = []
        
        for sample_id in unlabeled_samples:
            if sample_id in model_predictions:
                pred = model_predictions[sample_id]
                # Use entropy as uncertainty measure
                prob = F.softmax(pred, dim=0)
                uncertainty = -torch.sum(prob * torch.log(prob + 1e-8))
                uncertainties.append((sample_id, uncertainty.item()))
        
        # Sort by uncertainty (highest first)
        uncertainties.sort(key=lambda x: x[1], reverse=True)
        
        # Select top samples
        selected = [sample_id for sample_id, _ in uncertainties[:self.batch_size]]
        
        self.logger.info(f"🎯 Selected {len(selected)} samples via uncertainty sampling")
        return selected
    
    def _diversity_sampling(self, 
                          unlabeled_samples: List[str],
                          features: Dict[str, torch.Tensor]) -> List[str]:
        """
        Select diverse samples using clustering
        
        Args:
            unlabeled_samples: List of unlabeled sample IDs
            features: Feature representations for each sample
            
        Returns:
            List of selected sample IDs
        """
        # Extract features for unlabeled samples
        feature_matrix = []
        valid_samples = []
        
        for sample_id in unlabeled_samples:
            if sample_id in features:
                feature_matrix.append(features[sample_id].numpy())
                valid_samples.append(sample_id)
        
        if len(feature_matrix) == 0:
            return []
        
        feature_matrix = np.array(feature_matrix)
        
        # Use K-means clustering to find diverse samples
        n_clusters = min(self.batch_size, len(valid_samples))
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        clusters = kmeans.fit_predict(feature_matrix)
        
        # Select one sample from each cluster (closest to centroid)
        selected = []
        for cluster_id in range(n_clusters):
            cluster_indices = np.where(clusters == cluster_id)[0]
            cluster_features = feature_matrix[cluster_indices]
            centroid = kmeans.cluster_centers_[cluster_id]
            
            # Find closest sample to centroid
            distances = np.linalg.norm(cluster_features - centroid, axis=1)
            closest_idx = cluster_indices[np.argmin(distances)]
            selected.append(valid_samples[closest_idx])
        
        self.logger.info(f"🎯 Selected {len(selected)} samples via diversity sampling")
        return selected
    
    def _hybrid_sampling(self, 
                        unlabeled_samples: List[str],
                        model_predictions: Dict[str, torch.Tensor],
                        features: Dict[str, torch.Tensor],
                        dataset_map: Dict[str, DatasetMapMetrics]) -> List[str]:
        """
        Hybrid sampling combining uncertainty, diversity, and dataset map
        
        Args:
            unlabeled_samples: List of unlabeled sample IDs
            model_predictions: Model predictions for each sample
            features: Feature representations for each sample
            dataset_map: Dataset map metrics
            
        Returns:
            List of selected sample IDs
        """
        # Get uncertainty-based candidates
        uncertainty_candidates = self._uncertainty_sampling(
            unlabeled_samples, model_predictions
        )
        
        # Get diversity-based candidates
        diversity_candidates = self._diversity_sampling(
            unlabeled_samples, features
        )
        
        # Combine with dataset map priorities
        all_candidates = set(uncertainty_candidates + diversity_candidates)
        
        # Score candidates
        scored_candidates = []
        for sample_id in all_candidates:
            score = 0.0
            
            # Uncertainty score
            if sample_id in model_predictions:
                pred = model_predictions[sample_id]
                prob = F.softmax(pred, dim=0)
                uncertainty = -torch.sum(prob * torch.log(prob + 1e-8))
                score += uncertainty.item() * 0.4
            
            # Dataset map priority
            if sample_id in dataset_map:
                score += dataset_map[sample_id].active_learning_priority * 0.6
            
            scored_candidates.append((sample_id, score))
        
        # Sort by combined score
        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        
        # Select top samples
        selected = [sample_id for sample_id, _ in scored_candidates[:self.batch_size]]
        
        self.logger.info(f"🎯 Selected {len(selected)} samples via hybrid sampling")
        return selected 