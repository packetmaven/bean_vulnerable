"""
Bean Vulnerable GNN Framework - Ensemble Methods
Multi-model voting, Bayesian model averaging, and stacking for better accuracy
"""

import logging
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Any, Optional, Tuple, Callable
from sklearn.ensemble import VotingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class EnsembleVotingClassifier:
    """Multi-model voting ensemble for vulnerability detection"""
    
    def __init__(self, ensemble_config: Optional[Dict[str, Any]] = None):
        """
        Initialize ensemble voting classifier
        
        Args:
            ensemble_config: Configuration for ensemble
                - voting_strategy: 'hard' or 'soft' voting
                - model_weights: Weights for each model
                - confidence_threshold: Threshold for ensemble confidence
                - diversity_penalty: Penalty for low model diversity
        """
        self.config = ensemble_config or {}
        self.voting_strategy = self.config.get('voting_strategy', 'soft')
        self.model_weights = self.config.get('model_weights', None)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        self.diversity_penalty = self.config.get('diversity_penalty', 0.1)
        
        # Store individual models and their predictions
        self.models = {}
        self.model_performances = {}
        self.prediction_history = []
        
        logger.info(f"✅ Ensemble Voting Classifier initialized with {self.voting_strategy} voting")
    
    def add_model(self, model_name: str, model: Any, weight: float = 1.0) -> bool:
        """
        Add a model to the ensemble
        
        Args:
            model_name: Name identifier for the model
            model: Model object with predict method
            weight: Weight for this model in voting
            
        Returns:
            Success status
        """
        try:
            self.models[model_name] = {
                'model': model,
                'weight': weight,
                'predictions': [],
                'confidences': [],
                'accuracy': 0.0
            }
            
            logger.info(f"Model '{model_name}' added to ensemble with weight {weight}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add model '{model_name}': {e}")
            return False
    
    def predict_ensemble(self, input_data: Any) -> Dict[str, Any]:
        """
        Make ensemble prediction using all models
        
        Args:
            input_data: Input data for prediction
            
        Returns:
            Ensemble prediction results
        """
        try:
            start_time = time.time()
            
            # Collect predictions from all models
            model_predictions = {}
            model_confidences = {}
            
            for model_name, model_info in self.models.items():
                try:
                    # Get prediction from individual model
                    prediction = self._get_model_prediction(model_info['model'], input_data)
                    
                    model_predictions[model_name] = prediction['prediction']
                    model_confidences[model_name] = prediction['confidence']
                    
                    # Store for history
                    model_info['predictions'].append(prediction['prediction'])
                    model_info['confidences'].append(prediction['confidence'])
                    
                except Exception as e:
                    logger.warning(f"Model '{model_name}' prediction failed: {e}")
                    model_predictions[model_name] = 0.0
                    model_confidences[model_name] = 0.0
            
            # Perform ensemble voting
            if self.voting_strategy == 'hard':
                ensemble_result = self._hard_voting(model_predictions)
            else:
                ensemble_result = self._soft_voting(model_predictions, model_confidences)
            
            # Calculate ensemble metrics
            diversity_score = self._calculate_diversity(model_predictions)
            agreement_score = self._calculate_agreement(model_predictions)
            
            prediction_time = time.time() - start_time
            
            result = {
                'ensemble_prediction': ensemble_result['prediction'],
                'ensemble_confidence': ensemble_result['confidence'],
                'individual_predictions': model_predictions,
                'individual_confidences': model_confidences,
                'diversity_score': diversity_score,
                'agreement_score': agreement_score,
                'voting_strategy': self.voting_strategy,
                'num_models': len(self.models),
                'prediction_time': prediction_time,
                'ensemble_quality': self._assess_ensemble_quality(diversity_score, agreement_score)
            }
            
            # Store prediction history
            self.prediction_history.append(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Ensemble prediction failed: {e}")
            return {
                'error': str(e),
                'ensemble_prediction': 0.0,
                'ensemble_confidence': 0.0
            }
    
    def _get_model_prediction(self, model: Any, input_data: Any) -> Dict[str, float]:
        """Get prediction from individual model"""
        
        # Handle different model types
        if hasattr(model, 'analyze_code'):
            # Bean Vulnerable framework model
            result = model.analyze_code(input_data)
            return {
                'prediction': 1.0 if result.get('vulnerability_detected', False) else 0.0,
                'confidence': result.get('confidence', 0.0)
            }
        
        elif hasattr(model, 'predict_proba'):
            # Scikit-learn style model
            if isinstance(input_data, str):
                # Convert string to features (simplified)
                features = np.array([[len(input_data), input_data.count('SELECT'), 
                                   input_data.count('exec'), input_data.count('<script>')]])
            else:
                features = input_data
            
            proba = model.predict_proba(features)[0]
            return {
                'prediction': float(np.argmax(proba)),
                'confidence': float(np.max(proba))
            }
        
        elif hasattr(model, 'predict'):
            # Generic predict method
            prediction = model.predict(input_data)
            if isinstance(prediction, (list, np.ndarray)):
                prediction = prediction[0]
            
            return {
                'prediction': float(prediction),
                'confidence': 0.8  # Default confidence
            }
        
        else:
            # Fallback for unknown model types
            return {
                'prediction': 0.0,
                'confidence': 0.0
            }
    
    def _hard_voting(self, model_predictions: Dict[str, float]) -> Dict[str, float]:
        """Perform hard voting (majority vote)"""
        
        votes = []
        weights = []
        
        for model_name, prediction in model_predictions.items():
            binary_vote = 1 if prediction > 0.5 else 0
            votes.append(binary_vote)
            
            # Get model weight
            weight = self.models[model_name]['weight']
            weights.append(weight)
        
        # Weighted majority vote
        weighted_votes = np.array(votes) * np.array(weights)
        total_weight = sum(weights)
        
        ensemble_vote = np.sum(weighted_votes) / total_weight
        final_prediction = 1.0 if ensemble_vote > 0.5 else 0.0
        
        # Confidence based on vote margin
        vote_margin = abs(ensemble_vote - 0.5) * 2
        confidence = min(0.5 + vote_margin * 0.5, 1.0)
        
        return {
            'prediction': final_prediction,
            'confidence': confidence
        }
    
    def _soft_voting(self, model_predictions: Dict[str, float], model_confidences: Dict[str, float]) -> Dict[str, float]:
        """Perform soft voting (weighted average)"""
        
        weighted_predictions = 0.0
        total_weight = 0.0
        confidence_sum = 0.0
        
        for model_name in model_predictions.keys():
            prediction = model_predictions[model_name]
            confidence = model_confidences[model_name]
            weight = self.models[model_name]['weight']
            
            # Weight by both assigned weight and confidence
            effective_weight = weight * confidence
            
            weighted_predictions += prediction * effective_weight
            total_weight += effective_weight
            confidence_sum += confidence * weight
        
        if total_weight > 0:
            ensemble_prediction = weighted_predictions / total_weight
            ensemble_confidence = confidence_sum / sum(self.models[name]['weight'] for name in model_predictions.keys())
        else:
            ensemble_prediction = 0.0
            ensemble_confidence = 0.0
        
        return {
            'prediction': ensemble_prediction,
            'confidence': ensemble_confidence
        }
    
    def _calculate_diversity(self, model_predictions: Dict[str, float]) -> float:
        """Calculate diversity score among model predictions"""
        
        predictions = list(model_predictions.values())
        if len(predictions) < 2:
            return 0.0
        
        # Calculate pairwise disagreement
        disagreements = 0
        total_pairs = 0
        
        for i in range(len(predictions)):
            for j in range(i + 1, len(predictions)):
                # Binary disagreement
                pred_i = 1 if predictions[i] > 0.5 else 0
                pred_j = 1 if predictions[j] > 0.5 else 0
                
                if pred_i != pred_j:
                    disagreements += 1
                total_pairs += 1
        
        diversity = disagreements / total_pairs if total_pairs > 0 else 0.0
        return diversity
    
    def _calculate_agreement(self, model_predictions: Dict[str, float]) -> float:
        """Calculate agreement score among model predictions"""
        
        return 1.0 - self._calculate_diversity(model_predictions)
    
    def _assess_ensemble_quality(self, diversity_score: float, agreement_score: float) -> str:
        """Assess overall ensemble quality"""
        
        # Good ensemble has moderate diversity and high agreement on confident predictions
        if diversity_score > 0.8:
            return 'low_quality_high_disagreement'
        elif diversity_score < 0.1:
            return 'low_quality_low_diversity'
        elif agreement_score > 0.7:
            return 'high_quality'
        elif agreement_score > 0.5:
            return 'medium_quality'
        else:
            return 'low_quality'
    
    def update_model_performance(self, model_name: str, accuracy: float) -> bool:
        """Update performance metrics for a model"""
        
        if model_name in self.models:
            self.models[model_name]['accuracy'] = accuracy
            self.model_performances[model_name] = accuracy
            
            # Adjust weights based on performance
            if accuracy > 0.8:
                self.models[model_name]['weight'] *= 1.1  # Increase weight for good models
            elif accuracy < 0.6:
                self.models[model_name]['weight'] *= 0.9  # Decrease weight for poor models
            
            logger.info(f"Updated performance for '{model_name}': {accuracy:.3f}")
            return True
        
        return False


class BayesianModelAveraging:
    """Bayesian Model Averaging for uncertainty quantification"""
    
    def __init__(self, bma_config: Optional[Dict[str, Any]] = None):
        """
        Initialize Bayesian Model Averaging
        
        Args:
            bma_config: Configuration for BMA
                - prior_weights: Prior weights for models
                - update_rate: Rate for weight updates
                - min_samples: Minimum samples for weight updates
        """
        self.config = bma_config or {}
        self.prior_weights = self.config.get('prior_weights', {})
        self.update_rate = self.config.get('update_rate', 0.1)
        self.min_samples = self.config.get('min_samples', 10)
        
        # Model weights and evidence
        self.model_weights = {}
        self.model_evidence = {}
        self.prediction_history = []
        
        logger.info("✅ Bayesian Model Averaging initialized")
    
    def add_model(self, model_name: str, model: Any, prior_weight: float = 1.0) -> bool:
        """Add model to BMA ensemble"""
        
        try:
            self.model_weights[model_name] = prior_weight
            self.model_evidence[model_name] = []
            
            logger.info(f"Model '{model_name}' added to BMA with prior weight {prior_weight}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add model to BMA: {e}")
            return False
    
    def predict_bma(self, input_data: Any, true_label: Optional[int] = None) -> Dict[str, Any]:
        """Make Bayesian Model Averaged prediction"""
        
        try:
            # Get predictions from all models
            model_predictions = {}
            model_likelihoods = {}
            
            for model_name in self.model_weights.keys():
                # Simplified prediction for demonstration
                prediction = np.random.beta(2, 2)  # Would be actual model prediction
                likelihood = self._calculate_likelihood(prediction, true_label)
                
                model_predictions[model_name] = prediction
                model_likelihoods[model_name] = likelihood
                
                # Store evidence
                self.model_evidence[model_name].append(likelihood)
            
            # Update model weights using Bayesian updating
            self._update_weights(model_likelihoods)
            
            # Compute BMA prediction
            bma_prediction = 0.0
            total_weight = sum(self.model_weights.values())
            
            for model_name, prediction in model_predictions.items():
                weight = self.model_weights[model_name] / total_weight
                bma_prediction += weight * prediction
            
            # Compute prediction uncertainty
            uncertainty = self._compute_bma_uncertainty(model_predictions)
            
            return {
                'bma_prediction': bma_prediction,
                'bma_uncertainty': uncertainty,
                'model_weights': self.model_weights.copy(),
                'individual_predictions': model_predictions,
                'total_evidence': sum(sum(evidence) for evidence in self.model_evidence.values())
            }
            
        except Exception as e:
            logger.error(f"BMA prediction failed: {e}")
            return {'error': str(e)}
    
    def _calculate_likelihood(self, prediction: float, true_label: Optional[int]) -> float:
        """Calculate likelihood of prediction given true label"""
        
        if true_label is None:
            return 1.0  # Uniform likelihood without ground truth
        
        # Binary classification likelihood
        if true_label == 1:
            return prediction
        else:
            return 1.0 - prediction
    
    def _update_weights(self, model_likelihoods: Dict[str, float]):
        """Update model weights using Bayesian updating"""
        
        for model_name, likelihood in model_likelihoods.items():
            # Bayesian weight update
            current_weight = self.model_weights[model_name]
            updated_weight = current_weight * (1 + self.update_rate * (likelihood - 0.5))
            
            # Ensure positive weights
            self.model_weights[model_name] = max(updated_weight, 0.01)
    
    def _compute_bma_uncertainty(self, model_predictions: Dict[str, float]) -> float:
        """Compute uncertainty in BMA prediction"""
        
        predictions = list(model_predictions.values())
        weights = list(self.model_weights.values())
        
        # Weighted variance as uncertainty measure
        weighted_mean = np.average(predictions, weights=weights)
        weighted_variance = np.average((np.array(predictions) - weighted_mean) ** 2, weights=weights)
        
        return float(weighted_variance)


class StackingEnsemble:
    """Stacking ensemble with meta-learner"""
    
    def __init__(self, stacking_config: Optional[Dict[str, Any]] = None):
        """
        Initialize stacking ensemble
        
        Args:
            stacking_config: Configuration for stacking
                - meta_learner: Type of meta-learner ('logistic', 'neural', 'xgboost')
                - cv_folds: Number of cross-validation folds
                - use_probabilities: Use probabilities as meta-features
        """
        self.config = stacking_config or {}
        self.meta_learner_type = self.config.get('meta_learner', 'logistic')
        self.cv_folds = self.config.get('cv_folds', 5)
        self.use_probabilities = self.config.get('use_probabilities', True)
        
        # Base models and meta-learner
        self.base_models = {}
        self.meta_learner = None
        self.is_trained = False
        
        self._initialize_meta_learner()
        
        logger.info(f"✅ Stacking Ensemble initialized with {self.meta_learner_type} meta-learner")
    
    def _initialize_meta_learner(self):
        """Initialize the meta-learner"""
        
        if self.meta_learner_type == 'logistic':
            self.meta_learner = LogisticRegression(random_state=42)
        elif self.meta_learner_type == 'neural':
            self.meta_learner = self._create_neural_meta_learner()
        else:
            # Default to logistic regression
            self.meta_learner = LogisticRegression(random_state=42)
    
    def _create_neural_meta_learner(self) -> nn.Module:
        """Create neural network meta-learner"""
        
        class NeuralMetaLearner(nn.Module):
            def __init__(self, input_dim: int):
                super().__init__()
                self.layers = nn.Sequential(
                    nn.Linear(input_dim, 64),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(32, 1),
                    nn.Sigmoid()
                )
            
            def forward(self, x):
                return self.layers(x)
        
        # Will be initialized with proper input dimension during training
        return NeuralMetaLearner
    
    def add_base_model(self, model_name: str, model: Any) -> bool:
        """Add base model to stacking ensemble"""
        
        try:
            self.base_models[model_name] = model
            logger.info(f"Base model '{model_name}' added to stacking ensemble")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add base model: {e}")
            return False
    
    def train_stacking(self, training_data: List[str], labels: List[int]) -> Dict[str, Any]:
        """Train the stacking ensemble"""
        
        try:
            if len(self.base_models) < 2:
                raise ValueError("Need at least 2 base models for stacking")
            
            # Generate meta-features using cross-validation
            meta_features = self._generate_meta_features(training_data, labels)
            
            # Train meta-learner
            if self.meta_learner_type == 'neural':
                training_results = self._train_neural_meta_learner(meta_features, labels)
            else:
                self.meta_learner.fit(meta_features, labels)
                training_results = {'meta_learner_trained': True}
            
            self.is_trained = True
            
            logger.info("Stacking ensemble training completed")
            return training_results
            
        except Exception as e:
            logger.error(f"Stacking training failed: {e}")
            return {'error': str(e)}
    
    def _generate_meta_features(self, training_data: List[str], labels: List[int]) -> np.ndarray:
        """Generate meta-features using cross-validation"""
        
        from sklearn.model_selection import StratifiedKFold
        
        n_samples = len(training_data)
        n_models = len(self.base_models)
        
        # Initialize meta-features array
        meta_features = np.zeros((n_samples, n_models))
        
        # Cross-validation to generate meta-features
        skf = StratifiedKFold(n_splits=self.cv_folds, shuffle=True, random_state=42)
        
        for train_idx, val_idx in skf.split(training_data, labels):
            # Train base models on fold training data
            for model_idx, (model_name, model) in enumerate(self.base_models.items()):
                # Simplified training - in practice would train on train_idx data
                
                # Get predictions for validation fold
                for i in val_idx:
                    # Simplified prediction
                    prediction = self._get_base_model_prediction(model, training_data[i])
                    meta_features[i, model_idx] = prediction
        
        return meta_features
    
    def _get_base_model_prediction(self, model: Any, input_data: str) -> float:
        """Get prediction from base model"""
        
        # Simplified prediction - would use actual model prediction
        if hasattr(model, 'analyze_code'):
            result = model.analyze_code(input_data)
            return result.get('confidence', 0.0)
        else:
            return np.random.random()  # Placeholder
    
    def _train_neural_meta_learner(self, meta_features: np.ndarray, labels: List[int]) -> Dict[str, Any]:
        """Train neural network meta-learner"""
        
        input_dim = meta_features.shape[1]
        self.meta_learner = self.meta_learner(input_dim)
        
        # Convert to tensors
        X_tensor = torch.FloatTensor(meta_features)
        y_tensor = torch.FloatTensor(labels).unsqueeze(1)
        
        # Training setup
        optimizer = torch.optim.Adam(self.meta_learner.parameters(), lr=0.001)
        criterion = nn.BCELoss()
        
        # Training loop
        epochs = 100
        for epoch in range(epochs):
            optimizer.zero_grad()
            outputs = self.meta_learner(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()
        
        return {
            'meta_learner_trained': True,
            'final_loss': loss.item(),
            'epochs': epochs
        }
    
    def predict_stacking(self, input_data: str) -> Dict[str, Any]:
        """Make stacking ensemble prediction"""
        
        if not self.is_trained:
            return {'error': 'Stacking ensemble not trained'}
        
        try:
            # Get base model predictions
            base_predictions = []
            for model_name, model in self.base_models.items():
                prediction = self._get_base_model_prediction(model, input_data)
                base_predictions.append(prediction)
            
            # Convert to meta-features
            meta_features = np.array(base_predictions).reshape(1, -1)
            
            # Meta-learner prediction
            if self.meta_learner_type == 'neural':
                with torch.no_grad():
                    meta_input = torch.FloatTensor(meta_features)
                    meta_prediction = self.meta_learner(meta_input).item()
            else:
                meta_prediction = self.meta_learner.predict_proba(meta_features)[0][1]
            
            return {
                'stacking_prediction': meta_prediction,
                'base_predictions': dict(zip(self.base_models.keys(), base_predictions)),
                'meta_features': meta_features.tolist()
            }
            
        except Exception as e:
            logger.error(f"Stacking prediction failed: {e}")
            return {'error': str(e)}


class EnsembleManager:
    """Main ensemble manager coordinating all ensemble methods"""
    
    def __init__(self, ensemble_config: Optional[Dict[str, Any]] = None):
        """Initialize ensemble manager"""
        
        self.config = ensemble_config or {}
        
        # Initialize ensemble methods
        self.voting_ensemble = EnsembleVotingClassifier(self.config.get('voting', {}))
        self.bma_ensemble = BayesianModelAveraging(self.config.get('bma', {}))
        self.stacking_ensemble = StackingEnsemble(self.config.get('stacking', {}))
        
        # Performance tracking
        self.ensemble_performances = {}
        
        logger.info("✅ Ensemble Manager initialized with all ensemble methods")
    
    def add_model_to_all(self, model_name: str, model: Any, weight: float = 1.0) -> Dict[str, bool]:
        """Add model to all ensemble methods"""
        
        results = {
            'voting': self.voting_ensemble.add_model(model_name, model, weight),
            'bma': self.bma_ensemble.add_model(model_name, model, weight),
            'stacking': self.stacking_ensemble.add_base_model(model_name, model)
        }
        
        logger.info(f"Model '{model_name}' added to all ensembles: {results}")
        return results
    
    def predict_all_ensembles(self, input_data: Any) -> Dict[str, Any]:
        """Get predictions from all ensemble methods"""
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'input_data_length': len(input_data) if isinstance(input_data, str) else 0,
            'ensembles': {}
        }
        
        # Voting ensemble
        try:
            voting_result = self.voting_ensemble.predict_ensemble(input_data)
            results['ensembles']['voting'] = voting_result
        except Exception as e:
            results['ensembles']['voting'] = {'error': str(e)}
        
        # BMA ensemble
        try:
            bma_result = self.bma_ensemble.predict_bma(input_data)
            results['ensembles']['bma'] = bma_result
        except Exception as e:
            results['ensembles']['bma'] = {'error': str(e)}
        
        # Stacking ensemble (if trained)
        try:
            if self.stacking_ensemble.is_trained:
                stacking_result = self.stacking_ensemble.predict_stacking(input_data)
                results['ensembles']['stacking'] = stacking_result
            else:
                results['ensembles']['stacking'] = {'status': 'not_trained'}
        except Exception as e:
            results['ensembles']['stacking'] = {'error': str(e)}
        
        # Compute ensemble of ensembles
        results['meta_ensemble'] = self._compute_meta_ensemble(results['ensembles'])
        
        return results
    
    def _compute_meta_ensemble(self, ensemble_results: Dict[str, Any]) -> Dict[str, Any]:
        """Compute meta-ensemble from all ensemble predictions"""
        
        predictions = []
        confidences = []
        
        # Collect valid predictions
        for ensemble_name, result in ensemble_results.items():
            if 'error' not in result and ensemble_name != 'stacking':
                if 'ensemble_prediction' in result:
                    predictions.append(result['ensemble_prediction'])
                    confidences.append(result.get('ensemble_confidence', 0.5))
                elif 'bma_prediction' in result:
                    predictions.append(result['bma_prediction'])
                    confidences.append(1.0 - result.get('bma_uncertainty', 0.5))
        
        if not predictions:
            return {'error': 'No valid ensemble predictions'}
        
        # Simple average of ensemble predictions
        meta_prediction = np.mean(predictions)
        meta_confidence = np.mean(confidences)
        
        return {
            'meta_prediction': meta_prediction,
            'meta_confidence': meta_confidence,
            'individual_predictions': predictions,
            'individual_confidences': confidences,
            'num_ensembles': len(predictions)
        }
    
    def get_ensemble_statistics(self) -> Dict[str, Any]:
        """Get comprehensive ensemble statistics"""
        
        return {
            'voting_ensemble': {
                'num_models': len(self.voting_ensemble.models),
                'prediction_history_length': len(self.voting_ensemble.prediction_history),
                'model_performances': self.voting_ensemble.model_performances
            },
            'bma_ensemble': {
                'num_models': len(self.bma_ensemble.model_weights),
                'current_weights': self.bma_ensemble.model_weights,
                'total_evidence': sum(len(evidence) for evidence in self.bma_ensemble.model_evidence.values())
            },
            'stacking_ensemble': {
                'num_base_models': len(self.stacking_ensemble.base_models),
                'is_trained': self.stacking_ensemble.is_trained,
                'meta_learner_type': self.stacking_ensemble.meta_learner_type
            }
        }


# Configuration templates
ENSEMBLE_CONFIG_TEMPLATES = {
    'balanced': {
        'voting': {
            'voting_strategy': 'soft',
            'confidence_threshold': 0.7
        },
        'bma': {
            'update_rate': 0.1,
            'min_samples': 10
        },
        'stacking': {
            'meta_learner': 'logistic',
            'cv_folds': 5
        }
    },
    'performance_focused': {
        'voting': {
            'voting_strategy': 'hard',
            'confidence_threshold': 0.8
        },
        'bma': {
            'update_rate': 0.2,
            'min_samples': 5
        },
        'stacking': {
            'meta_learner': 'neural',
            'cv_folds': 3
        }
    },
    'conservative': {
        'voting': {
            'voting_strategy': 'soft',
            'confidence_threshold': 0.9
        },
        'bma': {
            'update_rate': 0.05,
            'min_samples': 20
        },
        'stacking': {
            'meta_learner': 'logistic',
            'cv_folds': 10
        }
    }
} 