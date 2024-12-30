from typing import List, Dict, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import pandas as pd
from dataclasses import dataclass

@dataclass
class ScanConfig:
    scan_type: str
    parameters: Dict[str, Any]
    estimated_duration: float
    resource_usage: Dict[str, float]
    expected_value: float

class ScanOptimizer:
    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=100)
        self.scaler = StandardScaler()
        self.value_predictor = ValuePredictor()
        self.scan_history = []
        
    def optimize_scan_plan(self,
                          available_scans: List[Dict[str, Any]],
                          context: Dict[str, Any],
                          constraints: Dict[str, Any]) -> List[ScanConfig]:
        """Optimize the scan plan based on context and constraints."""
        # Predict value of each scan
        scan_values = self._predict_scan_values(available_scans, context)
        
        # Generate candidate configurations
        candidates = self._generate_scan_configs(available_scans, scan_values)
        
        # Apply constraints
        valid_candidates = self._apply_constraints(candidates, constraints)
        
        # Optimize sequence
        optimized_sequence = self._optimize_sequence(valid_candidates, context)
        
        return optimized_sequence
        
    def update_models(self, scan_results: List[Dict[str, Any]]):
        """Update ML models with new scan results."""
        self.scan_history.extend(scan_results)
        
        # Extract features and labels
        X, y = self._prepare_training_data(self.scan_history)
        
        # Update random forest model
        self.rf_model.fit(X, y)
        
        # Update value predictor
        self.value_predictor.train(self.scan_history)
        
    def _predict_scan_values(self,
                           scans: List[Dict[str, Any]],
                           context: Dict[str, Any]) -> List[float]:
        """Predict the value of each potential scan."""
        values = []
        
        for scan in scans:
            # Extract features
            features = self._extract_scan_features(scan, context)
            
            # Get predictions from both models
            rf_pred = self.rf_model.predict_proba(features.reshape(1, -1))[0][1]
            value_pred = self.value_predictor.predict(scan, context)
            
            # Combine predictions
            combined_value = (rf_pred + value_pred) / 2
            values.append(combined_value)
            
        return values
        
    def _generate_scan_configs(self,
                             scans: List[Dict[str, Any]],
                             values: List[float]) -> List[ScanConfig]:
        """Generate scan configurations with different parameter sets."""
        configs = []
        
        for scan, value in zip(scans, values):
            # Generate parameter variations
            param_sets = self._generate_parameter_sets(scan)
            
            for params in param_sets:
                configs.append(ScanConfig(
                    scan_type=scan['type'],
                    parameters=params,
                    estimated_duration=self._estimate_duration(scan, params),
                    resource_usage=self._estimate_resource_usage(scan, params),
                    expected_value=value * self._parameter_value_modifier(params)
                ))
                
        return configs
        
    def _apply_constraints(self,
                         configs: List[ScanConfig],
                         constraints: Dict[str, Any]) -> List[ScanConfig]:
        """Apply resource and time constraints to configurations."""
        valid_configs = []
        
        for config in configs:
            if self._check_time_constraint(config, constraints.get('max_duration')):
                if self._check_resource_constraints(config, constraints.get('resources')):
                    valid_configs.append(config)
                    
        return valid_configs
        
    def _optimize_sequence(self,
                         configs: List[ScanConfig],
                         context: Dict[str, Any]) -> List[ScanConfig]:
        """Optimize the sequence of scans using dynamic programming."""
        n = len(configs)
        if n == 0:
            return []
            
        # Create value matrix
        dp = np.zeros((n + 1, n + 1))
        for i in range(1, n + 1):
            for j in range(i, n + 1):
                sequence = configs[i-1:j]
                dp[i][j] = self._calculate_sequence_value(sequence, context)
                
        # Find optimal sequence
        optimal_sequence = self._find_optimal_sequence(dp, configs)
        
        return optimal_sequence
        
    def _calculate_sequence_value(self,
                                sequence: List[ScanConfig],
                                context: Dict[str, Any]) -> float:
        """Calculate the total value of a scan sequence."""
        base_value = sum(config.expected_value for config in sequence)
        
        # Apply sequence-specific modifiers
        coverage_bonus = self._calculate_coverage_bonus(sequence)
        dependency_penalty = self._calculate_dependency_penalty(sequence)
        context_relevance = self._calculate_context_relevance(sequence, context)
        
        return base_value * (1 + coverage_bonus - dependency_penalty) * context_relevance
        
    def _find_optimal_sequence(self,
                             dp: np.ndarray,
                             configs: List[ScanConfig]) -> List[ScanConfig]:
        """Find the optimal sequence using dynamic programming results."""
        n = len(dp) - 1
        optimal_indices = []
        
        i = 1
        while i <= n:
            max_value = dp[i][i]
            best_j = i
            
            for j in range(i + 1, n + 1):
                if dp[i][j] > max_value:
                    max_value = dp[i][j]
                    best_j = j
                    
            optimal_indices.extend(range(i - 1, best_j))
            i = best_j + 1
            
        return [configs[i] for i in optimal_indices]

class ValuePredictor(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU()
        )
        
        self.predictor = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
        
    def forward(self, x):
        encoded = self.encoder(x)
        return self.predictor(encoded) 