from typing import List, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from transformers import AutoTokenizer, AutoModel
import torch

class DecisionEngine:
    def __init__(self, api_key: str):
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.scaler = StandardScaler()
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        self.code_analyzer = AutoModel.from_pretrained("microsoft/codebert-base")
        
    async def analyze_and_decide(self,
                               current_results: List[Dict[str, Any]],
                               scan_history: List[Dict[str, Any]],
                               company_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze results and make intelligent decisions about next steps."""
        # Analyze current findings
        critical_findings = self._identify_critical_findings(current_results)
        anomalies = self._detect_result_anomalies(current_results, scan_history)
        attack_patterns = self._identify_attack_patterns(current_results)
        
        # Generate decision factors
        decision_factors = {
            'risk_factors': self._analyze_risk_factors(current_results, company_context),
            'priority_areas': self._identify_priority_areas(current_results, company_context),
            'resource_constraints': self._assess_resource_constraints(company_context),
            'compliance_requirements': self._check_compliance_requirements(company_context)
        }
        
        # Make decisions
        next_actions = self._determine_next_actions(
            critical_findings,
            anomalies,
            attack_patterns,
            decision_factors
        )
        
        return {
            'analysis': {
                'critical_findings': critical_findings,
                'anomalies': anomalies,
                'attack_patterns': attack_patterns,
                'decision_factors': decision_factors
            },
            'decisions': next_actions
        }
        
    def _identify_critical_findings(self,
                                  results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical security findings using deep learning."""
        critical_findings = []
        
        for result in results:
            findings = result.get('findings', [])
            for finding in findings:
                # Encode finding description
                inputs = self.tokenizer(finding['description'],
                                      return_tensors="pt",
                                      padding=True,
                                      truncation=True)
                
                # Get embedding
                with torch.no_grad():
                    outputs = self.code_analyzer(**inputs)
                    embedding = outputs.last_hidden_state.mean(dim=1)
                
                # Analyze severity
                severity_score = self._calculate_severity_score(finding, embedding)
                
                if severity_score > 0.8:
                    critical_findings.append({
                        **finding,
                        'severity_score': severity_score,
                        'analysis': self._analyze_finding_context(finding, embedding)
                    })
                    
        return critical_findings
        
    def _detect_result_anomalies(self,
                                current_results: List[Dict[str, Any]],
                                scan_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in scan results using isolation forest."""
        # Extract features
        features = []
        for result in scan_history + current_results:
            features.append(self._extract_result_features(result))
            
        # Fit and predict
        X = self.scaler.fit_transform(features)
        predictions = self.anomaly_detector.fit_predict(X)
        
        # Identify anomalies in current results
        anomalies = []
        start_idx = len(scan_history)
        for i, pred in enumerate(predictions[start_idx:]):
            if pred == -1:  # Anomaly
                anomalies.append({
                    'result': current_results[i],
                    'anomaly_score': self.anomaly_detector.score_samples(X[start_idx + i].reshape(1, -1))[0],
                    'features': dict(zip(self._get_feature_names(), features[start_idx + i]))
                })
                
        return anomalies
        
    def _identify_attack_patterns(self,
                                results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential attack patterns in findings."""
        # Extract relevant features
        attack_indicators = []
        for result in results:
            findings = result.get('findings', [])
            for finding in findings:
                indicators = self._extract_attack_indicators(finding)
                if indicators:
                    attack_indicators.append(indicators)
                    
        # Cluster similar patterns
        if attack_indicators:
            patterns = self._cluster_attack_patterns(attack_indicators)
            return self._analyze_attack_patterns(patterns)
        
        return []
        
    def _determine_next_actions(self,
                              critical_findings: List[Dict[str, Any]],
                              anomalies: List[Dict[str, Any]],
                              attack_patterns: List[Dict[str, Any]],
                              decision_factors: Dict[str, Any]) -> Dict[str, Any]:
        """Determine next actions based on analysis."""
        actions = {
            'immediate_actions': [],
            'recommended_scans': [],
            'adjustments': [],
            'notifications': []
        }
        
        # Handle critical findings
        if critical_findings:
            actions['immediate_actions'].extend(
                self._generate_critical_actions(critical_findings)
            )
            
        # Handle anomalies
        if anomalies:
            actions['recommended_scans'].extend(
                self._generate_anomaly_scans(anomalies)
            )
            
        # Handle attack patterns
        if attack_patterns:
            pattern_actions = self._generate_pattern_actions(attack_patterns)
            actions['immediate_actions'].extend(pattern_actions['immediate'])
            actions['recommended_scans'].extend(pattern_actions['scans'])
            
        # Consider decision factors
        actions['adjustments'] = self._generate_adjustments(decision_factors)
        
        # Generate notifications
        actions['notifications'] = self._generate_notifications(
            critical_findings,
            anomalies,
            attack_patterns,
            decision_factors
        )
        
        return actions 