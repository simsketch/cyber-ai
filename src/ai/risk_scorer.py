from typing import List, Dict, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path

class RiskScorer:
    def __init__(self):
        self.model_path = Path('models/risk_scorer.joblib')
        self.scaler_path = Path('models/scaler.joblib')
        
        # Load or train model
        if self.model_path.exists() and self.scaler_path.exists():
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
        else:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.scaler = StandardScaler()
            
    def calculate_risk_score(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk score using machine learning model."""
        # Extract features
        features = self._extract_features(scan_results)
        
        # Scale features
        scaled_features = self.scaler.transform([features])
        
        # Predict risk score
        risk_score = self.model.predict_proba(scaled_features)[0]
        
        # Calculate confidence scores for different aspects
        confidence_scores = self._calculate_confidence_scores(features)
        
        return {
            'overall_risk_score': float(risk_score[1]),  # Probability of high risk
            'risk_level': self._get_risk_level(risk_score[1]),
            'confidence_scores': confidence_scores,
            'contributing_factors': self._get_contributing_factors(features, self.model)
        }
    
    def _extract_features(self, scan_results: List[Dict[str, Any]]) -> np.ndarray:
        """Extract numerical features from scan results."""
        features = {
            'num_critical_vulns': 0,
            'num_high_vulns': 0,
            'num_medium_vulns': 0,
            'num_low_vulns': 0,
            'num_open_ports': 0,
            'num_sensitive_ports': 0,
            'num_subdomains': 0,
            'num_outdated_tech': 0,
            'num_critical_findings': 0,
            'waf_detected': 0,
            'ssl_issues': 0
        }
        
        for result in scan_results:
            scan_type = result.get('scan_type')
            scan_results = result.get('results', {})
            
            if scan_type == 'vulnerability':
                for finding in scan_results.get('findings', []):
                    severity = finding.get('severity', 'LOW')
                    features[f'num_{severity.lower()}_vulns'] += 1
                    
            elif scan_type == 'port':
                features['num_open_ports'] = len(scan_results.get('open_ports', []))
                features['num_sensitive_ports'] = len([
                    p for p in scan_results.get('open_ports', [])
                    if p.get('number') in {21, 22, 23, 3389, 5432, 3306, 1433}
                ])
                
            elif scan_type == 'subdomain':
                features['num_subdomains'] = len(scan_results.get('subdomains', []))
                
            elif scan_type == 'tech':
                features['num_outdated_tech'] = len([
                    t for t in scan_results.get('technologies', [])
                    if t.get('is_outdated', False)
                ])
                
            elif scan_type == 'waf':
                features['waf_detected'] = int(scan_results.get('waf_detected', False))
                
        return np.array(list(features.values()))
    
    def _calculate_confidence_scores(self, features: np.ndarray) -> Dict[str, float]:
        """Calculate confidence scores for different security aspects."""
        return {
            'vulnerability_management': self._calculate_vuln_confidence(features),
            'network_security': self._calculate_network_confidence(features),
            'web_security': self._calculate_web_confidence(features),
            'overall_security_posture': self._calculate_overall_confidence(features)
        }
    
    def _get_contributing_factors(self, 
                                features: np.ndarray,
                                model: RandomForestClassifier) -> List[Dict[str, Any]]:
        """Get factors contributing most to the risk score."""
        feature_importance = model.feature_importances_
        feature_names = [
            'Critical Vulnerabilities',
            'High Vulnerabilities',
            'Medium Vulnerabilities',
            'Low Vulnerabilities',
            'Open Ports',
            'Sensitive Ports',
            'Subdomains',
            'Outdated Technologies',
            'Critical Findings',
            'WAF Protection',
            'SSL Issues'
        ]
        
        # Sort features by importance
        sorted_idx = np.argsort(feature_importance)
        top_features = []
        
        for idx in sorted_idx[-5:]:  # Get top 5 contributing factors
            top_features.append({
                'factor': feature_names[idx],
                'importance': float(feature_importance[idx]),
                'value': float(features[idx])
            })
            
        return top_features
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 0.8:
            return 'CRITICAL'
        elif risk_score >= 0.6:
            return 'HIGH'
        elif risk_score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW' 