from typing import List, Dict, Any
import asyncio
from datetime import datetime
import aiohttp
from collections import deque
import numpy as np
from dataclasses import dataclass
import json

@dataclass
class Alert:
    severity: str
    message: str
    timestamp: datetime
    finding_id: str
    context: Dict[str, Any]
    recommended_actions: List[str]

class SecurityMonitor:
    def __init__(self):
        self.alert_history = deque(maxlen=1000)
        self.baseline_metrics = {}
        self.anomaly_thresholds = {}
        self.active_scans = set()
        
    async def monitor_scan(self, scan_id: str, scan_executor: Any):
        """Monitor a scan in real-time."""
        self.active_scans.add(scan_id)
        
        try:
            while scan_id in self.active_scans:
                scan_status = scan_executor.get_scan_status(scan_id)
                
                if scan_status['status'] == 'completed':
                    await self._process_scan_completion(scan_id, scan_executor)
                    break
                    
                if scan_status['status'] == 'failed':
                    await self._handle_scan_failure(scan_id, scan_status)
                    break
                    
                # Monitor current scan progress
                current_scan = scan_status['current_scan']
                if current_scan:
                    await self._monitor_current_scan(scan_id, current_scan, scan_executor)
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
        except Exception as e:
            await self._create_alert(
                'HIGH',
                f"Error monitoring scan {scan_id}: {str(e)}",
                scan_id,
                {'error': str(e)},
                ['Check scan executor logs', 'Verify scan configuration']
            )
        finally:
            self.active_scans.remove(scan_id)
            
    async def _monitor_current_scan(self,
                                  scan_id: str,
                                  current_scan: str,
                                  scan_executor: Any):
        """Monitor the currently running scan."""
        # Get latest results
        results = scan_executor.get_scan_results(scan_id)
        latest_result = next((r for r in results 
                            if r['scan_type'] == current_scan), None)
        
        if latest_result:
            # Check for anomalies
            anomalies = self._detect_anomalies(current_scan, latest_result)
            if anomalies:
                await self._handle_anomalies(scan_id, anomalies)
            
            # Check for critical findings
            critical_findings = self._identify_critical_findings(latest_result)
            if critical_findings:
                await self._handle_critical_findings(scan_id, critical_findings)
            
            # Update baseline metrics
            self._update_baseline(current_scan, latest_result)
            
    async def _handle_anomalies(self, scan_id: str, anomalies: List[Dict[str, Any]]):
        """Handle detected anomalies."""
        for anomaly in anomalies:
            severity = 'HIGH' if anomaly['deviation'] > 3 else 'MEDIUM'
            
            await self._create_alert(
                severity,
                f"Anomaly detected in {anomaly['metric']}: {anomaly['details']}",
                scan_id,
                anomaly,
                self._generate_anomaly_recommendations(anomaly)
            )
            
    async def _handle_critical_findings(self,
                                      scan_id: str,
                                      findings: List[Dict[str, Any]]):
        """Handle critical security findings."""
        for finding in findings:
            await self._create_alert(
                'CRITICAL',
                f"Critical security finding: {finding['name']}",
                scan_id,
                finding,
                self._generate_finding_recommendations(finding)
            )
            
    async def _create_alert(self,
                           severity: str,
                           message: str,
                           finding_id: str,
                           context: Dict[str, Any],
                           recommended_actions: List[str]):
        """Create and store a new alert."""
        alert = Alert(
            severity=severity,
            message=message,
            timestamp=datetime.now(),
            finding_id=finding_id,
            context=context,
            recommended_actions=recommended_actions
        )
        
        self.alert_history.append(alert)
        
        # Trigger real-time notifications
        await self._send_notifications(alert)
        
    def _detect_anomalies(self,
                         scan_type: str,
                         result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in scan results."""
        anomalies = []
        baseline = self.baseline_metrics.get(scan_type, {})
        thresholds = self.anomaly_thresholds.get(scan_type, {})
        
        for metric, value in self._extract_metrics(result).items():
            if metric in baseline:
                mean = baseline[metric]['mean']
                std = baseline[metric]['std']
                
                if std > 0:
                    deviation = abs(value - mean) / std
                    threshold = thresholds.get(metric, 2.0)
                    
                    if deviation > threshold:
                        anomalies.append({
                            'metric': metric,
                            'value': value,
                            'baseline_mean': mean,
                            'deviation': deviation,
                            'threshold': threshold,
                            'details': f"Value {value} deviates significantly from baseline {mean:.2f}"
                        })
                        
        return anomalies
        
    def _update_baseline(self, scan_type: str, result: Dict[str, Any]):
        """Update baseline metrics with new results."""
        metrics = self._extract_metrics(result)
        
        if scan_type not in self.baseline_metrics:
            self.baseline_metrics[scan_type] = {}
            
        for metric, value in metrics.items():
            if metric not in self.baseline_metrics[scan_type]:
                self.baseline_metrics[scan_type][metric] = {
                    'mean': value,
                    'std': 0,
                    'count': 1,
                    'values': [value]
                }
            else:
                baseline = self.baseline_metrics[scan_type][metric]
                baseline['values'].append(value)
                baseline['count'] += 1
                baseline['mean'] = np.mean(baseline['values'])
                baseline['std'] = np.std(baseline['values'])
                
    async def _send_notifications(self, alert: Alert):
        """Send real-time notifications for alerts."""
        # Implementation would depend on notification channels (e.g., Slack, email, SMS)
        pass 