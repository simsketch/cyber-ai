from typing import Dict, Any, List
import asyncio
from datetime import datetime
import uuid
from scanners.domain_finder import DomainFinder
from scanners.port_scanner import PortScanner
from scanners.subdomain_finder import SubdomainFinder
from scanners.waf_detector import WAFDetector
from scanners.url_fuzzer import URLFuzzer
from scanners.tech_detector import TechDetector
from scanners.vulnerability_scanner import VulnerabilityScanner
from enum import Enum
from asyncio import Lock

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanExecutor:
    def __init__(self):
        self.scan_registry = {}  # Store scan status and results
        self.locks = {}  # Store locks for each scan
        
    async def execute_scan_plan(self, scan_plan: Dict[str, Any], domain: str) -> str:
        """Execute a scan plan and return scan ID."""
        scan_id = str(uuid.uuid4())
        
        # Initialize scan record
        self.scan_registry[scan_id] = {
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'domain': domain,
            'results': [],
            'current_scan': None,
            'completed_scans': [],
            'plan': scan_plan
        }
        
        # Start execution in background
        asyncio.create_task(self._run_scans(scan_id))
        
        return scan_id
    
    async def _run_scans(self, scan_id: str):
        """Run scans according to plan with pause support."""
        scan_record = self.scan_registry[scan_id]
        plan = scan_record['plan']
        domain = scan_record['domain']
        
        # Create lock if it doesn't exist
        if scan_id not in self.locks:
            self.locks[scan_id] = Lock()
        
        try:
            for scan_config in plan['priority_scans']:
                # Check if scan is paused
                async with self.locks[scan_id]:
                    if scan_record['status'] == ScanStatus.PAUSED.value:
                        return
                
                scan_type = scan_config['type']
                params = scan_config.get('params', {})
                
                # Update current scan
                scan_record['current_scan'] = scan_type
                
                # Initialize and run scanner
                scanner = self.scanners[scan_type](domain)
                result = await scanner.scan()
                
                # Store results
                scan_record['results'].append({
                    'scan_type': scan_type,
                    'timestamp': datetime.now().isoformat(),
                    'results': result
                })
                
                scan_record['completed_scans'].append(scan_type)
                
                # Check if we need to adjust the plan
                if result.get('attack_surface', {}).get('risk_level') == 'HIGH':
                    await self._adjust_scan_plan(scan_id, result)
            
            scan_record['status'] = ScanStatus.COMPLETED.value
            scan_record['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            scan_record['status'] = ScanStatus.FAILED.value
            scan_record['error'] = str(e)
    
    async def _adjust_scan_plan(self, scan_id: str, latest_results: Dict[str, Any]):
        """Adjust scan plan based on findings."""
        scan_record = self.scan_registry[scan_id]
        plan = scan_record['plan']
        
        # Extract relevant information from latest results
        risk_level = latest_results.get('attack_surface', {}).get('risk_level')
        findings = latest_results.get('findings', [])
        scan_type = latest_results.get('scan_type')
        
        new_scans = []
        
        if risk_level == 'HIGH':
            if scan_type == 'port':
                # If high-risk ports found, add targeted vulnerability scans
                open_ports = [f for f in findings if f.get('status') == 'open']
                for port in open_ports:
                    new_scans.append({
                        'type': 'vulnerability',
                        'params': {
                            'port': port['number'],
                            'service': port.get('service'),
                            'depth': 'deep'
                        }
                    })
                    
            elif scan_type == 'subdomain':
                # If interesting subdomains found, scan them too
                for subdomain in findings:
                    new_scans.append({
                        'type': 'domain',
                        'params': {'target': subdomain['name']}
                    })
                    new_scans.append({
                        'type': 'port',
                        'params': {'target': subdomain['name']}
                    })
                    
            elif scan_type == 'tech':
                # If vulnerable technologies detected, add specific checks
                for tech in findings:
                    if tech.get('version'):
                        new_scans.append({
                            'type': 'vulnerability',
                            'params': {
                                'technology': tech['name'],
                                'version': tech['version'],
                                'depth': 'focused'
                            }
                        })
        
        # Add new scans to plan
        if new_scans:
            plan['priority_scans'].extend(new_scans)
            scan_record['plan'] = plan
    
    async def pause_scan(self, scan_id: str):
        """Pause a running scan."""
        if scan_id not in self.scan_registry:
            raise KeyError(f"Scan ID {scan_id} not found")
            
        scan_record = self.scan_registry[scan_id]
        if scan_record['status'] != ScanStatus.RUNNING.value:
            raise ValueError(f"Scan {scan_id} is not running")
            
        scan_record['status'] = ScanStatus.PAUSED.value
        scan_record['pause_time'] = datetime.now().isoformat()
        
    async def resume_scan(self, scan_id: str):
        """Resume a paused scan."""
        if scan_id not in self.scan_registry:
            raise KeyError(f"Scan ID {scan_id} not found")
            
        scan_record = self.scan_registry[scan_id]
        if scan_record['status'] != ScanStatus.PAUSED.value:
            raise ValueError(f"Scan {scan_id} is not paused")
            
        scan_record['status'] = ScanStatus.RUNNING.value
        scan_record['resume_time'] = datetime.now().isoformat()
        
        # Resume scan execution
        asyncio.create_task(self._resume_scan_execution(scan_id))
        
    async def _resume_scan_execution(self, scan_id: str):
        """Resume scan execution from the last completed scan."""
        scan_record = self.scan_registry[scan_id]
        plan = scan_record['plan']
        
        # Find the last completed scan
        completed_scans = set(scan_record['completed_scans'])
        remaining_scans = [
            scan for scan in plan['priority_scans']
            if scan['type'] not in completed_scans
        ]
        
        # Update plan with remaining scans
        plan['priority_scans'] = remaining_scans
        scan_record['plan'] = plan
        
        # Continue execution
        await self._run_scans(scan_id)
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of a scan."""
        if scan_id not in self.scan_registry:
            raise KeyError(f"Scan ID {scan_id} not found")
            
        scan_record = self.scan_registry[scan_id]
        return {
            'status': scan_record['status'],
            'current_scan': scan_record['current_scan'],
            'completed_scans': scan_record['completed_scans'],
            'start_time': scan_record['start_time'],
            'end_time': scan_record.get('end_time'),
            'error': scan_record.get('error')
        }
    
    def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get results of a completed scan."""
        if scan_id not in self.scan_registry:
            raise KeyError(f"Scan ID {scan_id} not found")
            
        scan_record = self.scan_registry[scan_id]
        if scan_record['status'] != 'completed':
            raise ValueError(f"Scan {scan_id} is not completed")
            
        return scan_record['results'] 