import asyncio
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from datetime import datetime
import json
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from db.connection import init_db
from models.scan import Scan, ScanStatus, Vulnerability
from models.user import User
from models.report import Report

from agents.scan_agent import ScanAgent
from scanners.domain_finder import DomainFinder
from scanners.port_scanner import PortScanner
from scanners.subdomain_finder import SubdomainFinder
from scanners.waf_detector import WAFDetector
from scanners.url_fuzzer import URLFuzzer
from scanners.tech_detector import TechDetector
from scanners.vulnerability_scanner import VulnerabilityScanner

app = FastAPI(title="Cyber AI API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize connections and resources"""
    await init_db()

@app.get("/")
async def root():
    return {"message": "Cyber AI API is running"}

class ScanRequest(BaseModel):
    target: str
    user_id: str
    scan_type: str = "network"
    scan_options: dict = {}

@app.post("/api/scans")
async def start_scan(request: ScanRequest):
    """Start a new scan"""
    try:
        # Create new scan document
        scan = Scan(
            target=request.target,
            status=ScanStatus.PENDING,
            scan_type=request.scan_type,
            scan_options=request.scan_options
        )
        await scan.insert()
        
        # Start scan in background
        asyncio.create_task(run_scan(scan.id, request.target))
        
        return {
            "id": str(scan.id),
            "status": scan.status,
            "target": scan.target
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans")
async def get_scans(user_id: str):
    """Get all scans for a user"""
    try:
        scans = await Scan.find_all().to_list()
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan by ID"""
    try:
        scan = await Scan.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running scan"""
    try:
        scan = await Scan.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        if scan.status == ScanStatus.IN_PROGRESS:
            scan.status = ScanStatus.FAILED
            scan.error = "Cancelled by user"
            await scan.save()
            
        return {"message": "Scan cancelled successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def run_scan(scan_id: str, target: str):
    """Run scan in background"""
    try:
        # Update scan status
        scan = await Scan.get(scan_id)
        scan.status = ScanStatus.IN_PROGRESS
        await scan.save()
        
        # Initialize orchestrator
        orchestrator = SecurityOrchestrator(target)
        
        # Run each scanner
        for scanner_name in orchestrator.scan_order:
            result = await orchestrator.run_scan(scanner_name)
            
            # Update vulnerabilities if found
            if 'vulnerabilities' in result:
                for vuln in result['vulnerabilities']:
                    scan.vulnerabilities.append(
                        Vulnerability(
                            title=vuln['title'],
                            description=vuln['description'],
                            severity=vuln['severity'],
                            cvss_score=vuln.get('cvss_score'),
                            cve_id=vuln.get('cve_id'),
                            remediation=vuln.get('remediation')
                        )
                    )
                scan.total_vulnerabilities = len(scan.vulnerabilities)
                await scan.save()
        
        # Mark scan as completed
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        await scan.save()
        
    except Exception as e:
        # Update scan with error
        scan = await Scan.get(scan_id)
        scan.status = ScanStatus.FAILED
        scan.error = str(e)
        await scan.save()
        raise

class SecurityOrchestrator:
    def __init__(self, target: str):
        load_dotenv()
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.target = target
        
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
            
        self.scan_agent = ScanAgent(target=self.target, api_key=self.openai_api_key)
        self.console = Console()
        
        # Initialize all scanners
        self.scanners = {
            'domain': DomainFinder(target=self.target),
            'subdomain': SubdomainFinder(target=self.target),
            'port': PortScanner(target=self.target),
            'tech': TechDetector(target=self.target),
            'waf': WAFDetector(target=self.target),
            'fuzzer': URLFuzzer(target=self.target),
            'vulnerability': VulnerabilityScanner(target=self.target)
        }
        
        # Define scan order and dependencies
        self.scan_order = [
            'domain',      # Start with basic domain info
            'subdomain',   # Find subdomains
            'port',        # Scan ports on main domain and subdomains
            'tech',        # Identify technologies
            'waf',         # Detect WAF
            'fuzzer',      # Find sensitive URLs
            'vulnerability' # Test for vulnerabilities
        ]
        
        self.results_history = []
        
    async def run_scan(self, scanner_name: str) -> Dict[str, Any]:
        scanner = self.scanners.get(scanner_name)
        if not scanner:
            return {'error': f'Scanner {scanner_name} not found'}
            
        result = await scanner.scan()
        return result
        
    async def scan_target(self, selected_scanners: List[str] = None):
        scan_order = selected_scanners if selected_scanners else self.scan_order
        results = []
        
        for scanner_name in scan_order:
            if scanner_name not in self.scanners:
                continue
                
            result = await self.run_scan(scanner_name)
            results.append({
                'scan_type': scanner_name,
                'timestamp': datetime.now().isoformat(),
                'results': result
            })
        
        # Save results
        output_dir = 'data/scan_results'
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"{output_dir}/scan_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)