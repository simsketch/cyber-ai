import asyncio
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from datetime import datetime
import json
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.scan_agent import ScanAgent
from scanners.domain_finder import DomainFinder
from scanners.port_scanner import PortScanner
from scanners.subdomain_finder import SubdomainFinder
from scanners.waf_detector import WAFDetector
from scanners.url_fuzzer import URLFuzzer
from scanners.tech_detector import TechDetector
from scanners.vulnerability_scanner import VulnerabilityScanner

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://localhost:3002"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    scanners: List[str] = []

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

@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    try:
        orchestrator = SecurityOrchestrator(target=request.target)
        results = await orchestrator.scan_target(request.scanners)
        return {"status": "success", "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans")
async def get_scans():
    try:
        output_dir = 'data/scan_results'
        if not os.path.exists(output_dir):
            return {"scans": []}
            
        scans = []
        for file in os.listdir(output_dir):
            if file.endswith('.json'):
                with open(os.path.join(output_dir, file), 'r') as f:
                    scan_data = json.load(f)
                    scans.append({
                        "id": file.replace('scan_', '').replace('.json', ''),
                        "results": scan_data
                    })
        return {"scans": scans}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)