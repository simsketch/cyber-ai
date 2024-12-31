import asyncio
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from datetime import datetime
import json
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from db.connection import init_db
from models.scan import Scan, ScanStatus, Vulnerability
from models.user import User
from models.report import Report, ReportType

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

@app.post("/api/v1/scans")
async def start_scan(request: Request, scan_request: ScanRequest):
    """Start a new scan"""
    try:
        # Get user_id from header first, fallback to request body
        user_id = request.headers.get('X-User-ID') or scan_request.user_id
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        # Create new scan document
        scan = Scan(
            target=scan_request.target,
            status=ScanStatus.PENDING,
            scan_type=scan_request.scan_type,
            scan_options=scan_request.scan_options,
            user_id=user_id  # Use the user_id we got from header or body
        )
        await scan.insert()
        
        # Start scan in background
        asyncio.create_task(run_scan(scan.id, scan_request.target, user_id))
        
        return {
            "id": str(scan.id),
            "status": scan.status,
            "target": scan.target
        }
    except Exception as e:
        print(f"Error starting scan: {e}")  # Add debug logging
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans")
async def get_scans(request: Request):
    """Get all scans for a user"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")
            
        print(f"Received request for scans with user_id: {user_id}")  # Debug log
        scans = await Scan.find(
            {
                "$or": [
                    {"user_id": user_id},
                    {"user_id": "default-user"}  # Include default user reports for development
                ]
            }
        ).sort(-Scan.started_at).to_list()
        print(f"Found {len(scans)} scans")  # Debug log
        
        return [
            {
                "id": str(scan.id),
                "target": scan.target,
                "status": scan.status,
                "user_id": scan.user_id,
                "vulnerabilities": [vuln.dict() for vuln in scan.vulnerabilities],
                "total_vulnerabilities": scan.total_vulnerabilities,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "error": scan.error,
                "scan_type": scan.scan_type,
                "scan_options": scan.scan_options
            }
            for scan in scans
        ]
    except Exception as e:
        print(f"Error fetching scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    """Get scan by ID"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        scan = await Scan.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Check if scan belongs to user
        if scan.user_id != user_id and scan.user_id != "default-user":
            raise HTTPException(status_code=403, detail="Not authorized to access this scan")
            
        return scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scans/{scan_id}/cancel")
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

async def run_scan(scan_id: str, target: str, user_id: str):
    """Run scan in background"""
    try:
        # Update scan status
        scan = await Scan.get(scan_id)
        scan.status = ScanStatus.IN_PROGRESS
        await scan.save()
        
        # Initialize orchestrator
        orchestrator = SecurityOrchestrator(target)
        
        # Run each scanner
        all_vulnerabilities = []
        for scanner_name in orchestrator.scan_order:
            result = await orchestrator.run_scan(scanner_name)
            
            # Handle vulnerability scanner results
            if scanner_name == 'vulnerability' and 'vulnerabilities' in result:
                for vuln_type, vulns in result['vulnerabilities'].items():
                    for vuln in vulns:
                        severity = "high" if vuln['potentially_vulnerable'] else "medium"
                        description = f"Found {vuln_type} vulnerability with payload: {vuln['payload']}"
                        if vuln['get_test']['reflected']:
                            description += f"\nReflected in GET request at {vuln['get_test']['url']}"
                        if vuln['post_test']['reflected']:
                            description += f"\nReflected in POST request at {vuln['post_test']['url']}"
                        
                        all_vulnerabilities.append(
                            Vulnerability(
                                title=f"Potential {vuln_type.upper()} Vulnerability",
                                description=description,
                                severity=severity,
                                remediation=f"Review and sanitize inputs for {vuln_type} attacks"
                            )
                        )
            
            # Handle other scanner results
            elif 'findings' in result:
                for finding in result.get('findings', []):
                    if isinstance(finding, dict):
                        all_vulnerabilities.append(
                            Vulnerability(
                                title=finding.get('title', 'Unknown Finding'),
                                description=finding.get('description', ''),
                                severity=finding.get('severity', 'low'),
                                remediation=finding.get('remediation', '')
                            )
                        )
                    elif isinstance(finding, str):
                        all_vulnerabilities.append(
                            Vulnerability(
                                title="Finding",
                                description=finding,
                                severity="low",
                                remediation="Review and address the finding"
                            )
                        )
        
        # Update scan with all found vulnerabilities
        scan.vulnerabilities = all_vulnerabilities
        scan.total_vulnerabilities = len(all_vulnerabilities)
        await scan.save()
        
        # Mark scan as completed
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        await scan.save()
        
        # Before passing to generate_report, convert vulnerabilities to dicts
        vulnerabilities_dict = [
            {
                "title": vuln.title,
                "description": vuln.description,
                "severity": vuln.severity,
                "remediation": vuln.remediation,
                "cvss_score": vuln.cvss_score if hasattr(vuln, 'cvss_score') else None,
                "cve_id": vuln.cve_id if hasattr(vuln, 'cve_id') else None,
            }
            for vuln in all_vulnerabilities
        ]
        
        # Generate markdown report using LLM with dict version
        scan_agent = ScanAgent(target=target, api_key=os.getenv('OPENAI_API_KEY'))
        markdown_report = await scan_agent.generate_report(vulnerabilities_dict)
        
        # Create report with markdown content
        report = Report(
            title=f"Vulnerability Scan Report - {target}",
            type=ReportType.VULNERABILITY,
            description=f"Automated vulnerability scan report for {target}",
            data={
                "scan_id": str(scan_id),
                "target": target,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "vulnerabilities": [vuln.dict() for vuln in scan.vulnerabilities],
                "scan_duration": (scan.completed_at - scan.started_at).total_seconds(),
                "findings_summary": {
                    "high": len([v for v in scan.vulnerabilities if v.severity == "high"]),
                    "medium": len([v for v in scan.vulnerabilities if v.severity == "medium"]),
                    "low": len([v for v in scan.vulnerabilities if v.severity == "low"])
                }
            },
            markdown_content=markdown_report,
            user_id=user_id,
            scan_ids=[str(scan_id)]
        )
        await report.insert()
        
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

@app.get("/api/v1/reports")
async def get_reports(request: Request):
    """Get all reports for a user"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        reports = await Report.find(
            {
                "$or": [
                    {"user_id": user_id},
                    {"user_id": "default-user"}
                ]
            }
        ).sort(-Report.generated_at).to_list()
        
        print(f"Found {len(reports)} reports for user {user_id}")
        
        # Transform reports to ensure all required fields exist
        transformed_reports = []
        for report in reports:
            transformed = {
                "_id": str(report.id),
                "scan_ids": report.scan_ids,
                "generated_at": report.generated_at.isoformat() if report.generated_at else None,
                "user_id": report.user_id,
                "data": report.data or {},
                "markdown_content": report.markdown_content or ""  # Provide empty string if None
            }
            transformed_reports.append(transformed)
        
        return transformed_reports
    except Exception as e:
        print(f"Error in get_reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/reports/{report_id}")
async def get_report(report_id: str, request: Request):
    """Get report by ID"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        report = await Report.get(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
            
        # Check if report belongs to user
        if report.user_id != user_id and report.user_id != "default-user":
            raise HTTPException(status_code=403, detail="Not authorized to access this report")
            
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans/{scan_id}/report")
async def get_scan_report(scan_id: str, request: Request):
    """Get report for a specific scan"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        report = await Report.find_one(Report.scan_ids.contains(scan_id))
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
            
        # Check if report belongs to user
        if report.user_id != user_id and report.user_id != "default-user":
            raise HTTPException(status_code=403, detail="Not authorized to access this report")
            
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)