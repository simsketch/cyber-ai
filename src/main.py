import asyncio
import os
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from datetime import datetime
import json
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from db.connection import init_db, get_db
from models.scan import Scan, ScanStatus, Vulnerability
from models.user import User
from models.report import Report, ReportType
import logging
from bson import ObjectId

from agents.scan_agent import ScanAgent
from scanners.domain_finder import DomainFinder
from scanners.port_scanner import PortScanner
from scanners.subdomain_finder import SubdomainFinder
from scanners.waf_detector import WAFDetector
from scanners.url_fuzzer import URLFuzzer
from scanners.tech_detector import TechDetector
from scanners.vulnerability_scanner import VulnerabilityScanner

# Models
class ScanCreate(BaseModel):
    target: str
    user_id: str
    comprehensive: bool = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        # Configure cache directory
        CACHE_DIR = "/tmp/cyber-ai-cache"
        os.makedirs(CACHE_DIR, exist_ok=True)
        os.environ["SCANNER_CACHE_DIR"] = CACHE_DIR
        
        # Ensure cache directory exists and has correct permissions
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            os.chmod(CACHE_DIR, 0o777)  # Allow all users to write to cache
        except Exception as e:
            logging.error(f"Failed to set cache directory permissions: {e}")
        
        # Initialize database
        await init_db()
        logging.info("Database initialized")
    except Exception as e:
        logging.error(f"Startup error: {e}")
        raise
    yield
    # Shutdown
    # Clean up any background tasks or connections here
    pass

app = FastAPI(title="Cyber AI API", lifespan=lifespan)
active_scans = {}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend development server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def run_scan_in_background(scan_id: str, target: str, user_id: str):
    """Run a scan in the background"""
    db = await get_db()
    try:
        logging.info(f"Starting scan {scan_id} for target {target}")
        
        # Update scan status to in-progress and set started_at
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": ScanStatus.IN_PROGRESS.value,
                    "started_at": datetime.utcnow(),
                    "progress": 0
                }
            }
        )
        logging.info(f"Updated scan {scan_id} status to in-progress")
        
        # Initialize scanners
        logging.info(f"Initializing scanners for {target}")
        subdomain_finder = SubdomainFinder(target)
        port_scanner = PortScanner(target)
        vuln_scanner = VulnerabilityScanner(target)
        
        # Run subdomain enumeration
        subdomain_results = None
        try:
            logging.info(f"Starting subdomain enumeration for {target}")
            async with asyncio.timeout(300):  # 5 minute timeout for subdomain enumeration
                subdomain_results = await subdomain_finder.scan()
                if subdomain_results:
                    logging.info(f"Subdomain scan completed for {target}: {len(subdomain_results.get('subdomains', []))} subdomains found")
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"subdomain_results": subdomain_results, "progress": 33}}
                    )
                else:
                    logging.warning(f"Subdomain scan returned no results for {scan_id}")
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"progress": 33, "subdomain_error": "Scan returned no results"}}
                    )
        except asyncio.TimeoutError:
            logging.error(f"Subdomain enumeration timed out for scan {scan_id}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"progress": 33, "subdomain_error": "Scan timed out"}}
            )
        except Exception as e:
            logging.error(f"Error in subdomain enumeration for scan {scan_id}: {str(e)}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"progress": 33, "subdomain_error": str(e)}}
            )
        
        # Run port scanning
        port_results = None
        try:
            logging.info(f"Starting port scan for {target}")
            async with asyncio.timeout(300):  # 5 minute timeout for port scanning
                port_results = await port_scanner.scan()
                if port_results:
                    logging.info(f"Port scan completed for {target}: {len(port_results.get('open_ports', []))} open ports found")
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"port_results": port_results, "progress": 66}}
                    )
                else:
                    logging.warning(f"Port scan returned no results for {scan_id}")
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"progress": 66, "port_error": "Scan returned no results"}}
                    )
        except asyncio.TimeoutError:
            logging.error(f"Port scanning timed out for scan {scan_id}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"progress": 66, "port_error": "Scan timed out"}}
            )
        except Exception as e:
            logging.error(f"Error in port scanning for scan {scan_id}: {str(e)}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"progress": 66, "port_error": str(e)}}
            )
        
        # Run vulnerability scanning
        vuln_results = None
        try:
            logging.info(f"Starting vulnerability scan for {target}")
            async with asyncio.timeout(300):  # 5 minute timeout for vulnerability scanning
                vuln_results = await vuln_scanner.scan()
                if vuln_results:
                    logging.info(f"Vulnerability scan completed for {target}: {len(vuln_results.get('vulnerabilities', []))} vulnerabilities found")
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"vulnerability_results": vuln_results, "progress": 100}}
                    )
                else:
                    logging.warning(f"Vulnerability scan returned no results for {scan_id}")
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"progress": 100, "vulnerability_error": "Scan returned no results"}}
                    )
        except asyncio.TimeoutError:
            logging.error(f"Vulnerability scanning timed out for scan {scan_id}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"progress": 100, "vulnerability_error": "Scan timed out"}}
            )
        except Exception as e:
            logging.error(f"Error in vulnerability scanning for scan {scan_id}: {str(e)}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"progress": 100, "vulnerability_error": str(e)}}
            )
        
        # Calculate total vulnerabilities found from available results
        total_vulns = 0
        if vuln_results and "vulnerabilities" in vuln_results:
            total_vulns += len(vuln_results["vulnerabilities"])
        if subdomain_results and isinstance(subdomain_results, dict) and "attack_surface" in subdomain_results:
            total_vulns += len(subdomain_results["attack_surface"].get("security_issues", []))
        
        # Determine final status based on results
        final_status = ScanStatus.COMPLETED.value
        if not any([subdomain_results, port_results, vuln_results]):
            final_status = ScanStatus.FAILED.value
        
        # Update final scan results
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": final_status,
                    "completed_at": datetime.utcnow(),
                    "total_vulnerabilities": total_vulns,
                    "progress": 100
                }
            }
        )
        
        # Generate report regardless of status as long as we have some results
        if any([subdomain_results, port_results, vuln_results]):
            try:
                logging.info(f"Attempting to generate report for scan {scan_id}")
                
                # Extract findings summary with better error handling
                findings_summary = {"high": 0, "medium": 0, "low": 0}
                if vuln_results and isinstance(vuln_results, dict):
                    vulns = vuln_results.get("vulnerabilities", [])
                    if isinstance(vulns, list):
                        for v in vulns:
                            if isinstance(v, dict):
                                severity = v.get("severity", "").lower()
                                if severity in findings_summary:
                                    findings_summary[severity] += 1
                
                # Add findings from subdomain security issues
                if subdomain_results and isinstance(subdomain_results, dict):
                    attack_surface = subdomain_results.get("attack_surface", {})
                    if isinstance(attack_surface, dict):
                        for issue in attack_surface.get("security_issues", []):
                            if isinstance(issue, dict):
                                severity = issue.get("severity", "").lower()
                                if severity in findings_summary:
                                    findings_summary[severity] += 1
                
                # Create report document
                report_dict = {
                    "title": f"Security Scan Report - {target}",
                    "type": "scan",  # Use string directly instead of enum
                    "description": f"Security scan results for {target} - {final_status}",
                    "scan_ids": [scan_id],
                    "user_id": user_id,
                    "generated_at": datetime.utcnow(),
                    "data": {
                        "findings_summary": findings_summary,
                        "subdomain_results": subdomain_results if subdomain_results else {"error": "No subdomain results available"},
                        "port_results": port_results if port_results else {"error": "No port scan results available"},
                        "vulnerability_results": vuln_results if vuln_results else {"error": "No vulnerability scan results available"},
                        "vulnerabilities": []  # Initialize empty list for frontend
                    },
                    "markdown_content": generate_markdown_report(target, subdomain_results, port_results, vuln_results),
                    "ai_summary": None  # Optional field
                }
                
                # Process vulnerabilities for frontend
                if vuln_results and "vulnerabilities" in vuln_results:
                    logging.info(f"Processing {len(vuln_results['vulnerabilities'])} vulnerabilities from scanner")
                    # Transform vulnerability scanner results to match frontend format
                    for vuln in vuln_results["vulnerabilities"]:
                        try:
                            formatted_vuln = {
                                "title": f"{vuln.get('type', 'Unknown').upper()} Vulnerability",
                                "type": vuln.get('type', 'unknown'),
                                "severity": vuln.get('severity', 'medium'),
                                "description": "Potential security vulnerability detected",
                                "evidence": {
                                    "payload": vuln.get('payload', 'No payload data'),
                                    "endpoints": []
                                }
                            }
                            
                            # Add more details to description if available
                            if vuln.get('type'):
                                formatted_vuln["description"] = f"Potential {vuln['type']} vulnerability detected"
                            if vuln.get('payload'):
                                formatted_vuln["description"] += f" with payload: {vuln['payload']}"
                            
                            # Add GET test results if available
                            if vuln.get('get_test'):
                                formatted_vuln["evidence"]["endpoints"].append({
                                    "url": vuln['get_test'].get('url', 'Unknown URL'),
                                    "method": "GET",
                                    "status": vuln['get_test'].get('status', 0),
                                    "reflected": vuln['get_test'].get('reflected', False),
                                    "error_detected": vuln['get_test'].get('error_detected', False)
                                })
                            
                            # Add POST test results if available
                            if vuln.get('post_test'):
                                formatted_vuln["evidence"]["endpoints"].append({
                                    "url": vuln['post_test'].get('url', 'Unknown URL'),
                                    "method": "POST",
                                    "status": vuln['post_test'].get('status', 0),
                                    "reflected": vuln['post_test'].get('reflected', False),
                                    "error_detected": vuln['post_test'].get('error_detected', False)
                                })
                            
                            report_dict["data"]["vulnerabilities"].append(formatted_vuln)
                        except Exception as e:
                            logging.error(f"Error formatting vulnerability: {str(e)}")
                            # Still add a basic version of the vulnerability
                            basic_vuln = {
                                "title": "Unformatted Vulnerability",
                                "type": "unknown",
                                "severity": "medium",
                                "description": "A vulnerability was detected but could not be fully formatted",
                                "evidence": {
                                    "payload": "Error formatting vulnerability data",
                                    "endpoints": []
                                }
                            }
                            report_dict["data"]["vulnerabilities"].append(basic_vuln)
                else:
                    logging.info("No vulnerabilities found from scanner")
                
                # Add subdomain security issues as vulnerabilities
                if subdomain_results and isinstance(subdomain_results, dict):
                    attack_surface = subdomain_results.get("attack_surface", {})
                    if isinstance(attack_surface, dict):
                        security_issues = attack_surface.get("security_issues", [])
                        logging.info(f"Processing {len(security_issues)} security issues from subdomain scan")
                        for issue in security_issues:
                            if isinstance(issue, dict):
                                vuln = {
                                    "title": issue.get("title", "Unnamed Issue"),
                                    "type": "subdomain",
                                    "severity": issue.get("severity", "medium").lower(),
                                    "description": issue.get("description", "No description provided"),
                                    "evidence": {
                                        "details": issue
                                    }
                                }
                                report_dict["data"]["vulnerabilities"].append(vuln)
                
                # Add port scan findings as vulnerabilities if they're risky
                if port_results and isinstance(port_results, dict):
                    open_ports = port_results.get("open_ports", [])
                    logging.info(f"Processing {len(open_ports)} open ports from port scan")
                    risky_ports = {
                        21: ("high", "FTP service exposed"),
                        23: ("high", "Telnet service exposed"),
                        3389: ("high", "RDP service exposed"),
                        445: ("high", "SMB service exposed"),
                        137: ("medium", "NetBIOS service exposed"),
                        139: ("medium", "NetBIOS session service exposed"),
                        1433: ("medium", "MSSQL service exposed"),
                        3306: ("medium", "MySQL service exposed"),
                        5432: ("medium", "PostgreSQL service exposed"),
                        6379: ("medium", "Redis service exposed"),
                        27017: ("medium", "MongoDB service exposed")
                    }
                    
                    for port_info in open_ports:
                        port = port_info.get("port")
                        if port in risky_ports:
                            severity, desc = risky_ports[port]
                            vuln = {
                                "title": f"Exposed {port_info.get('service', 'Unknown')} Service",
                                "type": "port",
                                "severity": severity,
                                "description": desc,
                                "evidence": {
                                    "details": port_info
                                }
                            }
                            report_dict["data"]["vulnerabilities"].append(vuln)
                
                logging.info(f"Total vulnerabilities in report: {len(report_dict['data']['vulnerabilities'])}")
                
                # Save report directly
                try:
                    # Log the report structure before saving
                    logging.info("Report structure:")
                    logging.info(f"- Title: {report_dict['title']}")
                    logging.info(f"- Type: {report_dict['type']}")
                    logging.info(f"- Scan IDs: {report_dict['scan_ids']}")
                    logging.info(f"- Data fields: {list(report_dict['data'].keys())}")
                    logging.info(f"- Vulnerabilities count: {len(report_dict['data']['vulnerabilities'])}")
                    
                    result = await db.reports.insert_one(report_dict)
                    logging.info(f"Successfully generated and saved report {result.inserted_id} for scan {scan_id}")
                    
                    # Update scan with report ID
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"report_id": str(result.inserted_id)}}
                    )
                except Exception as e:
                    logging.error(f"Error saving report for scan {scan_id}: {str(e)}")
                    # Try to update the scan with the error
                    await db.scans.update_one(
                        {"_id": ObjectId(scan_id)},
                        {"$set": {"report_error": f"Failed to save report: {str(e)}"}}
                    )
                
            except Exception as e:
                logging.error(f"Error generating report for scan {scan_id}: {str(e)}")
                # Update scan with report generation error
                await db.scans.update_one(
                    {"_id": ObjectId(scan_id)},
                    {"$set": {"report_error": f"Failed to generate report: {str(e)}"}}
                )
        else:
            logging.warning(f"No results available to generate report for scan {scan_id}")
            await db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"report_error": "No scan results available for report generation"}}
            )
        
        logging.info(f"Scan {scan_id} completed with status {final_status}")
        
    except Exception as e:
        logging.error(f"Error in scan {scan_id}: {str(e)}")
        await db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": ScanStatus.FAILED.value,
                    "error": str(e),
                    "completed_at": datetime.utcnow(),
                    "progress": 100
                }
            }
        )
    finally:
        if scan_id in active_scans:
            del active_scans[scan_id]

def generate_markdown_report(target: str, subdomain_results: dict, port_results: dict, vuln_results: dict) -> str:
    """Generate a markdown report from scan results"""
    report = []
    
    # Header
    report.append(f"# Security Scan Report - {target}")
    report.append(f"\nScan completed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    
    # Executive Summary
    report.append("\n## Executive Summary")
    total_vulns = 0
    vuln_by_severity = {"high": 0, "medium": 0, "low": 0}
    
    if vuln_results and "vulnerabilities" in vuln_results:
        for vuln in vuln_results["vulnerabilities"]:
            severity = vuln.get("severity", "unknown").lower()
            if severity in vuln_by_severity:
                vuln_by_severity[severity] += 1
                total_vulns += 1
    
    report.append(f"\nTotal vulnerabilities found: {total_vulns}")
    report.append("Severity breakdown:")
    report.append(f"- High: {vuln_by_severity['high']}")
    report.append(f"- Medium: {vuln_by_severity['medium']}")
    report.append(f"- Low: {vuln_by_severity['low']}\n")
    
    # Subdomain Results
    report.append("\n## Subdomain Enumeration Results")
    if subdomain_results:
        if "subdomains" in subdomain_results:
            report.append("\n### Discovered Subdomains")
            for subdomain in subdomain_results["subdomains"]:
                if isinstance(subdomain, dict):
                    report.append(f"- {subdomain.get('subdomain', 'Unknown')}")
                else:
                    report.append(f"- {subdomain}")
        if "attack_surface" in subdomain_results:
            report.append("\n### Security Issues")
            for issue in subdomain_results["attack_surface"].get("security_issues", []):
                report.append(f"\n#### {issue.get('title', 'Unnamed Issue')}")
                report.append(f"- Severity: {issue.get('severity', 'Unknown')}")
                report.append(f"- Description: {issue.get('description', 'No description provided')}")
    else:
        report.append("\nNo subdomain results available")
    
    # Port Scan Results
    report.append("\n## Port Scan Results")
    if port_results:
        if "open_ports" in port_results:
            report.append("\n### Open Ports")
            for port in port_results["open_ports"]:
                service_info = []
                if port.get('service'):
                    service_info.append(port['service'])
                if port.get('product'):
                    service_info.append(port['product'])
                if port.get('version'):
                    service_info.append(port['version'])
                service_str = " - ".join(service_info) if service_info else "Unknown service"
                report.append(f"- Port {port.get('port')}: {service_str}")
    else:
        report.append("\nNo port scan results available")
    
    # Vulnerability Results
    report.append("\n## Vulnerability Scan Results")
    if vuln_results and "vulnerabilities" in vuln_results:
        for vuln in vuln_results["vulnerabilities"]:
            report.append(f"\n### {vuln.get('title', 'Unnamed Vulnerability')}")
            report.append(f"- Type: {vuln.get('type', 'Unknown')}")
            report.append(f"- Severity: {vuln.get('severity', 'Unknown')}")
            report.append(f"- Description: {vuln.get('description', 'No description provided')}")
            
            # Add evidence details
            if "evidence" in vuln:
                report.append("\n#### Evidence")
                report.append(f"- Payload: {vuln['evidence'].get('payload', 'N/A')}")
                
                for endpoint in vuln['evidence'].get('endpoints', []):
                    report.append(f"\n##### {endpoint.get('method', 'Unknown')} Request")
                    report.append(f"- URL: {endpoint.get('url', 'N/A')}")
                    report.append(f"- Status: {endpoint.get('status', 'N/A')}")
                    report.append(f"- Reflected: {'Yes' if endpoint.get('reflected') else 'No'}")
                    report.append(f"- Error Detected: {'Yes' if endpoint.get('error_detected') else 'No'}")
    else:
        report.append("\nNo vulnerabilities found")
    
    return "\n".join(report)

@app.post("/api/v1/scans")
async def create_scan(scan: ScanCreate):
    """Create a new scan and start it in the background"""
    db = await get_db()
    try:
        # Create scan record
        new_scan = {
            "target": scan.target,
            "user_id": scan.user_id,
            "status": ScanStatus.QUEUED.value,
            "created_at": datetime.utcnow(),
            "scan_type": "comprehensive" if scan.comprehensive else "quick",
            "scan_options": {
                "run_all_scanners": scan.comprehensive,
                "generate_report": scan.comprehensive,
                "detailed_analysis": scan.comprehensive
            },
            "progress": 0,
            "total_vulnerabilities": 0,
            "vulnerabilities": []
        }
        
        # Insert into database
        result = await db.scans.insert_one(new_scan)
        scan_id = str(result.inserted_id)
        
        # Start scan in background
        task = asyncio.create_task(run_scan_in_background(scan_id, scan.target, scan.user_id))
        active_scans[scan_id] = task
        
        return {"scan_id": scan_id, "status": new_scan["status"]}
    except Exception as e:
        logging.error(f"Error creating scan: {str(e)}")
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
        ).sort(-Scan.created_at).to_list()
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
                "scan_options": scan.scan_options,
                "progress": scan.progress
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
async def cancel_scan(scan_id: str, request: Request):
    """Cancel a running scan"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        scan = await Scan.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Check if scan belongs to user
        if scan.user_id != user_id and scan.user_id != "default-user":
            raise HTTPException(status_code=403, detail="Not authorized to cancel this scan")
            
        if scan.status == ScanStatus.IN_PROGRESS:
            # Cancel any active background tasks
            if scan_id in active_scans:
                task = active_scans[scan_id]
                task.cancel()
                del active_scans[scan_id]
            
            # Update scan status
            scan.status = ScanStatus.FAILED
            scan.error = "Cancelled by user"
            scan.completed_at = datetime.utcnow()
            await scan.save()
            return {"message": "Scan cancelled successfully"}
        else:
            return {"message": "Scan is not in progress"}
    except Exception as e:
        logging.error(f"Error cancelling scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/reports")
async def get_reports(request: Request):
    """Get all reports for a user"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        # Get reports directly from MongoDB to avoid validation errors
        db = await get_db()
        reports_cursor = db.reports.find({
                "$or": [
                    {"user_id": user_id},
                    {"user_id": "default-user"}
                ]
        }).sort("generated_at", -1)
        
        reports = await reports_cursor.to_list(length=None)
        logging.info(f"Found {len(reports)} reports for user {user_id}")
        
        transformed_reports = []
        for report in reports:
            # Convert ObjectId to string
            report['_id'] = str(report['_id'])
            
            # Ensure all required fields exist with defaults
            transformed = {
                "_id": report['_id'],
                "title": report.get('title', 'Untitled Report'),
                "type": report.get('type', 'scan'),
                "description": report.get('description', 'No description available'),
                "scan_ids": report.get('scan_ids', []),
                "generated_at": report.get('generated_at', datetime.utcnow()).isoformat() if isinstance(report.get('generated_at'), datetime) else report.get('generated_at'),
                "user_id": report.get('user_id', user_id),
                "data": report.get('data', {}),
                "markdown_content": report.get('markdown_content', ''),
                "ai_summary": report.get('ai_summary', '')
            }
            
            # Ensure data has required fields
            if not transformed["data"]:
                transformed["data"] = {}
            
            if "findings_summary" not in transformed["data"]:
                transformed["data"]["findings_summary"] = {
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            
            transformed_reports.append(transformed)
        
        return transformed_reports
    except Exception as e:
        logging.error(f"Error in get_reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/reports/{report_id}")
async def get_report(report_id: str, request: Request):
    """Get report by ID"""
    try:
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not provided")

        # Get report directly from MongoDB
        db = await get_db()
        report = await db.reports.find_one({"_id": ObjectId(report_id)})
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
            
        # Check if report belongs to user
        if report.get('user_id') != user_id and report.get('user_id') != "default-user":
            raise HTTPException(status_code=403, detail="Not authorized to access this report")
        
        # Convert ObjectId to string
        report['_id'] = str(report['_id'])
        
        # Ensure all required fields exist with defaults
        transformed = {
            "_id": report['_id'],
            "title": report.get('title', 'Untitled Report'),
            "type": report.get('type', 'scan'),
            "description": report.get('description', 'No description available'),
            "scan_ids": report.get('scan_ids', []),
            "generated_at": report.get('generated_at', datetime.utcnow()).isoformat() if isinstance(report.get('generated_at'), datetime) else report.get('generated_at'),
            "user_id": report.get('user_id', user_id),
            "data": report.get('data', {}),
            "markdown_content": report.get('markdown_content', ''),
            "ai_summary": report.get('ai_summary', '')
        }
        
        # Ensure data has required fields
        if not transformed["data"]:
            transformed["data"] = {}
        
        if "findings_summary" not in transformed["data"]:
            transformed["data"]["findings_summary"] = {
                "high": 0,
                "medium": 0,
                "low": 0
            }
        
        # Ensure vulnerabilities array exists
        if "vulnerabilities" not in transformed["data"]:
            transformed["data"]["vulnerabilities"] = []
            
        return transformed
        
    except Exception as e:
        logging.error(f"Error in get_report: {e}")
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