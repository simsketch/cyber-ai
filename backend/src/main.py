import asyncio
import os
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from datetime import datetime, timezone
import json
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from db.connection import init_db, get_db
from models.scan import Scan, ScanStatus, Vulnerability
from models.user import User
from models.report import Report, ReportType
import logging
from bson import ObjectId
from utils.cve_cache import CVECache
import uvicorn
from scanners.vulnerability_scanner import VulnerabilityScanner
from pathlib import Path

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize CVE cache in the local repository
CACHE_DIR = Path(__file__).parent / "cache"
os.makedirs(CACHE_DIR, exist_ok=True)
os.environ["SCANNER_CACHE_DIR"] = str(CACHE_DIR)

# Create FastAPI app instance
app = FastAPI(title="Cyber AI API")

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    try:
        logger.info("Starting application initialization...")
        
        # Ensure cache directory exists and has correct permissions
        os.chmod(CACHE_DIR, 0o777)  # Allow all users to write to cache
        logger.info(f"Cache directory {CACHE_DIR} created and permissions set")
        
        # Initialize CVE cache
        logger.info("Starting CVE cache initialization...")
        cve_cache = CVECache(str(CACHE_DIR))
        logger.info("Forcing initial CVE cache update...")
        await cve_cache.force_update()  # Force initial update
        logger.info("CVE cache initialized and updated successfully")
        
        # Initialize database
        logger.info("Starting database initialization...")
        await init_db()
        logger.info("Database initialized successfully")
        
        logger.info("Application initialization completed successfully")
    except Exception as e:
        logger.error(f"Critical initialization error: {str(e)}", exc_info=True)
        # Don't raise the error, just log it
        # This allows the server to start even if initialization fails

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with processing time"""
    logger.debug(f"Incoming request: {request.method} {request.url}")
    start_time = datetime.now()
    try:
        response = await call_next(request)
        process_time = (datetime.now() - start_time).total_seconds()
        logger.debug(f"Request completed: {request.method} {request.url} - Status: {response.status_code} - Time: {process_time}s")
        return response
    except Exception as e:
        logger.error(f"Request failed: {request.method} {request.url} - Error: {str(e)}")
        raise

@app.get("/health")
async def health_check():
    """Basic health check endpoint"""
    logger.debug("Health check requested")
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

active_scans = {}

# Models
class ScanCreate(BaseModel):
    target: str
    user_id: str
    comprehensive: bool = False

@app.get("/api/v1/cves")
async def get_cves():
    """Get latest CVEs from cache"""
    try:
        logger.debug("Handling GET /api/v1/cves request")
        cve_cache = CVECache(str(CACHE_DIR))
        
        # Use cached data if valid
        if cve_cache._is_cache_valid():
            logger.info("Using valid cache data...")
            cve_data = await cve_cache.get_latest_cves()
        else:
            logger.info("Cache invalid, fetching new data...")
            cve_data = await cve_cache.force_update()
        
        if not cve_data or 'cves' not in cve_data:
            logger.error("No CVE data available in response")
            raise HTTPException(status_code=500, detail="Failed to fetch CVE data")
            
        # Sort CVEs by published date (most recent first)
        sorted_cves = sorted(
            cve_data['cves'],
            key=lambda x: x.get('Published', ''),
            reverse=True
        )
        
        logger.info(f"Successfully retrieved {len(sorted_cves)} CVEs")
        return {
            "timestamp": cve_data.get('timestamp'),
            "cves": sorted_cves
        }
    except Exception as e:
        logger.error(f"Error fetching CVEs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

async def execute_scan(scan: Scan):
    """Execute the scan and update the scan document with results"""
    try:
        # Update scan status to in-progress
        scan.status = ScanStatus.IN_PROGRESS
        await scan.save()
        
        # Initialize vulnerability scanner
        vuln_scanner = VulnerabilityScanner(scan.target)
        
        # Run vulnerability scan
        scan_results = await vuln_scanner.scan()
        
        # Process results
        vulnerabilities = []
        total_vulnerabilities = 0
        
        # Process vulnerability scan results
        for vuln in scan_results.get('vulnerabilities', []):
            vulnerabilities.append(Vulnerability(
                title=vuln['title'],
                description=vuln['description'],
                severity=vuln['severity'],
                remediation="Review and patch the vulnerability"
            ))
            total_vulnerabilities += 1
        
        # Update scan with results
        scan.vulnerabilities = vulnerabilities
        scan.total_vulnerabilities = total_vulnerabilities
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        await scan.save()
        
        # Calculate scan duration
        scan_duration = (scan.completed_at - scan.started_at).total_seconds()
        
        # Calculate health score based on vulnerabilities and their severity
        total_score = 100
        for vuln in vulnerabilities:
            if vuln.severity == 'high':
                total_score -= 20
            elif vuln.severity == 'medium':
                total_score -= 10
            elif vuln.severity == 'low':
                total_score -= 5
        health_score = max(0, total_score)
        health_rating = "Good" if health_score >= 80 else "Fair" if health_score >= 60 else "Poor"
        
        # Create report
        report = Report(
            title=f"Security Assessment Report: {scan.target}",
            type="scan",
            description=f"Comprehensive security assessment for {scan.target}",
            scan_ids=[str(scan.id)],
            user_id=scan.user_id,
            generated_at=datetime.now(timezone.utc),
            data={
                "scan_id": str(scan.id),
                "target": scan.target,
                "total_vulnerabilities": total_vulnerabilities,
                "vulnerabilities": [v.dict() for v in vulnerabilities],
                "findings_summary": {
                    "high": len([v for v in vulnerabilities if v.severity == 'high']),
                    "medium": len([v for v in vulnerabilities if v.severity == 'medium']),
                    "low": len([v for v in vulnerabilities if v.severity == 'low'])
                }
            },
            markdown_content="",  # Will be generated by AI
            scan_duration=scan_duration,
            health_score=health_score,
            health_rating=health_rating
        )
        
        # Insert the report and ensure it's saved
        await report.insert()
        logger.info(f"Created report with health score {health_score} and rating {health_rating}")
        
        logger.info(f"Scan completed for {scan.target} with {total_vulnerabilities} vulnerabilities found")
        
    except Exception as e:
        logger.error(f"Error executing scan: {str(e)}")
        scan.status = ScanStatus.FAILED
        scan.error = str(e)
        scan.completed_at = datetime.now(timezone.utc)
        await scan.save()
        raise

@app.post("/api/v1/scans")
async def create_scan(scan_data: ScanCreate, db = Depends(get_db)):
    """Create a new scan"""
    try:
        # Create scan document
        scan = Scan(
            target=scan_data.target,
            status=ScanStatus.QUEUED,
            user_id=scan_data.user_id,
            scan_type="comprehensive" if scan_data.comprehensive else "basic",
            started_at=datetime.now(timezone.utc)
        )
        await scan.insert()
        logger.info(f"Created new scan for target {scan_data.target}")
        
        # Start scan in background
        asyncio.create_task(execute_scan(scan))
        
        return scan.dict()
    except Exception as e:
        logger.error(f"Error creating scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans")
async def list_scans(db = Depends(get_db), user_id: str = Header(None, alias="X-User-ID")):
    """List all scans for a user"""
    try:
        if not user_id:
            raise HTTPException(status_code=400, detail="X-User-ID header is required")
        scans = await Scan.find({"user_id": user_id}).sort("-created_at").to_list()
        return [scan.dict() for scan in scans]
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, db = Depends(get_db)):
    """Get scan details"""
    try:
        scan = await Scan.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan.dict()
    except Exception as e:
        logger.error(f"Error getting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/reports")
async def list_reports(db = Depends(get_db), user_id: str = Header(None, alias="X-User-ID")):
    """List all reports for a user"""
    try:
        if not user_id:
            raise HTTPException(status_code=400, detail="X-User-ID header is required")
        reports = await Report.find({"user_id": user_id}).sort("-generated_at").to_list()
        return [{
            **report.dict(),
            "id": str(report.id),  # Convert ObjectId to string
            "_id": str(report.id)  # Also include _id for frontend compatibility
        } for report in reports]
    except Exception as e:
        logger.error(f"Error listing reports: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/reports/{report_id}")
async def get_report(report_id: str, db = Depends(get_db), user_id: str = Header(None, alias="X-User-ID")):
    """Get report details"""
    try:
        if not user_id:
            raise HTTPException(status_code=400, detail="X-User-ID header is required")
        try:
            report_obj_id = ObjectId(report_id)
        except:
            raise HTTPException(status_code=400, detail="Invalid report ID format")
            
        report = await Report.get(report_obj_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if report.user_id != user_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this report")
            
        report_dict = report.dict()
        report_dict["id"] = str(report.id)  # Convert ObjectId to string
        report_dict["_id"] = str(report.id)  # Also include _id for frontend compatibility
        
        # Ensure health score and rating are included
        report_dict["health_score"] = report.health_score
        report_dict["health_rating"] = report.health_rating
        logger.debug(f"Returning report with health score: {report.health_score}, rating: {report.health_rating}")
        
        return report_dict
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="debug"
    )