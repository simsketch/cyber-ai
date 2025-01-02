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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize CVE cache
CACHE_DIR = "/tmp/cyber-ai-cache"
os.makedirs(CACHE_DIR, exist_ok=True)
os.environ["SCANNER_CACHE_DIR"] = CACHE_DIR

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        # Ensure cache directory exists and has correct permissions
        os.chmod(CACHE_DIR, 0o777)  # Allow all users to write to cache
        logging.info(f"Cache directory {CACHE_DIR} created and permissions set")
        
        # Initialize CVE cache on startup
        cve_cache = CVECache(CACHE_DIR)
        await cve_cache.force_update()  # Force initial update
        logging.info("CVE cache initialized and updated")
        
        # Initialize database
        await init_db()
        logging.info("Database initialized")
    except Exception as e:
        logging.error(f"Startup error: {e}")
        raise
    yield
    # Shutdown
    pass

app = FastAPI(title="Cyber AI API", lifespan=lifespan)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
        logging.info("Initializing CVE cache...")
        # Initialize CVECache with the configured cache directory
        cache_dir = os.environ.get("SCANNER_CACHE_DIR", "/tmp/cyber-ai-cache")
        os.makedirs(cache_dir, exist_ok=True)  # Ensure directory exists
        
        cve_cache = CVECache(cache_dir)
        logging.info("CVE cache initialized, checking validity...")
        
        # Force update if cache is invalid or missing
        if not cve_cache._is_cache_valid():
            logging.info("CVE cache is invalid or missing, forcing update...")
            cve_data = await cve_cache.force_update()
            logging.info("CVE cache updated successfully")
        else:
            logging.info("CVE cache is valid, fetching data...")
            cve_data = await cve_cache.get_latest_cves()
        
        if not cve_data or 'cves' not in cve_data:
            logging.error("No CVE data available in response")
            raise HTTPException(status_code=500, detail="Failed to fetch CVE data")
            
        # Sort CVEs by published date (most recent first)
        sorted_cves = sorted(
            cve_data['cves'],
            key=lambda x: x.get('Published', ''),
            reverse=True
        )
        
        logging.info(f"Successfully retrieved {len(sorted_cves)} CVEs")
        return {
            "timestamp": cve_data.get('timestamp'),
            "cves": sorted_cves
        }
    except Exception as e:
        logging.error(f"Error fetching CVEs: {str(e)}")
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
        
        logging.info(f"Scan completed for {scan.target} with {total_vulnerabilities} vulnerabilities found")
        
    except Exception as e:
        logging.error(f"Error executing scan: {str(e)}")
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
        logging.info(f"Created new scan for target {scan_data.target}")
        
        # Start scan in background
        asyncio.create_task(execute_scan(scan))
        
        return scan.dict()
    except Exception as e:
        logging.error(f"Error creating scan: {str(e)}")
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
        logging.error(f"Error listing scans: {str(e)}")
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
        logging.error(f"Error getting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )