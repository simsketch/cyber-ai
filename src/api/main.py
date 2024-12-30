from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from ai.orchestrator import AIOrchestrator
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = FastAPI(
    title="AI-Driven Security Scanner",
    description="Intelligent security scanning and assessment platform",
    version="1.0.0"
)

# Initialize AI Orchestrator
ai_orchestrator = AIOrchestrator(api_key=os.getenv('OPENAI_API_KEY'))

class ScanRequest(BaseModel):
    domain: str
    scan_type: Optional[str] = "comprehensive"
    params: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    results: Optional[Dict[str, Any]] = None

# Add new models
class ScanFilter(BaseModel):
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: Optional[str] = None
    scan_type: Optional[str] = None

class CustomScanConfig(BaseModel):
    scan_types: List[str] = Field(..., description="List of scan types to run")
    params: Dict[str, Any] = Field(default_factory=dict)
    priority: Optional[str] = "normal"

@app.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan."""
    try:
        # Research company
        company_info = await ai_orchestrator.research_company(scan_request.domain)
        
        # Get latest vulnerabilities
        latest_vulns = await ai_orchestrator.get_latest_vulnerabilities()
        
        # Create scan plan
        scan_plan = await ai_orchestrator.create_scan_plan(
            company_info,
            latest_vulns
        )
        
        # Start scan in background
        background_tasks.add_task(execute_scan_plan, scan_plan, scan_request.domain)
        
        return {
            "scan_id": "generated_id",
            "status": "started",
            "results": None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str):
    """Get the status of a running scan."""
    # Implementation here
    pass

@app.get("/report/{scan_id}")
async def get_scan_report(scan_id: str):
    """Get the report for a completed scan."""
    # Implementation here
    pass

async def execute_scan_plan(scan_plan: Dict[str, Any], domain: str):
    """Execute the scan plan in the background."""
    # Implementation here
    pass 

@app.post("/scan/custom", response_model=ScanResponse)
async def start_custom_scan(
    scan_request: ScanRequest,
    config: CustomScanConfig,
    background_tasks: BackgroundTasks
):
    """Start a custom scan with specific configuration."""
    try:
        # Research company
        company_info = await ai_orchestrator.research_company(scan_request.domain)
        
        # Create custom scan plan
        scan_plan = await ai_orchestrator.create_custom_scan_plan(
            company_info,
            config.scan_types,
            config.params,
            config.priority
        )
        
        # Start scan
        scan_id = await scan_executor.execute_scan_plan(scan_plan, scan_request.domain)
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "results": None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scans", response_model=List[ScanResponse])
async def list_scans(filters: ScanFilter = None):
    """List all scans with optional filtering."""
    try:
        scans = scan_executor.list_scans()
        
        if filters:
            if filters.start_date:
                scans = [s for s in scans if s['start_time'] >= filters.start_date]
            if filters.end_date:
                scans = [s for s in scans if s['start_time'] <= filters.end_date]
            if filters.status:
                scans = [s for s in scans if s['status'] == filters.status]
            if filters.scan_type:
                scans = [s for s in scans if filters.scan_type in s['completed_scans']]
                
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/report/{scan_id}/download")
async def download_report(scan_id: str, format: str = Query("pptx", regex="^(pptx|pdf|md)$")):
    """Download scan report in specified format."""
    try:
        results = scan_executor.get_scan_results(scan_id)
        company_info = results[0].get('company_info', {})
        
        if format == "pptx":
            report_path = ai_orchestrator.create_report(results, company_info)
            return FileResponse(
                report_path,
                filename=f"security_report_{scan_id}.pptx",
                media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation"
            )
        elif format == "pdf":
            report_path = ai_orchestrator.create_pdf_report(results, company_info)
            return FileResponse(
                report_path,
                filename=f"security_report_{scan_id}.pdf",
                media_type="application/pdf"
            )
        else:
            report_path = ai_orchestrator.create_markdown_report(results, company_info)
            return FileResponse(
                report_path,
                filename=f"security_report_{scan_id}.md",
                media_type="text/markdown"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/{scan_id}/pause")
async def pause_scan(scan_id: str):
    """Pause a running scan."""
    try:
        await scan_executor.pause_scan(scan_id)
        return {"status": "paused", "scan_id": scan_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/{scan_id}/resume")
async def resume_scan(scan_id: str):
    """Resume a paused scan."""
    try:
        await scan_executor.resume_scan(scan_id)
        return {"status": "resumed", "scan_id": scan_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 