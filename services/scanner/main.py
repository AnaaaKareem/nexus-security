import os
import shutil
import uuid
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException
from pydantic import BaseModel
from core.scanner import SecurityScanner
from core import parser
from common.core.logger import get_logger

logger = get_logger(__name__)
app = FastAPI(title="Scanner Service")

class ScanRequest(BaseModel):
    target_path: str
    project_name: str
    target_url: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "healthy", "service": "scanner"}

@app.post("/scan")
def trigger_scan(req: ScanRequest):
    """
    Triggers a security scan on a local path.
    """
    scanner = SecurityScanner()
    logger.info(f"Received scan request for {req.project_name}", extra_info={"event": "scan_request", "project": req.project_name, "path": req.target_path})
    
    # Run scan synchronously for now (or move to background if needed, but orchestrator usually waits)
    # Actually orchestrator runs this via http, so maybe synchronous is okay if timeout is long, 
    # but run_scan spawns threads. 
    # Let's return the report paths.
    try:
        report_paths = scanner.run_scan(req.target_path, req.project_name, req.target_url)
        return {"status": "completed", "reports": report_paths}
    except Exception as e:
        logger.error(f"Scan failed: {e}", extra_info={"event": "scan_failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/parse")
async def parse_report(file: UploadFile = File(...)):
    """
    Parses a single report file.
    """
    content = await file.read()
    findings = parser.extract_findings(content, file.filename)
    return {"findings": findings}
