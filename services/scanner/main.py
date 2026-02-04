"""
Scanner Service Entry Point.

This service is responsible for orchestrating the execution of security scanning tools.
It exposes HTTP endpoints to:
1. Run DAST scans (OWASP ZAP).
2. Run SAST/Secret scanners (Semgrep, Gitleaks, etc.) via the Scanner Core.
3. Parse generated reports into a unified format.
"""

import threading
import traceback
from fastapi import FastAPI, UploadFile, File, HTTPException
from common.core.logger import get_logger
from common.core.queue import StateManager
from pydantic import BaseModel
from typing import List, Optional

# Core Logic Imports
from core.zap_scanner import start_zap_scan
from core.parser import parse_scan_report
from core.scanner import SecurityScanner

logger = get_logger(__name__)
app = FastAPI(title="Scanner Service")

# --- REQUEST MODELS ---
class ScanRequest(BaseModel):
    """Request body for generic scan endpoint."""
    target_path: str                       # Path to source code to scan
    project_name: str                      # Project identifier
    target_url: Optional[str] = None       # URL for DAST scanning
    extra_rules: List[str] = []            # Additional Semgrep rulesets
    changed_files: List[str] = []          # Files for delta/diff-based scanning

class ZapScanRequest(BaseModel):
    """Request body for ZAP DAST scan."""
    target_url: str                        # Target URL to scan
    project_name: str                      # Project identifier
    target_path: Optional[str] = None      # Optional source path for context
    scan_id: Optional[int] = None          # DB scan ID for progress tracking

class SastScanRequest(BaseModel):
    """Request body for SAST-only scan."""
    target_path: str                       # Path to source code
    project_name: str                      # Project identifier
    extra_rules: List[str] = []            # Additional Semgrep rulesets
    scan_id: Optional[int] = None          # DB scan ID for progress tracking

@app.post("/scan")
def trigger_scan_http(req: ScanRequest):
    """
    HTTP endpoint to trigger a scan synchronously (blocking).
    Legacy endpoint, kept for compatibility if needed.
    """
    logger.info(f"Scan request: {req.project_name}", extra_info={
        "event": "scan_request_http",
        "project": req.project_name,
        "target_path": req.target_path,
        "has_target_url": req.target_url is not None,
        "has_extra_rules": len(req.extra_rules) > 0,
        "changed_files_count": len(req.changed_files)
    })
    import time
    start_time = time.time()
    
    scanner = SecurityScanner()
    # Run the scan (Semgrep + others)
    report_files = scanner.run_scan(req.target_path, req.project_name, req.target_url, req.extra_rules, req.changed_files)
    
    duration_ms = round((time.time() - start_time) * 1000, 2)
    logger.info(f"Scan completed: {req.project_name}", extra_info={
        "event": "scan_completed_http",
        "project": req.project_name,
        "report_count": len(report_files),
        "duration_ms": duration_ms
    })
    
    return {
        "scan_status": "completed",
        "reports": report_files
    }

@app.post("/zap_scan")
def trigger_zap_scan_http(req: ZapScanRequest):
    """
    HTTP endpoint to trigger a ZAP scan synchronously (blocking).
    """
    logger.info(f"🚀 Received ZAP Scan Request: {req.project_name} -> {req.target_url}", extra_info={"event": "zap_scan_request", "project": req.project_name, "target_url": req.target_url})
    
    # Initialize progress tracker if scan_id provided
    scan_id = req.scan_id
    state_mgr = StateManager(scan_id) if scan_id else None
    
    if state_mgr: state_mgr.update_step(1, 3, "Running DAST Scan (ZAP)")
    
    try:
        # Execute ZAP scan (this is long-running, may take several minutes)
        scan_res = start_zap_scan(req.target_url, req.project_name)
        
        # Check if ZAP returned findings directly (new format)
        if isinstance(scan_res, dict) and "findings" in scan_res:
            findings = scan_res["findings"]
            
            if state_mgr: state_mgr.complete()

            return {
                "scan_status": "completed",
                "findings": findings,
                "raw_output": str(scan_res.get("raw_alerts", ""))
            }
        else:
            # Fallback for legacy string return (error message or file path)
            if state_mgr: state_mgr.update_step(2, 3, "Parsing Scan Report")
            findings = parse_scan_report(scan_id or 0) 
            
            if state_mgr: state_mgr.complete()
    
            return {
                "scan_status": "completed",
                "findings": findings,
                "raw_output": str(scan_res)
            }
    except Exception as e:
        logger.error(f"ZAP Scan Failed: {e}")
        if state_mgr: state_mgr.fail(str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/sast_scan")
def trigger_sast_scan_http(req: SastScanRequest):
    """
    HTTP endpoint to trigger SAST scans.
    """
    logger.info(f"SAST scan request: {req.project_name}", extra_info={
        "event": "sast_scan_request",
        "project": req.project_name,
        "target_path": req.target_path,
        "scan_id": req.scan_id,
        "has_extra_rules": len(req.extra_rules) > 0
    })
    import time
    start_time = time.time()

    scan_id = req.scan_id
    state_mgr = StateManager(scan_id) if scan_id else None
    if state_mgr: state_mgr.update_step(1, 2, "Running SAST Scans")

    try:
        scanner = SecurityScanner()
        # Run the scan (Semgrep + others)
        report_files = scanner.run_scan(req.target_path, req.project_name, extra_rules=req.extra_rules)
        
        if state_mgr: state_mgr.complete()
        
        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(f"SAST scan completed: {req.project_name}", extra_info={
            "event": "sast_scan_completed",
            "project": req.project_name,
            "report_count": len(report_files),
            "duration_ms": duration_ms
        })

        return {
            "scan_status": "completed",
            "reports": report_files
        }
    except Exception as e:
        logger.error(f"SAST Scan Failed: {e}", extra_info={"event": "sast_scan_failed", "error": str(e), "project": req.project_name})
        if state_mgr: state_mgr.fail(str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/parse")
async def parse_report_http(file: UploadFile = File(...)):
    """
    Parses an uploaded report file and returns the findings.
    """
    content = await file.read()
    from core.parser import extract_findings
    findings = extract_findings(content, file.filename)
    return {"findings": findings}


@app.on_event("startup")
async def startup_event():
    logger.info("Scanner Service HTTP API Started", extra_info={"event": "startup_complete"})

@app.get("/health")
def health_check():
    return {"status": "ok", "mode": "http_api"}
