"""
Remediation Service Entry Point.

This service is responsible for determining and implementing fixes for security vulnerabilities.
It exposes HTTP endpoints to:
1. Generate specific code fixes using LLMs.
2. Create or update Pull Requests on version control platforms (GitHub).
"""

import threading
import traceback
import os
import httpx
from fastapi import FastAPI, Response, HTTPException
from common.core.logger import get_logger
from common.core.queue import StateManager
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

# Core Logic Imports
from core.fix_generator import generate_fix_code
from core.pr_agent import create_pr_for_fix, create_consolidated_pr
import asyncio

logger = get_logger(__name__)
app = FastAPI(title="Remediation Service")

# --- REQUEST MODELS ---
class FixRequest(BaseModel):
    """Request body for fix generation."""
    finding: Dict[str, Any]  # Finding data (snippet, message, file, line, full_content)
    project: str             # Project identifier

class PrRequest(BaseModel):
    """Request body for PR creation. Supports both consolidated and single-fix modes."""
    # Consolidated PR mode (multiple files in one PR)
    repo_name: Optional[str] = None                    # GitHub repo (owner/repo)
    branch_name: Optional[str] = None                  # Target feature branch
    file_updates: Optional[List[Dict[str, Any]]] = None  # List of {path, content, message}
    issue_summary: Optional[str] = None                # PR description summary
    ci_provider: Optional[str] = "github"              # 'github' or 'gitlab'
    
    # Single Fix mode (legacy compatibility)
    finding: Optional[Dict[str, Any]] = None           # Finding with fix content
    project: Optional[str] = None                      # Project name
    branch: str = "main"                               # Base branch for PR

@app.post("/generate_fix")
async def trigger_generate_fix_http(req: FixRequest):
    """
    HTTP endpoint to generate an AI fix for a finding.
    """
    import time
    start_time = time.time()
    finding_id = req.finding.get('id')
    file_path = req.finding.get('file', 'unknown')
    line = req.finding.get('line', 0)
    vulnerability_type = req.finding.get('rule_id', 'unknown')
    
    logger.info(f"Fix generation request: {req.project}", extra_info={
        "event": "fix_generation_request",
        "project": req.project,
        "finding_id": finding_id,
        "file": file_path,
        "line": line,
        "vulnerability_type": vulnerability_type
    })
    
    try:
        patch_code = await generate_fix_code(req.finding, req.project)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        patch_size = len(patch_code) if patch_code else 0
        
        logger.info(f"Fix generated: {req.project}", extra_info={
            "event": "fix_generation_completed",
            "project": req.project,
            "finding_id": finding_id,
            "patch_size": patch_size,
            "duration_ms": duration_ms
        })
        return {"patch": patch_code}
    except Exception as e:
        logger.error(f"Fix Generation Failed: {e}", extra_info={
            "event": "fix_generation_failed",
            "error": str(e),
            "project": req.project,
            "finding_id": finding_id
        })
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/create_pr")
def trigger_create_pr_http(req: PrRequest):
    """
    HTTP endpoint to create a Pull Request.
    Supports both consolidated PRs (list of updates) and legacy single-fix PRs.
    """
    import time
    start_time = time.time()
    
    is_consolidated = req.file_updates is not None and len(req.file_updates) > 0
    files_count = len(req.file_updates) if req.file_updates else 1
    
    logger.info(f"PR creation request", extra_info={
        "event": "pr_creation_request",
        "mode": "consolidated" if is_consolidated else "single",
        "repo": req.repo_name or req.project,
        "files_count": files_count
    })
    
    try:
        pr_url = None
        
        # Route to appropriate handler based on request type
        if req.file_updates:
            # Case A: Consolidated PR - multiple fixes in one PR
            logger.debug(f"Handling Consolidated PR request", extra_info={
                "event": "pr_consolidated_start",
                "repo": req.repo_name,
                "files": len(req.file_updates)
            })
            pr_url = create_consolidated_pr(
                repo_name=req.repo_name,
                branch_name=req.branch_name,
                file_updates=req.file_updates,
                issue_summary=req.issue_summary,
                provider=req.ci_provider
            )
        else:
            # Case B: Single Fix - legacy endpoint for individual fixes
            if not req.finding or not req.project:
                 raise HTTPException(status_code=400, detail="Missing finding/project for single PR")
                 
            logger.debug(f"Handling Single Fix PR request", extra_info={
                "event": "pr_single_start",
                "project": req.project
            })
            pr_url = create_pr_for_fix(
                req.finding, 
                req.project,
                req.branch
            )
        
        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(f"PR created successfully", extra_info={
            "event": "pr_creation_completed",
            "pr_url": pr_url,
            "files_changed": files_count,
            "duration_ms": duration_ms
        })
        
        # Return URL in both formats for compatibility
        return {"pr_url": pr_url, "url": pr_url}
        
    except Exception as e:
        logger.error(f"PR Creation Failed: {e}", extra_info={
            "event": "pr_creation_failed",
            "error": str(e),
            "repo": req.repo_name or req.project
        })
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "ok", "mode": "http_api"}

@app.get("/readiness")
async def readiness_check():
    skip = os.getenv("SKIP_MODEL_CHECK", "false").lower() == "true"
    if skip:
        return {"status": "skipped", "ready": True}
    
    url = os.getenv("LLM_BASE_URL")
    key = os.getenv("LLM_API_KEY")

    try:
         async with httpx.AsyncClient(timeout=3.0) as client:
             await client.get(f"{url}/models", headers={"Authorization": f"Bearer {key}"})
         return {"status": "ok", "ready": True}
    except Exception as e:
         logger.warning(f"Readiness Check Failed: {e}", extra_info={"event": "readiness_check_failed", "error": str(e)})
         return Response(content="LLM Not Ready", status_code=503)

@app.on_event("startup")
async def startup_event():
    logger.info("Remediation Service HTTP API Started", extra_info={"event": "startup_complete"})
    # Start the Heartbeat
    hb_thread = threading.Thread(target=run_heartbeat, daemon=True)
    hb_thread.start()

import time

def run_heartbeat():
    while True:
        try:
            logger.info("Service Heartbeat", extra_info={"event": "heartbeat", "status": "up"})
            time.sleep(30)
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")
            time.sleep(30)
