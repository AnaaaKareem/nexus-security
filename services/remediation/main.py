from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel
from typing import List, Dict, Any
from core.pr_agent import create_consolidated_pr
from core.fix_generator import llm
from common.core.logger import get_logger
import httpx
import asyncio
import os

logger = get_logger(__name__)
app = FastAPI(title="Remediation Service")

# Global Readiness Flag
MODEL_READY = False

@app.on_event("startup")
async def startup_event():
    global MODEL_READY
    logger.info("Remediation Service: Checking LLM connection...", extra_info={"event": "startup_check"})
    asyncio.create_task(wait_for_models())

async def wait_for_models():
    global MODEL_READY
    import time
    
    try:
        if os.getenv("SKIP_MODEL_CHECK", "false").lower() == "true":
            logger.warning("SKIP_MODEL_CHECK is set. Bypassing LLM readiness check.", extra_info={"event": "llm_check_skipped"})
            MODEL_READY = True
            return

        logger.info("Waiting for LLM Server...", extra_info={"event": "llm_wait_start"})
        
        timeout_minutes = 5
        start_time = time.time()
        end_time = start_time + (60 * timeout_minutes)
        
        while True:
            try:
                # Simple check if LLM base URL is reachable
                async with httpx.AsyncClient(timeout=2.0) as client:
                    llm_base = os.getenv("LLM_BASE_URL", "http://localhost:1234/v1")
                    base = llm_base.rstrip("/").replace("/v1", "")
                    url = f"{base}/v1/models"
                    
                    resp = await client.get(url) 
                    if resp.status_code == 200:
                        logger.info("✅ LLM Server is Online.")
                        MODEL_READY = True
                        break
            except Exception as e:
                # logger.warning(f"Readiness Check Failed: {e}") 
                # Keep silent or low noise unless it persists
                pass
                
            if time.time() > end_time:
                 logger.error("LLM Server timed out. Service will remain Unhealthy.", extra_info={"event": "llm_timeout"})
                 break
            
            await asyncio.sleep(5)
            
    except Exception as outer_e:
        logger.error(f"CRITICAL: wait_for_models crashed! {outer_e}")
        import traceback
        traceback.print_exc()

@app.get("/health")
def health():
    return {"status": "healthy", "service": "remediation"}

@app.get("/readiness")
def readiness(response: Response):
    global MODEL_READY
    if MODEL_READY:
        return {"status": "ready"}
    else:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "detail": "Waiting for LLM..."}

class PRRequest(BaseModel):
    repo_name: str
    branch_name: str
    file_updates: List[Dict[str, Any]]
    issue_summary: str

@app.get("/health")
def health():
    return {"status": "healthy", "service": "remediation"}

@app.post("/pr/create")
def create_pr(req: PRRequest):
    try:
        url = create_consolidated_pr(req.repo_name, req.branch_name, req.file_updates, req.issue_summary)
        return {"url": url}
    except Exception as e:
        logger.error(f"PR creation failed: {e}", extra_info={"event": "pr_creation_failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

class FixRequest(BaseModel):
    finding: Dict[str, Any]
    project: str

@app.post("/remediate/fix")
async def generate_fix(req: FixRequest):
    if os.getenv("SKIP_MODEL_CHECK", "false").lower() == "true":
        logger.warning("SKIP_MODEL_CHECK: Returning MOCKED Fix.", extra_info={"event": "mock_fix_generated"})
        # Return a dummy patch that just comments out the vulnerability
        return {"patch": "# Security Fix: Vulnerability Mocked Out\n# pass"}

    from core.fix_generator import generate_fix_code
    try:
        patch = await generate_fix_code(req.finding, req.project)
        return {"patch": patch}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

