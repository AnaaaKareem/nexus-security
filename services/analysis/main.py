from fastapi import FastAPI, Response, status
from pydantic import BaseModel
from typing import Dict, Any, List
from core.anomaly_detector import detect_anomalies, load_model
from core.triage import llm
from common.core.logger import get_logger
import httpx
import asyncio
import os

logger = get_logger(__name__)
app = FastAPI(title="Analysis Service")

# Global Readiness Flag
MODEL_READY = False

@app.on_event("startup")
async def startup_event():
    global MODEL_READY
    logger.info("Analysis Service calling startup checks...", extra_info={"event": "startup_check"})
    
    # 1. Load Anomaly Model (Local)
    load_model()
    
    # 2. Check LLM Connectivity (Remote)
    # Retry loop for LLM readiness
    max_retries = 30 # 5 minutes roughly if 10s wait? No, user said "number of minutes"
    # Let's say we wait up to 5 minutes.
    
    # Actually, we don't want to block startup entirely indefinitely, but the user requested "wait... or stop".
    # Blocking startup means the container fails the k8s probe or docker healthcheck.
    # Better to run this as a background task that updates the flag?
    # Or just block? If I block, uvicorn doesn't start serving /health either.
    # So I should start a background task.
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
        logger.info(f"timeout set for {timeout_minutes} min. Entering loop...")
        
        while True:
            try:
                # Simple check if LLM base URL is reachable
                async with httpx.AsyncClient(timeout=2.0) as client:
                    # Remove /v1 suffix if present for a root check, or just check /v1/models
                    # Use env var directly instead of accessing object property
                    llm_base = os.getenv("LLM_BASE_URL", "http://localhost:1234/v1")
                    base = llm_base.rstrip("/").replace("/v1", "")
                    url = f"{base}/v1/models"
                    
                    resp = await client.get(url) 
                    if resp.status_code == 200:
                        logger.info("✅ LLM Server is Online.")
                        MODEL_READY = True
                        break
            except Exception as e:
                logger.warning(f"Readiness Check Failed: {e}")
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
    return {"status": "healthy", "service": "analysis"}

@app.get("/readiness")
def readiness(response: Response):
    global MODEL_READY
    if MODEL_READY:
        return {"status": "ready", "llm": "connected"}
    else:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "detail": "Waiting for LLM server..."}

class AnomalyRequest(BaseModel):
    metadata: Dict[str, Any]

@app.post("/analyze/anomalies")
def check_anomalies(req: AnomalyRequest):
    anomalies = detect_anomalies(req.metadata)
    return {"anomalies": anomalies}

class TriageRequest(BaseModel):
    finding: Dict[str, Any]
    project: str

@app.post("/analyze/triage")
async def analyze_finding_api(req: TriageRequest):
    if os.getenv("SKIP_MODEL_CHECK", "false").lower() == "true":
         logger.warning("⚠️ SKIP_MODEL_CHECK: Returning MOCKED Triage Result.")
         return {"result": {
             "ai_verdict": "TP", 
             "ai_confidence": 0.99, 
             "reasoning": "Mocked TP for testing."
         }}

    from core.triage import analyze_finding
    result = await analyze_finding(req.finding, req.project)
    return {"result": result}

