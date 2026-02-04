"""
Analysis Service Entry Point.

This service is responsible for performing deep analysis on security findings.
It exposes HTTP endpoints to:
1. Intelligent Triage (using LLMs) to weed out False Positives.
2. Anomaly Detection in CI/CD pipelines.
3. EPSS Score synchronization.
"""

import threading
import traceback
import os
import httpx
from fastapi import FastAPI, Response, HTTPException
from common.core.logger import get_logger
from common.core.queue import StateManager
from common.core import database
import asyncio
from pydantic import BaseModel
from typing import Dict, Any, Optional

# Core Logic Imports
from core.triage import analyze_finding
from core.epss_worker import sync_epss_scores
from core.anomaly_detector import detect_anomalies

logger = get_logger(__name__)
app = FastAPI(title="Analysis Service")

# --- REQUEST MODELS ---
class TriageRequest(BaseModel):
    """Request body for AI triage analysis."""
    finding: Dict[str, Any]  # Finding data (snippet, message, rule_id, file, line)
    context: str = ""        # Additional context (project name, etc.)

class EpssRequest(BaseModel):
    """Request body for EPSS score sync."""
    cve_id: str              # CVE identifier (e.g., "CVE-2021-44228")

class AnomalyRequest(BaseModel):
    """Request body for pipeline anomaly detection."""
    metadata: Dict[str, Any]  # Pipeline metrics (build_duration, artifact_size, etc.)

@app.post("/triage")
async def trigger_triage_http(req: TriageRequest):
    """
    HTTP endpoint for intelligent triage of a finding.
    """
    import time
    start_time = time.time()
    finding_id = req.finding.get('id')
    rule_id = req.finding.get('rule_id', 'unknown')
    file_path = req.finding.get('file', 'unknown')
    
    logger.info(f"Triage request received", extra_info={
        "event": "triage_request_received",
        "finding_id": finding_id,
        "rule_id": rule_id,
        "file": file_path,
        "context": req.context[:50] if req.context else ""
    })
    
    try:
        result = await analyze_finding(req.finding, req.context)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(f"Triage completed", extra_info={
            "event": "triage_completed",
            "finding_id": finding_id,
            "verdict": result.get('ai_verdict'),
            "confidence": result.get('ai_confidence'),
            "duration_ms": duration_ms
        })
        return result
    except Exception as e:
        logger.error(f"Triage failed: {e}", extra_info={
            "event": "triage_failed",
            "error": str(e),
            "finding_id": finding_id,
            "rule_id": rule_id
        })
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/epss")
def trigger_epss_http(req: EpssRequest):
    """
    HTTP endpoint for EPSS score synchronization.
    """
    import time
    start_time = time.time()
    cve = req.cve_id
    
    logger.info(f"EPSS sync request: {cve}", extra_info={
        "event": "epss_sync_request",
        "cve_id": cve
    })
    
    if not cve:
        raise HTTPException(status_code=400, detail="No CVE ID provided")
    
    # Create a database session for EPSS data persistence
    db = database.SessionLocal()
    try:
        # Sync scores from FIRST.org EPSS API to local database
        sync_epss_scores(db, [cve])
        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(f"EPSS sync completed: {cve}", extra_info={
            "event": "epss_sync_completed",
            "cve_id": cve,
            "duration_ms": duration_ms
        })
        return {"status": "synced", "cve": cve}
    except Exception as e:
        logger.error(f"EPSS Sync Failed: {e}", extra_info={"event": "epss_sync_failed", "error": str(e), "cve": cve})
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()  # Always close session to return connection to pool

@app.post("/anomaly_check")
def trigger_anomaly_check_http(req: AnomalyRequest):
    """
    HTTP endpoint for anomaly detection in pipeline metadata.
    """
    import time
    start_time = time.time()
    
    logger.info(f"Anomaly check request", extra_info={
        "event": "anomaly_check_request",
        "metrics_count": len(req.metadata),
        "metrics_keys": list(req.metadata.keys())
    })
    
    try:
        anomalies = detect_anomalies(req.metadata)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(f"Anomaly check completed", extra_info={
            "event": "anomaly_check_completed",
            "anomalies_found": len(anomalies),
            "duration_ms": duration_ms
        })
        return {"anomalies": anomalies}
    except Exception as e:
        logger.error(f"Anomaly Check Failed: {e}", extra_info={"event": "anomaly_check_failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "ok", "mode": "http_api"}

@app.get("/readiness")
async def readiness_check():
    """
    Checks if the LLM backend is ready to accept requests.
    Used by orchestrator to wait for AI services before processing.
    """
    # Allow skipping model check for testing/demo mode
    skip = os.getenv("SKIP_MODEL_CHECK", "false").lower() == "true"
    if skip:
        logger.debug("Readiness check skipped (demo mode)", extra_info={"event": "readiness_skipped"})
        return {"status": "skipped", "ready": True}
    
    url = os.getenv("LLM_BASE_URL")
    key = os.getenv("LLM_API_KEY")

    try:
         async with httpx.AsyncClient(timeout=3.0) as client:
             # Probe the LLM API's models endpoint (OpenAI-compatible)
             await client.get(f"{url}/models", headers={"Authorization": f"Bearer {key}"})
         logger.info("LLM backend ready", extra_info={"event": "readiness_ok", "llm_url": url})
         return {"status": "ok", "ready": True}
    except Exception as e:
         logger.warning(f"Readiness Check Failed: {e}", extra_info={"event": "readiness_failed", "llm_url": url, "error": str(e)})
         return Response(content="LLM Not Ready", status_code=503)

@app.on_event("startup")
async def startup_event():
    logger.info("Analysis Service HTTP API Started", extra_info={"event": "startup_complete"})

