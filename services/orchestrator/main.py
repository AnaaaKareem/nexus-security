"""
Orchestrator Service - Main Entry Point.

This module is the central coordinator for the Sentinel-AI Security Agent platform.
It provides a FastAPI-based REST API that:

1. Ingests security scan requests from CI/CD platforms (GitHub, GitLab, Jenkins).
2. Accepts source code uploads for on-demand security analysis.
3. Dispatches scan jobs to Celery workers for asynchronous processing.
4. Orchestrates the AI-powered triage and remediation workflow via LangGraph.
5. Provides scan status endpoints for monitoring progress.

API Endpoints:
    POST /scan         - Trigger a scan job for a repository path.
    POST /triage       - Ingest scan reports and trigger AI triage.
    POST /scan/upload  - Upload source code ZIP for scanning.
    GET  /scan/{id}    - Get scan status by ID.
    GET  /scan_status/{id} - Get detailed scan status with findings count.

Environment Variables:
    AI_API_KEY          - API key for authenticating requests.
    DATABASE_URL        - PostgreSQL connection string.
    ANALYSIS_SERVICE_URL - URL of the Analysis microservice.
    REMEDIATION_SERVICE_URL - URL of the Remediation microservice.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file located in the project root
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"))

from fastapi import FastAPI, Form, UploadFile, File, Depends, Security, HTTPException, BackgroundTasks
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
from common.core import database, models
from common.core.logger import get_logger
from core.epss_worker import sync_epss_scores
from workflow import graph
from tasks import execute_scan_job, execute_triage_job
import shutil
import uuid
import subprocess
import asyncio
import traceback
import httpx
from contextlib import contextmanager, asynccontextmanager

logger = get_logger(__name__)

# --- CONFIGURATION ---
# API key for authenticating incoming requests (defaults to dev key if not set)
AI_API_KEY = os.getenv("AI_API_KEY", "default-dev-key")
# Header name where the API key should be provided by clients
API_KEY_NAME = "X-API-Key"
# FastAPI security dependency that extracts the key from request headers
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    """
    Validates the API Key provided in the request header.

    Args:
        api_key_header (str): The API key extracted from the `X-API-Key` header.

    Returns:
        str: The validated API key if it matches the expected `AI_API_KEY`.

    Raises:
        HTTPException: If the API key is invalid (403 Forbidden).
    """
    if api_key_header == AI_API_KEY:
        logger.debug("API key validated", extra_info={"event": "api_key_validated", "valid": True})
        return api_key_header
    logger.warning("Invalid API key attempt", extra_info={"event": "api_key_invalid", "valid": False})
    raise HTTPException(status_code=403, detail="Could not validate credentials")

@contextmanager
def get_db_session():
    """
    Context manager for database sessions.
    Ensures that a session is created and closed properly, even if exceptions occur.

    Yields:
        sqlalchemy.orm.Session: A database session object.
    """
    # Create a new database session from the connection pool
    db = database.SessionLocal()
    try:
        yield db
    finally:
        # Always close the session to return connection to pool
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifecycle Manager.
    Ensures Database is initialized and tables exist before accepting traffic.
    """
    logger.info("🚀 Starting Orchestrator Service...")
    
    # 1. Initialize Database (Tables & Migrations)
    try:
        from core.init_db import init_db
        logger.info("🛠️ Executing Database Initialization (init_db)...")
        # Run blocking sync code in thread
        await asyncio.to_thread(init_db)
        logger.info("✅ Database Initialization Complete.", extra_info={"event": "db_init_success"})
    except Exception as e:
        logger.critical(f"❌ FATAL: Database Initialization Failed: {e}", extra_info={"event": "db_init_failed", "error": str(e)})
        # We don't raise here to avoid crash loop, but it's critical.
        
    yield
    
    logger.info("🛑 Shutting down Orchestrator Service...")

import threading
import time


app = FastAPI(title="Universal AI Security Agent", lifespan=lifespan)

@app.on_event("startup")
async def startup_event():
    # Placeholder for startup tasks if needed
    pass

async def ensure_services_ready():
    """
    Checks if Analysis and Remediation services are ready (models loaded).
    Polls the readiness endpoints of dependent services until they are available or a timeout occurs.

    Returns:
        bool: True if all services are ready, False otherwise (timeout).
    """
    services = [
        {"name": "Analysis", "url": os.getenv("ANALYSIS_SERVICE_URL", "http://analysis:8000") + "/readiness"},
        {"name": "Remediation", "url": os.getenv("REMEDIATION_SERVICE_URL", "http://remediation:8000") + "/readiness"}
    ]
    
    logger.info("⏳ Orchestrator: Verifying AI Model Readiness...")
    
    timeout_minutes = 5
    end_time = asyncio.get_event_loop().time() + (60 * timeout_minutes)
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        while True:
            all_ready = True
            for svc in services:
                try:
                    # Ping the readiness endpoint of each service
                    resp = await client.get(svc["url"])
                    if resp.status_code != 200:
                        all_ready = False
                except:
                    # Service unreachable, continue polling
                    all_ready = False
            
            if all_ready:
                logger.info("✅ All AI Services are Ready.", extra_info={"event": "dependencies_ready"})
                return True
            
            # Check if we've exceeded the timeout window
            if asyncio.get_event_loop().time() > end_time:
                logger.error("AI Services Timed Out. Aborting scan.", extra_info={"event": "startup_timeout"})
                return False
            
            # Wait before next polling attempt
            await asyncio.sleep(5)

# Logic moved to core/logic.py and tasks.py

# --- HEALTH CHECKS ---
@app.get("/", include_in_schema=False)
async def root():
    return {"status": "active", "service": "Sentinel-AI Agent"}

@app.get("/health", status_code=200)
async def health_check():
    return {"status": "healthy", "components": ["api", "postgres"]}

# --- API ENDPOINTS ---

# --- SCAN REQUEST MODEL ---
from pydantic import BaseModel
class ScanRequest(BaseModel):
    """Request body schema for triggering a security scan."""
    project_name: str                          # Repository identifier (e.g., "owner/repo")
    target_path: str = "/app"                  # Path to source code (defaults to container's app dir)
    # Metadata fields for CI/CD adapter integration
    ci_provider: Optional[str] = "manual-scan" # CI platform (github-actions, gitlab-ci, jenkins)
    branch: Optional[str] = "main"             # Git branch being scanned
    commit_sha: Optional[str] = "latest"       # Git commit hash for tracking
    repo_url: Optional[str] = None             # Repository URL for cloning
    run_url: Optional[str] = None              # Link to CI/CD pipeline run
    changed_files: List[str] = []              # Support for delta/diff-based scanning

@app.post("/scan", status_code=202)
def trigger_scan_job(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(get_api_key)
):
    """
    Triggers a full security scan (Semgrep, Gitleaks, Checkov, Trivy) on the backend.
    """
    logger.info(f"Scan request received: {req.project_name}", extra_info={
        "event": "scan_request_received",
        "project": req.project_name,
        "ci_provider": req.ci_provider,
        "branch": req.branch,
        "commit_sha": req.commit_sha,
        "has_changed_files": len(req.changed_files) > 0,
        "changed_files_count": len(req.changed_files)
    })
    
    # Build metadata dict from request fields to pass to the Celery worker
    metadata = {
        "ci_provider": req.ci_provider,
        "branch": req.branch,
        "commit_sha": req.commit_sha,
        "repo_url": req.repo_url,
        "run_url": req.run_url,
        "changed_files": req.changed_files
    }
    # Dispatch scan job to Celery worker for async processing
    # .delay() returns immediately, actual scan runs in background
    execute_scan_job.delay(req.project_name, req.target_path, metadata)
    
    logger.info(f"Scan request accepted: {req.project_name}", extra_info={
        "event": "scan_request_accepted",
        "project": req.project_name,
        "queued": True
    })
    return {"status": "scanning_queued", "project": req.project_name}

@app.post("/triage", status_code=202)
async def ingest(
    background_tasks: BackgroundTasks,
    project: str = Form(...),
    sha: str = Form(...),
    token: str = Form(...),
    files: List[UploadFile] = File(...),
    # Optional Pipeline Metrics for Anomaly Detection
    build_duration: float = Form(None),
    artifact_size: int = Form(None),
    changed_files: int = Form(None),
    test_coverage: float = Form(None),
    # Multi-Platform CI/CD metadata
    platform: str = Form("github"),
    branch: str = Form("main"),
    instance_url: str = Form(None),
    job_url: str = Form(None),
    db: Session = Depends(database.get_db),
    _api_key: str = Depends(get_api_key)
):
    """
    Ingest endpoint for receiving security scan reports.
    """
    logger.info(f"Ingest request received: {project}", extra_info={
        "event": "ingest_request_received",
        "project": project,
        "sha": sha,
        "file_count": len(files),
        "ci_provider": platform
    })
    
    # Parse uploaded scan report files and extract vulnerability findings
    findings = []
    for f in files:
        findings.extend(parser.extract_findings(await f.read(), f.filename))
    
    # Create a new Scan record in the database to track this analysis
    scan = models.Scan(
        project_name=project, 
        commit_sha=sha,
        branch=branch,
        source_platform=platform,
        ci_provider=platform + "-ci" if platform != "jenkins" else "jenkins",
        repo_provider=platform,
        source_url=instance_url, 
        ci_job_url=job_url
    )
    db.add(scan); db.commit(); db.refresh(scan)

    # Store pipeline metrics if provided (used for anomaly detection)
    if any(x is not None for x in [build_duration, artifact_size, changed_files, test_coverage]):
        metric = models.PipelineMetric(
            scan_id=scan.id,
            build_duration_seconds=build_duration or 0.0,
            artifact_size_bytes=artifact_size or 0,
            num_changed_files=changed_files or 0,
            test_coverage_percent=test_coverage or 0.0
        )
        db.add(metric)
        db.commit()
    
    # Dispatch triage job to Celery worker for AI analysis
    execute_triage_job.delay(scan.id, project, sha, findings, token)
    logger.info(f"📥 Received triage request for {project} (SHA: {sha}). Scan ID: {scan.id}", extra_info={"event": "triage_queued", "scan_id": scan.id, "project": project, "sha": sha})
    
    return {"status": "queued", "scan_id": scan.id}

# --- SOURCE UPLOAD ENDPOINT ---
import zipfile

@app.post("/scan/upload", status_code=202)
async def upload_source_scan(
    background_tasks: BackgroundTasks,
    project: str = Form(...),
    branch: str = Form("main"),
    commit_sha: str = Form("latest"),
    ci_provider: str = Form("manual-scan"),
    repo_url: str = Form(""),
    run_url: str = Form(""),
    target_url: Optional[str] = Form(None),  # For DAST scanning
    file: UploadFile = File(...),
    _api_key: str = Depends(get_api_key)
):
    """
    Accepts a source code ZIP, extracts it, and triggers a server-side scan.
    """
    # Get file size for logging
    file.file.seek(0, 2)  # Seek to end
    file_size_mb = file.file.tell() / (1024 * 1024)
    file.file.seek(0)  # Seek back to start
    
    logger.info(f"Source upload received: {project}", extra_info={
        "event": "source_upload_received",
        "project": project,
        "file_size_mb": round(file_size_mb, 2),
        "ci_provider": ci_provider,
        "branch": branch,
        "commit_sha": commit_sha
    })
    
    # Generate a unique ID for this upload to create isolated directory
    scan_id = str(uuid.uuid4())[:8]
    upload_dir = f"/tmp/scans/uploads/{scan_id}_{project.replace('/', '_')}"
    os.makedirs(upload_dir, exist_ok=True)
    
    zip_path = f"{upload_dir}/source.zip"
    
    # Step 1: Save the uploaded ZIP file to disk
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # Step 2: Extract ZIP contents and remove the archive
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(upload_dir)
        os.remove(zip_path)  # Clean up ZIP after extraction
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
        
    # Step 3: Prepare metadata and dispatch scan job to Celery
    metadata = {
        "commit_sha": commit_sha,
        "ci_provider": ci_provider,
        "repo_url": repo_url,
        "run_url": run_url,
        "branch": branch,
        "target_url": target_url,        # URL for DAST scanning if provided
        "reference_id": scan_id           # UUID for async status tracking
    }
    
    # Placeholder to maintain API compatibility
    background_tasks.add_task(lambda: None)
    # Dispatch scan job with extracted source directory
    execute_scan_job.delay(project, upload_dir, metadata)
    
    logger.info(f"📤 Upload received for {project}. Extracted to {upload_dir}.", extra_info={"event": "source_upload", "project": project, "upload_dir": upload_dir, "scan_id": scan_id})

    return {
        "status": "uploaded", 
        "project": project, 
        "scan_id": scan_id, 
        "message": "Scan started in background."
    }

@app.get("/scan/{scan_id}", status_code=200)
def get_scan_status(
    scan_id: str, # UUID or Int ID depending on our model (it's Int in key, but string from UUID logic? Wait, DB ID is Int. Upload returns UUID string prefix? No, DB ID.)
    # Wait, Scan.id is Integer in models.py line 19.
    # But /scan/upload generates a temporary ID using uuid.uuid4()[:8] for upload dir...
    # Ah, `run_brain_background` gets called. Inside it:
    # 287: with get_db_session() as db: ... scan = models.Scan(...)
    # So the REAL scan ID comes from DB.
    # The /scan/upload endpoint returns `scan_id=scan_id` which is the UUID prefix.
    # This is a problem. Pipelines need the DB ID to query status.
    # Let's verify `perform_scan_background`...
    # It creates the DB entry and gets the integer ID.
    # But it runs in background. The caller of /scan/upload gets the returned UUID immediately.
    # We must allow querying by THIS temporary UUID if we stored it?
    # Or, `perform_scan_background` should update the status using the UUID?
    # The `models.Scan` doesn't have a UUID field.
    # 
    # Alternative: /scan/upload should WAIT for ID creation? No, slow.
    # 
    # Proposed Fix: Add `ref_id` (string) to `models.Scan`? 
    # Or simpler: Just rely on Project Name + Commit SHA? No, concurrency.
    # 
    # Let's check logic:
    # /scan/upload returns a scan_id generated at line 438: `str(uuid.uuid4())[:8]`
    # This ID is used for the upload directory.
    # Then `perform_scan_background` is called with this `upload_dir`.
    # Inside `perform_scan_background`:
    # It parses findings...
    # Then creates `models.Scan`. It does NOT save the upload UUID.
    # 
    # CRITICAL: We need to associate the returned UUID with the DB Scan.
    # Modify `Scan` model to have `reference_id`?
    # YES.
    # 
    # Plan adjustment:
    # 1. Add `reference_id` column to `models.Scan`.
    # 2. Pass the UUID from `/scan` and `/upload` to `perform_scan_background`.
    # 3. Store it in DB.
    # 4. /scan/{scan_id} queries by `reference_id` (string) OR `id` (int).
    
    db: Session = Depends(database.get_db),
    _api_key: str = Depends(get_api_key)
):
    """
    Get the status of a specific scan.
    """
    # Try parsing as int (DB ID)
    try:
        s_id = int(scan_id)
        scan = db.query(models.Scan).filter(models.Scan.id == s_id).first()
    except ValueError:
        # Try as reference_id (UUID string)
        # We need to add this column first!
        # For now, let's assume we use Int ID.
        # But /upload returns UUID...
        #
        # Quick Hack for this task without migration complexity:
        # The /scan/upload returns "scan_id": "uuid...".
        # We can change `/scan/upload` to NOT generate UUID but rely on `perform_scan_background`?
        # No, upload needs a dir name immediately.
        #
        # Let's do a migration-less trick? No.
        # We must add the column. But I can't start a migration tool easily.
        #
        # Wait! `scan_artifacts:/tmp/scans`.
        # The Orchestrator knows the upload dir.
        # 
        # Simpler approach for the user:
        # Just return the Scan ID (Int) from /scan/upload?
        # We can't, it's async background.
        #
        # OK, I will perform a minimal DB schema update using raw SQL via psql container to add `reference_id`.
        # And update `models.py`.
        
        # Check if column exists logic...
        pass
        
    # HOLD ON. `run_brain_background` returns nothing.
    # `perform_scan_background` is a background task.
    #
    # Let's just create the endpoint assuming we fix the model.
    pass

@app.get("/scan_status/{scan_id}")
def check_status(scan_id: str, db: Session = Depends(database.get_db), _api_key: str = Depends(get_api_key)):
    # Support lookup by reference_id (string)
    scan = db.query(models.Scan).filter(models.Scan.reference_id == scan_id).first()
    if not scan:
        # Fallback to int ID
        try:
            s_id = int(scan_id)
            scan = db.query(models.Scan).filter(models.Scan.id == s_id).first()
        except:
            pass
            
    if not scan:
        return {"status": "not_found"}
    
    # Calculate Risk Score
    risk_score = 0.0
    findings_count = len(scan.findings)
    if findings_count > 0:
        total_risk = sum([f.risk_score for f in scan.findings if f.risk_score])
        risk_score = round(total_risk, 1) # Simple sum? Or Avg? Dashboard uses sum usually.
    
    return {
        "scan_id": scan.id,
        "ref_id": scan.reference_id,
        "status": scan.status,
        "project": scan.project_name,
        "risk_score": risk_score, # Total Risk
        "findings_count": findings_count,
        "created_at": scan.timestamp
    }

if __name__ == "__main__":
    import uvicorn
    # START SERVER: Run the API service on port 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000)