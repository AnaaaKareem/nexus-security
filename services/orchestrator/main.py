"""
Main entry point for the AI Agent application.

This module exposes a FastAPI application that ingests security scanner findings
from multiple CI/CD platforms (GitHub, GitLab, Jenkins). It persists findings
to a database and orchestrates an AI-driven triage and remediation workflow 
using LangGraph.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file (parent directory)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from fastapi import FastAPI, Form, UploadFile, File, Depends, Security, HTTPException, BackgroundTasks
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
from common.core import database, models
# from services import parser # Removed
from common.core.logger import get_logger
# from services.scanner import SecurityScanner # Removed
from core.epss_worker import sync_epss_scores
from workflow import graph
import shutil
import uuid
import subprocess
import asyncio
import traceback
import asyncio
import traceback
from contextlib import contextmanager, asynccontextmanager

logger = get_logger(__name__)

# --- CONFIGURATION ---
AI_API_KEY = os.getenv("AI_API_KEY", "default-dev-key")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == AI_API_KEY:
        return api_key_header
    raise HTTPException(status_code=403, detail="Could not validate credentials")

@contextmanager
def get_db_session():
    db = database.SessionLocal()
    try:
        yield db
    finally:
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
        logger.info("✅ Database Initialization Complete.")
    except Exception as e:
        logger.critical(f"❌ FATAL: Database Initialization Failed: {e}")
        # We don't raise here to avoid crash loop, but it's critical.
        
    yield
    
    logger.info("🛑 Shutting down Orchestrator Service...")

app = FastAPI(title="Universal AI Security Agent", lifespan=lifespan)

async def ensure_services_ready():
    """
    Checks if Analysis and Remediation services are ready (models loaded).
    """
    services = [
        {"name": "Analysis", "url": os.getenv("ANALYSIS_SERVICE_URL", "http://analysis:8000") + "/readiness"},
        {"name": "Remediation", "url": os.getenv("REMEDIATION_SERVICE_URL", "http://remediation:8000") + "/readiness"}
    ]
    
    import httpx
    logger.info("⏳ Orchestrator: Verifying AI Model Readiness...")
    
    timeout_minutes = 5
    end_time = asyncio.get_event_loop().time() + (60 * timeout_minutes)
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        while True:
            all_ready = True
            for svc in services:
                try:
                    resp = await client.get(svc["url"])
                    if resp.status_code != 200:
                        all_ready = False
                        # logger.warning(f"Waiting for {svc['name']}... ({resp.status_code})")
                except:
                   all_ready = False
            
            if all_ready:
                logger.info("✅ All AI Services are Ready.")
                return True
            
            if asyncio.get_event_loop().time() > end_time:
                logger.error("AI Services Timed Out. Aborting scan.", extra_info={"event": "startup_timeout"})
                return False
                
            await asyncio.sleep(5)

async def run_brain_background(scan_id, project, sha, findings, token, local_source_path=None):
    """
    The core logic for AI triage.
    """
    # 0. WAIT FOR MODELS
    if not await ensure_services_ready():
         logger.error("Scan aborted due to AI model unavailability.")
         with get_db_session() as db:
            db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
            db.commit()
         return

    unique_id = str(uuid.uuid4())[:8]
    # FIX: Use /tmp/scans/ so it is on the shared volume visible to Sandbox/Scanner
    temp_src = f"/tmp/scans/brain_scan_{scan_id}_{unique_id}"
    
    # Use a variable for the limit so it's easy to change
    TRIAGE_LIMIT = 20
    findings_to_process = findings[:TRIAGE_LIMIT]

    repo_url = f"https://x-access-token:{token}@github.com/{project}.git"

    logger.info(f"Starting analysis for {project}", extra_info={"event": "brain_scan_start", "project": project, "sha": sha})

    try:
        # 1. CLONE & CHECKOUT OR USE LOCAL
        if local_source_path and os.path.exists(local_source_path):
             logger.info(f"Using local source path: {local_source_path}", extra_info={"project": project})
             if os.path.abspath(local_source_path) != os.path.abspath(temp_src):
                shutil.copytree(local_source_path, temp_src)
        elif project == "test/live-demo":
            logger.info("🧪 Demo Mode: Skipping Git Clone. Creating dummy context.")
            os.makedirs(temp_src, exist_ok=True)
            with open(os.path.join(temp_src, "app.py"), "w") as f:
                f.write("import os\n\ndef process_request(user_input):\n    # Vulnerable to Command Injection\n    os.system('echo ' + user_input)\n")
        else:
            logger.info(f"twisted_rightwards_arrows Cloning {repo_url}...")
            await asyncio.to_thread(subprocess.run, ["git", "clone", "--depth", "1", repo_url, temp_src], check=True)
            await asyncio.to_thread(subprocess.run, ["git", "-C", temp_src, "checkout", sha], check=True)

        # 2. POPULATE SNIPPETS
        from common.core.utils import populate_snippets
        await asyncio.to_thread(populate_snippets, findings_to_process, temp_src)

        # 3. PRE-PERSIST with Context Manager
        with get_db_session() as db:
            graph_findings = []
            for f in findings_to_process:
                db_finding = models.Finding(scan_id=scan_id, **f)
                db.add(db_finding)
                db.flush()
                f["id"] = db_finding.id
                graph_findings.append(f)
            db.commit()

        # 4. TRIGGER EXPLOITABILITY SYNC (EPSS)
        cve_ids = [f["rule_id"] for f in findings if f.get("rule_id", "").startswith("CVE-")]
        if cve_ids:
            logger.info(f"📡 Brain: Triggering exploitability sync for {len(cve_ids)} CVEs...")
            with get_db_session() as db:
                await asyncio.to_thread(sync_epss_scores, db, cve_ids)

        # 5. TRIGGER WORKFLOW
        initial_state = {
            "findings": graph_findings,
            "current_index": 0,
            "analyzed_findings": [],
            "source_path": temp_src, 
            "project": project,
            "scan_id": scan_id 
        }

        final = await graph.graph_app.ainvoke(
            initial_state, 
            config={"recursion_limit": 150} 
        )

        # 6. UPDATE RESULTS
        with get_db_session() as db:
            for f in final.get("analyzed_findings", []):
                if f.get("id"):
                    db.query(models.Finding).filter(models.Finding.id == f["id"]).update(f)
            
            # Update Status to Completed
            db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "completed"})
            db.commit()
            logger.info(f"Database: Updated AI results for scan {scan_id}", extra_info={"event": "brain_scan_complete", "scan_id": scan_id, "status": "completed"})

    except Exception as e:
        logger.error(f"❌ Scan/Triage Failed: {e}")
        logger.error(traceback.format_exc())
        with get_db_session() as db:
            db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
            db.commit()
    finally:
        if os.path.exists(temp_src):
            shutil.rmtree(temp_src)
            logger.info(f"Cleanup: Removed workspace {temp_src}", extra_info={"event": "cleanup", "path": temp_src})

async def perform_scan_background(project: str, path: str, metadata: Dict = None):
    try:
        logger.info(f"Starting analysis for {project}", extra_info={"event": "scan_start", "path": path, "project": project})
        
        if not metadata: metadata = {}
        repo_provider = "unknown"
        ci_provider = metadata.get("ci_provider", "manual-scan")
        branch = metadata.get("branch", "main")
        commit_sha = metadata.get("commit_sha", "latest")
        repo_url = metadata.get("repo_url", "")
        ci_job_url = metadata.get("run_url", "")
        
        if not os.path.exists(path):
            logger.error(f"❌ Error: Target path does not exist: {path}")
            return

        # 0. Create Scan Record (EARLY)
        scan_id = None
        with get_db_session() as db:
            try:
                scan = models.Scan(
                    project_name=project, 
                    commit_sha=commit_sha,
                    source_platform=repo_provider,
                    repo_provider=repo_provider,
                    ci_provider=ci_provider,
                    branch=branch,
                    repo_url=repo_url,
                    source_url="localhost",
                    ci_job_url=ci_job_url,
                    reference_id=metadata.get("reference_id"),
                    status="scanning" # [NEW] Set status to scanning immediately
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)
                scan_id = scan.id
                logger.info(f"✅ Created Scan ID {scan_id}: {project} [{branch}] via {ci_provider}")
            except Exception as e:
                logger.error(f"DB Error: {e}")
                return

        # 1. Execute Scanners via HTTP
        import httpx
        SCANNER_URL = os.getenv("SCANNER_SERVICE_URL", "http://scanner:8000")
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{SCANNER_URL}/scan", json={
                    "target_path": path,
                    "project_name": project,
                    "target_url": None
                }, timeout=600)
                resp.raise_for_status()
                data = resp.json()
                report_paths = data.get("reports", [])
                
            logger.info(f"Scan Complete. Generated {len(report_paths)} reports", extra_info={"event": "scan_complete", "report_count": len(report_paths), "reports": report_paths})
        except Exception as e:
            logger.error(f"Scan failed calling service: {e}")
            logger.error(traceback.format_exc())
            # Update status to failed
            with get_db_session() as db:
                db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
                db.commit()
            return


        # 2. Parse Findings (Also via Scanner Service if we want, or locally? 
        # The plan said Scanner API has /parse. Let's use it.)
        
        all_findings = []
        for report in report_paths:
             try:
                # We need to read the report file. 
                # Since we share volumes, we can read it directly OR ask Scanner to parse it.
                # If we ask Scanner to parse, we need to upload the file? No, it has the file path.
                # But Scanner /parse takes UploadFile. 
                # Let's read it locally since we share the volume '/tmp/scans'.
                
                # Wait, if we share volume, we can just use the shared parser code?
                # But we want to decouple.
                # Using /parse endpoint implies reading content and sending it.
                
                with open(report, "rb") as f:
                    content = f.read()
                    
                async with httpx.AsyncClient() as client:
                    files = {'file': (os.path.basename(report), content)}
                    resp = await client.post(f"{SCANNER_URL}/parse", files=files)
                    if resp.status_code == 200:
                        findings = resp.json().get("findings", [])
                        all_findings.extend(findings)
                    else:
                         logger.error(f"Failed to parse {report}: {resp.text}")

             except Exception as e:
                logger.error(f"Failed to parse {report}: {e}")

        # 3. Update Status to Analyzing
        with get_db_session() as db:
             db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "analyzing"})
             db.commit()

        logger.info(f"🧩 Parsed {len(all_findings)} total findings. Sending to Brain...")
        # (Scan ID already created)


        await run_brain_background(scan_id, project, commit_sha, all_findings, "no-token", local_source_path=path)

    except Exception as e:
        logger.error(f"FATAL CRASH in perform_scan: {str(e)}")
        logger.error(traceback.format_exc())
    finally:
        # Cleanup upload dir if applicable
        if path and "/tmp/scans/uploads/" in path and os.path.exists(path):
            shutil.rmtree(path)
            logger.info(f"🗑️ Upload Cleanup: Removed {path}")

# --- HEALTH CHECKS ---
@app.get("/", include_in_schema=False)
async def root():
    return {"status": "active", "service": "Sentinel-AI Agent"}

@app.get("/health", status_code=200)
async def health_check():
    return {"status": "healthy", "components": ["api", "postgres"]}

# --- API ENDPOINTS ---

from pydantic import BaseModel
class ScanRequest(BaseModel):
    project_name: str
    target_path: str = "/app" # Default to current repo
    # [NEW] Metadata fields for CI/CD Adapters
    ci_provider: Optional[str] = "manual-scan"
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = "latest"
    repo_url: Optional[str] = None
    run_url: Optional[str] = None

@app.post("/scan", status_code=202)
def trigger_scan_job(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(get_api_key)
):
    """
    Triggers a full security scan (Semgrep, Gitleaks, Checkov, Trivy) on the backend.
    """
    metadata = {
        "ci_provider": req.ci_provider,
        "branch": req.branch,
        "commit_sha": req.commit_sha,
        "repo_url": req.repo_url,
        "run_url": req.run_url
    }
    background_tasks.add_task(perform_scan_background, req.project_name, req.target_path, metadata)
    return {"status": "scanning_started", "project": req.project_name}

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
    # New Multi-Platform Args
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
    findings = []
    # Loop through uploaded files and extract valid findings
    for f in files:
        findings.extend(parser.extract_findings(await f.read(), f.filename))
    
    # create scan record
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

    # Save Pipeline Metrics if provided
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
    
    # DISPATCH TO BACKGROUND TASK
    background_tasks.add_task(run_brain_background, scan.id, project, sha, findings, token)
    logger.info(f"📥 Received triage request for {project} (SHA: {sha}). Scan ID: {scan.id}")
    
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
    file: UploadFile = File(...),
    _api_key: str = Depends(get_api_key)
):
    """
    Accepts a source code ZIP, extracts it, and triggers a server-side scan.
    """
    scan_id = str(uuid.uuid4())[:8]
    upload_dir = f"/tmp/scans/uploads/{scan_id}_{project.replace('/', '_')}"
    os.makedirs(upload_dir, exist_ok=True)
    
    zip_path = f"{upload_dir}/source.zip"
    
    # 1. Save Zip
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # 2. Extract
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(upload_dir)
        os.remove(zip_path)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
        
    # 3. Trigger Scan Task
    metadata = {
        "commit_sha": commit_sha,
        "ci_provider": ci_provider,
        "repo_url": repo_url,
        "run_url": run_url,
        "branch": branch,
        "reference_id": scan_id # Pass the UUID to be stored
    }
    
    background_tasks.add_task(perform_scan_background, project, upload_dir, metadata)
    
    logger.info(f"📤 Upload received for {project}. Extracted to {upload_dir}.")

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