"""
Main entry point for the AI Agent application.

This module exposes a FastAPI application that ingests security scanner findings,
persists them to a database, and orchestrates an AI-driven triage workflow using
LangGraph in the background.
"""

import subprocess, shutil, os, uuid
from dotenv import load_dotenv

# Load environment variables from .env file
# Load environment variables from .env file (parent directory)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from fastapi import FastAPI, BackgroundTasks, Form, UploadFile, File, Depends, Security, HTTPException
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session
from typing import List
from core import database, models
from services import parser
from workflow import graph

# --- CONFIGURATION ---
AI_API_KEY = os.getenv("AI_API_KEY", "default-dev-key")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    """
    Validates the API key from the request header.

    Args:
        api_key_header (str): The API key passed in the header.

    Returns:
        str: The validated API key.

    Raises:
        HTTPException: If the API key is invalid.
    """
    if api_key_header == AI_API_KEY:
        return api_key_header
    raise HTTPException(status_code=403, detail="Could not validate credentials")

app = FastAPI(title="Universal AI Security Agent")

# --- DYNAMIC ORCHESTRATION LOGIC ---
async def run_brain(scan_id, project, sha, findings, token):
    """
    Background task to orchestrate the AI triage process.

    This function clones the repository at the specific commit, creates a detailed
    graph of findings, and invokes the LangGraph workflow to process them.

    Args:
        scan_id (int): The ID of the database scan record.
        project (str): The project name (e.g., owner/repo).
        sha (str): The commit SHA to check out.
        findings (List[Dict]): List of finding dictionaries from the scanner.
        token (str): GitHub token for authentication.
    """
    unique_id = str(uuid.uuid4())[:8]
    temp_src = f"/tmp/brain_scan_{scan_id}_{unique_id}"
    repo_url = f"https://x-access-token:{token}@github.com/{project}.git"

    print(f"📡 Brain: Dynamically fetching {project} at commit {sha}...")

    try:
        # 1. CLONE & CHECKOUT: Fetch source code to provide context for the AI
        if project == "test/live-demo":
            print("🧪 Demo Mode: Skipping Git Clone. Creating dummy context.")
            os.makedirs(temp_src, exist_ok=True)
            # Create a dummy vulnerable file matching the SARIF report
            with open(os.path.join(temp_src, "app.py"), "w") as f:
                f.write("import os\n\ndef process_request(user_input):\n    # Vulnerable to Command Injection\n    os.system('echo ' + user_input)\n")
        else:
            subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_src], check=True)
            subprocess.run(["git", "-C", temp_src, "checkout", sha], check=True)

        # 2. POPULATE SNIPPETS: Read file content from disk to add code context to findings
        parser.populate_snippets(findings[:10], temp_src)

        # 3. 🔥 PRE-PERSIST: Save findings to database to generate IDs for the graph state
        db = database.SessionLocal()
        graph_findings = []
        try:
            for f in findings[:10]:
                db_finding = models.Finding(scan_id=scan_id, **f)
                db.add(db_finding)
                db.flush()  # Generates the ID immediately
                f["id"] = db_finding.id  # Attach ID to the dict for the graph
                graph_findings.append(f)
            db.commit()
        finally:
            db.close()

        # 4. TRIGGER THE WORKFLOW: Invoke the LangGraph app with the initial state
        initial_state = {
            "findings": graph_findings,
            "current_index": 0,
            "analyzed_findings": [],
            "source_path": temp_src, 
            "project": project
        }

        final = await graph.graph_app.ainvoke(
            initial_state, 
            config={"recursion_limit": 150} 
        )

        # 5. UPDATE FINAL RESULTS: Persist the AI's analysis and decisions back to the database
        db = database.SessionLocal()
        try:
            for f in final.get("analyzed_findings", []):
                if f.get("id"):
                    # Update the existing record with AI results
                    db_finding = db.query(models.Finding).get(f["id"])
                    if db_finding:
                        for key, value in f.items():
                            if hasattr(db_finding, key):
                                setattr(db_finding, key, value)
            db.commit()
            print(f"✅ Database: Updated AI results for scan {scan_id}")
        finally:
            db.close()

    except Exception as e:
        print(f"❌ Brain Orchestration Failed: {e}")
    finally:
        # Cleanup: Remove temporary directory
        if os.path.exists(temp_src):
            shutil.rmtree(temp_src)
            print(f"🗑️  Cleanup: Removed workspace {temp_src}")

# --- API ENDPOINTS ---
@app.post("/triage", status_code=202)
async def ingest(
    bt: BackgroundTasks,
    project: str = Form(...), # e.g., "AnaaaKareem/devsecops-test"
    sha: str = Form(...),     # The specific commit ID
    token: str = Form(...),   # The GITHUB_TOKEN passed from Actions
    files: List[UploadFile] = File(...),
    # Optional Pipeline Metrics for Anomaly Detection
    build_duration: float = Form(None),
    artifact_size: int = Form(None),
    changed_files: int = Form(None),
    test_coverage: float = Form(None),
    db: Session = Depends(database.get_db),
    _api_key: str = Depends(get_api_key)
):
    """
    Ingest endpoint for receiving security scan reports.

    Parses uploaded SARIF/JSON files, creates a scan record in the database,
    and initiates the background triage task.

    Args:
        bt (BackgroundTasks): FastAPI background task manager.
        project (str): Name of the project.
        sha (str): Commit SHA.
        token (str): GitHub token.
        files (List[UploadFile]): List of uploaded report files.
        db (Session): Database session.
    
    Returns:
        dict: Status message and the created scan ID.
    """
    findings = []
    # Loop through uploaded files and extract valid findings
    for f in files:
        findings.extend(parser.extract_findings(await f.read(), f.filename))
    
    # create scan record
    scan = models.Scan(project_name=project, commit_sha=sha)
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
    
    # Passing the token through to the background task
    bt.add_task(run_brain, scan.id, project, sha, findings, token)
    return {"status": "accepted", "scan_id": scan.id}

if __name__ == "__main__":
    import uvicorn
    # START SERVER: Run the API service on port 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000)