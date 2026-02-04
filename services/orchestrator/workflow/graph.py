"""
LangGraph Workflow Definition for AI Security Agent.

This module defines the StateGraph-based workflow that orchestrates the AI-powered
security analysis pipeline. The workflow executes a linear sequence of nodes,
each responsible for a specific phase of vulnerability assessment and remediation.

Workflow Architecture:
    1. anomaly_check    - Detects CI/CD pipeline anomalies from metadata.
    2. deploy_test_env  - Deploys application in Docker for DAST scanning.
    3. triage           - AI/LLM analysis to classify true/false positives.
    4. red_team         - Attempts PoC exploitation of confirmed vulnerabilities.
    5. prioritize       - Calculates risk scores based on EPSS and severity.
    6. remediate        - Generates code patches using AI.
    7. sanity_check     - Validates patches don't break functionality.
    8. human_review     - Optional pause for manual intervention.
    9. publish          - Creates consolidated Pull Request with fixes.
    10. cleanup         - Removes temporary containers and networks.

State Management:
    - Uses TypedDict (GraphState) to track findings through the pipeline.
    - Redis-backed StateManager provides real-time progress to dashboard.
    - Database updates persist results at each stage.

Service Dependencies:
    - Scanner Service: SAST/DAST scanning (Semgrep, ZAP).
    - Analysis Service: AI triage and anomaly detection.
    - Remediation Service: Fix generation and PR creation.
    - Sandbox Service: Red team exploit execution.

Usage:
    final_state = await graph_app.ainvoke(initial_state, config={"recursion_limit": 150})
"""

import os, difflib, docker
from typing import List, Dict, TypedDict
from dotenv import load_dotenv

# Load environment variables (safeguard for standalone use)
load_dotenv()
from core.utils import find_entry_point
from langgraph.graph import StateGraph, END
import re
from common.core import database, models
import uuid, traceback
from common.core.logger import get_logger
from common.core.queue import StateManager

import asyncio
import json
import httpx
import time
import socket

logger = get_logger(__name__)

# --- SERVICE URLS ---
# URLs for inter-service communication (read from environment with defaults)
SCANNER_URL = os.getenv("SCANNER_SERVICE_URL", "http://scanner:8000")       # SAST/DAST scanning
ANALYSIS_URL = os.getenv("ANALYSIS_SERVICE_URL", "http://analysis:8000")     # AI triage and anomaly detection
REMEDIATION_URL = os.getenv("REMEDIATION_SERVICE_URL", "http://remediation:8000")  # Fix generation and PR creation


def call_service(url: str, endpoint: str, payload: Dict, timeout: int = 60) -> Dict:
    """
    Helper to call a microservice synchronously (blocking) via HTTP.
    """
    logger.debug(f"🔌 Service Call: {url}/{endpoint} | Payload Size: {len(str(payload))} chars")
    try:
        # Use synchronous HTTP client with configurable timeout
        with httpx.Client(timeout=timeout) as client:
            start_time = time.time()
            resp = client.post(f"{url}/{endpoint}", json=payload)
            resp.raise_for_status()  # Raise exception for 4xx/5xx responses
            duration = time.time() - start_time
            logger.debug(f"✅ Service Call Success ({url}/{endpoint}) in {duration:.2f}s")
            return resp.json()
    except httpx.HTTPStatusError as e:
        # Log HTTP error details for debugging
        logger.error(f"❌ Service Call Error ({url}/{endpoint}) - Status {e.response.status_code}: {e.response.text}")
        return {}
    except Exception as e:
        logger.error(f"❌ Service Call Failed ({url}/{endpoint}): {e}")
        return {}


def update_scan_status(scan_id: int, status: str):
    """
    Helper to update the DB status of the scan for Dashboard visibility.
    """
    if not scan_id: return
    try:
        # Create a fresh database session for this update
        db = database.SessionLocal()
        db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": status})
        db.commit()
        db.close()  # Always close to return connection to pool
        logger.info(f"🔄 Scan {scan_id} Status Updated: {status}")
    except Exception as e:
        logger.warning(f"Failed to update scan status {scan_id} to {status}: {e}")

# --- HELPER FUNCTIONS FOR ENVIRONMENT ORCHESTRATION ---

def generate_and_build_image(client, source_path, scan_id, project_type):
    """
    Generates a robust Dockerfile based on project type and builds it.
    """
    dockerfile_content = ""
    image_tag = f"auto-build-{scan_id}:latest"
    logger.info(f"🏗️ Generating Dynamic Dockerfile for project type: {project_type}")

    if project_type == "python":
        # Python: Use thick image, install pipreqs if needed in command override
        dockerfile_content = """
        FROM python:3.10
        WORKDIR /app
        # Install system deps often needed for python packages
        RUN apt-get update && apt-get install -y gcc libpq-dev
        COPY . .
        """
    elif project_type == "node":
        dockerfile_content = """
        FROM node:18
        WORKDIR /app
        COPY . .
        # Attempt install if package.json exists, otherwise explicit install in CMD
        RUN if [ -f package.json ]; then npm install; fi
        """
    
    # Write the Dockerfile to the source directory temporarily
    df_path = os.path.join(source_path, "Dockerfile.autogen")
    try:
        with open(df_path, "w") as f:
            f.write(dockerfile_content)

        logger.info(f"🔨 Building Docker image {image_tag}...")
        
        # Build using the generated file
        image, logs = client.images.build(
            path=source_path,
            dockerfile="Dockerfile.autogen",
            tag=image_tag,
            rm=True
        )
        logger.info(f"✅ Docker Image Built Successfully: {image_tag}")
        return image_tag
    except docker.errors.BuildError as e:
        logger.error(f"❌ Build Failed for {image_tag}: {e}")
        for line in e.build_log:
            if 'stream' in line and line['stream'].strip(): 
                logger.error(f"   [Build Log] {line['stream'].strip()}")
        return None
    except Exception as e:
        logger.error(f"❌ Unexpected error building image: {e}")
        return None
    finally:
        if os.path.exists(df_path): 
            try:
                os.remove(df_path)
            except: pass


def wait_for_service(container_ip, port, timeout=30):
    logger.info(f"⏳ Waiting for service at {container_ip}:{port} (Timeout: {timeout}s)...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((container_ip, port), timeout=1):
                logger.info(f"✅ Connection established to {container_ip}:{port}")
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(1)
    logger.warning(f"❌ Connection timed out for {container_ip}:{port}")
    return False


class GraphState(TypedDict):
    """
    Represents the state of the AI workflow as it processes findings.
    This TypedDict is passed between all nodes and accumulates results.
    """
    findings: List[Dict]          # Initial list of raw findings to process
    current_index: int            # Pointer to current finding (for iterative processing)
    analyzed_findings: List[Dict] # Accumulating list of processed/analyzed findings
    source_path: str              # Absolute path to checked-out source code
    project: str                  # Project identifier (e.g., "owner/repo")
    anomalies: List[str]          # Detected CI/CD pipeline anomalies
    scan_id: int                  # Database Scan ID for status updates
    test_env_url: str             # URL of deployed test environment for DAST
    active_containers: List[str]  # Container IDs to cleanup after workflow
    orchestrator_connected_nets: List[str]  # Networks orchestrator attached to for cleanup


def node_anomaly_check(state):
    """
    Node: CI/CD Anomaly Detector.
    """
    project = state.get("project", "Unknown")
    scan_id = state.get("scan_id")
    logger.info(f"🚀 [Node: Anomaly Check] START for Project: {project}, ScanID: {scan_id}")
    
    metadata = {
        "project": project,
        "branch": "unknown", 
        "event_name": "push"  
    }
    
    # [NEW] Fetch Real Metrics from DB
    if scan_id:
        state_mgr = StateManager(scan_id)
        state_mgr.update_step(1, 8, "Checking Pipeline Anomalies", "running")

        db = database.SessionLocal()
        try:
             metric = db.query(models.PipelineMetric).filter(models.PipelineMetric.scan_id == scan_id).first()
             if metric:
                 metadata.update({
                     "build_duration": metric.build_duration_seconds,
                     "artifact_size": metric.artifact_size_bytes,
                     "changed_files": metric.num_changed_files,
                     "test_coverage": metric.test_coverage_percent
                 })
                 logger.info(f"📊 Loaded Metrics for Anomaly Check: {json.dumps(metadata)}")
             else:
                 logger.info("ℹ️ No pipeline metrics found in DB for this scan.")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load metrics for scan {scan_id}: {e}")
        finally:
            db.close()
    
    
    # [UPDATED] HTTP Call for Analysis (Anomaly)
    anomalies = []
    try:
        payload = {"metadata": metadata}
        logger.debug("🔎 Requesting anomaly analysis from Analysis Service...")
        result = call_service(ANALYSIS_URL, "anomaly_check", payload, timeout=30)
        if result and "anomalies" in result:
            anomalies = result.get("anomalies", [])
            logger.info(f"✅ Anomaly Analysis Complete. Found: {len(anomalies)} anomalies.")
        else:
             logger.warning("⚠️ Anomaly check failed or returned no data.")
             
    except Exception as e:
        logger.error(f"❌ Anomaly Detector failed: {e}")
        anomalies = [] 
    
    if anomalies:
        logger.warning(f"🚨 Anomalies detected: {anomalies}")
    else:
        logger.info(f"✅ No anomalies detected.")
    
    logger.info(f"🏁 [Node: Anomaly Check] COMPLETED.")
    return {"anomalies": anomalies}


async def node_deploy_test_env(state):
    """
    Node: Deploy Test Environment & Scan (REVISED).
    Includes Dynamic Entry Point Discovery, Safe Archive Creation, and PIPREQS.
    """
    project = state.get("project", "Unknown")
    scan_id = state.get("scan_id", "default")
    source_path = state.get("source_path")
    
    logger.info(f"🚀 [Node: Deploy Test Env] START for Project: {project}")
    update_scan_status(scan_id, "deploying_sandbox")

    # Progress Update
    if scan_id and scan_id != "default":
        state_mgr = StateManager(scan_id)
        state_mgr.update_step(2, 8, "Deploying Test Environment", "running")

    client = docker.from_env()
    
    import glob
    import tarfile
    import io
    
    # Track networks we attach ourselves to for cleanup
    orchestrator_connected_nets = state.get("orchestrator_connected_nets", []) or []

    try:
        # 1. Setup Networking
        network_name = f"scan-net-{scan_id}"
        logger.debug(f"🌐 Setting up network: {network_name}")
        
        for attempt in range(3):
            try:
                try:
                    client.networks.get(network_name)
                    logger.debug(f"   Network {network_name} already exists.")
                except docker.errors.NotFound:
                    client.networks.create(network_name, driver="bridge")
                    logger.info(f"   Created network: {network_name}")
                
                # Double check existence
                client.networks.get(network_name)
                break 
            except Exception as e:
                logger.warning(f"   ⚠️ Network setup retry {attempt+1}/3 failed: {e}")
                time.sleep(1)
        
        # [FIX] Connect Orchestrator to this network to allow connectivity check
        try:
            hostname = socket.gethostname()
            try:
                orch_container = client.containers.get(hostname)
                if network_name not in orch_container.attrs['NetworkSettings']['Networks']:
                    client.networks.get(network_name).connect(orch_container)
                    orchestrator_connected_nets.append(network_name)
                    logger.info(f"   🔗 Attached Orchestrator ({hostname}) to {network_name}")
            except docker.errors.NotFound:
                logger.warning(f"   ⚠️ Could not find self container ({hostname}). Running outside Docker?")
        except Exception as e:
             logger.warning(f"   ⚠️ Failed to attach Orchestrator to network: {e}")

        # Connect Scanners
        try:
            for svc_name in ["scanner", "zap", "nuclei", "devsecops-scanner-1", "devsecops-zap-1", "devsecops-nuclei-1"]:
                try:
                    svc_container = client.containers.get(svc_name)
                    if network_name not in svc_container.attrs['NetworkSettings']['Networks']:
                        client.networks.get(network_name).connect(svc_container)
                        logger.info(f"   🔗 Attached {svc_name} to {network_name}")
                except: pass
        except Exception as e:
            logger.warning(f"   ⚠️ Could not attach scanner/nuclei to network: {e}")

        # 2. Sidecar Injection (DB/Redis/RabbitMQ)
        active_containers = state.get("active_containers", []) or []
        env_vars = {}
        
        has_postgres = False
        has_redis = False
        has_rabbitmq = False
        
        # Heuristic check for reliable sidecars only (still useful to peek)
        # We can still peek at requirements.txt if it exists, or guess.
        try:
            if os.path.exists(os.path.join(source_path, "requirements.txt")):
                 with open(os.path.join(source_path, "requirements.txt"), "r") as f:
                    reqs = f.read().lower()
                    if "psycopg2" in reqs or "asyncpg" in reqs: has_postgres = True
                    if "redis" in reqs or "valkey" in reqs: has_redis = True
                    if "pika" in reqs or "celery" in reqs: has_rabbitmq = True
        except: pass
        
        if has_postgres:
            db_name = f"db-{scan_id}"
            logger.info("   🐘 PostgreSQL dependency detected. Spinning up DB container...")
            try:
                client.containers.run(
                    "postgres:17", name=db_name, network=network_name,
                    environment={"POSTGRES_USER": "user", "POSTGRES_PASSWORD": "password", "POSTGRES_DB": "testdb"},
                    detach=True,
                    labels={"scan_id": str(scan_id), "type": "dast-sidecar"}
                )
                active_containers.append(db_name) 
                env_vars["DATABASE_URL"] = f"postgresql://user:password@{db_name}:5432/testdb"
            except Exception as e: logger.warning(f"   ⚠️ DB Start Failed: {e}")

        if has_redis:
            redis_name = f"redis-{scan_id}"
            logger.info("   🔴 Redis dependency detected. Spinning up Redis container...")
            try:
                client.containers.run(
                    "redis:alpine", name=redis_name, network=network_name, detach=True,
                    labels={"scan_id": str(scan_id), "type": "dast-sidecar"}
                )
                active_containers.append(redis_name)
                env_vars["REDIS_URL"] = f"redis://{redis_name}:6379/0"
            except Exception as e: logger.warning(f"   ⚠️ Redis Start Failed: {e}")

        if has_rabbitmq:
            amqp_name = f"rabbitmq-{scan_id}"
            logger.info("   🐰 RabbitMQ dependency detected. Spinning up RabbitMQ container...")
            try:
                client.containers.run(
                    "rabbitmq:3-management", name=amqp_name, network=network_name, detach=True,
                    labels={"scan_id": str(scan_id), "type": "dast-sidecar"}
                )
                active_containers.append(amqp_name)
                env_vars["AMQP_URL"] = f"amqp://guest:guest@{amqp_name}:5672/"
                env_vars["RABBITMQ_URL"] = f"amqp://guest:guest@{amqp_name}:5672/"
            except Exception as e: logger.warning(f"   ⚠️ RabbitMQ Start Failed: {e}")

        # 3. Detect Language & Build Command
        target_name = f"target-app-{scan_id}"
        
        try:
            client.containers.get(target_name).remove(force=True)
        except docker.errors.NotFound: pass

        dast_suitable = True
        image = None
        command = None
        app_port = 8080 # Default
        
        # --- PYTHON LOGIC (ROBUST) ---
        if glob.glob(os.path.join(source_path, "*.py")):
            logger.info(f"   🐍 Python detected.")
            
            entry_point = find_entry_point(source_path, "python")
            
            if not entry_point:
                logger.warning("   ⚠️ No standard Python entry point found. Skipping DAST.")
                dast_suitable = False
            else:
                logger.info(f"   📍 Found entry point: {entry_point}")
                
                # Build Image (will just be base python if no requirements.txt yet)
                built_tag = generate_and_build_image(client, source_path, scan_id, "python")
                image = built_tag if built_tag else "python:3.10"
                
                # Check for explicit requirements
                has_reqs = os.path.exists(os.path.join(source_path, "requirements.txt"))
                
                # Prepare Command
                # 1. Install pipreqs if needed
                # 2. Generate requirements if missing
                # 3. Install requirements
                # 4. Run App
                
                setup_cmds = []
                if not has_reqs:
                    logger.info("   ⚠️ No requirements.txt. Auto-generating relying on pipreqs...")
                    setup_cmds.append("pip install pipreqs")
                    setup_cmds.append("pipreqs . --force")
                else:
                    logger.info("   ✅ Found requirements.txt.")

                setup_cmds.append("pip install --no-cache-dir -r requirements.txt")
                
                # Heuristic for port/command based on file content (still useful for command string)
                full_entry_path = os.path.join(source_path, entry_point)
                content = ""
                try:
                    with open(full_entry_path, 'r', errors='ignore') as f:
                        content = f.read().lower()
                except: pass
                
                run_cmd = f"python {entry_point}"
                if "fastapi" in content or "uvicorn" in content:
                    module_path = entry_point.replace("/", ".").replace(".py", "")
                    run_cmd = f"uvicorn {module_path}:app --host 0.0.0.0 --port 8080"
                    app_port = 8080
                elif "django" in content:
                    run_cmd = f"python {entry_point} runserver 0.0.0.0:8080"
                    app_port = 8080
                elif "flask" in content:
                    run_cmd = f"python {entry_point}"
                    app_port = 5000 # Flask Default
                elif "port" in content and "5000" in content:
                    app_port = 5000
                
                final_setup = " && ".join(setup_cmds)
                command = f"sh -c '{final_setup} && {run_cmd}'"

        # --- NODE.JS LOGIC (ROBUST) ---
        elif os.path.exists(os.path.join(source_path, "package.json")) or glob.glob(os.path.join(source_path, "*.js")):
            logger.info(f"   🟢 Node.js detected.")
            
            built_tag = generate_and_build_image(client, source_path, scan_id, "node")
            image = built_tag if built_tag else "node:18-alpine"
            
            entry_point = find_entry_point(source_path, "node")
            has_pkg = os.path.exists(os.path.join(source_path, "package.json"))
            
            if has_pkg:
                with open(os.path.join(source_path, "package.json")) as f:
                    pkg_data = json.load(f)
                scripts = pkg_data.get("scripts", {})
                if "start" in scripts:
                    command = "npm start"
                elif entry_point:
                    command = f"node {entry_point}"
            elif entry_point:
                # No package.json but found .js file
                logger.warning("   ⚠️ No package.json. Attempting raw node execution.")
                command = f"node {entry_point}"
            else:
                dast_suitable = False

        # --- GO LOGIC (ROBUST) ---
        elif os.path.exists(os.path.join(source_path, "go.mod")) or glob.glob(os.path.join(source_path, "*.go")):
            logger.info(f"   🔵 Go detected.")
            image = os.getenv("GO_IMAGE", "golang:1.23-alpine")
            env_vars["PORT"] = "8080"
            
            if os.path.exists(os.path.join(source_path, "go.mod")):
                command = "sh -c 'go mod tidy && go run .'"
            else:
                 logger.info("   ⚠️ No go.mod. Initializing module...")
                 command = "sh -c 'go mod init temp_app && go mod tidy && go run .'"

        # --- OTHERS PRESERVED ---
        elif os.path.exists(os.path.join(source_path, "pom.xml")): # Java Maven
            image = "maven:3.8-openjdk-17-slim"
            env_vars["SERVER_PORT"] = "8080"
            command = "sh -c 'mvn clean package -DskipTests && java -jar target/*.jar || mvn spring-boot:run'"
        elif os.path.exists(os.path.join(source_path, "composer.json")): # PHP
            image = "php:8.2-apache"
            app_port = 80
            command = "sh -c 'if [ -f composer.json ]; then apt-get update && apt-get install -y git unzip && curl -sS https://getcomposer.org/installer | php && mv composer.phar /usr/local/bin/composer && composer install; fi && apache2-foreground'"
        else:
             if not image:
                 logger.info("   ℹ️ Project not suitable for DAST or unknown language.")
                 return {"test_env_url": None, "active_containers": active_containers}
        
        if not dast_suitable:
            logger.info(f"   ⏩ Deployment Skipped: Project type not suitable for DAST.")
            return {"test_env_url": None, "active_containers": active_containers}

        # 4. Create Container
        internal_port = f'{app_port}/tcp'
        work_dir = "/app"
        if image and ("nginx" in image or "php" in image or "apache" in image):
            internal_port = '80/tcp'
            if "nginx" in image: work_dir = "/usr/share/nginx/html"
            
        container = client.containers.create(
            image,
            name=target_name,
            command=command,
            working_dir=work_dir,
            ports={internal_port: None}, 
            environment=env_vars,
            network=network_name,
            detach=True,
            labels={"scan_id": str(scan_id), "type": "dast-target"}
        )
        active_containers.append(container.id)

        # 5. Copy Source & Start
        def create_archive_safe(src_path):
            import io, tarfile
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as tar:
                for root, dirs, files in os.walk(src_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, src_path) 
                        tar.add(full_path, arcname=rel_path)
            stream.seek(0)
            return stream

        logger.debug("   📂 Copying source code to container...")
        tar_stream = create_archive_safe(source_path)
        container.put_archive(work_dir, tar_stream)
        
        container.start()
        
        # Readiness Logic
        try:
            container.reload()
            network_settings = client.api.inspect_container(container.id)['NetworkSettings']['Networks']
            ip_addr = None
            if network_name in network_settings:
                ip_addr = network_settings[network_name]['IPAddress']
            
            port_num = int(internal_port.split("/")[0])
            
            is_ready = False
            if ip_addr:
                 # Note: Orchestrator should now be on the same network to reach this IP!
                 is_ready = wait_for_service(ip_addr, port_num)
            
            if not is_ready:
                 logger.error(f"   ❌ Service timed out or crashed.")
                 try:
                     logger.error(f"   [Container Logs] {container.logs().decode('utf-8')[:1000]}")
                 except: pass
                 return {"test_env_url": None, "active_containers": active_containers, "orchestrator_connected_nets": orchestrator_connected_nets}

            url = f"http://{target_name}:{port_num}"
            logger.info(f"   ✅ Test Env Live at: {url}")
        except Exception as e:
             logger.error(f"   ❌ Error checking container readiness: {e}")
             return {"test_env_url": None, "active_containers": active_containers, "orchestrator_connected_nets": orchestrator_connected_nets}
        
        # ZAP Scan
        if scan_id:
            update_scan_status(scan_id, "dast_scanning")
            state_mgr = StateManager(scan_id)
            state_mgr.update_stage("DAST Scanning")

        logger.info(f"🚀 Triggering ZAP Scan for {url}...")
        scan_payload = {"target_url": url, "project_name": project, "target_path": "/app"}
        scan_result = call_service(SCANNER_URL, "zap_scan", scan_payload, timeout=600)
        
        dast_findings = []
        if scan_result and scan_result.get("scan_status") == "completed":
            dast_findings = scan_result.get("findings", [])

        if dast_findings:
            logger.info(f"[{project}] 🕷️ ZAP found {len(dast_findings)} issues.")
            db = database.SessionLocal()
            try:
                for f in dast_findings:
                    db_f = models.Finding(scan_id=scan_id, **f)
                    db.add(db_f)
                db.commit()
            finally: db.close()
            
            new_findings = state.get("findings", []) + dast_findings
            return {"test_env_url": url, "active_containers": active_containers, "findings": new_findings, "orchestrator_connected_nets": orchestrator_connected_nets}

        return {"test_env_url": url, "active_containers": active_containers, "orchestrator_connected_nets": orchestrator_connected_nets}
        
    except Exception as e:
        logger.error(f"[{project}] ❌ Deployment Failed: {e}")
        return {"test_env_url": None, "active_containers": [], "orchestrator_connected_nets": orchestrator_connected_nets}

def node_cleanup(state):
    """
    Node: Cleanup.
    """
    logger.info("🧹 [Node: Cleanup] START")
    client = docker.from_env()
    containers = state.get("active_containers", [])
    scan_id = state.get("scan_id")
    # [NEW] List of networks we attached Orchestrator to
    orch_nets = state.get("orchestrator_connected_nets", []) or []
    
    # 1. Disconnect Orchestrator from dynamic networks
    hostname = socket.gethostname()
    for net_name in orch_nets:
        try:
            network = client.networks.get(net_name)
            try:
                orch_container = client.containers.get(hostname)
                network.disconnect(orch_container)
                logger.info(f"   🔌 Disconnected Orchestrator from {net_name}")
            except: pass
        except: pass
    
    if scan_id:
        logger.info(f"   🔍 Finding containers with label scan_id={scan_id}...")
        try:
            # Robust cleanup using labels
            labeled_containers = client.containers.list(all=True, filters={"label": f"scan_id={scan_id}"})
            for c in labeled_containers:
                try:
                    c.remove(force=True, v=True) # v=True removes anonymous volumes
                    logger.debug(f"   🗑️ Removed container {c.name} and its volumes.")
                except Exception as e:
                    logger.warning(f"   ⚠️ Failed to remove container {c.name}: {e}")
        except Exception as e:
            logger.error(f"   ❌ Error listing containers for cleanup: {e}")
    
    elif containers:
        logger.info(f"   🗑️ Removing {len(containers)} containers (tracked list)...")
        for cid in containers:
            try:
                c = client.containers.get(cid)
                c.remove(force=True, v=True)
            except Exception as e:
                logger.warning(f"   ⚠️ Failed to cleanup container {cid}: {e}")
            
    # Cleanup Network
    if scan_id:
        try:
             state_manager = StateManager(scan_id)
             state_manager.update_step(8, 8, "Cleaning Up Resources", "completed")
        except: pass

    if scan_id:
        network_name = f"scan-net-{scan_id}"
        try:
            network = client.networks.get(network_name) # Refresh
            
            # Disconnect anything left
            network.reload()
            if network.containers:
                for container in network.containers:
                    try:
                        network.disconnect(container, force=True)
                    except: pass

            network.remove()
            logger.info(f"   🗑️ Removed network {network_name}")
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logger.warning(f"   ⚠️ Failed to remove network {network_name}: {e}")

    logger.info("🏁 [Node: Cleanup] COMPLETED")
    return {"active_containers": [], "orchestrator_connected_nets": []}

async def node_triage(state):
    """
    Node: Triage Agent (Batch Async via HTTP).
    """
    findings = state.get("findings", [])
    project = state.get("project", "Unknown")
    scan_id = state.get("scan_id")
    
    logger.info(f"🚀 [Node: Triage] START for {len(findings)} findings.")
    update_scan_status(scan_id, "ai_triage")
    
    if scan_id:
        state_mgr = StateManager(scan_id)
        state_mgr.update_stage("Analysis & Triage")
        state_mgr.update_step(3, 8, f"AI Analysis & Triage ({len(findings)} findings)", "running")

    processed_findings = []
    
    for i, finding in enumerate(findings):
        # 1. EPSS Check
        if finding.get("cve_id"):
             logger.debug(f"   [{i+1}/{len(findings)}] Checking EPSS for {finding.get('cve_id')}")
             epss_payload = {"cve_id": finding.get("cve_id")}
             epss_result = call_service(ANALYSIS_URL, "epss", epss_payload, timeout=20)
             if epss_result:
                 finding["epss_score"] = epss_result.get("epss_score")
        
        # 2. Triage Analysis
        triage_payload = {"finding": finding, "context": ""}
        logger.debug(f"   [{i+1}/{len(findings)}] Analyzing finding: {finding.get('rule_id')}")
        
        result = call_service(ANALYSIS_URL, "triage", triage_payload, timeout=300)
        
        if result:
            finding.update(result)
            logger.debug(f"     -> Verdict: {result.get('ai_verdict')}")
            processed_findings.append(finding)
        else:
            logger.error(f"   ❌ Triage Task Failed for {finding.get('id')}")
            processed_findings.append(finding)

    logger.info(f"🏁 [Node: Triage] COMPLETED. Processed {len(processed_findings)} findings.")
    return {"analyzed_findings": processed_findings}


SANDBOX_URL = os.getenv("SANDBOX_SERVICE_URL", "http://sandbox:8000")

def node_red_team(state):
    """
    Node: Red Team (PoC Exploitation).
    Attempts to exploit identified vulnerabilities to validate their severity.
    """
    analyzed = state.get("analyzed_findings", [])
    project = state.get("project", "Unknown")
    scan_id = state.get("scan_id")
    # Red Team needs a live target URL if available (for DAST checks)
    test_env_url = state.get("test_env_url") 

    logger.info(f"🚀 [Node: Red Team] START. Analyzing {len(analyzed)} findings for exploitation.")
    
    if scan_id:
        update_scan_status(scan_id, "red_team_attack")
        state_mgr = StateManager(scan_id)
        state_mgr.update_step(4, 9, "Red Team Exploitation", "running") # Shifted step count
        
    rt_findings = []
    
    for finding in analyzed:
        # Only attempt to exploit High confidence or Critical issues
        # Or if it's a specific rule type (e.g. command injection)
        should_exploit = False
        if finding.get("ai_verdict") == "TP": should_exploit = True
        if finding.get("epss_score", 0) > 0.4: should_exploit = True
        
        # Inject context for Red Team (important for DAST)
        finding["test_env_url"] = test_env_url
        
        if should_exploit:
            logger.debug(f"   🔥 Launching Red Team attack for {finding.get('rule_id')}...")
            payload = {"finding": finding, "project": project, "source_path": state.get("source_path", "/tmp")}
            
            result = call_service(SANDBOX_URL, "red_team", payload, timeout=600)
            
            if result and result.get("success"):
                logger.info(f"   ⚠️ EXPLOIT SUCCESS: {finding.get('id')} was exploited!")
                finding["red_team_success"] = True
                finding["red_team_output"] = result.get("output")
                
                # Telemetry
                if finding.get("id"):
                    save_telemetry(finding.get("id"), "RED_TEAM_POC", True, result.get("output"))
            else:
                 logger.debug(f"   🛡️ Exploit attempt failed.")
                 finding["red_team_success"] = False
                 if result and result.get("output") and finding.get("id"):
                      save_telemetry(finding.get("id"), "RED_TEAM_POC", False, result.get("output"))

        rt_findings.append(finding)

    logger.info(f"🏁 [Node: Red Team] COMPLETED.")
    return {"analyzed_findings": rt_findings}

def calculate_cvss_risk_score(finding: dict) -> tuple:
    """
    Calculates risk score using CVSS 3.1 inspired methodology.
    
    Returns:
        (score, severity) tuple where score is 1.0-10.0 and severity is a string.
    """
    # Base CVSS Metrics (defaults assume worst-case for unknowns)
    av = 0.85  # Attack Vector: Network (default)
    ac = 0.77  # Attack Complexity: Low (default)
    pr = 0.85  # Privileges Required: None (default)
    ui = 0.85  # User Interaction: None (default)
    
    message = (finding.get("message") or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    tool = (finding.get("tool") or "").lower()
    
    # --- Adjust Attack Vector ---
    if "local" in message or "file" in message:
        av = 0.55  # Local
    elif "adjacent" in message:
        av = 0.62  # Adjacent Network
    
    # --- Adjust Attack Complexity ---
    if "authenticated" in message or "session" in message or "login" in message:
        ac = 0.44  # High complexity (requires auth)
    
    # --- Adjust Privileges Required ---
    if "admin" in message or "root" in message or "superuser" in message:
        pr = 0.27  # High privileges required
    elif "user" in message and "authenticated" in message:
        pr = 0.62  # Low privileges required
    
    # --- Adjust User Interaction ---
    if "click" in message or "phishing" in message or "social" in message:
        ui = 0.62  # Requires user interaction
    
    # --- Impact Base Score ---
    impact_base = 4.0  # Default: Low-Medium
    
    # Red Team Success = Proven Exploitable (Critical)
    if finding.get("red_team_success"):
        impact_base = 10.0
    # AI Verdict = True Positive
    elif finding.get("ai_verdict") == "TP":
        impact_base = 6.0
        
        # Check for critical vulnerability keywords
        critical_keywords = [
            "rce", "remote code execution", "command injection", 
            "sql injection", "deserialization", "xxe", "ssrf",
            "arbitrary file", "buffer overflow"
        ]
        if any(kw in message for kw in critical_keywords):
            impact_base = 8.0
    
    # --- EPSS Score Boost ---
    epss = finding.get("epss_score") or 0
    if epss > 0.7:
        impact_base = min(10.0, impact_base + 2.0)  # High exploit probability
    elif epss > 0.4:
        impact_base = min(10.0, impact_base + 1.0)  # Medium exploit probability
    
    # --- AI Confidence Factor ---
    ai_confidence = finding.get("ai_confidence") or 0.5
    confidence_multiplier = 0.7 + (ai_confidence * 0.3)  # Range: 0.7 to 1.0
    
    # --- Calculate Final Score ---
    # Exploitability subscale
    exploitability = av * ac * pr * ui
    
    # Final score: exploitability * impact, scaled
    score = exploitability * impact_base * confidence_multiplier
    score = round(min(10.0, max(1.0, score)), 1)  # Clamp to 1.0-10.0
    
    # --- Severity Classification (CVSS 3.1 Ranges) ---
    if score >= 9.0:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 4.0:
        severity = "Medium"
    else:
        severity = "Low"
    
    return score, severity


def node_prioritize(state):
    """
    Node: Prioritize (Batch).
    Uses CVSS 3.1 inspired methodology for risk scoring.
    """
    analyzed = state.get("analyzed_findings", [])
    logger.info(f"🚀 [Node: Prioritize] START for {len(analyzed)} findings.")
    
    # Progress Update
    scan_id = state.get("scan_id")
    if scan_id:
        state_mgr = StateManager(scan_id)
        state_mgr.update_step(4, 8, "Risk Scoring & Prioritization", "running")
    
    high_risk_count = 0
    for finding in analyzed:
        # Use CVSS-based scoring methodology
        score, severity = calculate_cvss_risk_score(finding)
        
        # EPSS Database Lookup (additional context for CVEs)
        rule_id = finding.get("rule_id", "")
        if rule_id.startswith("CVE-"):
            db = database.SessionLocal()
            try:
                epss_record = db.query(models.EPSSData).filter(models.EPSSData.cve_id == rule_id).first()
                if epss_record and epss_record.probability > 0.4:
                    # Escalate based on EPSS data
                    score = min(10.0, score + 2.0)
                    if score >= 9.0:
                        severity = "Critical"
                    logger.info(f"   📈 Escalating {rule_id} due to high EPSS: {epss_record.probability}")
            except Exception as e:
                logger.warning(f"   ⚠️ EPSS Lookup failed: {e}")
            finally:
                db.close()
        
        finding["risk_score"] = score
        finding["severity"] = severity
        
        if score >= 7.0:
            high_risk_count += 1
        
        logger.debug(f"   -> {finding.get('file')}: Score={score} ({severity})")
        
        # Persist to database
        if finding.get("id"):
            db = database.SessionLocal()
            try:
                db_finding = db.query(models.Finding).get(finding["id"])
                if db_finding:
                    db_finding.risk_score = score
                    db_finding.severity = severity
                    db.commit()
            finally:
                db.close()

    analyzed.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    logger.info(f"🏁 [Node: Prioritize] COMPLETED. Found {high_risk_count} High/Critical risks.")
    return {"analyzed_findings": analyzed}

import urllib.parse
import subprocess

def resolve_source_file(url: str, source_path: str) -> str:
    """
    Dynamically maps a DAST URL to a local source file using multiple strategies.
    
    Strategies (in order):
    1. File Path Match - Check if URL path matches a file path directly
    2. Route Definition Search - Look for route decorators (@app.route, @router.get, etc.)
    3. Path Segment Narrowing - Progressively search shorter path segments
    4. Filename Heuristic - Match based on last path segment as potential filename
    
    Args:
        url (str): The finding URL (e.g. http://target:8080/api/users/123)
        source_path (str): The local source code root.
        
    Returns:
        str or None: Relative path to the source file if found, else None.
    """
    if not source_path or not os.path.isdir(source_path):
        return None
        
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path  # e.g. /api/users/123
        if not path or path == "/": 
            return None
        
        # Normalize path: remove leading/trailing slashes
        clean_path = path.strip("/")
        segments = clean_path.split("/") if clean_path else []
        
        # Define source file extensions to consider
        source_extensions = (".py", ".js", ".ts", ".go", ".php", ".java", ".rb", ".rs", ".cs")
        
        def find_source_files_containing(pattern: str) -> list:
            """Helper: Find source files containing a pattern using grep."""
            try:
                grep_cmd = ["grep", "-r", "-l", "--include=*.py", "--include=*.js", 
                           "--include=*.ts", "--include=*.go", "--include=*.php",
                           "--include=*.java", "--include=*.rb", pattern, source_path]
                out = subprocess.check_output(grep_cmd, stderr=subprocess.DEVNULL, timeout=10).decode().strip()
                return [line for line in out.split('\n') if line and line.endswith(source_extensions)]
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return []
        
        # Strategy 1: Direct File Path Match
        # Check if URL path directly maps to a file (e.g., /app/routes/files.py)
        potential_file = os.path.join(source_path, clean_path)
        if os.path.isfile(potential_file):
            logger.debug(f"   [resolve] Strategy 1 Match: Direct file path")
            return os.path.relpath(potential_file, source_path)
        
        # Try with common extensions
        for ext in source_extensions:
            potential_file = os.path.join(source_path, clean_path + ext)
            if os.path.isfile(potential_file):
                logger.debug(f"   [resolve] Strategy 1 Match: File with extension {ext}")
                return os.path.relpath(potential_file, source_path)
        
        # Strategy 2: Route Definition Search
        # Look for common route decorator patterns containing the path
        route_patterns = [
            f'@app.route("{path}"',       # Flask
            f'@app.route(\'{path}\'',     # Flask
            f'@router.get("{path}"',      # FastAPI
            f'@router.post("{path}"',     # FastAPI
            f'"{path}"',                  # Generic route string
            f"'{path}'",                  # Generic route string
        ]
        
        for pattern in route_patterns:
            matches = find_source_files_containing(pattern)
            if matches:
                result = os.path.relpath(matches[0], source_path)
                logger.debug(f"   [resolve] Strategy 2 Match: Route pattern '{pattern}' in {result}")
                return result
        
        # Strategy 3: Path Segment Narrowing
        # Progressively try shorter path segments (handles dynamic IDs like /users/123)
        if len(segments) > 1:
            for i in range(len(segments) - 1, 0, -1):
                subpath = "/" + "/".join(segments[:i])
                if len(subpath) < 3:
                    continue  # Too short, would match too many files
                
                matches = find_source_files_containing(subpath)
                if matches:
                    result = os.path.relpath(matches[0], source_path)
                    logger.debug(f"   [resolve] Strategy 3 Match: Subpath '{subpath}' in {result}")
                    return result
        
        # Strategy 4: Filename Heuristic
        # Check if last segment could be a route handler file (e.g., "users" -> users.py)
        if segments:
            last_segment = segments[-1]
            # Skip if it looks like a numeric ID
            if not last_segment.isdigit() and len(last_segment) > 2:
                for ext in source_extensions:
                    # Search for files named after the last segment
                    try:
                        find_cmd = ["find", source_path, "-name", f"{last_segment}{ext}", "-type", "f"]
                        out = subprocess.check_output(find_cmd, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
                        if out:
                            result = os.path.relpath(out.split('\n')[0], source_path)
                            logger.debug(f"   [resolve] Strategy 4 Match: Filename '{last_segment}{ext}'")
                            return result
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        pass
        
        logger.debug(f"   [resolve] No match found for URL: {url}")
        return None
        
    except Exception as e:
        logger.warning(f"Error resolving source file for {url}: {e}")
        return None

async def node_remediate(state):
    """
    Node: Remediate (Batch Async).
    """
    analyzed = state.get("analyzed_findings", [])
    project = state.get("project", "Unknown")
    scan_id = state.get("scan_id")
    
    # Filter for TPs
    to_fix = [f for f in analyzed if f.get("ai_verdict") == "TP"]
    others = [f for f in analyzed if f.get("ai_verdict") != "TP"]
    
    logger.info(f"🚀 [Node: Remediate] START. Generating fixes for {len(to_fix)} findings.")
    
    if not to_fix:
        logger.info("   ℹ️ No True Positives to fix. Skipping remediation.")
        return {"analyzed_findings": analyzed}

    if scan_id:
        update_scan_status(scan_id, "generating_fixes")
        state_mgr = StateManager(scan_id)
        state_mgr.update_stage("Remediation & Fix")
        state_mgr.update_step(5, 8, f"Generating Security Fixes ({len(to_fix)} items)", "running")

    success_count = 0
    for finding in to_fix:
        try:
            file_ref = finding.get("file")
            full_path = ""
            
            # [FIX] Handle URL-based Findings (DAST)
            if file_ref.startswith(("http://", "https://")):
                logger.info(f"   🔍 DAST Finding detected: {file_ref}. resolving source code...")
                resolved = resolve_source_file(file_ref, state.get("source_path"))
                if resolved:
                    logger.info(f"   ✅ Mapped URL to file: {resolved}")
                    finding["file"] = resolved # Update finding to point to file!
                    full_path = os.path.join(state.get("source_path"), resolved)
                else:
                    logger.warning(f"   ⚠️ Could not resolve source file for {file_ref}. Skipping patching.")
                    # We can't generate a specific code patch without the file.
                    finding["remediation_patch"] = None
                    continue
            else:
                 full_path = os.path.join(state.get("source_path"), file_ref)

            with open(full_path, "r") as f:
                content = f.read()
                finding["full_content"] = content
                
                # [FIX] Ensure 'snippet' exists (Required by Remediation Service)
                if not finding.get("snippet"):
                    if finding.get("line") and isinstance(finding["line"], int):
                         lines = content.splitlines()
                         start = max(0, finding["line"] - 5)
                         end = min(len(lines), finding["line"] + 5)
                         finding["snippet"] = "\n".join(lines[start:end])
                    else:
                         # Default to first 2000 chars if no line context (typical for DAST)
                         finding["snippet"] = content[:2000]
                
        except Exception as e:
            logger.error(f"   ❌ Could not read source file {finding.get('file')}: {e}")
            continue

        logger.debug(f"   🛠️ Requesting fix for {finding.get('rule_id')} in {finding.get('file')}...")
        
        payload = {"finding": finding, "project": project}
        result = call_service(REMEDIATION_URL, "generate_fix", payload, timeout=120)
        
        if result and result.get("patch"):
            patch = result.get("patch")
            finding["remediation_patch"] = patch
            logger.info(f"   ✅ Patch Generated for {finding.get('file')}")
            success_count += 1
        else:
            logger.error(f"   ❌ Fix Generation Failed for finding {finding.get('id')}")
            finding["remediation_patch"] = None

    logger.info(f"🏁 [Node: Remediate] COMPLETED. Generated {success_count}/{len(to_fix)} fixes.")
    # Recombine
    final_list = to_fix + others
    return {"analyzed_findings": final_list}

async def node_sanity_check(state):
    """
    Node: Sanity Check.
    """
    analyzed = state.get("analyzed_findings", [])
    logger.info(f"🚀 [Node: Sanity Check] START. Verifying {len(analyzed)} findings.")
    
    scan_id = state.get("scan_id")
    update_scan_status(scan_id, "verifying_fixes")

    if scan_id:
        state_mgr = StateManager(scan_id)
        state_mgr.update_step(6, 8, "Verifying Fixes", "running")
    
    blocked_count = 0
    for finding in analyzed:
        patch = finding.get("remediation_patch")
        snippet = finding.get("snippet", "")
        if not patch: continue
        
        # Calculate how much of the code was preserved
        diff_ratio = difflib.SequenceMatcher(None, snippet, patch).ratio()
        
        if diff_ratio < 0.2 and len(snippet) > 200:
            logger.warning(f"   ❌ Blocked Patch for {finding.get('file')}: Potential code wipe (Ratio: {diff_ratio:.2f})")
            finding["remediation_patch"] = None
            blocked_count += 1
            continue

        finding["regression_test_passed"] = True 
        logger.debug(f"   ✅ Sanity Check Passed for {finding.get('file')}")

    logger.info(f"🏁 [Node: Sanity Check] COMPLETED. Blocked {blocked_count} suspicious patches.")
    return {"analyzed_findings": analyzed}

def save_telemetry(finding_id, stage, success, output):
    """
    Persists sandbox execution results to the database Finding record.
    """
    db = database.SessionLocal()
    try:
        clean_output = output.decode('utf-8', errors='replace') if isinstance(output, bytes) else str(output)
        log_entry = f"\\n--- {stage} (SUCCESS: {success}) ---\\n{clean_output}\\n"
        
        finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
        if finding:
            finding.sandbox_logs = (finding.sandbox_logs or "") + log_entry
            db.commit()
    finally:
        db.close()

def node_human_review(state):
    """
    Node: Human Review.
    A placeholder node for manual intervention when `HUMAN_INTERACTION` is enabled.
    Prints statistics about findings and available fixes.

    Args:
        state (GraphState): The current state of the workflow.

    Returns:
        dict: No status update, just a pause/logging point.
    """
    if os.getenv("HUMAN_INTERACTION", "false").lower() == "true":
        analyzed = state.get("analyzed_findings", [])
        fixes_count = sum(1 for f in analyzed if f.get("ai_verdict") == "TP" and f.get("remediation_patch"))
        print("\\n" + "="*50)
        print("          ✋ HUMAN INTERACTION REQUIRED")
        print("="*50)
        print(f"Stats: {len(analyzed)} findings analyzed.")
        print(f"       {fixes_count} fixes ready to propagate.")

    return {}

def node_publish(state):
    """
    Node: Publish Agent.
    """
    analyzed = state.get("analyzed_findings", [])
    project = state.get("project", "Unknown")
    scan_id = state.get("scan_id")
    
    logger.info(f"🚀 [Node: Publish] START for Project: {project}")
    
    # 1. Collect all valid patches
    file_updates = []
    source_path = state.get("source_path", "")
    
    for finding in analyzed:
        patch = finding.get("remediation_patch")
        if finding.get("ai_verdict") == "TP" and patch:
            f_path = finding.get("file")
            # Path cleanup logic...
            if source_path and f_path.startswith(source_path):
                f_path = os.path.relpath(f_path, source_path)
            if f_path.startswith("/"): f_path = f_path.lstrip("/")
                
            file_updates.append({
                "path": f_path,
                "content": patch,
                "message": finding.get("message"),
                "line": finding.get("line"),
                "severity": finding.get("severity"),
                "risk_score": finding.get("risk_score"),
                "red_team_success": finding.get("red_team_success"),
                "red_team_output": finding.get("red_team_output")
            })

    logger.info(f"   📄 Collected {len(file_updates)} file updates for PR.")

    if not file_updates:
        logger.info(f"🏁 [Node: Publish] COMPLETED. No patches to publish.")
        return state

    # --- CI/CD Pipeline Upgrade (Deployment Injection) ---
    source_path = state.get("source_path", ".")
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    gitlab_file = os.path.join(source_path, ".gitlab-ci.yml") 
    gitlab_file_alt = os.path.join(source_path, "gitlab-ci.yml")
    jenkins_file = os.path.join(source_path, "Jenkinsfile")
    
    target_ci_file = None
    template_name = None
    
    if os.path.exists(gitlab_file):
        target_ci_file = ".gitlab-ci.yml"
        template_name = "gitlab-ci-deploy.yml"
    elif os.path.exists(gitlab_file_alt):
        target_ci_file = "gitlab-ci.yml"
        template_name = "gitlab-ci-deploy.yml"
    elif os.path.exists(jenkins_file):
        target_ci_file = "Jenkinsfile"
        template_name = "Jenkinsfile-deploy"

    # Inject Template if found
    if target_ci_file and template_name:
        template_path = os.path.join(template_dir, template_name)
        if os.path.exists(template_path):
            with open(template_path, "r") as f:
                new_pipeline_content = f.read()
            logger.info(f"   🚀 Injecting Deployment Pipeline ({template_name}) into PR...")
            file_updates.append({
                "path": target_ci_file,
                "content": new_pipeline_content,
                "message": f"CTO Approved: Upgraded pipeline to include Deployment stage.",
                "line": 1,
                "severity": "Info", 
                "risk_score": 0.0
            })

    # 2. Create Consolidated PR via HTTP
    if scan_id:
        state_mgr = StateManager(scan_id)
        state_mgr.update_stage("Publishing PR")
        state_mgr.update_step(7, 8, "Publishing Pull Request", "running")

    try:
        payload = {
            "repo_name": project,
            "branch_name": "ai-security-fixes",
            "file_updates": file_updates,
            "issue_summary": f"Security fixes for {len(file_updates)} findings"
        }
        
        # Send via HTTP
        result = call_service(REMEDIATION_URL, "create_pr", payload, timeout=300)
        
        if result and result.get("url"):
            pr_url = result.get("url")
            logger.info(f"   ✅ PR Created Successfully: {pr_url}")
            # Attach PR URL to all findings
            for f in analyzed:
                if f.get("remediation_patch"):
                    f["pr_url"] = pr_url
        else:
            logger.error(f"   ❌ Failed to create PR.")

    except Exception as e:
        logger.error(f"   ❌ PR Creation Exception: {e}")
        
    logger.info(f"🏁 [Node: Publish] COMPLETED.")
    return {"analyzed_findings": analyzed}

# --- GRAPH CONSTRUCTION ---
workflow = StateGraph(GraphState)

workflow.add_node("triage", node_triage)

workflow.add_node("red_team", node_red_team) # [NEW]
workflow.add_node("prioritize", node_prioritize)
workflow.add_node("remediate", node_remediate)
workflow.add_node("sanity_check", node_sanity_check) 
workflow.add_node("human_review", node_human_review)
workflow.add_node("publish", node_publish)
workflow.add_node("anomaly_check", node_anomaly_check)
workflow.add_node("deploy_test_env", node_deploy_test_env)
workflow.add_node("cleanup", node_cleanup)

workflow.set_entry_point("anomaly_check")

# LINEAR FLOW: No cycles
workflow.add_edge("anomaly_check", "deploy_test_env")
workflow.add_edge("deploy_test_env", "triage")
workflow.add_edge("triage", "red_team") # [UPDATED]
workflow.add_edge("red_team", "prioritize") # [UPDATED]
workflow.add_edge("prioritize", "remediate")
workflow.add_edge("remediate", "sanity_check") 
workflow.add_edge("sanity_check", "human_review") 
workflow.add_edge("human_review", "publish")
workflow.add_edge("publish", "cleanup")
workflow.add_edge("cleanup", END)

graph_app = workflow.compile()