import docker
import os
import subprocess
import re
import base64
import shutil
import tempfile
import uuid
import time
import socket
from typing import Tuple, Dict, Any, Optional
from common.core.logger import get_logger

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from common.core.secrets import get_container_image

logger = get_logger(__name__)

def verify_patch_in_sandbox(source_path: str, patch_code: str, target_file: str):
    """
    Applies a patch and runs Semgrep locally to verify the fix.

    Args:
        source_path (str): The root directory of the source code.
        patch_code (str): The new content of the fixed file.
        target_file (str): The relative path to the file being patched.

    Returns:
        tuple: (success (bool), output (str))
    """
    try:
        # 1. Write the fix directly to the temp directory on your host
        full_path = os.path.join(source_path, target_file)
        
        # Backup original file just in case
        if os.path.exists(full_path):
            with open(full_path, "r") as f:
                backup = f.read()
        else:
            backup = ""

        with open(full_path, "w") as f:
            f.write(patch_code)
        
        # 2. Run Semgrep directly on host (assuming semgrep CLI is installed)
        # We use cwd=source_path to ensure it scans the correct files
        scan = subprocess.run(
            ["semgrep", "scan", "--config=auto", "--error"], 
            cwd=source_path, 
            capture_output=True, 
            text=True
        )
        
        # Restore backup? Or keep patch? 
        # Usually, we want to revert verification changes so the PR process handles the real change.
        with open(full_path, "w") as f:
            f.write(backup)
        
        # 3. Return success if Semgrep found no issues (exit code 0)
        success = (scan.returncode == 0)
        logger.info(f"Patch verification finished. Success: {success}", extra_info={"event": "patch_verification", "target_file": target_file, "success": success})
        return success, scan.stdout + scan.stderr
    except Exception as e:
        logger.error(f"Patch verification failed: {e}", extra_info={"event": "patch_verification_error", "error": str(e)})
        return False, str(e)

def verify_poc(source_path: str, poc_code: str, file_extension: str) -> Tuple[bool, str]:
    """
    Executes a PoC in an isolated container against the source code.
    """
    runtime_map = {
        ".py":   {
            "image": get_container_image("python"), 
            "cmd": "python3 /app/poc_exploit.py",
            "install_cmd": "if [ -f requirements.txt ]; then pip install -r requirements.txt; fi"
        },
        ".js":   {
            "image": get_container_image("node"), 
            "cmd": "node /app/poc_exploit.js",
            "install_cmd": "if [ -f package.json ]; then npm install; fi"
        },
        ".go":   {
            "image": get_container_image("go"), 
            "cmd": "go run /app/poc_exploit.go",
            "install_cmd": "if [ -f go.mod ]; then go mod tidy; fi"
        },
        ".java": {
            "image": get_container_image("java"), 
            "cmd": "java /app/Exploit.java",
            "install_cmd": ""
        }
    }
    
    config = runtime_map.get(file_extension, runtime_map[".py"])
    client = docker.from_env()
    
    filename = "Exploit.java" if file_extension == ".java" else f"poc_exploit{file_extension}"
    container = None

    try:
        # Define Env
        env = {
            "PYTHONPATH": "/app",
            "NODE_PATH": "/app/node_modules",
            "PYTHONUNBUFFERED": "1"
        }

        # 1. Launch Container
        container = client.containers.run(
            image=config["image"],
            command="tail -f /dev/null",
            working_dir="/app", 
            environment=env,
            detach=True,
            network_mode="bridge"
        )
        
        # 2. Copy Source Code (Using tar stream to avoid host mounts)
        import tarfile
        import io
        
        # Create a tarball in memory
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            tar.add(source_path, arcname='.')
        buf.seek(0)
        
        # Put archive into container
        container.put_archive("/app", buf)

        # 3. Install Dependencies
        if config["install_cmd"]:
            # Check if installation succeeds
            res = container.exec_run(f"sh -c '{config['install_cmd']}'")
            if res.exit_code != 0:
                return False, f"Dependency Install Failed: {res.output.decode('utf-8')}"

        # 4. Inject PoC Code
        clean_code = _strip_llm_chatter(poc_code)
        b64_code = base64.b64encode(clean_code.encode('utf-8')).decode('utf-8')
        inject_cmd = f"sh -c 'printf \"%s\" \"{b64_code}\" | base64 -d > /app/{filename}'"
        container.exec_run(inject_cmd)

        # 5. Run Exploit
        logger.info(f"Running PoC: {filename}")
        res = container.exec_run(config["cmd"], stderr=True, stdout=True)
        
        output = res.output.decode('utf-8', errors='replace')
        
        if res.exit_code != 0:
            logger.warning(f"PoC Execution Error ({res.exit_code}):\n{output[:300]}")

        return (res.exit_code == 0), output

    except Exception as e:
        logger.error(f"Sandbox Error: {str(e)}")
        return False, f"Sandbox Error: {str(e)}"
    finally:
        if container:
            try:
                container.stop()
                container.remove()
            except: pass

def deploy_application(source_path: str, port: int, image: str = None, start_cmd: str = None) -> Dict[str, Any]:
    """
    Deploys the source code in a new container and returns the accessible URL.
    Uses 'wait_for_port' instead of sleep for reliability.
    """
    client = docker.from_env()
    container_name = f"dast_target_{uuid.uuid4().hex[:8]}"
    
    # Heuristics for Image/Command
    if not image:
        if os.path.exists(os.path.join(source_path, "requirements.txt")):
            image = "python:3.9-slim" 
            if not start_cmd:
                # Fallback heuristics for Python
                if os.path.exists(os.path.join(source_path, "main.py")):
                    start_cmd = "python3 main.py"
                else:
                    start_cmd = "python3 app.py" # Default fallback
        elif os.path.exists(os.path.join(source_path, "package.json")):
            image = "node:18-slim"
            if not start_cmd: start_cmd = "npm start"
        else:
             return {"success": False, "error": "Could not determine runtime image"}

    try:
        # Determine command chain: Install deps -> Run app
        cmd_chain = start_cmd
        if "python" in image:
            cmd_chain = f"sh -c 'if [ -f requirements.txt ]; then pip install -r requirements.txt; fi && {start_cmd}'"
        elif "node" in image:
            cmd_chain = f"sh -c 'if [ -f package.json ]; then npm install; fi && {start_cmd}'"

        # 1. Start Container
        # We bind the container port to a random ephemeral port on the host
        container = client.containers.run(
            image=image,
            name=container_name,
            command=cmd_chain,
            detach=True,
            working_dir="/app",
            ports={f"{port}/tcp": None}, # Docker assigns random port
            environment={"PYTHONUNBUFFERED": "1"}
        )
        
        # 2. Copy Source
        import tarfile
        import io
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            # Recursively add files with relative paths (Safe Method)
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, source_path)
                    tar.add(full_path, arcname=rel_path)
        buf.seek(0)
        container.put_archive("/app", buf)
        
        # 3. Wait for readiness (Polling)
        container.reload()
        mapped_ports = container.attrs['NetworkSettings']['Ports']
        host_port = None
        
        # Extract the random port assigned by Docker
        if f"{port}/tcp" in mapped_ports and mapped_ports[f"{port}/tcp"]:
            host_port = mapped_ports[f"{port}/tcp"][0]["HostPort"]
        
        if not host_port:
             _safe_cleanup(container)
             return {"success": False, "error": "Port mapping failed"}

        # Poll socket until open
        if not _wait_for_port(int(host_port), timeout=30):
             logs = container.logs().decode('utf-8')
             _safe_cleanup(container)
             return {"success": False, "error": f"App failed to start.\nLogs:\n{logs[:500]}"}

        return {
            "success": True,
            "url": f"http://localhost:{host_port}",
            "container_id": container.id,
            "container_name": container_name
        }

    except Exception as e:
        logger.error(f"Deploy failed: {e}")
        return {"success": False, "error": str(e)}

def _wait_for_port(port: int, host: str = 'localhost', timeout: float = 30.0) -> bool:
    """Check if a port is open by attempting to connect to it."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(1)
    return False

def _safe_cleanup(container):
    """Safely stop and remove a container, ignoring errors if it's already stopped."""
    try:
        container.kill()
    except Exception:
        pass # Ignore any error during kill (e.g. 409 Conflict if already stopped)
        
    try:
        container.remove(force=True)
    except Exception as e:
         logger.warning(f"Error removing container: {e}")

def _strip_llm_chatter(text: str) -> str:
    """Removes markdown code blocks and LLM reasoning tags if present."""
    # First, remove <think>...</think> or <thinking>...</thinking> blocks
    # These are common in reasoning models like qwen3, kimi, etc.
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL)
    
    # Then extract code from markdown blocks if present
    match = re.search(r"```(?:\w+)?\n(.*?)\n```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()