"""
Sandbox Verification Service.

Provides functionality to execute code in isolated Docker containers to:
1. Verify that a generated patch actually fixes a vulnerability (by running Semgrep).
2. Verify that a generated PoC (Proof of Concept) actually triggers the exploit.
"""

import docker
import os
import subprocess
import re
import base64
from common.core.logger import get_logger

logger = get_logger(__name__)

# Define the container image to be used for the sandbox environment
SANDBOX_IMAGE = "python:3.9-slim"

def verify_patch_in_sandbox(source_path: str, patch_code: str, target_file: str):
    """
    Applies a patch and runs Semgrep locally to verify the fix.
    
    Args:
        source_path (str): The directory containing the code.
        patch_code (str): The content of the patch to apply of the entire fixed file.
        target_file (str): The relative path to the file being patched.

    Returns:
        tuple: (success boolean, output string)
    """
    try:
        # 1. Write the fix directly to the temp directory on your host
        full_path = os.path.join(source_path, target_file)
        with open(full_path, "w") as f:
            f.write(patch_code)
        
        # 2. Run Semgrep and Pytest directly on your Fedora host
        # We use cwd=source_path to ensure it scans the correct files
        scan = subprocess.run(
            ["semgrep", "scan", "--config=auto", "--error"], 
            cwd=source_path, 
            capture_output=True, 
            text=True
        )
        
        # 3. Return success if Semgrep is happy (exit code 0)
        success = (scan.returncode == 0)
        logger.info(f"Patch verification finished. Success: {success}", extra_info={"event": "patch_verification", "target_file": target_file, "success": success})
        return success, scan.stdout + scan.stderr
    except Exception as e:
        logger.error(f"Patch verification failed: {e}", extra_info={"event": "patch_verification_error", "error": str(e)})
        return False, str(e)

def verify_poc(source_path: str, poc_code: str, file_extension: str):
    """
    Executes a PoC in an isolated container with improved path handling.
    """
    runtime_map = {
        ".py":   {"image": os.getenv("PYTHON_IMAGE", "python:3.9-slim"), "cmd": "python3 /app/poc_exploit.py"},
        ".js":   {"image": os.getenv("NODE_IMAGE", "node:18-slim"), "cmd": "node /app/poc_exploit.js"},
        ".go":   {"image": os.getenv("GO_IMAGE", "golang:1.23-alpine"), "cmd": "go run /app/poc_exploit.go"},
        ".java": {"image": os.getenv("JAVA_IMAGE", "openjdk:17-slim"), "cmd": "java /app/Exploit.java"}
    }
    
    config = runtime_map.get(file_extension, runtime_map[".py"])
    client = docker.from_env()
    
    # Standardize filename based on extension
    filename = "Exploit.java" if file_extension == ".java" else f"poc_exploit{file_extension}"
    
    try:
        # 🧪 FIX: Set PYTHONPATH so Python can find modules in subdirectories of /app
        env = {
            "PYTHONPATH": "/app",
            "NODE_PATH": "/app",
            "PYTHONUNBUFFERED": "1"
        }

        # 1. Launch container with the project source mounted
        container = client.containers.run(
            image=config["image"],
            command="sleep 60",
            volumes={os.path.abspath(source_path): {'bind': '/app', 'mode': 'rw'}},
            working_dir="/app", # Stay at root so relative paths work
            environment=env,     # Inject paths
            detach=True,
            network_disabled=True # Isolation for safety
        )

        # 2. Clean and Encode the PoC
        clean_code = _strip_llm_chatter(poc_code)
        b64_code = base64.b64encode(clean_code.encode('utf-8')).decode('utf-8')
        
        # 3. Inject code using a robust shell command
        # We use 'printf' and 'base64 -d' to avoid python dependency in non-python images
        inject_cmd = f"sh -c 'printf \"%s\" \"{b64_code}\" | base64 -d > /app/{filename}'"
        inject_res = container.exec_run(inject_cmd)
        
        if inject_res.exit_code != 0:
            return False, f"Injection Failed: {inject_res.output.decode()}"

        # 4. Run the exploit and capture output
        res = container.exec_run(config["cmd"])
        output = res.output.decode('utf-8', errors='replace')
        
        return (res.exit_code == 0), output

    except Exception as e:
        logger.error(f"Sandbox Critical Error: {str(e)}", extra_info={"event": "sandbox_critical_error", "error": str(e)})
        return False, f"Sandbox Critical Error: {str(e)}"
    finally:
        # Ensure cleanup even on failure
        try:
            container.stop(); container.remove()
        except: pass

def _strip_llm_chatter(text: str) -> str:
    """Removes 'Below is a minimal script...' conversational text."""
    # Find code inside triple backticks if present
    match = re.search(r"```(?:\w+)?\n(.*?)\n```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no backticks, just return the text
    return text.strip()

def run_exploit_poc(source_path: str, poc_script: str):
    """
    Runs a generated PoC script in a temporary container.
    (Alternative implementation to verify_poc)
    """
    client = docker.from_env()
    container = client.containers.run(
        image="python:3.9-slim",
        command="sleep 30",
        volumes={os.path.abspath(source_path): {'bind': '/app', 'mode': 'rw'}},
        working_dir="/app",
        detach=True,
        network_disabled=True # Isolated from internet
    )
    try:
        # Write PoC to file and run it
        container.exec_run(f"python3 -c \"with open('poc.py', 'w') as f: f.write('''{poc_script}''')\"")
        result = container.exec_run("python3 poc.py")
        
        # Check for specific success string in output
        success = "EXPLOIT_SUCCESS" in result.output.decode()
        return success, result.output.decode()
    finally:
        container.stop()
        container.remove()