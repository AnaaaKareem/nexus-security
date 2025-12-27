"""
Sandbox Verification Service.

Provides functionality to execute code in isolated Docker containers to:
1. Verify that a generated patch actually fixes a vulnerability (by running Semgrep).
2. Verify that a generated PoC (Proof of Concept) actually triggers the exploit.
"""

import docker, os, subprocess

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
        return success, scan.stdout + scan.stderr
    except Exception as e:
        return False, str(e)

def verify_poc(source_path: str, poc_code: str):
    """
    Executes a Proof of Concept script in a Docker container to check for exploitability.

    Args:
        source_path (str): The directory to mount into the container (the vulnerable code).
        poc_code (str): The python exploit code to run.

    Returns:
        tuple: (success boolean, output string)
    """
    try:
        client = docker.from_env()
        container = client.containers.run(
            image=SANDBOX_IMAGE,
            command="sleep 60",
            volumes={os.path.abspath(source_path): {'bind': '/app', 'mode': 'rw'}},
            working_dir="/app",
            detach=True,
            network_disabled=True
        )
    except Exception as e:
        return False, f"Docker unavailable: {e}"
    try:
        # 🛡️ Use Base64 encoding to avoid ALL quoting issues
        import base64
        b64_code = base64.b64encode(poc_code.encode('utf-8')).decode('utf-8')
        
        # Write the file using python inside the container
        container.exec_run(f"python3 -c \"import base64; open('poc_exploit.py', 'wb').write(base64.b64decode('{b64_code}'))\"")
        
        res = container.exec_run("python3 poc_exploit.py")
        return (res.exit_code == 0), res.output.decode()
    finally:
        container.stop(); container.remove()

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