import subprocess
import os
import uuid
import concurrent.futures
from typing import List, Dict
from common.core.logger import get_logger

logger = get_logger(__name__)

SCAN_DIR = "/tmp/scans"

class SecurityScanner:
    def __init__(self):
        os.makedirs(SCAN_DIR, exist_ok=True)

    def run_scan(self, target_path: str, project_name: str, target_url: str = None) -> List[str]:
        scan_id = str(uuid.uuid4())[:8]
        shared_src_dir = os.path.join(SCAN_DIR, f"{scan_id}_src")

        # 1. Prepare Source in Shared Volume
        if not os.path.exists(shared_src_dir):
            try:
                subprocess.run(["cp", "-r", target_path, shared_src_dir], check=True)
                subprocess.run(["chmod", "-R", "o+rw", shared_src_dir], check=True)
                subprocess.run(["chmod", "777", SCAN_DIR], check=False)
            except Exception as e:
                logger.error(f"Failed to copy source: {e}", extra_info={"event": "copy_source_failed", "error": str(e)})
                return []

        # Define all tool commands
        tasks = {
            "semgrep": ["semgrep", "scan", "--config=p/security-audit", "--sarif", "--quiet", "-o", f"/tmp/scans/semgrep_{scan_id}.sarif", f"/tmp/scans/{scan_id}_src"],
            "gitleaks": ["gitleaks", "detect", f"--source=/tmp/scans/{scan_id}_src", f"--report-path=/tmp/scans/gitleaks_{scan_id}.json", "--redact", "--no-banner", "--exit-code=0"],
            "trivy": ["trivy", "fs", "--format", "sarif", "--output", f"/tmp/scans/trivy_{scan_id}.sarif", "--scanners", "vuln,secret,config", f"/tmp/scans/{scan_id}_src"]
        }

        # 🔥 NEW: Add DAST Task if target_url is provided
        if target_url:
            tasks["zap"] = [
                "sh", "-c",
                # Ensure report file exists, run zap (ignoring failures), then ONLY copy if report has content size > 0
                f"touch /home/zap/zap_report.json; zap-baseline.py -t {target_url} -J zap_report.json -m 5; if [ -s /home/zap/zap_report.json ]; then cp /home/zap/zap_report.json /zap/wrk/zap_{scan_id}.json; else echo 'Empty Report'; exit 1; fi"
            ]

        report_files = []
        # 🚀 Execute all scanners simultaneously
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {}
            for name, cmd in tasks.items():
                # ZAP might return 1 (Fail) or 2 (Warn) if issues found. 3 is system error.
                codes = [0, 1, 2] if name == "zap" else [0]
                futures[executor.submit(self._exec_docker, name, cmd, allowed_exit_codes=codes)] = name

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                if future.result():
                    ext = "json" if name in ["gitleaks", "zap"] else "sarif"
                    report_files.append(os.path.join(SCAN_DIR, f"{name}_{scan_id}.{ext}"))
        
        return report_files

    def _exec_docker(self, container_name, cmd_list, output_file=None, allowed_exit_codes=[0]):
        """
        Runs 'docker exec <container_name> <cmd...>'
        """
        logger.info(f"Exec in {container_name}: {' '.join(cmd_list)}", extra_info={"event": "exec_start", "container": container_name, "command": cmd_list})
        
        full_cmd = ["docker", "exec", container_name] + cmd_list
        
        try:
            if output_file:
                # Capture stdout to file
                res = subprocess.run(full_cmd, capture_output=True, text=True)
                if res.returncode not in allowed_exit_codes:
                    logger.error(f"❌ {container_name} failed ({res.returncode}): {res.stderr}", extra_info={"event": "exec_failed", "container": container_name, "exit_code": res.returncode})
                    return False
                
                with open(output_file, 'w') as f:
                    f.write(res.stdout)
                return True
            else:
                # Run and wait
                res = subprocess.run(full_cmd, capture_output=True, text=True)
                if res.returncode not in allowed_exit_codes:
                     logger.error(f"❌ {container_name} failed ({res.returncode}): {res.stderr}", extra_info={"event": "exec_failed", "container": container_name, "exit_code": res.returncode})
                     return False
                return True
        except Exception as e:
            logger.error(f"Error executing in {container_name}: {e}")
            return False
