"""
Parser service for extracting findings from security scan reports.

Supports parsing of JSON/SARIF outputs from tools like Semgrep, Trivy, Checkov, and Gitleaks.
Also handles reading of source code snippets from the disk to provide context.
"""

# Import json for parsing report files and os for path handling
import json, os
# Import types for hints
from typing import List, Dict, Any

# Paths/Files to ignore when parsing findings to reduce noise
FORBIDDEN_PATHS = [
    ".github", 
    "venv", 
    "node_modules", 
    "k8s-specifications",   # Stop K8s noise
    "docker-compose",       # Stop Compose noise
    "Dockerfile",           # Stop Docker noise
    ".yml",                 # Stop all YAML noise
    ".yaml",                
    "semgrep.sarif",
    "gitleaks.json",
    "checkov.sarif"
]

# Define function to extract findings from raw file content based on filename/type
def extract_findings(content: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Parses a raw report file (bytes) and extracts standardized findings.

    Args:
        content (bytes): The raw file content uploaded to the server.
        filename (str): The name of the file (used to determine parsing logic, logic currently unified).

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each representing a finding with:
                              tool, rule_id, message, file, and line.
    """
    try:
        data = json.loads(content)
        extracted = []
        
        # --- 1. SARIF Logic (Semgrep, Trivy, Checkov) ---
        if "runs" in data:
            for run in data.get("runs", []):
                tool = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
                for res in run.get("results", []):
                    file_path = res.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    
                    # 🔥 FIREWALL: Skip forbidden files
                    if any(forbidden in file_path for forbidden in FORBIDDEN_PATHS):
                        # print(f"🚫 Firewall: Ignoring finding in {file_path}")
                        continue

                    extracted.append({
                        "tool": tool, 
                        "rule_id": res.get("ruleId"),
                        "message": res.get("message", {}).get("text", ""),
                        "file": file_path,
                        "line": res.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                    })
        
        # --- 2. Gitleaks Logic (Custom JSON format) ---
        elif isinstance(data, list) and len(data) > 0 and "Description" in data[0]:
            for issue in data:
                file_path = issue.get("File", "")
                
                # 🔥 FIREWALL: Skip forbidden files
                if any(forbidden in file_path for forbidden in FORBIDDEN_PATHS):
                    continue

                extracted.append({
                    "tool": "Gitleaks", 
                    "rule_id": issue.get("RuleID"),
                    "message": issue.get("Description"), 
                    "file": file_path,
                    "line": issue.get("StartLine")
                })

        # --- 3. OWASP ZAP Logic (JSON format) ---
        elif "site" in data:
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    extracted.append({
                        "tool": "OWASP ZAP",
                        "rule_id": alert.get("pluginid"),
                        "message": f"{alert.get('name')} (Risk: {alert.get('riskdesc')})\nURL: {alert.get('url', 'N/A')}\nSolution: {alert.get('solution', 'N/A')}",
                        "file": "dast-report", 
                        "line": 0
                    })
        
        print(f"✅ Parser: Extracted {len(extracted)} valid findings from {filename}")
        return extracted

    except Exception as e: 
        print(f"❌ Parser Error in {filename}: {e}")
        return []

def populate_snippets(findings: List[Dict], source_root: str):
    """
    Reads the source code for each finding from the disk and adds it to the finding dict.

    Args:
        findings (List[Dict]): The list of findings to update.
        source_root (str): The root directory where the repo is checked out.
    """
    for f in findings:
        # Initialize snippet as None or a clear message to avoid KeyErrors later
        f["snippet"] = "⚠️ Source code not found on local Fedora disk."
        
        path = os.path.join(source_root, f["file"])
        
        if os.path.exists(path):
            try:
                with open(path, 'r', errors='replace') as s:
                    lines = s.readlines()
                    
                    # SARIF/Gitleaks lines are 1-based; Python is 0-based
                    actual_line = f["line"] - 1 
                    
                    # Extract context (5 lines before and after)
                    start = max(0, actual_line - 5)
                    end = min(len(lines), actual_line + 5)
                    
                    f["snippet"] = "".join(lines[start:end])
            except Exception as e:
                print(f"❌ Could not read file {path}: {e}")