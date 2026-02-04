"""
Red Team Module (Hardened).

Updates:
- Enhanced System Prompt to strictly forbid unused imports (Go) and external libs (Node).
- Added logic to handle specific language constraints.
"""

import os
import re
import time
import traceback
import logging
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from typing import Dict, Any

from common.core.logger import get_logger

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from common.core.secrets import get_llm_config, get_setting

# Import verify_poc locally or from core
try:
    from core.sandbox import verify_poc
except ImportError:
    from sandbox import verify_poc

logger = get_logger(__name__)

# LLM Configuration from Vault
llm_config = get_llm_config()
# Determine model and kwargs
model = llm_config.get("model", "deepseek-coder-v2-lite")
model_kwargs = {}
if "kimi" in model.lower():
    model_kwargs["extra_body"] = {"chat_template_kwargs": {"thinking": True}}

llm = ChatOpenAI(
    base_url=llm_config.get("base_url", "http://localhost:1234/v1"),
    api_key=llm_config.get("api_key", "lm-studio"),
    model=model,
    model_kwargs=model_kwargs,
    temperature=0.1,
    timeout=int(llm_config.get("timeout", 600))
)

def run_red_team_attack(finding: Dict[str, Any], project: str, source_path: str) -> Dict[str, Any]:
    """
    Generates a PoC using AI and executes it in the sandbox.
    """
    file_path = finding.get("file", "")
    _, ext = os.path.splitext(file_path)
    
    # 🛡️ Guard: Skip unsupported languages
    if ext not in [".py", ".js", ".go", ".java"]:
        return {"success": False, "output": f"Extension {ext} not supported for PoC generation."}

    # 🛡️ New: Language-Specific Instructions to prevent common crashes
    lang_constraints = ""
    if ext == ".go":
        lang_constraints = (
            "GO RULES:\n"
            "- STRICTLY NO unused imports. If you import 'os' but don't use it, the compiler fails.\n"
            "- Do not use 'go.mod' specific libraries. Use standard library ONLY (net/http, strings, etc).\n"
            "- Write a single file 'main' package script.\n"
        )
    elif ext == ".js":
        lang_constraints = (
            "NODE.JS RULES:\n"
            "- Use ONLY standard 'http' or 'https' modules for network requests.\n"
            "- DO NOT use 'require' for external packages like 'axios', 'express', or 'node-fetch'. They are NOT installed.\n"
            "- Use 'child_process' if you need to execute shell commands.\n"
        )

    # Enhanced Prompt
    prompt = (
        f"You are a Senior QA Automation Engineer. Write a standalone {ext} script to VERIFY a specific vulnerability.\n"
        f"Target File: {file_path}\n"
        f"Vulnerability Message: {finding.get('message')}\n\n"
        
        f"--- ENVIRONMENT RULES (CRITICAL) ---\n"
        f"1. The script runs from the ROOT of the project (/app).\n"
        f"2. You MUST set up imports manually for nested files.\n"
        f"   - Python: `import sys; sys.path.append('/app')`\n"
        f"   - Node: `const target = require('./{file_path}')`\n"
        f"3. STANDALONE EXECUTION: You MUST MOCK all database/network calls. Do not try to connect to a real DB.\n"
        f"4. OUTPUT FORMAT warning: Do not add conversational text. Output ONLY the code block.\n\n"
        
        f"--- LANGUAGE CONSTRAINTS ---\n"
        f"{lang_constraints}\n\n"
        
        f"--- SUCCESS CRITERIA ---\n"
        f"If the vulnerability is successfully reproduced (triggered), print exactly:\n"
        f"   '[+] VULNERABILITY_TRIGGERED'\n"
        f"If the code handles the input safely, print exactly:\n"
        f"   '[-] EXPLOIT_FAILED'\n\n"
        
        f"--- VULNERABLE SNIPPET ---\n{finding.get('snippet')}\n\n"
        f"Respond ONLY with the executable code block."
    )
    
    try:
        # Rate Limiter from Vault config
        delay = int(get_setting("red_team_rate_limit_delay", "0"))
        if delay > 0:
            logger.info(f"⏳ Extending courtesy delay of {delay}s for Rate Limit...")
            time.sleep(delay)

        logger.info(f"[{project}] Generating PoC for {file_path}...")
        response = llm.invoke([HumanMessage(content=prompt)])
        
        # Clean the output
        poc = re.sub(r"```[a-zA-Z]*\n", "", response.content).replace("```", "").strip()
        
        # Execute in Sandbox
        success, output = verify_poc(source_path, poc, ext)
        
        # Check for our deterministic flags
        verification_success = False
        if "[+] VULNERABILITY_TRIGGERED" in output:
            verification_success = True
            logger.info(f"[{project}] 🚨 PoC SUCCESS: Vulnerability verified!")
        elif "[-] EXPLOIT_FAILED" in output:
            logger.info(f"[{project}] PoC Failed: Vulnerability not reproducible.")
        else:
            logger.warning(f"[{project}] PoC Indeterminate Output: {output[:200]}...")
            # Optional: If output contains "imported and not used", we could retry. 
            # For now, we accept the failure to keep complexity low.
        
        return {
            "success": verification_success, 
            "output": output,
            "poc_code": poc
        }
            
    except Exception as e:
        logger.error(f"[{project}] Red Team Error: {e}", extra_info={"traceback": traceback.format_exc()})
        return {"success": False, "output": str(e)}
