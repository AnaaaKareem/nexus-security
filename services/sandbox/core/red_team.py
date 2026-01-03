import os
import re
import traceback
import logging
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from typing import Dict, Any
from core.sandbox import verify_poc

from common.core.logger import get_logger

logger = get_logger(__name__)

# LLM Configuration
llm = ChatOpenAI(
    base_url=os.getenv("LLM_BASE_URL", "http://localhost:1234/v1"),
    api_key=os.getenv("LLM_API_KEY", "lm-studio"),
    default_headers={"X-API-Key": os.getenv("LLM_API_KEY", "lm-studio")},
    model=os.getenv("LLM_MODEL", "deepseek-coder-v2-lite"),
    max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
    temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
    timeout=int(os.getenv("LLM_TIMEOUT", "300")), 
    max_retries=int(os.getenv("LLM_MAX_RETRIES", "2"))
)

def run_red_team_attack(finding: Dict[str, Any], project: str, source_path: str) -> Dict[str, Any]:
    """
    Generates a PoC using AI and executes it in the sandbox.
    """
    line = finding.get("line", "?")
    file_path = finding.get("file", "")
    _, ext = os.path.splitext(file_path)
    
    # 🛡️ Guard: Skip if extension is unsupported
    if ext not in [".py", ".js", ".go", ".java", ".rb"]:
        return {"success": False, "output": f"Extension {ext} not supported."}

    prompt = (
        f"As a security researcher, generate a {ext} script to verify this vulnerability.\n"
        f"--- ENVIRONMENT ---\n"
        f"1. The entire repository is mounted at '/app'.\n"
        f"2. The target file is located at '/app/{file_path}'.\n"
        f"3. Working directory is '/app'.\n\n"
        f"--- IMPORT RULES ---\n"
        f"- For Python: You MUST use 'import sys; sys.path.append(\"/app\")'.\n"
        f"- To import the target, use the full relative path. Example: If the file is 'src/utils.py', use 'from src import utils'.\n"
        f"- For Node.js: Use absolute paths like const target = require('/app/{file_path}');\n\n"
        f"--- GOAL ---\n"
        f"Trigger the vulnerability: {finding.get('message')}\n"
        f"Code Context:\n{finding.get('snippet')}\n\n"
        f"Respond ONLY with code."
    )
    
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        poc = re.sub(r"```[a-zA-Z]*\n", "", response.content).replace("```", "").strip()
        
        success, output = verify_poc(source_path, poc, ext)
        
        return {
            "success": success, 
            "output": output,
            "poc_code": poc
        }
            
    except Exception as e:
        logger.error(f"[{project}] Red Team Error: {e}", extra_info={"event": "red_team_error", "project": project, "error": str(e), "traceback": traceback.format_exc()})
        return {"success": False, "output": str(e)}
