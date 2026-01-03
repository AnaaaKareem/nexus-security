import os
import re
import traceback
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from common.core.logger import get_logger

logger = get_logger(__name__)

# LLM Configuration
llm = ChatOpenAI(
    base_url=os.getenv("LLM_BASE_URL", "http://localhost:1234/v1"),
    api_key=os.getenv("LLM_API_KEY", "lm-studio"),
    default_headers={"X-API-Key": os.getenv("LLM_API_KEY", "lm-studio")},
    model=os.getenv("LLM_MODEL", "deepseek-coder-v2-lite"),
    max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
    temperature=float(os.getenv("LLM_TEMPERATURE", "0.3")),
    timeout=int(os.getenv("LLM_TIMEOUT", "300")), 
    max_retries=int(os.getenv("LLM_MAX_RETRIES", "4"))
)

async def generate_fix_code(finding: Dict[str, Any], project: str) -> str:
    """
    Generates a patch for the finding using the LLM.
    """
    line = finding.get("line", "?")
    logger.info(f"[{project}] Generative Fix for: {finding.get('file')}:{line}", extra_info={"event": "fix_generation_start", "project": project, "file": finding.get('file'), "line": line})
    
    prompt = (
        f"Fix the security vulnerability in this code. Preserve the original language and style.\n"
        f"ISSUE: {finding.get('message')}\n"
        f"CODE:\n{finding.get('snippet')}\n\n"
        f"Respond ONLY with the full corrected code block."
    )
    
    clean_patch = None
    try:
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        clean_patch = re.sub(r"```[a-zA-Z]*\n", "", response.content).replace("```", "").strip()
    except Exception as e:
        logger.error(f"[{project}] Fix Error: {e}", extra_info={"event": "fix_generation_error", "project": project, "error": str(e), "traceback": traceback.format_exc()})
        raise e
        
    return clean_patch
