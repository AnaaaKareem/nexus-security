import os
import re
import json
import logging
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from typing import Dict, Any

logger = logging.getLogger(__name__)

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

async def analyze_finding(finding: Dict[str, Any], project: str) -> Dict[str, Any]:
    """
    Analyzes a single finding using the LLM.
    """
    snippet = finding.get('snippet', "⚠️ NO CODE SNIPPET FOUND")
    message = finding.get('message', "No issue description")
    file_path = finding.get('file', "Unknown file")
    rule_id = finding.get('rule_id', 'Unknown Rule')
    line = finding.get('line', '?')
    
    logger.info(f"[{project}] 🔍 Analyzing Finding: {file_path}:{line} [{rule_id}]")

    prompt = (
        f"You are a Senior AppSec Engineer. Analyze the code for the specific issue described.\n\n"
        f"Respond ONLY in the following JSON format:\n"
        f"{{\n"
        f"  \"verdict\": \"TP\" or \"FP\",\n"
        f"  \"confidence\": 0.0 to 1.0,\n"
        f"  \"reasoning\": \"Short explanation\"\n"
        f"}}\n\n"
        f"CONTEXT:\n"
        f"File: {file_path}\n"
        f"Issue: {message}\n"
        f"Snippet:\n{snippet}"
    )

    ai_verdict = "FP"
    confidence = 0.0
    reasoning = ""
    
    try:
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        
        json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            ai_verdict = data.get("verdict", "FP").upper()
            confidence = float(data.get("confidence", 0.0))
            reasoning = data.get("reasoning", "")
        else:
            verdict = re.sub(r'[^a-zA-Z]', '', response.content).upper()
            ai_verdict = "TP" if "TP" in verdict else "FP"
            
    except Exception as e:
        logger.error(f"[{project}] ❌ Triage Error for {file_path}:{line}: {e}")

    return {
        **finding,
        "ai_verdict": ai_verdict,
        "ai_confidence": confidence,
        "ai_reasoning": reasoning,
        "triage_decision": "RV" if ai_verdict == "TP" else "FP"
    }
