"""
LangGraph Workflow Definition.

This module defines the StateGraph for the AI Agent. It orchestrates the flow
from Triage -> Red Team -> Remediation -> Sanity Check -> Publish PR.
"""

import os, difflib
from typing import List, Dict, TypedDict
from dotenv import load_dotenv

# Load environment variables (safeguard for standalone use)
load_dotenv()

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from services.sandbox import verify_patch_in_sandbox, verify_poc
from services.pr_agent import create_security_pr, create_consolidated_pr
import re
from core import database, models
import uuid, traceback
from services.anomaly_detector import detect_anomalies

class GraphState(TypedDict):
    """
    Represents the state of the AI workflow as it processes findings.
    """
    findings: List[Dict]          # List of initial findings to process
    current_index: int            # Pointer to the current finding being processed
    analyzed_findings: List[Dict] # The accumulating list of processed results
    source_path: str              # Path to the checked-out source code
    project: str                  # Project name (owner/repo)
    anomalies: List[str]          # Detected pipeline anomalies

# Local AI Configuration
# Connects to LM Studio running locally
llm = ChatOpenAI(
    base_url=os.getenv("LLM_BASE_URL", "http://localhost:1234/v1"),
    api_key=os.getenv("LLM_API_KEY", "lm-studio"),
    default_headers={"X-API-Key": os.getenv("LLM_API_KEY", "lm-studio")},
    model=os.getenv("LLM_MODEL", "deepseek-coder-v2-lite"),
    max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
    temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
    timeout=int(os.getenv("LLM_TIMEOUT", "300")), # 👈 Increase to 5 minutes to allow for large patch generation
    max_retries=int(os.getenv("LLM_MAX_RETRIES", "2"))
)


def node_anomaly_check(state):
    """
    Node: CI/CD Anomaly Detector.
    
    analyzes pipeline metadata for suspicious activity before processing findings.
    """
    print("🕵️ Anomaly Node: Scanning pipeline context...")
    
    # Extract metadata from state (in a real app, this would come from the initial inputs)
    metadata = {
        "project": state.get("project"),
        # In a real integration, we'd pass branch/event from main.py inputs
        "branch": "unknown", 
        "event_name": "push"  # Default assumption
    }
    
    anomalies = detect_anomalies(metadata)
    
    if anomalies:
        print(f"🚨 Anomalies detected: {anomalies}")
    
    return {"anomalies": anomalies}

def node_triage(state):
    """
    Node: Triage Agent (Batch).
    
    Process ALL findings in one go.
    """
    findings = state.get("findings", [])
    analyzed_batch = []
    
    print(f"🧪 Batch Triage: Analyzing {len(findings)} findings...")
    
    for finding in findings:
        snippet = finding.get('snippet', "⚠️ NO CODE SNIPPET FOUND")
        message = finding.get('message', "No issue description")
        file_path = finding.get('file', "Unknown file")

        # Build Prompt
        prompt = (
            f"You are a Senior AppSec Engineer. Analyze the code for the specific issue described.\n\n"
            f"CRITERIA:\n"
            f"- If the code uses f-strings/concatenation in SQL: ALWAYS TP.\n"
            f"- If the code uses shell=True with user variables: ALWAYS TP.\n"
            f"- If the code uses pickle.loads(): ALWAYS TP.\n"
            f"- If you are unsure but it looks suspicious: respond TP.\n\n"
            f"CONTEXT:\n"
            f"File: {file_path}\n"
            f"Issue: {message}\n"
            f"Snippet:\n{snippet}\n\n"
            f"Respond ONLY with 'TP' or 'FP'."
        )

        ai_verdict = "FP"
        try:
            response = llm.invoke([HumanMessage(content=prompt)])
            verdict = re.sub(r'[^a-zA-Z]', '', response.content).upper()
            ai_verdict = "TP" if "TP" in verdict else "FP"
            print(f"🧠 Verdict for {file_path}: {ai_verdict}")
        except Exception as e:
            print(f"❌ Triage Error for {file_path}: {e}")

        # Update finding
        new_finding = {
            **finding,
            "ai_verdict": ai_verdict,
            "triage_decision": "RV" if ai_verdict == "TP" else "FP"
        }
        analyzed_batch.append(new_finding)
        
    return {"analyzed_findings": analyzed_batch}

def node_red_team(state):
    """
    Node: Red Team Agent (Batch).
    """
    analyzed = state.get("analyzed_findings", [])
    print(f"🔥 Batch Red Team: Checking exploitability for {len(analyzed)} findings...")
    
    for finding in analyzed:
        if finding.get("ai_verdict") == "TP":
            print(f"   -> Red Teaming: {finding.get('file')}")
            prompt = (
                f"As a security researcher, generate a Python verification script (PoC) "
                f"to confirm the following vulnerability in a controlled sandbox environment. "
                f"Respond ONLY with the Python code.\n\n"
                f"Code to test:\n{finding.get('snippet')}"
            )
            
            try:
                response = llm.invoke([HumanMessage(content=prompt)])
                poc = response.content
                success, output = verify_poc(state.get("source_path", "."), poc)
                
                save_telemetry(finding.get("id"), "RED_TEAM_POC", success, output)
                
                finding["red_team_success"] = success
                finding["red_team_output"] = output
            except Exception as e:
                print(f"❌ Red Team Node Error: {e}")
                finding["red_team_success"] = False

    return {"analyzed_findings": analyzed}

def node_prioritize(state):
    """
    Node: Prioritize (Batch).
    
    Assigns scores and SORTS the findings.
    """
    analyzed = state.get("analyzed_findings", [])
    print(f"⚖️  Batch Prioritize: Scoring {len(analyzed)} findings...")
    
    for finding in analyzed:
        ai_verdict = finding.get("ai_verdict", "FP")
        rt_success = finding.get("red_team_success", False)
        message = finding.get("message", "").lower()
        
        score = 1.0
        severity = "Low"
        
        if rt_success:
            score = 10.0
            severity = "Critical"
        elif ai_verdict == "TP":
            critical_keywords = ["rce", "sql injection", "command injection", "remote code execution"]
            if any(kw in message for kw in critical_keywords):
                score = 8.0
                severity = "High"
            else:
                score = 5.0
                severity = "Medium"
        
        finding["risk_score"] = score
        finding["severity"] = severity
        
        print(f"   -> {finding.get('file')}: {score} ({severity})")
        
        # Save to DB
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

    # SORTING STEP: Critical First
    analyzed.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    print("✅ Findings Sorted by Risk Score.")
    
    return {"analyzed_findings": analyzed}

def node_remediate(state):
    """
    Node: Remediate (Batch).
    
    Fixes findings in order (Highest Risk First).
    """
    analyzed = state.get("analyzed_findings", [])
    print(f"🛠️  Batch Remediation: Fixing {len(analyzed)} findings (Sorted)...")
    
    for finding in analyzed:
        if finding.get("ai_verdict") == "TP":
            print(f"   -> Generative Fix for: {finding.get('file')} (Risk: {finding.get('risk_score')})")
            
            prompt = (
                f"Fix the security vulnerability in this Python code.\n"
                f"ISSUE: {finding.get('message')}\n"
                f"CODE:\n{finding.get('snippet')}\n\n"
                f"Respond ONLY with the full corrected Python code block."
            )
            
            try:
                response = llm.invoke([HumanMessage(content=prompt)])
                clean_patch = re.sub(r"```[a-zA-Z]*\n", "", response.content).replace("```", "").strip()
                finding["remediation_patch"] = clean_patch
                print(f"      ✅ Fix Generated.")
            except Exception as e:
                print(f"      ❌ Fix Error: {e}")

    return {"analyzed_findings": analyzed}

def node_sanity_check(state):
    """
    Node: Sanity Check (Batch).
    """
    analyzed = state.get("analyzed_findings", [])
    print(f"🧐 Batch Sanity Check...")
    
    CRITICAL_MODULES = ["auth", "jwt", "session", "encrypt"]
    
    for finding in analyzed:
        patch = finding.get("remediation_patch")
        if not patch: continue
        
        deleted_criticals = [w for w in CRITICAL_MODULES if w in finding['snippet'] and w not in patch]
        is_empty = len(patch.strip()) == 0
        is_wiped = len(patch.splitlines()) < 2 and len(finding['snippet'].splitlines()) > 10
        
        if deleted_criticals or is_empty or is_wiped:
            print(f"   ❌ Blocked: {finding.get('file')} (Invalid Patch)")
            finding["remediation_patch"] = None
        else:
            print(f"   ✅ Passed: {finding.get('file')}")

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
    
    Optional gatekeeper step: Pauses for developer interaction before publishing.
    Enable via HUMAN_INTERACTION=true in .env
    """
    if os.getenv("HUMAN_INTERACTION", "false").lower() == "true":
        analyzed = state.get("analyzed_findings", [])
        fixes_count = sum(1 for f in analyzed if f.get("ai_verdict") == "TP" and f.get("remediation_patch"))
        
        print("\\n" + "="*50)
        print("          ✋ HUMAN INTERACTION REQUIRED")
        print("="*50)
        print(f"Stats: {len(analyzed)} findings analyzed.")
        print(f"       {fixes_count} fixes ready to propagate.")
        
        # Display Diffs
        source_path = state.get("source_path", ".")
        for f in analyzed:
            if f.get("ai_verdict") == "TP" and f.get("remediation_patch"):
                file_path = f.get("file")
                full_path = os.path.join(source_path, file_path)
                patch_content = f.get("remediation_patch")
                
                print(f"\\n📄 Diff for {file_path}:")
                try:
                    if os.path.exists(full_path):
                        with open(full_path, "r") as original:
                            original_lines = original.readlines()
                        
                        patch_lines = patch_content.splitlines(keepends=True)
                        # Ensure patch lines have newlines for difflib if they don't
                        patch_lines = [line if line.endswith('\\n') else line + '\\n' for line in patch_lines]
                        
                        diff = difflib.unified_diff(
                            original_lines, 
                            patch_lines, 
                            fromfile=f"a/{file_path}", 
                            tofile=f"b/{file_path}",
                            lineterm=''
                        )
                        diff_text = "".join(diff)
                        if diff_text:
                            print(diff_text)
                        else:
                            print("   (No changes detected / Identical content)")
                    else:
                        print(f"   ⚠️ Original file not found at {full_path}. Showing new content only.")
                        print(patch_content[:500] + "\\n..." if len(patch_content) > 500 else patch_content)
                except Exception as e:
                    print(f"   ❌ Failed to generate diff: {e}")

        # In a real async/web environment, this would need to verify an external signal.
        # For local dev purposes, we use simple input().
        try:
            choice = input(f"\\n🚀 Proceed with creating PR for {fixes_count} fixes? [Y/n]: ")
            if choice.lower() == 'n':
                print("🛑 Operation cancelled by user. Discarding patches.")
                # Discard patches so node_publish sees nothing to do
                for f in analyzed:
                    f["remediation_patch"] = None
        except Exception:
            pass # Handle case where input fails (non-interactive)

    return {}

def node_publish(state):
    """
    Node: Publish Agent.
    
    Collects all verified patches and opens a SINGLE consolidated Pull Request.
    """
    analyzed = state.get("analyzed_findings", [])
    project = state.get("project")
    
    # 1. Collect all valid patches
    file_updates = []
    print("🔍 Publish Node: Collecting patches for consolidated PR...")
    
    for finding in analyzed:
        patch = finding.get("remediation_patch")
        ai_verdict = finding.get("ai_verdict")
        
        if ai_verdict == "TP" and patch:
            file_updates.append({
                "path": finding.get("file"),
                "content": patch,
                "message": finding.get("message"),
                "line": finding.get("line"),
                "severity": finding.get("severity"),
                "risk_score": finding.get("risk_score")
            })
            print(f"   - Added fix for {finding.get('file')}")

    if not file_updates:
        print("🛑 Agent: No patches generated. Skipping PR.")
        return state

    # 2. Create Consolidated PR
    print(f"🚀 Agent: Attempting to create consolidated PR for {len(file_updates)} files...")
    try:
        pr_url = create_consolidated_pr(
            repo_name=project,
            branch_name=f"ai-fix-{uuid.uuid4().hex[:6]}",
            file_updates=file_updates,
            issue_summary=f"Security fixes for {len(file_updates)} findings"
        )
        
        # Update findings with the PR URL
        for finding in analyzed:
            if finding.get("remediation_patch"):
                finding["pr_url"] = pr_url
                
    except Exception as e:
        print(f"❌ Publish Error: {str(e)}")
        traceback.print_exc()

    return {"analyzed_findings": analyzed}

# --- GRAPH CONSTRUCTION ---
workflow = StateGraph(GraphState)

workflow.add_node("triage", node_triage)
workflow.add_node("red_team", node_red_team)
workflow.add_node("prioritize", node_prioritize)
workflow.add_node("remediate", node_remediate)
workflow.add_node("sanity_check", node_sanity_check) 
workflow.add_node("human_review", node_human_review)
workflow.add_node("publish", node_publish)
workflow.add_node("anomaly_check", node_anomaly_check)

workflow.set_entry_point("anomaly_check")

# LINEAR FLOW: No cycles
workflow.add_edge("anomaly_check", "triage")
workflow.add_edge("triage", "red_team")
workflow.add_edge("red_team", "prioritize")
workflow.add_edge("prioritize", "remediate")
workflow.add_edge("remediate", "sanity_check") 
workflow.add_edge("sanity_check", "human_review") 
workflow.add_edge("human_review", "publish")
workflow.add_edge("publish", END)

graph_app = workflow.compile()