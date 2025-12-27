"""
Verification Script for Vulnerability Prioritization.
"""
import sys
import os
# Add parent directory to path so we can import workflow
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workflow.graph import node_prioritize

def verify():
    print("🧪 Starting Prioritization Verification...")
    
    # CASE 1: Critical (Red Team Success) -> Expect 10.0, Critical
    state_crit = {
        "analyzed_findings": [{
            "id": None, # Skip DB save for test
            "file": "critical.py",
            "message": "Some issue",
            "ai_verdict": "TP",
            "red_team_success": True
        }]
    }
    res_crit = node_prioritize(state_crit)
    f_crit = res_crit["analyzed_findings"][-1]
    print(f"Case 1 (Exploit verified): Score={f_crit['risk_score']}, Severity={f_crit['severity']}")
    if f_crit['risk_score'] == 10.0 and f_crit['severity'] == "Critical":
        print("✅ PASS: Critical case handled correctly.")
    else:
        print("❌ FAIL: Critical case failed.")

    # CASE 2: High (TP + Keywords) -> Expect 8.0, High
    state_high = {
        "analyzed_findings": [{
            "id": None,
            "file": "high.py",
            "message": "Potential SQL Injection detected",
            "ai_verdict": "TP",
            "red_team_success": False
        }]
    }
    res_high = node_prioritize(state_high)
    f_high = res_high["analyzed_findings"][-1]
    print(f"Case 2 (Keyowrd SQLi): Score={f_high['risk_score']}, Severity={f_high['severity']}")
    if f_high['risk_score'] == 8.0 and f_high['severity'] == "High":
        print("✅ PASS: High case handled correctly.")
    else:
        print("❌ FAIL: High case failed.")

    # CASE 3: Medium (TP, no keywords) -> Expect 5.0, Medium
    state_med = {
        "analyzed_findings": [{
            "id": None,
            "file": "medium.py",
            "message": "Use of deprecated function",
            "ai_verdict": "TP",
            "red_team_success": False
        }]
    }
    res_med = node_prioritize(state_med)
    f_med = res_med["analyzed_findings"][-1]
    print(f"Case 3 (General TP): Score={f_med['risk_score']}, Severity={f_med['severity']}")
    if f_med['risk_score'] == 5.0 and f_med['severity'] == "Medium":
        print("✅ PASS: Medium case handled correctly.")
    else:
        print("❌ FAIL: Medium case failed.")

    # CASE 4: Low (FP) -> Expect 1.0, Low
    state_low = {
        "analyzed_findings": [{
            "id": None,
            "file": "low.py",
            "message": "False positive",
            "ai_verdict": "FP",
            "red_team_success": False
        }]
    }
    res_low = node_prioritize(state_low)
    f_low = res_low["analyzed_findings"][-1]
    print(f"Case 4 (FP): Score={f_low['risk_score']}, Severity={f_low['severity']}")
    if f_low['risk_score'] == 1.0 and f_low['severity'] == "Low":
        print("✅ PASS: Low case handled correctly.")
    else:
        print("❌ FAIL: Low case failed.")

if __name__ == "__main__":
    verify()
