"""
Check Demo Results.

Inspects the database to verify that:
1. Prioritization (risk_score, severity) was applied.
2. Pipeline Metrics were saved.
"""
import sys
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env logic if needed, but we can just connect to the known DB file
DB_PATH = "sqlite:///security_brain.db"
engine = create_engine(DB_PATH)
Session = sessionmaker(bind=engine)
session = Session()

def check():
    print("🔍 Inspecting Database Results for Scan ID 1...\n")
    
    # Check Findings
    print("--- Findings ---")
    result = session.execute(text("SELECT id, file, message, risk_score, severity, ai_verdict FROM findings WHERE scan_id = 1"))
    findings = result.fetchall()
    
    if not findings:
        print("❌ No findings found for Scan 1.")
    else:
        for f in findings:
            print(f"ID: {f.id}")
            print(f"File: {f.file}")
            print(f"Verdict: {f.ai_verdict}")
            print(f"Risk Score: {f.risk_score}")
            print(f"Severity: {f.severity}")
            
            if f.risk_score is not None and f.severity is not None:
                print("✅ Prioritization Saved!")
            else:
                print("❌ Prioritization Missing.")

    # Check Metrics
    print("\n--- Pipeline Metrics ---")
    result_metrics = session.execute(text("SELECT * FROM pipeline_metrics WHERE scan_id = 1"))
    metrics = result_metrics.fetchall()
    
    if not metrics:
        print("❌ No metrics found for Scan 1.")
    else:
        for m in metrics:
            print(f"Build Duration: {m.build_duration_seconds}s")
            print(f"Artifact Size: {m.artifact_size_bytes} bytes")
            print("✅ Metrics Saved!")

if __name__ == "__main__":
    check()
