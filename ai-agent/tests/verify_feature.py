"""
Verification Script for Anomaly Detector.
"""
import os
import sys

# Add parent directory to path so we can import core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.anomaly_detector import detect_anomalies

def verify():
    print("🧪 Starting Verification...")
    
    # Test 1: Normal Data (should be clean)
    normal_meta = {
        "project": "test/repo",
        "branch": "feature/123",
        "event_name": "push",
        "build_duration": 100.0,
        "artifact_size": 52428800, # 50MB
        "changed_files": 5,
        "test_coverage": 80.0
    }
    print(f"\nrunning check on Normal Data: {normal_meta}")
    anomalies = detect_anomalies(normal_meta)
    if not anomalies:
        print("✅ PASS: No anomalies detected for normal data.")
    else:
        print(f"❌ FAIL: Unexpected anomalies: {anomalies}")

    # Test 2: Anomaly Data (should flag)
    # Huge duration, tiny artifact, mass deletion, zero coverage
    anomaly_meta = {
        "project": "test/repo",
        "branch": "feature/123",
        "event_name": "push",
        "build_duration": 5000.0, # Way too long
        "artifact_size": 1024,    # Way too small
        "changed_files": 500,     # Way too many
        "test_coverage": 0.0
    }
    print(f"\nrunning check on Anomaly Data: {anomaly_meta}")
    anomalies = detect_anomalies(anomaly_meta)
    if any("Statistical Anomaly" in a for a in anomalies):
        print("✅ PASS: Statistical anomaly detected.")
    else:
        print(f"❌ FAIL: Expected statistical anomaly, got: {anomalies}")

if __name__ == "__main__":
    verify()
