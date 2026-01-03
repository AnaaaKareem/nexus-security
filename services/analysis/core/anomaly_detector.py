"""
CI/CD Anomaly Detector Service.

Analyzes pipeline metadata and build logs to detect suspicious activity 
such as unusual build times, unauthorized code modifications, or risky git operations.
"""

from typing import Dict, List, Any
import re
import pickle
import os
import numpy as np

# Global model cache
MODEL_PATH = "ml/anomaly_model.pkl"
_MODEL = None

def load_model():
    global _MODEL
    if _MODEL is None:
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    _MODEL = pickle.load(f)
                print("🧠 Anomaly Detector: Loaded IsolationForest model.")
            except Exception as e:
                print(f"⚠️ Failed to load anomaly model: {e}")
        else:
            print("⚠️ Anomaly model not found. Skipping ML checks.")
    return _MODEL

def detect_anomalies(metadata: Dict[str, Any]) -> List[str]:
    """
    Analyzes pipeline metadata for potential security anomalies.
    
    Args:
        metadata (Dict): Contains keys like 'project', 'branch', 'event_name', 'commit_message', etc.
        
    Returns:
        List[str]: A list of detected anomaly descriptions.
    """
    anomalies = []
    
    project = metadata.get("project", "unknown")
    branch = metadata.get("branch", "unknown")
    event = metadata.get("event_name", "unknown")
    
    print(f"🕵️ Anomaly Detector: Analyzing {project} on {branch} ({event})")
    
    # 1. Detect Risky Events
    if event == "workflow_dispatch" or event == "manual":
        anomalies.append(f"⚠️ Manual workflow trigger detected on branch '{branch}'. This bypasses standard CI triggers.")
        
    # 2. Heuristic: Protect main/production branches
    if branch in ["main", "master", "production"] and event == "push":
        # In a real system, we'd check if this was a direct push vs merge request
        pass # Placeholder for "Direct push to main" check if not from PR
        
    # 3. ML-Based Anomaly Detection
    model = load_model()
    if model:
        # Extract features (adjust keys to match ingestion)
        # Defaults to 0 if not present to avoid crashes, but 0 might be an anomaly itself!
        features = [
            metadata.get("build_duration", 0.0),
            metadata.get("artifact_size", 0),
            metadata.get("changed_files", 0),
            metadata.get("test_coverage", 0.0)
        ]
        
        # Check if we have meaningful data (sum > 0 is a naive check)
        if sum(features) > 0:
            try:
                # Predict: -1 is outlier, 1 is inlier
                prediction = model.predict([features])[0]
                if prediction == -1:
                    anomalies.append(f"🚨 Statistical Anomaly Detected! Pipeline metrics deviate from baseline. Features: {features}")
            except Exception as e:
                print(f"⚠️ ML Prediction Error: {e}")

    if anomalies:
        for a in anomalies:
            print(f"   - {a}")
    else:
        print("   ✅ No metadata anomalies detected.")
        
    return anomalies
