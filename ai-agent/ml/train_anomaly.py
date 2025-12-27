"""
Anomaly Detection Training Script.

This script fetches historical pipeline metrics from the database,
trains an Isolation Forest model, and saves it for runtime inference.
"""

import os
import sys
import pickle
import numpy as np

# Add parent directory to path so we can import core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from core import database, models

MODEL_PATH = "ml/anomaly_model.pkl"

def fetch_data():
    """
    Fetches training data from the PipelineMetric table.
    Returns:
        np.array: Feature matrix (X)
    """
    db = database.SessionLocal()
    try:
        metrics = db.query(models.PipelineMetric).all()
        if not metrics:
            print("⚠️  No training data found in database.")
            return None
        
        # Extract features: duration, size, changed_files, coverage
        data = []
        for m in metrics:
            data.append([
                m.build_duration_seconds,
                m.artifact_size_bytes,
                m.num_changed_files,
                m.test_coverage_percent
            ])
        return np.array(data)
    finally:
        db.close()

def train_model():
    """
    Trains an Isolation Forest model and saves it.
    """
    print("🔄 Fetching training data...")
    X = fetch_data()
    
    if X is None or len(X) < 5:
        print("❌ Not enough data to train (need at least 5 samples).")
        return

    print(f"📊 Training on {len(X)} samples...")
    
    # Initialize Isolation Forest
    # contamination=0.1 means we expect ~10% of data to be anomalies
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(X)

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    
    print(f"✅ Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    # Ensure ml directory exists
    os.makedirs("ml", exist_ok=True)
    train_model()
