"""
Seed Database with Normal Pipeline Metrics.
"""
import os
import sys
from dotenv import load_dotenv

# Load .env explicitly
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

# Allow importing 'core' from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import models, database, models
import random

def seed():
    db = database.SessionLocal()
    try:
        print("🌱 Seeding normal pipeline metrics...")
        
        # Create a dummy scan if needed
        scan = models.Scan(project_name="seed/project", commit_sha="seedsha")
        db.add(scan)
        db.commit()
        
        # Add 50 normal samples
        # Normal duration: 100s +/- 20s
        # Normal size: 50MB +/- 10MB (50*1024*1024)
        # Normal changed files: 5 +/- 3
        # Normal coverage: 80% +/- 5%
        for _ in range(50):
            m = models.PipelineMetric(
                scan_id=scan.id,
                build_duration_seconds=random.gauss(100, 10),
                artifact_size_bytes=int(random.gauss(52428800, 5242880)),
                num_changed_files=max(1, int(random.gauss(5, 2))),
                test_coverage_percent=min(100, max(0, random.gauss(80, 2)))
            )
            db.add(m)
        
        db.commit()
        print("✅ Added 50 normal metric samples.")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
