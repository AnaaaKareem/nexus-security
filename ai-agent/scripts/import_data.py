
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 1. Setup Environment
# Append path to import 'core'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Models
from core import models, database

# 2. Configurations
SQLITE_URL = "sqlite:///./security_brain.db"
# Postgres URL from .env is loaded by core.database if env vars are set, 
# BUT we want to be explicit here to connect to TWO databases simultaneously.
# The 'database.engine' in 'core' is configured based on os.getenv. 
# We need separate engines.

POSTGRES_URL = "postgresql://postgres:password@localhost:5432/security_brain"

def import_data():
    print("🚀 Starting Data Import: SQLite -> Postgres")

    # 3. Create Engines
    sqlite_engine = create_engine(SQLITE_URL)
    postgres_engine = create_engine(POSTGRES_URL)

    # 4. Create Sessions
    SqliteSession = sessionmaker(bind=sqlite_engine)
    PostgresSession = sessionmaker(bind=postgres_engine)

    source_session = SqliteSession()
    dest_session = PostgresSession()

    try:
        # 5. Clear Target Tables (Optional, but good to avoid duplicates if re-running)
        # Be careful with Foreign Keys. Delete children first.
        print("🧹 Clearing existing data in Postgres...")
        dest_session.query(models.Feedback).delete()
        dest_session.query(models.PipelineMetric).delete()
        dest_session.query(models.Finding).delete()
        dest_session.query(models.Scan).delete()
        dest_session.commit()

        # 6. Migrate Scans
        print("📦 Migrating Scans...")
        scans = source_session.query(models.Scan).all()
        scan_map = {} # Map Old ID -> New ID (if auto-increment changes, though we try to keep same)
        
        for s in scans:
            # We explicitly copy fields to detach from source session
            new_scan = models.Scan(
                id=s.id, # Keep ID to preserve relationships
                project_name=s.project_name,
                commit_sha=s.commit_sha,
                timestamp=s.timestamp
            )
            dest_session.add(new_scan)
        dest_session.commit()
        print(f"   - Moved {len(scans)} scans.")

        # 7. Migrate Findings
        print("📦 Migrating Findings...")
        findings = source_session.query(models.Finding).all()
        for f in findings:
            new_finding = models.Finding(
                id=f.id,
                scan_id=f.scan_id,
                triage_decision=f.triage_decision,
                sandbox_logs=f.sandbox_logs,
                tool=f.tool,
                rule_id=f.rule_id,
                file=f.file,
                line=f.line,
                message=f.message,
                snippet=f.snippet,
                ai_verdict=f.ai_verdict,
                ai_confidence=f.ai_confidence,
                ai_reasoning=f.ai_reasoning,
                risk_score=f.risk_score,
                severity=f.severity,
                remediation_patch=f.remediation_patch,
                red_team_success=f.red_team_success,
                red_team_output=f.red_team_output,
                pr_url=f.pr_url,
                pr_error=f.pr_error
            )
            dest_session.add(new_finding)
        dest_session.commit()
        print(f"   - Moved {len(findings)} findings.")

        # 8. Migrate Feedback
        print("📦 Migrating Feedback...")
        feedbacks = source_session.query(models.Feedback).all()
        for fb in feedbacks:
            new_fb = models.Feedback(
                id=fb.id,
                finding_id=fb.finding_id,
                user_verdict=fb.user_verdict,
                comments=fb.comments,
                timestamp=fb.timestamp
            )
            dest_session.add(new_fb)
        dest_session.commit()
        print(f"   - Moved {len(feedbacks)} feedback entries.")
        
        # 9. Migrate Pipeline Metrics
        print("📦 Migrating Pipeline Metrics...")
        metrics = source_session.query(models.PipelineMetric).all()
        for m in metrics:
            new_m = models.PipelineMetric(
                id=m.id,
                scan_id=m.scan_id,
                build_duration_seconds=m.build_duration_seconds,
                artifact_size_bytes=m.artifact_size_bytes,
                num_changed_files=m.num_changed_files,
                test_coverage_percent=m.test_coverage_percent,
                timestamp=m.timestamp
            )
            dest_session.add(new_m)
        dest_session.commit()
        print(f"   - Moved {len(metrics)} pipeline metrics.")

        print("✅ Data Migration Complete!")

    except Exception as e:
        print(f"❌ Error during migration: {e}")
        dest_session.rollback()
    finally:
        source_session.close()
        dest_session.close()

if __name__ == "__main__":
    import_data()
