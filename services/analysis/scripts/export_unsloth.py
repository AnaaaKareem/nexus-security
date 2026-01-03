import os
import json
import logging
from sqlalchemy.orm import Session
from common.core import database, models

# Setup standalone logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UnslothExport")

OUTPUT_FILE = "fine_tuning_data.jsonl"

def export_feedback_dataset():
    """
    Exports human-verified True Positive findings to a JSONL file for Unsloth fine-tuning.
    """
    db = database.SessionLocal()
    try:
        # Fetch findings where human verdict matches AI verdict (True Positives)
        # and haven't been exported yet.
        verified_data = db.query(models.Finding).join(models.Feedback, models.Finding.id == models.Feedback.finding_id).filter(
            models.Feedback.user_verdict == models.Finding.ai_verdict,
            models.Finding.is_exported_for_training == False
        ).all()
        
        if not verified_data:
            logger.info("🚫 No new verified data found to export.")
            return

        logger.info(f"submit Found {len(verified_data)} verified findings for training...")
        
        with open(OUTPUT_FILE, "a") as f:
            for finding in verified_data:
                # Construct Alpaca-style instruction format for Unsloth
                instruction = {
                    "instruction": f"Fix this security vulnerability: {finding.message}",
                    "input": finding.snippet,
                    "output": finding.remediation_patch or "No patch available."
                }
                
                f.write(json.dumps(instruction) + "\n")
                
                # Mark as exported
                finding.is_exported_for_training = True
                
        db.commit()
        logger.info(f"✅ Successfully exported {len(verified_data)} records to {OUTPUT_FILE}")

    except Exception as e:
        logger.error(f"❌ Export Failed: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    export_feedback_dataset()
