
import requests
import logging
from sqlalchemy.orm import Session
from common.core import models, database

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EPSSWorker")

EPSS_API = "https://api.first.org/data/v1/epss"

def sync_epss_scores(db: Session, cve_ids: list):
    """
    Fetches and persists real-world exploit probability for findings.
    """
    if not cve_ids:
        logger.info("No CVEs to sync.")
        return
    
    logger.info(f"🔄 Syncing EPSS scores for {len(cve_ids)} CVEs...")
    
    # FIRST.org API supports comma-separated CVEs
    # Note: Large lists might need batching, but we'll assume manageable batches for now.
    params = {"cve": ",".join(cve_ids)}
    
    try:
        response = requests.get(EPSS_API, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", [])
            logger.info(f"✅ Received {len(data)} EPSS records.")
            
            for entry in data:
                # Upsert into epss_data table
                epss_record = models.EPSSData(
                    cve_id=entry["cve"],
                    probability=float(entry.get("epss", 0.0)),
                    percentile=float(entry.get("percentile", 0.0))
                )
                db.merge(epss_record)
            
            db.commit()
            logger.info("💾 EPSS Data Saved to DB.")
        else:
            logger.error(f"❌ EPSS API Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"❌ EPSS Sync Failed: {e}")

if __name__ == "__main__":
    # Test execution
    db = database.SessionLocal()
    try:
        # Example sync
        sync_epss_scores(db, ["CVE-2021-44228", "CVE-2017-5638"])
    finally:
        db.close()
