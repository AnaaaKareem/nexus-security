from dotenv import load_dotenv

# Ensure environment variables are loaded FIRST
load_dotenv()

from common.core.database import engine
from common.core import models
from sqlalchemy import text

def init_db():
    print("🚀 Initializing database...")
    
    # Retry loop for DB connection
    max_retries = 10
    retry_delay = 5
    
    import time
    from sqlalchemy.exc import OperationalError

    for i in range(max_retries):
        try:
            # Try to connect first to verify connection
            with engine.connect() as connection:
                pass
            break
        except OperationalError:
            if i == max_retries - 1:
               print("❌ Could not connect to database after multiple retries.")
               raise
            print(f"⏳ Database not ready, retrying in {retry_delay}s... ({i+1}/{max_retries})")
            time.sleep(retry_delay)

    models.Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully.")
    
    # Auto-Migration for missing columns (Backwards Compatibility)
    print("🔧 Checking for required schema migrations...")
    try:
        with engine.connect() as connection:
            # 1. Add target_url if missing (for Scans)
            connection.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS target_url VARCHAR;"))
            
            # 2. Add status if missing (for Scans)
            connection.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'pending';"))
            
            # 3. Add AI Confidence if missing (for Findings)
            connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_confidence FLOAT DEFAULT 0.0;"))

            # 4. Add DAST Endpoint if missing (for Findings)
            connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS dast_endpoint VARCHAR;"))

            connection.commit()
            print("✅ Schema migrations checked/applied.")
    except Exception as e:
        print(f"⚠️ Migration warning: {e}")

if __name__ == "__main__":
    init_db()
