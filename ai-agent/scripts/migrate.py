"""
Database Migration Script.

Applies schema changes to the database.
"""
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path so we can import core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env explicitly to ensure we migrate the correct DB
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from core import database, models

def migrate():
    print("🔄 Applying database migrations...")
    database.Base.metadata.create_all(bind=database.engine)
    print("✅ Database schema updated.")

if __name__ == "__main__":
    migrate()
