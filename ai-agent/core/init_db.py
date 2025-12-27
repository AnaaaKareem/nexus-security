from dotenv import load_dotenv

# Ensure environment variables are loaded FIRST
load_dotenv()

from core.database import engine
from core import models

def init_db():
    print("🚀 Initializing database...")
    models.Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully.")

if __name__ == "__main__":
    init_db()
