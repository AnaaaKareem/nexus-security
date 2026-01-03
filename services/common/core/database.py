"""
Database configuration and session management.

This module handles the database connection using SQLAlchemy, configures SQLite
specific optimizations (WAL mode), and provides a dependency for obtaining DB sessions.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

# Database URL configuration (defaulting to local SQLite for tests)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db") 

# SQLite-specific configuration for better concurrency
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

# --- WAL MODE CONFIGURATION ---
# This allows concurrent reads and writes, preventing "Ghost Scans" during high load
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    # Only run for SQLite
    if "sqlite" in str(getattr(engine.url, "drivername", "")):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
    else:
        pass # Not using SQLite, skipping PRAGMA execution

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """
    Dependency generator for creating and closing database sessions.

    Yields:
        Session: A SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()