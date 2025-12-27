from fastapi import FastAPI, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
import redis
import json
import os
import sys

import sys
from dotenv import load_dotenv

# Allow importing 'core' when running directly from dashboard/ (though local copy exists)
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env from root (parent directory)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

from core import models, database

app = FastAPI(title="Security Dashboard")

# Setup Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Setup Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    print("✅ Connected to Redis")
except redis.ConnectionError:
    print("⚠️ Redis not available, caching disabled")
    cache = None

@app.get("/")
def dashboard(request: Request, db: Session = Depends(database.get_db)):
    """
    Renders the main dashboard HTML.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/stats")
async def get_stats(db: Session = Depends(database.get_db)):
    """
    Returns aggregated security statistics.
    Cached in Redis for 60 seconds.
    """
    # 1. Try Cache
    if cache:
        cached_data = cache.get("dashboard_stats")
        if cached_data:
            print("🚀 Serving stats from Redis Cache")
            return json.loads(cached_data)

    # 2. Query DB (Cache Miss)
    print("🐢 Querying Database for stats...")
    
    total_scans = db.query(models.Scan).count()
    total_findings = db.query(models.Finding).count()
    
    # Severity Counts
    critical = db.query(models.Finding).filter(models.Finding.severity == "Critical").count()
    high = db.query(models.Finding).filter(models.Finding.severity == "High").count()
    medium = db.query(models.Finding).filter(models.Finding.severity == "Medium").count()
    low = db.query(models.Finding).filter(models.Finding.severity == "Low").count()
    
    # AI Performance
    false_positives = db.query(models.Finding).filter(models.Finding.ai_verdict == "FP").count()
    fixed_issues = db.query(models.Finding).filter(models.Finding.remediation_patch != None).count()

    # Real System Health Check
    redis_status = "connected" if cache else "disconnected"
    db_status = "connected"
    try:
        db.execute(func.text("SELECT 1"))
    except Exception:
        db_status = "error"

    data = {
        "system_health": {
            "database": db_status,
            "redis": redis_status,
            "status": "operational" if db_status == "connected" else "degraded"
        },
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "ai_metrics": {
            "false_positives": false_positives,
            "auto_fixed": fixed_issues
        }
    }

    # 3. Set Cache
    if cache:
        cache.setex("dashboard_stats", 60, json.dumps(data))

    return data

@app.get("/api/findings")
def get_findings(db: Session = Depends(database.get_db)):
    """
    Returns the top 10 most critical findings.
    """
    # 1. Try Cache
    if cache:
        cached_findings = cache.get("dashboard_findings")
        if cached_findings:
            print("🚀 Serving findings from Redis Cache")
            return json.loads(cached_findings)

    print("🐢 Querying Database for findings...")
    findings = db.query(models.Finding)\
        .order_by(models.Finding.risk_score.desc())\
        .limit(10)\
        .all()
    
    result = [
        {
            "id": f.id,
            "tool": f.tool,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "location": f"{f.file}:{f.line}",
            "verdict": f.ai_verdict
        }
        for f in findings
    ]

    # 2. Set Cache
    if cache:
        cache.setex("dashboard_findings", 60, json.dumps(result))

    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard.main:app", host="0.0.0.0", port=8001, reload=True)
