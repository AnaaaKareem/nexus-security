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
from core.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title="Security Dashboard")

# Setup Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Setup Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    logger.info("Connected to Redis", extra_info={"event": "redis_connected", "url": REDIS_URL})
except redis.ConnectionError:
    logger.warning("Redis not available, caching disabled", extra_info={"event": "redis_failed"})
    cache = None

@app.get("/")
def dashboard(request: Request, db: Session = Depends(database.get_db)):
    """
    Renders the main dashboard HTML.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health", status_code=200)
def health_check():
    return {"status": "healthy", "service": "dashboard"}

@app.get("/api/repos")
def get_repos(db: Session = Depends(database.get_db)):
    """
    Returns a list of all unique repository names.
    """
    repos = db.query(models.Scan.project_name).distinct().all()
    # repos is a list of tuples like [('user/repo1',), ('user/repo2',)]
    return [r[0] for r in repos if r[0]]

@app.get("/api/stats")
async def get_stats(repo: str = None, db: Session = Depends(database.get_db)):
    """
    Returns aggregated security statistics, optionally filtered by repository.
    Cached in Redis for 60 seconds.
    """
    cache_key = f"dashboard_stats_{repo}" if repo else "dashboard_stats_global"

    try:
        # ... (Previous code) ...
        # 1. Try Cache
        if cache:
            cached_data = cache.get(cache_key)
            cached_data = cache.get(cache_key)
            if cached_data:
                logger.info("Serving stats from Redis Cache", extra_info={"event": "stats_cached", "key": cache_key})
                return json.loads(cached_data)

        # 2. Query DB (Cache Miss)
        logger.info("Querying Database for stats", extra_info={"event": "stats_db_query", "repo": repo})
        
        # Base Queries
        scan_query = db.query(models.Scan)
        finding_query = db.query(models.Finding).join(models.Scan)

        # Filter by Completed Status
        scan_query = scan_query.filter(models.Scan.status == "completed")
        finding_query = finding_query.filter(models.Scan.status == "completed")

        if repo:
            scan_query = scan_query.filter(models.Scan.project_name == repo)
            finding_query = finding_query.filter(models.Scan.project_name == repo)

        total_scans = scan_query.count()
        total_findings = finding_query.count()
        
        # Severity Counts
        critical = finding_query.filter(models.Finding.severity == "Critical").count()
        high = finding_query.filter(models.Finding.severity == "High").count()
        medium = finding_query.filter(models.Finding.severity == "Medium").count()
        low = finding_query.filter(models.Finding.severity == "Low").count()
        
        # AI Performance
        false_positives = finding_query.filter(models.Finding.ai_verdict == "FP").count()
        fixed_issues = finding_query.filter(models.Finding.remediation_patch != None).count()

        # Real System Health Check
        redis_status = "connected" if cache else "disconnected"
        db_status = "connected"
        try:
            db.execute(func.text("SELECT 1"))
        except Exception:
            db_status = "error"

        # --- [UPDATED] Multi-Repo & Advanced Metrics ---

        # 1. MTTF (Mean Time To Fix) - SPLIT
        # AI-Assisted (Findings where remediation_patch exists)
        mttf_ai_query = finding_query.with_entities(
            func.avg(func.extract('epoch', models.Finding.resolved_at) - func.extract('epoch', models.Finding.created_at))
        ).filter(models.Finding.resolved_at != None, models.Finding.remediation_patch != None)
        
        # Manual (Findings where no AI patch was generated)
        mttf_manual_query = finding_query.with_entities(
            func.avg(func.extract('epoch', models.Finding.resolved_at) - func.extract('epoch', models.Finding.created_at))
        ).filter(models.Finding.resolved_at != None, models.Finding.remediation_patch == None)

        mttf_ai_seconds = mttf_ai_query.scalar() or 0
        mttf_manual_seconds = mttf_manual_query.scalar() or 0
        
        mttf_ai_hours = round(float(mttf_ai_seconds) / 3600, 2)
        mttf_manual_hours = round(float(mttf_manual_seconds) / 3600, 2)
        
        # Overall MTTF (Legacy support if needed, but we focus on split)
        mttf_avg_hours = round((mttf_ai_hours + mttf_manual_hours) / 2, 2) if (mttf_ai_hours and mttf_manual_hours) else (mttf_ai_hours or mttf_manual_hours)

        # 2. CI Distribution
        ci_stats = scan_query.with_entities(
            models.Scan.ci_provider, func.count(models.Scan.id)
        ).group_by(models.Scan.ci_provider).all()
        ci_distribution = {provider or "unknown": count for provider, count in ci_stats}

        # 3. AI Efficacy & Confidence
        tp_count = finding_query.filter(models.Finding.ai_verdict == "TP").count()
        total_ai_decisions = tp_count + false_positives
        ai_efficacy_score = round((tp_count / total_ai_decisions * 100), 1) if total_ai_decisions > 0 else 0.0
        
        # Average Confidence for TPs
        avg_conf = db.query(func.avg(models.Finding.ai_confidence)).filter(models.Finding.ai_verdict == 'TP').scalar() or 0.0

        # 4. Risk per Repo (Top 5 Riskiest Projects - for Global View)
        risk_per_repo = []
        try:
            risk_query = db.query(
                models.Scan.project_name, func.sum(models.Finding.risk_score)
            ).join(models.Finding).group_by(models.Scan.project_name).order_by(func.sum(models.Finding.risk_score).desc()).limit(5).all()
            risk_per_repo = [{"repo": r[0], "risk": float(r[1] or 0.0)} for r in risk_query]
        except Exception:
            risk_per_repo = []

        # 5. Vulnerability Trend (Last 10 Scans)
        trend_query = db.query(models.Scan).filter(models.Scan.status == "completed")
        if repo:
            trend_query = trend_query.filter(models.Scan.project_name == repo)
        
        # Get last 10 scans ordered by time
        last_scans = trend_query.order_by(models.Scan.timestamp.desc()).limit(10).all()
        # Reverse to show chronological order on chart
        last_scans = mb_list = sorted(last_scans, key=lambda x: x.timestamp)

        trend_data = {
            "labels": [],
            "critical": [],
            "high": [],
            "medium": []
        }

        for s in last_scans:
            # Simple label: "Scan #ID" or Date
            scan_label = s.timestamp.strftime("%m-%d %H:%M")
            trend_data["labels"].append(scan_label)
            
            # Count findings for this scan
            crit = db.query(models.Finding).filter(models.Finding.scan_id == s.id, models.Finding.severity == "Critical").count()
            hi = db.query(models.Finding).filter(models.Finding.scan_id == s.id, models.Finding.severity == "High").count()
            med = db.query(models.Finding).filter(models.Finding.scan_id == s.id, models.Finding.severity == "Medium").count()

            trend_data["critical"].append(crit)
            trend_data["high"].append(hi)
            trend_data["medium"].append(med)

        data = {
            "system_health": {
                "database": db_status,
                "redis": redis_status,
                "status": "operational" if (db_status == "connected" and redis_status == "connected") else "degraded"
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
                "auto_fixed": fixed_issues,
                "efficacy_percent": ai_efficacy_score,
                "confidence_avg": round(float(avg_conf) * 100, 1)
            },
            "devsecops_metrics": {
                "mttf_hours": mttf_avg_hours,
                "mttf_ai_hours": mttf_ai_hours,
                "mttf_manual_hours": mttf_manual_hours,
                "ci_distribution": ci_distribution,
                "ci_distribution": ci_distribution,
                "risk_per_repo": risk_per_repo,
                "trend_data": trend_data
            }
        }

        # 3. Set Cache
        if cache:
            cache.setex(cache_key, 60, json.dumps(data))

        return data
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Return a partial error response or re-raise
        logger.error(f"Error in /stats: {e}", extra_info={"event": "stats_error", "error": str(e)})
        return {"error": str(e), "system_health": {"status": "error"}}

@app.get("/api/findings")
def get_findings(repo: str = None, db: Session = Depends(database.get_db)):
    """
    Returns the top 10 most critical findings, optionally filtered by repo.
    """
    cache_key = f"dashboard_findings_{repo}" if repo else "dashboard_findings_global"

    # 1. Try Cache
    if cache:
        cached_findings = cache.get(cache_key)
        if cached_findings:
            logger.info("Serving findings from Redis Cache", extra_info={"event": "findings_cached", "key": cache_key})
            return json.loads(cached_findings)

    logger.info("Querying Database for findings", extra_info={"event": "findings_db_query", "repo": repo})
    
    query = db.query(models.Finding).join(models.Scan).filter(models.Scan.status == "completed")
    if repo:
        query = query.filter(models.Scan.project_name == repo)
        
    findings = query.order_by(models.Finding.risk_score.desc())\
        .limit(10)\
        .all()
    
    result = [
        {
            "id": f.id,
            "tool": f.tool,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "location": f"{f.file}:{f.line}",
            "verdict": f.ai_verdict,
            "project": f.scan.project_name,
            "ai_confidence": f.ai_confidence
        }
        for f in findings
    ]

    # 2. Set Cache
    if cache:
        cache.setex(cache_key, 60, json.dumps(result))

    return result



@app.get("/api/projects")
def get_projects(db: Session = Depends(database.get_db)):
    """
    Returns list of projects with metadata for the carousel.
    """
    # Get all distinct project names
    project_names = [r[0] for r in db.query(models.Scan.project_name).distinct().all() if r[0]]
    
    results = []
    for name in project_names:
        # Get latest scan for provider info
        latest = db.query(models.Scan).filter(models.Scan.project_name == name).order_by(models.Scan.timestamp.desc()).first()
        
        # Check active
        is_active = db.query(models.Scan).filter(
            models.Scan.project_name == name,
            models.Scan.status.in_(["pending", "processing", "uploaded", "scanning", "analyzing"])
        ).count() > 0
        
        results.append({
            "name": name,
            "provider": latest.ci_provider if latest else "unknown",
            "is_active": is_active,
            "branch": latest.branch if latest else "main",
            "last_run": latest.timestamp.isoformat() if latest else None
        })
        
    return results

@app.get("/api/activity")
def get_activity(db: Session = Depends(database.get_db)):
    """
    Returns currently running scans.
    """
    # Active statuses: scanning, analyzing, pending, processing, uploaded
    active_scans = db.query(models.Scan).filter(
        models.Scan.status.in_(["pending", "processing", "uploaded", "scanning", "analyzing"]) 
    ).order_by(models.Scan.timestamp.desc()).all()
    
    return [
        {
            "id": s.id,
            "project": s.project_name,
            "provider": s.ci_provider,
            "status": s.status,
            "start_time": s.timestamp.isoformat(),
            "branch": s.branch or "main"
        }
        for s in active_scans
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard.main:app", host="0.0.0.0", port=8001, reload=True)
