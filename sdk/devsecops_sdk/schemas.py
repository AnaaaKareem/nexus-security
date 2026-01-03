from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

class FeedbackRequest(BaseModel):
    finding_id: int
    verdict: str  # "TP" or "FP"
    comments: Optional[str] = None

class FindingSchema(BaseModel):
    id: Optional[int]
    tool: str
    rule_id: str
    file: str
    line: int
    message: str
    severity: str
    risk_score: float
    ai_verdict: Optional[str]
    ai_confidence: float = 0.0
    remediation_patch: Optional[str]

    class Config:
        from_attributes = True

class ScanSchema(BaseModel):
    id: Optional[int]
    project_name: str
    commit_sha: str
    status: str
    timestamp: datetime
    findings: List[FindingSchema] = []

    class Config:
        from_attributes = True
