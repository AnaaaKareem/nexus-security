from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.sandbox import verify_poc, verify_patch_in_sandbox
# Sandbox doesn't use shared logger in sandbox.py yet, but we should import it if needed.
# sandbox.py uses print? No, it used to use logging but in the snippet passing `get_logger` was not imported.
# Checking the view_file output for sandbox.py: it imports docker, os, subprocess... no logger imported.
# But it does not use logger inside. It returns success, output.
# I will just write main.py.

from common.core.logger import get_logger

logger = get_logger(__name__)
app = FastAPI(title="Sandbox Service")

class VerifyPOCRequest(BaseModel):
    source_path: str
    poc_code: str
    file_extension: str

class VerifyPatchRequest(BaseModel):
    source_path: str
    patch_code: str
    target_file: str

@app.get("/health")
def health():
    return {"status": "healthy", "service": "sandbox"}

@app.on_event("startup")
async def startup_event():
    logger.info("Sandbox Service Started", extra_info={"event": "startup_check"})

@app.post("/verify/poc")
def check_poc(req: VerifyPOCRequest):
    logger.info("Received POC Verification Request", extra_info={"event": "poc_verify_request", "path": req.source_path})
    success, output = verify_poc(req.source_path, req.poc_code, req.file_extension)
    return {"success": success, "output": output}

class AttackRequest(BaseModel):
    finding: dict
    project: str
    source_path: str

@app.post("/redteam/attack")
def execute_attack(req: AttackRequest):
    from core.red_team import run_red_team_attack
    result = run_red_team_attack(req.finding, req.project, req.source_path)
    return result


@app.post("/verify/patch")
def check_patch(req: VerifyPatchRequest):
    success, output = verify_patch_in_sandbox(req.source_path, req.patch_code, req.target_file)
    return {"success": success, "output": output}
