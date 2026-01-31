# API Reference

The **Orchestrator Service** provides the main entry point for the security platform. It exposes a REST API built with **FastAPI**.

**Base URL**: `http://localhost:8000` (Local) / `https://your-domain.com` (Production)

## Authentication

All requests must include the API key in the header:

- **Header**: `X-API-Key`
- **Value**: Your configured `AI_API_KEY` (Default: `default-dev-key`)

---

## Endpoints

### 1. Trigger Scan (`POST /scan`)

Triggers a security scan for a repository that is already accessible (e.g., cloned in a known path or via CI integration).

- **URL**: `/scan`
- **Body** (`application/json`):

  ```json
  {
    "project_name": "owner/repo",
    "target_path": "/app",
    "ci_provider": "manual-scan",
    "branch": "main",
    "commit_sha": "latest",
    "repo_url": "https://github.com/owner/repo.git",
    "run_url": "http://jenkins/job/123"
  }
  ```

- **Response**: `202 Accepted`

  ```json
  {
    "status": "scanning_queued",
    "project": "owner/repo"
  }
  ```

### 2. Ingest Scan Report (`POST /triage`)

Ingests an existing SARIF or JSON report from an external tool and triggers AI triage.

- **URL**: `/triage`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `project`: (Text) Project name
  - `sha`: (Text) Commit SHA
  - `token`: (Text) GitHub Token (for digging deeper if needed)
  - `platform`: (Text) `github` / `gitlab` / `jenkins`
  - `files`: (File) List of scan report files
- **Response**: `202 Accepted`

  ```json
  {
    "status": "queued",
    "scan_id": 123
  }
  ```

### 3. Upload Source Code (`POST /scan/upload`)

Uploads a ZIP file of the source code, extracts it, and triggers a full scan.

- **URL**: `/scan/upload`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `project`: (Text) Project Name
  - `file`: (File) The ZIP file containing source code
  - `branch`: (Text) Branch name
- **Response**: `202 Accepted`

  ```json
  {
    "status": "uploaded",
    "scan_id": "uuid-string",
    "message": "Scan started in background."
  }
  ```

### 4. Get Scan Status (`GET /scan_status/{id}`)

Retrieves the status and summary metrics of a specific scan.

- **URL**: `/scan_status/{scan_id}`
- **Path Params**:
  - `scan_id`: The ID returned by the initial request (Integer ID or Reference UUID).
- **Response**: `200 OK`

  ```json
  {
      "scan_id": 123,
      "ref_id": "uuid-string",
      "status": "completed",
      "project": "owner/repo",
      "risk_score": 45.5,
      "findings_count": 12,
      "created_at": "2023-10-27T10:00:00"
  }
  ```
