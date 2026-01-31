# Database Schema

The system uses **PostgreSQL** to store security findings, scan metadata, and user feedback. The schema is defined using SQLAlchemy in `services/common/core/models.py`.

## Overview

The database is designed to track the lifecycle of a security scan, from the initial commit to the final remediation and user feedback.

## Tables

### 1. Scans (`scans`)

Represents a single security scan execution on a project commit.

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | Integer (PK) | Unique identifier for the scan. |
| `project_name` | String | Project identifier (e.g., "user/repo"). |
| `commit_sha` | String | Git commit hash being scanned. |
| `timestamp` | DateTime | Timestamp of the scan init. |
| `reference_id` | String | UUID for async status tracking. |
| `status` | String | Current status (`pending`, `processing`, `completed`, `failed`). |
| `source_platform` | String | e.g., `github`, `gitlab`. |
| `repo_url` | String | Full repository URL. |
| `branch` | String | Branch name. |

### 2. Findings (`findings`)

Represents a single security vulnerability detected by a scanner tool.

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | Integer (PK) | Unique identifier. |
| `scan_id` | Integer (FK) | Link to the parent Scan. |
| `tool` | String | Scanner name (e.g., Semgrep, Trivy). |
| `rule_id` | String | Specific rule violated. |
| `file` | String | File path. |
| `line` | Integer | Line number. |
| `severity` | String | Severity level (Critical, High, Medium, Low). |
| `triage_decision` | String | `TP` (True Positive) or `FP` (False Positive). |
| `ai_verdict` | String | LLM's independent verdict. |
| `ai_confidence` | Float | AI confidence score (0.0 - 1.0). |
| `ai_reasoning` | Text | Explanation of the AI's decision. |
| `remediation_patch` | Text | AI-generated code fix. |
| `red_team_success` | Boolean | Whether the Red Team exploit succeeded. |

### 3. Feedback (`feedbacks`)

Stores human feedback (RLHF) on AI decisions.

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | Integer (PK) | Unique identifier. |
| `finding_id` | Integer (FK) | Link to the Finding. |
| `user_verdict` | String | User's decision (TP/FP). |
| `comments` | Text | User's comments. |
| `timestamp` | DateTime | Time of feedback. |

### 4. Pipeline Metrics (`pipeline_metrics`)

Stores metrics from CI/CD pipelines for anomaly detection.

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | Integer (PK) | Unique identifier. |
| `scan_id` | Integer (FK) | Link to the Scan. |
| `build_duration_seconds` | Float | Duration of the build. |
| `artifact_size_bytes` | Integer | Size of the build artifact. |
| `num_changed_files` | Integer | Number of files changed. |

### 5. EPSS Data (`epss_data`)

Stores Exploit Prediction Scoring System data.

| Column | Type | Description |
| :--- | :--- | :--- |
| `cve_id` | String (PK) | CVE Identifier. |
| `probability` | Float | Exploit probability (0.0 - 1.0). |
| `percentile` | Float | Percentile ranking. |

## Relationships

- **Scan ↔ Findings**: One-to-Many. A scan results in multiple findings.
- **Finding ↔ Feedback**: One-to-Many. A finding can have multiple feedback entries.
- **Scan ↔ PipelineMetric**: One-to-One (or Many-to-One depending on usage, currently defined as `uselist=False`).
