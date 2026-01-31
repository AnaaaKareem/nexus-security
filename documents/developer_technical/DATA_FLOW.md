# Data Flow & Pipeline Stages

This document details how data moves through the Universal Security Brain, from the initial scan ingestion to the final automated pull request.

## The 6-Phase Pipeline

### Phase 1: Ingestion

1. **Input**: CI/CD pipeline (e.g., GitHub Actions) sends a `POST /triage` request to the Orchestrator.
2. **Payload**: Includes `project_name`, `commit_sha`, and the raw scan file (SARIF/JSON).
3. **Action**:
    - Findings are parsed by the **Scanner Service**.
    - A `Scan` record is created in PostgreSQL with status `pending`.
    - The processing is offloaded to a background task (Celery).

### Phase 2: Context Enrichment

1. **Action**: The system clones the repository at the specific commit.
2. **Enrichment**: For each finding, the surrounding code snippet (context window) is extracted.
3. **Storage**: Snippets are stored in the `findings` table in the database.

### Phase 3: AI Analysis (Triage)

1. **Input**: Code snippet + Finding Metadata (Rule ID, Message).
2. **Process**: The **Analysis Service** constructs a prompt for the LLM.
3. **Decision**: The LLM classifies the finding as **True Positive (TP)** or **False Positive (FP)**.
4. **Output**: `ai_verdict`, `ai_confidence`, and `ai_reasoning` updated in DB.

### Phase 4: Verification (Red Teaming)

1. **Condition**: Only for High/Critical **TP** findings.
2. **Process**:
    - The LLM generates a Python Proof-of-Concept (PoC) script.
    - The **Sandbox Service** spins up an isolated container.
    - The PoC is executed against the vulnerable code.
3. **Outcome**: If the PoC succeeds (exit code 0), the finding is confirmed as exploitable (`red_team_success = True`).

### Phase 5: Remediation

1. **Condition**: Confirmed TPs.
2. **Process**: The **Remediation Service** asks the LLM to generate a minimal code patch.
3. **Validation**: A sanity check ensures the patch is valid Python and doesn't delete excessive code.
4. **Storage**: The `remediation_patch` is saved to the DB.

### Phase 6: Publication

1. **Action**: The Orchestrator aggregates all fixes.
2. **Output**: A single "Consolidated Pull Request" is created/updated on the target repository featuring all the fixes.

## Data States

| State | Description |
| :--- | :--- |
| `pending` | Scan received, waiting for worker. |
| `processing` | Currently moving through the LangGraph workflow. |
| `completed` | Workflow finished, PR created (if applicable). |
| `failed` | Error occurred during processing. |
