# Dashboard Design Specifications

## Overview

The Dashboard is the operational center for the Security Brain. It provides real-time visibility into security posture and enables Human-in-the-Loop interaction.

## Tech Stack

- **Backend API**: FastAPI (Proxy to Orchestrator + DB Queries).
- **Frontend**: Server-Side Rendered (Jinja2) with vanilla JS + HTMX (inferred) or plain Bootstrap/Tailwind.
- **Visualization**: Chart.js (or similar) for metrics.

## Key Screens

### 1. Home / Overview

- **Summary Cards**:
  - Total Scans run today.
  - Active Threats (Open TP findings).
  - Risk Score trend.
- **Activity Feed**: List of recent scans with status badges (`queued`, `processing`, `completed`).

### 2. Scan Detail View

- **Header**: Project Name, Commit SHA, Timestamp.
- **Findings Table**:
  - Columns: ID, Severity, Tool, File, Verdict (AI), Actions.
  - **Filters**: Show TPs only, Show Fixed.
- **Interaction**:
  - "View Patch": Modal showing the diff.
  - "Feedback": Thumbs Up/Down buttons to correct AI verdict.

### 3. System Health (Monitor)

- **Container Status**: Green/Red indicators for Orchestrator, Analysis, Remediation, DB.
- **Queue Depth**: Number of jobs waiting in Redis/Celery.

## UX Principles

- **Real-Time**: Auto-refresh or WebSocket updates for Scan Status.
- **Transparency**: Always show *why* the AI made a decision (Reasoning field).
- **Control**: Provide a "Stop Scan" or "Override" button.
