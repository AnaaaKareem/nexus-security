# Software Design Document (SDD)

## 1. Introduction

The Universal Security Brain is an AI-driven security orchestration platform designed to automate the detection, verification, and remediation of code vulnerabilities.

## 2. System Architecture

The system adopts an event-driven **Microservices Architecture**.

- **Orchestration**: Managed by a central API (`orchestrator`) using **LangGraph** for state management.
- **Communication**: REST APIs for direct service-to-service calls; **Redis/Celery** for asynchronous background processing.
- **Storage**: **PostgreSQL** for relational data; **Redis** for caching.

## 3. Component Design

### 3.1 Orchestrator

- **Pattern**: API Gateway + Workflow Engine.
- **Key Classes**: `ScanRequest`, `Scan` (Model).
- **Logic**: Handles incoming webhooks, dispatches jobs to Celery, and exposes status APIs.

### 3.2 Analysis Service

- **Pattern**: Stateless AI Worker.
- **Logic**: Accepts code snippets -> Prompts LLM -> Returns Verdict (TP/FP).

### 3.3 Remediation Service

- **Pattern**: Stateless AI Worker.
- **Logic**: Accepts Vulnerability -> Prompts LLM -> Returns Git Patch.

### 3.4 Sandbox Service

- **Pattern**: Ephemeral Execution Environment.
- **Logic**: Spawns `docker run ...` commands to execute Python PoCs in isolation.

## 4. Data Design

See `DATABASE_SCHEMA.md` for full ERD.
Key entities: `Scan`, `Finding`, `Feedback`.

## 5. Interface Design

See `API_REFERENCE.md` for backend APIs.
See `DASHBOARD_DESIGN.md` for Frontend specifications.
