# Microservices Overview

The **Universal Security Brain** is composed of several Dockerized microservices that collaborate to perform security scanning, analysis, remediation, and reporting.

## Service List

### 1. Orchestrator (`orchestrator`)

- **Port**: 8000
- **Role**: Central API gateway and workflow manager.
- **Tech**: FastAPI, LangGraph.
- **Dependencies**: DB, Redis, Scanner, Analysis, Remediation.
- **Responsibility**: Receives scan requests, coordinates the LangGraph workflow, and manages state.

### 2. Scanner (`scanner`)

- **Port**: 8002
- **Role**: Ingestion and normalization of security scan results.
- **Tech**: FastAPI.
- **Responsibility**: Runs (or triggers) security tools like Semgrep, Trivy, Gitleaks, Checkov and normalizes their output into a standard JSON format.

### 3. Analysis (`analysis`)

- **Port**: 8003
- **Role**: AI-powered triage and anomaly detection.
- **Tech**: FastAPI, LLM (Ollama/DeepSeek).
- **Responsibility**: Analyzes findings using LLMs to distinguish True Positives from False Positives and detects CI/CD anomalies.

### 4. Remediation (`remediation`)

- **Port**: 8004
- **Role**: Automated code patching.
- **Tech**: FastAPI, LLM.
- **Responsibility**: Generates code patches for verified vulnerabilities.

### 5. Sandbox (`sandbox`)

- **Port**: 8005
- **Role**: Isolated verification environment.
- **Responsibility**: Safely executes Proof-of-Concept (PoC) exploits to verify vulnerabilities and test patches.

### 6. Dashboard (`dashboard`)

- **Port**: 8001
- **Role**: User Interface.
- **Tech**: FastAPI (Backend), Jinja2/HTML/JS (Frontend).
- **Responsibility**: Provides a real-time view of scans, findings, and metrics. Allows user feedback.

### 7. Orchestrator Worker (`orchestrator-worker`)

- **Role**: Asynchronous task processor.
- **Tech**: Celery.
- **Dependencies**: RabbitMQ, Redis.
- **Responsibility**: Handles background tasks to scale the orchestration logic off the main API loop.

## Infrastructure Services

- **Database (`db`)**: PostgreSQL 15 for persistent storage.
- **Cache/Queue (`redis`)**: Redis 6 for caching and simple message queuing.
- **Message Broker (`rabbitmq`)**: RabbitMQ for robust task queue management (Celery).
- **Observability**:
  - **Grafana (`grafana`)**: Metrics visualization (:3000).
  - **Loki (`loki`)**: Log aggregation.
  - **Promtail (`promtail`)**: Log shipping.
  - **Prometheus (`prometheus`)**: Metric collection.
  - **cAdvisor (`cadvisor`)**: Container metrics.

## Communication

Services communicate primarily via **HTTP REST APIs**. The Orchestrator acts as the conductor, calling other services as steps in its execution graph. Asynchronous tasks are offloaded to **Celery/RabbitMQ**.
