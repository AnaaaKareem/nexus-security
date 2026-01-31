# Deployment Guide

The System is designed to be deployed using **Docker** and **Docker Compose**. It can be deployed on a single powerful server or scaled across a Kubernetes cluster (with manifest adaptation).

## Prerequisites

- **Docker Engine**: v20.10+
- **Docker Compose**: v2.0+
- **Ollama**: Running locally or on a reachable network host for LLM inference.
- **Git**: To clone the repository.
- **Ports**:
  - `8000-8005` (Microservices)
  - `3000` (Grafana)
  - `5432` (PostgreSQL)
  - `6379` (Redis)

## Environment Configuration

1. Create a `.env` file in the root directory.
2. Copy the contents of the provided/example configuration:

```ini
# --- Secrets ---
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxx
AI_API_KEY=my-secret-key-123

# --- Database ---
DATABASE_URL=postgresql://postgres:password@db:5432/security_brain
POSTGRES_PASSWORD=password
REDIS_URL=redis://redis:6379/0

# --- LLM Provider (Ollama) ---
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=deepseek-coder-v2-lite
```

## Deployment Steps

1. **Clone the Repository**:

   ```bash
   git clone <repo-url>
   cd DevSecOps
   ```

2. **Pull Required Images**:

   ```bash
   docker-compose pull
   ```

3. **Build Custom Services**:

   ```bash
   docker-compose build
   ```

4. **Start the Stack**:

   ```bash
   docker-compose up -d
   ```

5. **Verify Deployment**:
   - Check container status: `docker-compose ps`
   - View Dashboard: `http://localhost:8001`
   - Check Orchestrator Health: `curl http://localhost:8000/health`

## Updating the System

To deploy the latest changes:

```bash
git pull origin main
docker-compose up -d --build
```

This command rebuilds the containers if the Code/Dockerfiles have changed and restarts them.

## Troubleshooting

- **Database Errors**: Check logs `docker-compose logs -f db`. Ensure the volume `postgres_data` is not corrupted.
- **LLM Connection**: Ensure `host.docker.internal` works on your OS (Linux adds it via `extra_hosts` in `docker-compose.yml` usually, or use the host IP).
