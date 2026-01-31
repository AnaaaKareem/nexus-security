# Getting Started Guide

Welcome to the **Universal Security Brain** project! This guide will help you set up your local development environment.

## 1. System Requirements

- **OS**: Linux (Preferred), macOS, or Windows with WSL2.
- **Memory**: Minimum 16GB RAM (Running LLMs + 8 Containers takes ~8-12GB).
- **Disk**: 20GB free space for Docker images and AI models.

## 2. Installation

### Step 1: Install Docker

Ensure you have Docker and Docker Compose installed.
[Docker Desktop / Engine Installation Guide](https://docs.docker.com/get-docker/)

### Step 2: Install Ollama (The AI Brain)

The system relies on a local LLM. We recommend **Ollama**.

1. Download & Install: [ollama.com](https://ollama.com)
2. Pull the model:

   ```bash
   ollama pull deepseek-coder-v2-lite
   ```

3. Test it:

   ```bash
   ollama run deepseek-coder-v2-lite "Hello"
   ```

### Step 3: Clone the Project

```bash
git clone <repo_url>
cd DevSecOps
```

### Step 4: Configure Environment

Create a `.env` file (see `DEPLOYMENT.md` for full config) and set your `GITHUB_TOKEN` to allow the agent to create Pull Requests.

## 3. Running the System

Start the entire stack:

```bash
docker-compose up -d --build
```

Wait about 30 seconds for the database to initialize and services to connect.

## 4. Your First Scan

You can test the system by uploading a ZIP file of code or using the Dashboard.

**Via CLI (cURL):**

```bash
curl -X POST http://localhost:8000/scan/upload \
  -H "X-API-Key: default-dev-key" \
  -F "project=MyTestProject" \
  -F "file=@/path/to/my/code.zip"
```

**Via Dashboard:**

1. Open `http://localhost:8001`
2. Navigate to "New Scan".
3. Upload a file or input a Repo URL.

## 5. Development Workflow

- **Logs**: View logs for all services: `docker-compose logs -f`
- **Code Changes**: The `services/` directory is mounted in containers (check `docker-compose.yml`), so simple code changes *might* reflect immediately for Python (if using `uvicorn --reload`), but Docker rebuild is recommended for heavy changes.
