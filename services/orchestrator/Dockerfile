FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (git for cloning)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

COPY services/orchestrator/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --default-timeout=100 --no-cache-dir -r requirements.txt

# Copy common (shared code)
COPY services/common /app/common

# Copy service code
COPY services/orchestrator /app

ENV PYTHONPATH=/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
