FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY services/dashboard/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --default-timeout=1000 --retries 10 --no-cache-dir -r requirements.txt

# Copy Dashboard Code
COPY services/dashboard/ .

# Copy Shared Core Module
COPY services/common/core ./core

# Expose port
EXPOSE 8001

# Run Dashboard
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
