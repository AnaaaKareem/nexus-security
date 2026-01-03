FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
# Install necessary system tools
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install python dependencies
# Install python dependencies
COPY dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Dashboard Code
COPY dashboard/ .

# Copy Shared Core Module
# Copy Shared Core Module
COPY services/common/core ./core

# Expose port
EXPOSE 8001

# Run Dashboard
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
