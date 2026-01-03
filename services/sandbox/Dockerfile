FROM python:3.9-slim

WORKDIR /app

# Install Docker CLI via multi-stage copy
COPY --from=library/docker:latest /usr/local/bin/docker /usr/local/bin/docker
    
COPY services/sandbox/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy common
COPY services/common /app/common

# Copy service code
COPY services/sandbox /app

ENV PYTHONPATH=/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
