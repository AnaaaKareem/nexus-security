FROM python:3.9-slim

WORKDIR /app

COPY services/analysis/requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --default-timeout=100 --no-cache-dir -r requirements.txt

# Copy common
COPY services/common /app/common

# Copy service code
COPY services/analysis /app

ENV PYTHONPATH=/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
