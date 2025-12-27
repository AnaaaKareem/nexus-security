# STAGE 1: Builder - This stage installs heavy tools and compiles dependencies
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install only necessary system build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Optimize pip caching to reduce data usage on rebuilds
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# STAGE 2: Final - The lean production image
FROM python:3.12-slim-bookworm

WORKDIR /app

# Install runtime dependencies (Git is required for cloning)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy only the compiled dependencies from the builder stage
COPY --from=builder /install /usr/local
COPY . .

# Add a health check to verify the app is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]