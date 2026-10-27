# ==============================================================================
# SECURESHARE MULTI-STAGE SECURE DOCKERFILE
# Adheres to CIS Docker Benchmark & DevSecOps Best Practices:
# - Minimal attack surface (Python 3.12 Slim)
# - Principle of Least Privilege: Runs as non-root user (appuser, UID 10001)
# - Explicit vulnerability surface reduction
# - Integrated container health checks
# ==============================================================================

# --- Stage 1: Build & Dependencies ---
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build essentials for native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: Hardened Runtime Container ---
FROM python:3.12-slim AS runtime

# Security: Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/home/appuser/.local/bin:$PATH"

# Install essential runtime shared libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Security: Create non-root system user with explicit UID/GID
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source code
COPY . /app

# Prepare secure local storage directory and set non-root file ownership
RUN mkdir -p /app/secure_storage_data && \
    chown -R appuser:appgroup /app /home/appuser

# Switch to unprivileged non-root user
USER appuser

# Expose standard application port
EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch production server via Uvicorn with standard production flags
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
