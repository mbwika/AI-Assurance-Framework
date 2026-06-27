FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies for psycopg2-binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application layer ─────────────────────────────────────────────────────────
FROM base AS final

WORKDIR /app

COPY src/ ./src/
COPY data/ ./data/

# Non-root user for security
RUN useradd -r -u 1001 -g root aiaf && \
    chown -R aiaf:root /app
USER aiaf

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AIAF_LOG_FORMAT=json

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["python", "-m", "aiaf.cli", "run", "--host", "0.0.0.0", "--port", "8000"]
