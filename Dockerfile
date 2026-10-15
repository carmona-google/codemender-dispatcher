# ==============================================================================
# CodeMender Dispatcher Control Plane & Web Portal Image (Cloud Run / GKE)
# ==============================================================================
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CODEMENDER_MODEL=gemini-4-argon \
    CODEMENDER_CLI_VERSION=0.14.0 \
    CODEMENDER_STORAGE_DIR=/tmp/codemender/sessions \
    DATABASE_URI=sqlite:////tmp/codemender/codemender.db \
    K8S_NAMESPACE=codemender-executors \
    EXECUTION_BACKEND=auto

# Install minimal system tools (git, bash, zip/unzip for archive extraction)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    jq \
    patch \
    tar \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY demo/ ./demo/
COPY tests/mocks/ ./tests/mocks/

RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /tmp/codemender/sessions && \
    chmod +x ./tests/mocks/mock_cm.sh && \
    chown -R appuser:appuser /app /tmp/codemender

USER appuser

EXPOSE 8080

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 120 'src.app:create_app()'"]
