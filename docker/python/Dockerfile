# ==============================================================================
# CodeMender Python Execution Engine Sandbox Image
# ==============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    CODEMENDER_HOME=/home/cm \
    CODEMENDER_SOURCE_DIR=/workspace/source \
    CODEMENDER_OUTPUT_DIR=/workspace/output \
    CODEMENDER_STATE_DIR=/run/codemender/state \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install baseline utilities + Python toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    jq \
    patch \
    procps \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install common testing / build runners in user environment
RUN pip3 install --no-cache-dir --break-system-packages pytest flake8

# Create unprivileged runtime user and sandbox directories
RUN useradd -m -u 1000 -s /bin/bash cm && \
    mkdir -p /workspace/source /workspace/output /run/codemender/state && \
    chown -R cm:cm /workspace /run/codemender /home/cm

# Copy entrypoint script and test mock harness
COPY docker/base/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY tests/mocks/mock_cm.sh /usr/local/bin/mock_cm.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/mock_cm.sh

USER cm
WORKDIR /workspace/source

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["all"]
