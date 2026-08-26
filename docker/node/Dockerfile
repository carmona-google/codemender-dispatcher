# ==============================================================================
# CodeMender Node.js Execution Engine Sandbox Image
# ==============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    CODEMENDER_HOME=/home/cm \
    CODEMENDER_SOURCE_DIR=/workspace/source \
    CODEMENDER_OUTPUT_DIR=/workspace/output \
    CODEMENDER_STATE_DIR=/run/codemender/state \
    NODE_ENV=development

# Install baseline utilities + Node.js 20 LTS toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    patch \
    procps \
    tar \
    unzip \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y nodejs --no-install-recommends \
    && npm install -g npm@latest jest \
    && rm -rf /var/lib/apt/lists/*

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
