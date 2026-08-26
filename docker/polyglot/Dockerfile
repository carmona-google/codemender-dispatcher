# ==============================================================================
# CodeMender Polyglot Execution Engine Sandbox Image
# Bundles Python, Node.js, Go, and OpenJDK for multi-language repositories.
# ==============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    CODEMENDER_HOME=/home/cm \
    CODEMENDER_SOURCE_DIR=/workspace/source \
    CODEMENDER_OUTPUT_DIR=/workspace/output \
    CODEMENDER_STATE_DIR=/run/codemender/state \
    GOPATH=/home/cm/go \
    PATH=$PATH:/usr/local/go/bin:/home/cm/go/bin

# Install system dependencies, Python, OpenJDK 17, and base build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    openjdk-17-jdk-headless \
    patch \
    procps \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y nodejs --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22
RUN curl -fsSL https://go.dev/dl/go1.22.6.linux-amd64.tar.gz -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# Create unprivileged runtime user and sandbox directories
RUN useradd -m -u 1000 -s /bin/bash cm && \
    mkdir -p /workspace/source /workspace/output /run/codemender/state /home/cm/go && \
    chown -R cm:cm /workspace /run/codemender /home/cm

# Copy entrypoint script and test mock harness
COPY docker/base/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY tests/mocks/mock_cm.sh /usr/local/bin/mock_cm.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/mock_cm.sh

USER cm
WORKDIR /workspace/source

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["all"]
