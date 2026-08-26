# ==============================================================================
# CodeMender Go Execution Engine Sandbox Image
# ==============================================================================
FROM golang:1.22-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CODEMENDER_HOME=/home/cm \
    CODEMENDER_SOURCE_DIR=/workspace/source \
    CODEMENDER_OUTPUT_DIR=/workspace/output \
    CODEMENDER_STATE_DIR=/run/codemender/state

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    jq \
    patch \
    procps \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash cm && \
    mkdir -p /workspace/source /workspace/output /run/codemender/state && \
    chown -R cm:cm /workspace /run/codemender /home/cm /go

COPY docker/base/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY tests/mocks/mock_cm.sh /usr/local/bin/mock_cm.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/mock_cm.sh

USER cm
WORKDIR /workspace/source

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["all"]
