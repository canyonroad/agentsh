# agentsh Docker Image
# 
# Build: docker build -t agentsh:latest .
# Run:   docker run -d --name agentsh \
#          --cap-add SYS_ADMIN --cap-add NET_ADMIN \
#          --device /dev/fuse --security-opt apparmor=unconfined \
#          -p 8080:8080 -v ./workspaces:/workspaces \
#          agentsh:latest

# =============================================================================
# Build stage
# =============================================================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /agentsh ./cmd/agentsh
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /agentsh-shell-shim ./cmd/agentsh-shell-shim

# =============================================================================
# Runtime stage
# =============================================================================
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="agentsh"
LABEL org.opencontainers.image.description="Secure shell environment for AI agents"
LABEL org.opencontainers.image.source="https://github.com/agentsh/agentsh"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # FUSE support
    fuse3 \
    libfuse3-3 \
    # Network tools
    iptables \
    iproute2 \
    # Process tools
    procps \
    # Useful utilities for agents
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy binary from builder
COPY --from=builder /agentsh /usr/local/bin/agentsh
COPY --from=builder /agentsh-shell-shim /usr/local/bin/agentsh-shell-shim

# Install sh/bash shims for container compatibility.
# Preserve real shells at /bin/sh.real and /bin/bash.real (when present).
RUN set -eux; \
    if [ -e /bin/sh ] && [ ! -e /bin/sh.real ]; then mv /bin/sh /bin/sh.real; fi; \
    if [ -e /bin/bash ] && [ ! -e /bin/bash.real ]; then mv /bin/bash /bin/bash.real; fi; \
    install -m 0755 /usr/local/bin/agentsh-shell-shim /bin/sh; \
    if [ -e /bin/bash.real ]; then install -m 0755 /usr/local/bin/agentsh-shell-shim /bin/bash; fi

# Create directories
RUN mkdir -p /etc/agentsh/policies \
    && mkdir -p /var/lib/agentsh \
    && mkdir -p /var/log/agentsh \
    && mkdir -p /var/run/agentsh \
    && mkdir -p /workspaces

# Copy default configuration
COPY configs/server-config.yaml /etc/agentsh/config.yaml
COPY configs/default-policy.yaml /etc/agentsh/policies/default.yaml
COPY configs/api_keys.yaml /etc/agentsh/api_keys.yaml

# Create non-root user for running agents (agentsh itself needs root for namespaces)
RUN useradd -m -s /bin/bash agent

# Volume for workspaces
VOLUME ["/workspaces"]

# Volume for custom configuration
VOLUME ["/etc/agentsh"]

# Expose ports
# HTTP API
EXPOSE 8080
# gRPC API
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/agentsh"]
CMD ["server", "--config", "/etc/agentsh/config.yaml"]
