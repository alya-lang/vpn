# ==============================================================================
# Alya VPN Server - Production Dockerfile
# Ubuntu 24.04 (Noble) based container matching alya GLIBC 2.39+
# ==============================================================================

FROM ubuntu:24.04 AS builder

ARG ALYA_VERSION=0.0.19
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime C build essentials and download utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gcc \
    libc6-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH

# Install Alya Compiler (alya)
RUN case "${TARGETARCH}" in \
        "amd64") ALYA_ARCH="x86_64-linux" ;; \
        "arm64") ALYA_ARCH="arm64-linux" ;; \
        *) ALYA_ARCH="x86_64-linux" ;; \
    esac && \
    curl -fsSL "https://github.com/alya-lang/alya/releases/download/v${ALYA_VERSION}/alya-v${ALYA_VERSION}-${ALYA_ARCH}.tar.gz" | tar -xz --strip-components=1 -C /usr/local/bin \
    && chmod +x /usr/local/bin/alya \
    && alya --version

WORKDIR /build

# Copy source files
COPY . .

# Compile native binary with bundled C crypto & process inspection
RUN alya build src/main.alya -o /build/alya-vpn-server

# ==============================================================================
# Production Runtime Container
# ==============================================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# C runtime and netcat for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libc6 \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled standalone binary and configuration from builder
COPY --from=builder /build/alya-vpn-server /app/alya-vpn-server
COPY --from=builder /build/config/server.toml /app/config/server.toml

# Expose default VPN tunnel port (51822)
EXPOSE 51822

# Mark configuration directory as mountable volume
VOLUME ["/app/config"]

# Start VPN server daemon
ENTRYPOINT ["/app/alya-vpn-server"]
CMD ["server", "--config", "/app/config/server.toml"]
