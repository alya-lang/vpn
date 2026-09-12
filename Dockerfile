# ==============================================================================
# Alya VPN Server - Production Dockerfile
# Multi-stage lightweight Linux container with bundled C crypto engine
# ==============================================================================

FROM debian:bookworm-slim AS builder

ARG ALYA_VERSION=0.0.14

# Install runtime C build essentials and download utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gcc \
    libc6-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

# Install Alya Compiler (alyac)
RUN curl -fsSL "https://github.com/alya-lang/alya/releases/download/v${ALYA_VERSION}/alyac-v${ALYA_VERSION}-x86_64-linux.tar.gz" | tar -xz -C /usr/local/bin \
    && chmod +x /usr/local/bin/alyac \
    && alyac --version

WORKDIR /build

# Copy source files
COPY . .

# Compile native binary with bundled C crypto & process inspection
RUN alyac build src/main.alya -o /build/alya-vpn-server

# ==============================================================================
# Production Runtime Container
# ==============================================================================
FROM debian:bookworm-slim

# GCC and standard C library for C runtime links
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled standalone binary and configuration from builder
COPY --from=builder /build/alya-vpn-server /app/alya-vpn-server
COPY --from=builder /build/config/server.toml /app/config/server.toml

# Expose default VPN tunnel port
EXPOSE 8443

# Mark configuration directory as mountable volume
VOLUME ["/app/config"]

# Start VPN server daemon
ENTRYPOINT ["/app/alya-vpn-server"]
CMD ["server", "--config", "/app/config/server.toml"]
