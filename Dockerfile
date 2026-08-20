# checkov:skip=CKV_DOCKER_2:Kubernetes ignores HEALTHCHECK; liveness/readiness probes are defined in the DaemonSet (:9443/healthz, /readyz)
# checkov:skip=CKV_DOCKER_3:The NRI plugin must run as root: it connects to containerd's root-owned NRI socket and writes to host paths; the DaemonSet runs privileged
FROM golang:1.26@sha256:45a5f7a810238aabcbad211d70b9ae082022d96f7c7259e94041ad1b933575ac AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Build the binary
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -trimpath -o cainjekt ./cmd/cainjekt

# Installer image with shell for initContainer
FROM debian:13-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS installer

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# Simple installer script
RUN echo '#!/bin/sh\ncp /cainjekt "$1"\nchmod +x "$1"' > /install.sh && \
    chmod +x /install.sh

# Use distroless base image for minimal attack surface
# Note: Using root variant because the NRI plugin needs root access to connect to containerd's NRI socket
FROM gcr.io/distroless/static-debian13:latest@sha256:9197324ba51d9cd071af8505989365c006adf9d6d2067eada25aef00abbb5278

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# The binary runs in different modes:
# - NRI plugin mode (default)
# - Hook mode (via CAINJEKT_HOOK_MODE env)
# - Wrapper mode (via CAINJEKT_WRAPPER_MODE env)
ENTRYPOINT ["/cainjekt"]
