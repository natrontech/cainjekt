# checkov:skip=CKV_DOCKER_2:Kubernetes ignores HEALTHCHECK; liveness/readiness probes are defined in the DaemonSet (:9443/healthz, /readyz)
# checkov:skip=CKV_DOCKER_3:The NRI plugin must run as root: it connects to containerd's root-owned NRI socket and writes to host paths; the DaemonSet runs privileged
FROM golang:1.27@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS builder

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
FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS installer

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# Simple installer script
RUN echo '#!/bin/sh\ncp /cainjekt "$1"\nchmod +x "$1"' > /install.sh && \
    chmod +x /install.sh

# Use distroless base image for minimal attack surface
# Note: Using root variant because the NRI plugin needs root access to connect to containerd's NRI socket
FROM gcr.io/distroless/static-debian13:latest@sha256:58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# The binary runs in different modes:
# - NRI plugin mode (default)
# - Hook mode (via CAINJEKT_HOOK_MODE env)
# - Wrapper mode (via CAINJEKT_WRAPPER_MODE env)
ENTRYPOINT ["/cainjekt"]
