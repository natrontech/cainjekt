FROM golang:1.26 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -a -ldflags="-s -w" -trimpath -o cainjekt ./cmd/cainjekt

# Installer image with shell for initContainer
FROM debian:12-slim AS installer

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# Simple installer script
RUN echo '#!/bin/sh\ncp /cainjekt "$1"\nchmod +x "$1"' > /install.sh && \
    chmod +x /install.sh

# Use distroless base image for minimal attack surface
# Note: Using root variant because the NRI plugin needs root access to connect to containerd's NRI socket
FROM gcr.io/distroless/static-debian12:latest

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# The binary runs in different modes:
# - NRI plugin mode (default)
# - Hook mode (via CAINJEKT_HOOK_MODE env)
# - Wrapper mode (via CAINJEKT_WRAPPER_MODE env)
ENTRYPOINT ["/cainjekt"]
