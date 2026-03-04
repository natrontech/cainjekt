FROM golang:1.23-alpine AS builder

WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o cainjekt ./cmd/cainjekt

FROM alpine:3.21

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# The binary runs in different modes:
# - NRI plugin mode (default)
# - Hook mode (via CAINJEKT_HOOK_MODE env)
# - Wrapper mode (via CAINJEKT_WRAPPER_MODE env)
ENTRYPOINT ["/cainjekt"]
