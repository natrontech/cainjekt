# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cainjekt is a Kubernetes CA certificate injection tool using containerd NRI (Node Resource Interface). It dynamically injects custom CA certificates into containers at runtime without modifying container images. Pure Go, no CGO. The Go module path is `github.com/natrontech/cainjekt`.

## Common Commands

```bash
# Build
make build                    # Build binary (CGO_ENABLED=0) to bin/cainjekt
make docker-build             # Build Docker images (main + installer)

# Test
make test                     # Unit tests (go test ./...)
go test ./internal/nri/ -run TestSpecificName -v   # Single test

# Integration tests (require Docker, kind, kubectl)
make prepare-test-cluster     # Create kind cluster (one-time)
make integration-test         # TLS integration tests
make e2e-test                 # Kubernetes manifest deployment tests
make test-all                 # All integration + E2E tests

# Lint & format
make lint                     # golangci-lint
make lint-fix                 # Auto-fix lint issues
make fmt                      # go fmt
make vet                      # go vet

# Helm
make helm-lint                # Lint the Helm chart
make helm-template            # Render templates for review

# Kind cluster
make reset-test-cluster       # Delete and recreate
make kind-load                # Build and load images into kind
make copy-plugin              # Copy binary to kind node
```

## Architecture

**Three runtime modes** (detected in `internal/app/run.go` via env vars):

1. **NRI Plugin** (default) — `internal/nri/plugin.go`: Registers with containerd NRI, intercepts `CreateContainer` to stage per-container CA files and inject OCI hooks + wrapper binary.
2. **Hook Mode** (`HOOK_MODE`) — `internal/runtime/hook/runner.go`: OCI CreateRuntime hook. Detects OS distro, merges CA into system trust stores, persists wrapper context to `{rootfs}/etc/cainjekt/hook-context.json`.
3. **Wrapper Mode** (`WRAPPER_MODE`) — `internal/runtime/wrapper/run.go`: Prepended to container entrypoint. Sets language-specific env vars, then `syscall.Exec()` replaces itself with real entrypoint.

**Processor system** (`internal/engine/`):
- `api/types.go`: Core interfaces — `Processor` (Detect/Apply) and `WrapperProcessor` (adds ApplyWrapper for env var injection)
- `processors/registry.go`: Global registry with priority-based detection, include/exclude filtering via pod annotations
- `processors/osstore/`: OS CA store processors (debian, rhel, alpine, arch, opensuse, fallback) — priority 275-300
- `processors/java/`, `processors/nodejs/`, `processors/python/`: Language processors (JAVA_TOOL_OPTIONS, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE) — priority 100

**Key flow**: NRI intercepts container creation → stages CA file in `/run/cainjekt/containers/{id}/` → OCI hook detects OS and patches trust stores → wrapper sets env vars and execs original entrypoint.

**Pod opt-in**: Annotation `cainjekt.natron.io/enabled: "true"`. Filter processors via `cainjekt.natron.io/processors.include` / `cainjekt.natron.io/processors.exclude`.

## Known Limitations

- **Silent failures**: `fail-open` policy means containers start without CA on error — check logs for warnings
- **Static binaries** (Go, Rust): CA verification compiled in, ignores system stores — injection doesn't help
- **Distroless/scratch images**: No `/etc/os-release`, minimal writable FS — fallback unreliable
- **Read-only root filesystems**: OS trust store not modified, but language processors still work via env vars + dynamic CA path

## Testing Notes

- Integration tests use build tag `//go:build integration` gated by env vars (`CAINJEKT_TLS_INTEGRATION=1`, `CAINJEKT_E2E=1`)
- Tests run against real kind clusters (default: `cainjekt-test-cluster`, configurable via `CAINJEKT_CLUSTER_NAME`)
- Test helpers in `internal/testutil/`
- Kind config at `hack/kind.yaml` enables NRI plugin in containerd

## Configuration

- Constants and env var names: `internal/config/constants.go`
- Default CA file: `/etc/cainjekt/ca-bundle.pem`
- Dynamic CA root: `/run/cainjekt/containers/<container-id>/cainjekt.crt`
- Kubernetes manifests: `deploy/kubernetes/` (kustomize) or `charts/cainjekt/` (Helm)
- Hook timeout: 2 seconds (hardcoded in `config.DefaultHookTimeoutSec`)

## Deployment

**Helm** (recommended):
```bash
helm install cainjekt charts/cainjekt \
  --namespace kube-system \
  --set-file caBundle=/path/to/ca-bundle.pem
```

**Kustomize**: `deploy/kubernetes/` with `deploy.sh` helper script.
