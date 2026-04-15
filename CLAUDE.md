# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cainjekt is a Kubernetes CA certificate injection tool using containerd NRI (Node Resource Interface). It dynamically injects custom CA certificates into containers at runtime without modifying container images. The Go module path is `github.com/natrontech/cainjekt`.

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
make e2e-test                 # Kubernetes E2E tests (kustomize + Helm)
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

1. **NRI Plugin** (default) — `internal/nri/plugin.go`: Registers with containerd NRI, intercepts `CreateContainer` to stage per-container CA files and inject OCI hooks + wrapper binary. Runs HTTP server on `:9443` for health probes and Prometheus metrics. Includes graceful shutdown and orphan CA cleanup.
2. **Hook Mode** (`HOOK_MODE`) — `internal/runtime/hook/runner.go`: OCI CreateRuntime hook. Detects OS distro and rootfs writability, merges CA into system trust stores (or falls back to dynamic CA path on read-only rootfs), persists wrapper context to `/etc/cainjekt/hook-context.json`.
3. **Wrapper Mode** (`WRAPPER_MODE`) — `internal/runtime/wrapper/run.go`: Prepended to container entrypoint. Sets language-specific env vars, then `syscall.Exec()` replaces itself with real entrypoint. Fail-open: always execs original command even if injection fails.

**Processor system** (`internal/engine/`):
- `api/types.go`: Core interfaces — `Processor` (Detect/Apply) and `WrapperProcessor` (adds ApplyWrapper for env var injection)
- `processors/registry.go`: Global registry with priority-based detection, include/exclude filtering via pod annotations
- `processors/osstore/`: OS CA store processors (debian, rhel, alpine, arch, opensuse, fallback) — priority 275-300. Detects read-only rootfs and skips gracefully.
- `processors/golang/`, `processors/java/`, `processors/nodejs/`, `processors/python/`, `processors/ruby/`: Language processors — priority 100

**Key flow**: NRI intercepts container creation → stages CA file in `/run/cainjekt/containers/{id}/` → OCI hook detects OS and patches trust stores → wrapper sets env vars and execs original entrypoint.

**Opt-in**: Pod annotation `cainjekt.natron.io/enabled: "true"` or pod/namespace label with same key. Configurable prefix via `CAINJEKT_ANNOTATION_PREFIX`. Filter processors via `cainjekt.natron.io/processors.include` / `cainjekt.natron.io/processors.exclude`.

## Known Limitations

- **Static binaries** (Go, Rust): CA verification compiled in, but Go respects `SSL_CERT_FILE` env var (lang-go processor handles this)
- **Distroless/scratch images**: No `/etc/os-release`, minimal writable FS — fallback unreliable, but language env vars work
- **Read-only root filesystems**: OS trust store not modified, but language processors still work via env vars + dynamic CA path

## Testing Notes

- Integration tests use build tag `//go:build integration` gated by env vars (`CAINJEKT_TLS_INTEGRATION=1`, `CAINJEKT_E2E=1`)
- Tests run against real kind clusters (default: `cainjekt-test-cluster`, configurable via `CAINJEKT_CLUSTER_NAME`)
- Two E2E tests: `TestE2E_ManifestDeployment` (kustomize) and `TestE2E_HelmDeployment` (Helm chart)
- Test helpers in `internal/testutil/`
- Kind config at `hack/kind.yaml` enables NRI plugin in containerd

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `CAINJEKT_CA_FILE` | `/etc/cainjekt/ca-bundle.pem` | CA bundle path |
| `CAINJEKT_ANNOTATION_PREFIX` | `cainjekt.natron.io` | Annotation prefix |
| `CAINJEKT_FAIL_POLICY` | `fail-open` | Hook failure policy |
| `CAINJEKT_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `CAINJEKT_DYNAMIC_CA_ROOT` | `/run/cainjekt/containers` | Per-container CA staging |

## Deployment

**Helm** (recommended):
```bash
helm install cainjekt charts/cainjekt \
  --namespace kube-system \
  --set-file caBundle=/path/to/ca-bundle.pem
```

CA bundle updates are picked up automatically for new containers (ConfigMap volume refresh).

**Kustomize**: `deploy/kubernetes/` with `deploy.sh` helper script.

## Observability

- Prometheus metrics at `:9443/metrics` (injection counts, errors, processor stats, active containers, orphan cleanups)
- Health probe: `:9443/healthz`
- Readiness probe: `:9443/readyz`
- Helm chart supports ServiceMonitor for Prometheus Operator (`serviceMonitor.enabled: true`)
