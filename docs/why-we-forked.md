# Why We Forked

cainjekt is a fork of [tsuzu/cainjekt](https://github.com/tsuzu/cainjekt). This document explains what we changed and why.

## The Original Project

The original cainjekt by [tsuzu](https://github.com/tsuzu) is a well-engineered CA injection tool for Kubernetes using containerd NRI. It supports Debian, Ubuntu, Alpine, RHEL, Fedora, Arch, and openSUSE distributions with Node.js and Python language processors. The code is clean, secure (atomic writes, symlink protection), and the architecture is extensible.

We evaluated it for use on our Kubernetes container platform and found it to be safe, legitimate, and a strong foundation — but it needed several changes to be production-ready for our use case.

## What We Changed

### Annotation Prefix

**Before:** `cainjekt.io/enabled` (hardcoded)
**After:** `cainjekt.natron.io/enabled` (configurable via `CAINJEKT_ANNOTATION_PREFIX`)

We don't own the `cainjekt.io` domain. Using it would create confusion about which version is running and potential conflicts if the upstream project publishes something there. The prefix is now configurable so any organization can use their own domain.

### Go Module Path

**Before:** `github.com/tsuzu/cainjekt`
**After:** `github.com/natrontech/cainjekt`

Clean module ownership for our fork.

### Container Registry

**Before:** `ghcr.io/tsuzu/cainjekt`
**After:** `ghcr.io/natrontech/cainjekt`

### Helm Chart

The original project uses kustomize only. We added a Helm chart (`charts/cainjekt/`) because:

- Helm is the standard package manager on our platform
- Values-based configuration is easier to manage across environments
- ServiceMonitor, PDB, PrometheusRule, and Grafana dashboard integration require Helm templates
- OCI-based chart publishing integrates with our existing release pipeline

### Additional Language Processors

**Added:** Go (`SSL_CERT_FILE`), Java (`JAVA_TOOL_OPTIONS`), Ruby (`SSL_CERT_FILE`)

The original had Node.js and Python only. Our platform runs Java, Go, and Ruby workloads that need CA injection.

### Wrapper Fail-Open

**Before:** If the wrapper failed (e.g., hook context missing, processor error), the container would not start — stuck in CrashLoopBackOff.
**After:** The wrapper always execs the original command. Failures are logged as warnings but never block the container.

This was a critical production safety issue in the original.

### Read-Only Root Filesystem Support

**Before:** Silently failed on read-only rootfs — container started without CA, no warning.
**After:** Detects read-only rootfs, skips OS trust store modification, sets language env vars to point at the dynamic CA file (which is on a writable host-mounted path). Logs a clear warning.

### Observability

**Before:** Basic logging only. No metrics, no health probes, no status file.
**After:**
- Prometheus metrics endpoint (`:9443/metrics`) with injection counts, error rates, per-processor stats
- Liveness and readiness probes (`/healthz`, `/readyz`)
- `/etc/cainjekt/status.json` inside every injected container
- Grafana dashboard (auto-provisioned via ConfigMap sidecar)
- PrometheusRule alerting (high error rate, DaemonSet not ready, orphan accumulation)
- Configurable log level (`CAINJEKT_LOG_LEVEL`)

### Operational Safety

- **Graceful shutdown**: SIGTERM/SIGINT handling with clean plugin stop
- **Orphan cleanup**: Background sweep removes stale CA directories for crashed/removed containers
- **CA bundle validation**: Rejects invalid PEM at staging time with clear error
- **Namespace-level opt-in**: Pod labels and namespace labels work in addition to annotations

### Tooling

- golangci-lint configuration (20+ linters)
- Dependabot (Go modules, GitHub Actions, Docker — monthly grouped)
- Pre-commit hooks (gitleaks, checkov, standard file fixers)
- Claude Code rules and settings for consistent AI-assisted development
- CI: lint, unit tests, integration tests, E2E tests (kustomize + Helm), Docker build, Helm lint
- Release workflow: multi-arch images + OCI Helm chart publishing

## What We Kept

The core architecture is unchanged:

- Three-phase pipeline (NRI plugin → OCI hook → wrapper)
- Priority-based processor registry with detection and application phases
- Per-container dynamic CA staging with atomic writes
- Symlink protection and ownership preservation
- Fail-open hook policy
- Distroless container image

The original design is sound. Our changes add production-readiness on top of it.
