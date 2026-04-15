# Why We Forked

## The Problem We're Solving

Every enterprise Kubernetes platform that uses TLS inspection, internal PKI, or self-signed certificates faces the same pain: **containers don't trust your CAs**. Teams work around this by baking certificates into images, mounting volumes, or adding init containers — all of which are fragile, error-prone, and don't scale.

We needed transparent, zero-touch CA injection across our entire container platform. No image changes, no pod spec changes, no developer burden.

## Why This Project

[tsuzu/cainjekt](https://github.com/tsuzu/cainjekt) is a clever proof-of-concept that uses containerd NRI to solve exactly this problem. The architecture is sound — a three-phase pipeline (NRI plugin → OCI hook → entrypoint wrapper) that transparently patches trust stores and sets language-specific environment variables.

We evaluated it thoroughly (including a full security review of every source file) and found:

- Clean, well-engineered Go code with proper error handling
- Solid security practices (atomic writes, symlink protection, no network calls)
- An extensible processor system that makes it easy to add support for new distros and languages
- No malicious code, no telemetry, no hidden functionality

It's exactly the foundation we wanted.

## Why Fork Instead of Contribute Upstream

The original project is maintained by a single individual with no organization behind it. It has 12 stars, no other forks, and the last activity was March 2026. For a component that runs as a privileged DaemonSet on every node in our production clusters, we need:

- **Ownership and accountability** — we need to be able to ship fixes on our own timeline
- **Production hardening** — the original is a great MVP but needed significant work for production use (see below)
- **Organizational backing** — [natrontech](https://github.com/natrontech) provides a stable home with multiple maintainers
- **Release infrastructure** — Helm chart publishing, multi-arch images, CI/CD, Prometheus integration

We believe this project has significant potential beyond our own use case. Every Kubernetes platform with custom CAs faces this exact problem, and there's no good open-source solution. By forking under an organization, we can build a community around it.

**We are open for contributions.** See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to get involved.

## What We Changed

The core architecture is unchanged — we kept the three-phase pipeline, the processor registry, the per-container CA staging, and the fail-open design. Our changes add production-readiness on top of it.

### Production Safety

| Area | Before (upstream) | After (fork) |
|------|-------------------|--------------|
| Wrapper failure | Container blocked (CrashLoopBackOff) | Fail-open: always execs original command |
| Read-only rootfs | Silent failure, no warning | Detected, skipped gracefully, language env vars still work |
| CA bundle validation | None (invalid PEM staged silently) | PEM validated before staging, clear error on invalid |
| Graceful shutdown | `os.Exit(1)` on NRI disconnect | SIGTERM/SIGINT handling, clean plugin stop |
| Orphaned CA files | Accumulate indefinitely on crash | Background sweep every 5 minutes |

### Observability

| Feature | Before | After |
|---------|--------|-------|
| Metrics | None | Prometheus endpoint (`:9443/metrics`) with 9+ metrics |
| Health probes | None | `/healthz` and `/readyz` endpoints |
| Status file | None | `/etc/cainjekt/status.json` in every injected container |
| Alerting | None | PrometheusRule with 3 default alerts |
| Dashboard | None | Grafana dashboard (auto-provisioned via sidecar) |
| Log level | Hardcoded info | Configurable via `CAINJEKT_LOG_LEVEL` |

### Language Coverage

| Processor | Before | After |
|-----------|--------|-------|
| Node.js (`NODE_EXTRA_CA_CERTS`) | Yes | Yes |
| Python (`SSL_CERT_FILE`) | Yes | Yes |
| Java (`JAVA_TOOL_OPTIONS`) | No | Yes |
| Go (`SSL_CERT_FILE`) | No | Yes |
| Ruby (`SSL_CERT_FILE`) | No | Yes |

### Platform Integration

| Feature | Before | After |
|---------|--------|-------|
| Deployment | Kustomize only | Helm chart + kustomize |
| Annotation prefix | Hardcoded `cainjekt.io` | Configurable (default `cainjekt.natron.io`) |
| Namespace opt-in | Per-pod only | Per-pod annotation + namespace label (K8s API lookup with 1min cache) |
| Container opt-out | Not supported | `exclude-containers` annotation for sidecars |
| Host network/PID | Required | Not required (removed, configurable) |
| Helm: ServiceMonitor | No | Yes |
| Helm: PodDisruptionBudget | No | Yes |
| Helm: PrometheusRule | No | Yes |
| Helm: Grafana dashboard | No | Yes |
| Container registry | `ghcr.io/tsuzu` | `ghcr.io/natrontech` |
| Go module path | `github.com/tsuzu/cainjekt` | `github.com/natrontech/cainjekt` |

### Developer Experience

| Feature | Before | After |
|---------|--------|-------|
| Linting | None | golangci-lint (20+ linters) |
| Dependabot | None | Go, GitHub Actions, Docker (monthly) |
| Pre-commit hooks | None | gitleaks, checkov, standard fixers |
| E2E tests | 1 (kustomize) | 5 (kustomize + Helm + init container + restart + status) |
| CI | Basic (test + build) | Lint + test + integration + E2E + Helm lint + Docker build |
| Release | Images only | Images + OCI Helm chart + GitHub release |
| Documentation | README only | Architecture deep-dive, usage guide, fork rationale |
