# cainjekt

Transparent CA certificate injection for Kubernetes containers using containerd NRI (Node Resource Interface).

> **Fork of [tsuzu/cainjekt](https://github.com/tsuzu/cainjekt)** — maintained by [natrontech](https://github.com/natrontech) with configurable annotation prefix, Helm chart, and additional tooling.

## Features

- Inject custom CA certificates into containers at runtime — no image modifications needed
- Uses containerd NRI for transparent integration with the container runtime
- Per-container dynamic CA bundle staging with atomic writes and symlink protection
- Supports multiple OS distributions (Debian, Ubuntu, Alpine, RHEL, Fedora, Arch, openSUSE)
- Language-specific processors for Go, Java, Node.js, Python, and Ruby
- Prometheus metrics endpoint (`/metrics`), health (`/healthz`) and readiness (`/readyz`) probes
- Namespace-level opt-in via labels (in addition to per-pod annotations)
- Configurable annotation prefix (default: `cainjekt.natron.io`)
- Minimal distroless container image (~15MB)
- Multi-architecture support (amd64, arm64)

## Quick Start

### Install with Helm (recommended)

```bash
helm install cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --namespace kube-system \
  --set-file caBundle=/path/to/ca-bundle.pem
```

### Install with kustomize

```bash
# Create CA bundle ConfigMap
kubectl create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/ca-bundle.pem \
  --namespace=kube-system

# Deploy
kubectl apply -k deploy/kubernetes/
```

### Enable CA injection for a pod

Add the annotation to opt in:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  containers:
  - name: app
    image: my-app:latest
```

You can also filter which processors run:

```yaml
annotations:
  cainjekt.natron.io/enabled: "true"
  cainjekt.natron.io/processors.include: "os-debian,lang-python"
  cainjekt.natron.io/processors.exclude: "os-fallback"
```

## How It Works

cainjekt runs as a DaemonSet on every node. When a container with the opt-in annotation starts:

1. **NRI Plugin** intercepts container creation, stages a per-container CA file, and injects an OCI hook + wrapper binary
2. **OCI Hook** runs before the container starts — detects the OS distro and merges the CA into system trust stores (e.g. `/etc/ssl/certs/ca-certificates.crt`)
3. **Wrapper** runs as the container entrypoint — sets language-specific environment variables and then `exec`s the original command

This three-stage pipeline ensures both OS-level and language-level trust stores are updated transparently.

## Container Images

Pre-built images on GitHub Container Registry:

```
ghcr.io/natrontech/cainjekt:<version>
ghcr.io/natrontech/cainjekt-installer:<version>
```

Both `linux/amd64` and `linux/arm64` platforms are supported.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `CAINJEKT_CA_FILE` | `/etc/cainjekt/ca-bundle.pem` | Path to CA bundle |
| `CAINJEKT_ANNOTATION_PREFIX` | `cainjekt.natron.io` | Annotation prefix for pod opt-in |
| `CAINJEKT_FAIL_POLICY` | `fail-open` | `fail-open` or `fail-closed` |
| `CAINJEKT_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `CAINJEKT_DYNAMIC_CA_ROOT` | `/run/cainjekt/containers` | Per-container CA staging root |

## Known Limitations

- **Static binaries** (Go, Rust): CA verification is compiled in — system stores are ignored
- **Distroless/scratch images**: No `/etc/os-release`, limited writable filesystem — fallback processor may not detect the correct trust store
- **Read-only root filesystems**: OS trust store cannot be modified, but language processors (Java, Node.js, Python) still work via env vars pointing to the dynamic CA path
- **Fail-open default**: Failed injection is silent — container starts without CA (check pod logs for warnings)

## Language Processors

| Processor | Env Var Set | Detection |
|-----------|------------|-----------|
| `lang-go` | `SSL_CERT_FILE` | `/usr/local/go/bin/go` |
| `lang-java` | `JAVA_TOOL_OPTIONS` (trustStore + PEM type) | `/usr/bin/java` |
| `lang-nodejs` | `NODE_EXTRA_CA_CERTS` | `/usr/bin/node` |
| `lang-python` | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | `/usr/bin/python3` |
| `lang-ruby` | `SSL_CERT_FILE` | `/usr/bin/ruby` |

## Observability

The NRI plugin exposes a Prometheus-compatible metrics endpoint on `:9443`:

- `GET /metrics` — Prometheus metrics (injection counts, errors, processor stats, active containers)
- `GET /healthz` — liveness probe
- `GET /readyz` — readiness probe

Enable Prometheus Operator scraping via Helm:

```bash
helm install cainjekt charts/cainjekt \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.labels.release=prometheus
```

## Building from Source

```bash
make build          # Build binary
make docker-build   # Build Docker images
make test           # Unit tests
make lint           # golangci-lint
make helm-lint      # Lint Helm chart
```

## Documentation

- [Architecture Deep-Dive](docs/architecture.md) — injection pipeline, processor system, security model
- [Usage Guide](docs/usage.md) — installation, configuration, verification, troubleshooting
- [Why We Forked](docs/why-we-forked.md) — what changed vs upstream and why
- [Kubernetes Deployment (kustomize)](deploy/kubernetes/README.md) — step-by-step kustomize deployment

## Requirements

- Kubernetes cluster with containerd runtime
- containerd v2.0+ (NRI enabled by default) or v1.x with NRI manually enabled

## License

MIT — see [LICENSE](LICENSE) for details. Original work by [tsuzu](https://github.com/tsuzu).
