# Architecture

This document explains how cainjekt works at a technical level — the three-stage injection pipeline, the processor system, and the design decisions behind them.

## The Problem

Enterprise Kubernetes clusters often use custom Certificate Authorities (CAs) — for TLS inspection proxies, internal PKI, or self-signed services. Every container that makes HTTPS calls needs to trust these CAs. Without cainjekt, teams have two bad options:

1. **Bake CAs into every container image** — breaks the separation between application and infrastructure, requires rebuilding images when CAs rotate, and doesn't work for third-party images.
2. **Mount CA bundles via volumes** — requires every pod spec to include volume mounts, which is error-prone and doesn't update the OS trust store (only puts a file on disk).

cainjekt solves this by injecting CAs transparently at the container runtime level — no image changes, no pod spec changes beyond a single annotation.

## How It Works

cainjekt uses containerd's [Node Resource Interface (NRI)](https://github.com/containerd/nri) to intercept container lifecycle events. It runs as a DaemonSet on every node and operates in three phases:

```
┌──────────────────────────────────────────────────────────────────┐
│ Node                                                             │
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐     │
│  │ NRI Plugin  │────▶│ OCI Hook    │────▶│ Wrapper         │     │
│  │ (DaemonSet) │     │ (host ctx)  │     │ (container PID1)│     │
│  └─────────────┘     └─────────────┘     └─────────────────┘     │
│                                                                  │
│  CreateContainer      CreateRuntime       Container Start        │
│  event from           hook callback       entrypoint exec        │
│  containerd           before container    replaces wrapper       │
│                       process starts      with real command      │
└──────────────────────────────────────────────────────────────────┘
```

### Phase 1: NRI Plugin (CreateContainer)

When containerd creates a container, the NRI plugin receives a `CreateContainer` event. If the pod has the opt-in annotation (`cainjekt.natron.io/enabled: "true"`), the plugin:

1. **Reads the CA bundle** from the ConfigMap-mounted file (`/etc/cainjekt/ca-bundle.pem`)
2. **Validates the PEM** — rejects bundles with no valid certificates
3. **Stages a per-container copy** at `/run/cainjekt/containers/<container-id>/ca-bundle.pem` (so each container gets its own copy, isolated from others)
4. **Injects an OCI CreateRuntime hook** pointing to the cainjekt binary with env vars for hook mode
5. **Prepends the wrapper binary** to the container's entrypoint args (`[/cainjekt-entrypoint, original-cmd, ...]`)
6. **Bind-mounts the cainjekt binary** into the container as `/cainjekt-entrypoint`
7. **Sets env vars** in the container: `CAINJEKT_WRAPPER_MODE=1`, `CAINJEKT_HOOK_CONTEXT_FILE=/etc/cainjekt/hook-context.json`

All of this happens via NRI container adjustments — the container spec is modified before the container starts.

### Phase 2: OCI Hook (CreateRuntime)

The CreateRuntime hook runs on the host after the container's root filesystem is mounted but before the container process starts. This is the phase that modifies the container's filesystem:

1. **Reads OCI state** from stdin (container ID, bundle path, annotations)
2. **Resolves the container rootfs** from the OCI spec
3. **Runs the processor pipeline** in priority order:
   - **OS store processors** (priority 275-300): Detect the distro via `/etc/os-release`, merge the CA into the system trust store (e.g., `/etc/ssl/certs/ca-certificates.crt` on Debian)
   - **Language processors** (priority 100): Detect language runtimes, but do nothing in the hook phase (they act in the wrapper phase)
   - **Fallback processor** (priority -100): Tries common trust store paths if no distro matched
4. **Detects read-only rootfs** — if the filesystem is not writable, skips trust store modification and sets a fact so language processors can use the dynamic CA path instead
5. **Writes individual CA file** to the container's anchor directory (e.g., `/usr/local/share/ca-certificates/cainjekt.crt`)
6. **Persists hook context** to `/etc/cainjekt/hook-context.json` — which processors were detected, which facts were collected (distro, trust store path, individual CA path)
7. **Writes status file** to `/etc/cainjekt/status.json` — human-readable injection status for operator inspection

### Phase 3: Wrapper (Container Entrypoint)

The wrapper runs as the container's first process (PID 1). It:

1. **Reads the persisted hook context** from `/etc/cainjekt/hook-context.json`
2. **Runs wrapper processors** for each detected language runtime:
   - `lang-go`: sets `SSL_CERT_FILE`
   - `lang-java`: sets `JAVA_TOOL_OPTIONS` with `-Djavax.net.ssl.trustStore=... -Djavax.net.ssl.trustStoreType=PEM`
   - `lang-nodejs`: sets `NODE_EXTRA_CA_CERTS`
   - `lang-python`: sets `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`
   - `lang-ruby`: sets `SSL_CERT_FILE`
3. **Applies environment variables** to the process
4. **Execs the original command** via `syscall.Exec()` — the wrapper process is replaced by the real entrypoint, maintaining PID 1

The wrapper is **fail-open**: if any step fails (reading context, running processors, resolving the command), it logs a warning and execs the original command anyway. The container always starts.

## Processor System

Processors are the extensible core of cainjekt. Each processor implements a simple interface:

```go
type Processor interface {
    Name() string
    Category() string
    Detect(*Context) DetectResult
    Apply(*Context) error
}

type WrapperProcessor interface {
    Processor
    ApplyWrapper(*Context) error
}
```

### OS Store Processors

These run in the hook phase and modify the container's filesystem:

| Processor | Distro Match | Trust Store Path | Priority |
|-----------|-------------|------------------|----------|
| `os-debian` | debian, ubuntu | `/etc/ssl/certs/ca-certificates.crt` | 300 |
| `os-rhel` | rhel, fedora, centos, rocky, almalinux, ol, amzn | `/etc/pki/tls/certs/ca-bundle.crt` | 290 |
| `os-opensuse` | opensuse, sles, suse | `/etc/ssl/ca-bundle.pem` | 285 |
| `os-alpine` | alpine | `/etc/ssl/certs/ca-certificates.crt` | 280 |
| `os-arch` | arch | `/etc/ssl/certs/ca-certificates.crt` | 275 |
| `os-fallback` | (any) | tries common paths | -100 |

Detection works by reading `/etc/os-release` in the container rootfs and matching the `ID` and `ID_LIKE` fields.

### Language Processors

These run in the wrapper phase and set environment variables:

| Processor | Detection | Env Vars Set |
|-----------|-----------|-------------|
| `lang-go` | `/usr/local/go/bin/go` | `SSL_CERT_FILE` |
| `lang-java` | `/usr/bin/java` | `JAVA_TOOL_OPTIONS` (`-Djavax.net.ssl.trustStore`, `-Djavax.net.ssl.trustStoreType=PEM`) |
| `lang-nodejs` | `/usr/bin/node` | `NODE_EXTRA_CA_CERTS` |
| `lang-python` | `/usr/bin/python3` | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` |
| `lang-ruby` | `/usr/bin/ruby` | `SSL_CERT_FILE` |

Detection checks for the binary at multiple common paths in the container rootfs.

### Processor Filtering

Pods can control which processors run via annotations:

```yaml
annotations:
  cainjekt.natron.io/processors.include: "os-debian,lang-python"
  cainjekt.natron.io/processors.exclude: "os-fallback"
```

## Security Model

### Privileges

The DaemonSet runs with `privileged: true`, `hostPID: true`, and `hostNetwork: true`. This is required because:

- **NRI socket access**: The NRI socket at `/var/run/nri` is owned by containerd and requires root access
- **Container rootfs access**: The hook modifies files inside the container's mounted rootfs, which lives under containerd's internal storage
- **File ownership preservation**: When modifying trust stores, cainjekt preserves the original file ownership (uid/gid), which requires root

### Safety Guarantees

- **Opt-in only**: Containers are never modified unless the pod has `cainjekt.natron.io/enabled: "true"`
- **Atomic writes**: All file operations use temp file + rename for crash safety
- **Symlink protection**: Refuses to overwrite symlinks in trust stores (prevents symlink attacks)
- **Fail-open**: Hook and wrapper failures never block container startup
- **Per-container isolation**: Each container gets its own staged CA file; containers can't interfere with each other
- **No network calls**: The plugin operates entirely on local filesystem; no external communication

### CA Bundle Validation

The CA bundle is validated at staging time: `certs.ValidatePEM()` checks that the file contains at least one parseable X.509 certificate in PEM format. Invalid bundles are rejected with a clear error.

## Read-Only Root Filesystem Handling

When a container has a read-only root filesystem:

1. The OS store processor **detects** the read-only rootfs by probing writability
2. Trust store modification is **skipped** (no error)
3. The `FactRootfsReadOnly` fact is set
4. The `FactIndividualCAPath` is set to the **dynamic CA file path** (host-mounted, always readable)
5. Language processors use this path for env vars — they work regardless of rootfs writability
6. A warning is logged in the hook output

This means: **OS-level tools (curl, wget) won't trust the CA on read-only rootfs**, but **language runtimes (Java, Node.js, Python, Ruby, Go) will**, because they use the env var pointing to the dynamic CA file.

## Observability

### Prometheus Metrics

The NRI plugin exposes metrics on `:9443/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `cainjekt_injections_total` | Counter | Total injection attempts |
| `cainjekt_injections_errors_total` | Counter | Injection errors |
| `cainjekt_skipped_total` | Counter | Containers without opt-in annotation |
| `cainjekt_active_containers` | Gauge | Currently tracked injected containers |
| `cainjekt_cleanups_total` | Counter | Dynamic CA cleanups on removal |
| `cainjekt_cleanups_errors_total` | Counter | Cleanup errors |
| `cainjekt_orphans_cleaned_total` | Counter | Orphaned CA dirs cleaned |
| `cainjekt_processor_detected_total{processor}` | Counter | Per-processor detection count |
| `cainjekt_processor_applied_total{processor}` | Counter | Per-processor application count |

Plus standard Go runtime and process metrics via `prometheus/client_golang`.

### Status File

Every injected container has `/etc/cainjekt/status.json`:

```json
{
  "injected": true,
  "timestamp": "2026-04-15T08:27:15Z",
  "distro": "debian",
  "trust_store": "/etc/ssl/certs/ca-certificates.crt",
  "ca_file": "/run/cainjekt/containers/.../ca-bundle.pem",
  "processors": [
    { "name": "os-debian", "category": "os", "applicable": true },
    { "name": "lang-python", "category": "language", "applicable": true },
    ...
  ]
}
```

### Logging

Structured logging via `log/slog`. Configurable via `CAINJEKT_LOG_LEVEL` (debug/info/warn/error).

Key log points:
- Hook start: processor count, rootfs path, CA file
- Hook end: applied/skipped/failed counts, distro, trust store path
- Hook warning: read-only rootfs detected
- Wrapper: each applied processor, exec command
- Plugin: container create/remove events, injection decisions

## Lifecycle Management

### Orphan Cleanup

If the plugin crashes or a container is removed without triggering `RemoveContainer`, the per-container CA directory at `/run/cainjekt/containers/<id>/` becomes orphaned. A background goroutine sweeps every 5 minutes and removes directories that:

- Are not tracked by any currently active container
- Are older than 10 minutes

### Graceful Shutdown

On SIGTERM/SIGINT:
1. Stop accepting new NRI events
2. Stop the orphan cleaner
3. Gracefully shut down the HTTP server
4. Exit cleanly

### ConfigMap Hot-Reload

The CA bundle ConfigMap is read fresh on every `CreateContainer` call. When the ConfigMap is updated, Kubernetes refreshes the mounted file (via symlink swap). New containers automatically get the updated CA — no DaemonSet restart needed. Existing containers keep their staged CA.
