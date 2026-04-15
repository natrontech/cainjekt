# General Conventions

## Project Structure

cainjekt is a single Go binary that runs in three modes (NRI plugin, OCI hook, wrapper). All code lives in one module.

```
cmd/cainjekt/          Entry point
internal/
  app/                 Mode routing
  config/              Constants, env vars, defaults
  engine/api/          Processor interfaces and types
  engine/processors/   Processor registry and implementations
  nri/                 NRI plugin (containerd integration)
  runtime/hook/        OCI CreateRuntime hook
  runtime/hookctx/     Hook context persistence
  runtime/wrapper/     Container entrypoint wrapper
  testutil/            Shared test helpers
  util/                Small utility packages
pkg/
  certs/               PEM certificate handling
  fsx/                 Atomic file operations
```

## Adding a New Processor

1. Create `internal/engine/processors/<name>/` with `<name>.go`
2. Implement `hookapi.Processor` (and `hookapi.WrapperProcessor` if env vars needed)
3. Register in `internal/engine/processors/registry.go` `init()`
4. Add unit tests
5. Add integration test if applicable

## Configuration

Environment-driven via constants in `internal/config/constants.go`. Pod opt-in via annotations or labels:
- `cainjekt.natron.io/enabled: "true"` — pod annotation or label (also works as namespace label)
- `cainjekt.natron.io/processors.include` (optional CSV filter)
- `cainjekt.natron.io/processors.exclude` (optional CSV filter)

Annotation prefix is configurable via `CAINJEKT_ANNOTATION_PREFIX`.

## Deployment

**Production**: Helm chart (`charts/cainjekt/`) or kustomize (`deploy/kubernetes/`).
**Development**: `make` targets with kind cluster (`hack/kind.yaml`).

## Observability

- Prometheus metrics at `:9443/metrics` (uses `prometheus/client_golang`)
- Health/readiness probes at `:9443/healthz` and `:9443/readyz`
- Helm chart supports ServiceMonitor (`serviceMonitor.enabled: true`)
- Structured logging via `log/slog`, configurable via `CAINJEKT_LOG_LEVEL`

## Security

- Atomic writes with symlink protection for all CA file operations
- Refuse to overwrite symlinks in trust stores
- Preserve file ownership when modifying existing files
- No network calls from the plugin — all operations are local filesystem
- Fail-open policy: hook failures never block container startup
