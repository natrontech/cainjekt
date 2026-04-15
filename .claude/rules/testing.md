# Testing Conventions

## Test Levels

### Unit Tests
```bash
go test ./...
go test ./internal/nri/ -run TestSpecificName -v
```
- Standard `testing` package, no external frameworks
- Use `t.TempDir()` for filesystem tests
- Use `t.Helper()` in test helpers
- Use `t.Parallel()` for independent tests
- Table-driven tests with `tc := tc` pattern (Go <1.22) are no longer needed

### Integration Tests
```bash
make integration-test    # TLS integration (requires kind cluster)
make e2e-test           # Kubernetes manifest deployment
make test-all           # Everything
```
- Build tag: `//go:build integration`
- Gated by env vars: `CAINJEKT_TLS_INTEGRATION=1`, `CAINJEKT_E2E=1`
- Run against real kind clusters (not mocks)
- Cluster name: `cainjekt-test-cluster` (configurable via `CAINJEKT_CLUSTER_NAME`)

## Test Patterns

- **Idempotent**: safe to run repeatedly
- **Self-contained**: tests create and clean up their own resources
- **Descriptive names**: `TestApplySkipsWhenTrustStoreAlreadyConfigured`
- **Test helpers** in `internal/testutil/`: `WriteExecutableInRootfs`, `EnvValue`
- **Rootfs simulation**: create temp dirs mimicking container filesystem layout

## Adding Tests

When adding a new processor:
1. Add unit tests for `Detect()` with matching/non-matching distros
2. Add unit tests for `Apply()` with CA merge verification
3. Add unit tests for `ApplyWrapper()` with env var verification
4. If applicable, add integration test in `integration/` with real container images
