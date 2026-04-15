# Contributing to cainjekt

Thank you for your interest in contributing! cainjekt is an open-source project and we welcome contributions of all kinds — bug reports, feature requests, documentation improvements, and code.

## Getting Started

### Prerequisites

- Go 1.25+
- Docker
- [kind](https://kind.sigs.k8s.io/) (for integration/E2E tests)
- kubectl
- Helm 3
- golangci-lint

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/natrontech/cainjekt.git
cd cainjekt

# Build
make build

# Run unit tests
make test

# Run linter
make lint

# Create a kind cluster with NRI enabled and run E2E tests
make prepare-test-cluster
make kind-load
make e2e-test
```

### Running All Tests

```bash
# Unit tests
make test

# Lint
make lint

# Integration tests (requires kind cluster)
make integration-test

# E2E tests (requires kind cluster with images loaded)
make e2e-test

# Everything
make test-all

# Helm chart
make helm-lint
```

## How to Contribute

### Bug Reports

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- cainjekt version, Kubernetes version, containerd version
- Output of `kubectl exec <pod> -- cat /etc/cainjekt/status.json` if applicable

### Feature Requests

Open an issue describing:
- The problem you're trying to solve
- Your proposed solution (if you have one)
- Whether you'd be willing to implement it

### Code Contributions

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feat/my-feature`
3. **Make your changes** — follow the conventions below
4. **Run tests**: `make test && make lint`
5. **Commit** with a [conventional commit](https://www.conventionalcommits.org/) message
6. **Push** and open a pull request

### Adding a New Processor

This is the most common type of contribution. Follow these steps:

1. Create `internal/engine/processors/<name>/<name>.go`
2. Implement `hookapi.Processor` (and `hookapi.WrapperProcessor` if env vars are needed)
3. Register in `internal/engine/processors/registry.go` `init()`
4. Add unit tests in `<name>_test.go`
5. Update documentation:
   - `README.md` (language processor table)
   - `CLAUDE.md` (processor list)
   - `docs/architecture.md` (processor tables)
   - `docs/usage.md` (available processors, limitations table)
   - `deploy/kubernetes/README.md` (processor selection)

Look at `internal/engine/processors/python/python.go` for a clean example.

## Conventions

### Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(processor): add .NET CA injection via SSL_CERT_FILE
fix(hook): handle empty os-release gracefully
docs: update processor table in architecture.md
test(e2e): add distroless image injection test
ci: add arm64 runner to release workflow
```

### Go Code

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use `log/slog` for logging
- Wrap errors with `fmt.Errorf("context: %w", err)`
- Three import groups: stdlib, external, internal
- Run `make lint` before pushing — zero issues required

### Documentation

Every code change that affects behavior must include doc updates. See `.claude/rules/docs.md` for the full sync table.

### Tests

- Unit tests alongside source files (`_test.go`)
- Integration tests in `integration/` with `//go:build integration` tag
- Use `t.TempDir()`, `t.Helper()`, `t.Parallel()` where applicable
- Table-driven tests for multi-case scenarios

## Architecture Overview

See [docs/architecture.md](docs/architecture.md) for the full technical deep-dive. The key components:

- **NRI Plugin** (`internal/nri/`): Intercepts container creation, stages CA files
- **Hook** (`internal/runtime/hook/`): Modifies container rootfs trust stores
- **Wrapper** (`internal/runtime/wrapper/`): Sets language env vars, execs original command
- **Processors** (`internal/engine/processors/`): Extensible detection + application system
- **Helm Chart** (`charts/cainjekt/`): Production deployment with monitoring integration

## Need Help?

- Open an issue for questions
- Check [docs/usage.md](docs/usage.md) for troubleshooting
- Check [docs/architecture.md](docs/architecture.md) for understanding the internals
