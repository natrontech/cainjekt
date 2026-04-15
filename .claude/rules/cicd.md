# CI/CD Conventions

## Overview

GitHub Actions handles CI and releases. Container images are published to GitHub Container Registry (`ghcr.io/natrontech/`).

## Workflows

- **`ci.yml`**: runs on push to `main` and pull requests. Unit tests, integration tests (kind cluster), E2E tests, Docker build verification.
- **`release.yml`**: runs on `v*` tags. Builds and pushes multi-arch images (amd64 + arm64), generates release manifests.

## Release Process

1. Create and push a tag: `git tag v0.1.0 && git push origin v0.1.0`
2. The release workflow builds images, tags with semver, and publishes manifests
3. Images are tagged with: full semver, major.minor, and git SHA

## Container Images

| Image | Source | Registry |
|-------|--------|----------|
| `cainjekt` | `Dockerfile` | `ghcr.io/natrontech/cainjekt` |
| `cainjekt-installer` | `Dockerfile` (installer target) | `ghcr.io/natrontech/cainjekt-installer` |

## Rules

- Never push images from local machines. All publishing goes through GitHub Actions.
- All images use multi-stage builds (Go builder + distroless runtime).
- Use GitHub Actions cache (`type=gha`) for Docker layer caching.
- Dependabot keeps all dependencies current (monthly schedule).
- Build with `-ldflags="-s -w" -trimpath` for minimal binary size.
- Multi-arch: linux/amd64 and linux/arm64.
