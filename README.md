# cainjekt

CA certificate injection tool for Kubernetes using NRI (Node Resource Interface).

## Features

- 🔒 Inject custom CA certificates into containers at runtime
- 🚀 Uses containerd NRI for transparent integration
- 🎯 Per-container dynamic CA bundle staging
- 🐧 Supports multiple OS distributions (Debian, Ubuntu, Alpine, etc.)
- 📦 Minimal container image based on distroless (~15MB)
- 🏗️ Multi-architecture support (amd64, arm64)

## Quick Start

### Deploy to Kubernetes

```bash
# Pull pre-built image from GitHub Container Registry
docker pull ghcr.io/tsuzu/cainjekt:latest

# Deploy using kustomize
kubectl apply -k deploy/kubernetes/

# Or use the deployment script
cd deploy/kubernetes
./deploy.sh --ca-file /path/to/ca-bundle.pem
```

See [deploy/kubernetes/README.md](deploy/kubernetes/README.md) for detailed deployment instructions.

### Enable CA injection for a pod

Add the annotation to your pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  annotations:
    cainjekt.io/enabled: "true"
spec:
  containers:
  - name: app
    image: my-app:latest
```

## Container Images

Pre-built images are available on GitHub Container Registry:

- `ghcr.io/tsuzu/cainjekt:latest` - Latest main branch
- `ghcr.io/tsuzu/cainjekt:v1.0.0` - Specific version
- `ghcr.io/tsuzu/cainjekt:main-<sha>` - Specific commit

Both `linux/amd64` and `linux/arm64` platforms are supported.

## Building from Source

```bash
# Build binary
make build

# Build Docker image
make docker-build

# Build and load into kind cluster
make kind-load
```

## Requirements

- Kubernetes cluster with containerd runtime
- containerd v2.0+ (NRI enabled by default) or v1.x with NRI manually enabled
- CA certificate bundle to inject

## License

See LICENSE file for details.
