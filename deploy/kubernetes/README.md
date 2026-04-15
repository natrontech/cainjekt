# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying cainjekt as a DaemonSet.

## Prerequisites

- Kubernetes cluster with containerd runtime
- kubectl configured to access the cluster
- CA certificate bundle you want to inject

**Note on NRI Support:**
- containerd v2.0+: NRI is **enabled by default** - no configuration needed
- containerd v1.x: NRI must be manually enabled (see troubleshooting section)

## Quick Start

### 1. Verify NRI is enabled (optional)

For **containerd v2.0 and later**, NRI is enabled by default. You can skip this step.

For **containerd v1.x**, verify NRI is enabled by checking the containerd configuration:

```bash
# Check containerd version
containerd --version

# For v1.x, ensure NRI is enabled in /etc/containerd/config.toml:
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  socket_path = "/var/run/nri/nri.sock"
  plugin_registration_timeout = "5s"
  plugin_request_timeout = "2s"

# Restart containerd if you made changes:
sudo systemctl restart containerd
```

### 2. (Optional) Use pre-built image from GHCR

The project provides pre-built container images on GitHub Container Registry:

```bash
# Images are available at:
# ghcr.io/natrontech/cainjekt:latest (latest main branch)
# ghcr.io/natrontech/cainjekt:v1.0.0 (specific version)
# ghcr.io/natrontech/cainjekt:main-<sha> (specific commit)

# Supports both amd64 and arm64 architectures
docker pull ghcr.io/natrontech/cainjekt:latest
```

The kustomization.yaml already points to the GHCR image. If you want to use a different image, update the `newName` in `kustomization.yaml`.

### 3. Create ConfigMap with your CA bundle

Create a ConfigMap containing your CA certificate bundle:

```bash
kubectl create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/your/ca-bundle.pem \
  --namespace=kube-system
```

**Note**: The ConfigMap is not included in the kustomization by default. You must create it separately with your actual CA bundle.

### 4. Deploy using kubectl

```bash
# Deploy the manifests
kubectl apply -f rbac.yaml
kubectl apply -f daemonset.yaml
```

### 5. Deploy using kustomize

```bash
# Create ConfigMap first
kubectl create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/your/ca-bundle.pem \
  --namespace=kube-system

# Then apply kustomization
kubectl apply -k .
```

### 6. Deploy using the deployment script

The script handles ConfigMap creation automatically:

```bash
cd deploy/kubernetes
./deploy.sh --ca-file /path/to/ca-bundle.pem
```

## Verify Installation

Check that the DaemonSet is running:

```bash
kubectl get daemonset -n kube-system cainjekt
kubectl get pods -n kube-system -l app=cainjekt
```

Check logs:

```bash
kubectl logs -n kube-system -l app=cainjekt -f
```

## Test CA Injection

Create a test pod with the annotation to enable CA injection:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-ca-injection
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  containers:
  - name: test
    image: ubuntu:22.04
    command: ["sleep", "infinity"]
```

Apply and verify:

```bash
kubectl apply -f test-pod.yaml
kubectl exec test-ca-injection -- cat /etc/ssl/certs/ca-certificates.crt
```

## Configuration

### Environment Variables

The DaemonSet supports the following environment variables:

- `CAINJEKT_CA_FILE`: Path to the CA bundle file (default: `/etc/cainjekt/ca-bundle.pem`)
- `CAINJEKT_DYNAMIC_CA_ROOT`: Root directory for per-container CA staging (default: `/run/cainjekt/containers`)
- `CAINJEKT_FAIL_POLICY`: Failure policy, either `fail-open` or `fail-closed` (default: `fail-open`)
- `CAINJEKT_ANNOTATION_PREFIX`: Annotation prefix for pod opt-in (default: `cainjekt.natron.io`)
- `CAINJEKT_LOG_LEVEL`: Log level: `debug`, `info`, `warn`, `error` (default: `info`)

### Pod Annotations

To enable CA injection for a specific pod, add the following annotation:

```yaml
metadata:
  annotations:
    cainjekt.natron.io/enabled: "true"
```

### Processor Selection

You can include or exclude specific processors using annotations:

```yaml
metadata:
  annotations:
    cainjekt.natron.io/enabled: "true"
    cainjekt.natron.io/processors.include: "osstore,lang-nodejs,lang-python"
    cainjekt.natron.io/processors.exclude: "java"
```

Language-specific processors currently include:

- `lang-nodejs`: sets `NODE_EXTRA_CA_CERTS`
- `lang-python`: sets `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`

## Customization

### Change Image Repository

Edit `kustomization.yaml` to use your own image registry:

```yaml
images:
- name: cainjekt
  newName: your-registry.io/cainjekt
  newTag: v1.0.0
```

### Adjust Resource Limits

Edit `daemonset.yaml` to adjust CPU and memory limits:

```yaml
resources:
  requests:
    cpu: 10m
    memory: 32Mi
  limits:
    cpu: 100m
    memory: 128Mi
```

## Troubleshooting

### DaemonSet pods not starting

1. **Check containerd version and NRI status:**
   ```bash
   # Check containerd version on node
   kubectl debug node/<node-name> -it --image=alpine -- chroot /host containerd --version

   # For containerd v2.0+: NRI is enabled by default
   # For containerd v1.x: Check if NRI is enabled
   kubectl debug node/<node-name> -it --image=alpine -- chroot /host cat /etc/containerd/config.toml | grep -A5 nri
   ```

2. **Check for NRI socket:**
   ```bash
   kubectl exec -n kube-system <cainjekt-pod> -- ls -la /var/run/nri/
   ```

   If socket doesn't exist and you're on containerd v1.x, you need to enable NRI:
   ```toml
   # Add to /etc/containerd/config.toml on each node
   [plugins."io.containerd.nri.v1.nri"]
     disable = false
     socket_path = "/var/run/nri/nri.sock"
   ```
   Then restart containerd: `systemctl restart containerd`

### CA not being injected

1. Verify pod has the correct annotation:
   ```bash
   kubectl get pod <pod-name> -o jsonpath='{.metadata.annotations}'
   ```

2. Check cainjekt logs:
   ```bash
   kubectl logs -n kube-system -l app=cainjekt
   ```

3. Verify the CA bundle is mounted correctly:
   ```bash
   kubectl exec -n kube-system <cainjekt-pod> -- cat /etc/cainjekt/ca-bundle.pem
   ```

## Uninstall

```bash
kubectl delete -k .
```

Or individually:

```bash
kubectl delete -f daemonset.yaml
kubectl delete -f configmap.yaml
kubectl delete -f rbac.yaml
```
