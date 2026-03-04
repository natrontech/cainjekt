# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying cainjekt as a DaemonSet.

## Prerequisites

- Kubernetes cluster with NRI enabled in containerd
- kubectl configured to access the cluster
- CA certificate bundle you want to inject

## Quick Start

### 1. Enable NRI in containerd

NRI must be enabled in containerd configuration. Add the following to your containerd config (typically `/etc/containerd/config.toml`):

```toml
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  socket_path = "/var/run/nri/nri.sock"
  plugin_registration_timeout = "5s"
  plugin_request_timeout = "2s"
```

Restart containerd after making this change:

```bash
sudo systemctl restart containerd
```

### 2. Prepare your CA bundle

Edit `configmap.yaml` and replace the placeholder with your actual CA certificate bundle:

```bash
kubectl create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/your/ca-bundle.pem \
  --namespace=kube-system \
  --dry-run=client -o yaml > configmap.yaml
```

### 3. Deploy using kubectl

```bash
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f daemonset.yaml
```

### 4. Deploy using kustomize

```bash
kubectl apply -k .
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
    cainjekt.io/enabled: "true"
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

### Pod Annotations

To enable CA injection for a specific pod, add the following annotation:

```yaml
metadata:
  annotations:
    cainjekt.io/enabled: "true"
```

### Processor Selection

You can include or exclude specific processors using annotations:

```yaml
metadata:
  annotations:
    cainjekt.io/enabled: "true"
    cainjekt.io/processors.include: "osstore,nodejs"
    cainjekt.io/processors.exclude: "java"
```

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

1. Check if NRI is enabled in containerd:
   ```bash
   kubectl exec -n kube-system <containerd-node> -- cat /etc/containerd/config.toml | grep -A5 nri
   ```

2. Check for NRI socket:
   ```bash
   kubectl exec -n kube-system <cainjekt-pod> -- ls -la /var/run/nri/
   ```

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
