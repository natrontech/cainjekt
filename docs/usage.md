# Usage Guide

## Installation

### Helm (recommended)

```bash
helm install cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --namespace kube-system \
  --set-file caBundle=/path/to/ca-bundle.pem
```

With monitoring enabled:

```bash
helm install cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --namespace kube-system \
  --set-file caBundle=/path/to/ca-bundle.pem \
  --set serviceMonitor.enabled=true \
  --set grafanaDashboard.enabled=true \
  --set prometheusRule.enabled=true \
  --set podDisruptionBudget.enabled=true
```

### Using an existing CA bundle ConfigMap

If you already have a ConfigMap with your CA certificates:

```bash
helm install cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --namespace kube-system \
  --set caBundleExistingConfigMap=my-existing-ca-configmap
```

The ConfigMap must have a key named `ca-bundle.pem`.

## Enabling CA Injection

### Per-Pod (annotation)

Add the annotation to any pod that should receive CA injection:

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

This works for Deployments, StatefulSets, Jobs, CronJobs — any resource that creates pods.

### Per-Namespace (label)

To enable injection for all pods in a namespace, set the label on the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-team
  labels:
    cainjekt.natron.io/enabled: "true"
```

Pods in this namespace will be injected unless they explicitly opt out. Pod-level annotations take precedence over namespace labels. The namespace label is checked via the Kubernetes API (cached for 1 minute).

### Excluding Specific Containers

To skip injection for sidecars or other containers within an injected pod:

```yaml
annotations:
  cainjekt.natron.io/enabled: "true"
  cainjekt.natron.io/exclude-containers: "istio-proxy,linkerd-proxy"
```

### Custom Annotation Prefix

If your organization uses a different annotation domain:

```bash
helm install cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --set annotationPrefix=ca.example.com \
  --set-file caBundle=/path/to/ca-bundle.pem
```

Pods would then use `ca.example.com/enabled: "true"`.

## Processor Selection

By default, all processors run. You can filter which processors are active per pod:

```yaml
annotations:
  cainjekt.natron.io/enabled: "true"
  # Only run these processors (comma-separated)
  cainjekt.natron.io/processors.include: "os-debian,lang-python"
  # Or exclude specific ones
  cainjekt.natron.io/processors.exclude: "os-fallback,lang-java"
```

Available processors:

**OS store** (modify system trust stores):
`os-debian`, `os-rhel`, `os-opensuse`, `os-alpine`, `os-arch`, `os-fallback`

**Language** (set environment variables):
`lang-go`, `lang-java`, `lang-nodejs`, `lang-python`, `lang-ruby`

## Verifying Injection

### Check the status file

Every injected container has a status file at `/etc/cainjekt/status.json`:

```bash
kubectl exec my-pod -- cat /etc/cainjekt/status.json | jq .
```

Output:

```json
{
  "injected": true,
  "timestamp": "2026-04-15T08:27:15Z",
  "distro": "debian",
  "trust_store": "/etc/ssl/certs/ca-certificates.crt",
  "processors": [
    { "name": "os-debian", "category": "os", "applicable": true },
    { "name": "lang-python", "category": "language", "applicable": true }
  ]
}
```

### Check the trust store

```bash
# Debian/Ubuntu
kubectl exec my-pod -- cat /etc/ssl/certs/ca-certificates.crt | grep -c "BEGIN CERTIFICATE"

# RHEL/Fedora
kubectl exec my-pod -- cat /etc/pki/tls/certs/ca-bundle.crt | grep -c "BEGIN CERTIFICATE"

# Individual CA file
kubectl exec my-pod -- ls /usr/local/share/ca-certificates/cainjekt.crt
```

### Check environment variables

```bash
# Java
kubectl exec my-pod -- env | grep JAVA_TOOL_OPTIONS

# Node.js
kubectl exec my-pod -- env | grep NODE_EXTRA_CA_CERTS

# Python
kubectl exec my-pod -- env | grep SSL_CERT_FILE
```

### Check the plugin logs

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=cainjekt -f
```

### Check metrics

```bash
kubectl port-forward -n kube-system daemonset/cainjekt 9443:9443
curl http://localhost:9443/metrics | grep cainjekt_
```

## Updating the CA Bundle

Update the ConfigMap with the new CA bundle:

```bash
kubectl create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/new-ca-bundle.pem \
  --namespace=kube-system \
  --dry-run=client -o yaml | kubectl apply -f -
```

Or with Helm:

```bash
helm upgrade cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --namespace kube-system \
  --set-file caBundle=/path/to/new-ca-bundle.pem
```

**New containers** will automatically get the updated CA. **Existing containers** keep their current CA until they are restarted.

## Troubleshooting

### Container starts but HTTPS calls fail

1. Check if injection was enabled: `kubectl get pod <name> -o jsonpath='{.metadata.annotations}'`
2. Check the status file: `kubectl exec <pod> -- cat /etc/cainjekt/status.json`
3. Check if the trust store was modified: `kubectl exec <pod> -- cat /etc/ssl/certs/ca-certificates.crt | tail -20`
4. Check cainjekt logs: `kubectl logs -n kube-system -l app.kubernetes.io/name=cainjekt`

### Status file says "rootfs_read_only: true"

The container has a read-only root filesystem. OS trust stores cannot be modified, but language processors still set env vars. If you're using `curl` or `wget` (which read the OS trust store), they won't trust the CA. Use language-specific tools instead, or make the rootfs writable.

### Injection works on some images but not others

Check the distro detection: `kubectl exec <pod> -- cat /etc/os-release`. If the file doesn't exist (distroless images), the fallback processor tries common paths but may not find the right one. Language env vars will still work.

### Metrics show high error rate

Check `CAINJEKT_LOG_LEVEL=debug` for detailed logs:

```bash
helm upgrade cainjekt oci://ghcr.io/natrontech/charts/cainjekt \
  --set logLevel=debug
```

Common causes: invalid CA bundle (check PEM format), NRI socket issues (check containerd version), insufficient permissions.

## Limitations

| Scenario | Works? | Details |
|----------|--------|---------|
| Standard Linux distros | Yes | Debian, Ubuntu, Alpine, RHEL, Fedora, Arch, openSUSE |
| Java apps (JDK 18+) | Yes | `JAVA_TOOL_OPTIONS` with `-Djavax.net.ssl.trustStoreType=PEM` |
| Java apps (JDK < 18) | No | PEM trust store type not supported; would need JKS keystore manipulation |
| Node.js apps | Yes | `NODE_EXTRA_CA_CERTS` |
| Python apps | Yes | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` |
| Ruby apps | Yes | `SSL_CERT_FILE` |
| Go apps | Yes | `SSL_CERT_FILE` + OS trust store |
| Static Go binaries | Partial | OS trust store works if paths exist; `SSL_CERT_FILE` requires Go binary in image |
| Distroless images | Partial | Language env vars work; OS trust store may not |
| Read-only rootfs | Partial | Language env vars work; OS trust store cannot be modified |
| Scratch images (no shell) | No | No OS trust store, no language binaries to detect |
| .NET apps | Untested | May work via OS trust store on Linux |
| Custom TLS implementations | No | Apps that don't read system CAs or env vars |
