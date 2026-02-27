//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKindIntegration_CainjektInjection(t *testing.T) {
	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	pluginIdx := getenvOr("CAINJEKT_PLUGIN_IDX", fmt.Sprintf("%02d", (time.Now().UnixNano()%90)+10))

	requireCommand(t, "make")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireCommand(t, "docker")
	requireDockerAccess(t)

	runCmd(t, 10*time.Minute, "make", "copy-plugin", "CLUSTER_NAME="+clusterName)

	node := strings.TrimSpace(runCmd(t, 30*time.Second, "kind", "get", "nodes", "--name="+clusterName))
	if node == "" {
		t.Fatalf("could not determine kind node for cluster %q", clusterName)
	}

	caFile := writeTempCABundle(t)
	runCmd(t, 30*time.Second, "docker", "exec", node, "mkdir", "-p", "/etc/cainjekt")
	runCmd(t, 30*time.Second, "docker", "cp", caFile, node+":/etc/cainjekt/ca-bundle.pem")

	runCmd(t, 30*time.Second, "docker", "exec", "-d", node, "/cainjekt", "--idx", pluginIdx)
	t.Cleanup(func() {
		_ = tryCmd(20*time.Second, "docker", "exec", node, "sh", "-lc", fmt.Sprintf("pkill -f %q", "/cainjekt --idx "+pluginIdx))
	})
	// Let NRI plugin connect before creating pods.
	time.Sleep(2 * time.Second)

	ns := fmt.Sprintf("cainjekt-it-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true")
	})

	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	for _, tc := range []struct {
		name           string
		annotationsYML string
		expectWrapper  bool
	}{
		{
			name:          "default-processors",
			expectWrapper: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			podName := "it-" + strings.ReplaceAll(tc.name, "_", "-")
			manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    cainjekt.io/enabled: "true"
  annotations:
%sspec:
  restartPolicy: Never
  containers:
  - name: app
    image: alpine:3.20
    command: ["sh", "-c", "sleep 300"]
`, podName, ns, tc.annotationsYML)

			runCmdInput(t, 30*time.Second, manifest, "kubectl", "apply", "-f", "-")
			waitForPodReady(t, 2*time.Minute, ns, podName, "120s")

			containerID := strings.TrimSpace(runCmd(t, 30*time.Second, "kubectl", "get", "pod", podName, "-n", ns, "-o", "jsonpath={.status.containerStatuses[0].containerID}"))
			containerID = strings.TrimPrefix(containerID, "containerd://")
			if containerID == "" {
				t.Fatalf("container ID is empty")
			}

			inspect := inspectOCIConfig(t, node, containerID)
			if inspect.hasWrapper != tc.expectWrapper {
				t.Fatalf("wrapper expectation mismatch: expect=%v got=%v", tc.expectWrapper, inspect.hasWrapper)
			}
		})
	}
}

func TestKindIntegration_HTTPSWithInjectedCA(t *testing.T) {
	if getenvOr("CAINJEKT_TLS_E2E", "0") != "1" {
		t.Skip("set CAINJEKT_TLS_E2E=1 to run TLS trust E2E test")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	pluginIdx := getenvOr("CAINJEKT_PLUGIN_IDX", fmt.Sprintf("%02d", (time.Now().UnixNano()%90)+10))

	requireCommand(t, "make")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireCommand(t, "docker")
	requireDockerAccess(t)

	runCmd(t, 10*time.Minute, "make", "copy-plugin", "CLUSTER_NAME="+clusterName)
	node := strings.TrimSpace(runCmd(t, 30*time.Second, "kind", "get", "nodes", "--name="+clusterName))
	if node == "" {
		t.Fatalf("could not determine kind node for cluster %q", clusterName)
	}

	ns := fmt.Sprintf("cainjekt-e2e-%d", time.Now().UnixNano())
	svc := "https-server"
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true")
	})
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	caPath, srvCertPath, srvKeyPath := writeServicePKI(t, ns, svc)
	runCmd(t, 30*time.Second, "docker", "exec", node, "mkdir", "-p", "/etc/cainjekt")
	runCmd(t, 30*time.Second, "docker", "cp", caPath, node+":/etc/cainjekt/ca-bundle.pem")

	runCmd(t, 30*time.Second, "kubectl", "create", "secret", "generic", "https-server-tls", "-n", ns, "--from-file=tls.crt="+srvCertPath, "--from-file=tls.key="+srvKeyPath)

	_ = tryCmd(20*time.Second, "docker", "exec", node, "sh", "-lc", "pkill -f '/cainjekt --idx' || true")
	runCmd(t, 30*time.Second, "docker", "exec", "-d", node, "/cainjekt", "--idx", pluginIdx)
	t.Cleanup(func() {
		_ = tryCmd(20*time.Second, "docker", "exec", node, "sh", "-lc", fmt.Sprintf("pkill -f %q", "/cainjekt --idx "+pluginIdx))
	})
	time.Sleep(2 * time.Second)

	serverManifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: https-server
  namespace: %s
  labels:
    app: https-server
spec:
  restartPolicy: Never
  containers:
  - name: server
    image: python:3.12-alpine
    command:
    - python
    - -u
    - -c
    - |
      import http.server, ssl
      class H(http.server.BaseHTTPRequestHandler):
          def do_GET(self):
              if self.path == "/healthz":
                  self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
              else:
                  self.send_response(404); self.end_headers()
          def log_message(self, *args):
              pass
      srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
      ctx.load_cert_chain("/certs/tls.crt", "/certs/tls.key")
      srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
      srv.serve_forever()
    ports:
    - containerPort: 8443
    volumeMounts:
    - name: tls
      mountPath: /certs
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: https-server-tls
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: https-server
  ports:
  - protocol: TCP
    port: 8443
    targetPort: 8443
`, ns, svc, ns)
	runCmdInput(t, 30*time.Second, serverManifest, "kubectl", "apply", "-f", "-")
	waitForPodReady(t, 3*time.Minute, ns, "https-server", "180s")

	serviceURL := fmt.Sprintf("https://%s.%s.svc.cluster.local:8443/healthz", svc, ns)
	clientCases := []struct {
		name      string
		baseImage string
		install   string
		removeCA  bool
	}{
		{name: "alpine", baseImage: "alpine:3.20", install: "apk add --no-cache curl ca-certificates"},
		{name: "debian", baseImage: "debian:12-slim", install: "apt-get update && apt-get install -y --no-install-recommends curl ca-certificates"},
		{name: "fedora", baseImage: "fedora:40", install: "dnf -y install curl ca-certificates"},
		{name: "debian-no-ca", baseImage: "debian:12-slim", install: "apt-get update && apt-get install -y --no-install-recommends curl ca-certificates", removeCA: true},
	}

	for _, tc := range clientCases {
		tc := tc
		t.Run("client-"+tc.name, func(t *testing.T) {
			image := buildClientImageAndLoadToKind(t, clusterName, tc.baseImage, tc.install, tc.removeCA)
			suffix := strings.ReplaceAll(tc.name, "_", "-")

			injectedName := "curl-injected-" + suffix
			injectedPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    cainjekt.io/enabled: "true"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: %s
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "sleep 600"]
`, injectedName, ns, image)
			runCmdInput(t, 30*time.Second, injectedPod, "kubectl", "apply", "-f", "-")
			waitForPodReady(t, 2*time.Minute, ns, injectedName, "120s")
			runCmd(t, 5*time.Minute, "kubectl", "exec", "-n", ns, injectedName, "--", "sh", "-lc",
				fmt.Sprintf("test \"$(curl -fsS %s)\" = \"ok\"", serviceURL))

			plainName := "curl-plain-" + suffix
			plainPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    cainjekt.io/enabled: "false"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: %s
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "sleep 600"]
`, plainName, ns, image)
			runCmdInput(t, 30*time.Second, plainPod, "kubectl", "apply", "-f", "-")
			waitForPodReady(t, 2*time.Minute, ns, plainName, "120s")
			runCmd(t, 5*time.Minute, "kubectl", "exec", "-n", ns, plainName, "--", "sh", "-lc",
				fmt.Sprintf("if curl -fsS %s >/dev/null 2>&1; then exit 1; else exit 0; fi", serviceURL))
		})
	}
}

type ociInspect struct {
	hasWrapper bool
}

func inspectOCIConfig(t *testing.T, node, containerID string) ociInspect {
	t.Helper()
	py := `import json,sys
cid=sys.argv[1]
p=f"/run/containerd/io.containerd.runtime.v2.task/k8s.io/{cid}/config.json"
with open(p) as f:
    cfg=json.load(f)
env=cfg.get("process",{}).get("env",[])
args=cfg.get("process",{}).get("args",[])
def value(prefix):
    for v in env:
        if v.startswith(prefix):
            return v[len(prefix):]
    return ""
print(json.dumps({
  "wrapper": (len(args) > 0 and args[0] == "/cainjekt-entrypoint")
}))
`
	out := runCmd(t, 30*time.Second, "docker", "exec", node, "python3", "-c", py, containerID)
	var parsed struct {
		Wrapper bool `json:"wrapper"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("unexpected inspect output: %q (%v)", out, err)
	}
	return ociInspect{
		hasWrapper: parsed.Wrapper,
	}
}

func writeTempCABundle(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: "cainjekt-integration-root",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	p := filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := os.WriteFile(p, pemBytes, 0o644); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return p
}

func writeServicePKI(t *testing.T, namespace, service string) (caPath, serverCertPath, serverKeyPath string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: "cainjekt-test-root-ca",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace),
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{
			service,
			fmt.Sprintf("%s.%s", service, namespace),
			fmt.Sprintf("%s.%s.svc", service, namespace),
			fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace),
		},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	dir := t.TempDir()
	caPath = filepath.Join(dir, "ca-bundle.pem")
	serverCertPath = filepath.Join(dir, "server.crt")
	serverKeyPath = filepath.Join(dir, "server.key")

	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}
	if err := os.WriteFile(serverCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o644); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(serverKey)
	if err := os.WriteFile(serverKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}
	return caPath, serverCertPath, serverKeyPath
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("skipping integration test, missing command %q: %v", name, err)
	}
}

func requireDockerAccess(t *testing.T) {
	t.Helper()
	out, err := runCmdWithInput(15*time.Second, "", "docker", "info", "--format", "{{.ServerVersion}}")
	if err != nil {
		t.Skipf("skipping integration test, docker is not accessible: %v\n%s", err, out)
	}
}

func buildClientImageAndLoadToKind(t *testing.T, clusterName, baseImage, installCmd string, removeCA bool) string {
	t.Helper()
	tag := fmt.Sprintf("cainjekt/curl-no-ca:%d", time.Now().UnixNano())
	tmp := t.TempDir()
	dockerfile := fmt.Sprintf(`FROM %s
RUN %s%s
CMD ["sh", "-c", "sleep 600"]
`, baseImage, installCmd, func() string {
		if removeCA {
			return " && rm -f /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt && mkdir -p /etc/ssl && : > /etc/ssl/cert.pem"
		}
		return ""
	}())
	df := filepath.Join(tmp, "Dockerfile")
	if err := os.WriteFile(df, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write dockerfile: %v", err)
	}
	runCmd(t, 5*time.Minute, "docker", "build", "-t", tag, "-f", df, tmp)
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "docker", "rmi", tag)
	})
	if out, err := runCmdWithInput(2*time.Minute, "", "kind", "load", "docker-image", "--name", clusterName, tag); err != nil {
		t.Logf("kind load docker-image failed, falling back to ctr import: %v\n%s", err, out)
		importImageViaCtr(t, clusterName, tag)
	}
	return tag
}

func importImageViaCtr(t *testing.T, clusterName, tag string) {
	t.Helper()
	nodesRaw := runCmd(t, 30*time.Second, "kind", "get", "nodes", "--name="+clusterName)
	nodes := strings.Fields(nodesRaw)
	if len(nodes) == 0 {
		t.Fatalf("no kind nodes found for cluster %q", clusterName)
	}

	for _, node := range nodes {
		runCmd(t, 3*time.Minute, "bash", "-lc",
			fmt.Sprintf("docker save %s | docker exec -i %s ctr -n k8s.io images import -", tag, node))
	}
}

func waitForDefaultServiceAccount(t *testing.T, namespace string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := runCmdWithInput(5*time.Second, "", "kubectl", "get", "serviceaccount", "default", "-n", namespace, "-o", "name")
		if err == nil && strings.TrimSpace(out) == "serviceaccount/default" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("default serviceaccount did not appear in namespace %q within timeout", namespace)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitForPodReady(t *testing.T, timeout time.Duration, namespace, podName, kubectlTimeout string) {
	t.Helper()

	args := []string{
		"wait", "--for=condition=Ready", "pod/" + podName,
		"-n", namespace,
		"--timeout=" + kubectlTimeout,
	}
	out, err := runCmdWithInput(timeout, "", "kubectl", args...)
	if err == nil {
		return
	}

	describe, describeErr := runCmdWithInput(30*time.Second, "", "kubectl", "describe", "pod", podName, "-n", namespace)
	if describeErr != nil {
		describe = fmt.Sprintf("failed to describe pod: %v\noutput:\n%s", describeErr, describe)
	}

	t.Fatalf("command failed: kubectl %s\nerror: %v\noutput:\n%s\n\npod describe (%s/%s):\n%s",
		strings.Join(args, " "), err, out, namespace, podName, describe)
}

func runCmd(t *testing.T, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	out, err := runCmdWithInput(timeout, "", name, args...)
	if err != nil {
		t.Fatalf("command failed: %s %s\nerror: %v\noutput:\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func runCmdInput(t *testing.T, timeout time.Duration, input string, name string, args ...string) string {
	t.Helper()
	out, err := runCmdWithInput(timeout, input, name, args...)
	if err != nil {
		t.Fatalf("command failed: %s %s\nerror: %v\noutput:\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func runCmdRetry(t *testing.T, attempts int, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	var lastOut string
	var lastErr error
	for i := 1; i <= attempts; i++ {
		out, err := runCmdWithInput(timeout, "", name, args...)
		if err == nil {
			return out
		}
		lastOut = out
		lastErr = err
		time.Sleep(time.Duration(i) * time.Second)
	}
	t.Fatalf("command failed after %d attempts: %s %s\nlast error: %v\noutput:\n%s", attempts, name, strings.Join(args, " "), lastErr, lastOut)
	return ""
}

func tryCmd(timeout time.Duration, name string, args ...string) error {
	_, err := runCmdWithInput(timeout, "", name, args...)
	return err
}

func runCmdWithInput(timeout time.Duration, input string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = mustRepoRoot()
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timeout after %s", timeout)
	}
	return string(out), err
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

var (
	repoRootOnce sync.Once
	repoRootVal  string
	repoRootErr  error
)

func mustRepoRoot() string {
	repoRootOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			repoRootErr = err
			return
		}
		dir := wd
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				repoRootVal = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				repoRootErr = fmt.Errorf("go.mod not found from %s", wd)
				return
			}
			dir = parent
		}
	})
	if repoRootErr != nil {
		panic(repoRootErr)
	}
	return repoRootVal
}
