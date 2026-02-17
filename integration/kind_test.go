//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKindIntegration_CainjektInjection(t *testing.T) {
	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	pluginIdx := getenvOr("CAINJEKT_PLUGIN_IDX", fmt.Sprintf("%02d", time.Now().Unix()%90+10))

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
			runCmd(t, 2*time.Minute, "kubectl", "wait", "--for=condition=Ready", "pod/"+podName, "-n", ns, "--timeout=120s")

			containerID := strings.TrimSpace(runCmd(t, 30*time.Second, "kubectl", "get", "pod", podName, "-n", ns, "-o", "jsonpath={.status.containerStatuses[0].containerID}"))
			containerID = strings.TrimPrefix(containerID, "containerd://")
			if containerID == "" {
				t.Fatalf("container ID is empty")
			}

			inspect := inspectOCIConfig(t, node, containerID)
			if !inspect.hasSSLCertFile || !inspect.hasNodeExtra || !inspect.hasRequestsBundle {
				t.Fatalf("expected CA env vars in OCI spec, got ssl=%v node=%v requests=%v", inspect.hasSSLCertFile, inspect.hasNodeExtra, inspect.hasRequestsBundle)
			}
			if inspect.hasWrapper != tc.expectWrapper {
				t.Fatalf("wrapper expectation mismatch: expect=%v got=%v", tc.expectWrapper, inspect.hasWrapper)
			}
		})
	}
}

type ociInspect struct {
	hasSSLCertFile    bool
	hasNodeExtra      bool
	hasRequestsBundle bool
	hasWrapper        bool
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
def has(prefix):
    return any(v.startswith(prefix) for v in env)
print(int(has("SSL_CERT_FILE=")))
print(int(has("NODE_EXTRA_CA_CERTS=")))
print(int(has("REQUESTS_CA_BUNDLE=")))
print(int(len(args) > 0 and args[0] == "/cainjekt-entrypoint"))
`
	out := runCmd(t, 30*time.Second, "docker", "exec", node, "python3", "-c", py, containerID)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("unexpected inspect output: %q", out)
	}
	parse := func(s string) bool {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			t.Fatalf("failed to parse inspect output %q: %v", s, err)
		}
		return n == 1
	}
	return ociInspect{
		hasSSLCertFile:    parse(lines[0]),
		hasNodeExtra:      parse(lines[1]),
		hasRequestsBundle: parse(lines[2]),
		hasWrapper:        parse(lines[3]),
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
