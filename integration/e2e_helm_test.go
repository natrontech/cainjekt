//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E_HelmDeployment(t *testing.T) {
	if getenvOr("CAINJEKT_E2E", "0") != "1" {
		t.Skip("set CAINJEKT_E2E=1 to run E2E Helm deployment test")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")

	requireCommand(t, "make")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireCommand(t, "docker")
	requireCommand(t, "helm")
	requireDockerAccess(t)

	// Ensure cluster exists and images are loaded
	node := strings.TrimSpace(runCmd(t, 30*time.Second, "kind", "get", "nodes", "--name="+clusterName))
	if node == "" {
		t.Fatalf("could not determine kind node for cluster %q", clusterName)
	}

	t.Log("Building Docker images and loading to kind cluster...")
	runCmd(t, 5*time.Minute, "make", "kind-load", "CLUSTER_NAME="+clusterName)

	// Clean up any previous cainjekt Helm releases to avoid NRI plugin conflicts.
	_ = tryCmd(1*time.Minute, "helm", "uninstall", "cainjekt-e2e", "-n", "kube-system")

	// Create test CA bundle
	caPath := writeTempCABundle(t)

	// Helm install
	chartDir := filepath.Join(mustGetProjectRoot(t), "charts", "cainjekt")
	releaseName := "cainjekt-e2e"

	t.Log("Installing cainjekt via Helm...")
	runCmd(t, 2*time.Minute, "helm", "install", releaseName, chartDir,
		"--namespace", "kube-system",
		"--set", "image.repository=cainjekt",
		"--set", "image.tag=latest",
		"--set", "image.pullPolicy=IfNotPresent",
		"--set", "installerImage.repository=cainjekt-installer",
		"--set", "installerImage.tag=latest",
		"--set", "installerImage.pullPolicy=IfNotPresent",
		"--set-file", "caBundle="+caPath,
		"--wait",
		"--timeout", "3m",
	)

	t.Cleanup(func() {
		t.Log("Uninstalling Helm release...")
		_ = tryCmd(1*time.Minute, "helm", "uninstall", releaseName, "-n", "kube-system")
	})

	// Verify DaemonSet is ready (--wait should have ensured this, but verify)
	t.Log("Verifying DaemonSet is ready...")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			podDesc, _ := runCmdWithInput(10*time.Second, "", "kubectl", "describe", "pods", "-n", "kube-system",
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName))
			t.Logf("Pod description:\n%s", podDesc)
			t.Fatal("timeout waiting for DaemonSet to be ready")
		case <-time.After(3 * time.Second):
			dsReady, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "daemonset", releaseName,
				"-n", "kube-system", "-o", "jsonpath={.status.numberReady}")
			if strings.TrimSpace(dsReady) == "1" {
				goto ready
			}
		}
	}

ready:
	// Check pod logs for successful plugin registration
	t.Log("Checking plugin registration...")
	podName := strings.TrimSpace(runCmd(t, 30*time.Second,
		"kubectl", "get", "pods", "-n", "kube-system",
		"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName),
		"-o", "jsonpath={.items[0].metadata.name}"))
	logs := runCmd(t, 30*time.Second, "kubectl", "logs", "-n", "kube-system", podName, "--tail=50")
	t.Logf("Pod logs:\n%s", logs)

	if !strings.Contains(logs, "Started plugin") {
		t.Error("Expected 'Started plugin' in pod logs")
	}

	// Deploy test pod with CA injection
	ns := fmt.Sprintf("cainjekt-helm-e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true")
	})
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	t.Log("Deploying test pod with CA injection annotation...")
	testPodManifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: test-helm-ca
  namespace: %s
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  restartPolicy: Never
  containers:
  - name: ubuntu
    image: ubuntu:22.04
    command: ["sleep", "3600"]
`, ns)

	tmpManifest := filepath.Join(t.TempDir(), "test-pod.yaml")
	if err := os.WriteFile(tmpManifest, []byte(testPodManifest), 0o644); err != nil {
		t.Fatalf("failed to write test pod manifest: %v", err)
	}
	runCmd(t, 30*time.Second, "kubectl", "apply", "-f", tmpManifest)

	// Wait for pod to be running
	waitForPodPhase(t, 2*time.Minute, ns, "test-helm-ca", "Running")

	// Verify CA was injected
	t.Log("Verifying CA certificate injection...")
	output := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-helm-ca", "--",
		"ls", "-la", "/usr/local/share/ca-certificates/")
	t.Logf("CA certificates directory:\n%s", output)

	if !strings.Contains(output, "cainjekt.crt") {
		t.Error("Expected cainjekt.crt in /usr/local/share/ca-certificates/")
	}

	output2 := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-helm-ca", "--",
		"cat", "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(output2, "BEGIN CERTIFICATE") {
		t.Error("Expected certificates in trust store")
	}

	t.Log("Helm E2E test passed: Helm deployment with CA injection works!")
}
