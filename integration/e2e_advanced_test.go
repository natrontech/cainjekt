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

// TestE2E_InitContainerInjection verifies that init containers also receive CA injection.
func TestE2E_InitContainerInjection(t *testing.T) {
	if getenvOr("CAINJEKT_E2E", "0") != "1" {
		t.Skip("set CAINJEKT_E2E=1 to run E2E tests")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	requireCommand(t, "kubectl")
	requireCommand(t, "helm")

	ensureHelmRelease(t, clusterName)

	ns := fmt.Sprintf("cainjekt-init-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true") })
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: test-init
  namespace: %s
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  restartPolicy: Never
  initContainers:
  - name: init
    image: ubuntu:22.04
    command: ["sh", "-c", "ls /usr/local/share/ca-certificates/ > /shared/init-result.txt"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  containers:
  - name: main
    image: ubuntu:22.04
    command: ["sh", "-c", "cat /shared/init-result.txt && sleep 3600"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  volumes:
  - name: shared
    emptyDir: {}
`, ns)

	tmpFile := filepath.Join(t.TempDir(), "pod.yaml")
	if err := os.WriteFile(tmpFile, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	runCmd(t, 30*time.Second, "kubectl", "apply", "-f", tmpFile)

	waitForPodPhase(t, 2*time.Minute, ns, "test-init", "Running")

	// Check that the init container saw the CA file.
	output := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-init", "-c", "main", "--", "cat", "/shared/init-result.txt")
	t.Logf("Init container CA listing: %s", output)
	if !strings.Contains(output, "cainjekt.crt") {
		t.Error("Expected init container to see cainjekt.crt")
	}

	t.Log("Init container injection test passed")
}

// TestE2E_ContainerRestartReinjection verifies CA is re-injected after container restart.
func TestE2E_ContainerRestartReinjection(t *testing.T) {
	if getenvOr("CAINJEKT_E2E", "0") != "1" {
		t.Skip("set CAINJEKT_E2E=1 to run E2E tests")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	requireCommand(t, "kubectl")
	requireCommand(t, "helm")

	ensureHelmRelease(t, clusterName)

	ns := fmt.Sprintf("cainjekt-restart-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true") })
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	// Pod that exits with code 1, then on second run succeeds.
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: test-restart
  namespace: %s
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  restartPolicy: Always
  containers:
  - name: app
    image: ubuntu:22.04
    command: ["sh", "-c", "ls /usr/local/share/ca-certificates/cainjekt.crt && sleep 3600"]
`, ns)

	tmpFile := filepath.Join(t.TempDir(), "pod.yaml")
	if err := os.WriteFile(tmpFile, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	runCmd(t, 30*time.Second, "kubectl", "apply", "-f", tmpFile)

	waitForPodPhase(t, 2*time.Minute, ns, "test-restart", "Running")

	// Verify CA exists.
	output := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-restart", "--",
		"ls", "/usr/local/share/ca-certificates/")
	if !strings.Contains(output, "cainjekt.crt") {
		t.Fatal("CA not found after initial start")
	}

	// Delete the pod and recreate it (simulates restart scenario via new container).
	runCmd(t, 2*time.Minute, "kubectl", "delete", "pod", "test-restart", "-n", ns, "--wait=true")
	runCmd(t, 30*time.Second, "kubectl", "apply", "-f", tmpFile)
	waitForPodPhase(t, 2*time.Minute, ns, "test-restart", "Running")

	output2 := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-restart", "--",
		"ls", "/usr/local/share/ca-certificates/")
	if !strings.Contains(output2, "cainjekt.crt") {
		t.Fatal("CA not found after pod recreation")
	}

	t.Log("Container restart re-injection test passed")
}

// TestE2E_StatusFilePresent verifies /etc/cainjekt/status.json exists in injected containers.
func TestE2E_StatusFilePresent(t *testing.T) {
	if getenvOr("CAINJEKT_E2E", "0") != "1" {
		t.Skip("set CAINJEKT_E2E=1 to run E2E tests")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")
	requireCommand(t, "kubectl")
	requireCommand(t, "helm")

	ensureHelmRelease(t, clusterName)

	ns := fmt.Sprintf("cainjekt-status-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true") })
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: test-status
  namespace: %s
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: ubuntu:22.04
    command: ["sleep", "3600"]
`, ns)

	tmpFile := filepath.Join(t.TempDir(), "pod.yaml")
	if err := os.WriteFile(tmpFile, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	runCmd(t, 30*time.Second, "kubectl", "apply", "-f", tmpFile)
	waitForPodPhase(t, 2*time.Minute, ns, "test-status", "Running")

	// First verify CA injection worked (proves the hook ran).
	caOutput := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-status", "--",
		"ls", "/usr/local/share/ca-certificates/")
	if !strings.Contains(caOutput, "cainjekt.crt") {
		t.Fatal("CA not injected — hook did not run, cannot verify status file")
	}

	// Hook ran successfully, status file should exist.
	output := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-status", "--",
		"cat", "/etc/cainjekt/status.json")
	t.Logf("Status file:\n%s", output)

	if !strings.Contains(output, `"injected"`) {
		t.Error("Expected status.json to contain injected field")
	}
	if !strings.Contains(output, `"processors"`) {
		t.Error("Expected status.json to contain processors field")
	}

	t.Log("Status file test passed")
}

// ensureHelmRelease installs cainjekt via Helm if not already installed.
func ensureHelmRelease(t *testing.T, clusterName string) {
	t.Helper()

	// Check if already installed and DaemonSet is ready.
	_, err := runCmdWithInput(10*time.Second, "", "helm", "status", "cainjekt-e2e", "-n", "kube-system")
	if err == nil {
		// Wait for DaemonSet to be ready (may have just been installed by another test).
		for i := 0; i < 20; i++ {
			ready, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "daemonset", "cainjekt-e2e",
				"-n", "kube-system", "-o", "jsonpath={.status.numberReady}")
			if strings.TrimSpace(ready) != "" && strings.TrimSpace(ready) != "0" {
				return
			}
			time.Sleep(3 * time.Second)
		}
		return
	}

	// Build and load images.
	runCmd(t, 5*time.Minute, "make", "kind-load", "CLUSTER_NAME="+clusterName)

	caPath := writeTempCABundle(t)
	chartDir := filepath.Join(mustGetProjectRoot(t), "charts", "cainjekt")

	runCmd(t, 2*time.Minute, "helm", "install", "cainjekt-e2e", chartDir,
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
		_ = tryCmd(1*time.Minute, "helm", "uninstall", "cainjekt-e2e", "-n", "kube-system")
	})
}

// waitForPodPhase waits until the named pod reaches the given phase AND all containers are ready.
func waitForPodPhase(t *testing.T, timeout time.Duration, namespace, name, phase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			podYaml, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "pod", name, "-n", namespace, "-o", "yaml")
			t.Logf("Pod YAML:\n%s", podYaml)
			t.Fatalf("timeout waiting for pod %s to reach phase %s", name, phase)
		case <-time.After(3 * time.Second):
			got, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "pod", name, "-n", namespace, "-o", "jsonpath={.status.phase}")
			if strings.TrimSpace(got) != phase {
				continue
			}
			// Phase matches — also check container readiness.
			ready, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "pod", name, "-n", namespace,
				"-o", "jsonpath={.status.containerStatuses[0].ready}")
			if strings.TrimSpace(ready) == "true" {
				return
			}
		}
	}
}
