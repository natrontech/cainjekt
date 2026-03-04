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

func TestManifestDeploy_KustomizeE2E(t *testing.T) {
	if getenvOr("CAINJEKT_E2E_MANIFEST", "0") != "1" {
		t.Skip("set CAINJEKT_E2E_MANIFEST=1 to run manifest deployment E2E test")
	}

	clusterName := getenvOr("CAINJEKT_CLUSTER_NAME", "cainjekt-test-cluster")

	requireCommand(t, "make")
	requireCommand(t, "kind")
	requireCommand(t, "kubectl")
	requireCommand(t, "docker")
	requireDockerAccess(t)

	// Ensure cluster exists
	node := strings.TrimSpace(runCmd(t, 30*time.Second, "kind", "get", "nodes", "--name="+clusterName))
	if node == "" {
		t.Fatalf("could not determine kind node for cluster %q", clusterName)
	}

	// Build and load image to kind
	t.Log("Building Docker image and loading to kind cluster...")
	runCmd(t, 5*time.Minute, "make", "kind-load", "CLUSTER_NAME="+clusterName)

	// Create test CA bundle
	caPath := writeTestCABundle(t)
	t.Cleanup(func() {
		_ = os.Remove(caPath)
	})

	// Create ConfigMap with CA bundle
	t.Log("Creating ConfigMap with CA bundle...")
	runCmd(t, 30*time.Second, "kubectl", "create", "configmap", "cainjekt-ca-bundle",
		"--from-file=ca-bundle.pem="+caPath,
		"--namespace=kube-system",
		"--dry-run=client", "-o", "yaml")

	// Apply ConfigMap
	runCmd(t, 30*time.Second, "kubectl", "create", "configmap", "cainjekt-ca-bundle",
		"--from-file=ca-bundle.pem="+caPath,
		"--namespace=kube-system")
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "kubectl", "delete", "configmap", "cainjekt-ca-bundle", "-n", "kube-system")
	})

	// Deploy using kustomize with local image
	t.Log("Deploying cainjekt using kustomize...")
	manifestDir := filepath.Join(mustGetProjectRoot(t), "deploy", "kubernetes")

	// Create a temporary kustomization that uses the local image
	tmpKustomizeDir := t.TempDir()
	runCmd(t, 30*time.Second, "cp", "-r", manifestDir+"/.", tmpKustomizeDir)

	// Update kustomization to use local image
	kustomizationContent := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: kube-system

resources:
- rbac.yaml
- daemonset.yaml

images:
- name: cainjekt
  newName: cainjekt
  newTag: latest
`
	if err := os.WriteFile(filepath.Join(tmpKustomizeDir, "kustomization.yaml"), []byte(kustomizationContent), 0644); err != nil {
		t.Fatalf("failed to write kustomization.yaml: %v", err)
	}

	runCmd(t, 1*time.Minute, "kubectl", "apply", "-k", tmpKustomizeDir)
	manifestDir = tmpKustomizeDir

	t.Cleanup(func() {
		t.Log("Cleaning up cainjekt deployment...")
		_ = tryCmd(1*time.Minute, "kubectl", "delete", "-k", manifestDir)
	})

	// Wait for DaemonSet to be ready
	t.Log("Waiting for DaemonSet to be ready...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// First check: verify DaemonSet exists and get initial status
	dsStatus, _ := runCmdWithInput(30*time.Second, "", "kubectl", "get", "daemonset", "cainjekt", "-n", "kube-system", "-o", "yaml")
	t.Logf("Initial DaemonSet status:\n%s", dsStatus)

	// Get pod status for debugging
	podList, _ := runCmdWithInput(30*time.Second, "", "kubectl", "get", "pods", "-n", "kube-system", "-l", "app=cainjekt", "-o", "wide")
	t.Logf("Pods status:\n%s", podList)

	for {
		select {
		case <-ctx.Done():
			// Final debug info before failing
			t.Log("Timeout reached. Gathering debug information...")
			podDesc, _ := runCmdWithInput(30*time.Second, "", "kubectl", "describe", "pods", "-n", "kube-system", "-l", "app=cainjekt")
			t.Logf("Pod description:\n%s", podDesc)

			podLogs, _ := runCmdWithInput(30*time.Second, "", "kubectl", "logs", "-n", "kube-system", "-l", "app=cainjekt", "--tail=100", "--all-containers=true")
			t.Logf("Pod logs:\n%s", podLogs)

			t.Fatal("timeout waiting for DaemonSet to be ready")
		case <-time.After(5 * time.Second):
			out, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "daemonset", "cainjekt", "-n", "kube-system", "-o", "jsonpath={.status.numberReady}")
			if strings.TrimSpace(out) == "1" {
				t.Log("DaemonSet is ready")
				goto ready
			}

			// Show more detailed status every 30 seconds
			if time.Now().Unix()%30 == 0 {
				podStatus, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "pods", "-n", "kube-system", "-l", "app=cainjekt")
				t.Logf("Current pod status:\n%s", podStatus)
			}

			t.Logf("Waiting for DaemonSet... (numberReady=%s)", strings.TrimSpace(out))
		}
	}

ready:
	// Get pod name
	podName := strings.TrimSpace(runCmd(t, 30*time.Second, "kubectl", "get", "pods", "-n", "kube-system", "-l", "app=cainjekt", "-o", "jsonpath={.items[0].metadata.name}"))
	if podName == "" {
		t.Fatal("could not find cainjekt pod")
	}
	t.Logf("Found cainjekt pod: %s", podName)

	// Check pod logs
	t.Log("Checking pod logs...")
	logs := runCmd(t, 30*time.Second, "kubectl", "logs", "-n", "kube-system", podName, "--tail=50")
	t.Logf("Pod logs:\n%s", logs)

	// Create test namespace
	ns := fmt.Sprintf("cainjekt-manifest-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = tryCmd(30*time.Second, "kubectl", "delete", "ns", ns, "--wait=true")
	})
	runCmd(t, 30*time.Second, "kubectl", "create", "ns", ns)
	waitForDefaultServiceAccount(t, ns)

	// Deploy test pod with CA injection enabled
	t.Log("Deploying test pod with CA injection annotation...")
	testPodManifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: test-ca-injection
  namespace: %s
  annotations:
    cainjekt.io/enabled: "true"
spec:
  restartPolicy: Never
  containers:
  - name: ubuntu
    image: ubuntu:22.04
    command: ["sleep", "3600"]
`, ns)

	tmpManifest := filepath.Join(t.TempDir(), "test-pod.yaml")
	if err := os.WriteFile(tmpManifest, []byte(testPodManifest), 0644); err != nil {
		t.Fatalf("failed to write test pod manifest: %v", err)
	}

	runCmd(t, 30*time.Second, "kubectl", "apply", "-f", tmpManifest)

	// Wait for pod to be running
	t.Log("Waiting for test pod to be running...")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel2()

	for {
		select {
		case <-ctx2.Done():
			t.Fatal("timeout waiting for test pod to be running")
		case <-time.After(3 * time.Second):
			phase, _ := runCmdWithInput(10*time.Second, "", "kubectl", "get", "pod", "test-ca-injection", "-n", ns, "-o", "jsonpath={.status.phase}")
			if strings.TrimSpace(phase) == "Running" {
				t.Log("Test pod is running")
				goto podReady
			}
			t.Logf("Waiting for test pod... (phase=%s)", strings.TrimSpace(phase))
		}
	}

podReady:
	// Verify CA was injected
	t.Log("Verifying CA certificate was injected...")

	// Check if trust store exists
	output := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-ca-injection", "--",
		"ls", "-la", "/etc/ssl/certs/ca-certificates.crt")
	t.Logf("Trust store check:\n%s", output)

	// Check if individual CA file exists (Debian/Ubuntu specific)
	output2 := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-ca-injection", "--",
		"ls", "-la", "/usr/local/share/ca-certificates/")
	t.Logf("CA certificates directory:\n%s", output2)

	if !strings.Contains(output2, "cainjekt.crt") {
		t.Error("Expected to find cainjekt.crt in /usr/local/share/ca-certificates/")
	}

	// Verify the CA is in the trust store
	output3 := runCmd(t, 30*time.Second, "kubectl", "exec", "-n", ns, "test-ca-injection", "--",
		"cat", "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(output3, "BEGIN CERTIFICATE") {
		t.Error("Expected to find certificates in trust store")
	}

	t.Log("✅ E2E test passed: CA injection via manifest deployment works!")
}

func writeTestCABundle(t *testing.T) string {
	t.Helper()

	// Reuse the existing function from kind_test.go
	return writeTempCABundle(t)
}

func mustGetProjectRoot(t *testing.T) string {
	t.Helper()

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}

	// integration tests run from integration directory, go up one level
	if filepath.Base(cwd) == "integration" {
		return filepath.Dir(cwd)
	}

	return cwd
}
