//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TODO: This is mostly a copy of TestKindIntegration_NodeFetchWithInjectedCA, but using Python requests instead of curl. We should probably refactor to share more code between these tests, and add more client languages as well.
func TestKindIntegration_PythonRequestsWithInjectedCA(t *testing.T) {
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

	ns := fmt.Sprintf("cainjekt-python-e2e-%d", time.Now().UnixNano())
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
	image := buildClientImageAndLoadToKind(t, clusterName, "python:3.12-alpine", "pip install --no-cache-dir requests")
	requestCmd := pythonRequestsCommand(serviceURL)

	injectedName := "python-requests-injected"
	injectedPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  annotations:
    cainjekt.natron.io/enabled: "true"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: %s
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -lc
    - |
      %s
      sleep 600
`, injectedName, ns, image, requestCmd)
	runCmdInput(t, 30*time.Second, injectedPod, "kubectl", "apply", "-f", "-")
	waitForPodReady(t, 2*time.Minute, ns, injectedName, "120s")

	plainName := "python-requests-plain"
	plainPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  annotations:
    cainjekt.natron.io/enabled: "false"
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: %s
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -lc
    - |
      if %s; then
        echo "unexpected success" >&2
        exit 1
      fi
      sleep 600
`, plainName, ns, image, requestCmd)
	runCmdInput(t, 30*time.Second, plainPod, "kubectl", "apply", "-f", "-")
	waitForPodReady(t, 2*time.Minute, ns, plainName, "120s")
}

func pythonRequestsCommand(url string) string {
	script := `import requests,sys;` +
		`r=requests.get(sys.argv[1],timeout=10);` +
		`r.raise_for_status();` +
		`body=r.text.strip();` +
		`assert body=="ok","body:"+body`
	return fmt.Sprintf("python -c %q %q", script, url)
}
