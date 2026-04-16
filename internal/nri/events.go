package nri

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// emitNodeEvent creates a Kubernetes Event on the current node.
// Best-effort: failures are logged but don't block the caller.
func emitNodeEvent(log *slog.Logger, reason, message, eventType string) {
	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	namespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	podName := strings.TrimSpace(os.Getenv("POD_NAME"))

	if nodeName == "" {
		log.Debug("NODE_NAME not set, skipping event emission")
		return
	}
	if namespace == "" {
		namespace = "kube-system"
	}

	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Debug("no service account token, skipping event", "error", err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventName := fmt.Sprintf("cainjekt-%s-%d", reason, time.Now().UnixNano())

	event := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata": map[string]interface{}{
			"name":      eventName,
			"namespace": namespace,
		},
		"involvedObject": map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Node",
			"name":       nodeName,
		},
		"reason":  reason,
		"message": message,
		"type":    eventType,
		"source": map[string]interface{}{
			"component": "cainjekt",
			"host":      nodeName,
		},
		"firstTimestamp": now,
		"lastTimestamp":  now,
		"count":          1,
	}

	// Include reporting pod if available.
	if podName != "" {
		event["reportingComponent"] = "cainjekt"
		event["reportingInstance"] = podName
	}

	body, err := json.Marshal(event)
	if err != nil {
		log.Debug("failed to marshal event", "error", err)
		return
	}

	apiURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/events", namespace)
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		log.Debug("failed to create event request", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: eventTLSConfig()},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("failed to emit event", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		log.Debug("event API returned error", "status", resp.StatusCode)
	} else {
		log.Info("emitted Kubernetes event", "reason", reason, "node", nodeName)
	}
}

func eventTLSConfig() *tls.Config {
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
