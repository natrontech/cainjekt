package nri

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// nsLabelCache caches namespace labels with a TTL to avoid excessive API calls.
type nsLabelCache struct {
	mu      sync.RWMutex
	entries map[string]nsEntry
	ttl     time.Duration
	client  *http.Client
	token   string
	apiURL  string
}

type nsEntry struct {
	labels  map[string]string
	fetched time.Time
}

func newNSLabelCache() *nsLabelCache {
	token, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return &nsLabelCache{
		entries: map[string]nsEntry{},
		ttl:     1 * time.Minute,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfigFromServiceAccount(),
			},
		},
		token:  strings.TrimSpace(string(token)),
		apiURL: "https://kubernetes.default.svc/api/v1/namespaces/",
	}
}

// getLabel returns the value of a label on the given namespace.
func (c *nsLabelCache) getLabel(namespace, key string) (string, bool) {
	labels, ok := c.getCachedLabels(namespace)
	if ok {
		v, found := labels[key]
		return v, found
	}

	labels, err := c.fetchLabels(namespace)
	if err != nil {
		return "", false
	}

	c.mu.Lock()
	c.entries[namespace] = nsEntry{labels: labels, fetched: time.Now()}
	c.mu.Unlock()

	v, found := labels[key]
	return v, found
}

func (c *nsLabelCache) getCachedLabels(namespace string) (map[string]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[namespace]
	if !ok || time.Since(entry.fetched) > c.ttl {
		return nil, false
	}
	return entry.labels, true
}

func (c *nsLabelCache) fetchLabels(namespace string) (map[string]string, error) {
	if c.token == "" {
		return nil, fmt.Errorf("no service account token")
	}

	req, err := http.NewRequest("GET", c.apiURL+namespace, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d for namespace %s", resp.StatusCode, namespace)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ns struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &ns); err != nil {
		return nil, err
	}

	return ns.Metadata.Labels, nil
}

func tlsConfigFromServiceAccount() *tls.Config {
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // fallback when SA not mounted
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
