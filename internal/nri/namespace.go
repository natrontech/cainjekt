package nri

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// nsLabelCache caches namespace labels with a TTL to avoid excessive API calls.
type nsLabelCache struct {
	mu      sync.RWMutex
	entries map[string]nsEntry
	ttl     time.Duration
	client  *http.Client // nil if K8s API is not available
	apiURL  string

	// Service account token handling. The token is re-read from tokenPath (with a
	// short TTL) rather than cached for the process lifetime. The kubelet rotates
	// the projected token file before expiry, and bound tokens can expire in as
	// little as one hour — reading it once at startup makes namespace-label opt-in
	// silently fail after the first expiry (the lookup 401s and the pod is treated
	// as not opted in). See [[sa-token-not-refreshed-bug]].
	tokenMu      sync.Mutex
	tokenPath    string
	tokenTTL     time.Duration
	token        string
	tokenFetched time.Time

	log     *slog.Logger
	metrics *Metrics
}

type nsEntry struct {
	labels  map[string]string
	fetched time.Time
}

func newNSLabelCache(log *slog.Logger, metrics *Metrics) *nsLabelCache {
	cache := &nsLabelCache{
		entries:   map[string]nsEntry{},
		ttl:       1 * time.Minute,
		apiURL:    "https://kubernetes.default.svc/api/v1/namespaces/",
		tokenPath: defaultTokenPath,
		tokenTTL:  30 * time.Second,
		log:       log,
		metrics:   metrics,
	}

	// Require the token to exist at startup; if it does not, the API client stays
	// nil and namespace-label lookups are disabled (pods can still opt in via pod
	// annotation/label). The token value itself is read fresh on use, not cached.
	if _, err := os.ReadFile(cache.tokenPath); err != nil {
		return cache // client stays nil — namespace lookups disabled
	}

	tlsCfg, err := tlsConfigFromServiceAccount()
	if err != nil {
		return cache // client stays nil — namespace lookups disabled
	}

	cache.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return cache
}

// currentToken returns the service account token, re-reading it from disk when the
// cached copy is older than tokenTTL. The kubelet keeps the file current; on a
// transient read failure (e.g. mid-rotation) we keep using the last-known token.
func (c *nsLabelCache) currentToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.token != "" && time.Since(c.tokenFetched) < c.tokenTTL {
		return c.token
	}

	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		if c.token == "" && c.log != nil {
			c.log.Warn("failed to read service account token", "path", c.tokenPath, "error", err)
		}
		return c.token // best effort: keep using the last-known token
	}

	c.token = strings.TrimSpace(string(b))
	c.tokenFetched = time.Now()
	return c.token
}

// getLabel returns the value of a label on the given namespace. A failed lookup
// (expired token, API unreachable) is surfaced via a Warn log and the
// NsLookupErrors metric rather than silently masquerading as "not opted in".
func (c *nsLabelCache) getLabel(namespace, key string) (string, bool) {
	if c.client == nil {
		return "", false
	}

	labels, ok := c.getCachedLabels(namespace)
	if !ok {
		var err error
		labels, err = c.fetchLabels(namespace)
		if err != nil {
			if c.metrics != nil {
				c.metrics.NsLookupErrors.Inc()
			}
			if c.log != nil {
				c.log.Warn("namespace label lookup failed; treating pod as not opted in "+
					"(check service account token expiry, RBAC, and API reachability)",
					"namespace", namespace, "error", err)
			}
			return "", false
		}
		c.mu.Lock()
		c.entries[namespace] = nsEntry{labels: labels, fetched: time.Now()}
		c.mu.Unlock()
	}

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
	if c.client == nil {
		return nil, fmt.Errorf("K8s API client not available")
	}

	token := c.currentToken()
	if token == "" {
		return nil, fmt.Errorf("no service account token")
	}

	req, err := http.NewRequest("GET", c.apiURL+namespace, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("API returned 401 for namespace %s "+
			"(service account token expired or invalid)", namespace)
	}
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

func tlsConfigFromServiceAccount() (*tls.Config, error) {
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read SA CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
