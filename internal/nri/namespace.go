package nri

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

// Namespace lookups happen inline in CreateContainer, and NRI gives a plugin
// only api.DefaultPluginRequestTimeout (2s) to answer. Blowing that deadline is
// classed as a *fatal* error by containerd's NRI adaptation — it closes the
// plugin connection, which makes cainjekt exit and stops injection node-wide
// until the DaemonSet pod restarts. So the whole lookup, retries included, has
// to finish well inside 2s. Failing an attempt fast and retrying beats one long
// wait: the common failure on a freshly booted node is a connection error that
// returns in milliseconds while CoreDNS/CNI are still converging, and a retry a
// fraction of a second later usually succeeds.
const (
	nsLookupBudget         = 1200 * time.Millisecond
	nsLookupAttemptTimeout = 300 * time.Millisecond
	nsLookupRetryDelay     = 100 * time.Millisecond
)

// errUnauthorized marks a 401 from the API server. Retrying it is pointless —
// the token is stale and re-reading it is handled by currentToken on the next
// lookup, not by hammering the API within the same one.
var errUnauthorized = errors.New("unauthorized")

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
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
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
	//
	// This is permanent for the process lifetime, and every namespace-label opt-in
	// silently becomes a skip, so it is logged loudly rather than swallowed.
	if _, err := os.ReadFile(cache.tokenPath); err != nil {
		log.Warn("namespace-label opt-in is DISABLED: cannot read service account token; "+
			"only pod annotations/labels will opt pods in",
			"path", cache.tokenPath, "error", err)
		return cache // client stays nil — namespace lookups disabled
	}

	tlsCfg, err := tlsConfigFromServiceAccount()
	if err != nil {
		log.Warn("namespace-label opt-in is DISABLED: cannot build TLS config from the "+
			"service account; only pod annotations/labels will opt pods in", "error", err)
		return cache // client stays nil — namespace lookups disabled
	}

	cache.client = &http.Client{
		Timeout:   nsLookupBudget,
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

// getLabel returns the value of a label on the given namespace.
//
// The three outcomes are deliberately distinguishable, because conflating them
// is what made a busy or not-yet-reachable API server look exactly like a pod
// that never opted in:
//
//	("x", true,  nil) — namespace fetched, label present
//	("",  false, nil) — namespace fetched, label absent (or lookups disabled)
//	("",  false, err) — lookup failed; the caller must NOT read this as opt-out
func (c *nsLabelCache) getLabel(ctx context.Context, namespace, key string) (string, bool, error) {
	if c.client == nil {
		return "", false, nil
	}

	labels, ok := c.getCachedLabels(namespace)
	if !ok {
		var err error
		labels, err = c.fetchLabelsWithRetry(ctx, namespace)
		if err != nil {
			if c.metrics != nil {
				c.metrics.NsLookupErrors.Inc()
			}
			c.log.Warn("namespace label lookup failed; cannot tell whether this pod opted in "+
				"(check service account token expiry, RBAC, and API reachability)",
				"namespace", namespace, "error", err)
			return "", false, err
		}
		c.mu.Lock()
		c.entries[namespace] = nsEntry{labels: labels, fetched: time.Now()}
		c.mu.Unlock()
	}

	v, found := labels[key]
	return v, found, nil
}

// fetchLabelsWithRetry retries fetchLabels inside nsLookupBudget. Only the
// budget bounds it — not an attempt count — so the NRI request deadline is
// respected no matter how the individual attempts fail.
func (c *nsLabelCache) fetchLabelsWithRetry(ctx context.Context, namespace string) (map[string]string, error) {
	deadline := time.Now().Add(nsLookupBudget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	var lastErr error
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, nsLookupAttemptTimeout)
		labels, err := c.fetchLabels(attemptCtx, namespace)
		cancel()
		if err == nil {
			return labels, nil
		}
		lastErr = err

		// A stale token is not fixed by trying again within the same lookup.
		if errors.Is(err, errUnauthorized) {
			return nil, err
		}
		// Stop unless a whole further attempt still fits in the budget.
		if time.Now().Add(nsLookupRetryDelay + nsLookupAttemptTimeout).After(deadline) {
			return nil, fmt.Errorf("after %d attempt(s): %w", attempt, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("after %d attempt(s): %w", attempt, ctx.Err())
		case <-time.After(nsLookupRetryDelay):
		}
	}
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

func (c *nsLabelCache) fetchLabels(ctx context.Context, namespace string) (map[string]string, error) {
	if c.client == nil {
		return nil, fmt.Errorf("K8s API client not available")
	}

	token := c.currentToken()
	if token == "" {
		return nil, fmt.Errorf("no service account token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+namespace, nil)
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
			"(service account token expired or invalid): %w", namespace, errUnauthorized)
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
