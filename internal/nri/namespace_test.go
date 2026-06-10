package nri

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/natrontech/cainjekt/internal/config"
)

// counterValue reads the current value of a Prometheus counter without pulling in
// the testutil helper (and its extra dependency).
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestNSLabelCacheRefreshesRotatedToken reproduces the AKS outage: a bound
// service account token expires after ~1h, the kubelet rotates the file, and the
// cache must pick up the new token instead of 401ing forever. It also asserts the
// failure is surfaced via the NsLookupErrors metric rather than silently skipped.
func TestNSLabelCacheRefreshesRotatedToken(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("old-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the rotated token is accepted, mimicking an expired credential.
		if r.Header.Get("Authorization") != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"metadata":{"labels":{"`+config.AnnoEnabled()+`":"true"}}}`)
	}))
	defer srv.Close()

	m := newMetrics()
	c := &nsLabelCache{
		entries:   map[string]nsEntry{},
		ttl:       time.Minute,
		client:    srv.Client(),
		apiURL:    srv.URL + "/",
		tokenPath: tokenPath,
		tokenTTL:  0, // re-read the token on every lookup
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:   m,
	}

	// Stale token -> 401 -> treated as not opted in, but surfaced via the metric.
	if _, ok := c.getLabel("argocd", config.AnnoEnabled()); ok {
		t.Fatal("expected lookup to fail while the cached token is stale")
	}
	if got := counterValue(t, m.NsLookupErrors); got != 1 {
		t.Fatalf("expected cainjekt_ns_lookup_errors_total=1 after 401, got %v", got)
	}

	// Kubelet rotates the projected token file; the next lookup must pick it up.
	if err := os.WriteFile(tokenPath, []byte("new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, ok := c.getLabel("argocd", config.AnnoEnabled())
	if !ok || v != "true" {
		t.Fatalf("expected opt-in label after token rotation, got value=%q ok=%v", v, ok)
	}
}

// TestNSLabelCacheTokenTTL verifies the token is cached for tokenTTL and not
// re-read from disk on every single call.
func TestNSLabelCacheTokenTTL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &nsLabelCache{tokenPath: tokenPath, tokenTTL: time.Hour}

	if got := c.currentToken(); got != "first" {
		t.Fatalf("expected first token, got %q", got)
	}
	// Rotate the file, but within the TTL the cached value must still be returned.
	if err := os.WriteFile(tokenPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.currentToken(); got != "first" {
		t.Fatalf("expected cached token within TTL, got %q", got)
	}

	// Force expiry: the next read picks up the rotated value.
	c.tokenMu.Lock()
	c.tokenFetched = time.Now().Add(-2 * time.Hour)
	c.tokenMu.Unlock()
	if got := c.currentToken(); got != "second" {
		t.Fatalf("expected refreshed token after TTL, got %q", got)
	}
}
