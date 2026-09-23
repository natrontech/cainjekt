package nri

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/natrontech/cainjekt/internal/config"
)

// newTestCache wires a cache against a test server with a readable token.
func newTestCache(t *testing.T, url string, client *http.Client) *nsLabelCache {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &nsLabelCache{
		entries:   map[string]nsEntry{},
		ttl:       time.Minute,
		client:    client,
		apiURL:    url + "/",
		tokenPath: tokenPath,
		tokenTTL:  time.Hour,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:   newMetrics(),
	}
}

// TestNSLookupRetriesTransientFailure covers the freshly-booted-node case: the
// API server is briefly unreachable while CNI/CoreDNS converge, then works. The
// lookup must retry rather than report "not opted in".
func TestNSLookupRetriesTransientFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			// Simulate a connection-level failure without a usable response.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"metadata":{"labels":{"` + config.AnnoEnabled() + `":"true"}}}`))
	}))
	defer srv.Close()

	c := newTestCache(t, srv.URL, srv.Client())

	v, ok, err := c.getLabel(context.Background(), "argocd", config.AnnoEnabled())
	if err != nil {
		t.Fatalf("expected the retry to succeed, got error: %v", err)
	}
	if !ok || v != "true" {
		t.Fatalf("expected opt-in label after retry, got value=%q ok=%v", v, ok)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", got)
	}
}

// TestNSLookupRespectsNRIDeadline is the important one. CreateContainer runs
// inside NRI's request timeout (api.DefaultPluginRequestTimeout, 2s) and
// overrunning it is FATAL: containerd closes the plugin connection, cainjekt
// exits, and injection stops node-wide. A hung API server must therefore never
// keep the lookup past that budget.
func TestNSLookupRespectsNRIDeadline(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	}))
	defer srv.Close()

	c := newTestCache(t, srv.URL, srv.Client())

	start := time.Now()
	_, ok, err := c.getLabel(context.Background(), "argocd", config.AnnoEnabled())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a hung API server")
	}
	if ok {
		t.Fatal("expected no label from a hung API server")
	}
	if elapsed >= api.DefaultPluginRequestTimeout {
		t.Fatalf("lookup took %v, which meets or exceeds NRI's %v request timeout — "+
			"containerd would close the plugin connection",
			elapsed, api.DefaultPluginRequestTimeout)
	}
}

// TestDecideFailedLookupIsNotOptOut is the behavioural contract behind the fix:
// a lookup that fails must be reported as "lookup-failed", never silently folded
// into "not-opted-in", which is what made opted-in pods vanish without a trace.
func TestDecideFailedLookupIsNotOptOut(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestCache(t, srv.URL, srv.Client())
	pod := &api.PodSandbox{Name: "app", Namespace: "argocd"}

	d := decide(context.Background(), pod, c)
	if d.inject {
		t.Fatal("a failed lookup must not opt a pod in")
	}
	if d.reason != "lookup-failed" {
		t.Fatalf("expected reason %q so the skip is reported, got %q", "lookup-failed", d.reason)
	}
	if d.err == nil {
		t.Fatal("expected the underlying lookup error to be carried for logging")
	}
}

// TestDecodePodOptInSkipsAPI guards the hot path: a pod that opts in via its own
// annotation must not touch the API server at all, so a broken control plane
// cannot affect it.
func TestDecodePodOptInSkipsAPI(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestCache(t, srv.URL, srv.Client())
	pod := &api.PodSandbox{
		Name:        "app",
		Namespace:   "argocd",
		Annotations: map[string]string{config.AnnoEnabled(): "true"},
	}

	if d := decide(context.Background(), pod, c); !d.inject {
		t.Fatalf("expected pod-annotation opt-in, got reason=%q", d.reason)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("pod-annotation opt-in must not call the API server, got %d calls", got)
	}
}
