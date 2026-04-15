package nri

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

func newHTTPServer(addr string, metrics *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleReady(&metrics.InjectionsTotal))
	mux.HandleFunc("GET /metrics", handleMetrics(metrics))
	return &http.Server{Addr: addr, Handler: mux}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}

func handleReady(injections *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Ready once we've processed at least one container event (or immediately — plugin is registered).
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ok, injections=%d", injections.Load())
	}
}

func handleMetrics(m *Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_injections_total Total CA injection attempts.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_injections_total counter\n")
		_, _ = fmt.Fprintf(w, "cainjekt_injections_total %d\n", m.InjectionsTotal.Load())

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_injections_errors_total Total CA injection errors.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_injections_errors_total counter\n")
		_, _ = fmt.Fprintf(w, "cainjekt_injections_errors_total %d\n", m.InjectionsErrors.Load())

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_skipped_total Containers skipped (no annotation).\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_skipped_total counter\n")
		_, _ = fmt.Fprintf(w, "cainjekt_skipped_total %d\n", m.SkippedTotal.Load())

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_cleanups_total Total dynamic CA cleanups.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_cleanups_total counter\n")
		_, _ = fmt.Fprintf(w, "cainjekt_cleanups_total %d\n", m.CleanupsTotal.Load())

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_cleanups_errors_total Cleanup errors.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_cleanups_errors_total counter\n")
		_, _ = fmt.Fprintf(w, "cainjekt_cleanups_errors_total %d\n", m.CleanupsErrors.Load())

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_orphans_cleaned_total Orphaned CA dirs cleaned up.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_orphans_cleaned_total counter\n")
		_, _ = fmt.Fprintf(w, "cainjekt_orphans_cleaned_total %d\n", m.OrphansCleaned.Load())

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_active_containers Currently tracked containers.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_active_containers gauge\n")
		_, _ = fmt.Fprintf(w, "cainjekt_active_containers %d\n", m.ActiveContainers.Load())

		detected, applied := m.ProcessorStats()
		_, _ = fmt.Fprintf(w, "# HELP cainjekt_processor_detected_total Times a processor was detected as applicable.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_processor_detected_total counter\n")
		for name, count := range detected {
			_, _ = fmt.Fprintf(w, "cainjekt_processor_detected_total{processor=%q} %d\n", name, count)
		}

		_, _ = fmt.Fprintf(w, "# HELP cainjekt_processor_applied_total Times a processor was successfully applied.\n")
		_, _ = fmt.Fprintf(w, "# TYPE cainjekt_processor_applied_total counter\n")
		for name, count := range applied {
			_, _ = fmt.Fprintf(w, "cainjekt_processor_applied_total{processor=%q} %d\n", name, count)
		}
	}
}
