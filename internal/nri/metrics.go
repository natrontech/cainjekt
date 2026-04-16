package nri

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds all Prometheus metrics for cainjekt.
type Metrics struct {
	Registry             *prometheus.Registry
	InjectionsTotal      prometheus.Counter
	InjectionsErrors     prometheus.Counter
	SkippedTotal         prometheus.Counter
	CleanupsTotal        prometheus.Counter
	CleanupsErrors       prometheus.Counter
	OrphansCleaned       prometheus.Counter
	ActiveContainers     prometheus.Gauge
	ProcessorDetected    *prometheus.CounterVec
	ProcessorApplied     *prometheus.CounterVec
	CABundleHash         *prometheus.CounterVec
	CABundleLastModified prometheus.Gauge
	CABundleCertCount    prometheus.Gauge
	NRIAvailable         prometheus.Gauge
}

func newMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())

	m := &Metrics{
		Registry: reg,
		InjectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_injections_total",
			Help: "Total CA injection attempts.",
		}),
		InjectionsErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_injections_errors_total",
			Help: "Total CA injection errors.",
		}),
		SkippedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_skipped_total",
			Help: "Containers skipped (no opt-in annotation).",
		}),
		CleanupsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_cleanups_total",
			Help: "Total dynamic CA cleanups on container removal.",
		}),
		CleanupsErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_cleanups_errors_total",
			Help: "Total cleanup errors.",
		}),
		OrphansCleaned: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_orphans_cleaned_total",
			Help: "Orphaned CA directories cleaned up.",
		}),
		ActiveContainers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_active_containers",
			Help: "Currently tracked containers with CA injection.",
		}),
		ProcessorDetected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cainjekt_processor_detected_total",
			Help: "Times a processor was detected as applicable.",
		}, []string{"processor"}),
		ProcessorApplied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cainjekt_processor_applied_total",
			Help: "Times a processor was successfully applied.",
		}, []string{"processor"}),
		CABundleHash: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cainjekt_ca_bundle_injections_total",
			Help: "Injections per CA bundle hash (first 12 chars of SHA-256). Helps detect stale CAs after rotation.",
		}, []string{"hash"}),
		CABundleLastModified: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_ca_bundle_last_modified_timestamp",
			Help: "Unix timestamp of the CA bundle file's last modification time.",
		}),
		CABundleCertCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_ca_bundle_certificates_count",
			Help: "Number of PEM certificates in the CA bundle.",
		}),
		NRIAvailable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_nri_available",
			Help: "Whether NRI is available on this node (1=yes, 0=no).",
		}),
	}

	reg.MustRegister(
		m.InjectionsTotal,
		m.InjectionsErrors,
		m.SkippedTotal,
		m.CleanupsTotal,
		m.CleanupsErrors,
		m.OrphansCleaned,
		m.ActiveContainers,
		m.ProcessorDetected,
		m.ProcessorApplied,
		m.CABundleHash,
		m.CABundleLastModified,
		m.CABundleCertCount,
		m.NRIAvailable,
	)

	return m
}
