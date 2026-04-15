package nri

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/natrontech/cainjekt/internal/config"
)

func newPlugin(log *slog.Logger) *Plugin {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Plugin{log: log, metrics: newMetrics()}
}

// shouldInject checks pod and namespace annotations for the opt-in annotation.
// Pod-level annotation takes precedence. If not set, falls back to namespace label
// (passed as annotation by NRI: io.kubernetes.pod.namespace).
func shouldInject(pod *api.PodSandbox) bool {
	annos := pod.GetAnnotations()
	labels := pod.GetLabels()

	// Pod-level explicit opt-in/out (highest priority).
	if v, ok := annos[config.AnnoEnabled()]; ok {
		return strings.EqualFold(v, "true")
	}

	// Namespace-level opt-in via pod label (set by namespace label propagation or policy).
	if v, ok := labels[config.AnnoEnabled()]; ok {
		return strings.EqualFold(v, "true")
	}

	return false
}

func hasEnv(env []string, key string) bool {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
