package nri

import (
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/natrontech/cainjekt/internal/config"
)

func newPlugin(log *slog.Logger) *Plugin {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Plugin{log: log, metrics: newMetrics(), nsCache: newNSLabelCache()}
}

// shouldInject checks pod annotations, pod labels, and namespace labels for the opt-in key.
// Pod-level annotation takes highest priority. Then pod labels. Then namespace labels
// (fetched from the Kubernetes API with caching).
func shouldInject(pod *api.PodSandbox, nsCache *nsLabelCache) bool {
	annos := pod.GetAnnotations()
	labels := pod.GetLabels()
	key := config.AnnoEnabled()

	// Pod-level explicit opt-in/out (highest priority).
	if v, ok := annos[key]; ok {
		return strings.EqualFold(v, "true")
	}

	// Pod-level label.
	if v, ok := labels[key]; ok {
		return strings.EqualFold(v, "true")
	}

	// Namespace-level label (fetched from K8s API).
	if nsCache != nil && pod.GetNamespace() != "" {
		if v, ok := nsCache.getLabel(pod.GetNamespace(), key); ok {
			return strings.EqualFold(v, "true")
		}
	}

	return false
}

// isContainerExcluded checks the pod annotation for per-container opt-out.
// Annotation: cainjekt.natron.io/exclude-containers: "istio-proxy,linkerd-proxy"
func isContainerExcluded(pod *api.PodSandbox, ctr *api.Container) bool {
	raw, ok := pod.GetAnnotations()[config.AnnoExcludeContainers()]
	if !ok {
		return false
	}
	name := strings.TrimSpace(ctr.GetName())
	for _, excluded := range strings.Split(raw, ",") {
		if strings.TrimSpace(excluded) == name {
			return true
		}
	}
	return false
}

// hookTimeoutSec returns the configured hook timeout from env or the default.
func hookTimeoutSec() int {
	if v := strings.TrimSpace(os.Getenv(config.EnvHookTimeoutSec)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return config.DefaultHookTimeoutSec
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
