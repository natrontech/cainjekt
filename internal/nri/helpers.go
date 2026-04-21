package nri

import (
	"encoding/pem"
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

// injectDecision explains why a pod was (or wasn't) selected for injection.
// Source identifies where the opt-in/out signal came from; reason is a short tag
// suitable for a log field. When inject is false but a matching key was examined
// with an unexpected value, value holds that value for diagnostics.
type injectDecision struct {
	inject bool
	source string // pod-annotation | pod-label | namespace-label | default
	reason string // opted-in | explicit-opt-out | not-opted-in
	value  string // observed value when explicit-opt-out
}

// decide checks pod annotations, pod labels, and namespace labels for the opt-in key.
// Pod-level annotation takes highest priority. Then pod labels. Then namespace labels
// (fetched from the Kubernetes API with caching).
func decide(pod *api.PodSandbox, nsCache *nsLabelCache) injectDecision {
	annos := pod.GetAnnotations()
	labels := pod.GetLabels()
	key := config.AnnoEnabled()

	if v, ok := annos[key]; ok {
		return decisionFromValue(v, "pod-annotation")
	}
	if v, ok := labels[key]; ok {
		return decisionFromValue(v, "pod-label")
	}
	if nsCache != nil && pod.GetNamespace() != "" {
		if v, ok := nsCache.getLabel(pod.GetNamespace(), key); ok {
			return decisionFromValue(v, "namespace-label")
		}
	}
	return injectDecision{source: "default", reason: "not-opted-in"}
}

func decisionFromValue(v, source string) injectDecision {
	if strings.EqualFold(v, "true") {
		return injectDecision{inject: true, source: source, reason: "opted-in"}
	}
	return injectDecision{source: source, reason: "explicit-opt-out", value: v}
}

// suspiciousKeys returns keys on the pod/namespace that share the cainjekt
// annotation prefix but are not recognised. These usually indicate a typo in
// the opt-in key (e.g. `.../enable` instead of `.../enabled`).
func suspiciousKeys(pod *api.PodSandbox, nsCache *nsLabelCache) []string {
	prefix := config.AnnotationPrefix() + "/"
	known := map[string]struct{}{
		config.AnnoEnabled():           {},
		config.AnnoExcludeContainers(): {},
		prefix + "processors.include":  {},
		prefix + "processors.exclude":  {},
	}
	seen := map[string]struct{}{}
	collect := func(m map[string]string) {
		for k := range m {
			if !strings.HasPrefix(k, prefix) {
				continue
			}
			if _, ok := known[k]; ok {
				continue
			}
			seen[k] = struct{}{}
		}
	}
	collect(pod.GetAnnotations())
	collect(pod.GetLabels())
	if nsCache != nil && pod.GetNamespace() != "" {
		// Best-effort: reads from cache only. We don't trigger a fetch here.
		if labels, ok := nsCache.getCachedLabels(pod.GetNamespace()); ok {
			collect(labels)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// shortID returns the last 12 characters of a sanitized container id for logging.
func shortID(ctr *api.Container) string {
	id := sanitizePathToken(ctr.GetId())
	if len(id) > 12 {
		return id[len(id)-12:]
	}
	return id
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

// updateCABundleGauges sets the CA bundle mtime and certificate count gauges.
func updateCABundleGauges(m *Metrics, caFilePath string, content []byte) {
	if fi, err := os.Stat(caFilePath); err == nil {
		m.CABundleLastModified.Set(float64(fi.ModTime().Unix()))
	}
	m.CABundleCertCount.Set(float64(pemCertCount(content)))
}

// pemCertCount counts the CERTIFICATE blocks in a PEM bundle.
func pemCertCount(content []byte) int {
	count := 0
	rest := content
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return count
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
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
