package nri

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/tsuzu/cainjekt/internal/config"
)

func newPlugin(log *slog.Logger) *Plugin {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Plugin{log: log}
}

func shouldInject(pod *api.PodSandbox, ctr *api.Container) bool {
	if pod == nil || ctr == nil {
		return false
	}
	return strings.EqualFold(pod.GetAnnotations()[config.AnnoEnabled], "true")
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

func getPodNamespace(pod *api.PodSandbox) string {
	if pod == nil {
		return ""
	}
	return pod.GetNamespace()
}

func getPodName(pod *api.PodSandbox) string {
	if pod == nil {
		return ""
	}
	return pod.GetName()
}

func getContainerName(ctr *api.Container) string {
	if ctr == nil {
		return ""
	}
	return ctr.GetName()
}
