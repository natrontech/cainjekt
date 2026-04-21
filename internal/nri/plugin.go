// Package nri implements the containerd NRI plugin for CA certificate injection.
package nri

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/natrontech/cainjekt/internal/config"
)

// Plugin implements the NRI stub interface for CA certificate injection.
type Plugin struct {
	stub    stub.Stub
	log     *slog.Logger
	metrics *Metrics
	tracked sync.Map // map[string]struct{} — sanitized container IDs
	nsCache *nsLabelCache
}

// Run starts the NRI plugin, HTTP server, orphan cleaner, and blocks until shutdown.
func Run(log *slog.Logger, args []string) error {
	var (
		pluginName string
		pluginIdx  string
		socketPath string
		httpAddr   string
	)

	fs := flag.NewFlagSet("cainjekt", flag.ContinueOnError)
	fs.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	fs.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	fs.StringVar(&socketPath, "socket", "", "path to the plugin socket")
	fs.StringVar(&httpAddr, "http-addr", ":9443", "address for health/metrics HTTP server")
	if err := fs.Parse(args); err != nil {
		return err
	}

	metrics := newMetrics()
	nsCache := newNSLabelCache()
	p := &Plugin{log: log, metrics: metrics, nsCache: nsCache}

	opts := []stub.Option{stub.WithOnClose(p.onClose)}
	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}
	if socketPath != "" {
		opts = append(opts, stub.WithSocketPath(socketPath))
	}

	// Start HTTP server for health/readiness/metrics (always, even if NRI is unavailable).
	srv := newHTTPServer(httpAddr, metrics)
	go func() {
		log.Info("starting HTTP server", "addr", httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server error", "error", err)
		}
	}()

	// Handle graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	st, err := stub.New(p, opts...)
	if err != nil {
		metrics.NRIAvailable.WithLabelValues(nodeName()).Set(0)
		return fmt.Errorf("NRI not available on this node (containerd may not have NRI enabled, "+
			"e.g. AKS GPU nodes). Either enable NRI in containerd config or exclude this node "+
			"from the cainjekt DaemonSet via nodeSelector/affinity: %w", err)
	}
	metrics.NRIAvailable.WithLabelValues(nodeName()).Set(1)
	p.stub = st

	// Start orphan cleanup goroutine.
	stopCleanup := make(chan struct{})
	cleaner := newOrphanCleaner(dynamicCARoot(), &p.tracked, metrics, log)
	go cleaner.run(stopCleanup)

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.stub.Run(ctx)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, stopping plugin")
		close(stopCleanup)
		_ = srv.Shutdown(context.Background())
		p.stub.Stop()
		return nil
	case err := <-errCh:
		close(stopCleanup)
		_ = srv.Shutdown(context.Background())
		if err != nil {
			return fmt.Errorf("plugin exited: %w", err)
		}
		return nil
	}
}

// PostCreateContainer logs container creation events.
func (p *Plugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.log.Debug("post create container",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"container", ctr.GetName(),
		"container_id", shortID(ctr),
	)
	return nil
}

// CreateContainer intercepts container creation to inject CA certificates.
func (p *Plugin) CreateContainer(
	_ context.Context, pod *api.PodSandbox, ctr *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	cid := shortID(ctr)
	base := []any{
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"container", ctr.GetName(),
		"container_id", cid,
		"runtime_handler", pod.GetRuntimeHandler(),
	}

	p.log.Debug("create container examined",
		append(base,
			"pod_annotations", pod.GetAnnotations(),
			"pod_labels", pod.GetLabels(),
			"opt_in_key", config.AnnoEnabled(),
		)...,
	)

	d := decide(pod, p.nsCache)
	if !d.inject {
		// Flag typos in the cainjekt-prefixed keys — a common cause of silent skips.
		if suspects := suspiciousKeys(pod, p.nsCache); len(suspects) > 0 {
			p.log.Warn("skip: pod has cainjekt-prefixed keys but no recognised opt-in — check for typos",
				append(base, "expected_key", config.AnnoEnabled(), "unrecognised_keys", suspects)...)
		} else if d.reason == "explicit-opt-out" {
			p.log.Info("skip: explicit opt-out",
				append(base, "source", d.source, "value", d.value)...)
		} else {
			p.log.Debug("skip: not opted in", append(base, "source", d.source)...)
		}
		p.metrics.SkippedTotal.Inc()
		return nil, nil, nil
	}

	// Per-container opt-out via annotation.
	if isContainerExcluded(pod, ctr) {
		p.log.Info("skip: container excluded by annotation",
			append(base, "annotation", config.AnnoExcludeContainers())...)
		p.metrics.SkippedTotal.Inc()
		return nil, nil, nil
	}

	p.metrics.InjectionsTotal.Inc()

	// Use env var if set (for DaemonSet deployment), otherwise use os.Executable()
	self := getenvOr(config.EnvPluginBinaryPath, "")
	if self == "" {
		var err error
		self, err = os.Executable()
		if err != nil {
			p.metrics.InjectionsErrors.Inc()
			return nil, nil, fmt.Errorf("failed to determine plugin binary path: %w", err)
		}
	}

	sourceCAFile := getenvOr(config.EnvCAFile, config.DefaultCAFile)
	caFileForHook, caContent, err := stageDynamicCAFile(sourceCAFile, dynamicCARoot(), ctr)
	if err != nil {
		p.log.Error("failed to stage CA file for container",
			append(base, "error", err, "sourceCAFile", sourceCAFile)...)
		_ = cleanupDynamicCAFile(dynamicCARoot(), ctr)
		p.metrics.InjectionsErrors.Inc()
		return nil, nil, err
	}

	// Track container for orphan cleanup.
	key, _ := containerCAKey(ctr)
	if key != "" {
		p.tracked.Store(key, struct{}{})
		p.metrics.ActiveContainers.Inc()
	}

	// Track CA bundle hash for rotation visibility.
	caHash := fmt.Sprintf("%x", sha256.Sum256(caContent))
	p.metrics.CABundleHash.WithLabelValues(caHash[:12]).Inc()

	// Update CA bundle age and cert count gauges.
	updateCABundleGauges(p.metrics, sourceCAFile, caContent)

	p.log.Info("inject: ca bundle staged",
		append(base,
			"source", d.source,
			"ca_hash", caHash[:12],
			"ca_cert_count", pemCertCount(caContent),
			"ca_bytes", len(caContent),
			"dynamic_ca_path", caFileForHook,
		)...,
	)

	hook := &api.Hook{
		Path: self,
		Env: []string{
			config.EnvHookMode + "=" + config.ModeCreateRT,
			config.EnvCAFile + "=" + caFileForHook,
			config.EnvFailPolicy + "=" + config.FailPolicyOpen,
			config.EnvHookContextFile + "=" + config.HookContextFile,
			config.EnvAnnotationPrefix + "=" + config.AnnotationPrefix(),
			config.EnvLogLevel + "=" + getenvOr(config.EnvLogLevel, "info"),
		},
		Timeout: api.Int(hookTimeoutSec()),
	}

	adjustment := &api.ContainerAdjustment{}
	adjustment.AddEnv(config.EnvWrapperMode, "1")
	if !hasEnv(ctr.GetEnv(), config.EnvHookContextFile) {
		adjustment.AddEnv(config.EnvHookContextFile, config.HookContextFile)
	}
	if args := ctr.GetArgs(); len(args) > 0 && args[0] != config.WrapperPath {
		adjustment.UpdateArgs(append([]string{config.WrapperPath}, args...))
	}
	adjustment.AddMount(&api.Mount{
		Destination: config.WrapperPath,
		Type:        "bind",
		Source:      self,
		Options:     []string{"bind", "ro"},
	})
	adjustment.AddHooks(&api.Hooks{CreateRuntime: []*api.Hook{hook}})
	return adjustment, nil, nil
}

// RemoveContainer cleans up per-container dynamic CA files.
func (p *Plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	cid := shortID(ctr)
	base := []any{
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"container", ctr.GetName(),
		"container_id", cid,
	}
	p.log.Debug("removed container", base...)

	// Untrack container.
	key, _ := containerCAKey(ctr)
	if key != "" {
		if _, loaded := p.tracked.LoadAndDelete(key); loaded {
			p.metrics.ActiveContainers.Dec()
		}
	}

	if !decide(pod, p.nsCache).inject {
		return nil
	}
	p.metrics.CleanupsTotal.Inc()
	if err := cleanupDynamicCAFile(dynamicCARoot(), ctr); err != nil {
		p.metrics.CleanupsErrors.Inc()
		p.log.Warn("failed to cleanup dynamic CA bundle", append(base, "error", err)...)
	}
	return nil
}

func (p *Plugin) onClose() {
	p.log.Info("connection to runtime lost")
	os.Exit(1)
}
