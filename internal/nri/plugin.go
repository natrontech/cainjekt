// Package nri implements the containerd NRI plugin for CA certificate injection.
package nri

import (
	"context"
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

	st, err := stub.New(p, opts...)
	if err != nil {
		return fmt.Errorf("failed to create plugin stub: %w", err)
	}
	p.stub = st

	// Start HTTP server for health/readiness/metrics.
	srv := newHTTPServer(httpAddr, metrics)
	go func() {
		log.Info("starting HTTP server", "addr", httpAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server error", "error", err)
		}
	}()

	// Start orphan cleanup goroutine.
	stopCleanup := make(chan struct{})
	cleaner := newOrphanCleaner(dynamicCARoot(), &p.tracked, metrics, log)
	go cleaner.run(stopCleanup)

	// Handle graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

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
	p.log.Info("post create container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())
	return nil
}

// CreateContainer intercepts container creation to inject CA certificates.
func (p *Plugin) CreateContainer(
	_ context.Context, pod *api.PodSandbox, ctr *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	p.log.Info("create container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())

	if !shouldInject(pod, p.nsCache) {
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
	caFileForHook, err := stageDynamicCAFile(sourceCAFile, dynamicCARoot(), ctr)
	if err != nil {
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
		Timeout: api.Int(config.DefaultHookTimeoutSec),
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
	p.log.Info("removed container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())

	// Untrack container.
	key, _ := containerCAKey(ctr)
	if key != "" {
		if _, loaded := p.tracked.LoadAndDelete(key); loaded {
			p.metrics.ActiveContainers.Dec()
		}
	}

	if !shouldInject(pod, p.nsCache) {
		return nil
	}
	p.metrics.CleanupsTotal.Inc()
	if err := cleanupDynamicCAFile(dynamicCARoot(), ctr); err != nil {
		p.metrics.CleanupsErrors.Inc()
		p.log.Warn("failed to cleanup dynamic CA bundle", "error", err)
	}
	return nil
}

func (p *Plugin) onClose() {
	p.log.Info("connection to runtime lost")
	os.Exit(1)
}
