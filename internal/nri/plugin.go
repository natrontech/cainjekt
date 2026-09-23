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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/natrontech/cainjekt/internal/config"
)

// Plugin implements the NRI stub interface for CA certificate injection.
type Plugin struct {
	stub      stub.Stub
	log       *slog.Logger
	metrics   *Metrics
	tracked   sync.Map // map[string]struct{} — sanitized container IDs
	nsCache   *nsLabelCache
	ready     atomic.Bool    // true once the runtime has synchronised with us
	verifyWG  sync.WaitGroup // tracks in-flight hook-verification goroutines
	stopCh    chan struct{}  // closed on shutdown to abort verification waits
	closeOnce sync.Once
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
	nsCache := newNSLabelCache(log, metrics)
	p := &Plugin{log: log, metrics: metrics, nsCache: nsCache, stopCh: make(chan struct{})}

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
	srv := newHTTPServer(httpAddr, metrics, p.ready.Load)
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
		p.closeOnce.Do(func() { close(p.stopCh) })
		p.verifyWG.Wait()
		_ = srv.Shutdown(context.Background())
		p.stub.Stop()
		return nil
	case err := <-errCh:
		close(stopCleanup)
		p.closeOnce.Do(func() { close(p.stopCh) })
		p.verifyWG.Wait()
		_ = srv.Shutdown(context.Background())
		if err != nil {
			return fmt.Errorf("plugin exited: %w", err)
		}
		return nil
	}
}

// PostCreateContainer logs container creation events. Note: in containerd's
// NRI integration this fires during the CRI Create phase, BEFORE the runtime
// has executed the OCI CreateRuntime hook — so it cannot be used to verify
// the hook ran. Verification happens in PostStartContainer.
func (p *Plugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.log.Debug("post create container",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"container", ctr.GetName(),
		"container_id", shortID(ctr),
	)
	return nil
}

// verifyHookCompletion runs in a goroutine after CreateContainer. It waits up
// to hookTimeoutSec (the deadline at which containerd SIGKILLs the hook),
// then briefly polls for hook.done to absorb any small scheduling lag. If the
// hook didn't finish, it logs a warning and increments HookIncompleteTotal.
//
// We use a timer rather than NRI lifecycle events because NRI's
// PostCreateContainer fires before the runtime has run hooks, and
// PostStartContainer never fires when the hook fails (the container never
// reaches "started"). A timer is the only event source that works for both
// success and failure cases.
func (p *Plugin) verifyHookCompletion(key string, base []any) {
	defer p.verifyWG.Done()

	timeout := time.Duration(hookTimeoutSec()) * time.Second
	select {
	case <-p.stopCh:
		return
	case <-time.After(timeout):
	}

	dir := filepath.Join(dynamicCARoot(), key)
	donePath := filepath.Join(dir, config.BreadcrumbDone)

	// Poll briefly to cover scheduling lag between containerd kicking off the
	// hook and the hook process writing its breadcrumb. 5×100ms is plenty —
	// the hook either wrote hook.done before its deadline or it didn't.
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(donePath); err == nil {
			return // hook completed
		}
		select {
		case <-p.stopCh:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Container may have been removed in the meantime — skip silently.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return
	}

	if _, err := os.Stat(filepath.Join(dir, config.BreadcrumbStarted)); err != nil {
		p.log.Warn("hook did not run for tracked container — "+
			"verify NRI is enabled and the runtime honours OCI CreateRuntime hooks",
			append(base, "timeout_sec", hookTimeoutSec())...)
		p.metrics.HookIncompleteTotal.Inc()
		return
	}

	progress := ""
	if b, err := os.ReadFile(filepath.Join(dir, config.BreadcrumbProgress)); err == nil {
		progress = strings.TrimSpace(string(b))
	}
	p.log.Warn("hook started but did not complete — likely SIGKILLed on timeout; "+
		"bump CAINJEKT_HOOK_TIMEOUT_SEC",
		append(base, "last_progress", progress, "timeout_sec", hookTimeoutSec())...)
	p.metrics.HookIncompleteTotal.Inc()
}

// CreateContainer intercepts container creation to inject CA certificates.
//
// ctx carries NRI's plugin request deadline and is passed down to the namespace
// lookup: overrunning it is a fatal error to containerd, which closes the plugin
// connection and stops injection on the whole node.
func (p *Plugin) CreateContainer(
	ctx context.Context, pod *api.PodSandbox, ctr *api.Container,
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

	d := decide(ctx, pod, p.nsCache)
	if !d.inject {
		suspects := suspiciousKeys(pod, p.nsCache)
		switch {
		// A failed namespace lookup is not an opt-out — we simply could not tell.
		// It is the dominant silent-miss path on a freshly booted node, where the
		// API server is unreachable until CNI/CoreDNS converge, so it gets its own
		// metric and a Warn rather than being buried in cainjekt_skipped_total.
		case d.reason == "lookup-failed":
			p.log.Warn("skip: could not determine opt-in, namespace label lookup failed — "+
				"if this namespace is opted in, the container did NOT get the CA bundle",
				append(base, "error", d.err)...)
			p.metrics.NsLookupSkipped.Inc()
			return nil, nil, nil

		// Flag typos in the cainjekt-prefixed keys — a common cause of silent skips.
		case len(suspects) > 0:
			p.log.Warn("skip: pod has cainjekt-prefixed keys but no recognised opt-in — check for typos",
				append(base, "expected_key", config.AnnoEnabled(), "unrecognised_keys", suspects)...)
		case d.reason == "explicit-opt-out":
			p.log.Info("skip: explicit opt-out",
				append(base, "source", d.source, "value", d.value)...)
		default:
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
			config.EnvBreadcrumbDir + "=" + filepath.Dir(caFileForHook),
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

	if key != "" {
		p.verifyWG.Add(1)
		go p.verifyHookCompletion(key, base)
	}
	return adjustment, nil, nil
}

// RemoveContainer cleans up per-container dynamic CA files.
func (p *Plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
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

	// Cleanup is best-effort and must not depend on the API server being reachable:
	// if we cannot tell whether the pod opted in, remove the staged CA dir anyway
	// rather than leaking it until the orphan cleaner notices.
	if d := decide(ctx, pod, p.nsCache); !d.inject && d.reason != "lookup-failed" {
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
	p.ready.Store(false)
	p.log.Info("connection to runtime lost")
	os.Exit(1)
}

// Synchronize is invoked by the NRI stub once the runtime has finished handshaking
// and is ready to dispatch container lifecycle events. We use this as the signal
// that the plugin is truly ready — before this, the HTTP server is up but NRI
// wouldn't see any CreateContainer calls.
//
// The pods/containers the runtime hands us here are the ones that already existed
// while we were not connected — i.e. exactly the ones we could not inject. We
// cannot fix them (an NRI ContainerUpdate only adjusts resources, not mounts,
// env or hooks), but we can say which they are, which is the difference between
// "CA injection is silently missing" and "restart these pods".
func (p *Plugin) Synchronize(
	_ context.Context, pods []*api.PodSandbox, ctrs []*api.Container,
) ([]*api.ContainerUpdate, error) {
	p.ready.Store(true)
	p.log.Info("runtime synchronised, plugin is ready", "pods", len(pods), "containers", len(ctrs))

	// Off the hot path: this does one API lookup per namespace and must not hold
	// up the handshake that makes us ready for new containers.
	p.verifyWG.Add(1)
	go func() {
		defer p.verifyWG.Done()
		p.reportMissedContainers(pods, ctrs)
	}()

	return nil, nil
}

// reportMissedContainers counts running containers that are opted in but carry no
// hook.done breadcrumb — they were created while the plugin was disconnected
// (node boot, containerd restart, DaemonSet rollout) and never got the CA bundle.
func (p *Plugin) reportMissedContainers(pods []*api.PodSandbox, ctrs []*api.Container) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	byID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		byID[pod.GetId()] = pod
	}

	missed := 0
	for _, ctr := range ctrs {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			p.log.Warn("missed-container scan timed out", "scanned_so_far", missed)
			return
		default:
		}

		if ctr.GetState() != api.ContainerState_CONTAINER_RUNNING {
			continue
		}
		pod, ok := byID[ctr.GetPodSandboxId()]
		if !ok {
			continue
		}
		if !decide(ctx, pod, p.nsCache).inject || isContainerExcluded(pod, ctr) {
			continue
		}

		key, err := containerCAKey(ctr)
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dynamicCARoot(), key, config.BreadcrumbDone)); err == nil {
			continue // we injected this one in a previous life
		}

		missed++
		p.log.Warn("missed injection: container was created while the plugin was not connected — "+
			"it has no CA bundle and needs a restart",
			"namespace", pod.GetNamespace(),
			"pod", pod.GetName(),
			"container", ctr.GetName(),
			"container_id", shortID(ctr),
		)
	}

	p.metrics.MissedContainers.Set(float64(missed))
	if missed > 0 {
		p.log.Warn("missed injection summary: restart these pods to pick up the CA bundle",
			"missed_containers", missed, "running_containers", len(ctrs))
	}
}
