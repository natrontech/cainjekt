package nri

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/tsuzu/cainjekt/internal/config"
	"github.com/tsuzu/cainjekt/pkg/fsx"
)

type Plugin struct {
	stub stub.Stub
	log  *slog.Logger
}

const dynamicCAFileName = "ca-bundle.pem"

var unsafePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func Run(log *slog.Logger, args []string) error {
	var (
		pluginName string
		pluginIdx  string
		socketPath string
	)

	fs := flag.NewFlagSet("cainjekt", flag.ContinueOnError)
	fs.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	fs.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	fs.StringVar(&socketPath, "socket", "", "path to the plugin socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p := newPlugin(log)
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
	if err := p.stub.Run(context.Background()); err != nil {
		return fmt.Errorf("plugin exited: %w", err)
	}
	return nil
}

func (p *Plugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.log.Info("post create container", "namespace", getPodNamespace(pod), "pod", getPodName(pod), "container", getContainerName(ctr))
	return nil
}

func (p *Plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	p.log.Info("create container", "namespace", getPodNamespace(pod), "pod", getPodName(pod), "container", getContainerName(ctr))

	if !shouldInject(pod, ctr) {
		return nil, nil, nil
	}

	self, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine own executable path: %w", err)
	}

	sourceCAFile := getenvOr(config.EnvCAFile, config.DefaultCAFile)
	caFileForHook, err := stageDynamicCAFile(sourceCAFile, dynamicCARoot(), ctr)
	if err != nil {
		return nil, nil, err
	}

	hook := &api.Hook{
		Path: self,
		Env: []string{
			config.EnvHookMode + "=" + config.ModeCreateRT,
			config.EnvCAFile + "=" + caFileForHook,
			config.EnvFailPolicy + "=" + config.FailPolicyOpen,
			config.EnvHookContextFile + "=" + config.HookContextFile,
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

func (p *Plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.log.Info("removed container", "namespace", getPodNamespace(pod), "pod", getPodName(pod), "container", getContainerName(ctr))
	if !shouldInject(pod, ctr) {
		return nil
	}
	if err := cleanupDynamicCAFile(dynamicCARoot(), ctr); err != nil {
		p.log.Warn("failed to cleanup dynamic CA bundle", "error", err)
	}
	return nil
}

func (p *Plugin) onClose() {
	p.log.Info("connection to runtime lost")
	os.Exit(1)
}

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
	if strings.EqualFold(pod.GetAnnotations()[config.AnnoEnabled], "true") {
		return true
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

func stageDynamicCAFile(sourceCAFile, root string, ctr *api.Container) (string, error) {
	content, err := os.ReadFile(sourceCAFile)
	if err != nil {
		return "", fmt.Errorf("failed to read source CA file %s: %w", sourceCAFile, err)
	}

	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create dynamic CA directory %s: %w", targetDir, err)
	}

	targetPath := filepath.Join(targetDir, dynamicCAFileName)
	if err := fsx.AtomicWrite(targetPath, content, fsx.WriteOptions{
		FallbackMode:  0o600,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", fmt.Errorf("failed to write dynamic CA file %s: %w", targetPath, err)
	}

	return targetPath, nil
}

func cleanupDynamicCAFile(root string, ctr *api.Container) error {
	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return err
	}
	err = os.RemoveAll(targetDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove dynamic CA directory %s: %w", targetDir, err)
	}
	return nil
}

func containerCADir(root string, ctr *api.Container) (string, error) {
	key, err := containerCAKey(ctr)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, key), nil
}

func containerCAKey(ctr *api.Container) (string, error) {
	if ctr == nil {
		return "", errors.New("container is nil")
	}
	id := sanitizePathToken(ctr.GetId())
	if id == "" {
		return "", errors.New("container id is empty")
	}
	return id, nil
}

func sanitizePathToken(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return ""
	}
	safe := unsafePathChars.ReplaceAllString(trimmed, "_")
	return strings.Trim(safe, "._-")
}

func dynamicCARoot() string {
	return getenvOr(config.EnvDynamicCARoot, config.DefaultDynamicCARoot)
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
