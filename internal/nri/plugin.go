package nri

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/tsuzu/cainjekt/internal/config"
)

type Plugin struct {
	stub stub.Stub
	log  *slog.Logger
}

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
	p.log.Info("post create container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())
	return nil
}

func (p *Plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	p.log.Info("create container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())

	if !shouldInject(pod) {
		return nil, nil, nil
	}

	self, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine own executable path: %w", err)
	}

	sourceCAFile := getenvOr(config.EnvCAFile, config.DefaultCAFile)
	caFileForHook, err := stageDynamicCAFile(sourceCAFile, dynamicCARoot(), ctr)
	if err != nil {
		_ = cleanupDynamicCAFile(dynamicCARoot(), ctr)
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
	p.log.Info("removed container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())
	if !shouldInject(pod) {
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
