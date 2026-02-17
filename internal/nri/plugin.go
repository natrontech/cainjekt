package nri

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

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

	p := &Plugin{log: log}
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

	if !shouldInject(pod, ctr) {
		return nil, nil, nil
	}

	self, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine own executable path: %w", err)
	}

	mode := strings.ToLower(strings.TrimSpace(pod.GetAnnotations()[config.AnnoMode]))
	if mode == "" {
		mode = config.DefaultMode
	}
	if mode == "off" {
		return nil, nil, nil
	}

	hook := &api.Hook{
		Path: self,
		Env: []string{
			config.EnvHookMode + "=" + config.ModeCreateRT,
			config.EnvCAFile + "=" + config.DefaultCAFile,
			config.EnvFailPolicy + "=" + config.FailPolicyOpen,
		},
		Timeout: api.Int(config.DefaultHookTimeoutSec),
	}

	adjustment := &api.ContainerAdjustment{}
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
	return nil
}

func (p *Plugin) onClose() {
	p.log.Info("connection to runtime lost")
	os.Exit(1)
}

func shouldInject(pod *api.PodSandbox, ctr *api.Container) bool {
	if strings.EqualFold(pod.GetAnnotations()[config.AnnoDisable], "true") {
		return false
	}
	if strings.EqualFold(ctr.GetLabels()[config.AnnoDisable], "true") {
		return false
	}
	if strings.EqualFold(pod.GetAnnotations()[config.AnnoMode], "off") {
		return false
	}
	enabled := strings.ToLower(strings.TrimSpace(pod.GetLabels()[config.LabelEnabled]))
	if enabled == "false" {
		return false
	}
	return true
}
