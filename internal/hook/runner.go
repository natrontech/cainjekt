package hook

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/tsuzu/cainjekt/internal/config"
	hookapi "github.com/tsuzu/cainjekt/internal/hook/api"
	"github.com/tsuzu/cainjekt/internal/hook/oci"
	"github.com/tsuzu/cainjekt/internal/hook/processors"
	"github.com/tsuzu/cainjekt/pkg/fsx"
)

func Run(log *slog.Logger) error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(config.EnvHookMode)))
	if mode != config.ModeCreateRT && mode != config.ModeCreateCtr {
		return fmt.Errorf("unknown hook mode: %q", mode)
	}

	state, err := oci.ReadState(os.Stdin)
	if err != nil {
		return err
	}

	specPath, spec, err := oci.LoadSpec(state.Bundle)
	if err != nil {
		return err
	}

	ctx := &hookapi.Context{
		Mode:        mode,
		Bundle:      state.Bundle,
		Annotations: state.Annotations,
		Rootfs:      oci.ResolveRootfsPath(state.Bundle, spec),
		SpecPath:    specPath,
		Spec:        spec,
		CAFile:      getenvOr(config.EnvCAFile, config.DefaultCAFile),
		FailPolicy:  getenvOr(config.EnvFailPolicy, config.FailPolicyOpen),
		Facts:       hookapi.NewMapFactStore(),
	}

	all := processors.Default()
	include := processors.ParseCSV(ctx.Annotations[config.AnnoProcessorsInclude])
	exclude := processors.ParseCSV(ctx.Annotations[config.AnnoProcessorsExclude])
	filtered := processors.FilterByNames(all, include, exclude)

	runOSStage(ctx, processors.ForStage(filtered, hookapi.StageOS))
	runLanguageStage(ctx, processors.ForStage(filtered, hookapi.StageLanguage))

	if ctx.SpecChanged {
		specBytes, err := oci.SaveSpec(ctx.SpecPath, ctx.Spec)
		if err != nil {
			return err
		}
		if err := fsx.AtomicWrite(ctx.SpecPath, specBytes, fsx.WriteOptions{
			FallbackMode:  0o644,
			RefuseSymlink: true,
			PreserveOwner: true,
		}); err != nil {
			return fmt.Errorf("failed to write updated OCI spec: %w", err)
		}
	}

	for _, r := range ctx.Results {
		log.Info("processor result",
			"name", r.Name,
			"stage", r.Stage,
			"applied", r.Applied,
			"skipped", r.Skipped,
			"reason", r.Reason,
			"error", r.Err,
		)
	}

	return nil
}

func runOSStage(ctx *hookapi.Context, list []hookapi.Processor) {
	detected := processors.DetectSorted(ctx, list)
	for _, d := range detected {
		if !d.Detect.Applicable {
			ctx.AddResult(hookapi.ProcessorResult{Name: d.Processor.Name(), Stage: d.Processor.Stage(), Skipped: true, Reason: d.Detect.Reason})
			continue
		}
		err := d.Processor.Apply(ctx)
		ctx.AddResult(hookapi.ProcessorResult{Name: d.Processor.Name(), Stage: d.Processor.Stage(), Applied: err == nil, Err: err})
		return
	}
}

func runLanguageStage(ctx *hookapi.Context, list []hookapi.Processor) {
	detected := processors.DetectSorted(ctx, list)
	for _, d := range detected {
		if !d.Detect.Applicable {
			ctx.AddResult(hookapi.ProcessorResult{Name: d.Processor.Name(), Stage: d.Processor.Stage(), Skipped: true, Reason: d.Detect.Reason})
			continue
		}
		err := d.Processor.Apply(ctx)
		ctx.AddResult(hookapi.ProcessorResult{Name: d.Processor.Name(), Stage: d.Processor.Stage(), Applied: err == nil, Err: err})
	}
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
