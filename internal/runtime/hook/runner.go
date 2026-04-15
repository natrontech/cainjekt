// Package hook implements the OCI CreateRuntime hook for CA injection.
package hook

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/natrontech/cainjekt/internal/config"
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/engine/processors"
	"github.com/natrontech/cainjekt/internal/runtime/hookctx"
	"github.com/natrontech/cainjekt/internal/util/oci"
)

// Run executes the OCI hook phase: detects processors, applies CA injection, and persists wrapper context.
func Run(log *slog.Logger) error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(config.EnvHookMode)))
	if mode != config.ModeCreateRT && mode != config.ModeCreateCtr {
		return fmt.Errorf("unknown hook mode: %q", mode)
	}

	state, err := oci.ReadState(os.Stdin)
	if err != nil {
		return err
	}

	_, spec, err := oci.LoadSpec(state.Bundle)
	if err != nil {
		return err
	}

	ctx := &hookapi.Context{
		Mode:        mode,
		Bundle:      state.Bundle,
		Annotations: state.Annotations,
		Rootfs:      oci.ResolveRootfsPath(state.Bundle, spec),
		CAFile:      getenvOr(config.EnvCAFile, config.DefaultCAFile),
		FailPolicy:  getenvOr(config.EnvFailPolicy, config.FailPolicyOpen),
		Facts:       hookapi.NewMapFactStore(),
	}

	all := processors.Default()
	include := processors.ParseCSV(ctx.Annotations[config.AnnoProcessorsInclude()])
	exclude := processors.ParseCSV(ctx.Annotations[config.AnnoProcessorsExclude()])
	filtered := processors.FilterByNames(all, include, exclude)

	log.Info("running hook",
		"mode", mode,
		"rootfs", ctx.Rootfs,
		"ca_file", ctx.CAFile,
		"processors", len(filtered),
	)

	detected := runProcessors(ctx, filtered)
	if err := persistWrapperContext(ctx, detected); err != nil {
		return err
	}

	var applied, skipped, failed int
	for _, r := range ctx.Results {
		log.Info("processor result",
			"name", r.Name,
			"category", r.Category,
			"applied", r.Applied,
			"skipped", r.Skipped,
			"reason", r.Reason,
			"error", r.Err,
		)
		switch {
		case r.Applied:
			applied++
		case r.Skipped:
			skipped++
		default:
			failed++
		}
	}

	// Log read-only rootfs detection.
	if v, ok := ctx.Facts.Get(hookapi.FactRootfsReadOnly); ok && v == "true" {
		log.Warn("rootfs is read-only, OS trust store was not modified; language processors will use dynamic CA path")
	}

	log.Info("hook complete",
		"applied", applied,
		"skipped", skipped,
		"failed", failed,
		"distro", factOrEmpty(ctx, hookapi.FactDistro),
		"trust_store", factOrEmpty(ctx, hookapi.FactTrustStorePath),
	)

	return nil
}

func persistWrapperContext(ctx *hookapi.Context, detected []hookctx.DetectedProcessor) error {
	state := hookctx.NewStateFromContext(ctx, detected)
	return hookctx.Write(ctx.Rootfs, state)
}

func runProcessors(ctx *hookapi.Context, list []hookapi.Processor) []hookctx.DetectedProcessor {
	detected := processors.DetectSorted(ctx, list)
	persisted := make([]hookctx.DetectedProcessor, 0, len(detected))
	for _, d := range detected {
		persisted = append(persisted, hookctx.DetectedProcessor{
			Name:       d.Processor.Name(),
			Category:   d.Processor.Category(),
			Applicable: d.Detect.Applicable,
			Priority:   d.Detect.Priority,
			Reason:     d.Detect.Reason,
		})
		if !d.Detect.Applicable {
			ctx.AddResult(hookapi.ProcessorResult{
				Name:     d.Processor.Name(),
				Category: d.Processor.Category(),
				Skipped:  true,
				Reason:   d.Detect.Reason,
			})
			continue
		}
		err := d.Processor.Apply(ctx)
		ctx.AddResult(hookapi.ProcessorResult{
			Name:     d.Processor.Name(),
			Category: d.Processor.Category(),
			Applied:  err == nil,
			Err:      err,
		})
	}
	return persisted
}

func factOrEmpty(ctx *hookapi.Context, key hookapi.FactKey) string {
	if ctx == nil || ctx.Facts == nil {
		return ""
	}
	v, _ := ctx.Facts.Get(key)
	return v
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
