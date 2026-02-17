package entrypoint

import (
	"github.com/tsuzu/cainjekt/internal/config"
	hookapi "github.com/tsuzu/cainjekt/internal/hook/api"
)

type processor struct{}

func New() hookapi.Processor { return &processor{} }

func (p *processor) Name() string { return "entrypoint" }

func (p *processor) Stage() hookapi.Stage { return hookapi.StageLanguage }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if _, ok := ctx.Facts.Get(hookapi.FactTrustStorePath); !ok {
		return hookapi.DetectResult{Applicable: false, Reason: "missing trust store fact", Priority: 0}
	}
	if ctx.Spec.Process == nil || len(ctx.Spec.Process.Args) == 0 {
		return hookapi.DetectResult{Applicable: false, Reason: "process args not found", Priority: 0}
	}
	if ctx.Spec.Process.Args[0] == config.WrapperPath {
		return hookapi.DetectResult{Applicable: false, Reason: "already wrapped", Priority: 0}
	}
	return hookapi.DetectResult{Applicable: true, Priority: 90}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	certPath, _ := ctx.Facts.Get(hookapi.FactTrustStorePath)
	setEnvDefault(ctx, config.EnvWrapperMode, "1")
	setEnvDefault(ctx, config.EnvWrapperTrustStore, certPath)
	ctx.SpecChanged = true

	oldArgs := append([]string{}, ctx.Spec.Process.Args...)
	ctx.Spec.Process.Args = append([]string{config.WrapperPath}, oldArgs...)
	ctx.SpecChanged = true
	return nil
}

func (p *processor) ApplyWrapper(_ *hookapi.WrapperContext) error {
	// Entrypoint rewrites OCI args/env in hook phase; nothing to do in wrapper runtime.
	return nil
}

func setEnvDefault(ctx *hookapi.Context, key, value string) {
	if ctx.Spec.Process == nil {
		return
	}
	prefix := key + "="
	for i := range ctx.Spec.Process.Env {
		if len(ctx.Spec.Process.Env[i]) >= len(prefix) && ctx.Spec.Process.Env[i][:len(prefix)] == prefix {
			return
		}
	}
	ctx.Spec.Process.Env = append(ctx.Spec.Process.Env, prefix+value)
}
