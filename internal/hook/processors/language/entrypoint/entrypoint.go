package entrypoint

import (
	"strings"

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
	if ctx.Spec.Process == nil {
		return hookapi.DetectResult{Applicable: false, Reason: "process not found", Priority: 0}
	}
	return hookapi.DetectResult{Applicable: true, Priority: 90}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	certPath, _ := ctx.Facts.Get(hookapi.FactTrustStorePath)
	if setEnvDefault(ctx, config.EnvWrapperMode, "1") {
		ctx.SpecChanged = true
	}
	if setEnvDefault(ctx, config.EnvWrapperTrustStore, certPath) {
		ctx.SpecChanged = true
	}
	return nil
}

func (p *processor) ApplyWrapper(_ *hookapi.WrapperContext) error {
	// Wrapper env values are injected in hook phase; nothing to do in wrapper runtime.
	return nil
}

func setEnvDefault(ctx *hookapi.Context, key, value string) bool {
	if ctx.Spec.Process == nil {
		return false
	}
	prefix := key + "="
	for i := range ctx.Spec.Process.Env {
		if strings.HasPrefix(ctx.Spec.Process.Env[i], prefix) {
			return false
		}
	}
	ctx.Spec.Process.Env = append(ctx.Spec.Process.Env, prefix+value)
	return true
}
