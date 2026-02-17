package envvars

import (
	"strings"

	"github.com/tsuzu/cainjekt/internal/config"
	hookapi "github.com/tsuzu/cainjekt/internal/hook/api"
)

type processor struct{}

func New() hookapi.Processor { return &processor{} }

func (p *processor) Name() string { return "envvars" }

func (p *processor) Stage() hookapi.Stage { return hookapi.StageLanguage }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if _, ok := ctx.Facts.Get(hookapi.FactTrustStorePath); !ok {
		return hookapi.DetectResult{Applicable: false, Reason: "missing trust store fact", Priority: 0}
	}
	return hookapi.DetectResult{Applicable: true, Priority: 100}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	certPath, _ := ctx.Facts.Get(hookapi.FactTrustStorePath)
	for _, key := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
		if setSpecEnvDefault(ctx, key, certPath) {
			ctx.SpecChanged = true
		}
	}
	return nil
}

func (p *processor) ApplyWrapper(ctx *hookapi.WrapperContext) error {
	if strings.TrimSpace(ctx.TrustStore) == "" {
		for _, env := range ctx.Env {
			if strings.HasPrefix(env, config.EnvWrapperTrustStore+"=") {
				ctx.TrustStore = strings.TrimPrefix(env, config.EnvWrapperTrustStore+"=")
				break
			}
		}
	}
	if strings.TrimSpace(ctx.TrustStore) == "" {
		return nil
	}
	for _, key := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
		ctx.Env = setProcessEnvDefault(ctx.Env, key, ctx.TrustStore)
	}
	return nil
}

func setSpecEnvDefault(ctx *hookapi.Context, key, value string) bool {
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

func setProcessEnvDefault(env []string, key, value string) []string {
	prefix := key + "="
	for _, v := range env {
		if strings.HasPrefix(v, prefix) {
			return env
		}
	}
	return append(env, prefix+value)
}
