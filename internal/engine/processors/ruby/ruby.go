// Package ruby provides a Ruby CA injection processor.
package ruby

import (
	"strings"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-ruby"
	processorPriority    = 100
	envSSLCertFile       = "SSL_CERT_FILE"
	rubyBinaryNotFound   = "ruby binary not found"
	missingContextReason = "missing context"
)

var rubyBinaryCandidates = []string{
	"/usr/bin/ruby",
	"/usr/local/bin/ruby",
	"/bin/ruby",
}

type processor struct{}

// New returns a Ruby CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasRubyBinary(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: rubyBinaryNotFound}
}

func (p *processor) Apply(_ *hookapi.Context) error {
	return nil
}

func (p *processor) ApplyWrapper(ctx *hookapi.Context) error {
	if ctx == nil || ctx.Facts == nil {
		return nil
	}
	individualCAPath, ok := ctx.Facts.Get(hookapi.FactIndividualCAPath)
	if !ok {
		return nil
	}
	individualCAPath = strings.TrimSpace(individualCAPath)
	if individualCAPath == "" {
		return nil
	}
	ctx.Env = envutil.Upsert(ctx.Env, envSSLCertFile, individualCAPath)
	return nil
}

func hasRubyBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, rubyBinaryCandidates)
}
