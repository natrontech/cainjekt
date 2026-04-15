// Package golang provides a Go CA injection processor.
//
// Go's crypto/x509 reads system trust stores and respects SSL_CERT_FILE (since Go 1.21).
// The OS store processor handles the primary case; this processor adds the env var fallback
// for read-only rootfs or distroless images where trust store modification is not possible.
package golang

import (
	"strings"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-go"
	processorPriority    = 100
	envSSLCertFile       = "SSL_CERT_FILE"
	goBinaryNotFound     = "go binary not found"
	missingContextReason = "missing context"
)

var goBinaryCandidates = []string{
	"/usr/local/go/bin/go",
	"/usr/bin/go",
	"/usr/local/bin/go",
}

type processor struct{}

// New returns a Go CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasGoBinary(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: goBinaryNotFound}
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

func hasGoBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, goBinaryCandidates)
}
