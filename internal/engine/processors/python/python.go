// Package python provides a Python CA injection processor.
package python

import (
	"strings"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/internal/util/containerfs"
	"github.com/tsuzu/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-python"
	processorPriority    = 100
	envSSLCAFile         = "SSL_CERT_FILE"
	envRequestsCABundle  = "REQUESTS_CA_BUNDLE"
	pythonBinaryNotFound = "python binary not found"
	missingContextReason = "missing context"
)

var pythonBinaryCandidates = []string{
	"/usr/bin/python3",
	"/usr/local/bin/python3",
	"/bin/python3",
	"/usr/bin/python",
	"/usr/local/bin/python",
	"/bin/python",
}

type processor struct{}

// New returns a Python CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasPythonBinary(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: pythonBinaryNotFound}
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
	ctx.Env = envutil.Upsert(ctx.Env, envSSLCAFile, individualCAPath)
	ctx.Env = envutil.Upsert(ctx.Env, envRequestsCABundle, individualCAPath)
	return nil
}

// TODO: Make rootfs binary detection handle absolute symlinks without resolving them on the host.
func hasPythonBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, pythonBinaryCandidates)
}
