// Package python provides a Python CA injection processor.
package python

import (
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/internal/util/envutil"
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
	if ctx == nil {
		return nil
	}
	caPath := hookapi.PreferredCABundlePath(ctx.Facts)
	if caPath == "" {
		return nil
	}
	ctx.Env = envutil.Upsert(ctx.Env, envSSLCAFile, caPath)
	ctx.Env = envutil.Upsert(ctx.Env, envRequestsCABundle, caPath)
	return nil
}

// TODO: Make rootfs binary detection handle absolute symlinks without resolving them on the host.
func hasPythonBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, pythonBinaryCandidates)
}
