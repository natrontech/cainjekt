// Package dotnet provides a .NET CA injection processor.
//
// On Linux, .NET loads its root store through OpenSSL and honors SSL_CERT_FILE.
// The OS store processor handles the primary case; this processor adds the env var
// fallback for read-only rootfs or chiseled images where the trust store cannot be patched.
package dotnet

import (
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-dotnet"
	processorPriority    = 100
	envSSLCertFile       = "SSL_CERT_FILE"
	dotnetHostNotFound   = "dotnet host not found"
	missingContextReason = "missing context"
)

var dotnetHostCandidates = []string{
	"/usr/share/dotnet/dotnet", // mcr.microsoft.com/dotnet images
	"/usr/lib/dotnet/dotnet",   // distro packages (Ubuntu, Fedora)
	"/usr/bin/dotnet",
}

type processor struct{}

// New returns a .NET CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasDotnetHost(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: dotnetHostNotFound}
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
	ctx.Env = envutil.Upsert(ctx.Env, envSSLCertFile, caPath)
	return nil
}

func hasDotnetHost(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, dotnetHostCandidates)
}
