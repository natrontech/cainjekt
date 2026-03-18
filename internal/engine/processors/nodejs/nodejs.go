package nodejs

import (
	"strings"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/internal/util/containerfs"
	"github.com/tsuzu/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-nodejs"
	processorPriority    = 100
	envNodeExtraCACerts  = "NODE_EXTRA_CA_CERTS"
	nodeBinaryNotFound   = "node binary not found"
	missingContextReason = "missing context"
)

var nodeBinaryCandidates = []string{
	"/usr/bin/node",
	"/usr/local/bin/node",
	"/bin/node",
	"/usr/bin/nodejs",
}

type processor struct{}

func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasNodeBinary(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: nodeBinaryNotFound}
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
	ctx.Env = envutil.Upsert(ctx.Env, envNodeExtraCACerts, individualCAPath)
	return nil
}

func hasNodeBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, nodeBinaryCandidates)
}
