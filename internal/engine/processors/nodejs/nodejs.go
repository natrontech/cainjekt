package nodejs

import (
	"os"
	"path/filepath"
	"strings"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
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
	ctx.Env = upsertEnv(ctx.Env, envNodeExtraCACerts, individualCAPath)
	return nil
}

func hasNodeBinary(rootfs string) bool {
	for _, p := range nodeBinaryCandidates {
		host := pathInRootfs(rootfs, p)
		fi, err := os.Stat(host)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func upsertEnv(env []string, key, value string) []string {
	prefix := key + "="
	entry := prefix + value
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}

func pathInRootfs(rootfs, containerPath string) string {
	trimmed := strings.TrimPrefix(containerPath, "/")
	return filepath.Join(rootfs, filepath.FromSlash(trimmed))
}
