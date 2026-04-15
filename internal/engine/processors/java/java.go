// Package java provides a Java CA injection processor.
package java

import (
	"strings"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-java"
	processorPriority    = 100
	envJavaToolOptions   = "JAVA_TOOL_OPTIONS"
	javaBinaryNotFound   = "java binary not found"
	missingContextReason = "missing context"
)

var javaBinaryCandidates = []string{
	"/usr/bin/java",
	"/usr/local/bin/java",
	"/usr/lib/jvm/default/bin/java",
	"/usr/lib/jvm/default-java/bin/java",
	"/opt/java/bin/java",
}

type processor struct{}

// New returns a Java CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasJavaBinary(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: javaBinaryNotFound}
}

func (p *processor) Apply(_ *hookapi.Context) error {
	// Java CA injection is handled entirely in the wrapper phase via JAVA_TOOL_OPTIONS.
	// Modifying cacerts directly is fragile (location varies, keytool may not exist,
	// password may differ, rootfs may be read-only). The env var approach works across
	// all JVM versions.
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

	// JAVA_TOOL_OPTIONS is picked up by all JVM invocations.
	// We append the trust store flags so existing JAVA_TOOL_OPTIONS values are preserved.
	existing := envutil.GetValue(ctx.Env, envJavaToolOptions)
	trustStoreFlags := "-Djavax.net.ssl.trustStore=" + individualCAPath +
		" -Djavax.net.ssl.trustStoreType=PEM"
	if existing != "" {
		ctx.Env = envutil.Upsert(ctx.Env, envJavaToolOptions, existing+" "+trustStoreFlags)
	} else {
		ctx.Env = envutil.Upsert(ctx.Env, envJavaToolOptions, trustStoreFlags)
	}
	return nil
}

func hasJavaBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, javaBinaryCandidates)
}
