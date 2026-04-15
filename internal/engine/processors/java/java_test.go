package java

import (
	"strings"
	"testing"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/testutil"
)

const testIndividualCAPath = "/usr/local/share/ca-certificates/cainjekt.crt"

func TestDetectApplicableWhenJavaExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenJavaDoesNotExist(t *testing.T) {
	t.Parallel()

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: t.TempDir()})
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenContextIsNil(t *testing.T) {
	t.Parallel()

	p := New()
	got := p.Detect(nil)
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
	if got.Reason != missingContextReason {
		t.Fatalf("Detect() reason mismatch: got=%q want=%q", got.Reason, missingContextReason)
	}
}

func TestApplyWrapperSetsJavaToolOptions(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{
		Env:   []string{"PATH=/usr/bin"},
		Facts: hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactIndividualCAPath, testIndividualCAPath)

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	got := testutil.EnvValue(ctx.Env, envJavaToolOptions)
	if !strings.Contains(got, "-Djavax.net.ssl.trustStore="+testIndividualCAPath) {
		t.Fatalf("env %q missing trustStore flag: got=%q", envJavaToolOptions, got)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStoreType=PEM") {
		t.Fatalf("env %q missing trustStoreType flag: got=%q", envJavaToolOptions, got)
	}
}

func TestApplyWrapperAppendsToExistingJavaToolOptions(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{
		Env:   []string{"JAVA_TOOL_OPTIONS=-Xmx512m"},
		Facts: hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactIndividualCAPath, testIndividualCAPath)

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	got := testutil.EnvValue(ctx.Env, envJavaToolOptions)
	if !strings.HasPrefix(got, "-Xmx512m ") {
		t.Fatalf("env %q should preserve existing flags: got=%q", envJavaToolOptions, got)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStore=") {
		t.Fatalf("env %q missing trustStore flag: got=%q", envJavaToolOptions, got)
	}
}

func TestApplyWrapperNoopWithoutIndividualCAPath(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{
		Env:   []string{"PATH=/usr/bin"},
		Facts: hookapi.NewMapFactStore(),
	}

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}
	if got := testutil.EnvValue(ctx.Env, envJavaToolOptions); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envJavaToolOptions, got)
	}
}
