package python

import (
	"testing"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/testutil"
)

const testIndividualCAPath = "/usr/local/share/ca-certificates/cainjekt.crt"

func TestDetectApplicableWhenPythonExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/python3")

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenPythonDoesNotExist(t *testing.T) {
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

func TestApplyWrapperSetsPythonEnvVars(t *testing.T) {
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

	if got := testutil.EnvValue(ctx.Env, envSSLCAFile); got != testIndividualCAPath {
		t.Fatalf("env %q mismatch: got=%q", envSSLCAFile, got)
	}
	if got := testutil.EnvValue(ctx.Env, envRequestsCABundle); got != testIndividualCAPath {
		t.Fatalf("env %q mismatch: got=%q", envRequestsCABundle, got)
	}
}

func TestApplyWrapperOverwritesExistingPythonEnvVars(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{
		Env: []string{
			"SSL_CERT_FILE=/tmp/old.crt",
			"REQUESTS_CA_BUNDLE=/tmp/old.crt",
		},
		Facts: hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactIndividualCAPath, testIndividualCAPath)

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	if got := testutil.EnvValue(ctx.Env, envSSLCAFile); got != testIndividualCAPath {
		t.Fatalf("env %q mismatch: got=%q", envSSLCAFile, got)
	}
	if got := testutil.EnvValue(ctx.Env, envRequestsCABundle); got != testIndividualCAPath {
		t.Fatalf("env %q mismatch: got=%q", envRequestsCABundle, got)
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
	if got := testutil.EnvValue(ctx.Env, envSSLCAFile); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envSSLCAFile, got)
	}
	if got := testutil.EnvValue(ctx.Env, envRequestsCABundle); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envRequestsCABundle, got)
	}
}
