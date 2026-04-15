package ruby

import (
	"testing"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/testutil"
)

const testIndividualCAPath = "/usr/local/share/ca-certificates/cainjekt.crt"

func TestDetectApplicableWhenRubyExists(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/ruby")

	got := New().Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenRubyMissing(t *testing.T) {
	t.Parallel()
	got := New().Detect(&hookapi.Context{Rootfs: t.TempDir()})
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
}

func TestApplyWrapperSetsSSLCertFile(t *testing.T) {
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
	if got := testutil.EnvValue(ctx.Env, envSSLCertFile); got != testIndividualCAPath {
		t.Fatalf("env %q = %q, want %q", envSSLCertFile, got, testIndividualCAPath)
	}
}

func TestApplyWrapperNoopWithoutCA(t *testing.T) {
	t.Parallel()
	ctx := &hookapi.Context{Env: []string{}, Facts: hookapi.NewMapFactStore()}

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}
	if got := testutil.EnvValue(ctx.Env, envSSLCertFile); got != "" {
		t.Fatalf("env %q should not be set: %q", envSSLCertFile, got)
	}
}
