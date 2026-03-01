package nodejs

import (
	"os"
	"path/filepath"
	"testing"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
)

func TestDetectApplicableWhenNodeExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeNodeBinary(t, rootfs, "/usr/bin/node")

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenNodeDoesNotExist(t *testing.T) {
	t.Parallel()

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: t.TempDir()})
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
}

func TestApplyWrapperSetsNodeExtraCACerts(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{
		Env:   []string{"PATH=/usr/bin"},
		Facts: hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactIndividualCAPath, "/usr/local/share/ca-certificates/cainjekt.crt")

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	if got := envValue(ctx.Env, envNodeExtraCACerts); got != "/usr/local/share/ca-certificates/cainjekt.crt" {
		t.Fatalf("env %q mismatch: got=%q", envNodeExtraCACerts, got)
	}
}

func TestApplyWrapperOverwritesExistingNodeExtraCACerts(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{
		Env:   []string{"NODE_EXTRA_CA_CERTS=/tmp/old.crt"},
		Facts: hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactIndividualCAPath, "/usr/local/share/ca-certificates/cainjekt.crt")

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	if got := envValue(ctx.Env, envNodeExtraCACerts); got != "/usr/local/share/ca-certificates/cainjekt.crt" {
		t.Fatalf("env %q mismatch: got=%q", envNodeExtraCACerts, got)
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
	if got := envValue(ctx.Env, envNodeExtraCACerts); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envNodeExtraCACerts, got)
	}
}

func writeNodeBinary(t *testing.T, rootfs, containerPath string) {
	t.Helper()

	hostPath := pathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(hostPath), err)
	}
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", hostPath, err)
	}
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):]
		}
	}
	return ""
}
