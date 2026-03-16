package python

import (
	"os"
	"path/filepath"
	"testing"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/internal/util/containerfs"
)

func TestDetectApplicableWhenPythonExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writePythonBinary(t, rootfs, "/usr/bin/python3")

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
	ctx.Facts.Set(hookapi.FactIndividualCAPath, "/usr/local/share/ca-certificates/cainjekt.crt")

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	if got := envValue(ctx.Env, envSSLCAFile); got != "/usr/local/share/ca-certificates/cainjekt.crt" {
		t.Fatalf("env %q mismatch: got=%q", envSSLCAFile, got)
	}
	if got := envValue(ctx.Env, envRequestsCABundle); got != "/usr/local/share/ca-certificates/cainjekt.crt" {
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
	ctx.Facts.Set(hookapi.FactIndividualCAPath, "/usr/local/share/ca-certificates/cainjekt.crt")

	p := New().(*processor)
	if err := p.ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}

	if got := envValue(ctx.Env, envSSLCAFile); got != "/usr/local/share/ca-certificates/cainjekt.crt" {
		t.Fatalf("env %q mismatch: got=%q", envSSLCAFile, got)
	}
	if got := envValue(ctx.Env, envRequestsCABundle); got != "/usr/local/share/ca-certificates/cainjekt.crt" {
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
	if got := envValue(ctx.Env, envSSLCAFile); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envSSLCAFile, got)
	}
	if got := envValue(ctx.Env, envRequestsCABundle); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envRequestsCABundle, got)
	}
}

func writePythonBinary(t *testing.T, rootfs, containerPath string) {
	t.Helper()

	hostPath := containerfs.PathInRootfs(rootfs, containerPath)
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
