// Package testutil provides shared test helpers for cainjekt.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/natrontech/cainjekt/internal/util/containerfs"
)

// WriteExecutableInRootfs creates a minimal executable at the given container path inside rootfs.
func WriteExecutableInRootfs(t testing.TB, rootfs, containerPath string) {
	t.Helper()

	hostPath := containerfs.PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(hostPath), err)
	}
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", hostPath, err)
	}
}

// EnvValue returns the value for the given key from an env slice, or empty string if not found.
func EnvValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):]
		}
	}
	return ""
}
