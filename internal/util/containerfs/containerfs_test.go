package containerfs

import (
	"os"
	"path/filepath"
	"testing"
)

const testJavaPath = "/usr/bin/java"

func writeFileInRootfs(t *testing.T, rootfs, containerPath string) {
	t.Helper()

	host := PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(host), err)
	}
	if err := os.WriteFile(host, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", host, err)
	}
}

func symlinkInRootfs(t *testing.T, rootfs, containerPath, target string) {
	t.Helper()

	host := PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(host), err)
	}
	if err := os.Symlink(target, host); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", host, target, err)
	}
}

func TestResolveSymlinksFollowsAbsoluteChainInsideRootfs(t *testing.T) {
	t.Parallel()

	// RHEL alternatives layout: /usr/bin/java -> /etc/alternatives/java -> real binary.
	rootfs := t.TempDir()
	writeFileInRootfs(t, rootfs, "/usr/lib/jvm/java-17-openjdk/bin/java")
	symlinkInRootfs(t, rootfs, "/etc/alternatives/java", "/usr/lib/jvm/java-17-openjdk/bin/java")
	symlinkInRootfs(t, rootfs, testJavaPath, "/etc/alternatives/java")

	got, err := ResolveSymlinks(rootfs, testJavaPath)
	if err != nil {
		t.Fatalf("ResolveSymlinks() error = %v", err)
	}
	if want := "/usr/lib/jvm/java-17-openjdk/bin/java"; got != want {
		t.Fatalf("ResolveSymlinks() = %q, want %q", got, want)
	}
}

func TestResolveSymlinksFollowsRelativeLink(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeFileInRootfs(t, rootfs, "/usr/bin/python3.9")
	symlinkInRootfs(t, rootfs, "/usr/bin/python3", "python3.9")

	got, err := ResolveSymlinks(rootfs, "/usr/bin/python3")
	if err != nil {
		t.Fatalf("ResolveSymlinks() error = %v", err)
	}
	if want := "/usr/bin/python3.9"; got != want {
		t.Fatalf("ResolveSymlinks() = %q, want %q", got, want)
	}
}

func TestResolveSymlinksReturnsMissingPathUnchanged(t *testing.T) {
	t.Parallel()

	got, err := ResolveSymlinks(t.TempDir(), testJavaPath)
	if err != nil {
		t.Fatalf("ResolveSymlinks() error = %v", err)
	}
	if want := testJavaPath; got != want {
		t.Fatalf("ResolveSymlinks() = %q, want %q", got, want)
	}
}

func TestResolveSymlinksErrorsOnLoop(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	symlinkInRootfs(t, rootfs, "/usr/bin/a", "/usr/bin/b")
	symlinkInRootfs(t, rootfs, "/usr/bin/b", "/usr/bin/a")

	if _, err := ResolveSymlinks(rootfs, "/usr/bin/a"); err == nil {
		t.Fatal("ResolveSymlinks() should error on symlink loop")
	}
}

func TestHasAnyRegularFileFindsAbsoluteSymlinkTarget(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeFileInRootfs(t, rootfs, "/usr/lib/jvm/java-17-openjdk/bin/java")
	symlinkInRootfs(t, rootfs, "/etc/alternatives/java", "/usr/lib/jvm/java-17-openjdk/bin/java")
	symlinkInRootfs(t, rootfs, testJavaPath, "/etc/alternatives/java")

	if !HasAnyRegularFile(rootfs, []string{testJavaPath}) {
		t.Fatal("HasAnyRegularFile() should find java through absolute symlink chain")
	}
}

func TestHasAnyRegularFileIgnoresDanglingSymlink(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	symlinkInRootfs(t, rootfs, testJavaPath, "/etc/alternatives/java")

	if HasAnyRegularFile(rootfs, []string{testJavaPath}) {
		t.Fatal("HasAnyRegularFile() should not match a dangling symlink")
	}
}

func TestHasAnyRegularFileMissingFile(t *testing.T) {
	t.Parallel()

	if HasAnyRegularFile(t.TempDir(), []string{testJavaPath}) {
		t.Fatal("HasAnyRegularFile() should not match a missing file")
	}
}
