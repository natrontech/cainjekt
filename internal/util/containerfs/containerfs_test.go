package containerfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
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

func TestReadRegularFileRejectsNonRegular(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadRegularFile(regular); err != nil || string(b) != "ok" {
		t.Fatalf("regular file: got %q, %v", b, err)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	// A FIFO must be refused, not read: reading one blocks until the hook is killed.
	for _, p := range []string{fifo, link, dir} {
		if _, err := ReadRegularFile(p); err == nil {
			t.Errorf("%s: expected error, got nil", p)
		}
	}

	if _, err := ReadRegularFile(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: want os.ErrNotExist, got %v", err)
	}
}

func TestReadRegularFileRejectsOversized(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Sparse file: no real disk use.
	if err := os.Truncate(p, MaxReadSize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(p); err == nil {
		t.Fatal("expected error for file larger than MaxReadSize")
	}
}
