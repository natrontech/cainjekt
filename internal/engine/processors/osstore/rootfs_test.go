package osstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
)

// TestIsRootfsWritableRefusesSymlink pins that the writability probe does not
// follow a symlink at the probe path or modify what it points to.
func TestIsRootfsWritableRefusesSymlink(t *testing.T) {
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(tmp, "host-file")
	const payload = "unchanged"
	if err := os.WriteFile(host, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, filepath.Join(rootfs, ".cainjekt-probe")); err != nil {
		t.Fatal(err)
	}

	_ = isRootfsWritable(rootfs)

	got, err := os.ReadFile(host)
	if err != nil {
		t.Fatalf("host file gone: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("host file was modified through the probe symlink: %q", got)
	}
}

// TestIsRootfsWritableTrueOnCleanRootfs keeps the probe honest: a genuinely
// writable rootfs with no planted probe must still report writable.
func TestIsRootfsWritableTrueOnCleanRootfs(t *testing.T) {
	rootfs := t.TempDir()
	if !isRootfsWritable(rootfs) {
		t.Fatal("expected a writable rootfs to report writable")
	}
	if _, err := os.Lstat(filepath.Join(rootfs, ".cainjekt-probe")); !os.IsNotExist(err) {
		t.Fatalf("probe file was left behind: %v", err)
	}
}

// TestReadOSReleaseDoesNotEscapeRootfs pins that a symlinked os-release cannot
// redirect the distro read at a file on the node.
func TestReadOSReleaseDoesNotEscapeRootfs(t *testing.T) {
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(tmp, "host-os-release")
	if err := os.WriteFile(host, []byte("ID=attacker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, filepath.Join(rootfs, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}

	info, err := readOSRelease(rootfs)
	// The re-anchored target does not exist inside the rootfs, so this reads as
	// "not found"; crucially it must never surface the host file's ID.
	if err == nil && info.id == "attacker" {
		t.Fatal("readOSRelease read os-release from outside the rootfs")
	}
}

// TestApplyRefusesNonRegularTrustStore pins that a trust store path the image
// turned into a FIFO (or device node) is refused instead of read: the hook runs
// as root on the node, and reading a FIFO would block until containerd kills it.
func TestApplyRefusesNonRegularTrustStore(t *testing.T) {
	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=debian\n")
	mustMkdirAll(t, filepath.Join(rootfs, "etc/ssl/certs"))
	if err := syscall.Mkfifo(filepath.Join(rootfs, "etc/ssl/certs/ca-certificates.crt"), 0o644); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, mustCreateTestCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &hookapi.Context{Rootfs: rootfs, CAFile: caFile, Facts: hookapi.NewMapFactStore()}

	done := make(chan error, 1)
	go func() { done <- NewDebian().Apply(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for FIFO trust store")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Apply blocked reading a FIFO trust store")
	}
}
