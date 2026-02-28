package osstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
)

func TestParseOSRelease(t *testing.T) {
	t.Parallel()

	raw := `
# comment
NAME="Ubuntu"
ID=ubuntu
ID_LIKE="debian  linux"
`
	info, err := parseOSRelease(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parseOSRelease() error = %v", err)
	}
	if info.id != "ubuntu" {
		t.Fatalf("ID mismatch: got=%q want=%q", info.id, "ubuntu")
	}
	if len(info.idLike) != 2 || info.idLike[0] != "debian" || info.idLike[1] != "linux" {
		t.Fatalf("ID_LIKE mismatch: got=%v", info.idLike)
	}
}

func TestDetectByOSRelease(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=ubuntu\nID_LIKE=debian\n")
	ctx := &hookapi.Context{Rootfs: rootfs}

	if got := NewDebian().Detect(ctx); !got.Applicable {
		t.Fatalf("debian detect should be applicable: %+v", got)
	}
	if got := NewRHEL().Detect(ctx); got.Applicable {
		t.Fatalf("rhel detect should not be applicable: %+v", got)
	}
	if got := NewAlpine().Detect(ctx); got.Applicable {
		t.Fatalf("alpine detect should not be applicable: %+v", got)
	}
	if got := NewOpenSUSE().Detect(ctx); got.Applicable {
		t.Fatalf("opensuse detect should not be applicable: %+v", got)
	}
	if got := NewArch().Detect(ctx); got.Applicable {
		t.Fatalf("arch detect should not be applicable: %+v", got)
	}
}

func TestDetectRHELFamilyByFedoraID(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=fedora\nID_LIKE=\"fedora rhel\"\n")
	ctx := &hookapi.Context{Rootfs: rootfs}

	if got := NewRHEL().Detect(ctx); !got.Applicable {
		t.Fatalf("rhel detect should be applicable for fedora: %+v", got)
	}
}

func TestDetectOpenSUSEByIDLike(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=sles\nID_LIKE=\"suse opensuse\"\n")
	ctx := &hookapi.Context{Rootfs: rootfs}

	if got := NewOpenSUSE().Detect(ctx); !got.Applicable {
		t.Fatalf("opensuse detect should be applicable for sles: %+v", got)
	}
}

func TestDetectArchByID(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=arch\n")
	ctx := &hookapi.Context{Rootfs: rootfs}

	if got := NewArch().Detect(ctx); !got.Applicable {
		t.Fatalf("arch detect should be applicable for arch: %+v", got)
	}
}

func TestFallbackWhenOSReleaseMissing(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{Rootfs: t.TempDir()}

	if got := NewDebian().Detect(ctx); got.Applicable {
		t.Fatalf("debian detect should not be applicable without os-release: %+v", got)
	}
	if got := NewFallback().Detect(ctx); !got.Applicable {
		t.Fatalf("fallback detect should be applicable without os-release: %+v", got)
	}
}

func TestApplySkipsWhenTrustStoreAlreadyConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		processor hookapi.Processor
	}{
		{name: "fallback", processor: NewFallback()},
		{name: "non-fallback", processor: NewDebian()},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := &hookapi.Context{
				Rootfs: t.TempDir(),
				CAFile: filepath.Join(t.TempDir(), "missing-ca.pem"),
				Facts:  hookapi.NewMapFactStore(),
			}
			ctx.Facts.Set(hookapi.FactTrustStorePath, "/etc/ssl/certs/ca-certificates.crt")

			if err := tc.processor.Apply(ctx); err != nil {
				t.Fatalf("Apply() should skip when trust store is already configured: %v", err)
			}
		})
	}
}

func TestResolveContainerPathAbsoluteSymlink(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	mustMkdirAll(t, filepath.Join(rootfs, "real", "ssl"), 0o755)
	mustMkdirAll(t, filepath.Join(rootfs, "etc"), 0o755)
	mustSymlink(t, "/real/ssl/ca-bundle.pem", filepath.Join(rootfs, "etc", "ssl-bundle.pem"))

	host, container, err := resolveContainerPath(rootfs, "/etc/ssl-bundle.pem")
	if err != nil {
		t.Fatalf("resolveContainerPath() error = %v", err)
	}
	if container != "/real/ssl/ca-bundle.pem" {
		t.Fatalf("container path mismatch: got=%q want=%q", container, "/real/ssl/ca-bundle.pem")
	}
	if host != filepath.Join(rootfs, "real", "ssl", "ca-bundle.pem") {
		t.Fatalf("host path mismatch: got=%q", host)
	}
}

func TestResolveContainerPathRelativeDirSymlink(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	mustMkdirAll(t, filepath.Join(rootfs, "etc"), 0o755)
	mustMkdirAll(t, filepath.Join(rootfs, "usr", "lib"), 0o755)
	mustSymlink(t, "../usr/lib", filepath.Join(rootfs, "etc", "ssl"))

	host, container, err := resolveContainerPath(rootfs, "/etc/ssl/ca-certificates.crt")
	if err != nil {
		t.Fatalf("resolveContainerPath() error = %v", err)
	}
	if container != "/usr/lib/ca-certificates.crt" {
		t.Fatalf("container path mismatch: got=%q want=%q", container, "/usr/lib/ca-certificates.crt")
	}
	if host != filepath.Join(rootfs, "usr", "lib", "ca-certificates.crt") {
		t.Fatalf("host path mismatch: got=%q", host)
	}
}

func TestWriteIndividualCAResolvesSymlinkedAnchorDir(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	mustMkdirAll(t, filepath.Join(rootfs, "usr", "local", "share"), 0o755)
	mustMkdirAll(t, filepath.Join(rootfs, "var", "certs"), 0o755)
	mustSymlink(t, "/var/certs", filepath.Join(rootfs, "usr", "local", "share", "ca-certificates"))

	content := []byte("dummy")
	if err := writeIndividualCA(rootfs, "/usr/local/share/ca-certificates", content); err != nil {
		t.Fatalf("writeIndividualCA() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(rootfs, "var", "certs", individualCAFileName))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got=%q want=%q", string(got), string(content))
	}
}

func writeOSRelease(t *testing.T, rootfs, body string) {
	t.Helper()
	p := filepath.Join(rootfs, "etc", "os-release")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", p, err)
	}
}

func mustMkdirAll(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, mode); err != nil {
		t.Fatalf("MkdirAll(%q): %v", p, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(link), 0o755)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", link, target, err)
	}
}
