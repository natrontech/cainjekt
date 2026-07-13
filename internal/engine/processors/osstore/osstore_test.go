package osstore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/natrontech/cainjekt/internal/config"
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
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
	mustMkdirAll(t, filepath.Join(rootfs, "real", "ssl"))
	mustMkdirAll(t, filepath.Join(rootfs, "etc"))
	mustSymlink(t, "/real/ssl/ca-bundle.pem", filepath.Join(rootfs, "etc", "ssl-bundle.pem"))

	container, err := containerfs.ResolveSymlinks(rootfs, "/etc/ssl-bundle.pem")
	if err != nil {
		t.Fatalf("ResolveSymlinks() error = %v", err)
	}
	if container != "/real/ssl/ca-bundle.pem" {
		t.Fatalf("container path mismatch: got=%q want=%q", container, "/real/ssl/ca-bundle.pem")
	}
}

func TestResolveContainerPathRelativeDirSymlink(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	mustMkdirAll(t, filepath.Join(rootfs, "etc"))
	mustMkdirAll(t, filepath.Join(rootfs, "usr", "lib"))
	mustSymlink(t, "../usr/lib", filepath.Join(rootfs, "etc", "ssl"))

	container, err := containerfs.ResolveSymlinks(rootfs, "/etc/ssl/ca-certificates.crt")
	if err != nil {
		t.Fatalf("ResolveSymlinks() error = %v", err)
	}
	if container != "/usr/lib/ca-certificates.crt" {
		t.Fatalf("container path mismatch: got=%q want=%q", container, "/usr/lib/ca-certificates.crt")
	}
}

func TestWriteIndividualCAResolvesSymlinkedAnchorDir(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	mustMkdirAll(t, filepath.Join(rootfs, "usr", "local", "share"))
	mustMkdirAll(t, filepath.Join(rootfs, "var", "certs"))
	mustSymlink(t, "/var/certs", filepath.Join(rootfs, "usr", "local", "share", "ca-certificates"))

	content := []byte("dummy")
	resolvedPath, err := writeIndividualCA(rootfs, "/usr/local/share/ca-certificates", content)
	if err != nil {
		t.Fatalf("writeIndividualCA() error = %v", err)
	}
	if resolvedPath != "/var/certs/"+individualCAFileName {
		t.Fatalf("resolved path mismatch: got=%q", resolvedPath)
	}
	got, err := os.ReadFile(filepath.Join(rootfs, "var", "certs", individualCAFileName))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got=%q want=%q", string(got), string(content))
	}
}

func TestApplySetsIndividualCAPathFact(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=ubuntu\nID_LIKE=debian\n")

	caPath := filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := os.WriteFile(caPath, mustCreateTestCertPEM(t), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", caPath, err)
	}

	ctx := &hookapi.Context{
		Rootfs: rootfs,
		CAFile: caPath,
		Facts:  hookapi.NewMapFactStore(),
	}

	if err := NewDebian().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	got, ok := ctx.Facts.Get(hookapi.FactIndividualCAPath)
	if !ok {
		t.Fatalf("missing fact %q", hookapi.FactIndividualCAPath)
	}
	want := "/usr/local/share/ca-certificates/" + individualCAFileName
	if got != want {
		t.Fatalf("individual CA path mismatch: got=%q want=%q", got, want)
	}

	gotMerged, ok := ctx.Facts.Get(hookapi.FactMergedCAPath)
	if !ok {
		t.Fatalf("missing fact %q", hookapi.FactMergedCAPath)
	}
	if gotMerged != "/etc/ssl/certs/ca-certificates.crt" {
		t.Fatalf("merged CA path mismatch: got=%q", gotMerged)
	}
}

// On a writable rootfs the wrapper points entrypoint processes at the in-place store,
// but exec'd processes resolve the bundle in the bind-mounted dynamic CA dir. Apply
// must refine that bundle too, or a container job step gets the plugin's seed (public
// roots, no org CA) and internal TLS fails.
func TestApplyWritableRootfsStagesMergedBundleForExecdProcesses(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=debian\n")

	storeCert := mustCreateTestCertPEM(t)
	storePath := filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt")
	mustMkdirAll(t, filepath.Dir(storePath))
	if err := os.WriteFile(storePath, storeCert, 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", storePath, err)
	}

	dynamicDir := t.TempDir()
	orgCert := mustCreateTestCertPEM(t)
	caPath := filepath.Join(dynamicDir, config.DynamicCAFileName)
	if err := os.WriteFile(caPath, orgCert, 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", caPath, err)
	}

	ctx := &hookapi.Context{
		Rootfs: rootfs,
		CAFile: caPath,
		Facts:  hookapi.NewMapFactStore(),
	}
	if err := NewDebian().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	staged, err := os.ReadFile(filepath.Join(dynamicDir, config.MergedCAFileName))
	if err != nil {
		t.Fatalf("merged bundle not staged for exec'd processes: %v", err)
	}
	if !bytes.Contains(staged, bytes.TrimSpace(orgCert)) {
		t.Fatalf("staged bundle is missing the org CA — internal TLS would fail under exec")
	}
	if !bytes.Contains(staged, bytes.TrimSpace(storeCert)) {
		t.Fatalf("staged bundle is missing the system roots — public TLS would break")
	}

	// The wrapper must keep using the in-place store, so entrypoint processes are
	// unchanged by this.
	if got, _ := ctx.Facts.Get(hookapi.FactMergedCAPath); got != "/etc/ssl/certs/ca-certificates.crt" {
		t.Fatalf("merged CA fact = %q, want the in-place store", got)
	}
}

func TestApplyReadOnlyRootfsStagesMergedBundle(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=ubuntu\nID_LIKE=debian\n")
	storeCert := mustCreateTestCertPEM(t)
	storePath := filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(storePath, storeCert, 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", storePath, err)
	}

	dynamicDir := t.TempDir()
	orgCert := mustCreateTestCertPEM(t)
	caPath := filepath.Join(dynamicDir, "ca-bundle.pem")
	if err := os.WriteFile(caPath, orgCert, 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", caPath, err)
	}

	// Make the rootfs read-only so Apply takes the RO branch.
	if err := os.Chmod(rootfs, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(rootfs, 0o755) })

	ctx := &hookapi.Context{
		Rootfs: rootfs,
		CAFile: caPath,
		Facts:  hookapi.NewMapFactStore(),
	}
	if err := NewDebian().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if v, _ := ctx.Facts.Get(hookapi.FactRootfsReadOnly); v != "true" {
		t.Fatalf("expected read-only rootfs fact, got %q", v)
	}
	// The fact must name the path as the container sees it — the dynamic CA dir is
	// bind-mounted at config.ContainerCADir. A host path here would be a dangling
	// SSL_CERT_FILE inside the container.
	gotMerged, ok := ctx.Facts.Get(hookapi.FactMergedCAPath)
	if !ok {
		t.Fatalf("missing fact %q", hookapi.FactMergedCAPath)
	}
	if gotMerged != config.ContainerMergedCA {
		t.Fatalf("merged CA path mismatch: got=%q want=%q", gotMerged, config.ContainerMergedCA)
	}
	if gotIndividual, _ := ctx.Facts.Get(hookapi.FactIndividualCAPath); gotIndividual != config.ContainerOrgCA {
		t.Fatalf("individual CA path mismatch: got=%q want=%q", gotIndividual, config.ContainerOrgCA)
	}

	// The bundle itself is written to the host-side dynamic CA dir.
	content, err := os.ReadFile(filepath.Join(dynamicDir, config.MergedCAFileName))
	if err != nil {
		t.Fatalf("ReadFile(merged): %v", err)
	}
	if !bytes.Contains(content, bytes.TrimSpace(storeCert)) || !bytes.Contains(content, bytes.TrimSpace(orgCert)) {
		t.Fatalf("merged bundle must contain both the system store and the org CA")
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

func mustMkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", p, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(link))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", link, target, err)
	}
}

func mustCreateTestCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "cainjekt-test-ca",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
