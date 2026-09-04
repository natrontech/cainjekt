package java

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/testutil"
	"github.com/natrontech/cainjekt/pkg/javakeystore"
)

const jvmHome = "/usr/lib/jvm/java-17-openjdk"

func TestDetectApplicableWhenJavaExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")

	got := New().Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectApplicableWhenJavaIsAbsoluteSymlinkChain(t *testing.T) {
	t.Parallel()

	// RHEL alternatives layout: /usr/bin/java -> /etc/alternatives/java -> real
	// binary, all absolute symlinks. Resolution must stay inside the rootfs.
	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, jvmHome+"/bin/java")
	testutil.SymlinkInRootfs(t, rootfs, "/etc/alternatives/java", jvmHome+"/bin/java")
	testutil.SymlinkInRootfs(t, rootfs, "/usr/bin/java", "/etc/alternatives/java")

	got := New().Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

// jlink runtimes put the launcher somewhere only JAVA_HOME knows about.
func TestDetectApplicableFromJavaHomeEnv(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeTrustStore(t, rootfs, "/app/runtime/lib/security/cacerts", javakeystore.FormatJKS)

	got := New().Detect(&hookapi.Context{Rootfs: rootfs, Env: []string{"JAVA_HOME=/app/runtime"}})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenJavaDoesNotExist(t *testing.T) {
	t.Parallel()

	got := New().Detect(&hookapi.Context{Rootfs: t.TempDir()})
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
	if got.Reason != javaNotFoundReason {
		t.Fatalf("Detect() reason mismatch: got=%q want=%q", got.Reason, javaNotFoundReason)
	}
}

func TestDetectNotApplicableWhenContextIsNil(t *testing.T) {
	t.Parallel()

	got := New().Detect(nil)
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
	if got.Reason != missingContextReason {
		t.Fatalf("Detect() reason mismatch: got=%q want=%q", got.Reason, missingContextReason)
	}
}

func TestApplyAddsCAToCacerts(t *testing.T) {
	t.Parallel()

	for _, format := range []javakeystore.Format{javakeystore.FormatJKS, javakeystore.FormatPKCS12} {
		t.Run(format.String(), func(t *testing.T) {
			t.Parallel()

			rootfs := t.TempDir()
			store := jvmHome + "/lib/security/cacerts"
			testutil.WriteExecutableInRootfs(t, rootfs, jvmHome+"/bin/java")
			testutil.SymlinkInRootfs(t, rootfs, "/usr/bin/java", jvmHome+"/bin/java")
			writeTrustStore(t, rootfs, store, format)

			ctx := newContext(t, rootfs)
			if err := New().Apply(ctx); err != nil {
				t.Fatalf("Apply() error = %v", err)
			}

			gotFormat, entries := readTrustStore(t, filepath.Join(rootfs, strings.TrimPrefix(store, "/")))
			if gotFormat != format {
				t.Fatalf("Apply() changed keystore format: got=%s want=%s", gotFormat, format)
			}
			if len(entries) != 2 {
				t.Fatalf("Apply() wrote %d entries, want 2 (existing root + org CA)", len(entries))
			}
			if !hasCommonName(entries, "cainjekt-test-ca") {
				t.Fatalf("Apply() did not add the org CA: %v", aliases(entries))
			}

			// Wrapper stays out of the way once cacerts itself is patched.
			ctx.Env = []string{"PATH=/usr/bin"}
			if err := New().(*processor).ApplyWrapper(ctx); err != nil {
				t.Fatalf("ApplyWrapper() error = %v", err)
			}
			if got := testutil.EnvValue(ctx.Env, envJavaToolOptions); got != "" {
				t.Fatalf("env %q should not be set after in-place patch: got=%q", envJavaToolOptions, got)
			}
		})
	}
}

// The JDK's cacerts is normally a symlink into the distro trust store; the
// hook must patch the target, not replace the link.
func TestApplyFollowsCacertsSymlinkToDistroStore(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
	writeTrustStore(t, rootfs, "/etc/pki/ca-trust/extracted/java/cacerts", javakeystore.FormatJKS)
	testutil.SymlinkInRootfs(t, rootfs, "/etc/pki/java/cacerts", "/etc/pki/ca-trust/extracted/java/cacerts")
	testutil.SymlinkInRootfs(t, rootfs, jvmHome+"/lib/security/cacerts", "/etc/pki/java/cacerts")

	if err := New().Apply(newContext(t, rootfs)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	link := filepath.Join(rootfs, "etc/pki/java/cacerts")
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Apply() replaced the symlink %s: err=%v", link, err)
	}
	_, entries := readTrustStore(t, filepath.Join(rootfs, "etc/pki/ca-trust/extracted/java/cacerts"))
	if !hasCommonName(entries, "cainjekt-test-ca") {
		t.Fatalf("Apply() did not patch the symlink target: %v", aliases(entries))
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	store := jvmHome + "/lib/security/cacerts"
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
	writeTrustStore(t, rootfs, store, javakeystore.FormatJKS)
	hostStore := filepath.Join(rootfs, strings.TrimPrefix(store, "/"))

	ctx := newContext(t, rootfs)
	if err := New().Apply(ctx); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	first, err := os.ReadFile(hostStore)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if err := New().Apply(newContext2(t, rootfs, ctx.CAFile)); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	second, err := os.ReadFile(hostStore)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("Apply() rewrote the trust store on a second run")
	}
}

func TestApplyStagesStoreWhenCacertsIsNotWritable(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	rootfs := t.TempDir()
	store := jvmHome + "/lib/security/cacerts"
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
	writeTrustStore(t, rootfs, store, javakeystore.FormatJKS)

	securityDir := filepath.Join(rootfs, strings.TrimPrefix(filepath.Dir(store), "/"))
	if err := os.Chmod(securityDir, 0o555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(securityDir, 0o755) })

	ctx := newContext(t, rootfs)
	if err := New().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	staged, ok := ctx.Facts.Get(hookapi.FactJavaTrustStorePath)
	if !ok || staged == "" {
		t.Fatal("Apply() did not stage a trust store")
	}
	_, entries := readTrustStore(t, staged)
	if !hasCommonName(entries, "cainjekt-test-ca") {
		t.Fatalf("staged store is missing the org CA: %v", aliases(entries))
	}

	ctx.Env = []string{"JAVA_TOOL_OPTIONS=-Xmx512m"}
	if err := New().(*processor).ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}
	got := testutil.EnvValue(ctx.Env, envJavaToolOptions)
	if !strings.HasPrefix(got, "-Xmx512m ") {
		t.Fatalf("env %q should preserve existing flags: got=%q", envJavaToolOptions, got)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStore="+staged) {
		t.Fatalf("env %q missing trustStore flag: got=%q", envJavaToolOptions, got)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStoreType=JKS") {
		t.Fatalf("env %q missing trustStoreType flag: got=%q", envJavaToolOptions, got)
	}
}

func TestApplyWrapperNoopWithoutStagedStore(t *testing.T) {
	t.Parallel()

	ctx := &hookapi.Context{Env: []string{"PATH=/usr/bin"}, Facts: hookapi.NewMapFactStore()}
	if err := New().(*processor).ApplyWrapper(ctx); err != nil {
		t.Fatalf("ApplyWrapper() error = %v", err)
	}
	if got := testutil.EnvValue(ctx.Env, envJavaToolOptions); got != "" {
		t.Fatalf("env %q should not be set: got=%q", envJavaToolOptions, got)
	}
}

func newContext(t *testing.T, rootfs string) *hookapi.Context {
	t.Helper()
	return newContext2(t, rootfs, writeCAFile(t))
}

func newContext2(t *testing.T, rootfs, caFile string) *hookapi.Context {
	t.Helper()
	return &hookapi.Context{Rootfs: rootfs, CAFile: caFile, Facts: hookapi.NewMapFactStore()}
}

// writeCAFile writes the org CA PEM into a stand-in for the per-container
// dynamic CA directory, which is also where a staged keystore lands.
func writeCAFile(t *testing.T) string {
	t.Helper()

	cert := newTestCert(t, "cainjekt-test-ca")
	caFile := filepath.Join(t.TempDir(), "ca-bundle.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(caFile, block, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return caFile
}

func writeTrustStore(t *testing.T, rootfs, containerPath string, format javakeystore.Format) {
	t.Helper()

	data, err := javakeystore.Encode(format, []javakeystore.Entry{
		{Alias: "existing-root", Cert: newTestCert(t, "existing-root")},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	host := filepath.Join(rootfs, strings.TrimPrefix(containerPath, "/"))
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(host, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func readTrustStore(t *testing.T, hostPath string) (javakeystore.Format, []javakeystore.Entry) {
	t.Helper()

	data, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", hostPath, err)
	}
	format, entries, err := javakeystore.Parse(data)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", hostPath, err)
	}
	return format, entries
}

func hasCommonName(entries []javakeystore.Entry, cn string) bool {
	for _, e := range entries {
		if e.Cert != nil && e.Cert.Subject.CommonName == cn {
			return true
		}
	}
	return false
}

func aliases(entries []javakeystore.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Alias)
	}
	return out
}

func newTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert
}
