package processors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/runtime/hookctx"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
)

// TestHostileRootfs runs every registered processor, and the hook-context
// write, against an image built to attack the hook: links that point out of
// the rootfs (absolute and relative), FIFOs, an oversized file and a link loop.
// It pins the invariants of the threat model in docs/architecture.md:
//
//   - nothing outside the rootfs and the staging dir is created or modified
//   - the hook never blocks
//
// A new processor is covered as soon as it is registered.
func TestHostileRootfs(t *testing.T) {
	for _, distro := range []string{"debian", "rhel", "alpine", "opensuse", "arch", "unknown"} {
		for _, readOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/readonly=%t", distro, readOnly), func(t *testing.T) {
				t.Parallel()
				runHostile(t, distro, readOnly)
			})
		}
	}
}

func runHostile(t *testing.T, distro string, readOnly bool) {
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	host := filepath.Join(tmp, "host") // stands in for the node's filesystem
	stage := filepath.Join(tmp, "stage")
	buildHostRoot(t, host)
	buildHostileRootfs(t, rootfs, host, distro)
	mustMkdir(t, stage)
	caFile := filepath.Join(stage, "ca-bundle.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if readOnly {
		// Fails the rootfs writability probe (for a non-root test run), which
		// sends processors down the staging path.
		if err := os.Chmod(rootfs, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(rootfs, 0o755) })
	}

	before := snapshot(t, tmp, rootfs, stage)

	ctx := &hookapi.Context{
		Rootfs: rootfs,
		CAFile: caFile,
		Env:    []string{"JAVA_HOME=" + host},
		Facts:  hookapi.NewMapFactStore(),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Apply every processor whether or not it detected: detection is
		// driven by the image, so each code path must be safe regardless.
		for _, p := range Default() {
			_ = p.Detect(ctx)
			_ = p.Apply(ctx)
		}
		_ = hookctx.Write(rootfs, hookctx.NewStateFromContext(ctx, nil))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("hook blocked on a hostile rootfs")
	}

	after := snapshot(t, tmp, rootfs, stage)
	for p, v := range after {
		if before[p] != v {
			t.Errorf("hook wrote outside the rootfs: %s", p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("hook removed a file outside the rootfs: %s", p)
		}
	}
}

// buildHostRoot creates bait files where an escaping processor would land.
func buildHostRoot(t *testing.T, host string) {
	t.Helper()
	for _, f := range []string{
		"etc/ssl/certs/ca-certificates.crt",
		"pki/tls/certs/ca-bundle.crt",
		"pki/java/cacerts",
		"ca-certificates/keep",
		"cainjekt/keep",
		"bin/java",
		"lib/security/cacerts",
		"os-release",
	} {
		p := filepath.Join(host, f)
		mustMkdir(t, filepath.Dir(p))
		if err := os.WriteFile(p, []byte("host "+f+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func buildHostileRootfs(t *testing.T, rootfs, host, distro string) {
	t.Helper()
	in := func(p string) string { return filepath.Join(rootfs, p) }
	for _, d := range []string{"etc/ssl", "usr/local/share", "usr/bin", "usr/lib/jvm", "usr/local", "opt"} {
		mustMkdir(t, in(d))
	}
	if distro == "unknown" {
		// os-release pointing at the node's own.
		mustSymlink(t, filepath.Join(host, "os-release"), in("etc/os-release"))
	} else {
		if err := os.WriteFile(in("etc/os-release"), []byte("ID="+distro+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Absolute links to host paths: must be re-anchored inside the rootfs.
	mustSymlink(t, filepath.Join(host, "etc/ssl/certs"), in("etc/ssl/certs"))
	mustSymlink(t, filepath.Join(host, "ca-certificates"), in("usr/local/share/ca-certificates"))
	mustSymlink(t, filepath.Join(host, "bin/java"), in("usr/bin/java"))
	mustSymlink(t, host, in("opt/evil"))
	// Relative links that climb out: must be clamped at the rootfs root.
	mustSymlink(t, "../../host/pki", in("etc/pki"))
	mustSymlink(t, "../../host/cainjekt", in("etc/cainjekt"))
	mustSymlink(t, "../../../host", in("usr/lib/jvm/evil"))
	// Non-regular files where trust stores are read. The escaping links above
	// resolve to these re-anchored paths, so the reads really hit them.
	for _, p := range []string{
		filepath.Join(host, "etc/ssl/certs/ca-certificates.crt"), // debian, alpine, arch
		"host/pki/tls/certs/ca-bundle.crt",                       // rhel
	} {
		mustMkdir(t, filepath.Dir(in(p)))
		mustFIFO(t, in(p))
	}
	mustFIFO(t, in("etc/ssl/cert.pem"))
	mustFIFO(t, in("usr/bin/node"))
	// Oversized (sparse) trust store.
	big := in("etc/ssl/ca-bundle.pem")
	if err := os.WriteFile(big, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, containerfs.MaxReadSize+1); err != nil {
		t.Fatal(err)
	}
	// Link loop.
	mustSymlink(t, "/usr/local/go", in("usr/local/go"))
}

// snapshot records every entry under dir except the rootfs and staging dir.
func snapshot(t *testing.T, dir string, skip ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		for _, s := range skip {
			if p == s {
				return filepath.SkipDir
			}
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		out[strings.TrimPrefix(p, dir)] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cainjekt hostile test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func mustFIFO(t *testing.T, p string) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Fatal(err)
	}
}
