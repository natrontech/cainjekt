// Package java provides a Java CA injection processor.
package java

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/envutil"
	"github.com/natrontech/cainjekt/pkg/fsx"
	"github.com/natrontech/cainjekt/pkg/javakeystore"
)

const (
	processorName        = "lang-java"
	processorPriority    = 100
	envJavaToolOptions   = "JAVA_TOOL_OPTIONS"
	aliasPrefix          = "cainjekt-"
	stagedStoreName      = "cacerts"
	missingContextReason = "missing context"
	javaNotFoundReason   = "no java runtime found"
)

type processor struct{}

// New returns a Java CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if len(javaHomes(ctx.Rootfs, ctx.Env)) > 0 || len(discoverTrustStores(ctx.Rootfs, ctx.Env)) > 0 {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: javaNotFoundReason}
}

// Apply adds the organisation CA to every cacerts found in the rootfs. The JVM
// reads its trust store as a JKS or PKCS#12 keystore, so the PEM bundle the OS
// processors maintain is invisible to it — the keystore has to be rewritten.
//
// Patching in place means the default trust store lookup finds the CA, so no
// JVM flags are needed and applications keep whatever trust store settings they
// already have. When the rootfs is read-only the merged store is staged on the
// per-container CA path instead and the wrapper points the JVM at it.
func (p *processor) Apply(ctx *hookapi.Context) error {
	if ctx == nil {
		return nil
	}
	orgCerts, err := readPEMCerts(ctx.CAFile)
	if err != nil {
		return err
	}
	if len(orgCerts) == 0 {
		return nil
	}

	stores := discoverTrustStores(ctx.Rootfs, ctx.Env)
	if len(stores) == 0 {
		return nil
	}

	var (
		patched     int
		pending     []byte
		pendingKind javakeystore.Format
		lastErr     error
	)
	for _, s := range stores {
		merged, format, err := mergeStore(s.host, orgCerts)
		if err != nil {
			lastErr = fmt.Errorf("trust store %s: %w", s.container, err)
			continue
		}
		if merged == nil {
			patched++ // CA already trusted, nothing to rewrite
			continue
		}
		if err := fsx.AtomicWrite(s.host, merged, fsx.WriteOptions{
			FallbackMode:  0o644,
			RefuseSymlink: true,
			PreserveOwner: true,
		}); err != nil {
			// Read-only rootfs, or a path we may not replace. Keep the merged
			// store so it can be staged outside the rootfs instead.
			lastErr = fmt.Errorf("trust store %s: %w", s.container, err)
			if pending == nil {
				pending, pendingKind = merged, format
			}
			continue
		}
		patched++
	}

	if patched > 0 {
		return nil
	}
	if pending == nil {
		return lastErr
	}

	staged, err := stageTrustStore(ctx, pending, pendingKind)
	if err != nil {
		return err
	}
	ctx.Facts.Set(hookapi.FactJavaTrustStorePath, staged)
	ctx.Facts.Set(hookapi.FactJavaTrustStoreType, pendingKind.String())
	return nil
}

// ApplyWrapper points the JVM at the staged trust store. It is a no-op when the
// container's own cacerts was patched: the default lookup already finds the CA,
// and overriding javax.net.ssl.trustStore would shadow whatever the application
// configured for itself.
func (p *processor) ApplyWrapper(ctx *hookapi.Context) error {
	if ctx == nil || ctx.Facts == nil {
		return nil
	}
	store, _ := ctx.Facts.Get(hookapi.FactJavaTrustStorePath)
	if strings.TrimSpace(store) == "" {
		return nil
	}
	storeType, _ := ctx.Facts.Get(hookapi.FactJavaTrustStoreType)
	if strings.TrimSpace(storeType) == "" {
		storeType = javakeystore.FormatJKS.String()
	}

	flags := "-Djavax.net.ssl.trustStore=" + store + " -Djavax.net.ssl.trustStoreType=" + storeType
	if existing := envutil.GetValue(ctx.Env, envJavaToolOptions); existing != "" {
		flags = existing + " " + flags
	}
	ctx.Env = envutil.Upsert(ctx.Env, envJavaToolOptions, flags)
	return nil
}

// mergeStore returns the re-encoded trust store with the missing certificates
// added, or nil when they are all trusted already.
func mergeStore(hostPath string, add []*x509.Certificate) ([]byte, javakeystore.Format, error) {
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, javakeystore.FormatUnknown, fmt.Errorf("failed to read trust store: %w", err)
	}
	format, entries, err := javakeystore.Parse(data)
	if err != nil {
		return nil, format, err
	}

	present := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		present[fingerprint(e.Cert)] = struct{}{}
	}

	added := 0
	for _, c := range add {
		fp := fingerprint(c)
		if _, ok := present[fp]; ok {
			continue
		}
		present[fp] = struct{}{}
		// Fingerprint-derived alias so re-running the hook is idempotent.
		entries = append(entries, javakeystore.Entry{Alias: aliasPrefix + fp[:16], Cert: c})
		added++
	}
	if added == 0 {
		return nil, format, nil
	}

	out, err := javakeystore.Encode(format, entries)
	if err != nil {
		return nil, format, err
	}
	return out, format, nil
}

func stageTrustStore(ctx *hookapi.Context, data []byte, format javakeystore.Format) (string, error) {
	if strings.TrimSpace(ctx.CAFile) == "" {
		return "", errors.New("cannot stage java trust store: no CA file path")
	}
	target := filepath.Join(filepath.Dir(ctx.CAFile), stagedStoreName)
	if err := fsx.AtomicWrite(target, data, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", fmt.Errorf("failed to stage java trust store %s (%s): %w", target, format, err)
	}
	return target, nil
}

func readPEMCerts(pemPath string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file %s: %w", pemPath, err)
	}
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in %s: %w", pemPath, err)
		}
		out = append(out, cert)
	}
	return out, nil
}

func fingerprint(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
