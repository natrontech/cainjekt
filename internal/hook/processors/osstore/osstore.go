package osstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	hookapi "github.com/tsuzu/cainjekt/internal/hook/api"
	"github.com/tsuzu/cainjekt/pkg/certs"
	"github.com/tsuzu/cainjekt/pkg/fsx"
)

type processor struct {
	name       string
	distro     string
	candidates []string
	priority   int
	fallback   bool
}

func NewDebian() hookapi.Processor {
	return &processor{
		name:       "os-debian",
		distro:     "debian",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		priority:   300,
	}
}

func NewRHEL() hookapi.Processor {
	return &processor{
		name:       "os-rhel",
		distro:     "rhel",
		candidates: []string{"/etc/pki/tls/certs/ca-bundle.crt"},
		priority:   290,
	}
}

func NewAlpine() hookapi.Processor {
	return &processor{
		name:       "os-alpine",
		distro:     "alpine",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		priority:   280,
	}
}

func NewFallback() hookapi.Processor {
	return &processor{
		name:       "os-fallback",
		distro:     "fallback",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"},
		priority:   -100,
		fallback:   true,
	}
}

func (p *processor) Name() string { return p.name }

func (p *processor) Stage() hookapi.Stage { return hookapi.StageOS }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	_, _, err := detectTrustStorePath(ctx.Rootfs, p.candidates)
	if err == nil {
		return hookapi.DetectResult{Applicable: true, Priority: p.priority}
	}
	if p.fallback {
		return hookapi.DetectResult{Applicable: true, Priority: p.priority, Reason: "fallback"}
	}
	return hookapi.DetectResult{Applicable: false, Priority: p.priority, Reason: err.Error()}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	orgCA, err := os.ReadFile(ctx.CAFile)
	if err != nil {
		return fmt.Errorf("failed to read CA bundle file %s: %w", ctx.CAFile, err)
	}

	targetHost, targetContainer, err := detectTrustStorePath(ctx.Rootfs, p.candidates)
	if err != nil {
		return err
	}

	current, err := os.ReadFile(targetHost)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to read trust store %s: %w", targetHost, err)
	}

	merged, err := certs.MergePEM(current, orgCA)
	if err != nil {
		return err
	}

	if merged.Added > 0 {
		if err := os.MkdirAll(filepath.Dir(targetHost), 0o755); err != nil {
			return fmt.Errorf("failed to create trust store directory %s: %w", filepath.Dir(targetHost), err)
		}
		if err := fsx.AtomicWrite(targetHost, merged.Merged, fsx.WriteOptions{
			FallbackMode:  0o644,
			RefuseSymlink: true,
			PreserveOwner: true,
		}); err != nil {
			return fmt.Errorf("failed to write trust store %s: %w", targetHost, err)
		}
		// Alpine images often use /etc/ssl/cert.pem as curl/OpenSSL default.
		if p.distro == "alpine" {
			altContainer := "/etc/ssl/cert.pem"
			altHost := pathInRootfs(ctx.Rootfs, altContainer)
			if err := os.MkdirAll(filepath.Dir(altHost), 0o755); err != nil {
				return fmt.Errorf("failed to create alpine cert path %s: %w", filepath.Dir(altHost), err)
			}
			if err := fsx.AtomicWrite(altHost, merged.Merged, fsx.WriteOptions{
				FallbackMode:  0o644,
				RefuseSymlink: true,
				PreserveOwner: true,
			}); err != nil {
				return fmt.Errorf("failed to write alpine default cert path %s: %w", altHost, err)
			}
		}
	}

	ctx.Facts.Set(hookapi.FactTrustStorePath, targetContainer)
	ctx.Facts.Set(hookapi.FactTrustStoreKind, "bundle")
	ctx.Facts.Set(hookapi.FactDistro, p.distro)
	return nil
}

func detectTrustStorePath(rootfs string, candidates []string) (hostPath, containerPath string, err error) {
	for _, p := range candidates {
		host := pathInRootfs(rootfs, p)
		fi, statErr := os.Stat(host)
		if statErr == nil && fi.Mode().IsRegular() {
			return host, p, nil
		}
	}

	if len(candidates) > 0 {
		host := pathInRootfs(rootfs, candidates[0])
		return host, candidates[0], nil
	}
	return "", "", errors.New("no known trust store path found in rootfs")
}

func pathInRootfs(rootfs, containerPath string) string {
	trimmed := containerPath
	if len(trimmed) > 0 && trimmed[0] == '/' {
		trimmed = trimmed[1:]
	}
	return filepath.Join(rootfs, filepath.FromSlash(trimmed))
}
