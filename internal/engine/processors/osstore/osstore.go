// Package osstore provides OS-level CA trust store injection processors.
package osstore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/natrontech/cainjekt/internal/config"
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/pkg/certs"
)

const individualCAFileName = "cainjekt.crt"

type processor struct {
	name       string
	distro     string
	candidates []string
	anchorDir  string
	matchIDs   []string
	priority   int
	fallback   bool
}

// NewDebian returns a processor for Debian/Ubuntu-based distributions.
func NewDebian() hookapi.Processor {
	return &processor{
		name:       "os-debian",
		distro:     "debian",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		anchorDir:  "/usr/local/share/ca-certificates",
		matchIDs:   []string{"debian", "ubuntu"},
		priority:   300,
	}
}

// NewRHEL returns a processor for RHEL/Fedora/CentOS-based distributions.
func NewRHEL() hookapi.Processor {
	return &processor{
		name:       "os-rhel",
		distro:     "rhel",
		candidates: []string{"/etc/pki/tls/certs/ca-bundle.crt"},
		anchorDir:  "/etc/pki/ca-trust/source/anchors",
		matchIDs:   []string{"rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"},
		priority:   290,
	}
}

// NewOpenSUSE returns a processor for openSUSE/SLES-based distributions.
func NewOpenSUSE() hookapi.Processor {
	return &processor{
		name:       "os-opensuse",
		distro:     "opensuse",
		candidates: []string{"/etc/ssl/ca-bundle.pem"},
		anchorDir:  "/etc/pki/trust/anchors",
		matchIDs:   []string{"opensuse", "sles", "suse"},
		priority:   285,
	}
}

// NewAlpine returns a processor for Alpine Linux.
func NewAlpine() hookapi.Processor {
	return &processor{
		name:       "os-alpine",
		distro:     "alpine",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		anchorDir:  "/usr/local/share/ca-certificates",
		matchIDs:   []string{"alpine"},
		priority:   280,
	}
}

// NewArch returns a processor for Arch Linux.
func NewArch() hookapi.Processor {
	return &processor{
		name:       "os-arch",
		distro:     "arch",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		anchorDir:  "/etc/ca-certificates/trust-source/anchors",
		matchIDs:   []string{"arch"},
		priority:   275,
	}
}

// NewFallback returns a processor that tries common trust store paths when the distro is unknown.
func NewFallback() hookapi.Processor {
	return &processor{
		name:   "os-fallback",
		distro: "fallback",
		candidates: []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/ca-bundle.pem",
			"/etc/ssl/cert.pem",
		},
		priority: -100,
		fallback: true,
	}
}

func (p *processor) Name() string { return p.name }

func (p *processor) Category() string { return "os" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: p.priority, Reason: "missing context"}
	}
	info, err := readOSRelease(ctx.Rootfs)
	if err != nil {
		if p.fallback {
			return hookapi.DetectResult{Applicable: true, Priority: p.priority, Reason: "fallback: os-release not found"}
		}
		return hookapi.DetectResult{Applicable: false, Priority: p.priority, Reason: err.Error()}
	}
	if p.matches(info) {
		return hookapi.DetectResult{Applicable: true, Priority: p.priority}
	}
	if p.fallback {
		return hookapi.DetectResult{Applicable: true, Priority: p.priority, Reason: "fallback: unsupported distro"}
	}
	return hookapi.DetectResult{
		Applicable: false,
		Priority:   p.priority,
		Reason:     fmt.Sprintf("distro mismatch: id=%q id_like=%q", info.id, strings.Join(info.idLike, " ")),
	}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	if trustStoreConfigured(ctx) {
		return nil
	}

	orgCA, err := ctx.ReadCABundle()
	if err != nil {
		return err
	}

	target, err := detectTrustStorePath(ctx.Rootfs, p.candidates)
	if err != nil {
		return err
	}

	// Check if rootfs is writable before attempting modifications.
	if !containerfs.Writable(ctx.Rootfs) {
		ctx.Facts.Set(hookapi.FactRootfsReadOnly, "true")
		ctx.Facts.Set(hookapi.FactTrustStorePath, target)
		ctx.Facts.Set(hookapi.FactDistro, p.distro)
		// The store can't be merged in place; stage the merged bundle in the dynamic
		// CA dir instead. The facts must name the paths as the *container* sees them
		// (the dir is bind-mounted at config.ContainerCADir), not the host paths —
		// env vars pointing at /run/cainjekt/... resolve to nothing inside.
		if ctx.CAFile != "" {
			ctx.Facts.Set(hookapi.FactIndividualCAPath, config.ContainerOrgCA)
			if err := stageMergedCA(ctx, target, orgCA); err != nil {
				return err
			}
			ctx.Facts.Set(hookapi.FactMergedCAPath, config.ContainerMergedCA)
		}
		return nil
	}

	current, _, err := containerfs.ReadFile(ctx.Rootfs, target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to read trust store %s: %w", target, err)
	}

	merged, err := certs.MergePEM(current, orgCA)
	if err != nil {
		return err
	}

	if merged.Added > 0 {
		if _, err := containerfs.WriteFile(ctx.Rootfs, target, merged.Merged); err != nil {
			return fmt.Errorf("failed to write trust store: %w", err)
		}
		// Alpine images often use /etc/ssl/cert.pem as curl/OpenSSL default.
		if p.distro == "alpine" {
			if _, err := containerfs.WriteFile(ctx.Rootfs, "/etc/ssl/cert.pem", merged.Merged); err != nil {
				return fmt.Errorf("failed to write alpine default cert path: %w", err)
			}
		}
	}

	individualCAPath, err := writeIndividualCA(ctx.Rootfs, p.anchorDir, orgCA)
	if err != nil {
		return err
	}

	// Refine the bundle the container spec's trust env vars point at (seeded by the NRI
	// plugin with this image's roots) to the container's own store + the org CA. The
	// wrapper keeps using the in-place store below, so entrypoint processes are
	// unaffected; this is what processes started via exec resolve to.
	if ctx.CAFile != "" {
		if err := stageMergedCA(ctx, target, orgCA); err != nil {
			return err
		}
	}

	ctx.Facts.Set(hookapi.FactTrustStorePath, target)
	ctx.Facts.Set(hookapi.FactTrustStoreKind, "bundle")
	ctx.Facts.Set(hookapi.FactDistro, p.distro)
	// The in-place merged store doubles as the bundle for trust-replacing env vars.
	ctx.Facts.Set(hookapi.FactMergedCAPath, target)
	if individualCAPath != "" {
		ctx.Facts.Set(hookapi.FactIndividualCAPath, individualCAPath)
	}
	return nil
}

func trustStoreConfigured(ctx *hookapi.Context) bool {
	if ctx == nil || ctx.Facts == nil {
		return false
	}
	v, ok := ctx.Facts.Get(hookapi.FactTrustStorePath)
	return ok && strings.TrimSpace(v) != ""
}

// detectTrustStorePath returns the resolved container path of the first
// candidate that is a regular file, else of the first candidate.
func detectTrustStorePath(rootfs string, candidates []string) (string, error) {
	for _, c := range candidates {
		if resolved, ok := containerfs.RegularFile(rootfs, c); ok {
			return resolved, nil
		}
	}
	if len(candidates) > 0 {
		return containerfs.ResolveSymlinks(rootfs, candidates[0])
	}
	return "", errors.New("no known trust store path found in rootfs")
}

type osRelease struct {
	id     string
	idLike []string
}

func readOSRelease(rootfs string) (osRelease, error) {
	for _, c := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, resolved, err := containerfs.ReadFile(rootfs, c)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return osRelease{}, fmt.Errorf("failed to read os-release %s: %w", c, err)
		}
		info, err := parseOSRelease(bytes.NewReader(b))
		if err != nil {
			return osRelease{}, fmt.Errorf("failed to parse os-release %s: %w", resolved, err)
		}
		if info.id == "" {
			return osRelease{}, fmt.Errorf("os-release %s has empty ID", resolved)
		}
		return info, nil
	}
	return osRelease{}, errors.New("os-release not found")
}

func parseOSRelease(r io.Reader) (osRelease, error) {
	var out osRelease
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := normalizeOSReleaseValue(strings.TrimSpace(v))
		switch key {
		case "ID":
			out.id = strings.ToLower(val)
		case "ID_LIKE":
			out.idLike = append(out.idLike, strings.Fields(strings.ToLower(val))...)
		}
	}
	if err := sc.Err(); err != nil {
		return osRelease{}, err
	}
	return out, nil
}

func normalizeOSReleaseValue(v string) string {
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		v = v[1 : len(v)-1]
	}
	return strings.TrimSpace(v)
}

// stageMergedCA writes <container's own store + org CA> into the per-container dynamic
// CA dir, which the NRI plugin bind-mounts at config.ContainerCADir. This is the bundle
// the spec's trust env vars resolve to, so it is what processes started via exec use.
// The plugin seeds it with this image's roots; here we refine it with the container's
// actual store. No-op when the rootfs has no store to merge with — the seed then stands.
func stageMergedCA(ctx *hookapi.Context, store string, orgCA []byte) error {
	current, _, err := containerfs.ReadFile(ctx.Rootfs, store)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read trust store %s: %w", store, err)
	}
	merged, err := certs.MergePEM(current, orgCA)
	if err != nil {
		return err
	}
	_, err = ctx.StageFile(config.MergedCAFileName, merged.Merged)
	return err
}

func writeIndividualCA(rootfs, anchorDir string, content []byte) (string, error) {
	if anchorDir == "" {
		return "", nil
	}
	resolved, err := containerfs.WriteFile(rootfs, path.Join(anchorDir, individualCAFileName), content)
	if err != nil {
		return "", fmt.Errorf("failed to write individual CA file: %w", err)
	}
	return resolved, nil
}

func (p *processor) matches(info osRelease) bool {
	ids := map[string]struct{}{}
	if info.id != "" {
		ids[info.id] = struct{}{}
	}
	for _, like := range info.idLike {
		if like != "" {
			ids[like] = struct{}{}
		}
	}
	for _, id := range p.matchIDs {
		if _, ok := ids[id]; ok {
			return true
		}
	}
	return false
}
