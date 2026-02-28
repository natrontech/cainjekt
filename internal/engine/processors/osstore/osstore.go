package osstore

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/pkg/certs"
	"github.com/tsuzu/cainjekt/pkg/fsx"
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
			altHost, _, err := resolveContainerPath(ctx.Rootfs, "/etc/ssl/cert.pem")
			if err != nil {
				return fmt.Errorf("failed to resolve alpine cert path %s: %w", "/etc/ssl/cert.pem", err)
			}
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

	individualCAPath, err := writeIndividualCA(ctx.Rootfs, p.anchorDir, orgCA)
	if err != nil {
		return err
	}

	ctx.Facts.Set(hookapi.FactTrustStorePath, targetContainer)
	ctx.Facts.Set(hookapi.FactTrustStoreKind, "bundle")
	ctx.Facts.Set(hookapi.FactDistro, p.distro)
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

func detectTrustStorePath(rootfs string, candidates []string) (hostPath, containerPath string, err error) {
	for _, p := range candidates {
		host, resolved, resolveErr := resolveContainerPath(rootfs, p)
		if resolveErr != nil {
			continue
		}
		fi, statErr := os.Stat(host)
		if statErr == nil && fi.Mode().IsRegular() {
			return host, resolved, nil
		}
	}

	if len(candidates) > 0 {
		host, resolved, resolveErr := resolveContainerPath(rootfs, candidates[0])
		if resolveErr != nil {
			return "", "", resolveErr
		}
		return host, resolved, nil
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

type osRelease struct {
	id     string
	idLike []string
}

func readOSRelease(rootfs string) (osRelease, error) {
	candidates := []string{
		pathInRootfs(rootfs, "/etc/os-release"),
		pathInRootfs(rootfs, "/usr/lib/os-release"),
	}
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return osRelease{}, fmt.Errorf("failed to open os-release %s: %w", p, err)
		}
		info, err := parseOSRelease(f)
		_ = f.Close()
		if err != nil {
			return osRelease{}, fmt.Errorf("failed to parse os-release %s: %w", p, err)
		}
		if info.id == "" {
			return osRelease{}, fmt.Errorf("os-release %s has empty ID", p)
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
			for _, token := range strings.Fields(strings.ToLower(val)) {
				out.idLike = append(out.idLike, token)
			}
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

func writeIndividualCA(rootfs, anchorDir string, content []byte) (string, error) {
	if anchorDir == "" {
		return "", nil
	}
	targetContainer := path.Join(anchorDir, individualCAFileName)
	targetHost, resolvedContainer, err := resolveContainerPath(rootfs, targetContainer)
	if err != nil {
		return "", fmt.Errorf("failed to resolve individual CA path %s: %w", targetContainer, err)
	}
	if err := os.MkdirAll(filepath.Dir(targetHost), 0o755); err != nil {
		return "", fmt.Errorf("failed to create individual CA directory %s: %w", filepath.Dir(targetHost), err)
	}
	if err := fsx.AtomicWrite(targetHost, content, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", fmt.Errorf("failed to write individual CA file %s: %w", resolvedContainer, err)
	}
	return resolvedContainer, nil
}

func resolveContainerPath(rootfs, containerPath string) (hostPath, resolvedContainerPath string, err error) {
	resolved, err := resolveContainerSymlinks(rootfs, containerPath)
	if err != nil {
		return "", "", err
	}
	return pathInRootfs(rootfs, resolved), resolved, nil
}

func resolveContainerSymlinks(rootfs, containerPath string) (string, error) {
	remaining := splitContainerPath(containerPath)
	resolved := make([]string, 0, len(remaining))
	const maxSymlinkHops = 40
	hops := 0

	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		candidate := "/" + strings.Join(append(append([]string{}, resolved...), part), "/")
		host := pathInRootfs(rootfs, candidate)
		fi, statErr := os.Lstat(host)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				resolved = append(resolved, part)
				resolved = append(resolved, remaining...)
				remaining = nil
				break
			}
			return "", fmt.Errorf("failed to stat %s: %w", candidate, statErr)
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, part)
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return "", fmt.Errorf("too many symlink hops while resolving %s", containerPath)
		}
		target, readErr := os.Readlink(host)
		if readErr != nil {
			return "", fmt.Errorf("failed to read symlink %s: %w", candidate, readErr)
		}

		base := "/" + strings.Join(resolved, "/")
		targetContainer := path.Clean(path.Join(base, target))
		if path.IsAbs(target) {
			targetContainer = path.Clean(target)
		}

		remaining = append(splitContainerPath(targetContainer), remaining...)
		resolved = resolved[:0]
	}

	if len(resolved) == 0 {
		return "/", nil
	}
	return "/" + strings.Join(resolved, "/"), nil
}

func splitContainerPath(p string) []string {
	clean := path.Clean("/" + strings.TrimSpace(p))
	if clean == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(clean, "/"), "/")
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
