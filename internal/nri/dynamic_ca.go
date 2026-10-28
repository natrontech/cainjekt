package nri

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/natrontech/cainjekt/internal/config"
	"github.com/natrontech/cainjekt/pkg/certs"
	"github.com/natrontech/cainjekt/pkg/fsx"
)

// pluginTrustStore is the CA store of cainjekt's own image (distroless ships one).
// It seeds the merged bundle with public roots so that the trust-replacing env vars
// we put on the container spec are safe from the moment the container starts, even
// if the hook never gets to refine them with the container's own store.
const pluginTrustStore = "/etc/ssl/certs/ca-certificates.crt"

var unsafePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func stageDynamicCAFile(sourceCAFile, root string, ctr *api.Container) (string, []byte, error) {
	content, err := os.ReadFile(sourceCAFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read source CA file %s: %w", sourceCAFile, err)
	}
	if err := certs.ValidatePEM(content); err != nil {
		return "", nil, fmt.Errorf("invalid CA bundle %s: %w", sourceCAFile, err)
	}

	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return "", nil, err
	}
	// 0755/0644: this directory is bind-mounted into the container, which usually
	// runs as a non-root user and must be able to traverse it and read the bundles.
	// CA certificates are public material.
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("failed to create dynamic CA directory %s: %w", targetDir, err)
	}

	targetPath := filepath.Join(targetDir, config.DynamicCAFileName)
	if err := fsx.AtomicWrite(targetPath, content, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", nil, fmt.Errorf("failed to write dynamic CA file %s: %w", targetPath, err)
	}

	return targetPath, content, nil
}

// seedMergedCA writes <plugin image roots + org CA> to the merged bundle path, so the
// trust-replacing env vars on the container spec resolve to a complete bundle from the
// moment the container starts. The OCI hook overwrites this with <container's own store
// + org CA> once it has detected the distro; the seed only has to hold until then, and
// to be a safe fallback if the hook fails (fail-open).
func seedMergedCA(targetDir string, orgCA []byte) error {
	roots, err := os.ReadFile(pluginTrustStore)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to read plugin trust store %s: %w", pluginTrustStore, err)
		}
		// No roots to seed with: org CA alone still beats a dangling path.
		roots = nil
	}
	merged, err := certs.MergePEM(roots, orgCA)
	if err != nil {
		return err
	}
	target := filepath.Join(targetDir, config.MergedCAFileName)
	if err := fsx.AtomicWrite(target, merged.Merged, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return fmt.Errorf("failed to write seed merged CA bundle %s: %w", target, err)
	}
	return nil
}

func cleanupDynamicCAFile(root string, ctr *api.Container) error {
	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return err
	}
	err = os.RemoveAll(targetDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove dynamic CA directory %s: %w", targetDir, err)
	}
	return nil
}

func containerCADir(root string, ctr *api.Container) (string, error) {
	key, err := containerCAKey(ctr)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, key), nil
}

func containerCAKey(ctr *api.Container) (string, error) {
	id := sanitizePathToken(ctr.GetId())
	if id == "" {
		return "", errors.New("container id is empty")
	}
	return id, nil
}

func sanitizePathToken(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return ""
	}
	safe := unsafePathChars.ReplaceAllString(trimmed, "_")
	return strings.Trim(safe, "._-")
}

func dynamicCARoot() string {
	return getenvOr(config.EnvDynamicCARoot, config.DefaultDynamicCARoot)
}
