package nri

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/tsuzu/cainjekt/internal/config"
	"github.com/tsuzu/cainjekt/pkg/fsx"
)

const dynamicCAFileName = "ca-bundle.pem"

var unsafePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func stageDynamicCAFile(sourceCAFile, root string, ctr *api.Container) (string, error) {
	content, err := os.ReadFile(sourceCAFile)
	if err != nil {
		return "", fmt.Errorf("failed to read source CA file %s: %w", sourceCAFile, err)
	}

	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create dynamic CA directory %s: %w", targetDir, err)
	}

	targetPath := filepath.Join(targetDir, dynamicCAFileName)
	if err := fsx.AtomicWrite(targetPath, content, fsx.WriteOptions{
		FallbackMode:  0o600,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", fmt.Errorf("failed to write dynamic CA file %s: %w", targetPath, err)
	}

	return targetPath, nil
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
	if ctr == nil {
		return "", errors.New("container is nil")
	}
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
