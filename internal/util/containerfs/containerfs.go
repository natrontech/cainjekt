// Package containerfs provides utilities for working with container rootfs paths.
package containerfs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// PathInRootfs joins a container-absolute path onto the host rootfs mount.
func PathInRootfs(rootfs, containerPath string) string {
	trimmed := strings.TrimPrefix(containerPath, "/")
	return filepath.Join(rootfs, filepath.FromSlash(trimmed))
}

// HasAnyRegularFile returns true if any of the given container paths exist as regular files.
// Symlinks are resolved inside the rootfs so absolute targets (e.g. RHEL's
// /usr/bin/java -> /etc/alternatives/java) never escape to the host filesystem.
func HasAnyRegularFile(rootfs string, containerPaths []string) bool {
	for _, containerPath := range containerPaths {
		resolved, err := ResolveSymlinks(rootfs, containerPath)
		if err != nil {
			continue
		}
		fi, err := os.Lstat(PathInRootfs(rootfs, resolved))
		if err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// ResolveSymlinks resolves containerPath to a container-absolute path, following
// symlinks within the rootfs only: absolute targets are re-anchored to the rootfs
// instead of the host root. The returned path may not exist (dangling links and
// missing components resolve to their would-be location).
func ResolveSymlinks(rootfs, containerPath string) (string, error) {
	remaining := splitContainerPath(containerPath)
	resolved := make([]string, 0, len(remaining))
	const maxSymlinkHops = 40
	hops := 0

	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		candidate := "/" + strings.Join(append(append([]string{}, resolved...), part), "/")
		host := PathInRootfs(rootfs, candidate)
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
