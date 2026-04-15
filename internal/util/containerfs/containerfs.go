// Package containerfs provides utilities for working with container rootfs paths.
package containerfs

import (
	"os"
	"path/filepath"
	"strings"
)

// PathInRootfs joins a container-absolute path onto the host rootfs mount.
func PathInRootfs(rootfs, containerPath string) string {
	trimmed := strings.TrimPrefix(containerPath, "/")
	return filepath.Join(rootfs, filepath.FromSlash(trimmed))
}

// HasAnyRegularFile returns true if any of the given container paths exist as regular files.
func HasAnyRegularFile(rootfs string, containerPaths []string) bool {
	for _, containerPath := range containerPaths {
		host := PathInRootfs(rootfs, containerPath)
		fi, err := os.Stat(host)
		if err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}
