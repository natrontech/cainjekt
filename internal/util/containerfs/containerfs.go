package containerfs

import (
	"os"
	"path/filepath"
	"strings"
)

func PathInRootfs(rootfs, containerPath string) string {
	trimmed := strings.TrimPrefix(containerPath, "/")
	return filepath.Join(rootfs, filepath.FromSlash(trimmed))
}

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
