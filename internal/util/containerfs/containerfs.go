// Package containerfs provides utilities for working with container rootfs paths.
package containerfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/natrontech/cainjekt/pkg/fsx"
)

// MaxReadSize caps reads of files that come from a container image. Real trust
// stores are well under 1 MiB; the cap only stops an image from making the hook
// read without bound.
const MaxReadSize = 16 << 20

// ReadRegularFile reads a file inside a container rootfs from the host. The
// hook runs as root outside the container's device cgroup, so the image must
// not be able to point it at a FIFO (blocks until the hook is killed) or a
// device node (reads node devices, and the bytes may be written back into the
// container). hostPath must already be resolved with ResolveSymlinks.
//
// A missing file returns an error wrapping os.ErrNotExist.
func ReadRegularFile(hostPath string) ([]byte, error) {
	// Lstat first so a device node is never opened: opening some devices has
	// side effects of its own.
	fi, err := os.Lstat(hostPath)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read %s: not a regular file (%s)", hostPath, fi.Mode().Type())
	}

	f, err := os.OpenFile(hostPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// Re-check on the open file in case the entry was swapped after Lstat.
	if fi, err = f.Stat(); err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read %s: not a regular file (%s)", hostPath, fi.Mode().Type())
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	// Never truncate: a partial trust store written back would drop CAs.
	if len(data) > MaxReadSize {
		return nil, fmt.Errorf("refusing to read %s: larger than %d bytes", hostPath, MaxReadSize)
	}
	return data, nil
}

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
		if _, ok := RegularFile(rootfs, containerPath); ok {
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

// The functions below are the only way hook-phase code touches a container
// rootfs (enforced by forbidigo in .golangci.yml). They take container paths,
// resolve them with ResolveSymlinks, and apply the rules of the threat model in
// docs/architecture.md: never leave the rootfs, read only bounded regular files,
// never replace a symlink.

// RegularFile reports whether containerPath resolves to a regular file in the
// rootfs, and returns the resolved container path.
func RegularFile(rootfs, containerPath string) (string, bool) {
	resolved, err := ResolveSymlinks(rootfs, containerPath)
	if err != nil {
		return "", false
	}
	fi, err := os.Lstat(PathInRootfs(rootfs, resolved))
	return resolved, err == nil && fi.Mode().IsRegular()
}

// ReadFile reads containerPath from the rootfs (see ReadRegularFile) and
// returns the resolved container path. A missing file returns an error
// wrapping os.ErrNotExist.
func ReadFile(rootfs, containerPath string) ([]byte, string, error) {
	resolved, err := ResolveSymlinks(rootfs, containerPath)
	if err != nil {
		return nil, "", err
	}
	data, err := ReadRegularFile(PathInRootfs(rootfs, resolved))
	return data, resolved, err
}

// WriteFile atomically replaces containerPath in the rootfs, creating missing
// parent directories, and returns the resolved container path. It refuses to
// replace a symlink and keeps the existing file's mode and owner.
func WriteFile(rootfs, containerPath string, data []byte) (string, error) {
	resolved, err := ResolveSymlinks(rootfs, containerPath)
	if err != nil {
		return "", err
	}
	host := PathInRootfs(rootfs, resolved)
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		return "", fmt.Errorf("failed to create directory for %s: %w", resolved, err)
	}
	if err := fsx.AtomicWrite(host, data, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", resolved, err)
	}
	return resolved, nil
}

// Glob returns the container paths matching a rootfs-relative pattern (no
// leading slash). Matching runs on an os.Root, so a link that points out of
// the rootfs is not followed; absolute links are not followed either, callers
// that need them list the resolved path explicitly.
func Glob(rootfs, pattern string) []string {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	matches, err := fs.Glob(root.FS(), pattern)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, "/"+m)
	}
	return out
}

// Writable reports whether files can be created at the rootfs top level.
func Writable(rootfs string) bool {
	probe := filepath.Join(rootfs, ".cainjekt-probe")
	// O_NOFOLLOW|O_EXCL: never follow or reuse an existing entry; fail closed
	// as "not writable".
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}
