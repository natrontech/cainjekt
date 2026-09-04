package java

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/natrontech/cainjekt/internal/util/containerfs"
	"github.com/natrontech/cainjekt/internal/util/envutil"
)

const envJavaHome = "JAVA_HOME"

// javaBinaryCandidates are the usual locations of the java launcher. The parent
// of its bin directory is the java home.
var javaBinaryCandidates = []string{
	"/usr/bin/java",
	"/usr/local/bin/java",
	"/usr/lib/jvm/default/bin/java",
	"/usr/lib/jvm/default-java/bin/java",
	"/opt/java/bin/java",
	"/opt/java/openjdk/bin/java",
}

// trustStoreGlobs find cacerts in images where the launcher is not on a known
// path (jlink runtimes, multi-JDK images). Rootfs-relative, no leading slash.
var trustStoreGlobs = []string{
	"usr/lib/jvm/*/lib/security/cacerts",
	"usr/lib/jvm/*/jre/lib/security/cacerts",
	"opt/java/*/lib/security/cacerts",
	"opt/*/lib/security/cacerts",
	"opt/*/jre/lib/security/cacerts",
}

// distroTrustStores are the distro-managed stores that a JDK's own cacerts is
// usually symlinked to. Listed explicitly so they are patched even when the
// symlink points somewhere we did not enumerate.
var distroTrustStores = []string{
	"/etc/pki/java/cacerts",       // RHEL / UBI, written by update-ca-trust extract
	"/etc/ssl/certs/java/cacerts", // Debian / Ubuntu, written by ca-certificates-java
}

// trustStore is a cacerts file located inside a container rootfs.
type trustStore struct {
	container string // path as the container sees it
	host      string // path on the host, inside the rootfs
}

// javaHomes returns candidate java home directories as container paths.
func javaHomes(rootfs string, env []string) []string {
	var out []string
	if home := strings.TrimSpace(envutil.GetValue(env, envJavaHome)); home != "" && path.IsAbs(home) {
		out = append(out, path.Clean(home))
	}
	for _, bin := range javaBinaryCandidates {
		resolved, err := containerfs.ResolveSymlinks(rootfs, bin)
		if err != nil {
			continue
		}
		fi, err := os.Lstat(containerfs.PathInRootfs(rootfs, resolved))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		// <home>/bin/java
		out = append(out, path.Dir(path.Dir(resolved)))
	}
	return out
}

// discoverTrustStores returns every existing cacerts file in the rootfs,
// deduplicated by the path it finally resolves to.
func discoverTrustStores(rootfs string, env []string) []trustStore {
	candidates := make([]string, 0, 16)
	for _, home := range javaHomes(rootfs, env) {
		candidates = append(candidates,
			path.Join(home, "lib/security/cacerts"),
			path.Join(home, "jre/lib/security/cacerts"),
		)
	}
	candidates = append(candidates, distroTrustStores...)
	for _, glob := range trustStoreGlobs {
		matches, err := filepath.Glob(filepath.Join(rootfs, glob))
		if err != nil {
			continue
		}
		for _, m := range matches {
			rel, err := filepath.Rel(rootfs, m)
			if err != nil {
				continue
			}
			candidates = append(candidates, "/"+filepath.ToSlash(rel))
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	var out []trustStore
	for _, c := range candidates {
		resolved, err := containerfs.ResolveSymlinks(rootfs, c)
		if err != nil {
			continue
		}
		if _, dup := seen[resolved]; dup {
			continue
		}
		seen[resolved] = struct{}{}
		host := containerfs.PathInRootfs(rootfs, resolved)
		fi, err := os.Lstat(host)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, trustStore{container: resolved, host: host})
	}
	return out
}
