package java

import (
	"path"
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

// javaHomes returns candidate java home directories as container paths.
func javaHomes(rootfs string, env []string) []string {
	var out []string
	if home := strings.TrimSpace(envutil.GetValue(env, envJavaHome)); home != "" && path.IsAbs(home) {
		out = append(out, path.Clean(home))
	}
	for _, bin := range javaBinaryCandidates {
		resolved, ok := containerfs.RegularFile(rootfs, bin)
		if !ok {
			continue
		}
		// <home>/bin/java
		out = append(out, path.Dir(path.Dir(resolved)))
	}
	return out
}

// discoverTrustStores returns the resolved container path of every cacerts
// file in the rootfs, deduplicated.
func discoverTrustStores(rootfs string, env []string) []string {
	candidates := make([]string, 0, 16)
	for _, home := range javaHomes(rootfs, env) {
		candidates = append(candidates,
			path.Join(home, "lib/security/cacerts"),
			path.Join(home, "jre/lib/security/cacerts"),
		)
	}
	candidates = append(candidates, distroTrustStores...)
	for _, glob := range trustStoreGlobs {
		candidates = append(candidates, containerfs.Glob(rootfs, glob)...)
	}

	seen := make(map[string]struct{}, len(candidates))
	var out []string
	for _, c := range candidates {
		resolved, ok := containerfs.RegularFile(rootfs, c)
		if !ok {
			continue
		}
		if _, dup := seen[resolved]; dup {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out
}
