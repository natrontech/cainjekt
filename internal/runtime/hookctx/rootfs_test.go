package hookctx

import (
	"os"
	"path/filepath"
	"testing"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
)

// TestWriteStaysInsideRootfs pins the containment of the hook's writes. The root
// filesystem it writes into comes from the container image, so a symlinked path
// component must not redirect the write outside the rootfs. RefuseSymlink does not
// cover this — it checks the final component, while a parent directory is enough.
func TestWriteStaysInsideRootfs(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"absolute symlink", ""},          // filled in below with an out-of-rootfs path
		{"relative symlink", "../../../"}, // climbs out of the rootfs
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			rootfs := filepath.Join(tmp, "rootfs")
			outside := filepath.Join(tmp, "outside")
			for _, d := range []string{filepath.Join(rootfs, "etc"), outside} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			target := tc.target
			if target == "" {
				target = outside
			}
			if err := os.Symlink(target, filepath.Join(rootfs, "etc", "cainjekt")); err != nil {
				t.Fatal(err)
			}

			ctx := &hookapi.Context{Mode: "createruntime", Rootfs: rootfs, Facts: hookapi.NewMapFactStore()}
			if err := Write(rootfs, NewStateFromContext(ctx, nil)); err != nil {
				t.Logf("Write refused: %v", err) // refusing is also an acceptable outcome
			}

			for _, name := range []string{"hook-context.json", "status.json"} {
				if _, err := os.Lstat(filepath.Join(outside, name)); err == nil {
					t.Errorf("escape: %s written outside the rootfs", name)
				}
				if _, err := os.Lstat(filepath.Join(tmp, name)); err == nil {
					t.Errorf("escape: %s written above the rootfs", name)
				}
			}
		})
	}
}
