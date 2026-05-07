package hook

import (
	"os"
	"path/filepath"
	"time"

	"github.com/natrontech/cainjekt/internal/config"
)

// breadcrumb writes a small marker file into the staged dir on the node.
// Best-effort: errors are intentionally ignored so the hook never fails because
// of telemetry. The plugin reads these files in PostCreateContainer to detect
// hooks that were SIGKILLed by containerd on timeout (no "done" file present).
func breadcrumb(name, content string) {
	dir := os.Getenv(config.EnvBreadcrumbDir)
	if dir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
}

func breadcrumbNow(name string) {
	breadcrumb(name, time.Now().UTC().Format(time.RFC3339Nano))
}
