package hookctx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/natrontech/cainjekt/internal/config"
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
)

func TestWriteAndRead(t *testing.T) {
	rootfs := t.TempDir()
	t.Setenv(config.EnvHookContextFile, "/etc/cainjekt/test-hook-context.json")

	ctx := &hookapi.Context{
		Mode:        "createruntime",
		Bundle:      "/bundle",
		Annotations: map[string]string{"a": "b"},
		CAFile:      "/etc/cainjekt/ca-bundle.pem",
		FailPolicy:  "fail-open",
		Facts:       hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactTrustStorePath, "/etc/ssl/certs/ca-certificates.crt")
	in := NewStateFromContext(ctx, []DetectedProcessor{
		{Name: "dummy-os", Category: "os", Applicable: true, Priority: 20},
		{Name: "dummy-lang", Category: "language", Applicable: true, Priority: 10},
	})
	if err := Write(rootfs, in); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	hostPath := filepath.Join(rootfs, "etc", "cainjekt", "test-hook-context.json")
	if _, err := os.Stat(hostPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", hostPath, err)
	}

	// Read() reads from runtime filesystem path, so re-point it to host-written file for this test.
	t.Setenv(config.EnvHookContextFile, hostPath)
	out, err := Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if out.Context.Facts[string(hookapi.FactTrustStorePath)] != "/etc/ssl/certs/ca-certificates.crt" {
		t.Fatalf("TrustStore mismatch: got=%q", out.Context.Facts[string(hookapi.FactTrustStorePath)])
	}
	if len(out.Detected) != 2 {
		t.Fatalf("Detected count mismatch: %#v", out.Detected)
	}
	if out.Detected[0].Category != "os" || out.Detected[1].Category != "language" {
		t.Fatalf("Detected category mismatch: %#v", out.Detected)
	}
}
