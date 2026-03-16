//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tsuzu/cainjekt/internal/config"
	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/internal/runtime/hookctx"
)

func TestWrapperIntegration_PythonEnvVarsAreApplied(t *testing.T) {
	requireCommand(t, "go")
	requireCommand(t, "env")
	requireCommand(t, "sh")

	statePath := filepath.Join(t.TempDir(), "hook-context.json")
	want := "/usr/local/share/ca-certificates/cainjekt.crt"
	state := hookctx.State{
		Context: hookctx.PersistedContext{
			Facts: map[string]string{
				string(hookapi.FactIndividualCAPath): want,
			},
		},
		Detected: []hookctx.DetectedProcessor{
			{Name: "lang-python", Category: "language", Applicable: true, Priority: 100},
		},
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal(state): %v", err)
	}
	if err := os.WriteFile(statePath, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", statePath, err)
	}

	out := runCmd(t, 2*time.Minute,
		"env",
		config.EnvWrapperMode+"=1",
		config.EnvHookContextFile+"="+statePath,
		"SSL_CERT_FILE=/tmp/old.crt",
		"REQUESTS_CA_BUNDLE=/tmp/old.crt",
		"go", "run", "./cmd/cainjekt", "sh", "-c", "printf '%s|%s' \"${SSL_CERT_FILE:-}\" \"${REQUESTS_CA_BUNDLE:-}\"",
	)
	parts := strings.Split(strings.TrimSpace(out), "|")
	if len(parts) != 2 {
		t.Fatalf("expected 2 env values, got %q", out)
	}
	if parts[0] != want {
		t.Fatalf("SSL_CERT_FILE mismatch: got=%q want=%q", parts[0], want)
	}
	if parts[1] != want {
		t.Fatalf("REQUESTS_CA_BUNDLE mismatch: got=%q want=%q", parts[1], want)
	}
}
