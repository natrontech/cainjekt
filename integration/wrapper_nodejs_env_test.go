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

func TestWrapperIntegration_NodeExtraCACertsIsApplied(t *testing.T) {
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
			{Name: "lang-nodejs", Category: "language", Applicable: true, Priority: 100},
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
		"NODE_EXTRA_CA_CERTS=/tmp/old.crt",
		"go", "run", "./cmd/cainjekt", "sh", "-c", "printf %s \"${NODE_EXTRA_CA_CERTS:-}\"",
	)
	got := strings.TrimSpace(out)
	if got != want {
		t.Fatalf("NODE_EXTRA_CA_CERTS mismatch: got=%q want=%q", got, want)
	}
}
