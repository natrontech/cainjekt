package hookctx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tsuzu/cainjekt/internal/config"
	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/pkg/fsx"
)

type DetectedProcessor struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Applicable bool   `json:"applicable"`
	Priority   int    `json:"priority"`
	Reason     string `json:"reason,omitempty"`
}

type PersistedContext struct {
	Mode        string            `json:"mode,omitempty"`
	Bundle      string            `json:"bundle,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CAFile      string            `json:"ca_file,omitempty"`
	FailPolicy  string            `json:"fail_policy,omitempty"`
	Facts       map[string]string `json:"facts,omitempty"`
}

type State struct {
	Context  PersistedContext    `json:"context"`
	Detected []DetectedProcessor `json:"detected,omitempty"`
}

func NewStateFromContext(ctx *hookapi.Context, detected []DetectedProcessor) State {
	ann := make(map[string]string, len(ctx.Annotations))
	for k, v := range ctx.Annotations {
		ann[k] = v
	}
	facts := map[string]string{}
	for k, v := range ctx.Facts.Snapshot() {
		facts[string(k)] = v
	}
	return State{
		Context: PersistedContext{
			Mode:        ctx.Mode,
			Bundle:      ctx.Bundle,
			Annotations: ann,
			CAFile:      ctx.CAFile,
			FailPolicy:  ctx.FailPolicy,
			Facts:       facts,
		},
		Detected: detected,
	}
}

func (s State) ToHookContext() *hookapi.Context {
	facts := map[hookapi.FactKey]string{}
	for k, v := range s.Context.Facts {
		facts[hookapi.FactKey(k)] = v
	}
	return &hookapi.Context{
		Mode:        s.Context.Mode,
		Bundle:      s.Context.Bundle,
		Annotations: cloneStringMap(s.Context.Annotations),
		CAFile:      s.Context.CAFile,
		FailPolicy:  s.Context.FailPolicy,
		Facts:       hookapi.NewMapFactStoreFromSnapshot(facts),
	}
}

func Write(rootfs string, state State) error {
	containerPath := contextFilePath()
	hostPath := pathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return fmt.Errorf("failed to create hook context dir %s: %w", filepath.Dir(hostPath), err)
	}
	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal hook context: %w", err)
	}
	if err := fsx.AtomicWrite(hostPath, append(b, '\n'), fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return fmt.Errorf("failed to write hook context file %s: %w", hostPath, err)
	}
	return nil
}

func Read() (State, error) {
	p := contextFilePath()
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, nil
		}
		return State{}, fmt.Errorf("failed to read hook context file %s: %w", p, err)
	}
	var out State
	if err := json.Unmarshal(b, &out); err != nil {
		return State{}, fmt.Errorf("failed to parse hook context file %s: %w", p, err)
	}
	out.Context.Annotations = cloneStringMap(out.Context.Annotations)
	out.Context.Facts = cloneStringMap(out.Context.Facts)
	return out, nil
}

func contextFilePath() string {
	if p := strings.TrimSpace(os.Getenv(config.EnvHookContextFile)); p != "" {
		return p
	}
	// Backward compatibility for existing deployments.
	if p := strings.TrimSpace(os.Getenv("CAINJEKT_WRAPPER_CONTEXT_FILE")); p != "" {
		return p
	}
	return config.HookContextFile
}

func pathInRootfs(rootfs, containerPath string) string {
	trimmed := strings.TrimPrefix(containerPath, "/")
	return filepath.Join(rootfs, filepath.FromSlash(trimmed))
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
