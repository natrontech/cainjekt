// Package hookctx handles persistence of hook state between the hook and wrapper phases.
package hookctx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/natrontech/cainjekt/internal/config"
	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/pkg/fsx"
)

// DetectedProcessor records a processor's detection result for persistence.
type DetectedProcessor struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Applicable bool   `json:"applicable"`
	Priority   int    `json:"priority"`
	Reason     string `json:"reason,omitempty"`
}

// PersistedContext is the serializable subset of the hook context.
type PersistedContext struct {
	Mode        string            `json:"mode,omitempty"`
	Bundle      string            `json:"bundle,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CAFile      string            `json:"ca_file,omitempty"`
	FailPolicy  string            `json:"fail_policy,omitempty"`
	Facts       map[string]string `json:"facts,omitempty"`
}

// State holds the persisted hook context and detected processors.
type State struct {
	Context  PersistedContext    `json:"context"`
	Detected []DetectedProcessor `json:"detected,omitempty"`
}

// NewStateFromContext creates a State from the current hook context.
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

// ToHookContext reconstructs a hook context from persisted state.
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

// Write persists the hook state and a human-readable status file to the container rootfs.
func Write(rootfs string, state State) error {
	containerPath := contextFilePath()
	hostPath := pathInRootfs(rootfs, containerPath)
	dir := filepath.Dir(hostPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create hook context dir %s: %w", dir, err)
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

	// Write human-readable status file for operator inspection.
	statusPath := filepath.Join(dir, "status.json")
	status := buildStatus(state)
	sb, err := json.MarshalIndent(status, "", "  ")
	if err == nil {
		_ = fsx.AtomicWrite(statusPath, append(sb, '\n'), fsx.WriteOptions{
			FallbackMode:  0o644,
			RefuseSymlink: true,
		})
	}

	return nil
}

// InjectionStatus is the human-readable status written to /etc/cainjekt/status.json.
type InjectionStatus struct {
	Injected       bool              `json:"injected"`
	Timestamp      string            `json:"timestamp"`
	Distro         string            `json:"distro,omitempty"`
	TrustStore     string            `json:"trust_store,omitempty"`
	RootfsReadOnly bool              `json:"rootfs_read_only,omitempty"`
	CAFile         string            `json:"ca_file,omitempty"`
	Processors     []ProcessorStatus `json:"processors"`
}

// ProcessorStatus records one processor's result.
type ProcessorStatus struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Applicable bool   `json:"applicable"`
	Reason     string `json:"reason,omitempty"`
}

func buildStatus(state State) InjectionStatus {
	s := InjectionStatus{
		Injected:  true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		CAFile:    state.Context.CAFile,
	}
	if v, ok := state.Context.Facts["distro"]; ok {
		s.Distro = v
	}
	if v, ok := state.Context.Facts["trust_store_path"]; ok {
		s.TrustStore = v
	}
	if v, ok := state.Context.Facts["rootfs_read_only"]; ok && v == "true" {
		s.RootfsReadOnly = true
	}
	for _, d := range state.Detected {
		s.Processors = append(s.Processors, ProcessorStatus{
			Name:       d.Name,
			Category:   d.Category,
			Applicable: d.Applicable,
			Reason:     d.Reason,
		})
	}
	return s
}

// Read loads the persisted hook state from the container filesystem.
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
