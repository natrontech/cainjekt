// Package wrapper implements the container entrypoint wrapper for language-specific CA env vars.
package wrapper

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	hookapi "github.com/natrontech/cainjekt/internal/engine/api"
	"github.com/natrontech/cainjekt/internal/engine/processors"
	"github.com/natrontech/cainjekt/internal/log/level"
	"github.com/natrontech/cainjekt/internal/runtime/hookctx"
)

// Run executes the wrapper phase: applies language-specific env vars and execs the original entrypoint.
func Run() error {
	log := level.NewLogger()

	if len(os.Args) < 2 {
		return fmt.Errorf("wrapper requires original command in argv[1:]")
	}

	state, err := hookctx.Read()
	if err != nil {
		// Fail-open: if we can't read context, exec original command anyway.
		log.Warn("failed to read hook context, proceeding without CA injection", "error", err)
		return execOriginal(log)
	}
	ctx := state.ToHookContext()
	ctx.Env = os.Environ()

	var applied int
	for _, d := range state.Detected {
		if !d.Applicable {
			continue
		}
		p, ok := processors.ByName(d.Name)
		if !ok {
			continue
		}
		wp, ok := p.(hookapi.WrapperProcessor)
		if !ok {
			continue
		}
		if err := wp.ApplyWrapper(ctx); err != nil {
			// Fail-open: log and continue rather than blocking the container.
			log.Warn("wrapper processor failed, skipping", "name", wp.Name(), "error", err)
			continue
		}
		log.Info("wrapper processor applied", "name", wp.Name())
		applied++
	}

	log.Info("wrapper complete", "applied", applied, "command", os.Args[1])

	env, err := applyContextEnv(ctx.Env)
	if err != nil {
		log.Warn("failed to apply env, proceeding with original env", "error", err)
		return execOriginal(log)
	}
	ctx.Env = env

	argv0 := os.Args[1]
	if !strings.ContainsRune(argv0, '/') {
		resolved, err := exec.LookPath(argv0)
		if err != nil {
			return fmt.Errorf("failed to resolve command %q: %w", argv0, err)
		}
		argv0 = resolved
	}

	if err := syscall.Exec(argv0, os.Args[1:], ctx.Env); err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}
	return nil
}

// execOriginal execs the original command without any CA injection.
func execOriginal(log *level.Logger) error {
	argv0 := os.Args[1]
	if !strings.ContainsRune(argv0, '/') {
		resolved, err := exec.LookPath(argv0)
		if err != nil {
			return fmt.Errorf("failed to resolve command %q: %w", argv0, err)
		}
		argv0 = resolved
	}
	log.Info("exec original command (fail-open)", "command", argv0)
	if err := syscall.Exec(argv0, os.Args[1:], os.Environ()); err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}
	return nil
}

func applyContextEnv(env []string) ([]string, error) {
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return nil, fmt.Errorf("failed to apply env %q: %w", k, err)
		}
	}
	return os.Environ(), nil
}
