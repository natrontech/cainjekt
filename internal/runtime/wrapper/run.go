package wrapper

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	hookapi "github.com/tsuzu/cainjekt/internal/engine/api"
	"github.com/tsuzu/cainjekt/internal/engine/processors"
	"github.com/tsuzu/cainjekt/internal/runtime/hookctx"
)

func Run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("wrapper requires original command in argv[1:]")
	}

	state, err := hookctx.Read()
	if err != nil {
		return err
	}
	ctx := state.ToHookContext()
	ctx.Env = os.Environ()

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
			return fmt.Errorf("wrapper processor %q failed: %w", wp.Name(), err)
		}
	}

	env, err := applyContextEnv(ctx.Env)
	if err != nil {
		return err
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
