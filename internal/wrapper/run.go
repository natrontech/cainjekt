package wrapper

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/tsuzu/cainjekt/internal/config"
	hookapi "github.com/tsuzu/cainjekt/internal/hook/api"
	"github.com/tsuzu/cainjekt/internal/hook/processors"
)

func Run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("wrapper requires original command in argv[1:]")
	}

	wctx := &hookapi.WrapperContext{
		Env:        os.Environ(),
		TrustStore: strings.TrimSpace(os.Getenv(config.EnvWrapperTrustStore)),
	}
	for _, p := range processors.ForStage(processors.Default(), hookapi.StageLanguage) {
		lp, ok := p.(hookapi.LanguageProcessor)
		if !ok {
			continue
		}
		if err := lp.ApplyWrapper(wctx); err != nil {
			return fmt.Errorf("wrapper language processor %q failed: %w", lp.Name(), err)
		}
	}

	argv0 := os.Args[1]
	if !strings.ContainsRune(argv0, '/') {
		resolved, err := exec.LookPath(argv0)
		if err != nil {
			return fmt.Errorf("failed to resolve command %q: %w", argv0, err)
		}
		argv0 = resolved
	}

	if err := syscall.Exec(argv0, os.Args[1:], wctx.Env); err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}
	return nil
}
