// Package app routes cainjekt execution to the appropriate runtime mode.
package app

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/natrontech/cainjekt/internal/config"
	"github.com/natrontech/cainjekt/internal/nri"
	"github.com/natrontech/cainjekt/internal/runtime/hook"
	"github.com/natrontech/cainjekt/internal/runtime/wrapper"
)

// Run detects the runtime mode and dispatches to the appropriate handler.
func Run(log *slog.Logger, args []string) error {
	if strings.TrimSpace(os.Getenv(config.EnvHookMode)) != "" {
		if err := hook.Run(log); err != nil {
			if strings.EqualFold(getenvOr(config.EnvFailPolicy, config.FailPolicyOpen), config.FailPolicyOpen) {
				log.Error("hook failed (fail-open)", "error", err)
				return nil
			}
			return fmt.Errorf("hook failed: %w", err)
		}
		return nil
	}
	if strings.TrimSpace(os.Getenv(config.EnvWrapperMode)) != "" {
		if err := wrapper.Run(); err != nil {
			return fmt.Errorf("wrapper failed: %w", err)
		}
		return nil
	}

	if err := nri.Run(log, args); err != nil {
		return fmt.Errorf("plugin failed: %w", err)
	}
	return nil
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
