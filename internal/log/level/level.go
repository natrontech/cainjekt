// Package level provides configurable log level via CAINJEKT_LOG_LEVEL env var.
package level

import (
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger for convenience.
type Logger = slog.Logger

// NewLogger creates a slog.Logger with the level set by CAINJEKT_LOG_LEVEL.
// Valid values: debug, info, warn, error. Defaults to info.
func NewLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(os.Getenv("CAINJEKT_LOG_LEVEL")),
	}))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
