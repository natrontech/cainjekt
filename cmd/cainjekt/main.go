// Package main is the entry point for cainjekt.
package main

import (
	"log/slog"
	"os"

	"github.com/natrontech/cainjekt/internal/app"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := app.Run(log, os.Args[1:]); err != nil {
		log.Error("cainjekt failed", "error", err)
		os.Exit(1)
	}
}
