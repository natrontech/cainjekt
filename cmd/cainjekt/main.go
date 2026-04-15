// Package main is the entry point for cainjekt.
package main

import (
	"os"

	"github.com/natrontech/cainjekt/internal/app"
	"github.com/natrontech/cainjekt/internal/log/level"
)

func main() {
	log := level.NewLogger()
	if err := app.Run(log, os.Args[1:]); err != nil {
		log.Error("cainjekt failed", "error", err)
		os.Exit(1)
	}
}
