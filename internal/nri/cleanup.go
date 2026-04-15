package nri

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// orphanCleaner periodically removes stale dynamic CA directories
// for containers that are no longer tracked by the plugin.
type orphanCleaner struct {
	root     string
	tracked  *sync.Map // map[string]struct{} — currently tracked container IDs
	metrics  *Metrics
	log      *slog.Logger
	interval time.Duration
}

func newOrphanCleaner(root string, tracked *sync.Map, metrics *Metrics, log *slog.Logger) *orphanCleaner {
	return &orphanCleaner{
		root:     root,
		tracked:  tracked,
		metrics:  metrics,
		log:      log,
		interval: 5 * time.Minute,
	}
}

func (c *orphanCleaner) run(stop <-chan struct{}) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *orphanCleaner) sweep() {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		if !os.IsNotExist(err) {
			c.log.Warn("orphan cleanup: failed to read dynamic CA root", "error", err)
		}
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, tracked := c.tracked.Load(name); tracked {
			continue
		}

		// Check if directory is old enough to be considered orphaned (>10 minutes).
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) < 10*time.Minute {
			continue
		}

		dir := filepath.Join(c.root, name)
		if err := os.RemoveAll(dir); err != nil {
			c.log.Warn("orphan cleanup: failed to remove", "dir", dir, "error", err)
			continue
		}
		c.metrics.OrphansCleaned.Add(1)
		c.log.Info("orphan cleanup: removed stale CA directory", "dir", name)
	}
}
