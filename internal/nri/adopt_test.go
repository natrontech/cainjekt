package nri

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/natrontech/cainjekt/internal/config"
)

// gaugeValue mirrors counterValue for gauges.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// stageDir fakes a CA directory the plugin staged for a container in an earlier
// life, aged past the orphan cleaner's 10-minute grace period.
func stageDir(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca-bundle.pem", config.BreadcrumbDone} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestSynchronizeAdoptsStagedContainers is a regression test for a restart wiping
// live containers' CA bundles. The tracked set is rebuilt from scratch on every
// start and the orphan cleaner removes every staged directory not in it, so
// without adoption the first sweep after a restart (DaemonSet rollout, containerd
// restart, node reboot) deleted the CA bundle of every still-running container —
// breaking the dynamic CA path and destroying the hook.done breadcrumbs the
// missed-container scan depends on.
func TestSynchronizeAdoptsStagedContainers(t *testing.T) {
	root := t.TempDir()
	t.Setenv(config.EnvDynamicCARoot, root)

	live := stageDir(t, root, "aaaaaaaaaaaa")
	dead := stageDir(t, root, "bbbbbbbbbbbb")

	p := newPlugin(nil)
	// Only the live container is still known to the runtime.
	running := []*api.Container{{Id: "aaaaaaaaaaaa", State: api.ContainerState_CONTAINER_RUNNING}}

	if _, err := p.Synchronize(context.Background(), nil, running); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
	p.verifyWG.Wait()

	newOrphanCleaner(root, &p.tracked, p.metrics, p.log).sweep()

	if _, err := os.Stat(live); err != nil {
		t.Fatalf("staged CA dir of a running container was swept after restart: %v", err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatalf("expected the orphaned dir to be cleaned, stat err = %v", err)
	}
}

// TestSynchronizeIgnoresUnstagedContainers guards the ActiveContainers gauge: a
// container the plugin never injected has no staged directory and must not be
// adopted, otherwise the gauge drifts up on every reconnect.
func TestSynchronizeIgnoresUnstagedContainers(t *testing.T) {
	root := t.TempDir()
	t.Setenv(config.EnvDynamicCARoot, root)
	stageDir(t, root, "aaaaaaaaaaaa")

	p := newPlugin(nil)
	ctrs := []*api.Container{
		{Id: "aaaaaaaaaaaa", State: api.ContainerState_CONTAINER_RUNNING},
		{Id: "cccccccccccc", State: api.ContainerState_CONTAINER_RUNNING}, // never injected
	}

	p.adoptStagedContainers(ctrs)

	if _, ok := p.tracked.Load("aaaaaaaaaaaa"); !ok {
		t.Fatal("expected the staged container to be tracked")
	}
	if _, ok := p.tracked.Load("cccccccccccc"); ok {
		t.Fatal("a container with no staged CA dir must not be tracked")
	}
	if got := gaugeValue(t, p.metrics.ActiveContainers); got != 1 {
		t.Fatalf("expected cainjekt_active_containers=1, got %v", got)
	}
}
