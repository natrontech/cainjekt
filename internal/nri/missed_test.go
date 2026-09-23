package nri

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/natrontech/cainjekt/internal/config"
)

// TestMissedGaugeClearsOnPodRestart is a regression test for an alert that could
// never clear. cainjekt_missed_containers was Set once at Synchronize and never
// touched again, so restarting the pods the scan named did not move it — only
// restarting cainjekt itself did. The dashboard therefore showed however many
// were missed at the last plugin start, not how many are still outstanding.
func TestMissedGaugeClearsOnPodRestart(t *testing.T) {
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())

	p := newPlugin(nil)
	pod := &api.PodSandbox{
		Id:          "pod-1",
		Namespace:   "default",
		Name:        "app",
		Annotations: map[string]string{config.AnnoEnabled(): "true"},
	}
	// Opted in and running, with no hook.done breadcrumb staged: created while the
	// plugin was disconnected.
	ctr := &api.Container{
		Id:           "aaaaaaaaaaaa",
		Name:         "app",
		PodSandboxId: "pod-1",
		State:        api.ContainerState_CONTAINER_RUNNING,
	}
	pods, ctrs := []*api.PodSandbox{pod}, []*api.Container{ctr}

	p.reportMissedContainers(pods, ctrs)
	if got := gaugeValue(t, p.metrics.MissedContainers); got != 1 {
		t.Fatalf("expected cainjekt_missed_containers=1 after the scan, got %v", got)
	}

	// The runtime re-synchronises on reconnect; the same container must not count twice.
	p.reportMissedContainers(pods, ctrs)
	if got := gaugeValue(t, p.metrics.MissedContainers); got != 1 {
		t.Fatalf("a rescan must not drift the gauge, got %v", got)
	}

	if err := p.RemoveContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if got := gaugeValue(t, p.metrics.MissedContainers); got != 0 {
		t.Fatalf("restarting the pod must clear the gauge, got %v", got)
	}
}
