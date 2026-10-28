package nri

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/stub"
)

// fakeStub fails Run a few times, then blocks until ctx is cancelled.
type fakeStub struct {
	stub.Stub
	fails int
	runs  int
}

func (f *fakeStub) Run(ctx context.Context) error {
	f.runs++
	if f.runs <= f.fails {
		return errors.New("connection refused")
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestRunNRIReconnectsAfterConnectionLoss(t *testing.T) {
	t.Parallel()
	fs := &fakeStub{fails: 3}
	p := &Plugin{stub: fs, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.runNRI(ctx) }()

	time.Sleep(time.Second) // 100+200+400 ms of backoff
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runNRI returned %v on shutdown, want nil", err)
	}
	if fs.runs != 4 {
		t.Fatalf("Run called %d times, want 4 (3 failures + 1 connected)", fs.runs)
	}
}
