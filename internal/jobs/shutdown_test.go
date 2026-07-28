package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
	"go.uber.org/zap"
)

func TestWorkersStopWhenContextIsAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan struct{}, 2)
	go func() {
		(&OutboxWorker{
			cfg: config.OutboxConfig{
				PollInterval: time.Hour,
			},
			logger: zap.NewNop(),
		}).Start(ctx)
		stopped <- struct{}{}
	}()
	go func() {
		(&CleanupWorker{
			cfg: config.CleanupConfig{
				Interval: time.Hour,
			},
			logger: zap.NewNop(),
		}).Start(ctx)
		stopped <- struct{}{}
	}()

	for range 2 {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("worker did not stop after cancellation")
		}
	}
}
