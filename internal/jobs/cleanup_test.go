package jobs

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
	"go.uber.org/zap"
)

func TestCleanupWorkerRunsTasksRoundRobinWithinBudget(t *testing.T) {
	order := make([]string, 0, 4)
	worker := &CleanupWorker{
		cfg: config.CleanupConfig{
			BatchSize:   1,
			TableBudget: 2,
		},
		logger: zap.NewNop(),
	}
	tasks := []cleanupTask{
		{
			name: "sessions",
			run: func(context.Context, int) (int64, error) {
				order = append(order, "sessions")
				return 1, nil
			},
		},
		{
			name: "outbox",
			run: func(context.Context, int) (int64, error) {
				order = append(order, "outbox")
				return 1, nil
			},
		},
	}

	worker.runFair(context.Background(), tasks)

	want := []string{"sessions", "outbox", "sessions", "outbox"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("cleanup order = %v, want %v", order, want)
	}
}

func TestCleanupWorkerFailsClosedWhenLeaseBackendFails(t *testing.T) {
	lease := &fakeCleanupLease{err: errors.New("redis unavailable")}
	worker := &CleanupWorker{
		lease:  lease,
		cfg:    config.CleanupConfig{},
		logger: zap.NewNop(),
	}

	worker.runOnce(context.Background())

	if lease.acquireCalls != 1 {
		t.Fatalf("lease acquire calls = %d, want 1", lease.acquireCalls)
	}
	if lease.releaseCalls != 0 {
		t.Fatalf("lease release calls = %d, want 0", lease.releaseCalls)
	}
}

type fakeCleanupLease struct {
	err          error
	acquireCalls int
	releaseCalls int
}

func (l *fakeCleanupLease) Acquire(
	context.Context,
	string,
	time.Duration,
) (string, bool, error) {
	l.acquireCalls++
	return "", false, l.err
}

func (l *fakeCleanupLease) Release(context.Context, string, string) error {
	l.releaseCalls++
	return nil
}
