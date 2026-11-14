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

// File này kiểm chứng hành vi cleanup và các trường hợp lỗi liên quan.

// TestCleanupWorkerRunsTasksRoundRobinWithinBudget kiểm chứng kịch bản CleanupWorkerRunsTasksRoundRobinWithinBudget.
func TestCleanupWorkerRunsTasksRoundRobinWithinBudget(t *testing.T) {
	order := make([]string, 0, 6)
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
			name: "refresh_token_history",
			run: func(context.Context, int) (int64, error) {
				order = append(order, "refresh_token_history")
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

	want := []string{
		"sessions",
		"refresh_token_history",
		"outbox",
		"sessions",
		"refresh_token_history",
		"outbox",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("cleanup order = %v, want %v", order, want)
	}
}

// TestCleanupWorkerRefreshTokenHistoryCompletesEarly kiểm chứng task refresh_token_history dừng sớm khi hết bản ghi cần xóa.
func TestCleanupWorkerRefreshTokenHistoryCompletesEarly(t *testing.T) {
	callCount := 0
	worker := &CleanupWorker{
		cfg: config.CleanupConfig{
			BatchSize:   10,
			TableBudget: 50,
		},
		logger: zap.NewNop(),
	}
	tasks := []cleanupTask{
		{
			name: "refresh_token_history",
			run: func(ctx context.Context, limit int) (int64, error) {
				callCount++
				return 5, nil
			},
		},
	}

	worker.runFair(context.Background(), tasks)

	if callCount != 1 {
		t.Fatalf("callCount = %d, want 1", callCount)
	}
	if tasks[0].deleted != 5 {
		t.Fatalf("deleted = %d, want 5", tasks[0].deleted)
	}
	if !tasks[0].complete {
		t.Fatalf("task.complete = false, want true")
	}
}

// TestCleanupWorkerFailsClosedWhenLeaseBackendFails kiểm chứng kịch bản CleanupWorkerFailsClosedWhenLeaseBackendFails.
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

// fakeCleanupLease là mock triển khai CleanupLease phục vụ kiểm thử worker dọn dẹp.
type fakeCleanupLease struct {
	err          error
	acquireCalls int
	releaseCalls int
}

// Acquire mô phỏng lease acquisition cho cleanup worker test.
func (l *fakeCleanupLease) Acquire(
	context.Context,
	string,
	time.Duration,
) (string, bool, error) {
	l.acquireCalls++
	return "", false, l.err
}

// Release ghi nhận ownership token được cleanup worker trả lại.
func (l *fakeCleanupLease) Release(context.Context, string, string) error {
	l.releaseCalls++
	return nil
}
