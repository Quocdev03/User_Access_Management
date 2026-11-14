package jobs

import (
	"context"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"go.uber.org/zap"
)

// File này xóa dữ liệu TTL hết hạn theo batch và lịch chạy có giới hạn.

// CleanupLease định nghĩa interface phân tán để đảm bảo chỉ một instance worker thực hiện dọn dẹp tại một thời điểm.
type CleanupLease interface {
	// Acquire giành lease và trả ownership token khi tiến trình trở thành owner.
	Acquire(context.Context, string, time.Duration) (string, bool, error)
	// Release chỉ nhả lease khi ownership token vẫn khớp.
	Release(context.Context, string, string) error
}

// CleanupWorker định kỳ dọn dẹp các bản ghi hết hạn và dữ liệu cũ theo batch an toàn.
type CleanupWorker struct {
	challenges *mysqlstore.VerificationChallengeStore
	sessions   *mysqlstore.SessionStore
	passwords  *mysqlstore.PasswordResetStore
	emails     *mysqlstore.EmailChangeStore
	outbox     *mysqlstore.OutboxStore
	audit      *mysqlstore.AuditStore
	lease      CleanupLease
	cfg        config.CleanupConfig
	logger     *zap.Logger
}

// NewCleanupWorker khởi tạo CleanupWorker với các dependency được cung cấp.
func NewCleanupWorker(
	challenges *mysqlstore.VerificationChallengeStore,
	sessions *mysqlstore.SessionStore,
	passwords *mysqlstore.PasswordResetStore,
	emails *mysqlstore.EmailChangeStore,
	outbox *mysqlstore.OutboxStore,
	audit *mysqlstore.AuditStore,
	lease CleanupLease,
	cfg config.CleanupConfig,
	logger *zap.Logger,
) *CleanupWorker {
	return &CleanupWorker{
		challenges: challenges,
		sessions:   sessions,
		passwords:  passwords,
		emails:     emails,
		outbox:     outbox,
		audit:      audit,
		lease:      lease,
		cfg:        cfg,
		logger:     logger,
	}
}

// Start chạy cleanup theo interval cho đến khi context bị hủy.
func (w *CleanupWorker) Start(ctx context.Context) {
	w.logger.Info(
		"Cleanup worker started",
		zap.String("interval", w.cfg.Interval.String()),
		zap.Int("batch_size", w.cfg.BatchSize),
		zap.Int("table_budget", w.cfg.TableBudget),
	)
	w.runOnce(ctx)
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Cleanup worker stopped")
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

// runOnce giành lease rồi dọn từng nhóm dữ liệu theo batch giới hạn.
func (w *CleanupWorker) runOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	token, acquired, err := w.lease.Acquire(
		ctx,
		"cleanup",
		w.cfg.LeaseTTL,
	)
	if err != nil {
		w.logger.Error("Cleanup lease unavailable", zap.Error(err))
		return
	}
	if !acquired {
		w.logger.Debug("Cleanup skipped because another worker owns the lease")
		return
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			5*time.Second,
		)
		defer cancel()
		if err := w.lease.Release(releaseCtx, "cleanup", token); err != nil {
			w.logger.Warn("Cleanup lease release failed", zap.Error(err))
		}
	}()

	runCtx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()
	now := time.Now().UTC()
	tasks := []cleanupTask{
		{
			name: "sessions",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.sessions.DeleteExpiredBatch(ctx, now, limit)
			},
		},
		{
			name: "refresh_token_history",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.sessions.DeleteExpiredRefreshHistoryBatch(ctx, now, limit)
			},
		},
		{
			name: "verification_challenges",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.challenges.DeleteExpiredBatch(ctx, now, limit)
			},
		},
		{
			name: "password_reset_tokens",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.passwords.DeleteExpiredBatch(ctx, now, limit)
			},
		},
		{
			name: "email_change_requests",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.emails.DeleteExpiredBatch(ctx, now, limit)
			},
		},
		{
			name: "outbox_events",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.outbox.DeleteCompletedBatch(
					ctx,
					now.Add(-w.cfg.OutboxRetention),
					limit,
				)
			},
		},
	}
	if w.cfg.AuditRetention > 0 {
		tasks = append(tasks, cleanupTask{
			name: "audit_logs",
			run: func(ctx context.Context, limit int) (int64, error) {
				return w.audit.DeleteOlderThanBatch(
					ctx,
					now.Add(-w.cfg.AuditRetention),
					limit,
				)
			},
		})
	}
	w.runFair(runCtx, tasks)
}

// cleanupTask mô tả một đơn vị tác vụ dọn dẹp dữ liệu của một bảng cụ thể.
type cleanupTask struct {
	name     string
	deleted  int
	complete bool
	run      func(context.Context, int) (int64, error)
}

// runFair luân phiên các cleanup task để một bảng lớn không làm starvation bảng khác.
func (w *CleanupWorker) runFair(ctx context.Context, tasks []cleanupTask) {
	for {
		pending := 0
		for index := range tasks {
			task := &tasks[index]
			if task.complete || task.deleted >= w.cfg.TableBudget {
				continue
			}
			pending++
			limit := min(w.cfg.BatchSize, w.cfg.TableBudget-task.deleted)
			rows, err := task.run(ctx, limit)
			if err != nil {
				w.logger.Error(
					"Cleanup batch failed",
					zap.String("table", task.name),
					zap.Error(err),
				)
				task.complete = true
				continue
			}
			task.deleted += int(rows)
			task.complete = rows < int64(limit)
		}
		if pending == 0 || ctx.Err() != nil {
			break
		}
	}
	for _, task := range tasks {
		if task.deleted > 0 {
			w.logger.Info(
				"Cleanup deleted rows",
				zap.String("table", task.name),
				zap.Int("deleted", task.deleted),
			)
		}
	}
}
