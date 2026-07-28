package jobs

import (
	"context"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"go.uber.org/zap"
)

type CleanupLease interface {
	Acquire(context.Context, string, time.Duration) (string, bool, error)
	Release(context.Context, string, string) error
}

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

type cleanupTask struct {
	name     string
	deleted  int
	complete bool
	run      func(context.Context, int) (int64, error)
}

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
