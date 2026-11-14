package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này lưu email-change challenge trong MySQL transaction.

const (
	EmailChangePending   = "pending"
	EmailChangeCompleted = "completed"
	EmailChangeCancelled = "cancelled"
)

// EmailChangeRequest ánh xạ bản ghi yêu cầu thay đổi email trong bảng email_change_requests.
type EmailChangeRequest struct {
	ID                  string     `db:"id"`
	UserID              uint64     `db:"user_id"`
	OldEmail            string     `db:"old_email"`
	NewEmail            string     `db:"new_email"`
	AuthVersionSnapshot uint64     `db:"auth_version_snapshot"`
	State               string     `db:"state"`
	ExpiresAt           time.Time  `db:"expires_at"`
	CompletedAt         *time.Time `db:"completed_at"`
	CancelledAt         *time.Time `db:"cancelled_at"`
	CreatedAt           time.Time  `db:"created_at"`
}

// EmailChangeStore quản lý việc tạo, truy vấn, cập nhật và dọn dẹp các yêu cầu đổi email trong MySQL.
type EmailChangeStore struct {
	db *sqlx.DB
}

// NewEmailChangeStore khởi tạo EmailChangeStore với các dependency được cung cấp.
func NewEmailChangeStore(db *sqlx.DB) *EmailChangeStore {
	return &EmailChangeStore{db: db}
}

// DeleteExpiredBatch xóa expired batch tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *EmailChangeStore) DeleteExpiredBatch(
	ctx context.Context,
	threshold time.Time,
	limit int,
) (int64, error) {
	if limit < 1 {
		return 0, nil
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		DELETE FROM email_change_requests
		WHERE expires_at < ?
		ORDER BY expires_at, id
		LIMIT ?`,
		threshold.UTC(),
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired email-change requests: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted email-change rows: %w", err)
	}
	return rows, nil
}

// Create lưu email-change challenge trong transaction hiện tại.
func (s *EmailChangeStore) Create(
	ctx context.Context,
	request *EmailChangeRequest,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO email_change_requests (
			id, user_id, old_email, new_email, auth_version_snapshot,
			state, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		request.ID,
		request.UserID,
		request.OldEmail,
		request.NewEmail,
		request.AuthVersionSnapshot,
		request.State,
		request.ExpiresAt.UTC(),
		request.CreatedAt.UTC(),
		request.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("create email-change request: %w", err)
	}
	return nil
}

// FindPendingForUpdate truy vấn pending cho cập nhật và khóa bản ghi trong transaction hiện tại để tránh lost update.
func (s *EmailChangeStore) FindPendingForUpdate(
	ctx context.Context,
	userID uint64,
) (*EmailChangeRequest, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("email-change request lock requires a MySQL transaction")
	}
	var request EmailChangeRequest
	if err := executor(ctx, s.db).GetContext(ctx, &request, `
		SELECT id, user_id, old_email, new_email, auth_version_snapshot,
			state, expires_at, completed_at, cancelled_at, created_at
		FROM email_change_requests
		WHERE user_id = ? AND state = 'pending'
		ORDER BY created_at DESC, id DESC
		LIMIT 1 FOR UPDATE`,
		userID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("lock pending email-change request: %w", err)
	}
	return &request, nil
}

// CancelActiveByUser hủy mọi email-change challenge còn hiệu lực của user trong transaction.
func (s *EmailChangeStore) CancelActiveByUser(
	ctx context.Context,
	userID uint64,
	now time.Time,
) error {
	if !inTransaction(ctx) {
		return fmt.Errorf("email-change cancellation requires a MySQL transaction")
	}
	db := executor(ctx, s.db)
	if _, err := db.ExecContext(ctx, `
		UPDATE email_change_requests
		SET state = ?, cancelled_at = ?, updated_at = ?
		WHERE user_id = ? AND state = ?`,
		EmailChangeCancelled,
		now.UTC(),
		now.UTC(),
		userID,
		EmailChangePending,
	); err != nil {
		return fmt.Errorf("cancel active email-change requests: %w", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE verification_challenges
		SET consumed_at = ?, updated_at = ?
		WHERE user_id = ?
		  AND email_change_request_id IS NOT NULL
		  AND consumed_at IS NULL`,
		now.UTC(),
		now.UTC(),
		userID,
	); err != nil {
		return fmt.Errorf("invalidate email-change challenges: %w", err)
	}
	return nil
}

// Complete consume email-change challenge sau khi account mutation thành công.
func (s *EmailChangeStore) Complete(
	ctx context.Context,
	requestID string,
	now time.Time,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE email_change_requests
		SET state = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND state = ?`,
		EmailChangeCompleted,
		now.UTC(),
		now.UTC(),
		requestID,
		EmailChangePending,
	)
	if err != nil {
		return fmt.Errorf("complete email-change request: %w", err)
	}
	if err := requireOneRow(result, "complete email-change request"); err != nil {
		if errors.Is(err, apperror.ErrNotFound) {
			return apperror.ErrOTPExpired
		}
		return err
	}
	return nil
}
