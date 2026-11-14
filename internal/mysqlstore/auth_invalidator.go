package mysqlstore

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này tăng auth_version và xóa session trong transaction hiện tại.

// AuthInvalidator thực hiện tăng auth_version và thu hồi toàn bộ session người dùng trong MySQL transaction.
type AuthInvalidator struct {
	db *sqlx.DB
}

// NewAuthInvalidator khởi tạo AuthInvalidator với các dependency được cung cấp.
func NewAuthInvalidator(db *sqlx.DB) *AuthInvalidator {
	return &AuthInvalidator{db: db}
}

// Invalidate tăng auth_version và xóa session bằng transaction do caller sở hữu.
func (i *AuthInvalidator) Invalidate(ctx context.Context, userID uint64) error {
	if !inTransaction(ctx) {
		return fmt.Errorf("auth invalidation requires a MySQL transaction")
	}
	db := executor(ctx, i.db)
	result, err := db.ExecContext(ctx, `
		UPDATE users
		SET auth_version = auth_version + 1,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND auth_version IS NOT NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("increment auth version: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read auth-version update rows: %w", err)
	}
	if rows == 0 {
		return apperror.ErrNotFound
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete invalidated sessions: %w", err)
	}
	return nil
}

// DeleteSessions xóa session tại MySQL adapter và giữ mapping persistence khỏi domain.
func (i *AuthInvalidator) DeleteSessions(ctx context.Context, userID uint64) error {
	if !inTransaction(ctx) {
		return fmt.Errorf("session deletion requires a MySQL transaction")
	}
	if _, err := executor(ctx, i.db).ExecContext(
		ctx,
		`DELETE FROM sessions WHERE user_id = ?`,
		userID,
	); err != nil {
		return fmt.Errorf("delete account sessions: %w", err)
	}
	return nil
}
