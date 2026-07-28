package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

type PasswordResetToken struct {
	ID          uint64     `db:"id"`
	UserID      uint64     `db:"user_id"`
	TokenHash   string     `db:"token_hash"`
	AuthVersion uint64     `db:"auth_version"`
	ConsumedAt  *time.Time `db:"consumed_at"`
	ExpiresAt   time.Time  `db:"expires_at"`
	CreatedAt   time.Time  `db:"created_at"`
}

type PasswordResetStore struct {
	db *sqlx.DB
}

func NewPasswordResetStore(db *sqlx.DB) *PasswordResetStore {
	return &PasswordResetStore{db: db}
}

func (s *PasswordResetStore) Create(
	ctx context.Context,
	userID uint64,
	tokenHash string,
	authVersion uint64,
	expiresAt time.Time,
) (uint64, error) {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO password_reset_tokens (
			user_id, token_hash, auth_version, expires_at
		) VALUES (?, ?, ?, ?)`,
		userID,
		tokenHash,
		authVersion,
		expiresAt.UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("create password reset token: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read password reset token id: %w", err)
	}
	return uint64(id), nil
}

func (s *PasswordResetStore) FindByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*PasswordResetToken, error) {
	return s.find(ctx, "token_hash = ?", tokenHash, false)
}

func (s *PasswordResetStore) FindByIDForUpdate(
	ctx context.Context,
	id uint64,
) (*PasswordResetToken, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("FindByIDForUpdate requires a MySQL transaction")
	}
	return s.find(ctx, "id = ?", id, true)
}

func (s *PasswordResetStore) find(
	ctx context.Context,
	predicate string,
	value any,
	forUpdate bool,
) (*PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, auth_version, consumed_at,
			expires_at, created_at
		FROM password_reset_tokens
		WHERE ` + predicate + `
		LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var token PasswordResetToken
	if err := executor(ctx, s.db).GetContext(ctx, &token, query, value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find password reset token: %w", err)
	}
	return &token, nil
}

func (s *PasswordResetStore) Consume(
	ctx context.Context,
	id uint64,
	now time.Time,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE password_reset_tokens
		SET consumed_at = ?
		WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
		now.UTC(),
		id,
		now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("consume password reset token: %w", err)
	}
	return requireOneRow(result, "consume password reset token")
}

func (s *PasswordResetStore) InvalidateActiveByUser(
	ctx context.Context,
	userID uint64,
	now time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE password_reset_tokens
		SET consumed_at = COALESCE(consumed_at, ?)
		WHERE user_id = ? AND consumed_at IS NULL`,
		now.UTC(),
		userID,
	); err != nil {
		return fmt.Errorf("invalidate password reset tokens: %w", err)
	}
	return nil
}

func (s *PasswordResetStore) DeleteExpiredBatch(
	ctx context.Context,
	threshold time.Time,
	limit int,
) (int64, error) {
	if limit < 1 {
		limit = 1000
	}
	result, err := executor(ctx, s.db).ExecContext(ctx,
		"DELETE FROM password_reset_tokens WHERE expires_at < ? LIMIT ?",
		threshold.UTC(),
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired password reset tokens: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted password reset token rows: %w", err)
	}
	return rows, nil
}
