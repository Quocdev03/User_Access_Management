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

// File này lưu và consume email-verification challenge trong MySQL.

// VerificationChallenge ánh xạ bản ghi thử thách xác minh OTP từ bảng verification_challenges trong MySQL.
type VerificationChallenge struct {
	ID                   uint64     `db:"id"`
	RequestID            string     `db:"request_id"`
	UserID               uint64     `db:"user_id"`
	EmailChangeRequestID *string    `db:"email_change_request_id"`
	Purpose              string     `db:"purpose"`
	Subject              string     `db:"subject"`
	SecretHash           string     `db:"secret_hash"`
	Attempts             int        `db:"attempts"`
	ConsumedAt           *time.Time `db:"consumed_at"`
	ExpiresAt            time.Time  `db:"expires_at"`
	CreatedAt            time.Time  `db:"created_at"`
}

// VerificationChallengeStore quản lý việc lưu trữ, kiểm tra số lần thử và hoàn tất các thử thách OTP trong MySQL.
type VerificationChallengeStore struct {
	db *sqlx.DB
}

// NewVerificationChallengeStore khởi tạo VerificationChallengeStore với các dependency được cung cấp.
func NewVerificationChallengeStore(db *sqlx.DB) *VerificationChallengeStore {
	return &VerificationChallengeStore{db: db}
}

// InvalidateActive vô hiệu hóa active tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *VerificationChallengeStore) InvalidateActive(
	ctx context.Context,
	userID uint64,
	purpose string,
	now time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE verification_challenges
		SET consumed_at = ?, updated_at = ?
		WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL`,
		now.UTC(),
		now.UTC(),
		userID,
		purpose,
	); err != nil {
		return fmt.Errorf("invalidate active verification challenges: %w", err)
	}
	return nil
}

// Create lưu email-verification challenge trong transaction hiện tại.
func (s *VerificationChallengeStore) Create(
	ctx context.Context,
	challenge *VerificationChallenge,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO verification_challenges (
			request_id, user_id, email_change_request_id, purpose, subject,
			secret_hash, attempts, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		challenge.RequestID,
		challenge.UserID,
		challenge.EmailChangeRequestID,
		challenge.Purpose,
		challenge.Subject,
		challenge.SecretHash,
		challenge.ExpiresAt.UTC(),
		challenge.CreatedAt.UTC(),
		challenge.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("create verification challenge: %w", err)
	}
	id, err := parsePositiveInsertID(result, "create verification challenge")
	if err != nil {
		return err
	}
	challenge.ID = id
	return nil
}

// FindLatestActiveForUpdate khóa verification challenge mới nhất còn hiệu lực để consume an toàn.
func (s *VerificationChallengeStore) FindLatestActiveForUpdate(
	ctx context.Context,
	userID uint64,
	purpose string,
	now time.Time,
) (*VerificationChallenge, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("verification challenge lock requires a MySQL transaction")
	}
	var challenge VerificationChallenge
	err := executor(ctx, s.db).GetContext(ctx, &challenge, `
		SELECT id, request_id, user_id, email_change_request_id, purpose,
			subject, secret_hash, attempts, consumed_at, expires_at, created_at
		FROM verification_challenges
		WHERE user_id = ?
		  AND purpose = ?
		  AND consumed_at IS NULL
		  AND expires_at > ?
		ORDER BY created_at DESC, id DESC
		LIMIT 1 FOR UPDATE`,
		userID,
		purpose,
		now.UTC(),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("lock active verification challenge: %w", err)
	}
	return &challenge, nil
}

// FindEmailChangeForUpdate truy vấn email thay đổi cho cập nhật và khóa bản ghi trong transaction hiện tại để tránh lost update.
func (s *VerificationChallengeStore) FindEmailChangeForUpdate(
	ctx context.Context,
	emailChangeRequestID string,
	purpose string,
) (*VerificationChallenge, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("email-change challenge lock requires a MySQL transaction")
	}
	var challenge VerificationChallenge
	err := executor(ctx, s.db).GetContext(ctx, &challenge, `
		SELECT id, request_id, user_id, email_change_request_id, purpose,
			subject, secret_hash, attempts, consumed_at, expires_at, created_at
		FROM verification_challenges
		WHERE email_change_request_id = ?
		  AND purpose = ?
		  AND consumed_at IS NULL
		ORDER BY id
		LIMIT 1 FOR UPDATE`,
		emailChangeRequestID,
		purpose,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("lock email-change challenge: %w", err)
	}
	return &challenge, nil
}

// IncrementAttempts tăng attempts tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *VerificationChallengeStore) IncrementAttempts(
	ctx context.Context,
	id uint64,
) (int, error) {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE verification_challenges
		SET attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND consumed_at IS NULL`,
		id,
	)
	if err != nil {
		return 0, fmt.Errorf("increment verification attempts: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read verification-attempt rows: %w", err)
	}
	if rows != 1 {
		return 0, apperror.ErrOTPExpired
	}
	var attempts int
	if err := executor(ctx, s.db).GetContext(ctx, &attempts,
		"SELECT attempts FROM verification_challenges WHERE id = ?",
		id,
	); err != nil {
		return 0, fmt.Errorf("read verification attempts: %w", err)
	}
	return attempts, nil
}

// Consume đánh dấu verification challenge đã dùng bằng conditional update.
func (s *VerificationChallengeStore) Consume(
	ctx context.Context,
	id uint64,
	now time.Time,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE verification_challenges
		SET consumed_at = ?, updated_at = ?
		WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
		now.UTC(),
		now.UTC(),
		id,
		now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("consume verification challenge: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read consumed verification rows: %w", err)
	}
	if rows != 1 {
		return apperror.ErrOTPExpired
	}
	return nil
}

// DeleteExpiredBatch xóa expired batch tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *VerificationChallengeStore) DeleteExpiredBatch(
	ctx context.Context,
	threshold time.Time,
	limit int,
) (int64, error) {
	if limit < 1 {
		limit = 1000
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		DELETE FROM verification_challenges
		WHERE expires_at < ?
		LIMIT ?`,
		threshold.UTC(),
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired verification challenges: %w", err)
	}
	return result.RowsAffected()
}
