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

type TOTPRecord struct {
	UserID           uint64     `db:"user_id"`
	SecretCiphertext []byte     `db:"secret_ciphertext"`
	KeyVersion       string     `db:"key_version"`
	LastUsedStep     *uint64    `db:"last_used_step"`
	ConfirmedAt      *time.Time `db:"confirmed_at"`
	EnabledAt        *time.Time `db:"enabled_at"`
	CreatedAt        time.Time  `db:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at"`
}

type MFAStore struct {
	db *sqlx.DB
}

func NewMFAStore(db *sqlx.DB) *MFAStore {
	return &MFAStore{db: db}
}

func (s *MFAStore) FindByUserID(
	ctx context.Context,
	userID uint64,
) (*TOTPRecord, error) {
	return s.findByUserID(ctx, userID, false)
}

func (s *MFAStore) FindByUserIDForUpdate(
	ctx context.Context,
	userID uint64,
) (*TOTPRecord, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("MFA row lock requires a MySQL transaction")
	}
	return s.findByUserID(ctx, userID, true)
}

func (s *MFAStore) CreatePending(
	ctx context.Context,
	record *TOTPRecord,
	now time.Time,
) error {
	_, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO user_totp (
			user_id, secret_ciphertext, key_version, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?)`,
		record.UserID,
		record.SecretCiphertext,
		record.KeyVersion,
		now.UTC(),
		now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("create pending TOTP enrollment: %w", err)
	}
	return nil
}

func (s *MFAStore) ReplacePending(
	ctx context.Context,
	userID uint64,
	ciphertext []byte,
	keyVersion string,
	now time.Time,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE user_totp
		SET secret_ciphertext = ?,
			key_version = ?,
			last_used_step = NULL,
			confirmed_at = NULL,
			enabled_at = NULL,
			updated_at = ?
		WHERE user_id = ? AND enabled_at IS NULL`,
		ciphertext,
		keyVersion,
		now.UTC(),
		userID,
	)
	if err != nil {
		return fmt.Errorf("replace pending TOTP enrollment: %w", err)
	}
	return requireMFARow(
		result,
		"replace pending TOTP enrollment",
		apperror.ErrConflict,
	)
}

func (s *MFAStore) Enable(
	ctx context.Context,
	userID uint64,
	usedStep uint64,
	now time.Time,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE user_totp
		SET last_used_step = ?,
			confirmed_at = ?,
			enabled_at = ?,
			updated_at = ?
		WHERE user_id = ? AND enabled_at IS NULL`,
		usedStep,
		now.UTC(),
		now.UTC(),
		now.UTC(),
		userID,
	)
	if err != nil {
		return fmt.Errorf("enable TOTP MFA: %w", err)
	}
	return requireMFARow(result, "enable TOTP MFA", apperror.ErrConflict)
}

func (s *MFAStore) MarkTOTPUsed(
	ctx context.Context,
	userID uint64,
	usedStep uint64,
	now time.Time,
) (bool, error) {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE user_totp
		SET last_used_step = ?, updated_at = ?
		WHERE user_id = ?
		  AND enabled_at IS NOT NULL
		  AND (last_used_step IS NULL OR last_used_step < ?)`,
		usedStep,
		now.UTC(),
		userID,
		usedStep,
	)
	if err != nil {
		return false, fmt.Errorf("mark TOTP time step used: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read used TOTP update rows: %w", err)
	}
	return rows == 1, nil
}

func (s *MFAStore) Delete(ctx context.Context, userID uint64) error {
	result, err := executor(ctx, s.db).ExecContext(
		ctx,
		`DELETE FROM user_totp WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("delete TOTP MFA: %w", err)
	}
	return requireMFARow(result, "delete TOTP MFA", apperror.ErrNotFound)
}

func (s *MFAStore) ReplaceRecoveryCodes(
	ctx context.Context,
	userID uint64,
	hashes [][]byte,
	now time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(
		ctx,
		`DELETE FROM user_totp_recovery_codes WHERE user_id = ?`,
		userID,
	); err != nil {
		return fmt.Errorf("delete previous MFA recovery codes: %w", err)
	}
	for _, codeHash := range hashes {
		if _, err := executor(ctx, s.db).ExecContext(ctx, `
			INSERT INTO user_totp_recovery_codes (
				user_id, code_hash, created_at
			) VALUES (?, ?, ?)`,
			userID,
			codeHash,
			now.UTC(),
		); err != nil {
			return fmt.Errorf("create MFA recovery code: %w", err)
		}
	}
	return nil
}

func (s *MFAStore) ConsumeRecoveryCode(
	ctx context.Context,
	userID uint64,
	codeHash []byte,
	now time.Time,
) (bool, error) {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE user_totp_recovery_codes
		SET used_at = ?
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
		now.UTC(),
		userID,
		codeHash,
	)
	if err != nil {
		return false, fmt.Errorf("consume MFA recovery code: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read consumed MFA recovery rows: %w", err)
	}
	return rows == 1, nil
}

func (s *MFAStore) CountUnusedRecoveryCodes(
	ctx context.Context,
	userID uint64,
) (int, error) {
	var count int
	if err := executor(ctx, s.db).GetContext(ctx, &count, `
		SELECT COUNT(*)
		FROM user_totp_recovery_codes
		WHERE user_id = ? AND used_at IS NULL`,
		userID,
	); err != nil {
		return 0, fmt.Errorf("count unused MFA recovery codes: %w", err)
	}
	return count, nil
}

func (s *MFAStore) findByUserID(
	ctx context.Context,
	userID uint64,
	forUpdate bool,
) (*TOTPRecord, error) {
	query := `
		SELECT user_id, secret_ciphertext, key_version, last_used_step,
			confirmed_at, enabled_at, created_at, updated_at
		FROM user_totp
		WHERE user_id = ?
		LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var record TOTPRecord
	if err := executor(ctx, s.db).GetContext(ctx, &record, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find TOTP MFA record: %w", err)
	}
	return &record, nil
}

func requireMFARow(
	result interface {
		RowsAffected() (int64, error)
	},
	operation string,
	missing error,
) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows: %w", operation, err)
	}
	if rows != 1 {
		return missing
	}
	return nil
}
