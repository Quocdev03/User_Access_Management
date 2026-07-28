package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

type Account struct {
	ID                     uint64                 `db:"id"`
	Username               string                 `db:"username"`
	Email                  string                 `db:"email"`
	PasswordHash           string                 `db:"password_hash"`
	Lifecycle              accountstate.Lifecycle `db:"lifecycle_state"`
	EmailVerified          bool                   `db:"email_verified"`
	AdministrativeLockedAt *time.Time             `db:"administrative_locked_at"`
	LoginLockedUntil       *time.Time             `db:"login_locked_until"`
	FailedLoginAttempts    int                    `db:"failed_login_attempts"`
	PasswordChangeRequired bool                   `db:"password_change_required"`
	AuthVersion            uint64                 `db:"auth_version"`
	LastLoginAt            *time.Time             `db:"last_login_at"`
	CreatedAt              time.Time              `db:"created_at"`
	UpdatedAt              time.Time              `db:"updated_at"`
}

const accountProjection = `id, username, email, password_hash, lifecycle_state,
	email_verified, administrative_locked_at, login_locked_until,
	failed_login_attempts, password_change_required, auth_version,
	last_login_at, created_at, updated_at`

type AccountStore struct {
	db *sqlx.DB
}

type RegistrationAccount struct {
	ID           uint64
	Username     string
	Email        string
	PasswordHash string
}

func NewAccountStore(db *sqlx.DB) *AccountStore {
	return &AccountStore{db: db}
}

func (s *AccountStore) FindByID(ctx context.Context, id uint64) (*Account, error) {
	return s.findByID(ctx, id, false)
}

func (s *AccountStore) FindByIDForUpdate(ctx context.Context, id uint64) (*Account, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("FindByIDForUpdate requires a MySQL transaction")
	}
	return s.findByID(ctx, id, true)
}

func (s *AccountStore) FindByEmail(ctx context.Context, email string) (*Account, error) {
	return s.findByEmail(ctx, email, false)
}

func (s *AccountStore) FindByEmailForUpdate(
	ctx context.Context,
	email string,
) (*Account, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("FindByEmailForUpdate requires a MySQL transaction")
	}
	return s.findByEmail(ctx, email, true)
}

func (s *AccountStore) CreateRegistration(
	ctx context.Context,
	account *RegistrationAccount,
	now time.Time,
) error {
	state := accountstate.Registration()
	if err := state.Validate(); err != nil {
		return err
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO users (
			username, email, password_hash, lifecycle_state, email_verified,
			administrative_locked_at, login_locked_until, failed_login_attempts,
			password_change_required, auth_version,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		account.Username,
		account.Email,
		account.PasswordHash,
		state.Lifecycle,
		state.EmailVerified,
		state.AdministrativeLockedAt,
		state.LoginLockedUntil,
		state.PasswordChangeRequired,
		state.AuthVersion,
		now.UTC(),
		now.UTC(),
	)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return apperror.ErrConflict
		}
		return fmt.Errorf("create registration account: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read registration account id: %w", err)
	}
	account.ID = uint64(id)
	return nil
}

func (s *AccountStore) findByID(ctx context.Context, id uint64, forUpdate bool) (*Account, error) {
	query := `SELECT ` + accountProjection + ` FROM users WHERE id = ? LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var account Account
	if err := executor(ctx, s.db).GetContext(ctx, &account, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find account by id: %w", err)
	}
	return &account, nil
}

func (s *AccountStore) findByEmail(
	ctx context.Context,
	email string,
	forUpdate bool,
) (*Account, error) {
	query := `SELECT ` + accountProjection + ` FROM users WHERE email = ? LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var account Account
	if err := executor(ctx, s.db).GetContext(ctx, &account, query, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find account by email: %w", err)
	}
	return &account, nil
}

func (a Account) State() (accountstate.State, error) {
	state := accountstate.State{
		Lifecycle:              a.Lifecycle,
		EmailVerified:          a.EmailVerified,
		AdministrativeLockedAt: a.AdministrativeLockedAt,
		LoginLockedUntil:       a.LoginLockedUntil,
		FailedLoginAttempts:    a.FailedLoginAttempts,
		PasswordChangeRequired: a.PasswordChangeRequired,
		AuthVersion:            a.AuthVersion,
	}
	if err := state.Validate(); err != nil {
		return accountstate.State{}, fmt.Errorf("account %d: %w", a.ID, err)
	}
	return state, nil
}

func (s *AccountStore) UpdateState(
	ctx context.Context,
	accountID uint64,
	state accountstate.State,
	now time.Time,
) error {
	if err := state.Validate(); err != nil {
		return err
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE users
		SET lifecycle_state = ?,
			email_verified = ?,
			administrative_locked_at = ?,
			login_locked_until = ?,
			failed_login_attempts = ?,
			password_change_required = ?,
			auth_version = ?,
			updated_at = ?
		WHERE id = ?`,
		state.Lifecycle,
		state.EmailVerified,
		state.AdministrativeLockedAt,
		state.LoginLockedUntil,
		state.FailedLoginAttempts,
		state.PasswordChangeRequired,
		state.AuthVersion,
		now.UTC(),
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update account state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read updated account rows: %w", err)
	}
	if rows == 0 {
		return apperror.ErrNotFound
	}
	return nil
}

func (s *AccountStore) UpdateCredential(
	ctx context.Context,
	accountID uint64,
	passwordHash string,
	state accountstate.State,
	now time.Time,
) error {
	if err := state.Validate(); err != nil {
		return err
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE users
		SET password_hash = ?,
			lifecycle_state = ?,
			email_verified = ?,
			administrative_locked_at = ?,
			login_locked_until = ?,
			failed_login_attempts = ?,
			password_change_required = ?,
			auth_version = ?,
			updated_at = ?
		WHERE id = ?`,
		passwordHash,
		state.Lifecycle,
		state.EmailVerified,
		state.AdministrativeLockedAt,
		state.LoginLockedUntil,
		state.FailedLoginAttempts,
		state.PasswordChangeRequired,
		state.AuthVersion,
		now.UTC(),
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update account credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read updated account credential rows: %w", err)
	}
	if rows == 0 {
		return apperror.ErrNotFound
	}
	return nil
}

func (s *AccountStore) UpdateEmail(
	ctx context.Context,
	accountID uint64,
	email string,
	state accountstate.State,
	now time.Time,
) error {
	if err := state.Validate(); err != nil {
		return err
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE users
		SET email = ?,
			lifecycle_state = ?,
			email_verified = ?,
			administrative_locked_at = ?,
			login_locked_until = ?,
			failed_login_attempts = ?,
			password_change_required = ?,
			auth_version = ?,
			updated_at = ?
		WHERE id = ?`,
		email,
		state.Lifecycle,
		state.EmailVerified,
		state.AdministrativeLockedAt,
		state.LoginLockedUntil,
		state.FailedLoginAttempts,
		state.PasswordChangeRequired,
		state.AuthVersion,
		now.UTC(),
		accountID,
	)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return apperror.ErrConflict
		}
		return fmt.Errorf("update account email: %w", err)
	}
	return requireOneRow(result, "update account email")
}

func (s *AccountStore) UpdateLoginState(
	ctx context.Context,
	accountID uint64,
	state accountstate.State,
	lastLoginAt *time.Time,
	now time.Time,
) error {
	if err := state.Validate(); err != nil {
		return err
	}
	_, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE users
		SET lifecycle_state = ?,
			email_verified = ?,
			administrative_locked_at = ?,
			login_locked_until = ?,
			failed_login_attempts = ?,
			password_change_required = ?,
			auth_version = ?,
			last_login_at = COALESCE(?, last_login_at),
			updated_at = ?
		WHERE id = ?`,
		state.Lifecycle,
		state.EmailVerified,
		state.AdministrativeLockedAt,
		state.LoginLockedUntil,
		state.FailedLoginAttempts,
		state.PasswordChangeRequired,
		state.AuthVersion,
		lastLoginAt,
		now.UTC(),
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update account login state: %w", err)
	}
	// MySQL reports zero changed rows when two logins persist the same
	// second-level state. The caller already locked and loaded this account.
	return nil
}
