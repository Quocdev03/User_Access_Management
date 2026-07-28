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

type Session struct {
	ID                 uint64    `db:"id"`
	UserID             uint64    `db:"user_id"`
	CurrentRefreshHash string    `db:"current_refresh_hash"`
	AccessJTI          string    `db:"access_jti"`
	IPAddress          *string   `db:"ip_address"`
	UserAgent          *string   `db:"user_agent"`
	ClientProfileID    *uint64   `db:"client_profile_id"`
	ExpiresAt          time.Time `db:"expires_at"`
	CreatedAt          time.Time `db:"created_at"`
}

const sessionProjection = `id, user_id, current_refresh_hash, access_jti,
	ip_address, user_agent, client_profile_id, expires_at, created_at`

type SessionStore struct {
	db *sqlx.DB
}

func NewSessionStore(db *sqlx.DB) *SessionStore {
	return &SessionStore{db: db}
}

func (s *SessionStore) Create(ctx context.Context, session *Session) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO sessions (
			user_id, current_refresh_hash, access_jti, ip_address, user_agent,
			client_profile_id, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
		session.UserID,
		session.CurrentRefreshHash,
		session.AccessJTI,
		session.IPAddress,
		session.UserAgent,
		session.ClientProfileID,
		session.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read created session id: %w", err)
	}
	session.ID = uint64(id)
	return nil
}

func (s *SessionStore) FindByCurrentRefreshHashForUpdate(
	ctx context.Context,
	tokenHash string,
) (*Session, error) {
	var session Session
	err := executor(ctx, s.db).GetContext(ctx, &session,
		`SELECT `+sessionProjection+`
		 FROM sessions
		 WHERE current_refresh_hash = ? AND revoked_at IS NULL
		 LIMIT 1 FOR UPDATE`,
		tokenHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find current refresh session: %w", err)
	}
	return &session, nil
}

func (s *SessionStore) RefreshHistoryExists(ctx context.Context, tokenHash string) (bool, error) {
	var exists bool
	if err := executor(ctx, s.db).GetContext(ctx, &exists,
		`SELECT EXISTS(
			SELECT 1 FROM refresh_token_history WHERE token_hash = ?
		)`,
		tokenHash,
	); err != nil {
		return false, fmt.Errorf("check refresh history: %w", err)
	}
	return exists, nil
}

func (s *SessionStore) Rotate(
	ctx context.Context,
	session *Session,
	previousRefreshHash string,
	previousExpiresAt time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO refresh_token_history (
			token_hash, session_id, user_id, rotated_at, expires_at
		) VALUES (?, ?, ?, NOW(), ?)`,
		previousRefreshHash,
		session.ID,
		session.UserID,
		previousExpiresAt,
	); err != nil {
		return fmt.Errorf("record refresh history: %w", err)
	}

	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE sessions
		SET current_refresh_hash = ?,
			access_jti = ?,
			ip_address = ?,
			user_agent = ?,
			client_profile_id = ?,
			expires_at = ?,
			updated_at = NOW()
		WHERE id = ?
		  AND current_refresh_hash = ?
		  AND revoked_at IS NULL`,
		session.CurrentRefreshHash,
		session.AccessJTI,
		session.IPAddress,
		session.UserAgent,
		session.ClientProfileID,
		session.ExpiresAt,
		session.ID,
		previousRefreshHash,
	)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read rotated session rows: %w", err)
	}
	if rows != 1 {
		return apperror.ErrTokenReuse
	}
	return nil
}

func (s *SessionStore) RevokeByAccessJTI(
	ctx context.Context,
	userID uint64,
	accessJTI string,
) error {
	_, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, NOW()), updated_at = NOW()
		WHERE user_id = ? AND access_jti = ?`,
		userID,
		accessJTI,
	)
	if err != nil {
		return fmt.Errorf("revoke session by access JTI: %w", err)
	}
	return nil
}

func (s *SessionStore) FindActiveByUserID(ctx context.Context, userID uint64) ([]Session, error) {
	sessions := []Session{}
	err := executor(ctx, s.db).SelectContext(ctx, &sessions,
		`SELECT `+sessionProjection+`
		 FROM sessions
		 WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()
		 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	return sessions, nil
}

func (s *SessionStore) FindOwned(ctx context.Context, id, userID uint64) (*Session, error) {
	return s.findOwned(ctx, id, userID, false)
}

func (s *SessionStore) FindOwnedForUpdate(
	ctx context.Context,
	id uint64,
	userID uint64,
) (*Session, error) {
	return s.findOwned(ctx, id, userID, true)
}

func (s *SessionStore) findOwned(
	ctx context.Context,
	id uint64,
	userID uint64,
	forUpdate bool,
) (*Session, error) {
	var session Session
	query := `SELECT ` + sessionProjection + `
		FROM sessions
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL
		LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := executor(ctx, s.db).GetContext(ctx, &session,
		query,
		id,
		userID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find owned session: %w", err)
	}
	return &session, nil
}

func (s *SessionStore) RevokeOwned(ctx context.Context, id, userID uint64) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, NOW()), updated_at = NOW()
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		id,
		userID,
	)
	if err != nil {
		return fmt.Errorf("revoke owned session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked session rows: %w", err)
	}
	if rows == 0 {
		return apperror.ErrNotFound
	}
	return nil
}

func (s *SessionStore) RevokeLocked(ctx context.Context, id, userID uint64) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, NOW()), updated_at = NOW()
		WHERE id = ? AND user_id = ?`,
		id,
		userID,
	)
	if err != nil {
		return fmt.Errorf("revoke locked session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read locked-session revoke rows: %w", err)
	}
	if rows != 1 {
		return apperror.ErrNotFound
	}
	return nil
}

func (s *SessionStore) CountActiveByUserID(ctx context.Context, userID uint64) (int, error) {
	var count int
	err := executor(ctx, s.db).GetContext(ctx, &count, `
		SELECT COUNT(*)
		FROM sessions
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()`,
		userID,
	)
	return count, err
}

func (s *SessionStore) RevokeOldestActiveReturningJTI(
	ctx context.Context,
	userID uint64,
	limit int,
) ([]string, error) {
	if limit < 1 {
		return nil, nil
	}
	type row struct {
		ID  uint64 `db:"id"`
		JTI string `db:"access_jti"`
	}
	rows := []row{}
	if err := executor(ctx, s.db).SelectContext(ctx, &rows, `
		SELECT id, access_jti
		FROM sessions
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at ASC, id ASC
		LIMIT ? FOR UPDATE`,
		userID,
		limit,
	); err != nil {
		return nil, fmt.Errorf("lock oldest sessions: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ids := make([]uint64, 0, len(rows))
	jtis := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
		if row.JTI != "" {
			jtis = append(jtis, row.JTI)
		}
	}
	query, args, err := sqlx.In(`
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, NOW()), updated_at = NOW()
		WHERE id IN (?)`,
		ids,
	)
	if err != nil {
		return nil, fmt.Errorf("build oldest-session revoke: %w", err)
	}
	if _, err := executor(ctx, s.db).ExecContext(ctx, s.db.Rebind(query), args...); err != nil {
		return nil, fmt.Errorf("revoke oldest sessions: %w", err)
	}
	return jtis, nil
}

func (s *SessionStore) DeleteExpiredBatch(
	ctx context.Context,
	threshold time.Time,
	limit int,
) (int64, error) {
	if limit < 1 {
		limit = 1000
	}
	result, err := executor(ctx, s.db).ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at < ? LIMIT ?`,
		threshold,
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return result.RowsAffected()
}
