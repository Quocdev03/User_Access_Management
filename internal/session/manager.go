package session

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

type View struct {
	ID        uint64
	IPAddress *string
	UserAgent *string
	DeviceID  *uint64
	ExpiresAt time.Time
	CreatedAt time.Time
	IsCurrent bool
}

type Manager struct {
	sessions    *mysqlstore.SessionStore
	profiles    *mysqlstore.ClientProfileStore
	tokens      TokenState
	txManager   *mysqlstore.TxManager
	invalidator *Invalidator
	accessTTL   time.Duration
}

func NewManager(
	db *sqlx.DB,
	sessions *mysqlstore.SessionStore,
	profiles *mysqlstore.ClientProfileStore,
	tokens TokenState,
	invalidator *Invalidator,
	accessTTL time.Duration,
) *Manager {
	return &Manager{
		sessions:    sessions,
		profiles:    profiles,
		tokens:      tokens,
		txManager:   mysqlstore.NewTxManager(db),
		invalidator: invalidator,
		accessTTL:   accessTTL,
	}
}

func (m *Manager) List(
	ctx context.Context,
	userID uint64,
	currentAccessJTI string,
) ([]View, error) {
	sessions, err := m.sessions.FindActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]View, 0, len(sessions))
	for _, current := range sessions {
		result = append(result, View{
			ID:        current.ID,
			IPAddress: current.IPAddress,
			UserAgent: current.UserAgent,
			DeviceID:  current.ClientProfileID,
			ExpiresAt: current.ExpiresAt,
			CreatedAt: current.CreatedAt,
			IsCurrent: current.AccessJTI == currentAccessJTI,
		})
	}
	return result, nil
}

func (m *Manager) Revoke(ctx context.Context, userID, sessionID uint64) error {
	var jti string
	if err := m.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		current, err := m.sessions.FindOwnedForUpdate(txCtx, sessionID, userID)
		if err != nil {
			return err
		}
		if current == nil {
			return apperror.ErrNotFound
		}
		jti = current.AccessJTI
		return m.sessions.RevokeOwned(txCtx, sessionID, userID)
	}); err != nil {
		return err
	}
	if jti == "" {
		return nil
	}
	if err := m.tokens.BlacklistJTI(ctx, jti, m.accessTTL); err != nil {
		if invalidateErr := m.invalidator.InvalidateAll(ctx, userID); invalidateErr != nil {
			return fmt.Errorf("blacklist session JTI: %v; invalidate auth: %w", err, invalidateErr)
		}
		return fmt.Errorf("blacklist session JTI after durable revoke: %w", err)
	}
	return nil
}
