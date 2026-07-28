package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"go.uber.org/zap"
)

type Logout struct {
	sessions    *mysqlstore.SessionStore
	tokens      *redisstore.TokenStore
	invalidator *sessionapp.Invalidator
	logger      *zap.Logger
}

func NewLogout(
	sessions *mysqlstore.SessionStore,
	tokens *redisstore.TokenStore,
	invalidator *sessionapp.Invalidator,
	logger *zap.Logger,
) *Logout {
	return &Logout{
		sessions:    sessions,
		tokens:      tokens,
		invalidator: invalidator,
		logger:      logger,
	}
}

func (l *Logout) Current(
	ctx context.Context,
	userID uint64,
	jti string,
	expiresAt time.Time,
) error {
	if ttl := time.Until(expiresAt); ttl > 0 {
		if err := l.tokens.BlacklistJTI(ctx, jti, ttl); err != nil {
			return fmt.Errorf("blacklist access token: %w", err)
		}
	}
	if err := l.sessions.RevokeByAccessJTI(
		ctx,
		userID,
		jti,
	); err != nil {
		return fmt.Errorf("revoke current session: %w", err)
	}
	l.logger.Info("Đăng xuất thành công", zap.Uint64("user_id", userID))
	return nil
}

func (l *Logout) All(ctx context.Context, userID uint64) error {
	if err := l.invalidator.InvalidateAll(ctx, userID); err != nil {
		return fmt.Errorf("không thể thu hồi phiên đăng nhập: %w", err)
	}
	l.logger.Info("Đã đăng xuất khỏi tất cả thiết bị", zap.Uint64("user_id", userID))
	return nil
}
