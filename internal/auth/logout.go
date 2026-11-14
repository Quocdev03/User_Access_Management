package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"go.uber.org/zap"
)

// File này thu hồi một session hoặc toàn bộ auth state của tài khoản.

// LogoutCommand chứa dữ liệu nhận dạng phiên đăng nhập cần thu hồi.
type LogoutCommand struct {
	UserID       uint64
	AccessJTI    string
	ExpiresAt    time.Time
	RefreshToken string
}

// Logout thực thi use case đăng xuất người dùng, vô hiệu hóa session trong MySQL và blacklist JTI trong Redis.
type Logout struct {
	sessions    *mysqlstore.SessionStore
	tokens      *redisstore.TokenStore
	invalidator *sessionapp.Invalidator
	logger      *zap.Logger
}

// NewLogout khởi tạo Logout với các dependency được cung cấp.
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

// Session thu hồi session hiện tại qua access token (kể cả đã hết hạn) và/hoặc refresh token.
func (l *Logout) Session(ctx context.Context, cmd LogoutCommand) error {
	var revoked bool
	if cmd.AccessJTI != "" {
		if ttl := time.Until(cmd.ExpiresAt); ttl > 0 {
			if err := l.tokens.BlacklistJTI(ctx, cmd.AccessJTI, ttl); err != nil {
				return fmt.Errorf("blacklist access token: %w", err)
			}
		}
		if cmd.UserID > 0 {
			if err := l.sessions.RevokeByAccessJTI(ctx, cmd.UserID, cmd.AccessJTI); err != nil {
				return fmt.Errorf("revoke current session: %w", err)
			}
			revoked = true
		}
	}
	if cmd.RefreshToken != "" {
		refreshHash := hash.SHA256(cmd.RefreshToken)
		if err := l.sessions.RevokeByRefreshHash(ctx, refreshHash); err != nil {
			return fmt.Errorf("revoke session by refresh token: %w", err)
		}
		revoked = true
	}
	if !revoked {
		return apperror.ErrUnauthorized
	}
	l.logger.Info("Đăng xuất thành công", zap.Uint64("user_id", cmd.UserID))
	return nil
}

// Current thu hồi session hiện tại rồi blacklist JTI theo fail-closed policy.
func (l *Logout) Current(
	ctx context.Context,
	userID uint64,
	jti string,
	expiresAt time.Time,
) error {
	return l.Session(ctx, LogoutCommand{
		UserID:    userID,
		AccessJTI: jti,
		ExpiresAt: expiresAt,
	})
}

// All tăng auth_version và xóa mọi session trong một MySQL transaction.
func (l *Logout) All(ctx context.Context, userID uint64) error {
	if err := l.invalidator.InvalidateAll(ctx, userID); err != nil {
		return fmt.Errorf("không thể thu hồi phiên đăng nhập: %w", err)
	}
	l.logger.Info("Đã đăng xuất khỏi tất cả thiết bị", zap.Uint64("user_id", userID))
	return nil
}
