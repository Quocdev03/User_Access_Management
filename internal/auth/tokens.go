package auth

import (
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/pkg/jwt"
)

// File này gom dependency phát hành và luân chuyển token cho auth use case.

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

// TokenPolicy chứa cấu hình bí mật ký JWT và thời gian sống của access token và refresh token.
type TokenPolicy struct {
	JWTSecret     string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

// generateTokenPair phát hành access/refresh token dùng cùng account snapshot.
func generateTokenPair(
	userID uint64,
	authVersion uint64,
	roles []string,
	policy TokenPolicy,
) (accessToken, refreshToken, accessJTI string, err error) {
	accessToken, accessJTI, err = jwt.GenerateTokenWithAuthVersion(
		userID,
		authVersion,
		roles,
		tokenTypeAccess,
		policy.AccessExpiry,
		policy.JWTSecret,
	)
	if err != nil {
		return "", "", "", fmt.Errorf("generate access token: %w", err)
	}
	refreshToken, _, err = jwt.GenerateTokenWithAuthVersion(
		userID,
		authVersion,
		roles,
		tokenTypeRefresh,
		policy.RefreshExpiry,
		policy.JWTSecret,
	)
	if err != nil {
		return "", "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	return accessToken, refreshToken, accessJTI, nil
}
