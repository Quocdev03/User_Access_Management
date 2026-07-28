package auth

import (
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/pkg/jwt"
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type TokenPolicy struct {
	JWTSecret     string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

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
