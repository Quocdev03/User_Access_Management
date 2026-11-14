//go:build integration

package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	authapp "github.com/quocdev03/user-access-management/internal/auth"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// File này kiểm chứng tích hợp session integration với các dependency runtime liên quan.

// TestRefreshRotatesOnceAndDetectsReuse kiểm chứng kịch bản RefreshRotatesOnceAndDetectsReuse.
func TestRefreshRotatesOnceAndDetectsReuse(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, password, userID := verifiedLoginFixture(t, db, "refresh")
	loggedIn, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  password,
		IPAddress: "127.0.0.4",
		UserAgent: "session-integration-refresh",
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}

	tokenState := &loginTokenState{}
	rotator := sessionapp.NewRotator(
		db,
		mysqlstore.NewSessionStore(db),
		tokenState,
		sessionapp.NewInvalidator(db),
		15*time.Minute,
		24*time.Hour,
	)
	refresh := authapp.NewRefresh(
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewRoleStore(db),
		rotator,
		authapp.TokenPolicy{
			JWTSecret:     "auth-integration-jwt-secret",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 24 * time.Hour,
		},
		zap.NewNop(),
	)
	rotated, err := refresh.Rotate(context.Background(), authapp.RefreshCommand{
		RefreshToken: loggedIn.RefreshToken,
		IPAddress:    "127.0.0.5",
		UserAgent:    "session-integration-refresh-rotated",
	})
	if err != nil {
		t.Fatalf("Rotate(): %v", err)
	}
	if rotated.AccessToken == loggedIn.AccessToken ||
		rotated.RefreshToken == loggedIn.RefreshToken {
		t.Fatal("refresh did not rotate both tokens")
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM refresh_token_history
		WHERE token_hash = ?`,
		hash.SHA256(loggedIn.RefreshToken),
		1,
	)

	_, err = refresh.Rotate(context.Background(), authapp.RefreshCommand{
		RefreshToken: loggedIn.RefreshToken,
		IPAddress:    "127.0.0.6",
		UserAgent:    "session-integration-refresh-reuse",
	})
	if !errors.Is(err, apperror.ErrTokenReuse) {
		t.Fatalf("reused refresh error = %v, want token reuse", err)
	}
	assertScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 0)
	assertScalar(t, db, "SELECT COUNT(*) FROM users WHERE id = ? AND auth_version = 2", userID, 1)
}

// TestLogoutCurrentBlacklistsJTIAndRevokesSession kiểm chứng kịch bản LogoutCurrentBlacklistsJTIAndRevokesSession.
func TestLogoutCurrentBlacklistsJTIAndRevokesSession(t *testing.T) {
	redisAddress := os.Getenv("UAM_AUTH_TEST_REDIS_ADDR")
	if redisAddress == "" {
		t.Skip("disposable session Redis is not configured")
	}
	db := openAuthIntegrationDB(t)
	login, email, password, userID := verifiedLoginFixture(t, db, "logout")
	loggedIn, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  password,
		IPAddress: "127.0.0.7",
		UserAgent: "session-integration-logout",
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}
	claims, err := jwt.ParseToken(loggedIn.AccessToken, "auth-integration-jwt-secret")
	if err != nil {
		t.Fatalf("ParseToken(): %v", err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: redisAddress})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		_ = redisClient.Close()
		t.Fatalf("ping test Redis: %v", err)
	}
	t.Cleanup(func() {
		_ = redisClient.Del(
			context.Background(),
			"uam:v1:jti:"+claims.ID,
		).Err()
		_ = redisClient.Close()
	})
	tokenStore := redisstore.NewTokenStore(redisClient)
	logout := authapp.NewLogout(
		mysqlstore.NewSessionStore(db),
		tokenStore,
		sessionapp.NewInvalidator(db),
		zap.NewNop(),
	)
	if err := logout.Current(
		context.Background(),
		userID,
		claims.ID,
		claims.ExpiresAt.Time,
	); err != nil {
		t.Fatalf("Current(): %v", err)
	}
	blacklisted, err := tokenStore.IsJTIBlacklisted(context.Background(), claims.ID)
	if err != nil {
		t.Fatalf("IsJTIBlacklisted(): %v", err)
	}
	if !blacklisted {
		t.Fatal("logout did not blacklist current access JTI")
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM sessions
		WHERE user_id = ? AND revoked_at IS NOT NULL`,
		userID,
		1,
	)
}

// TestLogoutAllInvalidatesDurableAuthState kiểm chứng kịch bản LogoutAllInvalidatesDurableAuthState.
func TestLogoutAllInvalidatesDurableAuthState(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, password, userID := verifiedLoginFixture(t, db, "logout_all")
	if _, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  password,
		IPAddress: "127.0.0.8",
		UserAgent: "session-integration-logout-all",
	}); err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}
	logout := authapp.NewLogout(
		mysqlstore.NewSessionStore(db),
		nil,
		sessionapp.NewInvalidator(db),
		zap.NewNop(),
	)
	if err := logout.All(context.Background(), userID); err != nil {
		t.Fatalf("All(): %v", err)
	}
	assertScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 0)
	assertScalar(t, db, "SELECT COUNT(*) FROM users WHERE id = ? AND auth_version = 2", userID, 1)
}

// TestLogoutSessionWithRefreshTokenAndExpiredAccess kiểm chứng thu hồi session khi access token đã hết hạn hoặc dùng refresh token.
func TestLogoutSessionWithRefreshTokenAndExpiredAccess(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, password, userID := verifiedLoginFixture(t, db, "logout_refresh")
	loggedIn, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  password,
		IPAddress: "127.0.0.9",
		UserAgent: "session-integration-logout-refresh",
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}

	logout := authapp.NewLogout(
		mysqlstore.NewSessionStore(db),
		nil,
		sessionapp.NewInvalidator(db),
		zap.NewNop(),
	)

	// Thu hồi bằng refresh token mà không cần access token còn hạn
	if err := logout.Session(context.Background(), authapp.LogoutCommand{
		RefreshToken: loggedIn.RefreshToken,
	}); err != nil {
		t.Fatalf("Session() with refresh token: %v", err)
	}

	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM sessions
		WHERE user_id = ? AND revoked_at IS NOT NULL`,
		userID,
		1,
	)
}
