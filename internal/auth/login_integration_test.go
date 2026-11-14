//go:build integration

package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	authapp "github.com/quocdev03/user-access-management/internal/auth"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"go.uber.org/zap"
)

// File này kiểm chứng tích hợp login integration với các dependency runtime liên quan.

// TestLoginIssuesCanonicalSessionAndAudit kiểm chứng kịch bản LoginIssuesCanonicalSessionAndAudit.
func TestLoginIssuesCanonicalSessionAndAudit(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, password, userID := verifiedLoginFixture(t, db, "success")

	result, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  password,
		IPAddress: "127.0.0.1",
		UserAgent: "login-integration-success",
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}
	if result.UserID != userID ||
		result.Email != email ||
		result.FullName != "Login Integration success" {
		t.Fatalf("login result = %+v", result)
	}
	claims, err := jwt.ParseToken(result.AccessToken, "auth-integration-jwt-secret")
	if err != nil {
		t.Fatalf("ParseToken(): %v", err)
	}
	if claims.UserID != userID || claims.AuthVersion != 1 {
		t.Fatalf("access claims = %+v", claims)
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM sessions
		WHERE user_id = ?
		  AND revoked_at IS NULL
		  AND access_jti IS NOT NULL
		  AND current_refresh_hash IS NOT NULL`,
		userID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ? AND action = 'LOGIN' AND status = 'success'`,
		userID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ? AND last_login_at IS NOT NULL`,
		userID,
		1,
	)
}

// TestLoginWrongPasswordCommitsAttempt kiểm chứng kịch bản LoginWrongPasswordCommitsAttempt.
func TestLoginWrongPasswordCommitsAttempt(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, _, userID := verifiedLoginFixture(t, db, "wrong_password")

	_, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  "Wrong!Password1",
		IPAddress: "127.0.0.2",
		UserAgent: "login-integration-wrong-password",
	})
	if !errors.Is(err, apperror.ErrInvalidCredentials) {
		t.Fatalf("Authenticate() error = %v, want invalid credentials", err)
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ?
		  AND failed_login_attempts = 1
		  AND login_locked_until IS NULL`,
		userID,
		1,
	)
	assertScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 0)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ? AND action = 'LOGIN' AND status = 'failure'`,
		userID,
		1,
	)
}

// TestLoginDoesNotRevealDisabledStateBeforeCredentialProof kiểm chứng kịch bản LoginDoesNotRevealDisabledStateBeforeCredentialProof.
func TestLoginDoesNotRevealDisabledStateBeforeCredentialProof(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, password, userID := verifiedLoginFixture(t, db, "disabled_state")
	if _, err := db.Exec(`
		UPDATE users
		SET lifecycle_state = 'disabled'
		WHERE id = ?`,
		userID,
	); err != nil {
		t.Fatalf("disable account fixture: %v", err)
	}

	_, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:    email,
		Password: "Wrong!Password1",
	})
	if !errors.Is(err, apperror.ErrInvalidCredentials) {
		t.Fatalf("wrong credential error = %v, want invalid credentials", err)
	}

	_, err = login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:    email,
		Password: password,
	})
	if !errors.Is(err, apperror.ErrAccountDisabled) {
		t.Fatalf("proved credential error = %v, want account disabled", err)
	}
}

// TestLoginRejectsCredentialChangedAfterBcryptSnapshot kiểm chứng kịch bản LoginRejectsCredentialChangedAfterBcryptSnapshot.
func TestLoginRejectsCredentialChangedAfterBcryptSnapshot(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, oldPassword, userID := verifiedLoginFixture(t, db, "snapshot")

	lockTx, err := db.BeginTxx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTxx(): %v", err)
	}
	defer func() { _ = lockTx.Rollback() }()
	var lockedID uint64
	if err := lockTx.GetContext(
		context.Background(),
		&lockedID,
		"SELECT id FROM users WHERE id = ? FOR UPDATE",
		userID,
	); err != nil {
		t.Fatalf("lock account: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := login.Authenticate(context.Background(), authapp.LoginCommand{
			Email:     email,
			Password:  oldPassword,
			IPAddress: "127.0.0.3",
			UserAgent: "login-integration-snapshot",
		})
		result <- err
	}()
	waitForLoginRowLock(t, db)

	newPasswordHash, err := hash.HashPassword("AuthTest!NewPassword1")
	if err != nil {
		t.Fatalf("HashPassword(): %v", err)
	}
	if _, err := lockTx.ExecContext(context.Background(), `
		UPDATE users
		SET password_hash = ?, auth_version = auth_version + 1
		WHERE id = ?`,
		newPasswordHash,
		userID,
	); err != nil {
		t.Fatalf("update credential while login waits: %v", err)
	}
	if err := lockTx.Commit(); err != nil {
		t.Fatalf("commit credential update: %v", err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, apperror.ErrInvalidCredentials) {
			t.Fatalf("stale login error = %v, want invalid credentials", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale login did not resume after credential commit")
	}
	assertScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 0)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ? AND failed_login_attempts = 0 AND auth_version = 2`,
		userID,
		1,
	)
}

// verifiedLoginFixture tạo account đã xác minh với credential dùng cho login test.
func verifiedLoginFixture(
	t *testing.T,
	db *sqlx.DB,
	suffix string,
) (*authapp.Login, string, string, uint64) {
	t.Helper()
	registration, verification, codec := authFixture(t, db)
	email := "login_integration_" + suffix + "@example.test"
	password := "AuthTest!Password1"
	registered, err := registration.Register(context.Background(), authapp.RegisterCommand{
		Username:    "login_integration_" + suffix,
		Email:       email,
		Password:    password,
		FullName:    "Login Integration " + strings.ReplaceAll(suffix, "_", " "),
		Phone:       "0900000010",
		DateOfBirth: "1990-01-10",
	})
	if err != nil {
		t.Fatalf("Register(): %v", err)
	}
	if err := verification.Verify(
		context.Background(),
		email,
		verificationOTP(t, db, codec, registered.ID),
	); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	tokenState := &loginTokenState{}
	issuer := sessionapp.NewIssuer(
		mysqlstore.NewSessionStore(db),
		mysqlstore.NewClientProfileStore(db),
		tokenState,
		sessionapp.NewInvalidator(db),
		10,
		15*time.Minute,
		24*time.Hour,
	)
	accountStore := mysqlstore.NewAccountStore(db)
	mfa := authapp.NewMFA(
		authapp.MFADependencies{
			DB:       db,
			Accounts: accountStore,
			Store:    mysqlstore.NewMFAStore(db),
		},
		authapp.MFAPolicy{},
	)
	login := authapp.NewLogin(
		db,
		accountStore,
		mysqlstore.NewProfileStore(db),
		mysqlstore.NewRoleStore(db),
		mysqlstore.NewAuditStore(db),
		issuer,
		mfa,
		authapp.LoginPolicy{
			TokenPolicy: authapp.TokenPolicy{
				JWTSecret:     "auth-integration-jwt-secret",
				AccessExpiry:  15 * time.Minute,
				RefreshExpiry: 24 * time.Hour,
			},
			MaxFailedAttempts: 5,
			LockDuration:      30 * time.Minute,
		},
		zap.NewNop(),
	)
	return login, email, password, registered.ID
}

// waitForLoginRowLock chờ transaction giữ account row lock trước khi phát request cạnh tranh.
func waitForLoginRowLock(t *testing.T, db *sqlx.DB) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := db.Get(&waiting, `
			SELECT COUNT(*)
			FROM information_schema.PROCESSLIST
			WHERE DB = DATABASE()
			  AND COMMAND = 'Query'
			  AND INFO LIKE '%FROM users%'
			  AND INFO LIKE '%FOR UPDATE%'`); err != nil {
			t.Fatalf("inspect login row-lock wait: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("login did not reach account row lock")
}

// loginTokenState là stub triển khai TokenState phục vụ integration test đăng nhập.
type loginTokenState struct{}

// BlacklistJTI ghi nhận JTI mà login fixture yêu cầu blacklist.
func (*loginTokenState) BlacklistJTI(context.Context, string, time.Duration) error {
	return nil
}

// IsRefreshReuseMarked đọc reuse marker từ in-memory token state.
func (*loginTokenState) IsRefreshReuseMarked(context.Context, string) (bool, error) {
	return false, nil
}

// MarkRefreshReuse lưu reuse marker trong in-memory token state.
func (*loginTokenState) MarkRefreshReuse(context.Context, string, time.Duration) error {
	return nil
}
