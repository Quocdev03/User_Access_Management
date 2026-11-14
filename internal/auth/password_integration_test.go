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
	"github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này kiểm chứng tích hợp password integration với các dependency runtime liên quan.

// TestPasswordResetUsesVersionedTokenAndInvalidatesAuth kiểm chứng kịch bản PasswordResetUsesVersionedTokenAndInvalidatesAuth.
func TestPasswordResetUsesVersionedTokenAndInvalidatesAuth(t *testing.T) {
	db := openAuthIntegrationDB(t)
	login, email, currentPassword, userID := verifiedLoginFixture(t, db, "password_reset")
	loggedIn, err := login.Authenticate(context.Background(), authapp.LoginCommand{
		Email:     email,
		Password:  currentPassword,
		IPAddress: "127.0.0.20",
		UserAgent: "password-integration-reset-login",
	})
	if err != nil {
		t.Fatalf("Authenticate(): %v", err)
	}
	if loggedIn.AccessToken == "" {
		t.Fatal("login did not issue a session")
	}

	passwords, codec := passwordFixture(t, db)
	if err := passwords.Forgot(context.Background(), email); err != nil {
		t.Fatalf("Forgot(): %v", err)
	}
	token := passwordResetToken(t, db, codec, userID)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM password_reset_tokens
		WHERE user_id = ? AND auth_version = 1 AND consumed_at IS NULL`,
		userID,
		1,
	)

	newPassword := "AuthTest!ResetPassword2"
	if err := passwords.Reset(context.Background(), authapp.ResetPasswordCommand{
		Token:       token,
		NewPassword: newPassword,
		Metadata: authapp.PasswordMetadata{
			IPAddress: "127.0.0.21",
			UserAgent: "password-integration-reset",
		},
	}); err != nil {
		t.Fatalf("Reset(): %v", err)
	}

	var storedHash string
	if err := db.Get(&storedHash, "SELECT password_hash FROM users WHERE id = ?", userID); err != nil {
		t.Fatalf("load reset password hash: %v", err)
	}
	if !hash.CheckPassword(newPassword, storedHash) {
		t.Fatal("new password was not persisted")
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ?
		  AND auth_version = 2
		  AND failed_login_attempts = 0
		  AND password_change_required = FALSE`,
		userID,
		1,
	)
	assertScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 0)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM password_reset_tokens
		WHERE user_id = ? AND consumed_at IS NOT NULL`,
		userID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ? AND action = 'PASSWORD_RESET' AND status = 'success'`,
		userID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM outbox_events
		WHERE event_type = 'mail.password_reset_requested'
		  AND aggregate_type = 'password_reset_token'
		  AND dead_lettered_at IS NOT NULL
		  AND JSON_EXTRACT(payload, '$.redacted') = TRUE`,
		1,
	)
}

// TestConcurrentPasswordResetHasOneWinner kiểm chứng kịch bản ConcurrentPasswordResetHasOneWinner.
func TestConcurrentPasswordResetHasOneWinner(t *testing.T) {
	db := openAuthIntegrationDB(t)
	_, email, _, userID := verifiedLoginFixture(t, db, "password_reset_race")
	passwords, codec := passwordFixture(t, db)
	if err := passwords.Forgot(context.Background(), email); err != nil {
		t.Fatalf("Forgot(): %v", err)
	}
	token := passwordResetToken(t, db, codec, userID)

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- passwords.Reset(context.Background(), authapp.ResetPasswordCommand{
				Token:       token,
				NewPassword: "AuthTest!ConcurrentReset2",
			})
		}()
	}
	close(start)

	var successes, rejected int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, apperror.ErrResetTokenInvalid),
			errors.Is(err, apperror.ErrResetTokenUsed):
			rejected++
		default:
			t.Fatalf("concurrent Reset() error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("reset results: success=%d rejected=%d", successes, rejected)
	}
	assertScalar(t, db, "SELECT COUNT(*) FROM audit_logs WHERE user_id = ? AND action = 'PASSWORD_RESET'", userID, 1)
}

// TestChangePasswordWrongCredentialCommitsAttempt kiểm chứng kịch bản ChangePasswordWrongCredentialCommitsAttempt.
func TestChangePasswordWrongCredentialCommitsAttempt(t *testing.T) {
	db := openAuthIntegrationDB(t)
	_, _, _, userID := verifiedLoginFixture(t, db, "password_change_wrong")
	passwords, _ := passwordFixture(t, db)

	err := passwords.Change(
		context.Background(),
		userID,
		authapp.ChangePasswordCommand{
			CurrentPassword: "Wrong!Password1",
			NewPassword:     "AuthTest!ChangedPassword2",
		},
	)
	if !errors.Is(err, apperror.ErrInvalidCredentials) {
		t.Fatalf("Change() error = %v, want invalid credentials", err)
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ?
		  AND failed_login_attempts = 1
		  AND auth_version = 1`,
		userID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ? AND action = 'PASSWORD_CHANGE'`,
		userID,
		0,
	)
}

// TestPasswordCredentialSnapshotsRejectConcurrentMutation kiểm chứng kịch bản PasswordCredentialSnapshotsRejectConcurrentMutation.
func TestPasswordCredentialSnapshotsRejectConcurrentMutation(t *testing.T) {
	tests := []struct {
		name      string
		wantError error
		start     func(*testing.T, *sqlx.DB, *authapp.Password, *mail.SecretCodec, string, string, uint64) <-chan error
		setup     func(*testing.T, *sqlx.DB, uint64, string)
	}{
		{
			name:      "reset",
			wantError: apperror.ErrResetTokenInvalid,
			start: func(
				_ *testing.T,
				_ *sqlx.DB,
				passwords *authapp.Password,
				_ *mail.SecretCodec,
				_ string,
				token string,
				_ uint64,
			) <-chan error {
				result := make(chan error, 1)
				go func() {
					result <- passwords.Reset(context.Background(), authapp.ResetPasswordCommand{
						Token:       token,
						NewPassword: "AuthTest!StaleReset2",
					})
				}()
				return result
			},
		},
		{
			name:      "change",
			wantError: apperror.ErrInvalidCredentials,
			start: func(
				_ *testing.T,
				_ *sqlx.DB,
				passwords *authapp.Password,
				_ *mail.SecretCodec,
				_ string,
				currentPassword string,
				userID uint64,
			) <-chan error {
				result := make(chan error, 1)
				go func() {
					result <- passwords.Change(
						context.Background(),
						userID,
						authapp.ChangePasswordCommand{
							CurrentPassword: currentPassword,
							NewPassword:     "AuthTest!StaleChange2",
						},
					)
				}()
				return result
			},
		},
		{
			name:      "force_change",
			wantError: apperror.ErrInvalidCredentials,
			setup: func(t *testing.T, db *sqlx.DB, userID uint64, _ string) {
				t.Helper()
				if _, err := db.Exec(`
					UPDATE users
					SET password_change_required = TRUE,
						auth_version = auth_version + 1
					WHERE id = ?`,
					userID,
				); err != nil {
					t.Fatalf("require password change: %v", err)
				}
			},
			start: func(
				_ *testing.T,
				_ *sqlx.DB,
				passwords *authapp.Password,
				_ *mail.SecretCodec,
				email string,
				currentPassword string,
				_ uint64,
			) <-chan error {
				result := make(chan error, 1)
				go func() {
					result <- passwords.ForceChange(
						context.Background(),
						authapp.ForceChangePasswordCommand{
							Email:           email,
							CurrentPassword: currentPassword,
							NewPassword:     "AuthTest!StaleForce2",
						},
					)
				}()
				return result
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := openAuthIntegrationDB(t)
			_, email, currentPassword, userID := verifiedLoginFixture(
				t,
				db,
				"password_snapshot_"+strings.ReplaceAll(test.name, "_", ""),
			)
			if test.setup != nil {
				test.setup(t, db, userID, currentPassword)
			}
			passwords, codec := passwordFixture(t, db)
			operationCredential := currentPassword
			if test.name == "reset" {
				if err := passwords.Forgot(context.Background(), email); err != nil {
					t.Fatalf("Forgot(): %v", err)
				}
				operationCredential = passwordResetToken(t, db, codec, userID)
			}

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

			result := test.start(
				t,
				db,
				passwords,
				codec,
				email,
				operationCredential,
				userID,
			)
			waitForLoginRowLock(t, db)

			winnerPassword := "AuthTest!ConcurrentWinner2"
			winnerHash, err := hash.HashPassword(winnerPassword)
			if err != nil {
				t.Fatalf("HashPassword(): %v", err)
			}
			if _, err := lockTx.ExecContext(context.Background(), `
				UPDATE users
				SET password_hash = ?, auth_version = auth_version + 1
				WHERE id = ?`,
				winnerHash,
				userID,
			); err != nil {
				t.Fatalf("write concurrent credential: %v", err)
			}
			if err := lockTx.Commit(); err != nil {
				t.Fatalf("commit concurrent credential: %v", err)
			}

			select {
			case err := <-result:
				if !errors.Is(err, test.wantError) {
					t.Fatalf("stale operation error = %v, want %v", err, test.wantError)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stale password operation did not resume")
			}

			var storedHash string
			if err := db.Get(
				&storedHash,
				"SELECT password_hash FROM users WHERE id = ?",
				userID,
			); err != nil {
				t.Fatalf("load winning password: %v", err)
			}
			if !hash.CheckPassword(winnerPassword, storedHash) {
				t.Fatal("stale password operation overwrote the concurrent winner")
			}
		})
	}
}

// passwordFixture tạo account đã xác minh với password hash dùng cho integration test.
func passwordFixture(
	t *testing.T,
	db *sqlx.DB,
) (*authapp.Password, *mail.SecretCodec) {
	t.Helper()
	codec, err := mail.NewSecretCodec("auth-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	return authapp.NewPassword(
		db,
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewPasswordResetStore(db),
		mysqlstore.NewOutboxStore(db),
		mysqlstore.NewAuditStore(db),
		mysqlstore.NewAuthInvalidator(db),
		codec,
		mysqlstore.NewEmailChangeStore(db),
		authapp.PasswordPolicy{
			ResetExpiry:       time.Hour,
			MaxFailedAttempts: 5,
			LockDuration:      30 * time.Minute,
		},
	), codec
}

// passwordResetToken giải mã reset token từ durable outbox fixture.
func passwordResetToken(
	t *testing.T,
	db *sqlx.DB,
	codec *mail.SecretCodec,
	userID uint64,
) string {
	t.Helper()
	var payload []byte
	if err := db.Get(&payload, `
		SELECT o.payload
		FROM outbox_events o
		JOIN password_reset_tokens p
		  ON CAST(o.aggregate_id AS UNSIGNED) = p.id
		WHERE p.user_id = ?
		  AND o.event_type = 'mail.password_reset_requested'
		  AND o.dead_lettered_at IS NULL
		ORDER BY o.id DESC
		LIMIT 1`,
		userID,
	); err != nil {
		t.Fatalf("load password reset payload: %v", err)
	}
	message, err := codec.Open(payload)
	if err != nil {
		t.Fatalf("open password reset payload: %v", err)
	}
	return message.Secret
}
