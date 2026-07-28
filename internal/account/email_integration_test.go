//go:build integration

package account_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	accountapp "github.com/quocdev03/user-access-management/internal/account"
	"github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

func TestEmailChangeUsesDurableRequestChallengesAndOutbox(t *testing.T) {
	db := openAccountIntegrationDB(t)
	email, codec, userID, oldEmail, password := emailFixture(t, db, "durable")
	newEmail := "email_durable_new@example.test"

	if err := email.Request(context.Background(), userID, accountapp.RequestEmailChangeCommand{
		CurrentPassword: password,
		NewEmail:        newEmail,
		Metadata: accountapp.EmailMetadata{
			IPAddress: "127.0.0.41",
			UserAgent: "email-integration-request",
		},
	}); err != nil {
		t.Fatalf("Request(): %v", err)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM email_change_requests
		WHERE user_id = ? AND state = 'pending'
		  AND old_email = ? AND new_email = ?`,
		userID,
		oldEmail,
		newEmail,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM verification_challenges
		WHERE user_id = ? AND email_change_request_id IS NOT NULL
		  AND consumed_at IS NULL`,
		userID,
		2,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM outbox_events
		WHERE event_type = 'mail.email_change_verification_requested'
		  AND delivered_at IS NULL AND dead_lettered_at IS NULL`,
		2,
	)

	oldOTP := emailChangeOTP(t, db, codec, userID, "change_email_old")
	newOTP := emailChangeOTP(t, db, codec, userID, "change_email_new")
	if err := email.Verify(context.Background(), userID, accountapp.VerifyEmailChangeCommand{
		OldOTP: differentAccountOTP(oldOTP),
		NewOTP: newOTP,
	}); !errors.Is(err, apperror.ErrOTPInvalid) {
		t.Fatalf("wrong Verify() error = %v, want OTP invalid", err)
	}
	assertAccountScalar(t, db, `
		SELECT attempts
		FROM verification_challenges
		WHERE user_id = ? AND purpose = 'change_email_old'
		ORDER BY id DESC LIMIT 1`,
		userID,
		1,
	)

	if err := email.Verify(context.Background(), userID, accountapp.VerifyEmailChangeCommand{
		OldOTP: oldOTP,
		NewOTP: newOTP,
		Metadata: accountapp.EmailMetadata{
			IPAddress: "127.0.0.42",
			UserAgent: "email-integration-verify",
		},
	}); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ? AND email = ? AND auth_version = 2`,
		userID,
		newEmail,
		1,
	)
	assertAccountScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 0)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM email_change_requests
		WHERE user_id = ? AND state = 'completed' AND completed_at IS NOT NULL`,
		userID,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM verification_challenges
		WHERE user_id = ? AND email_change_request_id IS NOT NULL
		  AND consumed_at IS NOT NULL`,
		userID,
		2,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM password_reset_tokens
		WHERE user_id = ? AND consumed_at IS NOT NULL`,
		userID,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM outbox_events
		WHERE event_type = 'mail.email_change_completed'
		  AND aggregate_type = 'email_change_request'
		  AND dead_lettered_at IS NULL`,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = ?
		  AND action IN ('REQUEST_EMAIL_CHANGE', 'VERIFY_EMAIL_CHANGE')`,
		userID,
		2,
	)
}

func TestConcurrentEmailChangeResendLeavesOnePendingWorkflow(t *testing.T) {
	db := openAccountIntegrationDB(t)
	email, _, userID, _, password := emailFixture(t, db, "resend")
	if err := email.Request(context.Background(), userID, accountapp.RequestEmailChangeCommand{
		CurrentPassword: password,
		NewEmail:        "email_resend_new@example.test",
	}); err != nil {
		t.Fatalf("Request(): %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- email.Resend(context.Background(), userID)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Resend(): %v", err)
		}
	}

	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM email_change_requests
		WHERE user_id = ? AND state = 'pending'`,
		userID,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM verification_challenges
		WHERE user_id = ? AND email_change_request_id IS NOT NULL
		  AND consumed_at IS NULL AND expires_at > NOW()`,
		userID,
		2,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM outbox_events o
		JOIN verification_challenges v ON v.request_id = o.aggregate_id
		WHERE v.user_id = ?
		  AND o.event_type = 'mail.email_change_verification_requested'
		  AND o.delivered_at IS NULL AND o.dead_lettered_at IS NULL`,
		userID,
		2,
	)
}

func TestConcurrentEmailChangeVerifyHasOneWinner(t *testing.T) {
	db := openAccountIntegrationDB(t)
	email, codec, userID, _, password := emailFixture(t, db, "verify_race")
	if err := email.Request(context.Background(), userID, accountapp.RequestEmailChangeCommand{
		CurrentPassword: password,
		NewEmail:        "email_verify_race_new@example.test",
	}); err != nil {
		t.Fatalf("Request(): %v", err)
	}
	oldOTP := emailChangeOTP(t, db, codec, userID, "change_email_old")
	newOTP := emailChangeOTP(t, db, codec, userID, "change_email_new")

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- email.Verify(context.Background(), userID, accountapp.VerifyEmailChangeCommand{
				OldOTP: oldOTP,
				NewOTP: newOTP,
			})
		}()
	}
	close(start)
	successes := 0
	rejected := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		default:
			var appErr *apperror.AppError
			if errors.As(err, &appErr) && appErr.Code == apperror.ErrBadRequest.Code {
				rejected++
				continue
			}
			t.Fatalf("concurrent Verify() error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("verify results: success=%d rejected=%d", successes, rejected)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM email_change_requests
		WHERE user_id = ? AND state = 'completed'`,
		userID,
		1,
	)
}

func TestEmailChangeConflictCancelsWorkflowWithoutChangingAccount(t *testing.T) {
	db := openAccountIntegrationDB(t)
	email, codec, userID, oldEmail, password := emailFixture(t, db, "conflict")
	newEmail := "email_conflict_new@example.test"
	if err := email.Request(context.Background(), userID, accountapp.RequestEmailChangeCommand{
		CurrentPassword: password,
		NewEmail:        newEmail,
	}); err != nil {
		t.Fatalf("Request(): %v", err)
	}
	oldOTP := emailChangeOTP(t, db, codec, userID, "change_email_old")
	newOTP := emailChangeOTP(t, db, codec, userID, "change_email_new")

	if _, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, lifecycle_state, email_verified,
			failed_login_attempts,
			password_change_required, auth_version
		) VALUES (
			'email_conflict_owner', ?, ?, 'active', TRUE, 0, FALSE, 1
		)`,
		newEmail,
		hash.DummyPasswordHash,
	); err != nil {
		t.Fatalf("create conflicting email owner: %v", err)
	}

	err := email.Verify(context.Background(), userID, accountapp.VerifyEmailChangeCommand{
		OldOTP: oldOTP,
		NewOTP: newOTP,
	})
	var appErr *apperror.AppError
	if !errors.As(err, &appErr) || appErr.Code != apperror.ErrConflict.Code {
		t.Fatalf("Verify() error = %v, want conflict", err)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*) FROM users
		WHERE id = ? AND email = ? AND auth_version = 1`,
		userID,
		oldEmail,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*) FROM email_change_requests
		WHERE user_id = ? AND state = 'cancelled'`,
		userID,
		1,
	)
	assertAccountScalar(t, db, `
		SELECT COUNT(*) FROM verification_challenges
		WHERE user_id = ? AND consumed_at IS NOT NULL`,
		userID,
		2,
	)
	assertAccountScalar(t, db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", userID, 1)
}

func emailFixture(
	t *testing.T,
	db *sqlx.DB,
	suffix string,
) (*accountapp.Email, *mail.SecretCodec, uint64, string, string) {
	t.Helper()
	username := "email_integration_" + suffix
	oldEmail := username + "@example.test"
	password := "EmailTest!Password1"
	passwordHash, err := hash.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword(): %v", err)
	}
	result, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, lifecycle_state, email_verified,
			administrative_locked_at, login_locked_until,
			failed_login_attempts, password_change_required, auth_version
		) VALUES (?, ?, ?, 'active', TRUE, NULL, NULL, 0, FALSE, 1)`,
		username,
		oldEmail,
		passwordHash,
	)
	if err != nil {
		t.Fatalf("create email account: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read email account ID: %v", err)
	}
	userID := uint64(id)
	jti := fmt.Sprintf("email-integration-jti-%d", userID)
	ipAddress := "127.0.0.40"
	userAgent := "email-integration-session"
	if err := mysqlstore.NewSessionStore(db).Create(context.Background(), &mysqlstore.Session{
		UserID:             userID,
		CurrentRefreshHash: "email-integration-refresh-" + suffix,
		AccessJTI:          jti,
		IPAddress:          &ipAddress,
		UserAgent:          &userAgent,
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create email session: %v", err)
	}
	if _, err := mysqlstore.NewPasswordResetStore(db).Create(
		context.Background(),
		userID,
		"email-integration-reset-"+suffix,
		1,
		time.Now().UTC().Add(time.Hour),
	); err != nil {
		t.Fatalf("create email reset token: %v", err)
	}
	codec, err := mail.NewSecretCodec("email-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	return accountapp.NewEmail(
		db,
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewEmailChangeStore(db),
		mysqlstore.NewVerificationChallengeStore(db),
		mysqlstore.NewPasswordResetStore(db),
		mysqlstore.NewOutboxStore(db),
		mysqlstore.NewAuditStore(db),
		mysqlstore.NewAuthInvalidator(db),
		codec,
		"email-integration-pepper",
		accountapp.EmailPolicy{
			Expiry:      15 * time.Minute,
			MaxAttempts: 5,
		},
	), codec, userID, oldEmail, password
}

func emailChangeOTP(
	t *testing.T,
	db *sqlx.DB,
	codec *mail.SecretCodec,
	userID uint64,
	purpose string,
) string {
	t.Helper()
	var payload []byte
	if err := db.Get(&payload, `
		SELECT o.payload
		FROM outbox_events o
		JOIN verification_challenges v ON v.request_id = o.aggregate_id
		WHERE v.user_id = ? AND v.purpose = ?
		  AND v.consumed_at IS NULL
		  AND o.dead_lettered_at IS NULL
		ORDER BY o.id DESC LIMIT 1`,
		userID,
		purpose,
	); err != nil {
		t.Fatalf("load email-change OTP payload: %v", err)
	}
	message, err := codec.Open(payload)
	if err != nil {
		t.Fatalf("open email-change OTP payload: %v", err)
	}
	return message.Secret
}

func differentAccountOTP(otp string) string {
	if otp[0] == '0' {
		return "1" + otp[1:]
	}
	return "0" + otp[1:]
}
