//go:build integration

package auth_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	authapp "github.com/quocdev03/user-access-management/internal/auth"
	mailmessage "github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/database"
)

// File này kiểm chứng tích hợp auth integration với các dependency runtime liên quan.

var (
	authMigrationOnce sync.Once
	authMigrationErr  error
)

// TestRegistrationAndEmailVerificationUseDurableWorkflow kiểm chứng kịch bản RegistrationAndEmailVerificationUseDurableWorkflow.
func TestRegistrationAndEmailVerificationUseDurableWorkflow(t *testing.T) {
	db := openAuthIntegrationDB(t)
	registration, verification, codec := authFixture(t, db)
	email := "auth_registration@example.test"

	registered, err := registration.Register(context.Background(), authapp.RegisterCommand{
		Username:    "auth_registration",
		Email:       email,
		Password:    "AuthTest!Password1",
		FullName:    "Auth Registration",
		Phone:       "0900000001",
		DateOfBirth: "1990-01-01",
	})
	if err != nil {
		t.Fatalf("Register(): %v", err)
	}
	if registered.ID == 0 || registered.Status != "inactive" {
		t.Fatalf("registered account = %+v", registered)
	}

	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ?
		  AND lifecycle_state = 'pending_verification'
		  AND email_verified = 0
		  AND auth_version = 0`,
		registered.ID,
		1,
	)
	assertScalar(t, db, "SELECT COUNT(*) FROM user_profiles WHERE user_id = ?", registered.ID, 1)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.name = 'user'`,
		registered.ID,
		1,
	)

	otp := verificationOTP(t, db, codec, registered.ID)
	if err := verification.Verify(
		context.Background(),
		email,
		differentOTP(otp),
	); !errors.Is(err, apperror.ErrOTPInvalid) {
		t.Fatalf("wrong OTP error = %v, want OTP invalid", err)
	}
	assertScalar(t, db, `
		SELECT attempts
		FROM verification_challenges
		WHERE user_id = ? AND purpose = 'email_verification'
		ORDER BY id DESC LIMIT 1`,
		registered.ID,
		1,
	)

	if err := verification.Verify(context.Background(), email, otp); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM users
		WHERE id = ?
		  AND lifecycle_state = 'active'
		  AND email_verified = 1
		  AND auth_version = 1`,
		registered.ID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM verification_challenges
		WHERE user_id = ? AND consumed_at IS NOT NULL`,
		registered.ID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM outbox_events
		WHERE aggregate_type = 'verification_challenge'
		  AND dead_lettered_at IS NOT NULL
		  AND JSON_EXTRACT(payload, '$.redacted') = TRUE`,
		1,
	)
}

// TestConcurrentVerificationHasOneWinner kiểm chứng kịch bản ConcurrentVerificationHasOneWinner.
func TestConcurrentVerificationHasOneWinner(t *testing.T) {
	db := openAuthIntegrationDB(t)
	registration, verification, codec := authFixture(t, db)
	email := "auth_verify_race@example.test"
	registered, err := registration.Register(context.Background(), authapp.RegisterCommand{
		Username:    "auth_verify_race",
		Email:       email,
		Password:    "AuthTest!Password1",
		FullName:    "Auth Verify Race",
		Phone:       "0900000002",
		DateOfBirth: "1990-01-02",
	})
	if err != nil {
		t.Fatalf("Register(): %v", err)
	}
	otp := verificationOTP(t, db, codec, registered.ID)

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- verification.Verify(context.Background(), email, otp)
		}()
	}
	close(start)

	var successes, rejected int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, apperror.ErrOTPInvalid):
			rejected++
		default:
			t.Fatalf("concurrent Verify() error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf(
			"verification results: success=%d rejected=%d",
			successes,
			rejected,
		)
	}
}

// TestConcurrentResendLeavesOneActiveChallenge kiểm chứng kịch bản ConcurrentResendLeavesOneActiveChallenge.
func TestConcurrentResendLeavesOneActiveChallenge(t *testing.T) {
	db := openAuthIntegrationDB(t)
	registration, verification, _ := authFixture(t, db)
	email := "auth_resend_race@example.test"
	registered, err := registration.Register(context.Background(), authapp.RegisterCommand{
		Username:    "auth_resend_race",
		Email:       email,
		Password:    "AuthTest!Password1",
		FullName:    "Auth Resend Race",
		Phone:       "0900000003",
		DateOfBirth: "1990-01-03",
	})
	if err != nil {
		t.Fatalf("Register(): %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- verification.Resend(context.Background(), email)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Resend(): %v", err)
		}
	}

	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM verification_challenges
		WHERE user_id = ?
		  AND purpose = 'email_verification'
		  AND consumed_at IS NULL
		  AND expires_at > NOW()`,
		registered.ID,
		1,
	)
	assertScalar(t, db, `
		SELECT COUNT(*)
		FROM outbox_events o
		JOIN verification_challenges v ON v.request_id = o.aggregate_id
		WHERE v.user_id = ?
		  AND o.delivered_at IS NULL
		  AND o.dead_lettered_at IS NULL`,
		registered.ID,
		1,
	)
}

// authFixture tạo account cùng verification challenge cho auth integration test.
func authFixture(
	t *testing.T,
	db *sqlx.DB,
) (*authapp.Registration, *authapp.EmailVerification, *mailmessage.SecretCodec) {
	t.Helper()
	codec, err := mailmessage.NewSecretCodec("auth-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	accounts := mysqlstore.NewAccountStore(db)
	verification := authapp.NewEmailVerification(
		db,
		accounts,
		mysqlstore.NewVerificationChallengeStore(db),
		mysqlstore.NewOutboxStore(db),
		mysqlstore.NewAuthInvalidator(db),
		codec,
		"auth-integration-pepper",
		5*time.Minute,
		5,
	)
	registration := authapp.NewRegistration(
		db,
		accounts,
		mysqlstore.NewProfileStore(db),
		mysqlstore.NewRoleStore(db),
		verification,
	)
	return registration, verification, codec
}

// verificationOTP giải mã OTP từ outbox fixture thay vì đọc plaintext persistence.
func verificationOTP(
	t *testing.T,
	db *sqlx.DB,
	codec *mailmessage.SecretCodec,
	userID uint64,
) string {
	t.Helper()
	var payload []byte
	if err := db.Get(&payload, `
		SELECT o.payload
		FROM outbox_events o
		JOIN verification_challenges v ON v.request_id = o.aggregate_id
		WHERE v.user_id = ?
		  AND o.dead_lettered_at IS NULL
		ORDER BY o.id DESC
		LIMIT 1`,
		userID,
	); err != nil {
		t.Fatalf("load verification payload: %v", err)
	}
	message, err := codec.Open(payload)
	if err != nil {
		t.Fatalf("open verification payload: %v", err)
	}
	return message.Secret
}

// differentOTP tạo OTP hợp lệ về định dạng nhưng khác giá trị đầu vào.
func differentOTP(otp string) string {
	if strings.HasPrefix(otp, "0") {
		return "1" + otp[1:]
	}
	return "0" + otp[1:]
}

// assertScalar đọc một scalar MySQL và so sánh với giá trị mong đợi.
func assertScalar(t *testing.T, db *sqlx.DB, query string, args ...any) {
	t.Helper()
	want := args[len(args)-1].(int)
	queryArgs := args[:len(args)-1]
	var got int
	if err := db.Get(&got, query, queryArgs...); err != nil {
		t.Fatalf("query scalar: %v", err)
	}
	if got != want {
		t.Fatalf("query scalar = %d, want %d", got, want)
	}
}

// openAuthIntegrationDB kết nối disposable MySQL cho auth integration test.
func openAuthIntegrationDB(t *testing.T) *sqlx.DB {
	t.Helper()
	name := os.Getenv("UAM_AUTH_TEST_DB_NAME")
	if !strings.HasPrefix(name, "uam_auth_test_") {
		t.Skip("disposable auth database is not configured")
	}
	address := os.Getenv("UAM_AUTH_TEST_DB_ADDR")
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("parse auth integration database address: %v", err)
	}
	user := os.Getenv("UAM_AUTH_TEST_DB_USER")
	password := os.Getenv("UAM_AUTH_TEST_DB_PASSWORD")
	authMigrationOnce.Do(func() {
		authMigrationErr = database.RunMigrations(database.MySQLOptions{
			Host:     host,
			Port:     port,
			Name:     name,
			User:     user,
			Password: password,
		}, "../../migrations", "test")
	})
	if authMigrationErr != nil {
		t.Fatalf("run auth integration migrations: %v", authMigrationErr)
	}
	cfg := mysql.Config{
		User:                 user,
		Passwd:               password,
		Net:                  "tcp",
		Addr:                 address,
		DBName:               name,
		ParseTime:            true,
		Loc:                  time.UTC,
		AllowNativePasswords: true,
	}
	db, err := sqlx.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open auth integration database: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping auth integration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
