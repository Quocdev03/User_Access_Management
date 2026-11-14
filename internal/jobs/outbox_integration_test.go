//go:build integration

package jobs

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/config"
	mailmessage "github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/database"
	"go.uber.org/zap"
)

// File này kiểm chứng tích hợp outbox integration với các dependency runtime liên quan.

var (
	jobsMigrationOnce sync.Once
	jobsMigrationErr  error
)

// fakeVerificationSender là test double ghi nhận các lời gọi gửi email xác thực phục vụ kiểm thử outbox worker.
type fakeVerificationSender struct {
	err        error
	to         string
	otp        string
	resetToken string
}

// SendVerificationEmail gửi xác minh email trong bounded worker.
func (s *fakeVerificationSender) SendVerificationEmail(ctx context.Context, to, otp string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	s.to = to
	s.otp = otp
	return nil
}

// SendPasswordResetEmail gửi mật khẩu đặt lại email trong bounded worker.
func (s *fakeVerificationSender) SendPasswordResetEmail(ctx context.Context, to, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	s.to = to
	s.resetToken = token
	return nil
}

// SendEmailChangeVerification gửi email thay đổi xác minh trong bounded worker.
func (s *fakeVerificationSender) SendEmailChangeVerification(ctx context.Context, to, otp string) error {
	return s.SendVerificationEmail(ctx, to, otp)
}

// SendEmailChangeNotification ghi nhận cảnh báo đổi email trong fake mail sender.
func (s *fakeVerificationSender) SendEmailChangeNotification(ctx context.Context, oldEmail, newEmail string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	s.to = oldEmail
	s.resetToken = newEmail
	return nil
}

// SendAdminNotification ghi nhận thông báo quản trị trong fake mail sender.
func (s *fakeVerificationSender) SendAdminNotification(ctx context.Context, to, subject, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	s.to = to
	s.otp = subject
	s.resetToken = message
	return nil
}

var errDeliveryUnavailable = errors.New("delivery unavailable")

// TestOutboxWorkerDeliversAndRedactsVerificationPayload kiểm chứng kịch bản OutboxWorkerDeliversAndRedactsVerificationPayload.
func TestOutboxWorkerDeliversAndRedactsVerificationPayload(t *testing.T) {
	db := openJobsIntegrationDB(t)
	clearOutboxFixtures(t, db)
	codec, err := mailmessage.NewSecretCodec("jobs-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.Seal(mailmessage.SecretMessage{
		To:     "jobs_success@example.test",
		Secret: "654321",
	})
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	store := mysqlstore.NewOutboxStore(db)
	if err := store.Enqueue(context.Background(), &mysqlstore.OutboxEvent{
		EventType:      mailmessage.VerificationRequested,
		AggregateType:  "verification_challenge",
		AggregateID:    "jobs-integration-success",
		Payload:        payload,
		IdempotencyKey: "jobs-integration-success",
		MaxAttempts:    3,
		AvailableAt:    time.Now().UTC().Add(-time.Second),
	}); err != nil {
		t.Fatalf("Enqueue(): %v", err)
	}

	sender := &fakeVerificationSender{}
	worker := NewOutboxWorker(
		db,
		store,
		codec,
		sender,
		testOutboxConfig(),
		zap.NewNop(),
	)
	worker.runOnce(context.Background())
	if sender.to != "jobs_success@example.test" || sender.otp != "654321" {
		t.Fatalf("delivered message = to:%q otp:%q", sender.to, sender.otp)
	}

	var state struct {
		Attempts  int            `db:"attempts"`
		Delivered sql.NullTime   `db:"delivered_at"`
		Payload   string         `db:"payload"`
		ClaimedBy sql.NullString `db:"claimed_by"`
	}
	if err := db.Get(&state, `
		SELECT attempts, delivered_at, CAST(payload AS CHAR) AS payload, claimed_by
		FROM outbox_events
		WHERE idempotency_key = 'jobs-integration-success'`); err != nil {
		t.Fatalf("read delivered outbox event: %v", err)
	}
	if state.Attempts != 1 || !state.Delivered.Valid || state.ClaimedBy.Valid {
		t.Fatalf("delivered outbox state = %+v", state)
	}
	if strings.Contains(state.Payload, "654321") ||
		!strings.Contains(state.Payload, "redacted") {
		t.Fatalf("delivered payload was not redacted: %s", state.Payload)
	}
}

// TestOutboxWorkerReleasesFailedDeliveryForRetry kiểm chứng kịch bản OutboxWorkerReleasesFailedDeliveryForRetry.
func TestOutboxWorkerReleasesFailedDeliveryForRetry(t *testing.T) {
	db := openJobsIntegrationDB(t)
	clearOutboxFixtures(t, db)
	codec, err := mailmessage.NewSecretCodec("jobs-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.Seal(mailmessage.SecretMessage{
		To:     "jobs_failure@example.test",
		Secret: "123456",
	})
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	store := mysqlstore.NewOutboxStore(db)
	if err := store.Enqueue(context.Background(), &mysqlstore.OutboxEvent{
		EventType:      mailmessage.VerificationRequested,
		AggregateType:  "verification_challenge",
		AggregateID:    "jobs-integration-failure",
		Payload:        payload,
		IdempotencyKey: "jobs-integration-failure",
		MaxAttempts:    3,
		AvailableAt:    time.Now().UTC().Add(-time.Second),
	}); err != nil {
		t.Fatalf("Enqueue(): %v", err)
	}

	worker := NewOutboxWorker(
		db,
		store,
		codec,
		&fakeVerificationSender{err: errDeliveryUnavailable},
		testOutboxConfig(),
		zap.NewNop(),
	)
	worker.runOnce(context.Background())

	var state struct {
		Attempts     int            `db:"attempts"`
		AvailableAt  time.Time      `db:"available_at"`
		ClaimedBy    sql.NullString `db:"claimed_by"`
		DeliveredAt  sql.NullTime   `db:"delivered_at"`
		DeadLettered sql.NullTime   `db:"dead_lettered_at"`
		LastError    sql.NullString `db:"last_error"`
		Payload      string         `db:"payload"`
	}
	if err := db.Get(&state, `
		SELECT attempts, available_at, claimed_by, delivered_at,
			dead_lettered_at, last_error, CAST(payload AS CHAR) AS payload
		FROM outbox_events
		WHERE idempotency_key = 'jobs-integration-failure'`); err != nil {
		t.Fatalf("read failed outbox event: %v", err)
	}
	if state.Attempts != 1 ||
		state.ClaimedBy.Valid ||
		state.DeliveredAt.Valid ||
		state.DeadLettered.Valid ||
		!state.LastError.Valid ||
		!state.AvailableAt.After(time.Now().UTC()) {
		t.Fatalf("failed outbox state = %+v", state)
	}
	if strings.Contains(state.Payload, "123456") ||
		strings.Contains(state.LastError.String, "123456") {
		t.Fatal("failed delivery persisted plaintext OTP")
	}
}

// TestOutboxWorkerDeliversPasswordResetEvent kiểm chứng kịch bản OutboxWorkerDeliversPasswordResetEvent.
func TestOutboxWorkerDeliversPasswordResetEvent(t *testing.T) {
	db := openJobsIntegrationDB(t)
	clearOutboxFixtures(t, db)
	codec, err := mailmessage.NewSecretCodec("jobs-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.Seal(mailmessage.SecretMessage{
		To:     "jobs_reset@example.test",
		Secret: "reset-token-value",
	})
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	store := mysqlstore.NewOutboxStore(db)
	if err := store.Enqueue(context.Background(), &mysqlstore.OutboxEvent{
		EventType:      mailmessage.PasswordResetRequested,
		AggregateType:  "password_reset_token",
		AggregateID:    "900001",
		Payload:        payload,
		IdempotencyKey: "jobs-integration-password-reset",
		MaxAttempts:    3,
		AvailableAt:    time.Now().UTC().Add(-time.Second),
	}); err != nil {
		t.Fatalf("Enqueue(): %v", err)
	}

	sender := &fakeVerificationSender{}
	worker := NewOutboxWorker(
		db,
		store,
		codec,
		sender,
		testOutboxConfig(),
		zap.NewNop(),
	)
	worker.runOnce(context.Background())
	if sender.to != "jobs_reset@example.test" ||
		sender.resetToken != "reset-token-value" {
		t.Fatalf(
			"delivered reset = to:%q token:%q",
			sender.to,
			sender.resetToken,
		)
	}
}

// TestOutboxWorkerDeliversAdminNotificationEvent kiểm chứng kịch bản OutboxWorkerDeliversAdminNotificationEvent.
func TestOutboxWorkerDeliversAdminNotificationEvent(t *testing.T) {
	db := openJobsIntegrationDB(t)
	clearOutboxFixtures(t, db)
	codec, err := mailmessage.NewSecretCodec("jobs-integration-pepper")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.SealAdminNotification(mailmessage.AdminNotification{
		To:      "jobs_notify@example.test",
		Subject: "Access notice",
		Message: "Your account access changed.",
	})
	if err != nil {
		t.Fatalf("SealAdminNotification(): %v", err)
	}
	store := mysqlstore.NewOutboxStore(db)
	if err := store.Enqueue(context.Background(), &mysqlstore.OutboxEvent{
		EventType:      mailmessage.AdminNotificationRequested,
		AggregateType:  "user",
		AggregateID:    "900002",
		Payload:        payload,
		IdempotencyKey: "jobs-integration-admin-notification",
		MaxAttempts:    3,
		AvailableAt:    time.Now().UTC().Add(-time.Second),
	}); err != nil {
		t.Fatalf("Enqueue(): %v", err)
	}

	sender := &fakeVerificationSender{}
	worker := NewOutboxWorker(
		db,
		store,
		codec,
		sender,
		testOutboxConfig(),
		zap.NewNop(),
	)
	worker.runOnce(context.Background())
	if sender.to != "jobs_notify@example.test" ||
		sender.otp != "Access notice" ||
		sender.resetToken != "Your account access changed." {
		t.Fatalf(
			"delivered notification = to:%q subject:%q message:%q",
			sender.to,
			sender.otp,
			sender.resetToken,
		)
	}
}

// clearOutboxFixtures xóa event giữa các integration case để tránh ảnh hưởng chéo.
func clearOutboxFixtures(t *testing.T, db *sqlx.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM outbox_events`); err != nil {
		t.Fatalf("clear outbox fixtures: %v", err)
	}
}

// testOutboxConfig trả batch, retry và lease duration ngắn cho integration test.
func testOutboxConfig() config.OutboxConfig {
	return config.OutboxConfig{
		PollInterval:  time.Second,
		BatchSize:     10,
		ClaimTTL:      time.Minute,
		Timeout:       5 * time.Second,
		MaxConcurrent: 2,
	}
}

// openJobsIntegrationDB kết nối disposable MySQL và bỏ qua test khi integration DSN chưa được cấu hình.
func openJobsIntegrationDB(t *testing.T) *sqlx.DB {
	t.Helper()
	name := os.Getenv("UAM_JOBS_TEST_DB_NAME")
	if !strings.HasPrefix(name, "uam_jobs_test_") {
		t.Skip("disposable jobs database is not configured")
	}
	address := os.Getenv("UAM_JOBS_TEST_DB_ADDR")
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("parse jobs integration database address: %v", err)
	}
	user := os.Getenv("UAM_JOBS_TEST_DB_USER")
	password := os.Getenv("UAM_JOBS_TEST_DB_PASSWORD")
	jobsMigrationOnce.Do(func() {
		jobsMigrationErr = database.RunMigrations(database.MySQLOptions{
			Host:     host,
			Port:     port,
			Name:     name,
			User:     user,
			Password: password,
		}, "../../migrations", "test")
	})
	if jobsMigrationErr != nil {
		t.Fatalf("run jobs integration migrations: %v", jobsMigrationErr)
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
		t.Fatalf("open jobs integration database: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping jobs integration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
