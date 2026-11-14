package mail

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
)

// File này kiểm chứng hành vi sender và các trường hợp lỗi liên quan.

// captureTransport là mock transport ghi lại dữ liệu email gửi đi phục vụ unit test.
type captureTransport struct {
	called  bool
	to      string
	subject string
	body    string
}

// SendEmail gửi email qua mail boundary mà không ghi secret vào log.
func (c *captureTransport) SendEmail(ctx context.Context, to, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.called = true
	c.to = to
	c.subject = subject
	c.body = body
	return nil
}

// TestSenderRejectsHeaderInjection kiểm chứng kịch bản SenderRejectsHeaderInjection.
func TestSenderRejectsHeaderInjection(t *testing.T) {
	transport := &captureTransport{}
	sender := &Sender{sender: transport, cfg: &config.Config{}}
	ctx := context.Background()

	if err := sender.SendEmail(
		ctx,
		"user@example.test\r\nBcc: attacker@example.test",
		"subject",
		"body",
	); err == nil {
		t.Fatal("recipient header injection was accepted")
	}
	if err := sender.SendEmail(
		ctx,
		"user@example.test",
		"subject\r\nBcc: attacker@example.test",
		"body",
	); err == nil {
		t.Fatal("subject header injection was accepted")
	}
	if transport.called {
		t.Fatal("transport was called for an unsafe header")
	}
}

// TestSenderRespectsContextCancellation kiểm chứng sender dừng ngay khi context bị hủy.
func TestSenderRespectsContextCancellation(t *testing.T) {
	transport := &captureTransport{}
	sender := &Sender{sender: transport, cfg: &config.Config{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sender.SendEmail(ctx, "user@example.test", "subject", "body")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected context canceled, got: %v", err)
	}
	if transport.called {
		t.Fatal("transport should not be called when context is canceled")
	}
}

// TestSenderUsesConfiguredExpiryText kiểm chứng kịch bản SenderUsesConfiguredExpiryText.
func TestSenderUsesConfiguredExpiryText(t *testing.T) {
	transport := &captureTransport{}
	sender := &Sender{
		sender: transport,
		cfg: &config.Config{Security: config.SecurityConfig{
			OTPExpiry:           7 * time.Minute,
			PasswordResetExpiry: 2 * time.Hour,
			EmailChangeExpiry:   11 * time.Minute,
		}},
	}
	ctx := context.Background()

	if err := sender.SendVerificationEmail(ctx, "user@example.test", "123456"); err != nil {
		t.Fatalf("SendVerificationEmail(): %v", err)
	}
	if !strings.Contains(transport.body, "7 phút") {
		t.Fatalf("verification body = %q", transport.body)
	}
	if err := sender.SendPasswordResetEmail(ctx, "user@example.test", "token"); err != nil {
		t.Fatalf("SendPasswordResetEmail(): %v", err)
	}
	if !strings.Contains(transport.body, "2 giờ") {
		t.Fatalf("password reset body = %q", transport.body)
	}
	if err := sender.SendEmailChangeVerification(ctx, "user@example.test", "654321"); err != nil {
		t.Fatalf("SendEmailChangeVerification(): %v", err)
	}
	if !strings.Contains(transport.body, "11 phút") {
		t.Fatalf("email change body = %q", transport.body)
	}
}
