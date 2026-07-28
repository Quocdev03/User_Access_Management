package mail

import (
	"strings"
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/internal/config"
)

type captureTransport struct {
	called  bool
	to      string
	subject string
	body    string
}

func (c *captureTransport) SendEmail(to, subject, body string) error {
	c.called = true
	c.to = to
	c.subject = subject
	c.body = body
	return nil
}

func TestSenderRejectsHeaderInjection(t *testing.T) {
	transport := &captureTransport{}
	sender := &Sender{sender: transport, cfg: &config.Config{}}

	if err := sender.SendEmail(
		"user@example.test\r\nBcc: attacker@example.test",
		"subject",
		"body",
	); err == nil {
		t.Fatal("recipient header injection was accepted")
	}
	if err := sender.SendEmail(
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

	if err := sender.SendVerificationEmail("user@example.test", "123456"); err != nil {
		t.Fatalf("SendVerificationEmail(): %v", err)
	}
	if !strings.Contains(transport.body, "7 phút") {
		t.Fatalf("verification body = %q", transport.body)
	}
	if err := sender.SendPasswordResetEmail("user@example.test", "token"); err != nil {
		t.Fatalf("SendPasswordResetEmail(): %v", err)
	}
	if !strings.Contains(transport.body, "2 giờ") {
		t.Fatalf("password reset body = %q", transport.body)
	}
	if err := sender.SendEmailChangeVerification("user@example.test", "654321"); err != nil {
		t.Fatalf("SendEmailChangeVerification(): %v", err)
	}
	if !strings.Contains(transport.body, "11 phút") {
		t.Fatalf("email change body = %q", transport.body)
	}
}
