package mail

import (
	"bytes"
	"testing"
)

// File này kiểm chứng hành vi payload và các trường hợp lỗi liên quan.

// TestSecretCodecEncryptsAndAuthenticatesValue kiểm chứng kịch bản SecretCodecEncryptsAndAuthenticatesValue.
func TestSecretCodecEncryptsAndAuthenticatesValue(t *testing.T) {
	codec, err := NewSecretCodec("test-secret")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.Seal(SecretMessage{
		To:     "user@example.test",
		Secret: "123456",
	})
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	if bytes.Contains(payload, []byte("123456")) {
		t.Fatal("outbox payload contains plaintext OTP")
	}
	message, err := codec.Open(payload)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	if message.To != "user@example.test" || message.Secret != "123456" {
		t.Fatalf("decoded message = %+v", message)
	}

	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-2] ^= 1
	if _, err := codec.Open(tampered); err == nil {
		t.Fatal("tampered verification payload was accepted")
	}
}

// TestSecretCodecAdminNotificationRoundTrip kiểm chứng kịch bản SecretCodecAdminNotificationRoundTrip.
func TestSecretCodecAdminNotificationRoundTrip(t *testing.T) {
	codec, err := NewSecretCodec("test-secret")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.SealAdminNotification(AdminNotification{
		To:      "user@example.test",
		Subject: "Security notice",
		Message: "Your access was updated.",
	})
	if err != nil {
		t.Fatalf("SealAdminNotification(): %v", err)
	}
	for _, plaintext := range [][]byte{
		[]byte("Security notice"),
		[]byte("Your access was updated."),
	} {
		if bytes.Contains(payload, plaintext) {
			t.Fatalf("admin-notification payload contains plaintext %q", plaintext)
		}
	}
	message, err := codec.OpenAdminNotification(payload)
	if err != nil {
		t.Fatalf("OpenAdminNotification(): %v", err)
	}
	if message.To != "user@example.test" ||
		message.Subject != "Security notice" ||
		message.Message != "Your access was updated." {
		t.Fatalf("decoded admin notification = %+v", message)
	}
}

// TestSecretCodecEmailChangeNotificationRoundTrip kiểm chứng mã hóa và giải mã thông báo thay đổi email.
func TestSecretCodecEmailChangeNotificationRoundTrip(t *testing.T) {
	codec, err := NewSecretCodec("test-secret")
	if err != nil {
		t.Fatalf("NewSecretCodec(): %v", err)
	}
	payload, err := codec.SealEmailChangeNotification(EmailChangeNotification{
		OldEmail: "old@example.test",
		NewEmail: "new@example.test",
	})
	if err != nil {
		t.Fatalf("SealEmailChangeNotification(): %v", err)
	}
	if bytes.Contains(payload, []byte("new@example.test")) {
		t.Fatal("email-change payload contains plaintext new email in ciphertext")
	}
	message, err := codec.OpenEmailChangeNotification(payload)
	if err != nil {
		t.Fatalf("OpenEmailChangeNotification(): %v", err)
	}
	if message.OldEmail != "old@example.test" || message.NewEmail != "new@example.test" {
		t.Fatalf("decoded email change notification = %+v", message)
	}

	// Test fallback tương thích ngược với payload cũ
	legacyPayload, err := codec.Seal(SecretMessage{
		To:     "old@example.test",
		Secret: "new@example.test",
	})
	if err != nil {
		t.Fatalf("Seal(legacy): %v", err)
	}
	legacyMessage, err := codec.OpenEmailChangeNotification(legacyPayload)
	if err != nil {
		t.Fatalf("OpenEmailChangeNotification(legacy): %v", err)
	}
	if legacyMessage.OldEmail != "old@example.test" || legacyMessage.NewEmail != "new@example.test" {
		t.Fatalf("decoded legacy email change notification = %+v", legacyMessage)
	}
}
