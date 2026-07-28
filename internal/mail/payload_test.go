package mail

import (
	"bytes"
	"testing"
)

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
