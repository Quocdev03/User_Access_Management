package mail

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const (
	VerificationRequested            = "mail.verification_requested"
	PasswordResetRequested           = "mail.password_reset_requested"
	EmailChangeVerificationRequested = "mail.email_change_verification_requested"
	EmailChangeCompleted             = "mail.email_change_completed"
	AdminNotificationRequested       = "mail.admin_notification_requested"
)

type SecretMessage struct {
	To     string
	Secret string
}

type AdminNotification struct {
	To      string
	Subject string
	Message string
}

type adminNotificationContent struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type verificationPayload struct {
	To         string `json:"to"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type SecretCodec struct {
	aead cipher.AEAD
}

func NewSecretCodec(secret string) (*SecretCodec, error) {
	// Keep the original derivation context so verification events already
	// persisted before this rename remain decryptable.
	key := sha256.Sum256([]byte("uam:outbox:verification:v1:" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create secret payload cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create secret payload AEAD: %w", err)
	}
	return &SecretCodec{aead: aead}, nil
}

func (c *SecretCodec) Seal(message SecretMessage) ([]byte, error) {
	if message.To == "" || message.Secret == "" {
		return nil, fmt.Errorf("secret message requires recipient and value")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate verification payload nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nil, nonce, []byte(message.Secret), []byte(message.To))
	return json.Marshal(verificationPayload{
		To:         message.To,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
}

func (c *SecretCodec) Open(payload []byte) (SecretMessage, error) {
	var encoded verificationPayload
	if err := json.Unmarshal(payload, &encoded); err != nil {
		return SecretMessage{}, fmt.Errorf("decode secret payload: %w", err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(encoded.Nonce)
	if err != nil {
		return SecretMessage{}, fmt.Errorf("decode secret payload nonce: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(encoded.Ciphertext)
	if err != nil {
		return SecretMessage{}, fmt.Errorf("decode secret payload ciphertext: %w", err)
	}
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte(encoded.To))
	if err != nil {
		return SecretMessage{}, fmt.Errorf("decrypt secret payload: %w", err)
	}
	return SecretMessage{To: encoded.To, Secret: string(plaintext)}, nil
}

func (c *SecretCodec) SealAdminNotification(message AdminNotification) ([]byte, error) {
	if message.Subject == "" || message.Message == "" {
		return nil, fmt.Errorf("admin notification requires subject and message")
	}
	content, err := json.Marshal(adminNotificationContent{
		Subject: message.Subject,
		Message: message.Message,
	})
	if err != nil {
		return nil, fmt.Errorf("encode admin notification: %w", err)
	}
	return c.Seal(SecretMessage{To: message.To, Secret: string(content)})
}

func (c *SecretCodec) OpenAdminNotification(payload []byte) (AdminNotification, error) {
	message, err := c.Open(payload)
	if err != nil {
		return AdminNotification{}, err
	}
	var content adminNotificationContent
	if err := json.Unmarshal([]byte(message.Secret), &content); err != nil {
		return AdminNotification{}, fmt.Errorf("decode admin notification: %w", err)
	}
	if content.Subject == "" || content.Message == "" {
		return AdminNotification{}, fmt.Errorf("admin notification is incomplete")
	}
	return AdminNotification{
		To:      message.To,
		Subject: content.Subject,
		Message: content.Message,
	}, nil
}
