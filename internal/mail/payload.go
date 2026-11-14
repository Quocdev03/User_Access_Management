// Package mail mã hóa payload và gửi email qua các transport được cấu hình.
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

// File này mã hóa payload outbox để secret không được lưu plaintext.

const (
	VerificationRequested            = "mail.verification_requested"
	PasswordResetRequested           = "mail.password_reset_requested"
	EmailChangeVerificationRequested = "mail.email_change_verification_requested"
	EmailChangeCompleted             = "mail.email_change_completed"
	AdminNotificationRequested       = "mail.admin_notification_requested"
)

// SecretMessage chứa thông tin địa chỉ người nhận và mã bí mật cần gửi qua email.
type SecretMessage struct {
	To     string
	Secret string
}

// EmailChangeNotification chứa địa chỉ email cũ và mới sau khi hoàn tất thay đổi email.
type EmailChangeNotification struct {
	OldEmail string `json:"old_email"`
	NewEmail string `json:"new_email"`
}

// AdminNotification chứa nội dung thông báo gửi tới người dùng do quản trị viên soạn thảo.
type AdminNotification struct {
	To      string
	Subject string
	Message string
}

// adminNotificationContent đại diện cho payload JSON lưu trong outbox của thông báo quản trị.
type adminNotificationContent struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// verificationPayload đại diện cho payload JSON được mã hóa lưu trữ trong outbox table.
type verificationPayload struct {
	To         string `json:"to"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// SecretCodec chịu trách nhiệm mã hóa và giải mã các payload bí mật của outbox event bằng AES-GCM.
type SecretCodec struct {
	aead cipher.AEAD
}

// NewSecretCodec khởi tạo SecretCodec với các dependency được cung cấp.
func NewSecretCodec(secret string) (*SecretCodec, error) {
	// Giữ derivation context cũ để event đã persist trước lần đổi tên vẫn giải mã được.
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

// Seal mã hóa secret cùng metadata loại event trước khi ghi durable outbox.
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

// Open xác thực và giải mã payload outbox bằng derivation context tương thích.
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

// SealAdminNotification mã hóa subject và message do quản trị viên cung cấp.
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

// OpenAdminNotification xác thực rồi giải mã payload thông báo quản trị.
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

// SealEmailChangeNotification mã hóa thông báo đổi email gồm địa chỉ cũ và mới.
func (c *SecretCodec) SealEmailChangeNotification(message EmailChangeNotification) ([]byte, error) {
	if message.OldEmail == "" || message.NewEmail == "" {
		return nil, fmt.Errorf("email change notification requires old and new email")
	}
	content, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode email change notification: %w", err)
	}
	return c.Seal(SecretMessage{To: message.OldEmail, Secret: string(content)})
}

// OpenEmailChangeNotification xác thực và giải mã payload thông báo thay đổi email.
func (c *SecretCodec) OpenEmailChangeNotification(payload []byte) (EmailChangeNotification, error) {
	message, err := c.Open(payload)
	if err != nil {
		return EmailChangeNotification{}, err
	}
	var notification EmailChangeNotification
	if err := json.Unmarshal([]byte(message.Secret), &notification); err == nil && notification.OldEmail != "" && notification.NewEmail != "" {
		return notification, nil
	}
	// Fallback tương thích ngược nếu payload cũ lưu trực tiếp NewEmail vào Secret
	if message.To != "" && message.Secret != "" {
		return EmailChangeNotification{
			OldEmail: message.To,
			NewEmail: message.Secret,
		}, nil
	}
	return EmailChangeNotification{}, fmt.Errorf("email change notification is incomplete")
}
