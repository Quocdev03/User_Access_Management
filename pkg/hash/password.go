package hash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLength = 8

	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberChars  = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}<>?"
)

// DummyPasswordHash is a real bcrypt hash of "dummy-password" for timing equalization
// when a user/email does not exist (must be a valid bcrypt string).
const DummyPasswordHash = "$2a$10$IPzDZM5LbI2XJynYGwn0tepKOFLr0HNzTD6PCPRUzeu3yWfDZGk.G"

func SHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// HashOTP returns SHA-256 hex of otp+pepper for storage (never store OTP plaintext).
func HashOTP(otp, pepper string) string {
	return SHA256(otp + pepper)
}

func HashPassword(password string) (string, error) {
	if len([]byte(password)) > 72 {
		return "", errors.New("mật khẩu vượt quá giới hạn 72 bytes của bcrypt")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func ValidatePasswordComplexity(password string) error {
	if len(password) < minPasswordLength {
		return errors.New("mật khẩu phải có tối thiểu 8 ký tự")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, r := range password {
		switch {
		case 'a' <= r && r <= 'z':
			hasLower = true
		case 'A' <= r && r <= 'Z':
			hasUpper = true
		case '0' <= r && r <= '9':
			hasNumber = true
		case strings.ContainsRune(specialChars, r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("mật khẩu phải có ít nhất 1 chữ hoa, 1 chữ thường, 1 số và 1 ký tự đặc biệt")
	}

	return nil
}

// ValidateNewPassword checks complexity and bcrypt's 72-byte limit.
func ValidateNewPassword(password string) error {
	if err := ValidatePasswordComplexity(password); err != nil {
		return err
	}
	if len([]byte(password)) > 72 {
		return errors.New("mật khẩu không được vượt quá 72 ký tự")
	}
	return nil
}

func GenerateResetToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
