// Package hash cung cấp primitive băm mật khẩu và OTP cho các use case bảo mật.
package hash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// File này băm, so sánh và kiểm tra password hoặc OTP an toàn.

const (
	minPasswordLength = 8

	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberChars  = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}<>?"
)

// DummyPasswordHash là bcrypt hash hợp lệ dùng để cân bằng timing khi tài khoản không tồn tại.
//
//nolint:gosec // #nosec G101 -- dummy bcrypt hash used to equalize timing when account is not found
const DummyPasswordHash = "$2a$10$IPzDZM5LbI2XJynYGwn0tepKOFLr0HNzTD6PCPRUzeu3yWfDZGk.G" // #nosec G101

// SHA256 trả digest hex cho dữ liệu không cần password-hardening.
func SHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// HashOTP băm OTP cùng pepper bằng HMAC-SHA256 để không lưu OTP plaintext.
func HashOTP(otp, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(otp))
	return hex.EncodeToString(mac.Sum(nil))
}

// HashPassword băm mật khẩu bằng primitive phù hợp với dữ liệu xác thực.
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

// CheckPassword kiểm tra mật khẩu bằng primitive phù hợp với dữ liệu xác thực.
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ValidatePasswordComplexity kiểm tra mật khẩu Complexity bằng primitive phù hợp với dữ liệu xác thực.
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

// ValidateNewPassword kiểm tra độ phức tạp và giới hạn 72 byte của bcrypt trước khi băm.
func ValidateNewPassword(password string) error {
	if err := ValidatePasswordComplexity(password); err != nil {
		return err
	}
	if len([]byte(password)) > 72 {
		return errors.New("mật khẩu không được vượt quá 72 ký tự")
	}
	return nil
}

// GenerateResetToken tạo đặt lại token bằng primitive phù hợp với dữ liệu xác thực.
func GenerateResetToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
