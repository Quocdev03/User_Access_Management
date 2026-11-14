package auth

import (
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

// File này kiểm chứng các helper và logic của password policy.

// TestActiveResetToken kiểm chứng điều kiện reset token hợp lệ và còn hạn.
func TestActiveResetToken(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	consumedTime := now.Add(-time.Minute)

	tests := []struct {
		name     string
		token    *mysqlstore.PasswordResetToken
		expected bool
	}{
		{
			name:     "nil token",
			token:    nil,
			expected: false,
		},
		{
			name: "consumed token",
			token: &mysqlstore.PasswordResetToken{
				ConsumedAt: &consumedTime,
				ExpiresAt:  now.Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired token",
			token: &mysqlstore.PasswordResetToken{
				ExpiresAt: now.Add(-time.Second),
			},
			expected: false,
		},
		{
			name: "valid active token",
			token: &mysqlstore.PasswordResetToken{
				ExpiresAt: now.Add(time.Hour),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := activeResetToken(tt.token, now); got != tt.expected {
				t.Fatalf("activeResetToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}
