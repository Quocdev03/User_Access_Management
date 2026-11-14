package jwt

import (
	"testing"
	"time"
)

// File này kiểm chứng hành vi jwt và các trường hợp lỗi liên quan.

// TestGenerateAndParseToken kiểm chứng kịch bản GenerateAndParseToken.
func TestGenerateAndParseToken(t *testing.T) {
	secret := "my-super-secret-key-1234567890"
	userID := uint64(42)
	tokenType := "access"
	expiry := 10 * time.Minute

	token, jti, err := GenerateToken(userID, []string{"user"}, tokenType, expiry, secret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token == "" {
		t.Fatal("Expected token string to be non-empty")
	}

	if jti == "" {
		t.Fatal("Expected JTI to be non-empty")
	}

	claims, err := ParseToken(token, secret)
	if err != nil {
		t.Fatalf("Expected no error parsing token, got %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected UserID %d, got %d", userID, claims.UserID)
	}

	if claims.Type != tokenType {
		t.Errorf("Expected Type %s, got %s", tokenType, claims.Type)
	}

	if claims.ID != jti {
		t.Errorf("Expected JTI %s, got %s", jti, claims.ID)
	}
}

// TestGenerateTokenWithAuthVersion kiểm chứng kịch bản GenerateTokenWithAuthVersion.
func TestGenerateTokenWithAuthVersion(t *testing.T) {
	const authVersion = uint64(9)
	token, _, err := GenerateTokenWithAuthVersion(
		42,
		authVersion,
		[]string{"user"},
		"access",
		time.Minute,
		"my-super-secret-key-1234567890",
	)
	if err != nil {
		t.Fatalf("GenerateTokenWithAuthVersion(): %v", err)
	}
	claims, err := ParseToken(token, "my-super-secret-key-1234567890")
	if err != nil {
		t.Fatalf("ParseToken(): %v", err)
	}
	if claims.AuthVersion != authVersion {
		t.Fatalf("AuthVersion = %d, want %d", claims.AuthVersion, authVersion)
	}
}

// TestExpiredToken kiểm chứng kịch bản ExpiredToken.
func TestExpiredToken(t *testing.T) {
	secret := "my-super-secret-key-1234567890"
	userID := uint64(42)
	tokenType := "access"
	expiry := -1 * time.Minute

	token, _, err := GenerateToken(userID, []string{"user"}, tokenType, expiry, secret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err = ParseToken(token, secret)
	if err == nil {
		t.Fatal("Expected error parsing expired token, got nil")
	}

	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got %v", err)
	}
}

// TestTamperedToken kiểm chứng kịch bản TamperedToken.
func TestTamperedToken(t *testing.T) {
	secret := "my-super-secret-key-1234567890"
	userID := uint64(42)
	tokenType := "access"
	expiry := 10 * time.Minute

	token, _, err := GenerateToken(userID, []string{"user"}, tokenType, expiry, secret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tamperedToken := token[:len(token)-1] + "A"
	if tamperedToken == token {
		tamperedToken = token + "A"
	}

	_, err = ParseToken(tamperedToken, secret)
	if err == nil {
		t.Fatal("Expected error parsing tampered token, got nil")
	}

	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}
}

// TestInvalidSignature kiểm chứng lỗi khi giải mã token có chữ ký không hợp lệ.
func TestInvalidSignature(t *testing.T) {
	secret := "my-super-secret-key-1234567890"
	wrongSecret := "wrong-secret-key-0987654321"
	userID := uint64(42)
	tokenType := "access"
	expiry := 10 * time.Minute

	token, _, err := GenerateToken(userID, []string{"user"}, tokenType, expiry, secret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err = ParseToken(token, wrongSecret)
	if err == nil {
		t.Fatal("Expected error parsing token with wrong secret, got nil")
	}

	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}
}

// TestParseTokenAllowExpired kiểm chứng trích xuất claims khi token hết hạn nhưng chữ ký hợp lệ.
func TestParseTokenAllowExpired(t *testing.T) {
	secret := "my-super-secret-key-123456789012"
	userID := uint64(99)

	// Case 1: Token còn hạn
	validToken, jti, err := GenerateToken(userID, []string{"user"}, "access", time.Hour, secret)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, isExpired, err := ParseTokenAllowExpired(validToken, secret)
	if err != nil {
		t.Fatalf("ParseTokenAllowExpired valid: %v", err)
	}
	if isExpired {
		t.Fatal("expected isExpired to be false for valid token")
	}
	if claims.UserID != userID || claims.ID != jti {
		t.Fatalf("claims mismatch: %+v", claims)
	}

	// Case 2: Token đã hết hạn
	expiredToken, expJti, err := GenerateToken(userID, []string{"user"}, "access", -time.Minute, secret)
	if err != nil {
		t.Fatalf("GenerateToken expired: %v", err)
	}
	claims, isExpired, err = ParseTokenAllowExpired(expiredToken, secret)
	if err != nil {
		t.Fatalf("ParseTokenAllowExpired expired returned error: %v", err)
	}
	if !isExpired {
		t.Fatal("expected isExpired to be true for expired token")
	}
	if claims.UserID != userID || claims.ID != expJti {
		t.Fatalf("claims mismatch for expired token: %+v", claims)
	}

	// Case 3: Token sai chữ ký
	_, _, err = ParseTokenAllowExpired(expiredToken, "wrong-secret-key-12345678901234")
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}
