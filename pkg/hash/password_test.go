package hash

import "testing"

// File này kiểm chứng hành vi password và các trường hợp lỗi liên quan.

// TestValidateNewPassword kiểm chứng kịch bản ValidateNewPassword.
func TestValidateNewPassword(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"ok", "Abcd1234!", false},
		{"too short", "Ab1!", true},
		{"no special", "Abcd12345", true},
		{"no upper", "abcd1234!", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNewPassword(tt.pw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateNewPassword(%q) err=%v wantErr=%v", tt.pw, err, tt.wantErr)
			}
		})
	}
}

// TestHashOTPDeterministic kiểm chứng kịch bản HashOTPDeterministic dùng HMAC-SHA256.
func TestHashOTPDeterministic(t *testing.T) {
	a := HashOTP("123456", "pepper")
	b := HashOTP("123456", "pepper")
	if a != b {
		t.Fatal("HashOTP should be deterministic")
	}
	if a == "123456" {
		t.Fatal("HashOTP must not return plaintext")
	}
	if len(a) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(a))
	}

	// Đảm bảo không phải là SHA256 thô nối chuỗi
	rawConcat := SHA256("123456pepper")
	if a == rawConcat {
		t.Fatal("HashOTP must use HMAC-SHA256 instead of raw string concatenation")
	}

	differentPepper := HashOTP("123456", "different-pepper")
	if a == differentPepper {
		t.Fatal("different peppers must yield different hashes")
	}

	differentOTP := HashOTP("654321", "pepper")
	if a == differentOTP {
		t.Fatal("different OTPs must yield different hashes")
	}
}

// TestDummyPasswordHashValid kiểm chứng kịch bản DummyPasswordHashValid.
func TestDummyPasswordHashValid(t *testing.T) {
	if !CheckPassword("dummy-password", DummyPasswordHash) {
		t.Fatal("DummyPasswordHash must be a valid bcrypt of dummy-password")
	}
}
