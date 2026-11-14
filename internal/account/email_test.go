package account

import (
	"errors"
	"testing"

	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này kiểm chứng kết quả xử lý OTP khi đổi email.

// TestOTPAttemptResult kiểm chứng cấu trúc kết quả phân tích số lần nhập OTP thất bại.
func TestOTPAttemptResult(t *testing.T) {
	exceeded := OTPAttemptResult{
		ExceededMaxAttempts: true,
		BusinessError:       apperror.ErrOTPMaxAttempts,
	}
	if !exceeded.ExceededMaxAttempts {
		t.Fatal("expected ExceededMaxAttempts to be true")
	}
	if !errors.Is(exceeded.BusinessError, apperror.ErrOTPMaxAttempts) {
		t.Fatalf("expected ErrOTPMaxAttempts, got: %v", exceeded.BusinessError)
	}

	invalid := OTPAttemptResult{
		ExceededMaxAttempts: false,
		BusinessError:       apperror.ErrOTPInvalid,
	}
	if invalid.ExceededMaxAttempts {
		t.Fatal("expected ExceededMaxAttempts to be false")
	}
	if !errors.Is(invalid.BusinessError, apperror.ErrOTPInvalid) {
		t.Fatalf("expected ErrOTPInvalid, got: %v", invalid.BusinessError)
	}
}
