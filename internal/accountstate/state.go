// Package accountstate sở hữu policy chuyển đổi trạng thái tài khoản.
package accountstate

import (
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này định nghĩa state machine và effective status duy nhất của tài khoản.

// Lifecycle biểu diễn trạng thái vòng đời cốt lõi của tài khoản trong hệ thống.
type Lifecycle string

const (
	PendingVerification Lifecycle = "pending_verification"
	Active              Lifecycle = "active"
	Disabled            Lifecycle = "disabled"
)

// PublicStatus biểu diễn trạng thái công khai của tài khoản trả về qua API.
type PublicStatus string

const (
	PublicActive   PublicStatus = "active"
	PublicInactive PublicStatus = "inactive"
	PublicLocked   PublicStatus = "locked"
)

// State đóng gói toàn bộ trạng thái vòng đời, khóa bảo mật và cờ bắt buộc đổi mật khẩu của tài khoản.
type State struct {
	Lifecycle              Lifecycle
	EmailVerified          bool
	AdministrativeLockedAt *time.Time
	LoginLockedUntil       *time.Time
	FailedLoginAttempts    int
	PasswordChangeRequired bool
	AuthVersion            uint64
}

// Registration tạo state ban đầu cho tài khoản đang chờ xác minh email.
func Registration() State {
	return State{Lifecycle: PendingVerification}
}

// Validate từ chối tổ hợp account state vi phạm canonical invariant.
func (s State) Validate() error {
	switch s.Lifecycle {
	case PendingVerification:
		if s.EmailVerified {
			return fmt.Errorf("invalid account state: pending verification account is email-verified")
		}
	case Active:
		if !s.EmailVerified {
			return fmt.Errorf("invalid account state: active account is not email-verified")
		}
	case Disabled:
	default:
		return fmt.Errorf("invalid account state: unknown lifecycle %q", s.Lifecycle)
	}
	if s.FailedLoginAttempts < 0 {
		return fmt.Errorf("invalid account state: negative failed login attempts")
	}
	return nil
}

// EffectiveStatus tính public status với administrative/login lock có độ ưu tiên cao nhất.
func (s State) EffectiveStatus(now time.Time) PublicStatus {
	if s.AdministrativeLockedAt != nil {
		return PublicLocked
	}
	if s.LoginLockedUntil != nil && s.LoginLockedUntil.After(now) {
		return PublicLocked
	}
	if s.Lifecycle != Active {
		return PublicInactive
	}
	return PublicActive
}

// AuthenticationError ánh xạ state hiện tại sang business error dùng tại auth boundary.
func (s State) AuthenticationError(now time.Time) error {
	if s.AdministrativeLockedAt != nil ||
		(s.LoginLockedUntil != nil && s.LoginLockedUntil.After(now)) {
		return apperror.ErrAccountLocked
	}
	if s.Lifecycle == Disabled {
		return apperror.ErrAccountDisabled
	}
	if s.Lifecycle != Active || !s.EmailVerified {
		return apperror.ErrAccountInactive
	}
	return nil
}

// VerifyEmail kích hoạt tài khoản pending và tăng auth_version.
func (s *State) VerifyEmail() error {
	if s.EmailVerified {
		return apperror.ErrAccountAlreadyVerified
	}
	s.EmailVerified = true
	if s.Lifecycle == PendingVerification {
		s.Lifecycle = Active
	}
	s.invalidateAuth()
	return nil
}

// SetEmailVerification đồng bộ lifecycle với cờ xác minh rồi tăng auth_version.
func (s *State) SetEmailVerification(verified bool) {
	s.EmailVerified = verified
	switch {
	case verified && s.Lifecycle == PendingVerification:
		s.Lifecycle = Active
	case !verified && s.Lifecycle == Active:
		s.Lifecycle = PendingVerification
	}
	s.invalidateAuth()
}

// Disable chuyển lifecycle sang disabled và làm mất hiệu lực auth state.
func (s *State) Disable() {
	s.Lifecycle = Disabled
	s.invalidateAuth()
}

// Enable kích hoạt tài khoản đã xác minh và làm mất hiệu lực auth state cũ.
func (s *State) Enable() {
	s.Lifecycle = Active
	s.EmailVerified = true
	s.invalidateAuth()
}

// LockAdministratively ghi thời điểm admin lock và tăng auth_version.
func (s *State) LockAdministratively(now time.Time) {
	lockedAt := now.UTC()
	s.AdministrativeLockedAt = &lockedAt
	s.invalidateAuth()
}

// UnlockAdministratively gỡ admin lock và tăng auth_version.
func (s *State) UnlockAdministratively() {
	s.AdministrativeLockedAt = nil
	s.invalidateAuth()
}

// SetAdministrativeStatus áp dụng public status do admin yêu cầu mà không phá email invariant.
func (s *State) SetAdministrativeStatus(status PublicStatus, now time.Time) error {
	switch status {
	case PublicActive:
		if !s.EmailVerified {
			s.Lifecycle = PendingVerification
		} else {
			s.Lifecycle = Active
		}
		s.AdministrativeLockedAt = nil
		s.LoginLockedUntil = nil
		s.FailedLoginAttempts = 0
	case PublicInactive:
		s.Lifecycle = Disabled
		s.AdministrativeLockedAt = nil
		s.LoginLockedUntil = nil
		s.FailedLoginAttempts = 0
	case PublicLocked:
		lockedAt := now.UTC()
		s.AdministrativeLockedAt = &lockedAt
	default:
		return apperror.ErrBadRequest.WithMessage("Trạng thái tài khoản không hợp lệ")
	}
	s.invalidateAuth()
	return nil
}

// RecordFailedLogin tăng failed-attempt counter và đặt login lock khi chạm ngưỡng.
func (s *State) RecordFailedLogin(now time.Time, maxAttempts int, lockDuration time.Duration) {
	s.FailedLoginAttempts++
	if maxAttempts > 0 && s.FailedLoginAttempts >= maxAttempts {
		lockedUntil := now.UTC().Add(lockDuration)
		s.LoginLockedUntil = &lockedUntil
	}
}

// UnlockLoginIfExpired xóa login lock đã hết hạn và báo state có thay đổi hay không.
func (s *State) UnlockLoginIfExpired(now time.Time) bool {
	if s.LoginLockedUntil == nil || s.LoginLockedUntil.After(now) {
		return false
	}
	s.LoginLockedUntil = nil
	s.FailedLoginAttempts = 0
	return true
}

// CompleteAuthentication xóa failed-attempt state sau khi đăng nhập thành công.
func (s *State) CompleteAuthentication() {
	s.LoginLockedUntil = nil
	s.FailedLoginAttempts = 0
}

// CompleteCredentialChange xóa lock tạm, bỏ cờ bắt đổi mật khẩu và tăng auth_version.
func (s *State) CompleteCredentialChange() {
	s.LoginLockedUntil = nil
	s.FailedLoginAttempts = 0
	s.PasswordChangeRequired = false
	s.invalidateAuth()
}

// RequirePasswordChange buộc lần đăng nhập kế tiếp đổi mật khẩu và tăng auth_version.
func (s *State) RequirePasswordChange() {
	s.PasswordChangeRequired = true
	s.invalidateAuth()
}

// InvalidateAuth công khai transition tăng auth_version cho security mutation.
func (s *State) InvalidateAuth() {
	s.invalidateAuth()
}

// invalidateAuth tăng canonical auth_version đúng một lần cho mỗi transition.
func (s *State) invalidateAuth() {
	s.AuthVersion++
}
