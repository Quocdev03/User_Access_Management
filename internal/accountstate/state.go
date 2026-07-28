package accountstate

import (
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/pkg/apperror"
)

type Lifecycle string

const (
	PendingVerification Lifecycle = "pending_verification"
	Active              Lifecycle = "active"
	Disabled            Lifecycle = "disabled"
)

type PublicStatus string

const (
	PublicActive   PublicStatus = "active"
	PublicInactive PublicStatus = "inactive"
	PublicLocked   PublicStatus = "locked"
)

type State struct {
	Lifecycle              Lifecycle
	EmailVerified          bool
	AdministrativeLockedAt *time.Time
	LoginLockedUntil       *time.Time
	FailedLoginAttempts    int
	PasswordChangeRequired bool
	AuthVersion            uint64
}

func Registration() State {
	return State{Lifecycle: PendingVerification}
}

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

func (s *State) Disable() {
	s.Lifecycle = Disabled
	s.invalidateAuth()
}

func (s *State) Enable() {
	s.Lifecycle = Active
	s.EmailVerified = true
	s.invalidateAuth()
}

func (s *State) LockAdministratively(now time.Time) {
	lockedAt := now.UTC()
	s.AdministrativeLockedAt = &lockedAt
	s.invalidateAuth()
}

func (s *State) UnlockAdministratively() {
	s.AdministrativeLockedAt = nil
	s.invalidateAuth()
}

func (s *State) SetAdministrativeStatus(status PublicStatus, now time.Time) error {
	switch status {
	case PublicActive:
		if !s.EmailVerified {
			return apperror.ErrBadRequest.WithMessage(
				"Không thể kích hoạt tài khoản chưa xác thực email",
			)
		}
		s.Lifecycle = Active
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

func (s *State) RecordFailedLogin(now time.Time, maxAttempts int, lockDuration time.Duration) {
	s.FailedLoginAttempts++
	if maxAttempts > 0 && s.FailedLoginAttempts >= maxAttempts {
		lockedUntil := now.UTC().Add(lockDuration)
		s.LoginLockedUntil = &lockedUntil
	}
}

func (s *State) UnlockLoginIfExpired(now time.Time) bool {
	if s.LoginLockedUntil == nil || s.LoginLockedUntil.After(now) {
		return false
	}
	s.LoginLockedUntil = nil
	s.FailedLoginAttempts = 0
	return true
}

func (s *State) CompleteAuthentication() {
	s.LoginLockedUntil = nil
	s.FailedLoginAttempts = 0
}

func (s *State) CompleteCredentialChange() {
	s.LoginLockedUntil = nil
	s.FailedLoginAttempts = 0
	s.PasswordChangeRequired = false
	s.invalidateAuth()
}

func (s *State) RequirePasswordChange() {
	s.PasswordChangeRequired = true
	s.invalidateAuth()
}

func (s *State) InvalidateAuth() {
	s.invalidateAuth()
}

func (s *State) invalidateAuth() {
	s.AuthVersion++
}
