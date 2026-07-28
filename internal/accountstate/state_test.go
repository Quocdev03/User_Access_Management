package accountstate

import (
	"errors"
	"testing"
	"time"

	"github.com/quocdev03/user-access-management/pkg/apperror"
)

func TestState_EffectiveStatus(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Minute)
	past := now.Add(-time.Minute)

	tests := []struct {
		name  string
		state State
		want  PublicStatus
	}{
		{"active", State{Lifecycle: Active, EmailVerified: true}, PublicActive},
		{"pending", Registration(), PublicInactive},
		{"disabled", State{Lifecycle: Disabled, EmailVerified: true}, PublicInactive},
		{"administrative lock wins", State{Lifecycle: Active, EmailVerified: true, AdministrativeLockedAt: &past}, PublicLocked},
		{"active login lock", State{Lifecycle: Active, EmailVerified: true, LoginLockedUntil: &future}, PublicLocked},
		{"expired login lock", State{Lifecycle: Active, EmailVerified: true, LoginLockedUntil: &past}, PublicActive},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.state.EffectiveStatus(now); got != test.want {
				t.Fatalf("EffectiveStatus() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestState_TransitionsDoNotClearAdministrativeLock(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	state := State{
		Lifecycle:              Active,
		EmailVerified:          true,
		AdministrativeLockedAt: &now,
		LoginLockedUntil:       timePointer(now.Add(time.Minute)),
		FailedLoginAttempts:    5,
		PasswordChangeRequired: true,
		AuthVersion:            7,
	}

	state.CompleteCredentialChange()

	if state.AdministrativeLockedAt == nil {
		t.Fatal("credential change cleared administrative lock")
	}
	if state.LoginLockedUntil != nil || state.FailedLoginAttempts != 0 || state.PasswordChangeRequired {
		t.Fatalf("credential cleanup incomplete: %+v", state)
	}
	if state.AuthVersion != 8 {
		t.Fatalf("auth version = %d, want 8", state.AuthVersion)
	}
	if err := state.AuthenticationError(now); !errors.Is(err, apperror.ErrAccountLocked) {
		t.Fatalf("AuthenticationError() = %v, want account locked", err)
	}
}

func TestState_VerifyEmailPreservesDisabledLifecycle(t *testing.T) {
	state := State{Lifecycle: Disabled}

	if err := state.VerifyEmail(); err != nil {
		t.Fatalf("VerifyEmail(): %v", err)
	}
	if state.Lifecycle != Disabled || !state.EmailVerified {
		t.Fatalf("VerifyEmail() reopened disabled account: %+v", state)
	}
}

func TestState_SetAdministrativeStatus(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	state := State{
		Lifecycle:              Active,
		EmailVerified:          true,
		AdministrativeLockedAt: timePointer(now.Add(-time.Minute)),
		LoginLockedUntil:       timePointer(now.Add(time.Minute)),
		FailedLoginAttempts:    5,
		AuthVersion:            3,
	}
	if err := state.SetAdministrativeStatus(PublicActive, now); err != nil {
		t.Fatalf("SetAdministrativeStatus(active): %v", err)
	}
	if state.EffectiveStatus(now) != PublicActive ||
		state.AdministrativeLockedAt != nil ||
		state.LoginLockedUntil != nil ||
		state.FailedLoginAttempts != 0 ||
		state.AuthVersion != 4 {
		t.Fatalf("active administrative transition = %+v", state)
	}
	if err := state.SetAdministrativeStatus(PublicInactive, now); err != nil {
		t.Fatalf("SetAdministrativeStatus(inactive): %v", err)
	}
	if state.Lifecycle != Disabled || state.AuthVersion != 5 {
		t.Fatalf("inactive administrative transition = %+v", state)
	}
}

func TestState_SetEmailVerificationPreservesDisabledLifecycle(t *testing.T) {
	state := State{Lifecycle: Disabled, AuthVersion: 7}
	state.SetEmailVerification(true)
	if state.Lifecycle != Disabled ||
		!state.EmailVerified ||
		state.AuthVersion != 8 {
		t.Fatalf("email-verification transition = %+v", state)
	}
}

func TestState_RecordFailedLoginAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	state := State{Lifecycle: Active, EmailVerified: true}

	state.RecordFailedLogin(now, 2, 15*time.Minute)
	if state.LoginLockedUntil != nil {
		t.Fatal("account locked before threshold")
	}
	state.RecordFailedLogin(now, 2, 15*time.Minute)
	if state.LoginLockedUntil == nil {
		t.Fatal("account was not locked at threshold")
	}
	if state.UnlockLoginIfExpired(now.Add(14 * time.Minute)) {
		t.Fatal("login lock opened before expiry")
	}
	if !state.UnlockLoginIfExpired(now.Add(16 * time.Minute)) {
		t.Fatal("expired login lock was not opened")
	}
}

func TestState_Validate(t *testing.T) {
	tests := []struct {
		name    string
		state   State
		wantErr bool
	}{
		{"registration", Registration(), false},
		{"active verified", State{Lifecycle: Active, EmailVerified: true}, false},
		{"active unverified", State{Lifecycle: Active}, true},
		{"pending verified", State{Lifecycle: PendingVerification, EmailVerified: true}, true},
		{"unknown lifecycle", State{Lifecycle: "unknown"}, true},
		{"negative attempts", State{Lifecycle: Disabled, FailedLoginAttempts: -1}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.state.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}
