package httpapi

import "time"

type UserInfoResponse struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

type RegisterRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=50,maxbytes=50"`
	Email       string `json:"email" binding:"required,email,maxbytes=254"`
	Password    string `json:"password" binding:"required,min=8,maxbytes=72"`
	FullName    string `json:"full_name" binding:"required,max=100,maxbytes=400"`
	Phone       string `json:"phone" binding:"required,max=20,maxbytes=20"`
	DateOfBirth string `json:"date_of_birth" binding:"required,datetime=2006-01-02"`
}

type RegisterResponse struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Status   string `json:"status"`
}

type VerifyEmailRequest struct {
	Email string `json:"email" binding:"required,email,maxbytes=254"`
	OTP   string `json:"otp" binding:"required,len=6"`
}

type ResendVerificationEmailRequest struct {
	Email string `json:"email" binding:"required,email,maxbytes=254"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email,maxbytes=254"`
	Password string `json:"password" binding:"required,maxbytes=72"`
}

type LoginResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	User         UserInfoResponse `json:"user"`
}

type MFALoginChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	Challenge   string `json:"challenge"`
}

type MFALoginVerifyRequest struct {
	Challenge string `json:"challenge" binding:"required,len=43,maxbytes=43"`
	Code      string `json:"code" binding:"required,min=6,max=19,maxbytes=19"`
}

type MFASetupRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,maxbytes=72"`
}

type MFASetupResponse struct {
	Secret        string `json:"secret"`
	EnrollmentURI string `json:"enrollment_uri"`
}

type MFAConfirmRequest struct {
	Code string `json:"code" binding:"required,len=6,maxbytes=6"`
}

type MFASensitiveRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,maxbytes=72"`
	Code            string `json:"code" binding:"required,min=6,max=19,maxbytes=19"`
}

type MFARecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

type MFAStatusResponse struct {
	Enabled                bool `json:"enabled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// --------------- Refresh Token ---------------

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,maxbytes=4096"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email,maxbytes=254"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required,maxbytes=4096"`
	NewPassword string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required,maxbytes=72"`
	NewPassword string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

type ForceChangePasswordRequest struct {
	Email           string `json:"email" binding:"required,email,maxbytes=254"`
	CurrentPassword string `json:"temp_password" binding:"required,maxbytes=72"`
	NewPassword     string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

type SessionResponse struct {
	ID        uint64    `json:"id"`
	IPAddress *string   `json:"ip_address"`
	UserAgent *string   `json:"user_agent"`
	DeviceID  *uint64   `json:"device_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IsCurrent bool      `json:"is_current"`
}

type DeviceResponse struct {
	ID           uint64     `json:"id"`
	DeviceName   *string    `json:"device_name"`
	DeviceType   *string    `json:"device_type"`
	OS           *string    `json:"os"`
	Browser      *string    `json:"browser"`
	IPAddress    *string    `json:"ip_address"`
	LastActiveAt *time.Time `json:"last_active_at"`
}
