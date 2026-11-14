package httpapi

import "time"

// File này khai báo request và response DTO cho API xác thực.

// UserInfoResponse biểu diễn thông tin cơ bản của người dùng sau khi xác thực.
type UserInfoResponse struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

// RegisterRequest chứa các thông tin đăng ký tài khoản mới từ client.
type RegisterRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=50,maxbytes=50"`
	Email       string `json:"email" binding:"required,email,maxbytes=254"`
	Password    string `json:"password" binding:"required,min=8,maxbytes=72"`
	FullName    string `json:"full_name" binding:"required,max=100,maxbytes=400"`
	Phone       string `json:"phone" binding:"required,max=20,maxbytes=20"`
	DateOfBirth string `json:"date_of_birth" binding:"required,datetime=2006-01-02"`
}

// RegisterResponse chứa thông tin tài khoản vừa đăng ký thành công.
type RegisterResponse struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Status   string `json:"status"`
}

// VerifyEmailRequest chứa email và OTP để xác minh email kích hoạt tài khoản.
type VerifyEmailRequest struct {
	Email string `json:"email" binding:"required,email,maxbytes=254"`
	OTP   string `json:"otp" binding:"required,len=6"`
}

// ResendVerificationEmailRequest chứa email yêu cầu gửi lại OTP kích hoạt tài khoản.
type ResendVerificationEmailRequest struct {
	Email string `json:"email" binding:"required,email,maxbytes=254"`
}

// LoginRequest chứa email và mật khẩu để yêu cầu đăng nhập.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email,maxbytes=254"`
	Password string `json:"password" binding:"required,maxbytes=72"`
}

// LoginResponse chứa cặp token và thông tin người dùng khi đăng nhập thành công.
type LoginResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	User         UserInfoResponse `json:"user"`
}

// MFALoginChallengeResponse thông báo yêu cầu thử thách MFA khi đăng nhập.
type MFALoginChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	Challenge   string `json:"challenge"`
}

// MFALoginVerifyRequest chứa mã thử thách và mã OTP xác minh MFA khi đăng nhập.
type MFALoginVerifyRequest struct {
	Challenge string `json:"challenge" binding:"required,len=43,maxbytes=43"`
	Code      string `json:"code" binding:"required,min=6,max=19,maxbytes=19"`
}

// MFASetupRequest chứa mật khẩu hiện tại để bắt đầu thiết lập MFA.
type MFASetupRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,maxbytes=72"`
}

// MFASetupResponse chứa khóa bí mật và URI mã QR để cài đặt ứng dụng xác thực.
type MFASetupResponse struct {
	Secret        string `json:"secret"`
	EnrollmentURI string `json:"enrollment_uri"`
}

// MFAConfirmRequest chứa mã OTP để xác nhận và kích hoạt MFA.
type MFAConfirmRequest struct {
	Code string `json:"code" binding:"required,len=6,maxbytes=6"`
}

// MFASensitiveRequest chứa mật khẩu và mã OTP để thực hiện các thao tác MFA nhạy cảm.
type MFASensitiveRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,maxbytes=72"`
	Code            string `json:"code" binding:"required,min=6,max=19,maxbytes=19"`
}

// MFARecoveryCodesResponse chứa danh sách mã khôi phục dự phòng cho MFA.
type MFARecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// MFAStatusResponse biểu diễn trạng thái bật/tắt MFA và số mã khôi phục còn lại.
type MFAStatusResponse struct {
	Enabled                bool `json:"enabled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// RefreshTokenRequest chứa refresh token để làm mới phiên đăng nhập.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,maxbytes=4096"`
}

// LogoutRequest chứa refresh token tùy chọn khi yêu cầu đăng xuất.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"omitempty,maxbytes=4096"`
}

// RefreshTokenResponse chứa cặp token mới sau khi làm mới phiên thành công.
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// ForgotPasswordRequest chứa email yêu cầu gửi liên kết đặt lại mật khẩu.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email,maxbytes=254"`
}

// ResetPasswordRequest chứa token đặt lại và mật khẩu mới.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required,maxbytes=4096"`
	NewPassword string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

// ChangePasswordRequest chứa mật khẩu cũ và mật khẩu mới khi chủ động đổi mật khẩu.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required,maxbytes=72"`
	NewPassword string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

// ForceChangePasswordRequest chứa thông tin đổi mật khẩu bắt buộc tại lần đăng nhập đầu tiên.
type ForceChangePasswordRequest struct {
	Email           string `json:"email" binding:"required,email,maxbytes=254"`
	CurrentPassword string `json:"temp_password" binding:"required,maxbytes=72"`
	NewPassword     string `json:"new_password" binding:"required,min=8,maxbytes=72"`
}

// SessionResponse biểu diễn thông tin chi tiết của một phiên đăng nhập người dùng.
type SessionResponse struct {
	ID        uint64    `json:"id"`
	IPAddress *string   `json:"ip_address"`
	UserAgent *string   `json:"user_agent"`
	DeviceID  *uint64   `json:"device_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IsCurrent bool      `json:"is_current"`
}

// DeviceResponse biểu diễn thông tin thiết bị đã đăng nhập của người dùng.
type DeviceResponse struct {
	ID           uint64     `json:"id"`
	DeviceName   *string    `json:"device_name"`
	DeviceType   *string    `json:"device_type"`
	OS           *string    `json:"os"`
	Browser      *string    `json:"browser"`
	IPAddress    *string    `json:"ip_address"`
	LastActiveAt *time.Time `json:"last_active_at"`
}
