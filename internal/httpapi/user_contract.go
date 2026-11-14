package httpapi

import "time"

// File này khai báo request và response DTO cho API tài khoản hiện tại.

// UserProfileResponse chứa thông tin hồ sơ chi tiết của người dùng hiện tại.
type UserProfileResponse struct {
	ID            uint64    `json:"id"`
	AvatarURL     *string   `json:"avatar_url"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	FullName      string    `json:"full_name"`
	Phone         string    `json:"phone"`
	Status        string    `json:"status"`
	DateOfBirth   string    `json:"date_of_birth"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	Roles         []string  `json:"roles"`
}

// UpdateProfileRequest chứa các trường thông tin cập nhật hồ sơ cá nhân.
type UpdateProfileRequest struct {
	FullName    *string `json:"full_name" binding:"omitempty,max=100,maxbytes=400"`
	Phone       *string `json:"phone" binding:"omitempty,max=20,maxbytes=20"`
	DateOfBirth *string `json:"date_of_birth" binding:"omitempty,datetime=2006-01-02"`
}

// RequestEmailChangeRequest chứa mật khẩu hiện tại và email mới để yêu cầu đổi email.
type RequestEmailChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,maxbytes=72"`
	NewEmail        string `json:"new_email" binding:"required,email,maxbytes=254"`
}

// VerifyEmailChangeRequest chứa mã OTP gửi về email cũ và email mới để hoàn tất đổi email.
type VerifyEmailChangeRequest struct {
	OldOTP string `json:"old_otp" binding:"required,len=6"`
	NewOTP string `json:"new_otp" binding:"required,len=6"`
}

// UploadAvatarResponse chứa đường dẫn URL ảnh đại diện sau khi tải lên thành công.
type UploadAvatarResponse struct {
	AvatarURL string `json:"avatar_url"`
}
