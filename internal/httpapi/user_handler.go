package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	accountapp "github.com/quocdev03/user-access-management/internal/account"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"github.com/quocdev03/user-access-management/pkg/response"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

type UserHandler struct {
	profile        *accountapp.Profile
	email          *accountapp.Email
	avatar         *accountapp.Avatar
	sessionManager *sessionapp.Manager
}

func NewUserHandler(
	profile *accountapp.Profile,
	email *accountapp.Email,
	avatar *accountapp.Avatar,
	sessionManager *sessionapp.Manager,
) *UserHandler {
	return &UserHandler{
		profile:        profile,
		email:          email,
		avatar:         avatar,
		sessionManager: sessionManager,
	}
}

func getUserID(c *gin.Context) (uint64, bool) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		response.Error(c, apperror.ErrUnauthorized)
		return 0, false
	}
	userID, ok := userIDVal.(uint64)
	if !ok {
		response.Error(c, apperror.ErrUnauthorized)
		return 0, false
	}
	return userID, true
}

// @Summary Lấy thông tin cá nhân
// @Description Lấy thông tin hồ sơ của người dùng hiện tại
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=UserProfileResponse}
// @Failure 401 {object} response.Response
// @Router /users/me [get]
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}

	profile, err := h.profile.Get(c.Request.Context(), userID)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Lấy thông tin hồ sơ thành công", &UserProfileResponse{
		ID:            profile.ID,
		AvatarURL:     profile.AvatarURL,
		Username:      profile.Username,
		Email:         profile.Email,
		FullName:      profile.FullName,
		Phone:         profile.Phone,
		Status:        profile.Status,
		DateOfBirth:   profile.DateOfBirth,
		EmailVerified: profile.EmailVerified,
		CreatedAt:     profile.CreatedAt,
		Roles:         profile.Roles,
	})
}

// @Summary Cập nhật hồ sơ
// @Description Cập nhật thông tin hồ sơ của người dùng hiện tại
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateProfileRequest true "Thông tin cập nhật"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me [patch]
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}

	req, ok := validator.BindAndValidate[UpdateProfileRequest](c)
	if !ok {
		return
	}

	err := h.profile.Update(c.Request.Context(), userID, accountapp.UpdateProfileCommand{
		FullName:    req.FullName,
		Phone:       req.Phone,
		DateOfBirth: req.DateOfBirth,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Cập nhật hồ sơ thành công", nil)
}

// @Summary Yêu cầu đổi email
// @Description Yêu cầu đổi địa chỉ email, hệ thống sẽ gửi OTP
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body RequestEmailChangeRequest true "Email mới"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me/email/change-request [post]
func (h *UserHandler) RequestEmailChange(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}

	req, ok := validator.BindAndValidate[RequestEmailChangeRequest](c)
	if !ok {
		return
	}

	err := h.email.Request(c.Request.Context(), userID, accountapp.RequestEmailChangeCommand{
		CurrentPassword: req.CurrentPassword,
		NewEmail:        req.NewEmail,
		Metadata: accountapp.EmailMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(
		c,
		http.StatusOK,
		"Yêu cầu đổi email thành công. Mã xác thực OTP đã được gửi đến email cũ và email mới.",
		nil,
	)
}

// @Summary Xác thực đổi email
// @Description Nhập mã OTP để hoàn tất quá trình đổi email
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyEmailChangeRequest true "OTP cũ và mới"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me/email/verify [post]
func (h *UserHandler) VerifyEmailChange(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}

	req, ok := validator.BindAndValidate[VerifyEmailChangeRequest](c)
	if !ok {
		return
	}

	err := h.email.Verify(c.Request.Context(), userID, accountapp.VerifyEmailChangeCommand{
		OldOTP: req.OldOTP,
		NewOTP: req.NewOTP,
		Metadata: accountapp.EmailMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Thay đổi email thành công. Phiên hoạt động cũ của bạn đã được thu hồi.", nil)
}

// @Summary Tải lên ảnh đại diện
// @Description Upload ảnh đại diện mới
// @Tags Users
// @Accept multipart/form-data
// @Produce json
// @Security BearerAuth
// @Param avatar formData file true "File ảnh"
// @Success 200 {object} response.Response{data=UploadAvatarResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me/avatar [post]
func (h *UserHandler) UploadAvatar(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}
	fileHeader, ok := ValidatedMultipartFile(c, "avatar")
	if !ok {
		var err error
		fileHeader, err = c.FormFile("avatar")
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				response.Error(c, apperror.ErrRequestTooLarge)
			} else {
				response.ValidationError(c, err)
			}
			return
		}
	}

	src, err := fileHeader.Open()
	if err != nil {
		response.Error(c, apperror.ErrBadRequest.WithMessage("Không thể mở tệp tải lên"))
		return
	}
	defer src.Close()

	avatarURL, err := h.avatar.Upload(
		c.Request.Context(),
		userID,
		src,
		fileHeader.Filename,
		fileHeader.Size,
		accountapp.AvatarMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Tải ảnh đại diện lên thành công", &UploadAvatarResponse{
		AvatarURL: avatarURL,
	})
}

// @Summary Xóa ảnh đại diện
// @Description Xóa ảnh đại diện hiện tại
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me/avatar [delete]
func (h *UserHandler) DeleteAvatar(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}

	err := h.avatar.Delete(c.Request.Context(), userID, accountapp.AvatarMetadata{
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Xóa ảnh đại diện thành công", nil)
}

// @Summary Lấy danh sách phiên đăng nhập
// @Description Lấy danh sách các phiên đăng nhập đang hoạt động của người dùng
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=[]SessionResponse}
// @Failure 401 {object} response.Response
// @Router /users/me/sessions [get]
func (h *UserHandler) GetSessions(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)

	sessions, err := h.sessionManager.List(c.Request.Context(), userID, claims.ID)
	if err != nil {
		response.Error(c, err)
		return
	}
	result := make([]SessionResponse, 0, len(sessions))
	for _, current := range sessions {
		result = append(result, SessionResponse{
			ID:        current.ID,
			IPAddress: current.IPAddress,
			UserAgent: current.UserAgent,
			DeviceID:  current.DeviceID,
			ExpiresAt: current.ExpiresAt,
			CreatedAt: current.CreatedAt,
			IsCurrent: current.IsCurrent,
		})
	}
	response.Success(c, http.StatusOK, "Thành công", result)
}

// @Summary Xóa phiên đăng nhập
// @Description Hủy một phiên đăng nhập cụ thể theo ID
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Session ID"
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me/sessions/{id} [delete]
func (h *UserHandler) RevokeSession(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}
	sessionID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, apperror.ErrBadRequest.WithMessage("ID phiên không hợp lệ"))
		return
	}
	err = h.sessionManager.Revoke(c.Request.Context(), userID, sessionID)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Đã xóa phiên", nil)
}

// @Summary Lấy danh sách thiết bị
// @Description Lấy thông tin các thiết bị đã đăng nhập
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=[]DeviceResponse}
// @Failure 401 {object} response.Response
// @Router /users/me/devices [get]
func (h *UserHandler) GetDevices(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}
	profiles, err := h.sessionManager.ListClientProfiles(c.Request.Context(), userID)
	if err != nil {
		response.Error(c, err)
		return
	}
	res := make([]DeviceResponse, 0, len(profiles))
	for _, profile := range profiles {
		res = append(res, DeviceResponse{
			ID:           profile.ID,
			DeviceName:   profile.DeviceName,
			DeviceType:   profile.DeviceType,
			OS:           profile.OS,
			Browser:      profile.Browser,
			IPAddress:    profile.IPAddress,
			LastActiveAt: profile.LastActiveAt,
		})
	}
	response.Success(c, http.StatusOK, "Thành công", res)
}

// @Summary Gửi lại OTP đổi email
// @Description Yêu cầu gửi lại OTP cho thao tác đổi email
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /users/me/email/resend [post]
func (h *UserHandler) ResendChangeEmailOTP(c *gin.Context) {
	userID, ok := getUserID(c)
	if !ok {
		return
	}

	err := h.email.Resend(c.Request.Context(), userID)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Đã gửi lại mã OTP. Vui lòng kiểm tra email.", nil)
}
