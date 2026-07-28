package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	authapp "github.com/quocdev03/user-access-management/internal/auth"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"github.com/quocdev03/user-access-management/pkg/response"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

type AuthHandler struct {
	registration      *authapp.Registration
	emailVerification *authapp.EmailVerification
	login             *authapp.Login
	refresh           *authapp.Refresh
	logout            *authapp.Logout
	password          *authapp.Password
	mfa               *authapp.MFA
}

func NewAuthHandler(
	registration *authapp.Registration,
	emailVerification *authapp.EmailVerification,
	login *authapp.Login,
	refresh *authapp.Refresh,
	logout *authapp.Logout,
	password *authapp.Password,
	mfa *authapp.MFA,
) *AuthHandler {
	return &AuthHandler{
		registration:      registration,
		emailVerification: emailVerification,
		login:             login,
		refresh:           refresh,
		logout:            logout,
		password:          password,
		mfa:               mfa,
	}
}

// @Summary Đăng ký tài khoản mới
// @Description Đăng ký người dùng mới vào hệ thống
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Thông tin đăng ký"
// @Success 201 {object} response.Response{data=RegisterResponse}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	req, ok := validator.BindAndValidate[RegisterRequest](c)
	if !ok {
		return
	}

	registered, err := h.registration.Register(
		c.Request.Context(),
		authapp.RegisterCommand{
			Username:    req.Username,
			Email:       req.Email,
			Password:    req.Password,
			FullName:    req.FullName,
			Phone:       req.Phone,
			DateOfBirth: req.DateOfBirth,
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(
		c,
		http.StatusCreated,
		"Đăng ký thành công. Vui lòng kiểm tra email để nhận mã OTP.",
		RegisterResponse{
			ID:       registered.ID,
			Username: registered.Username,
			Email:    registered.Email,
			Status:   registered.Status,
		},
	)
}

// @Summary Xác thực email
// @Description Xác thực tài khoản qua email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body VerifyEmailRequest true "OTP xác thực"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /auth/email/verify [post]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	req, ok := validator.BindAndValidate[VerifyEmailRequest](c)
	if !ok {
		return
	}

	err := h.emailVerification.Verify(c.Request.Context(), req.Email, req.OTP)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Xác thực email thành công", nil)
}

// @Summary Gửi lại OTP xác thực
// @Description Yêu cầu gửi lại email chứa OTP xác thực tài khoản
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ResendVerificationEmailRequest true "Thông tin yêu cầu"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /auth/email/resend [post]
func (h *AuthHandler) ResendVerificationEmail(c *gin.Context) {
	req, ok := validator.BindAndValidate[ResendVerificationEmailRequest](c)
	if !ok {
		return
	}

	err := h.emailVerification.Resend(c.Request.Context(), req.Email)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Đã gửi lại mã OTP. Vui lòng kiểm tra email của bạn.", nil)
}

// @Summary Đăng nhập
// @Description Đăng nhập vào hệ thống
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Thông tin đăng nhập"
// @Success 200 {object} response.Response{data=LoginResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	req, ok := validator.BindAndValidate[LoginRequest](c)
	if !ok {
		return
	}

	loggedIn, err := h.login.Authenticate(c.Request.Context(), authapp.LoginCommand{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	if loggedIn.MFARequired {
		c.Header("Cache-Control", "no-store")
		response.Success(
			c,
			http.StatusOK,
			"Cần xác thực MFA để hoàn tất đăng nhập",
			MFALoginChallengeResponse{
				MFARequired: true,
				Challenge:   loggedIn.MFAChallenge,
			},
		)
		return
	}

	response.Success(c, http.StatusOK, "Đăng nhập thành công", LoginResponse{
		AccessToken:  loggedIn.AccessToken,
		RefreshToken: loggedIn.RefreshToken,
		User: UserInfoResponse{
			ID:       loggedIn.UserID,
			Username: loggedIn.Username,
			Email:    loggedIn.Email,
			FullName: loggedIn.FullName,
		},
	})
}

// @Summary Hoàn tất đăng nhập bằng MFA
// @Description Xác thực TOTP hoặc recovery code bằng opaque login challenge
// @Tags MFA
// @Accept json
// @Produce json
// @Param request body MFALoginVerifyRequest true "Challenge và mã MFA"
// @Success 200 {object} response.Response{data=LoginResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 503 {object} response.Response
// @Router /auth/mfa/login/verify [post]
func (h *AuthHandler) VerifyMFALogin(c *gin.Context) {
	req, ok := validator.BindAndValidate[MFALoginVerifyRequest](c)
	if !ok {
		return
	}
	loggedIn, err := h.mfa.VerifyLogin(
		c.Request.Context(),
		authapp.MFALoginCommand{
			Challenge: req.Challenge,
			Code:      req.Code,
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Success(c, http.StatusOK, "Đăng nhập thành công", LoginResponse{
		AccessToken:  loggedIn.AccessToken,
		RefreshToken: loggedIn.RefreshToken,
		User: UserInfoResponse{
			ID:       loggedIn.UserID,
			Username: loggedIn.Username,
			Email:    loggedIn.Email,
			FullName: loggedIn.FullName,
		},
	})
}

// @Summary Bắt đầu thiết lập MFA
// @Description Xác thực mật khẩu hiện tại và tạo TOTP enrollment mới
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MFASetupRequest true "Mật khẩu hiện tại"
// @Success 200 {object} response.Response{data=MFASetupResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/mfa/setup [post]
func (h *AuthHandler) SetupMFA(c *gin.Context) {
	req, ok := validator.BindAndValidate[MFASetupRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	setup, err := h.mfa.Setup(
		c.Request.Context(),
		claims.UserID,
		req.CurrentPassword,
		authapp.PasswordMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Success(c, http.StatusOK, "Đã tạo enrollment MFA", MFASetupResponse{
		Secret:        setup.Secret,
		EnrollmentURI: setup.EnrollmentURI,
	})
}

// @Summary Xác nhận và bật MFA
// @Description Xác nhận TOTP enrollment và trả recovery codes đúng một lần
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MFAConfirmRequest true "Mã TOTP"
// @Success 200 {object} response.Response{data=MFARecoveryCodesResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/mfa/confirm [post]
func (h *AuthHandler) ConfirmMFA(c *gin.Context) {
	req, ok := validator.BindAndValidate[MFAConfirmRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	codes, err := h.mfa.Confirm(
		c.Request.Context(),
		claims.UserID,
		claims.AuthVersion,
		req.Code,
		authapp.PasswordMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Success(
		c,
		http.StatusOK,
		"MFA đã được bật; hãy lưu recovery codes ở nơi an toàn",
		MFARecoveryCodesResponse{RecoveryCodes: codes},
	)
}

// @Summary Tắt MFA
// @Description Yêu cầu mật khẩu hiện tại và TOTP hoặc recovery code
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MFASensitiveRequest true "Mật khẩu và mã MFA"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/mfa/disable [post]
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	req, ok := validator.BindAndValidate[MFASensitiveRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err := h.mfa.Disable(
		c.Request.Context(),
		claims.UserID,
		req.CurrentPassword,
		req.Code,
		authapp.PasswordMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "MFA đã được tắt; vui lòng đăng nhập lại", nil)
}

// @Summary Trạng thái MFA
// @Description Trả trạng thái bật và số recovery code chưa dùng
// @Tags MFA
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=MFAStatusResponse}
// @Failure 401 {object} response.Response
// @Router /auth/mfa/status [get]
func (h *AuthHandler) MFAStatus(c *gin.Context) {
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	status, err := h.mfa.Status(c.Request.Context(), claims.UserID)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Lấy trạng thái MFA thành công", MFAStatusResponse{
		Enabled:                status.Enabled,
		RecoveryCodesRemaining: status.RecoveryCodesRemaining,
	})
}

// @Summary Tạo lại recovery codes
// @Description Thay toàn bộ recovery codes sau khi xác thực mật khẩu và MFA
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MFASensitiveRequest true "Mật khẩu và mã MFA"
// @Success 200 {object} response.Response{data=MFARecoveryCodesResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/mfa/recovery/regenerate [post]
func (h *AuthHandler) RegenerateMFARecoveryCodes(c *gin.Context) {
	req, ok := validator.BindAndValidate[MFASensitiveRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	codes, err := h.mfa.RegenerateRecoveryCodes(
		c.Request.Context(),
		claims.UserID,
		req.CurrentPassword,
		req.Code,
		authapp.PasswordMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Success(
		c,
		http.StatusOK,
		"Recovery codes đã được thay thế; vui lòng đăng nhập lại",
		MFARecoveryCodesResponse{RecoveryCodes: codes},
	)
}

// @Summary Làm mới Access Token
// @Description Cấp lại Access Token mới dựa trên Refresh Token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh Token"
// @Success 200 {object} response.Response{data=RefreshTokenResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/token/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	req, ok := validator.BindAndValidate[RefreshTokenRequest](c)
	if !ok {
		return
	}

	rotated, err := h.refresh.Rotate(c.Request.Context(), authapp.RefreshCommand{
		RefreshToken: req.RefreshToken,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Làm mới token thành công", RefreshTokenResponse{
		AccessToken:  rotated.AccessToken,
		RefreshToken: rotated.RefreshToken,
	})
}

// @Summary Đăng xuất
// @Description Đăng xuất khỏi hệ thống
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	claims := c.MustGet("tokenClaims").(*jwt.Claims)

	err := h.logout.Current(
		c.Request.Context(),
		claims.UserID,
		claims.ID,
		claims.ExpiresAt.Time,
	)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Đăng xuất thành công", nil)
}

// @Summary Đăng xuất khỏi tất cả thiết bị
// @Description Hủy tất cả các phiên đăng nhập của người dùng
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	claims := c.MustGet("tokenClaims").(*jwt.Claims)

	err := h.logout.All(c.Request.Context(), claims.UserID)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Đăng xuất khỏi tất cả thiết bị thành công", nil)
}

// @Summary Quên mật khẩu
// @Description Yêu cầu đặt lại mật khẩu — gửi email chứa link/token (không OTP)
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Email đã đăng ký"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /auth/password/forgot [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	req, ok := validator.BindAndValidate[ForgotPasswordRequest](c)
	if !ok {
		return
	}

	err := h.password.Forgot(c.Request.Context(), req.Email)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Nếu email hợp lệ, hệ thống sẽ gửi một link khôi phục mật khẩu. Vui lòng kiểm tra hộp thư của bạn.",
		nil,
	)
}

// @Summary Đặt lại mật khẩu
// @Description Đặt lại mật khẩu bằng token từ email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Token + mật khẩu mới"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /auth/password/reset [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	req, ok := validator.BindAndValidate[ResetPasswordRequest](c)
	if !ok {
		return
	}

	err := h.password.Reset(c.Request.Context(), authapp.ResetPasswordCommand{
		Token:       req.Token,
		NewPassword: req.NewPassword,
		Metadata: authapp.PasswordMetadata{
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		},
	})
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Khôi phục mật khẩu thành công. Vui lòng đăng nhập lại.", nil)
}

// @Summary Đổi mật khẩu
// @Description Đổi mật khẩu tài khoản
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ChangePasswordRequest true "Thông tin đổi mật khẩu"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /auth/password/change [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	req, ok := validator.BindAndValidate[ChangePasswordRequest](c)
	if !ok {
		return
	}

	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err := h.password.Change(
		c.Request.Context(),
		claims.UserID,
		authapp.ChangePasswordCommand{
			CurrentPassword: req.OldPassword,
			NewPassword:     req.NewPassword,
			Metadata: authapp.PasswordMetadata{
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
			},
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Đổi mật khẩu thành công. Vui lòng đăng nhập lại trên các thiết bị.", nil)
}

// @Summary Đổi mật khẩu bắt buộc
// @Description Đổi mật khẩu khi tài khoản bị yêu cầu thay credential. Không cần Bearer.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ForceChangePasswordRequest true "Email, mật khẩu hiện tại, mật khẩu mới"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /auth/password/force-change [post]
func (h *AuthHandler) ForceChangePassword(c *gin.Context) {
	req, ok := validator.BindAndValidate[ForceChangePasswordRequest](c)
	if !ok {
		return
	}

	err := h.password.ForceChange(
		c.Request.Context(),
		authapp.ForceChangePasswordCommand{
			Email:           req.Email,
			CurrentPassword: req.CurrentPassword,
			NewPassword:     req.NewPassword,
			Metadata: authapp.PasswordMetadata{
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
			},
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Đổi mật khẩu bắt buộc thành công. Vui lòng đăng nhập lại với mật khẩu mới.", nil)
}
