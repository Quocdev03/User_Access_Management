package httpapi

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

// File này đăng ký public và protected route của auth module.

// setupAuthRoutes tách public, MFA và protected auth routes theo security boundary.
func setupAuthRoutes(
	rg *gin.RouterGroup,
	authHandler *AuthHandler,
	authMiddleware gin.HandlerFunc,
	limiter *redisstore.Limiter,
	metrics *HTTPMetrics,
	banDuration time.Duration,
) {
	rateLimit := func(name string, limit, banLimit int) gin.HandlerFunc {
		return RateLimitMiddleware(
			limiter,
			metrics,
			name,
			limit,
			banLimit,
			time.Minute,
			banDuration,
		)
	}

	auth := rg.Group("/auth")
	auth.POST(
		"/register",
		validator.ValidateJSON[RegisterRequest](),
		rateLimit("register", 10, 30),
		authHandler.Register,
	)
	auth.POST(
		"/login",
		validator.ValidateJSON[LoginRequest](),
		rateLimit("login", 15, 50),
		authHandler.Login,
	)
	auth.POST("/logout", authHandler.Logout)
	auth.POST("/logout-all", authMiddleware, authHandler.LogoutAll)

	email := auth.Group("/email")
	email.POST(
		"/verify",
		validator.ValidateJSON[VerifyEmailRequest](),
		rateLimit("verify-email", 10, 30),
		authHandler.VerifyEmail,
	)
	email.POST(
		"/resend",
		validator.ValidateJSON[ResendVerificationEmailRequest](),
		rateLimit("resend-verification-email", 10, 30),
		authHandler.ResendVerificationEmail,
	)

	token := auth.Group("/token")
	token.POST(
		"/refresh",
		validator.ValidateJSON[RefreshTokenRequest](),
		rateLimit("refresh-token", 30, 60),
		authHandler.RefreshToken,
	)

	password := auth.Group("/password")
	password.POST(
		"/forgot",
		validator.ValidateJSON[ForgotPasswordRequest](),
		rateLimit("forgot-password", 10, 30),
		authHandler.ForgotPassword,
	)
	password.POST(
		"/reset",
		validator.ValidateJSON[ResetPasswordRequest](),
		rateLimit("reset-password", 10, 30),
		authHandler.ResetPassword,
	)
	password.POST(
		"/change",
		validator.ValidateJSON[ChangePasswordRequest](),
		rateLimit("change-password", 10, 30),
		authMiddleware,
		authHandler.ChangePassword,
	)
	password.POST(
		"/force-change",
		validator.ValidateJSON[ForceChangePasswordRequest](),
		rateLimit("force-change-password", 10, 30),
		authHandler.ForceChangePassword,
	)

	mfa := auth.Group("/mfa")
	mfa.POST(
		"/login/verify",
		validator.ValidateJSON[MFALoginVerifyRequest](),
		rateLimit("mfa-login-verify", 10, 30),
		authHandler.VerifyMFALogin,
	)
	mfa.POST(
		"/setup",
		validator.ValidateJSON[MFASetupRequest](),
		rateLimit("mfa-setup", 5, 15),
		authMiddleware,
		authHandler.SetupMFA,
	)
	mfa.POST(
		"/confirm",
		validator.ValidateJSON[MFAConfirmRequest](),
		rateLimit("mfa-confirm", 10, 20),
		authMiddleware,
		authHandler.ConfirmMFA,
	)
	mfa.POST(
		"/disable",
		validator.ValidateJSON[MFASensitiveRequest](),
		rateLimit("mfa-disable", 5, 15),
		authMiddleware,
		authHandler.DisableMFA,
	)
	mfa.GET("/status", authMiddleware, authHandler.MFAStatus)
	mfa.POST(
		"/recovery/regenerate",
		validator.ValidateJSON[MFASensitiveRequest](),
		rateLimit("mfa-recovery-regenerate", 5, 15),
		authMiddleware,
		authHandler.RegenerateMFARecoveryCodes,
	)
}
