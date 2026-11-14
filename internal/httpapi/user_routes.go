package httpapi

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

// File này đăng ký route hồ sơ, email, avatar và session của người dùng.

// setupUserRoutes gắn profile, email, avatar và session routes sau authentication.
func setupUserRoutes(
	rg *gin.RouterGroup,
	userHandler *UserHandler,
	authMiddleware gin.HandlerFunc,
	limiter *redisstore.Limiter,
	metrics *HTTPMetrics,
	banDuration time.Duration,
) {
	users := rg.Group("/users")
	users.GET("/me", authMiddleware, userHandler.GetProfile)
	users.PATCH(
		"/me",
		validator.ValidateJSON[UpdateProfileRequest](),
		authMiddleware,
		userHandler.UpdateProfile,
	)
	emailRateLimit := RateLimitMiddleware(
		limiter,
		metrics,
		"change-email",
		5,
		20,
		time.Minute,
		banDuration,
	)

	users.POST(
		"/me/email/change-request",
		validator.ValidateJSON[RequestEmailChangeRequest](),
		emailRateLimit,
		authMiddleware,
		userHandler.RequestEmailChange,
	)
	users.POST(
		"/me/email/verify",
		validator.ValidateJSON[VerifyEmailChangeRequest](),
		emailRateLimit,
		authMiddleware,
		userHandler.VerifyEmailChange,
	)
	users.POST(
		"/me/email/resend",
		emailRateLimit,
		authMiddleware,
		userHandler.ResendChangeEmailOTP,
	)

	users.POST(
		"/me/avatar",
		ValidateMultipartFile("avatar"),
		RateLimitMiddleware(
			limiter,
			metrics,
			"upload-avatar",
			5,
			20,
			time.Minute,
			banDuration,
		),
		authMiddleware,
		userHandler.UploadAvatar,
	)

	users.DELETE("/me/avatar", authMiddleware, userHandler.DeleteAvatar)

	users.GET("/me/sessions", authMiddleware, userHandler.GetSessions)
	users.DELETE("/me/sessions/:id", authMiddleware, userHandler.RevokeSession)
	users.GET("/me/devices", authMiddleware, userHandler.GetDevices)
}
