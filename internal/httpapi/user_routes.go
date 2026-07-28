package httpapi

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

func setupUserRoutes(
	rg *gin.RouterGroup,
	userHandler *UserHandler,
	authMiddleware gin.HandlerFunc,
	limiter *redisstore.Limiter,
	metrics *HTTPMetrics,
	banDuration time.Duration,
) {
	users := rg.Group("/users", authMiddleware)
	users.GET("/me", userHandler.GetProfile)
	users.PATCH(
		"/me",
		validator.ValidateJSON[UpdateProfileRequest](),
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
		userHandler.RequestEmailChange,
	)
	users.POST(
		"/me/email/verify",
		validator.ValidateJSON[VerifyEmailChangeRequest](),
		emailRateLimit,
		userHandler.VerifyEmailChange,
	)
	users.POST(
		"/me/email/resend",
		emailRateLimit,
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
		userHandler.UploadAvatar,
	)

	users.DELETE("/me/avatar", userHandler.DeleteAvatar)

	users.GET("/me/sessions", userHandler.GetSessions)
	users.DELETE("/me/sessions/:id", userHandler.RevokeSession)
	users.GET("/me/devices", userHandler.GetDevices)
}
