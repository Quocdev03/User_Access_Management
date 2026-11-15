package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	pkglogger "github.com/quocdev03/user-access-management/pkg/logger"
	"github.com/quocdev03/user-access-management/pkg/response"
	"go.uber.org/zap"
)

// File này xác minh access token và gắn principal vào request context.

// AuthMiddleware xác minh Bearer token và principal state theo fail-closed policy.
func AuthMiddleware(
	cfg *config.Config,
	accounts *mysqlstore.AccountStore,
	tokens *redisstore.TokenStore,
	logger *zap.Logger,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Error(c, apperror.ErrMissingAuthHeader)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			response.Error(c, apperror.ErrInvalidAuthHeader)
			c.Abort()
			return
		}

		tokenStr := parts[1]
		claims, err := jwt.ParseToken(tokenStr, cfg.JWT.Secret)
		if err != nil {
			errCode := "ERR_INVALID_TOKEN"
			errMsg := "Mã token xác thực không hợp lệ"
			if errors.Is(err, jwt.ErrExpiredToken) {
				errCode = "ERR_TOKEN_EXPIRED"
				errMsg = "Mã token xác thực đã hết hạn"
			}
			response.Error(c, apperror.NewAppError(errCode, errMsg, http.StatusUnauthorized))
			c.Abort()
			return
		}

		if claims.Type != "access" {
			response.Error(c, apperror.ErrNotAccessToken)
			c.Abort()
			return
		}

		blacklisted, err := tokens.IsJTIBlacklisted(c.Request.Context(), claims.ID)
		if err != nil {
			logger.Error(
				"Lỗi kết nối Redis khi check blacklist, từ chối request",
				zap.Error(err),
				zap.String("jti", pkglogger.SanitizeLogValue(claims.ID)),
			)
			response.Error(c, serviceUnavailableError())
			c.Abort()
			return
		}
		if blacklisted {
			response.Error(c, apperror.ErrTokenRevoked)
			c.Abort()
			return
		}

		account, err := accounts.FindByID(c.Request.Context(), claims.UserID)
		if err != nil {
			logger.Error(
				"Không thể kiểm tra auth version, từ chối request",
				zap.Error(err),
				zap.Uint64("user_id", claims.UserID),
			)
			response.Error(c, serviceUnavailableError())
			c.Abort()
			return
		}
		if account == nil {
			response.Error(c, apperror.ErrUnauthorized)
			c.Abort()
			return
		}
		state, err := account.State()
		if err != nil {
			logger.Error(
				"Canonical account state không hợp lệ, từ chối request",
				zap.Error(err),
				zap.Uint64("user_id", claims.UserID),
			)
			response.Error(c, serviceUnavailableError())
			c.Abort()
			return
		}
		if state.AuthVersion != claims.AuthVersion {
			response.Error(c, apperror.ErrSessionRevokedGlobal)
			c.Abort()
			return
		}
		if err := state.AuthenticationError(time.Now().UTC()); err != nil {
			response.Error(c, err)
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("token", tokenStr)
		c.Set("tokenClaims", claims)

		c.Next()
	}
}

// serviceUnavailableError trả 503 khi security dependency không thể đưa ra quyết định.
func serviceUnavailableError() error {
	return apperror.NewAppError(
		"ERR_SERVICE_UNAVAILABLE",
		"Hệ thống tạm thời không khả dụng",
		http.StatusServiceUnavailable,
	)
}
