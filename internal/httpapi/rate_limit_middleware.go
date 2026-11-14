package httpapi

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/response"
	"go.uber.org/zap"
)

// File này áp dụng token bucket và fail closed khi Redis không khả dụng.

// RateLimitMiddleware áp dụng limiter theo scope và trả 503 khi Redis không quyết định được.
func RateLimitMiddleware(
	limiter *redisstore.Limiter,
	metrics *HTTPMetrics,
	name string,
	limit int,
	banLimit int,
	window time.Duration,
	banDuration time.Duration,
) gin.HandlerFunc {
	abuseLimit := banLimit - limit
	if abuseLimit < 1 {
		abuseLimit = 1
	}
	policy := redisstore.LimitPolicy{
		Capacity:    limit,
		AbuseLimit:  abuseLimit,
		Window:      window,
		BanDuration: banDuration,
	}

	return func(c *gin.Context) {
		subject := strings.ReplaceAll(strings.ReplaceAll(c.ClientIP(), "{", ""), "}", "")
		decision, retryAfter, err := limiter.Allow(
			c.Request.Context(),
			name,
			subject,
			policy,
		)
		if err != nil {
			zap.L().Error(
				"rate limiter unavailable",
				zap.String("scope", name),
				zap.String("request_id", RequestID(c)),
				zap.Error(err),
			)
			response.Error(c, serviceUnavailableError())
			c.Abort()
			return
		}
		if retryAfter > 0 {
			seconds := int64((retryAfter + time.Second - 1) / time.Second)
			c.Header("Retry-After", strconv.FormatInt(seconds, 10))
		}

		switch decision {
		case redisstore.LimitBanned:
			if metrics != nil {
				metrics.RecordRateLimitReject()
			}
			response.Error(c, apperror.ErrIPBanned)
			c.Abort()
			return
		case redisstore.LimitRejected:
			if metrics != nil {
				metrics.RecordRateLimitReject()
			}
			response.Error(c, apperror.ErrRateLimited)
			c.Abort()
			return
		}

		c.Next()
	}
}
