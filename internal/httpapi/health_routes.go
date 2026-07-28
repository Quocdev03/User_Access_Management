package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func setupHealthRoutes(
	r *gin.Engine,
	db *sqlx.DB,
	redisClient *redis.Client,
	readinessTimeout time.Duration,
	logger *zap.Logger,
) {
	health := r.Group("/health")
	{
		health.GET("", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "UP"})
		})

		health.GET("/ready", func(c *gin.Context) {
			ctx, cancel := context.WithTimeout(c.Request.Context(), readinessTimeout)
			defer cancel()

			if err := db.PingContext(ctx); err != nil {
				logger.Error(
					"readiness dependency unavailable",
					zap.String("dependency", "mysql"),
					zap.String("request_id", RequestID(c)),
					zap.Error(err),
				)
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "DOWN"})
				return
			}
			if err := redisClient.Ping(ctx).Err(); err != nil {
				logger.Error(
					"readiness dependency unavailable",
					zap.String("dependency", "redis"),
					zap.String("request_id", RequestID(c)),
					zap.Error(err),
				)
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "DOWN"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "UP", "mysql": "UP", "redis": "UP"})
		})
	}
}
