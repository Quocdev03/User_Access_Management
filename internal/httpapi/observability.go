package httpapi

import (
	"crypto/subtle"
	"net/http"
	"regexp"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/response"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const RequestIDKey = "requestID"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func RequestID(c *gin.Context) string {
	requestID, _ := c.Get(RequestIDKey)
	value, _ := requestID.(string)
	return value
}

type HTTPMetrics struct {
	requests         atomic.Uint64
	inFlight         atomic.Int64
	responses2xx     atomic.Uint64
	responses3xx     atomic.Uint64
	responses4xx     atomic.Uint64
	responses5xx     atomic.Uint64
	durationNanos    atomic.Uint64
	rateLimitRejects atomic.Uint64
}

func (m *HTTPMetrics) RecordRateLimitReject() {
	m.rateLimitRejects.Add(1)
}

func RequestObservability(logger *zap.Logger, metrics *HTTPMetrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if !requestIDPattern.MatchString(requestID) {
			requestID = uuid.NewString()
		}
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)

		start := time.Now()
		metrics.requests.Add(1)
		metrics.inFlight.Add(1)
		defer metrics.inFlight.Add(-1)

		c.Next()

		status := c.Writer.Status()
		switch status / 100 {
		case 2:
			metrics.responses2xx.Add(1)
		case 3:
			metrics.responses3xx.Add(1)
		case 4:
			metrics.responses4xx.Add(1)
		case 5:
			metrics.responses5xx.Add(1)
		}
		elapsed := time.Since(start)
		metrics.durationNanos.Add(uint64(elapsed))

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		clientClass := "anonymous"
		if _, exists := c.Get("userID"); exists {
			clientClass = "authenticated"
		}
		logger.Info(
			"http request",
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("route", route),
			zap.Int("status", status),
			zap.Duration("latency", elapsed),
			zap.String("client_class", clientClass),
		)
	}
}

func Recovery(logger *zap.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		requestID, _ := c.Get(RequestIDKey)
		logger.Error(
			"http panic recovered",
			zap.Any("panic", recovered),
			zap.Any("request_id", requestID),
			zap.Stack("stack"),
		)
		response.Error(c, apperror.ErrInternalServer)
		c.Abort()
	})
}

func MetricsHandler(
	metrics *HTTPMetrics,
	db *sqlx.DB,
	redisClient *redis.Client,
	token string,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token != "" {
			provided := c.GetHeader("Authorization")
			expected := "Bearer " + token
			if len(provided) != len(expected) ||
				subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
				c.Status(http.StatusNotFound)
				return
			}
		}

		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		dbStats := db.Stats()
		redisStats := redisClient.PoolStats()
		c.JSON(http.StatusOK, gin.H{
			"http": gin.H{
				"requests_total":          metrics.requests.Load(),
				"in_flight":               metrics.inFlight.Load(),
				"responses_2xx_total":     metrics.responses2xx.Load(),
				"responses_3xx_total":     metrics.responses3xx.Load(),
				"responses_4xx_total":     metrics.responses4xx.Load(),
				"responses_5xx_total":     metrics.responses5xx.Load(),
				"duration_seconds_total":  float64(metrics.durationNanos.Load()) / float64(time.Second),
				"rate_limit_reject_total": metrics.rateLimitRejects.Load(),
			},
			"mysql": gin.H{
				"max_open":           dbStats.MaxOpenConnections,
				"open":               dbStats.OpenConnections,
				"in_use":             dbStats.InUse,
				"idle":               dbStats.Idle,
				"wait_count_total":   dbStats.WaitCount,
				"wait_seconds_total": dbStats.WaitDuration.Seconds(),
			},
			"redis": gin.H{
				"hits_total":        redisStats.Hits,
				"misses_total":      redisStats.Misses,
				"timeouts_total":    redisStats.Timeouts,
				"total_conns":       redisStats.TotalConns,
				"idle_conns":        redisStats.IdleConns,
				"stale_conns_total": redisStats.StaleConns,
			},
			"runtime": gin.H{
				"goroutines":       runtime.NumGoroutine(),
				"heap_alloc_bytes": memory.HeapAlloc,
				"heap_objects":     memory.HeapObjects,
				"gc_cycles_total":  memory.NumGC,
			},
		})
	}
}
