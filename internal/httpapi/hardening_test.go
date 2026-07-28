package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/internal/httpapi"
	"github.com/quocdev03/user-access-management/internal/redisstore"
	"github.com/quocdev03/user-access-management/pkg/validator"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func TestBodyLimitRejectsKnownAndStreamingOversizeBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(httpapi.BodyLimitMiddleware(64, 256))
	engine.POST("/known", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	engine.POST(
		"/stream",
		validator.ValidateJSON[httpapi.LoginRequest](),
		func(c *gin.Context) { c.Status(http.StatusNoContent) },
	)

	known := httptest.NewRequest(
		http.MethodPost,
		"/known",
		strings.NewReader(strings.Repeat("x", 65)),
	)
	knownRecorder := httptest.NewRecorder()
	engine.ServeHTTP(knownRecorder, known)
	if knownRecorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("known-length status = %d", knownRecorder.Code)
	}

	stream := httptest.NewRequest(
		http.MethodPost,
		"/stream",
		strings.NewReader(`{"email":"user@example.test","password":"`+
			strings.Repeat("x", 80)+`"}`),
	)
	stream.ContentLength = -1
	stream.Header.Set("Content-Type", "application/json")
	streamRecorder := httptest.NewRecorder()
	engine.ServeHTTP(streamRecorder, stream)
	if streamRecorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streaming status = %d; body=%s", streamRecorder.Code, streamRecorder.Body)
	}
}

func TestDTOByteLimitRunsBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	engine := gin.New()
	engine.POST(
		"/login",
		validator.ValidateJSON[httpapi.LoginRequest](),
		func(c *gin.Context) {
			called = true
			c.Status(http.StatusNoContent)
		},
	)
	body, err := json.Marshal(httpapi.LoginRequest{
		Email:    "user@example.test",
		Password: strings.Repeat("x", 73),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest || called {
		t.Fatalf("status=%d called=%v body=%s", recorder.Code, called, recorder.Body)
	}
}

func TestRequestObservabilityControlsRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics := &httpapi.HTTPMetrics{}
	engine := gin.New()
	engine.Use(httpapi.RequestObservability(zap.NewNop(), metrics))
	engine.GET("/ok", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	request := httptest.NewRequest(http.MethodGet, "/ok", nil)
	request.Header.Set("X-Request-ID", "invalid request id")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	generated := recorder.Header().Get("X-Request-ID")
	if generated == "" || generated == "invalid request id" {
		t.Fatalf("generated request ID = %q", generated)
	}

	request = httptest.NewRequest(http.MethodGet, "/ok", nil)
	request.Header.Set("X-Request-ID", "edge-123")
	recorder = httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("X-Request-ID"); got != "edge-123" {
		t.Fatalf("preserved request ID = %q", got)
	}
}

func TestSensitiveLimiterRunsAfterFormatAndFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 10 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })
	limiter := redisstore.NewLimiter(client)
	engine := gin.New()
	engine.POST(
		"/login",
		validator.ValidateJSON[httpapi.LoginRequest](),
		httpapi.RateLimitMiddleware(
			limiter,
			&httpapi.HTTPMetrics{},
			"login-test",
			2,
			4,
			time.Minute,
			time.Minute,
		),
		func(c *gin.Context) { c.Status(http.StatusNoContent) },
	)

	malformed := httptest.NewRequest(
		http.MethodPost,
		"/login",
		strings.NewReader(`{"email":`),
	)
	malformed.Header.Set("Content-Type", "application/json")
	malformedRecorder := httptest.NewRecorder()
	engine.ServeHTTP(malformedRecorder, malformed)
	if malformedRecorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed status = %d", malformedRecorder.Code)
	}

	valid := httptest.NewRequest(
		http.MethodPost,
		"/login",
		strings.NewReader(`{"email":"user@example.test","password":"Password1!"}`),
	)
	valid.Header.Set("Content-Type", "application/json")
	validRecorder := httptest.NewRecorder()
	engine.ServeHTTP(validRecorder, valid)
	if validRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("Redis failure status = %d; body=%s", validRecorder.Code, validRecorder.Body)
	}
}
