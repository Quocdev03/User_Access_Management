package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// File này kiểm chứng hành vi health routes và các trường hợp lỗi liên quan.

// TestLivenessHasNoDependencyOrRateLimiter kiểm chứng kịch bản LivenessHasNoDependencyOrRateLimiter.
func TestLivenessHasNoDependencyOrRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	setupHealthRoutes(engine, nil, nil, time.Second, zap.NewNop())

	for i := 0; i < 100; i++ {
		request := httptest.NewRequest(http.MethodGet, "/health", nil)
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d status = %d", i, recorder.Code)
		}
	}
}

// TestMetricsHandlerRejectsEmptyToken kiểm chứng kịch bản MetricsHandler từ chối khi token rỗng bằng 404.
func TestMetricsHandlerRejectsEmptyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/metrics", MetricsHandler(&HTTPMetrics{}, nil, nil, ""))

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 when token is empty, got %d", recorder.Code)
	}
}
