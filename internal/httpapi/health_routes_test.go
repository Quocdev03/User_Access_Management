package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

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
