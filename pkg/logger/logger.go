// Package logger khởi tạo structured logger dùng chung cho tiến trình.
package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// File này khởi tạo global Zap logger theo môi trường runtime.

// New khởi tạo  với các dependency được cung cấp.
func New(env string) (*zap.Logger, error) {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if env == "production" {
		config = zap.NewProductionConfig()
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	return config.Build(zap.AddStacktrace(zapcore.ErrorLevel))
}

// SanitizeLogValue loại bỏ ký tự điều khiển xuống dòng (\r, \n) để ngăn chặn Log Injection (CWE-117).
func SanitizeLogValue(val string) string {
	val = strings.ReplaceAll(val, "\r", "")
	return strings.ReplaceAll(val, "\n", "")
}
