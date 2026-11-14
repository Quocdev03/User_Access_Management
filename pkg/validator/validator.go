// Package validator cung cấp các kiểm tra định dạng dùng chung tại boundary.
package validator

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	playvalidator "github.com/go-playground/validator/v10"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/response"
)

// File này kiểm tra email, username và số điện thoại trước các bước tốn tài nguyên.

const validatedBodyKey = "validatedJSONBody"

// init đăng ký hoặc chuẩn bị dependency bắt buộc trước khi package được sử dụng.
func init() {
	engine, ok := binding.Validator.Engine().(*playvalidator.Validate)
	if !ok {
		return
	}
	if err := engine.RegisterValidation("maxbytes", func(field playvalidator.FieldLevel) bool {
		value := field.Field()
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return true
			}
			value = value.Elem()
		}
		maxBytes, err := strconv.Atoi(field.Param())
		return err == nil &&
			(value.Kind() != reflect.String || len([]byte(value.String())) <= maxBytes)
	}); err != nil {
		panic("register maxbytes validation: " + err.Error())
	}
	if err := engine.RegisterValidation("mailheader", func(field playvalidator.FieldLevel) bool {
		return !strings.ContainsAny(field.Field().String(), "\r\n")
	}); err != nil {
		panic("register mailheader validation: " + err.Error())
	}
}

// ValidateJSON bind request JSON và trả validation error có field metadata.
func ValidateJSON[T any]() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req T
		if err := c.ShouldBindJSON(&req); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				response.Error(c, apperror.ErrRequestTooLarge)
			} else {
				response.ValidationError(c, err)
			}
			c.Abort()
			return
		}
		c.Set(validatedBodyKey, &req)
		c.Next()
	}
}

// BindAndValidate bind JSON, chạy validator và tự ghi response 400 khi input không hợp lệ.
func BindAndValidate[T any](c *gin.Context) (*T, bool) {
	if value, exists := c.Get(validatedBodyKey); exists {
		if req, ok := value.(*T); ok {
			return req, true
		}
	}
	var req T
	if err := c.ShouldBindJSON(&req); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			response.Error(c, apperror.ErrRequestTooLarge)
			return nil, false
		}
		response.ValidationError(c, err)
		return nil, false
	}
	return &req, true
}
