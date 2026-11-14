package httpapi

import (
	"errors"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/response"
)

// File này giới hạn request body trước bước bind để giảm rủi ro tài nguyên.

// BodyLimitMiddleware từ chối request body vượt giới hạn trước bước bind.
func BodyLimitMiddleware(jsonMaxBytes, multipartMaxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := jsonMaxBytes
		if strings.HasPrefix(
			strings.ToLower(c.GetHeader("Content-Type")),
			"multipart/form-data",
		) {
			limit = multipartMaxBytes
		}
		if limit < 1 || c.Request.Body == nil {
			c.Next()
			return
		}
		if c.Request.ContentLength > limit {
			response.Error(c, apperror.ErrRequestTooLarge)
			c.Abort()
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

const multipartFileKeyPrefix = "validatedMultipartFile:"

// ValidateMultipartFile kiểm tra multipart file tại HTTP boundary.
func ValidateMultipartFile(field string) gin.HandlerFunc {
	return func(c *gin.Context) {
		fileHeader, err := c.FormFile(field)
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				response.Error(c, apperror.ErrRequestTooLarge)
			} else {
				response.ValidationError(c, err)
			}
			c.Abort()
			return
		}
		c.Set(multipartFileKeyPrefix+field, fileHeader)
		c.Next()
	}
}

// ValidatedMultipartFile giới hạn kích thước và loại nội dung trước khi đọc upload vào memory.
func ValidatedMultipartFile(c *gin.Context, field string) (*multipart.FileHeader, bool) {
	value, exists := c.Get(multipartFileKeyPrefix + field)
	if !exists {
		return nil, false
	}
	fileHeader, ok := value.(*multipart.FileHeader)
	return fileHeader, ok
}
