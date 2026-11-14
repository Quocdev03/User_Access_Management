// Package response ánh xạ kết quả HTTP sang response envelope ổn định.
package response

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này tạo response envelope và kiểm soát mức chi tiết lỗi được trả ra.

// Response định nghĩa cấu trúc envelope JSON chuẩn mực cho toàn bộ phản hồi API của hệ thống.
type Response struct {
	Data    interface{} `json:"data,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Success bool        `json:"success"`
}

// Success ghi response envelope thành công với HTTP status và payload đã cho.
func Success(c *gin.Context, statusCode int, message string, data interface{}) {
	c.JSON(statusCode, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// SuccessWithMeta bổ sung metadata phân trang vào response thành công.
func SuccessWithMeta(c *gin.Context, statusCode int, message string, data interface{}, meta interface{}) {
	c.JSON(statusCode, Response{
		Success: true,
		Message: message,
		Data:    data,
		Meta:    meta,
	})
}

// Error ánh xạ business hoặc system error sang public HTTP response an toàn.
func Error(c *gin.Context, err error) {
	var appErr *apperror.AppError
	if errors.As(err, &appErr) {
		errResp := gin.H{
			"code":    appErr.Code,
			"message": appErr.Message,
		}
		if appErr.Details != nil {
			errResp["details"] = appErr.Details
		}

		c.JSON(appErr.HTTPStatus, Response{
			Success: false,
			Error:   errResp,
		})
		return
	}

	errBody := gin.H{
		"code":    "INTERNAL_ERROR",
		"message": "Đã xảy ra lỗi hệ thống",
	}
	// Chỉ trả chi tiết lỗi ngoài production để tránh lộ SQL hoặc filesystem path.
	if gin.Mode() != gin.ReleaseMode {
		errBody["details"] = err.Error()
	}
	c.JSON(http.StatusInternalServerError, Response{
		Success: false,
		Error:   errBody,
	})
}

// ValidationError trả lỗi input theo response envelope thống nhất.
func ValidationError(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, Response{
		Success: false,
		Error: gin.H{
			"code":    apperror.ErrValidationError.Code,
			"message": apperror.ErrValidationError.Message,
			"details": err.Error(),
		},
	})
}
