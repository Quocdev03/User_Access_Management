package httpapi

import (
	"github.com/gin-gonic/gin"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"github.com/quocdev03/user-access-management/pkg/response"
)

// File này chặn request không có permission yêu cầu.

// PermissionMiddleware yêu cầu principal có permission trước khi vào admin handler.
func PermissionMiddleware(
	authorizer *accessapp.Authorizer,
	requiredPermission string,
) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		val, exists := ctx.Get("tokenClaims")
		if !exists {
			response.Error(ctx, apperror.ErrUnauthorized)
			ctx.Abort()
			return
		}

		claims, ok := val.(*jwt.Claims)
		if !ok {
			response.Error(ctx, apperror.ErrUnauthorized)
			ctx.Abort()
			return
		}

		allowed, err := authorizer.Allowed(
			ctx.Request.Context(),
			claims.UserID,
			requiredPermission,
		)
		if err != nil {
			response.Error(ctx, apperror.ErrInternalServer.WithMessage("không thể lấy dữ liệu phân quyền"))
			ctx.Abort()
			return
		}

		if !allowed {
			response.Error(ctx, apperror.ErrForbidden)
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}
