package httpapi

import (
	"github.com/gin-gonic/gin"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

func setupAdminRoutes(
	rg *gin.RouterGroup,
	adminHandler *AdminHandler,
	authMw gin.HandlerFunc,
	authorizer *accessapp.Authorizer,
) {
	admin := rg.Group("/admin")
	admin.Use(authMw)

	users := admin.Group("/users")
	users.GET(
		"",
		PermissionMiddleware(authorizer, "users.read"),
		adminHandler.ListUsers,
	)
	users.GET(
		"/:id",
		PermissionMiddleware(authorizer, "users.read"),
		adminHandler.GetUserDetail,
	)
	users.PUT(
		"/:id",
		validator.ValidateJSON[AdminUpdateUserRequest](),
		PermissionMiddleware(authorizer, "users.update"),
		adminHandler.UpdateUser,
	)
	users.PATCH(
		"/:id/status",
		validator.ValidateJSON[AdminChangeStatusRequest](),
		PermissionMiddleware(authorizer, "users.lock"),
		adminHandler.ChangeUserStatus,
	)
	users.POST(
		"/:id/password/reset",
		PermissionMiddleware(authorizer, "users.reset_password"),
		adminHandler.ResetPassword,
	)
	users.POST(
		"/:id/notify",
		validator.ValidateJSON[AdminNotifyRequest](),
		PermissionMiddleware(authorizer, "users.notify"),
		adminHandler.NotifyUser,
	)

	roles := admin.Group("/roles")
	roles.GET(
		"",
		PermissionMiddleware(authorizer, "roles.read"),
		adminHandler.ListRoles,
	)
	roles.POST(
		"",
		validator.ValidateJSON[CreateRoleRequest](),
		PermissionMiddleware(authorizer, "roles.create"),
		adminHandler.CreateRole,
	)
	roles.PUT(
		"/:id",
		validator.ValidateJSON[UpdateRoleRequest](),
		PermissionMiddleware(authorizer, "roles.update"),
		adminHandler.UpdateRole,
	)
	roles.DELETE(
		"/:id",
		PermissionMiddleware(authorizer, "roles.delete"),
		adminHandler.DeleteRole,
	)
	roles.PUT(
		"/:id/permissions",
		validator.ValidateJSON[AssignPermissionsRequest](),
		PermissionMiddleware(authorizer, "permissions.assign"),
		adminHandler.AssignPermissions,
	)

	admin.POST(
		"/users/:id/roles",
		validator.ValidateJSON[AssignRoleRequest](),
		PermissionMiddleware(authorizer, "roles.assign"),
		adminHandler.AssignUserRole,
	)
	admin.DELETE(
		"/users/:id/roles/:roleId",
		PermissionMiddleware(authorizer, "roles.assign"),
		adminHandler.RemoveUserRole,
	)

	admin.GET(
		"/audit-logs/export",
		PermissionMiddleware(authorizer, "audit_logs.export"),
		adminHandler.Export,
	)
}
