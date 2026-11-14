package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/jwt"
	"github.com/quocdev03/user-access-management/pkg/response"
	"github.com/quocdev03/user-access-management/pkg/validator"
)

// File này bind request quản trị và ánh xạ kết quả use case sang HTTP.

// AdminHandler tiếp nhận và xử lý các HTTP request quản trị người dùng, vai trò và nhật ký kiểm toán.
type AdminHandler struct {
	users *accessapp.Users
	roles *accessapp.Roles
	audit *accessapp.Audit
}

// NewAdminHandler khởi tạo AdminHandler với các dependency được cung cấp.
func NewAdminHandler(
	users *accessapp.Users,
	roles *accessapp.Roles,
	audit *accessapp.Audit,
) *AdminHandler {
	return &AdminHandler{users: users, roles: roles, audit: audit}
}

// parseTargetID phân tích target ID tại HTTP boundary.
func parseTargetID(ctx *gin.Context) (uint64, error) {
	return parseUintParam(ctx, "id", "ID người dùng không hợp lệ")
}

// parseUintParam từ chối path parameter không phải uint64 trước khi gọi use case.
func parseUintParam(ctx *gin.Context, name, badMsg string) (uint64, error) {
	id, err := strconv.ParseUint(ctx.Param(name), 10, 64)
	if err != nil {
		return 0, apperror.ErrBadRequest.WithMessage(badMsg)
	}
	return id, nil
}

// ListUsers xử lý HTTP cho thao tác lấy danh sách người dùng.
// @Summary Lấy danh sách người dùng
// @Description Dành cho Admin lấy danh sách users (hỗ trợ phân trang, lọc, sắp xếp)
// @Tags Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param page query int false "Số trang"
// @Param per_page query int false "Số lượng bản ghi mỗi trang"
// @Param sort_by query string false "Sắp xếp theo trường nào"
// @Param sort_order query string false "Chiều sắp xếp (asc/desc)"
// @Param status query string false "Lọc theo trạng thái"
// @Param username query string false "Tìm kiếm theo username"
// @Param email query string false "Tìm kiếm theo email"
// @Param role query string false "Lọc theo role"
// @Success 200 {object} response.Response{data=[]AdminUserListItem,meta=PaginationMeta}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users [get]
func (h *AdminHandler) ListUsers(ctx *gin.Context) {
	var req AdminListUsersRequest

	if err := ctx.ShouldBindQuery(&req); err != nil {
		response.Error(ctx, apperror.ErrBadRequest.WithMessage("query parameters không hợp lệ"))
		return
	}

	page, err := h.users.List(ctx.Request.Context(), accessapp.UserListQuery{
		Username:  req.Username,
		Email:     req.Email,
		Status:    req.Status,
		Role:      req.Role,
		SortBy:    req.SortBy,
		SortOrder: req.SortOrder,
		Page:      req.Page,
		PerPage:   req.PerPage,
	})
	if err != nil {
		response.Error(ctx, err)
		return
	}
	users := make([]AdminUserListItem, 0, len(page.Users))
	for _, user := range page.Users {
		users = append(users, adminUserResponse(user))
	}
	response.SuccessWithMeta(
		ctx,
		http.StatusOK,
		"lấy danh sách thành công",
		users,
		PaginationMeta{
			Page:       page.Page,
			PerPage:    page.PerPage,
			Total:      page.Total,
			TotalPages: page.TotalPages,
		},
	)
}

// GetUserDetail xử lý HTTP cho thao tác xem chi tiết người dùng.
// @Summary Xem chi tiết người dùng
// @Description Dành cho Admin xem chi tiết thông tin của một user cụ thể
// @Tags Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} response.Response{data=UserProfileResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id} [get]
func (h *AdminHandler) GetUserDetail(c *gin.Context) {
	targetID, err := parseTargetID(c)
	if err != nil {
		response.Error(c, err)
		return
	}

	user, err := h.users.Get(c.Request.Context(), targetID)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Lấy thông tin thành công", adminUserResponse(*user))
}

// UpdateUser xử lý HTTP cho thao tác cập nhật thông tin người dùng.
// @Summary Cập nhật thông tin người dùng
// @Description Dành cho Admin cập nhật thông tin cá nhân của user
// @Tags Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body AdminUpdateUserRequest true "Dữ liệu cập nhật"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id} [put]
func (h *AdminHandler) UpdateUser(ctx *gin.Context) {
	targetID, err := parseTargetID(ctx)
	if err != nil {
		response.Error(ctx, err)
		return
	}

	claims := ctx.MustGet("tokenClaims").(*jwt.Claims)
	req, ok := validator.BindAndValidate[AdminUpdateUserRequest](ctx)
	if !ok {
		return
	}

	err = h.users.Update(ctx.Request.Context(), accessapp.UpdateUserCommand{
		ActorID:         claims.UserID,
		TargetID:        targetID,
		FullName:        req.FullName,
		Phone:           req.Phone,
		Email:           req.Email,
		EmailVerified:   req.EmailVerified,
		DateOfBirth:     req.DateOfBirth,
		AvatarObjectKey: req.AvatarObjectKey,
		Metadata:        adminMetadata(ctx),
	})
	if err != nil {
		response.Error(ctx, err)
		return
	}

	response.Success(ctx, http.StatusOK, "Cập nhật người dùng thành công", nil)
}

// ChangeUserStatus xử lý HTTP cho thao tác thay đổi trạng thái người dùng.
// @Summary Thay đổi trạng thái người dùng
// @Description Dành cho Admin khóa hoặc mở khóa tài khoản user
// @Tags Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body AdminChangeStatusRequest true "Trạng thái và lý do"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id}/status [patch]
func (h *AdminHandler) ChangeUserStatus(ctx *gin.Context) {
	targetID, err := parseTargetID(ctx)
	if err != nil {
		response.Error(ctx, err)
		return
	}

	claims := ctx.MustGet("tokenClaims").(*jwt.Claims)
	req, ok := validator.BindAndValidate[AdminChangeStatusRequest](ctx)
	if !ok {
		return
	}

	err = h.users.ChangeStatus(ctx.Request.Context(), accessapp.ChangeStatusCommand{
		ActorID:  claims.UserID,
		TargetID: targetID,
		Status:   req.Status,
		Metadata: adminMetadata(ctx),
	})

	if err != nil {
		response.Error(ctx, err)
		return
	}

	response.Success(ctx, http.StatusOK, "cập nhật trạng thái thành công", nil)
}

// ResetPassword xử lý HTTP cho thao tác đặt lại mật khẩu người dùng.
// @Summary Đặt lại mật khẩu người dùng
// @Description Gửi liên kết đặt lại mật khẩu dùng một lần và thu hồi phiên hiện tại
// @Tags Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id}/password/reset [post]
func (h *AdminHandler) ResetPassword(ctx *gin.Context) {
	targetID, err := parseTargetID(ctx)
	if err != nil {
		response.Error(ctx, err)
		return
	}

	claims := ctx.MustGet("tokenClaims").(*jwt.Claims)

	err = h.users.RequestPasswordReset(
		ctx.Request.Context(),
		accessapp.ResetPasswordCommand{
			ActorID:  claims.UserID,
			TargetID: targetID,
			Metadata: adminMetadata(ctx),
		},
	)

	if err != nil {
		response.Error(ctx, err)
		return
	}

	response.Success(ctx, http.StatusOK, "Đã gửi liên kết đặt lại mật khẩu qua email", nil)
}

// NotifyUser xử lý HTTP cho thao tác gửi thông báo cho người dùng.
// @Summary Gửi thông báo cho người dùng
// @Description Dành cho Admin gửi email thông báo trực tiếp tới user
// @Tags Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body AdminNotifyRequest true "Nội dung thông báo"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id}/notify [post]
func (h *AdminHandler) NotifyUser(ctx *gin.Context) {
	targetID, err := parseTargetID(ctx)
	if err != nil {
		response.Error(ctx, err)
		return
	}
	claims := ctx.MustGet("tokenClaims").(*jwt.Claims)
	req, ok := validator.BindAndValidate[AdminNotifyRequest](ctx)
	if !ok {
		return
	}

	err = h.users.Notify(ctx.Request.Context(), accessapp.NotifyUserCommand{
		ActorID:  claims.UserID,
		TargetID: targetID,
		Subject:  req.Subject,
		Message:  req.Message,
		Metadata: adminMetadata(ctx),
	})
	if err != nil {
		response.Error(ctx, err)
		return
	}

	response.Success(ctx, http.StatusOK, "Đã gửi thông báo thành công", nil)
}

// ListRoles xử lý HTTP cho thao tác lấy danh sách Roles.
// @Summary Lấy danh sách Roles
// @Description Lấy danh sách tất cả các role trong hệ thống
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=[]RoleResponse}
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/roles [get]
func (h *AdminHandler) ListRoles(c *gin.Context) {
	roles, err := h.roles.List(c.Request.Context())
	if err != nil {
		response.Error(c, err)
		return
	}
	result := make([]RoleResponse, 0, len(roles))
	for _, role := range roles {
		result = append(result, adminRoleResponse(role))
	}
	response.Success(c, http.StatusOK, "Thành công", result)
}

// CreateRole xử lý HTTP cho thao tác tạo Role mới.
// @Summary Tạo Role mới
// @Description Tạo một role mới trong hệ thống
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateRoleRequest true "Thông tin Role"
// @Success 200 {object} response.Response{data=RoleResponse}
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/roles [post]
func (h *AdminHandler) CreateRole(c *gin.Context) {
	req, ok := validator.BindAndValidate[CreateRoleRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	role, err := h.roles.Create(c.Request.Context(), accessapp.CreateRoleCommand{
		ActorID:     claims.UserID,
		Name:        req.Name,
		Description: req.Description,
		Metadata:    adminMetadata(c),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Tạo role thành công", adminRoleResponse(*role))
}

// UpdateRole xử lý HTTP cho thao tác cập nhật Role.
// @Summary Cập nhật Role
// @Description Cập nhật thông tin của một role
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Role ID"
// @Param request body UpdateRoleRequest true "Thông tin cập nhật"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/roles/{id} [put]
func (h *AdminHandler) UpdateRole(c *gin.Context) {
	id, err := parseUintParam(c, "id", "ID role không hợp lệ")
	if err != nil {
		response.Error(c, err)
		return
	}
	req, ok := validator.BindAndValidate[UpdateRoleRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err = h.roles.Update(c.Request.Context(), accessapp.UpdateRoleCommand{
		ActorID:     claims.UserID,
		RoleID:      id,
		Name:        req.Name,
		Description: req.Description,
		Metadata:    adminMetadata(c),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Cập nhật role thành công", nil)
}

// DeleteRole xử lý HTTP cho thao tác xóa Role.
// @Summary Xóa Role
// @Description Xóa một role khỏi hệ thống (nếu không có user đang sử dụng)
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Role ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/roles/{id} [delete]
func (h *AdminHandler) DeleteRole(c *gin.Context) {
	id, err := parseUintParam(c, "id", "ID role không hợp lệ")
	if err != nil {
		response.Error(c, err)
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err = h.roles.Delete(c.Request.Context(), accessapp.DeleteRoleCommand{
		ActorID:  claims.UserID,
		RoleID:   id,
		Metadata: adminMetadata(c),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Xóa role thành công", nil)
}

// AssignPermissions xử lý HTTP cho thao tác gán Permissions cho Role.
// @Summary Gán Permissions cho Role
// @Description Phân quyền (permissions) cho một role
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Role ID"
// @Param request body AssignPermissionsRequest true "Danh sách permission IDs"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/roles/{id}/permissions [put]
func (h *AdminHandler) AssignPermissions(c *gin.Context) {
	id, err := parseUintParam(c, "id", "ID role không hợp lệ")
	if err != nil {
		response.Error(c, err)
		return
	}
	req, ok := validator.BindAndValidate[AssignPermissionsRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err = h.roles.ReplacePermissions(
		c.Request.Context(),
		accessapp.ReplacePermissionsCommand{
			ActorID:       claims.UserID,
			RoleID:        id,
			PermissionIDs: req.PermissionIDs,
			Metadata:      adminMetadata(c),
		},
	)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Gán quyền thành công", nil)
}

// AssignUserRole xử lý HTTP cho thao tác gán Role cho User.
// @Summary Gán Role cho User
// @Description Gán một role cho một user
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body AssignRoleRequest true "Role ID cần gán"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id}/roles [post]
func (h *AdminHandler) AssignUserRole(c *gin.Context) {
	userID, err := parseUintParam(c, "id", "ID người dùng không hợp lệ")
	if err != nil {
		response.Error(c, err)
		return
	}
	req, ok := validator.BindAndValidate[AssignRoleRequest](c)
	if !ok {
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err = h.roles.Assign(c.Request.Context(), accessapp.AssignRoleCommand{
		ActorID:  claims.UserID,
		TargetID: userID,
		RoleID:   req.RoleID,
		Metadata: adminMetadata(c),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Gán role cho user thành công", nil)
}

// RemoveUserRole xử lý HTTP cho thao tác gỡ Role khỏi User.
// @Summary Gỡ Role khỏi User
// @Description Gỡ một role đã được gán cho một user
// @Tags Admin - Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param roleId path int true "Role ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/users/{id}/roles/{roleId} [delete]
func (h *AdminHandler) RemoveUserRole(c *gin.Context) {
	userID, err := parseUintParam(c, "id", "ID người dùng không hợp lệ")
	if err != nil {
		response.Error(c, err)
		return
	}
	roleID, err := parseUintParam(c, "roleId", "ID role không hợp lệ")
	if err != nil {
		response.Error(c, err)
		return
	}
	claims := c.MustGet("tokenClaims").(*jwt.Claims)
	err = h.roles.Remove(c.Request.Context(), accessapp.RemoveRoleCommand{
		ActorID:  claims.UserID,
		TargetID: userID,
		RoleID:   roleID,
		Metadata: adminMetadata(c),
	})
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, http.StatusOK, "Gỡ role khỏi user thành công", nil)
}

// Export xử lý HTTP cho thao tác xuất Audit Logs.
// @Summary Xuất Audit Logs
// @Description Xuất nhật ký hệ thống (audit logs) ra file CSV (tối đa 10000 dòng)
// @Tags Admin - Audit Logs
// @Accept json
// @Produce text/csv
// @Security BearerAuth
// @Param user_id query int false "Lọc theo User ID"
// @Param action query string false "Lọc theo hành động (VD: login, create_user)"
// @Param start_date query string false "Từ ngày (YYYY-MM-DD)"
// @Param end_date query string false "Đến ngày (YYYY-MM-DD)"
// @Success 200 {file} file "File CSV"
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Router /admin/audit-logs/export [get]
func (h *AdminHandler) Export(c *gin.Context) {
	var req ExportAuditLogsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		response.ValidationError(c, err)
		return
	}

	csvData, err := h.audit.Export(c.Request.Context(), accessapp.AuditFilter{
		UserID:    req.UserID,
		Action:    req.Action,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
	})
	if err != nil {
		response.Error(c, err)
		return
	}

	filename := fmt.Sprintf("audit_logs_%s.csv", time.Now().Format("20060102_150405"))
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", csvData)
}

// adminUserResponse ánh xạ domain user sang public admin response.
func adminUserResponse(user accessapp.User) AdminUserListItem {
	return AdminUserListItem{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		FullName:      user.FullName,
		Phone:         user.Phone,
		Status:        user.Status,
		EmailVerified: user.EmailVerified,
		DateOfBirth:   user.DateOfBirth.Format("2006-01-02"),
		AvatarURL:     user.AvatarURL,
		Roles:         user.Roles,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
	}
}

// adminRoleResponse ánh xạ role và permission projection sang public response.
func adminRoleResponse(role accessapp.Role) RoleResponse {
	permissions := make([]PermissionResponse, 0, len(role.Permissions))
	for _, permission := range role.Permissions {
		permissions = append(permissions, PermissionResponse{
			ID:          permission.ID,
			Name:        permission.Name,
			Description: permission.Description,
			Resource:    permission.Resource,
			Action:      permission.Action,
		})
	}
	return RoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		Permissions: permissions,
	}
}

// adminMetadata đọc principal metadata dùng cho audit của admin mutation.
func adminMetadata(ctx *gin.Context) accessapp.Metadata {
	return accessapp.Metadata{
		IPAddress: ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	}
}
