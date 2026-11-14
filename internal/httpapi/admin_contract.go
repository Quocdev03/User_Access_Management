package httpapi

import "time"

// File này khai báo request và response DTO cho API quản trị.

// AdminListUsersRequest chứa các tham số lọc và phân trang khi quản trị viên tìm kiếm người dùng.
type AdminListUsersRequest struct {
	Username  string `form:"username"`
	Email     string `form:"email"`
	Status    string `form:"status"`
	Role      string `form:"role"`
	SortBy    string `form:"sort_by"`
	SortOrder string `form:"sort_order"`
	Page      int    `form:"page,default=1"`
	PerPage   int    `form:"per_page,default=20"`
}

// AdminUserListItem chứa thông tin tóm tắt của một người dùng trong danh sách trả về.
type AdminUserListItem struct {
	ID            uint64   `json:"id"`
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	FullName      string   `json:"full_name"`
	Phone         string   `json:"phone"`
	Status        string   `json:"status"`
	EmailVerified bool     `json:"email_verified"`
	DateOfBirth   string   `json:"date_of_birth"`
	AvatarURL     *string  `json:"avatar_url,omitempty"`
	Roles         []string `json:"roles"`
	CreatedAt     string   `json:"created_at"`
}

// AdminListUsersResponse đóng gói danh sách người dùng và metadata phân trang trả về cho client.
type AdminListUsersResponse struct {
	Users []AdminUserListItem `json:"users"`
	Meta  PaginationMeta      `json:"meta"`
}

// PaginationMeta chứa thông tin phân trang bao gồm trang hiện tại, số lượng mỗi trang và tổng số bản ghi.
type PaginationMeta struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// AdminUpdateUserRequest chứa các trường thông tin cập nhật tài khoản người dùng bởi quản trị viên.
type AdminUpdateUserRequest struct {
	FullName        *string `json:"full_name" binding:"omitempty,min=2,max=100,maxbytes=400"`
	Phone           *string `json:"phone" binding:"omitempty,min=9,max=20,maxbytes=20"`
	Email           *string `json:"email" binding:"omitempty,email,maxbytes=254"`
	EmailVerified   *bool   `json:"email_verified"`
	DateOfBirth     *string `json:"date_of_birth" binding:"omitempty,datetime=2006-01-02"`
	AvatarObjectKey *string `json:"avatar_object_key" binding:"omitempty,maxbytes=255"`
}

// AdminChangeStatusRequest chứa trạng thái mới cần áp dụng cho tài khoản người dùng.
type AdminChangeStatusRequest struct {
	Status string `json:"status" binding:"required,oneof=active inactive locked"`
}

// AdminNotifyRequest chứa tiêu đề và nội dung thông báo gửi tới người dùng.
type AdminNotifyRequest struct {
	Subject string `json:"subject" binding:"required,max=200,maxbytes=800,mailheader"`
	Message string `json:"message" binding:"required,max=5000,maxbytes=20000"`
}

// PermissionResponse biểu diễn chi tiết quyền hạn trả về trong phản hồi API.
type PermissionResponse struct {
	ID          uint64  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
}

// RoleResponse biểu diễn chi tiết vai trò cùng danh sách quyền hạn đi kèm.
type RoleResponse struct {
	ID          uint64               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	CreatedAt   time.Time            `json:"created_at"`
	Permissions []PermissionResponse `json:"permissions,omitempty"`
}

// CreateRoleRequest chứa thông tin tên và mô tả để tạo mới vai trò.
type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required,max=50,maxbytes=200"`
	Description string `json:"description" binding:"max=255,maxbytes=1020"`
}

// UpdateRoleRequest chứa thông tin tên và mô tả cập nhật cho vai trò hiện có.
type UpdateRoleRequest struct {
	Name        string `json:"name" binding:"required,max=50,maxbytes=200"`
	Description string `json:"description" binding:"max=255,maxbytes=1020"`
}

// AssignPermissionsRequest chứa danh sách định danh quyền hạn cần gán cho vai trò.
type AssignPermissionsRequest struct {
	PermissionIDs []uint64 `json:"permission_ids" binding:"required,max=500"`
}

// AssignRoleRequest chứa định danh vai trò cần gán cho người dùng.
type AssignRoleRequest struct {
	RoleID uint64 `json:"role_id" binding:"required"`
}

// ExportAuditLogsRequest chứa các tham số lọc phục vụ xuất dữ liệu nhật ký kiểm toán.
type ExportAuditLogsRequest struct {
	UserID    *uint64 `form:"user_id"`
	Action    *string `form:"action"`
	StartDate *string `form:"start_date" binding:"omitempty,datetime=2006-01-02"`
	EndDate   *string `form:"end_date"   binding:"omitempty,datetime=2006-01-02"`
}
