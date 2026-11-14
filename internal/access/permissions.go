package access

import (
	"context"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

// File này cung cấp capability kiểm tra permission cho authorization boundary.

const (
	RoleAdmin     = "admin"
	RoleModerator = "moderator"
	RoleUser      = "user"
)

// Authorizer kiểm tra quyền hạn (permissions) của người dùng dựa trên các role được gán.
type Authorizer struct {
	store *mysqlstore.AccessStore
}

// NewAuthorizer khởi tạo Authorizer với các dependency được cung cấp.
func NewAuthorizer(store *mysqlstore.AccessStore) *Authorizer {
	return &Authorizer{store: store}
}

// Allowed kiểm tra principal có permission yêu cầu hoặc quyền wildcard tương ứng.
func (a *Authorizer) Allowed(
	ctx context.Context,
	userID uint64,
	permission string,
) (bool, error) {
	return a.store.HasPermission(ctx, userID, permission)
}

// isReservedRoleName nhận diện role hệ thống không được sửa hoặc xóa.
func isReservedRoleName(name string) bool {
	switch name {
	case RoleAdmin, RoleModerator, RoleUser:
		return true
	default:
		return false
	}
}
