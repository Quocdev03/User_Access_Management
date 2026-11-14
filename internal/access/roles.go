package access

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này điều phối các use case tạo, sửa, xóa và gán role.

// Permission đại diện cho một quyền hạn cụ thể gắn liền với tài nguyên và hành động trong hệ thống.
type Permission struct {
	ID          uint64
	Name        string
	Description *string
	Resource    string
	Action      string
}

// Role đại diện cho một vai trò người dùng kèm theo danh sách các quyền hạn được gán.
type Role struct {
	ID          uint64
	Name        string
	Description string
	CreatedAt   time.Time
	Permissions []Permission
}

// CreateRoleCommand chứa thông tin tham số để tạo một vai trò mới trong hệ thống.
type CreateRoleCommand struct {
	ActorID     uint64
	Name        string
	Description string
	Metadata    Metadata
}

// UpdateRoleCommand chứa thông tin tham số để cập nhật thông tin của một vai trò hiện có.
type UpdateRoleCommand struct {
	ActorID     uint64
	RoleID      uint64
	Name        string
	Description string
	Metadata    Metadata
}

// DeleteRoleCommand chứa thông tin tham số để xóa một vai trò tùy chỉnh.
type DeleteRoleCommand struct {
	ActorID  uint64
	RoleID   uint64
	Metadata Metadata
}

// ReplacePermissionsCommand chứa danh sách quyền hạn mới thay thế cho quyền hạn hiện tại của vai trò.
type ReplacePermissionsCommand struct {
	ActorID       uint64
	RoleID        uint64
	PermissionIDs []uint64
	Metadata      Metadata
}

// AssignRoleCommand chứa thông tin để gán một vai trò cho người dùng mục tiêu.
type AssignRoleCommand struct {
	ActorID  uint64
	TargetID uint64
	RoleID   uint64
	Metadata Metadata
}

// RemoveRoleCommand chứa thông tin để gỡ bỏ một vai trò khỏi người dùng mục tiêu.
type RemoveRoleCommand struct {
	ActorID  uint64
	TargetID uint64
	RoleID   uint64
	Metadata Metadata
}

// Roles cung cấp các use case quản lý vai trò và phân quyền người dùng trong hệ thống.
type Roles struct {
	store       *mysqlstore.AccessStore
	audits      *mysqlstore.AuditStore
	invalidator *mysqlstore.AuthInvalidator
	txManager   *mysqlstore.TxManager
	lastAdmin   *LastAdminGuard
}

// NewRoles khởi tạo Roles với các dependency được cung cấp.
func NewRoles(
	db *sqlx.DB,
	store *mysqlstore.AccessStore,
	accounts *mysqlstore.AccountStore,
	audits *mysqlstore.AuditStore,
	invalidator *mysqlstore.AuthInvalidator,
) *Roles {
	return &Roles{
		store:       store,
		audits:      audits,
		invalidator: invalidator,
		txManager:   mysqlstore.NewTxManager(db),
		lastAdmin:   NewLastAdminGuard(accounts, store),
	}
}

// List trả role cùng permission projection cho API quản trị.
func (r *Roles) List(ctx context.Context) ([]Role, error) {
	rows, err := r.store.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	roleIDs := make([]uint64, 0, len(rows))
	for _, row := range rows {
		roleIDs = append(roleIDs, row.ID)
	}
	permissionRows, err := r.store.PermissionsByRoleIDs(ctx, roleIDs)
	if err != nil {
		return nil, err
	}
	roles := make([]Role, 0, len(rows))
	for _, row := range rows {
		permissions := make([]Permission, 0, len(permissionRows[row.ID]))
		for _, permission := range permissionRows[row.ID] {
			permissions = append(permissions, Permission{
				ID:          permission.ID,
				Name:        permission.Name,
				Description: permission.Description,
				Resource:    permission.Resource,
				Action:      permission.Action,
			})
		}
		roles = append(roles, Role{
			ID:          row.ID,
			Name:        row.Name,
			Description: row.Description,
			CreatedAt:   row.CreatedAt,
			Permissions: permissions,
		})
	}
	return roles, nil
}

// Create tạo role và gán permission trong cùng transaction.
func (r *Roles) Create(ctx context.Context, command CreateRoleCommand) (*Role, error) {
	if isReservedRoleName(command.Name) {
		return nil, apperror.ErrBadRequest.WithMessage(
			"Không thể tạo role với tên hệ thống",
		)
	}
	var created *mysqlstore.AccessRole
	err := r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		roleID, err := r.store.CreateRole(txCtx, command.Name, command.Description)
		if err != nil {
			return err
		}
		created, err = r.store.LockRoleByID(txCtx, roleID)
		if err != nil {
			return err
		}
		if created == nil {
			return fmt.Errorf("created role %d is missing", roleID)
		}
		return writeAudit(
			txCtx,
			r.audits,
			command.ActorID,
			"ADMIN_CREATE_ROLE",
			"roles",
			strconv.FormatUint(roleID, 10),
			command.Metadata,
		)
	})
	if err != nil {
		return nil, err
	}
	return &Role{
		ID:          created.ID,
		Name:        created.Name,
		Description: created.Description,
		CreatedAt:   created.CreatedAt,
	}, nil
}

// Update khóa role rồi thay đổi metadata và permission trong cùng transaction.
func (r *Roles) Update(ctx context.Context, command UpdateRoleCommand) error {
	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		adminRole, err := r.store.LockAdminRole(txCtx)
		if err != nil {
			return err
		}
		if adminRole == nil {
			return fmt.Errorf("system admin role is missing")
		}
		role := adminRole
		if command.RoleID != adminRole.ID {
			role, err = r.store.LockRoleByID(txCtx, command.RoleID)
			if err != nil {
				return err
			}
		}
		if err := requireRole(role, command.RoleID); err != nil {
			return err
		}
		if role.IsSystem && role.Name != command.Name {
			return apperror.ErrBadRequest.WithMessage(
				"Không thể đổi tên role hệ thống",
			)
		}
		if isReservedRoleName(command.Name) && role.Name != command.Name {
			return apperror.ErrBadRequest.WithMessage(
				"Không thể đổi tên role thành tên hệ thống",
			)
		}
		nameChanged := role.Name != command.Name
		var assignedUserIDs []uint64
		if nameChanged {
			assignedUserIDs, err = r.store.LockUserIDsByRole(txCtx, role.ID)
			if err != nil {
				return err
			}
			if _, err := r.store.LockAccountStates(txCtx, assignedUserIDs); err != nil {
				return err
			}
		}
		if err := r.store.UpdateRole(
			txCtx,
			role.ID,
			command.Name,
			command.Description,
		); err != nil {
			return err
		}
		if err := r.invalidateUsers(txCtx, assignedUserIDs); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			r.audits,
			command.ActorID,
			"ADMIN_UPDATE_ROLE",
			"roles",
			strconv.FormatUint(role.ID, 10),
			command.Metadata,
		)
	})
}

// Delete từ chối role hệ thống hoặc role còn được gán trước khi xóa.
func (r *Roles) Delete(ctx context.Context, command DeleteRoleCommand) error {
	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		adminRole, err := r.store.LockAdminRole(txCtx)
		if err != nil {
			return err
		}
		if adminRole == nil {
			return fmt.Errorf("system admin role is missing")
		}
		role := adminRole
		if command.RoleID != adminRole.ID {
			role, err = r.store.LockRoleByID(txCtx, command.RoleID)
			if err != nil {
				return err
			}
		}
		if err := requireRole(role, command.RoleID); err != nil {
			return err
		}
		if role.IsSystem {
			return apperror.ErrBadRequest.WithMessage("Không thể xóa role hệ thống")
		}
		assignedUserIDs, err := r.store.LockUserIDsByRole(txCtx, role.ID)
		if err != nil {
			return err
		}
		if len(assignedUserIDs) > 0 {
			return apperror.ErrBadRequest.WithMessage(
				"Không thể xóa role đang được gán cho người dùng",
			)
		}
		if err := r.store.DeleteRole(txCtx, role.ID); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			r.audits,
			command.ActorID,
			"ADMIN_DELETE_ROLE",
			"roles",
			strconv.FormatUint(role.ID, 10),
			command.Metadata,
		)
	})
}

// ReplacePermissions thay thế permission trong access use case.
func (r *Roles) ReplacePermissions(
	ctx context.Context,
	command ReplacePermissionsCommand,
) error {
	if command.PermissionIDs == nil {
		return apperror.ErrValidationError.WithMessage(
			"permission_ids là bắt buộc",
		)
	}
	if hasDuplicateIDs(command.PermissionIDs) {
		return apperror.ErrBadRequest.WithMessage("permission_ids bị trùng")
	}
	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		snapshot, err := r.lastAdmin.Lock(txCtx, command.ActorID, command.ActorID)
		if err != nil {
			return err
		}
		if !snapshot.ActorIsAdmin {
			return apperror.ErrForbidden.WithMessage(
				"Chỉ quản trị viên mới có quyền sửa permissions của role",
			)
		}
		role := snapshot.AdminRole
		if command.RoleID != snapshot.AdminRole.ID {
			role, err = r.store.LockRoleByID(txCtx, command.RoleID)
			if err != nil {
				return err
			}
		}
		if err := requireRole(role, command.RoleID); err != nil {
			return err
		}
		if role.IsSystem && role.Name == RoleAdmin {
			return apperror.ErrBadRequest.WithMessage(
				"Không thể sửa permissions của system admin role",
			)
		}
		count, err := r.store.CountPermissionsByIDs(txCtx, command.PermissionIDs)
		if err != nil {
			return err
		}
		if count != len(command.PermissionIDs) {
			return apperror.ErrBadRequest.WithMessage(
				"Một hoặc nhiều permission_id không tồn tại",
			)
		}
		assignedUserIDs, err := r.store.LockUserIDsByRole(txCtx, role.ID)
		if err != nil {
			return err
		}
		if _, err := r.store.LockAccountStates(txCtx, assignedUserIDs); err != nil {
			return err
		}
		if err := r.store.ReplaceRolePermissions(
			txCtx,
			role.ID,
			command.PermissionIDs,
		); err != nil {
			return err
		}
		if err := r.invalidateUsers(txCtx, assignedUserIDs); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			r.audits,
			command.ActorID,
			"ADMIN_REPLACE_ROLE_PERMISSIONS",
			"roles",
			strconv.FormatUint(role.ID, 10),
			command.Metadata,
		)
	})
}

// Assign gán role cho user và vô hiệu hóa auth state trong cùng transaction.
func (r *Roles) Assign(ctx context.Context, command AssignRoleCommand) error {
	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		snapshot, err := r.lastAdmin.Lock(txCtx, command.ActorID, command.TargetID)
		if err != nil {
			return err
		}
		role := snapshot.AdminRole
		if command.RoleID != snapshot.AdminRole.ID {
			role, err = r.store.LockRoleByID(txCtx, command.RoleID)
			if err != nil {
				return err
			}
		}
		if err := requireRole(role, command.RoleID); err != nil {
			return err
		}
		if snapshot.TargetIsAdmin && !snapshot.ActorIsAdmin {
			return apperror.ErrForbidden.WithMessage(
				"Không thể thay đổi role của tài khoản admin",
			)
		}
		if role.ID == snapshot.AdminRole.ID && !snapshot.ActorIsAdmin {
			return apperror.ErrForbidden.WithMessage(
				"Chỉ admin mới được gán role admin",
			)
		}
		if err := r.store.AssignRole(txCtx, command.TargetID, role.ID); err != nil {
			return err
		}
		if err := r.invalidator.Invalidate(txCtx, command.TargetID); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			r.audits,
			command.ActorID,
			"ADMIN_ASSIGN_ROLE",
			"users",
			strconv.FormatUint(command.TargetID, 10),
			command.Metadata,
		)
	})
}

// Remove gỡ role khỏi user nhưng bảo vệ last-admin invariant.
func (r *Roles) Remove(ctx context.Context, command RemoveRoleCommand) error {
	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		snapshot, err := r.lastAdmin.Lock(txCtx, command.ActorID, command.TargetID)
		if err != nil {
			return err
		}
		role := snapshot.AdminRole
		if command.RoleID != snapshot.AdminRole.ID {
			role, err = r.store.LockRoleByID(txCtx, command.RoleID)
			if err != nil {
				return err
			}
		}
		if err := requireRole(role, command.RoleID); err != nil {
			return err
		}
		if !containsID(snapshot.TargetRoleIDs, role.ID) {
			return apperror.ErrNotFound.WithMessage(
				"Role chưa được gán cho người dùng",
			)
		}
		if snapshot.TargetIsAdmin && !snapshot.ActorIsAdmin {
			return apperror.ErrForbidden.WithMessage(
				"Không thể thay đổi role của tài khoản admin",
			)
		}
		if role.ID == snapshot.AdminRole.ID {
			if !snapshot.ActorIsAdmin {
				return apperror.ErrForbidden.WithMessage(
					"Chỉ admin mới được gỡ role admin",
				)
			}
			if err := snapshot.EnsureTargetRemainsAvailable(false); err != nil {
				return err
			}
		}
		if err := r.store.RemoveRole(txCtx, command.TargetID, role.ID); err != nil {
			return err
		}
		if err := r.invalidator.Invalidate(txCtx, command.TargetID); err != nil {
			return err
		}
		return writeAudit(
			txCtx,
			r.audits,
			command.ActorID,
			"ADMIN_REMOVE_ROLE",
			"users",
			strconv.FormatUint(command.TargetID, 10),
			command.Metadata,
		)
	})
}

// invalidateUsers vô hiệu hóa người dùng trong access use case.
func (r *Roles) invalidateUsers(ctx context.Context, userIDs []uint64) error {
	for _, userID := range userIDs {
		if err := r.invalidator.Invalidate(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

// hasDuplicateIDs kiểm tra trùng lặp ID trong access use case.
func hasDuplicateIDs(ids []uint64) bool {
	seen := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			return true
		}
		seen[id] = struct{}{}
	}
	return false
}
