package access

import (
	"context"
	"errors"
	"fmt"

	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này bảo vệ invariant không khóa hoặc hạ quyền quản trị viên cuối cùng.

// LastAdminGuard bảo vệ invariant không cho phép xóa, khóa hoặc tước quyền của quản trị viên hoạt động cuối cùng.
type LastAdminGuard struct {
	accounts *mysqlstore.AccountStore
	access   *mysqlstore.AccessStore
}

// LastAdminSnapshot nắm giữ snapshot trạng thái quyền và số lượng quản trị viên trong transaction để kiểm tra an toàn.
type LastAdminSnapshot struct {
	Target           *mysqlstore.Account
	AdminRole        *mysqlstore.AccessRole
	ActorIsAdmin     bool
	TargetIsAdmin    bool
	TargetRoleIDs    []uint64
	TargetWasUsable  bool
	UsableAdminCount int
}

// NewLastAdminGuard khởi tạo LastAdminGuard với các dependency được cung cấp.
func NewLastAdminGuard(
	accounts *mysqlstore.AccountStore,
	accessStore *mysqlstore.AccessStore,
) *LastAdminGuard {
	return &LastAdminGuard{accounts: accounts, access: accessStore}
}

// Lock khóa các admin liên quan theo thứ tự ổn định để kiểm tra last-admin invariant.
func (g *LastAdminGuard) Lock(
	ctx context.Context,
	actorID uint64,
	targetID uint64,
) (LastAdminSnapshot, error) {
	adminRole, err := g.access.LockAdminRole(ctx)
	if err != nil {
		return LastAdminSnapshot{}, err
	}
	if adminRole == nil {
		return LastAdminSnapshot{}, errors.New("system admin role is missing")
	}

	target, err := g.accounts.FindByIDForUpdate(ctx, targetID)
	if err != nil {
		return LastAdminSnapshot{}, err
	}
	if target == nil {
		return LastAdminSnapshot{}, apperror.ErrNotFound
	}
	targetState, err := target.State()
	if err != nil {
		return LastAdminSnapshot{}, err
	}

	targetRoleIDs, err := g.access.LockUserRoleIDs(ctx, targetID)
	if err != nil {
		return LastAdminSnapshot{}, err
	}
	adminUserIDs, err := g.access.LockUserIDsByRole(ctx, adminRole.ID)
	if err != nil {
		return LastAdminSnapshot{}, err
	}
	lockedAdmins, err := g.access.LockAccountStates(ctx, adminUserIDs)
	if err != nil {
		return LastAdminSnapshot{}, err
	}

	snapshot := LastAdminSnapshot{
		Target:        target,
		AdminRole:     adminRole,
		TargetRoleIDs: targetRoleIDs,
	}
	for _, roleID := range targetRoleIDs {
		if roleID == adminRole.ID {
			snapshot.TargetIsAdmin = true
			break
		}
	}
	for _, userID := range adminUserIDs {
		if userID == actorID {
			snapshot.ActorIsAdmin = true
		}
	}
	for _, account := range lockedAdmins {
		state, err := account.State()
		if err != nil {
			return LastAdminSnapshot{}, err
		}
		if usableAdmin(state) {
			snapshot.UsableAdminCount++
		}
	}
	snapshot.TargetWasUsable = snapshot.TargetIsAdmin && usableAdmin(targetState)
	return snapshot, nil
}

// RequireAdminForAdminTarget khóa tập admin liên quan khi mutation tác động một admin hiện tại.
func (s LastAdminSnapshot) RequireAdminForAdminTarget(message string) error {
	if s.TargetIsAdmin && !s.ActorIsAdmin {
		return apperror.ErrForbidden.WithMessage(message)
	}
	return nil
}

// EnsureTargetRemainsAvailable từ chối mutation làm hệ thống không còn admin sử dụng được.
func (s LastAdminSnapshot) EnsureTargetRemainsAvailable(willBeUsable bool) error {
	if s.TargetWasUsable && !willBeUsable && s.UsableAdminCount <= 1 {
		return apperror.ErrBadRequest.WithMessage(
			"Không thể vô hiệu hóa admin khả dụng cuối cùng",
		)
	}
	return nil
}

// usableAdmin kiểm tra account state và role sau mutation còn đủ điều kiện quản trị.
func usableAdmin(state accountstate.State) bool {
	return state.Lifecycle == accountstate.Active &&
		state.EmailVerified &&
		state.AdministrativeLockedAt == nil
}

// containsID kiểm tra tập ID đã khóa có chứa target hay không.
func containsID(ids []uint64, target uint64) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

// requireRole trả role đã khóa hoặc business error khi role không tồn tại.
func requireRole(role *mysqlstore.AccessRole, roleID uint64) error {
	if role == nil {
		return apperror.ErrNotFound.WithMessage(fmt.Sprintf("Role %d không tồn tại", roleID))
	}
	return nil
}
