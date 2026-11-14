// Package mysqlstore triển khai các query và command MySQL cho domain use case.
package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này thực hiện query và command MySQL cho role, permission và admin user.

// AccessUser ánh xạ bản ghi người dùng cùng thông tin hồ sơ và trạng thái từ MySQL.
type AccessUser struct {
	ID              uint64    `db:"id"`
	Username        string    `db:"username"`
	Email           string    `db:"email"`
	FullName        string    `db:"full_name"`
	Phone           string    `db:"phone"`
	DateOfBirth     time.Time `db:"date_of_birth"`
	AvatarObjectKey *string   `db:"avatar_object_key"`
	Status          string    `db:"effective_status"`
	EmailVerified   bool      `db:"email_verified"`
	CreatedAt       time.Time `db:"created_at"`
}

// AccessUserFilter chứa các điều kiện lọc và phân trang khi truy vấn danh sách người dùng trong MySQL.
type AccessUserFilter struct {
	Username string
	Email    string
	Status   string
	Role     string
	SortBy   string
	SortDesc bool
	Limit    int
	Offset   int
	Now      time.Time
}

// AccessRole ánh xạ bản ghi vai trò trong bảng roles.
type AccessRole struct {
	ID          uint64    `db:"id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	IsSystem    bool      `db:"is_system"`
	CreatedAt   time.Time `db:"created_at"`
}

// AccessPermission ánh xạ bản ghi quyền hạn trong bảng permissions.
type AccessPermission struct {
	ID          uint64  `db:"id"`
	Name        string  `db:"name"`
	Description *string `db:"description"`
	Resource    string  `db:"resource"`
	Action      string  `db:"action"`
}

// LockedAccountState chứa snapshot trạng thái tài khoản đọc với FOR UPDATE để kiểm tra concurrency.
type LockedAccountState struct {
	ID                     uint64                 `db:"id"`
	Lifecycle              accountstate.Lifecycle `db:"lifecycle_state"`
	EmailVerified          bool                   `db:"email_verified"`
	AdministrativeLockedAt *time.Time             `db:"administrative_locked_at"`
	LoginLockedUntil       *time.Time             `db:"login_locked_until"`
	FailedLoginAttempts    int                    `db:"failed_login_attempts"`
	PasswordChangeRequired bool                   `db:"password_change_required"`
	AuthVersion            uint64                 `db:"auth_version"`
}

// State chuyển account row thành canonical state để domain policy xử lý.
func (a LockedAccountState) State() (accountstate.State, error) {
	state := accountstate.State{
		Lifecycle:              a.Lifecycle,
		EmailVerified:          a.EmailVerified,
		AdministrativeLockedAt: a.AdministrativeLockedAt,
		LoginLockedUntil:       a.LoginLockedUntil,
		FailedLoginAttempts:    a.FailedLoginAttempts,
		PasswordChangeRequired: a.PasswordChangeRequired,
		AuthVersion:            a.AuthVersion,
	}
	if err := state.Validate(); err != nil {
		return accountstate.State{}, fmt.Errorf("account %d: %w", a.ID, err)
	}
	return state, nil
}

// AccessStore quản lý các thao tác truy vấn và cập nhật dữ liệu quyền truy cập, vai trò và người dùng trong MySQL.
type AccessStore struct {
	db *sqlx.DB
}

// NewAccessStore khởi tạo AccessStore với các dependency được cung cấp.
func NewAccessStore(db *sqlx.DB) *AccessStore {
	return &AccessStore{db: db}
}

// ListUsers liệt kê người dùng tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) ListUsers(
	ctx context.Context,
	filter AccessUserFilter,
) ([]AccessUser, int64, error) {
	const statusExpression = `CASE
		WHEN u.administrative_locked_at IS NOT NULL
			OR (u.login_locked_until IS NOT NULL AND u.login_locked_until > ?)
			THEN 'locked'
		WHEN u.lifecycle_state <> 'active' THEN 'inactive'
		ELSE 'active'
	END`

	where := ` FROM users u
		INNER JOIN user_profiles p ON p.user_id = u.id
		WHERE u.lifecycle_state IS NOT NULL`
	args := []any{}
	if filter.Username != "" {
		where += ` AND u.username LIKE ?`
		args = append(args, "%"+filter.Username+"%")
	}
	if filter.Email != "" {
		where += ` AND u.email LIKE ?`
		args = append(args, "%"+filter.Email+"%")
	}
	if filter.Status != "" {
		where += ` AND ` + statusExpression + ` = ?`
		args = append(args, filter.Now.UTC(), filter.Status)
	}
	if filter.Role != "" {
		where += ` AND EXISTS (
			SELECT 1
			FROM user_roles ur
			INNER JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = u.id AND r.name = ?
		)`
		args = append(args, filter.Role)
	}

	var total int64
	if err := executor(ctx, s.db).GetContext(
		ctx,
		&total,
		`SELECT COUNT(*)`+where,
		args...,
	); err != nil {
		return nil, 0, fmt.Errorf("count access users: %w", err)
	}

	sortColumn := "u.created_at"
	switch filter.SortBy {
	case "username":
		sortColumn = "u.username"
	case "email":
		sortColumn = "u.email"
	case "created_at":
	}
	sortOrder := "ASC"
	if filter.SortDesc {
		sortOrder = "DESC"
	}
	query := `SELECT u.id, u.username, u.email, p.full_name, p.phone,
			p.date_of_birth, p.avatar_object_key, u.email_verified, u.created_at,
			` + statusExpression + ` AS effective_status` +
		where + ` ORDER BY ` + sortColumn + ` ` + sortOrder + ` LIMIT ? OFFSET ?`
	selectArgs := make([]any, 0, len(args)+3)
	selectArgs = append(selectArgs, filter.Now.UTC())
	selectArgs = append(selectArgs, args...)
	selectArgs = append(selectArgs, filter.Limit, filter.Offset)

	users := []AccessUser{}
	if err := executor(ctx, s.db).SelectContext(ctx, &users, query, selectArgs...); err != nil {
		return nil, 0, fmt.Errorf("list access users: %w", err)
	}
	return users, total, nil
}

// FindUser truy vấn người dùng tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) FindUser(ctx context.Context, userID uint64, now time.Time) (*AccessUser, error) {
	var user AccessUser
	err := executor(ctx, s.db).GetContext(ctx, &user, `
		SELECT u.id, u.username, u.email, p.full_name, p.phone,
			p.date_of_birth, p.avatar_object_key, u.email_verified, u.created_at,
			CASE
				WHEN u.administrative_locked_at IS NOT NULL
					OR (u.login_locked_until IS NOT NULL AND u.login_locked_until > ?)
					THEN 'locked'
				WHEN u.lifecycle_state <> 'active' THEN 'inactive'
				ELSE 'active'
			END AS effective_status
		FROM users u
		INNER JOIN user_profiles p ON p.user_id = u.id
		WHERE u.id = ? AND u.lifecycle_state IS NOT NULL
		LIMIT 1`,
		now.UTC(),
		userID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find access user: %w", err)
	}
	return &user, nil
}

// RoleNamesByUserID truy vấn tên role của một người dùng.
func (s *AccessStore) RoleNamesByUserID(ctx context.Context, userID uint64) ([]string, error) {
	roles := []string{}
	if err := executor(ctx, s.db).SelectContext(ctx, &roles, `
		SELECT r.name
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ?
		ORDER BY r.id`,
		userID,
	); err != nil {
		return nil, fmt.Errorf("find user role names: %w", err)
	}
	return roles, nil
}

// RoleNamesByUserIDs truy vấn tên role cho nhiều người dùng trong một lần đọc.
func (s *AccessStore) RoleNamesByUserIDs(
	ctx context.Context,
	userIDs []uint64,
) (map[uint64][]string, error) {
	result := make(map[uint64][]string, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}
	query, args, err := sqlx.In(`
		SELECT ur.user_id, r.name
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id IN (?)
		ORDER BY ur.user_id, r.id`,
		userIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("build user-role query: %w", err)
	}
	// userRole ánh xạ kết quả truy vấn liên kết giữa người dùng và vai trò.
	type userRole struct {
		UserID uint64 `db:"user_id"`
		Name   string `db:"name"`
	}
	rows := []userRole{}
	if err := executor(ctx, s.db).SelectContext(ctx, &rows, s.db.Rebind(query), args...); err != nil {
		return nil, fmt.Errorf("find role names by user ids: %w", err)
	}
	for _, row := range rows {
		result[row.UserID] = append(result[row.UserID], row.Name)
	}
	return result, nil
}

// HasPermission kiểm tra permission tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) HasPermission(
	ctx context.Context,
	userID uint64,
	permission string,
) (bool, error) {
	var allowed bool
	err := executor(ctx, s.db).GetContext(ctx, &allowed, `
		SELECT EXISTS (
			SELECT 1
			FROM user_roles ur
			INNER JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = ?
			  AND (
				(r.name = 'admin' AND r.is_system = TRUE)
				OR EXISTS (
					SELECT 1
					FROM role_permissions rp
					INNER JOIN permissions p ON p.id = rp.permission_id
					WHERE rp.role_id = r.id AND p.name = ?
				)
			  )
		)`,
		userID,
		permission,
	)
	if err != nil {
		return false, fmt.Errorf("check access permission: %w", err)
	}
	return allowed, nil
}

// LockAdminRole khóa quản trị role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) LockAdminRole(ctx context.Context) (*AccessRole, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("admin role lock requires a MySQL transaction")
	}
	return s.findRole(ctx, `name = 'admin' AND is_system = TRUE`, nil, true)
}

// LockRoleByID khóa role theo ID tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) LockRoleByID(ctx context.Context, roleID uint64) (*AccessRole, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("role lock requires a MySQL transaction")
	}
	return s.findRole(ctx, `id = ?`, []any{roleID}, true)
}

// FindRoleByID truy vấn role theo ID tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) FindRoleByID(ctx context.Context, roleID uint64) (*AccessRole, error) {
	return s.findRole(ctx, `id = ?`, []any{roleID}, false)
}

// FindRoleByName truy vấn role theo tên tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) FindRoleByName(ctx context.Context, name string) (*AccessRole, error) {
	return s.findRole(ctx, `name = ?`, []any{name}, false)
}

// findRole truy vấn role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) findRole(
	ctx context.Context,
	where string,
	args []any,
	forUpdate bool,
) (*AccessRole, error) {
	query := `SELECT id, name, COALESCE(description, '') AS description,
			COALESCE(is_system, FALSE) AS is_system, created_at
		FROM roles WHERE ` + where + ` LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var role AccessRole
	if err := executor(ctx, s.db).GetContext(ctx, &role, query, args...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find access role: %w", err)
	}
	return &role, nil
}

// ListRoles liệt kê role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) ListRoles(ctx context.Context) ([]AccessRole, error) {
	roles := []AccessRole{}
	if err := executor(ctx, s.db).SelectContext(ctx, &roles, `
		SELECT id, name, COALESCE(description, '') AS description,
			COALESCE(is_system, FALSE) AS is_system, created_at
		FROM roles
		ORDER BY id`); err != nil {
		return nil, fmt.Errorf("list access roles: %w", err)
	}
	return roles, nil
}

// PermissionsByRoleIDs truy vấn tập permission được gán cho các role.
func (s *AccessStore) PermissionsByRoleIDs(
	ctx context.Context,
	roleIDs []uint64,
) (map[uint64][]AccessPermission, error) {
	result := make(map[uint64][]AccessPermission, len(roleIDs))
	if len(roleIDs) == 0 {
		return result, nil
	}
	query, args, err := sqlx.In(`
		SELECT rp.role_id, p.id, p.name, p.description, p.resource, p.action
		FROM role_permissions rp
		INNER JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.role_id IN (?)
		ORDER BY rp.role_id, p.id`,
		roleIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("build role-permission query: %w", err)
	}
	// rolePermission ánh xạ kết quả truy vấn liên kết giữa vai trò và quyền hạn.
	type rolePermission struct {
		RoleID uint64 `db:"role_id"`
		AccessPermission
	}
	rows := []rolePermission{}
	if err := executor(ctx, s.db).SelectContext(ctx, &rows, s.db.Rebind(query), args...); err != nil {
		return nil, fmt.Errorf("find permissions by role ids: %w", err)
	}
	for _, row := range rows {
		result[row.RoleID] = append(result[row.RoleID], row.AccessPermission)
	}
	return result, nil
}

// CreateRole tạo role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) CreateRole(
	ctx context.Context,
	name string,
	description string,
) (uint64, error) {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO roles (name, description, is_system, created_at, updated_at)
		VALUES (?, ?, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		name,
		description,
	)
	if err != nil {
		return 0, mapAccessWriteError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read created role id: %w", err)
	}
	return uint64(id), nil
}

// UpdateRole cập nhật role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) UpdateRole(
	ctx context.Context,
	roleID uint64,
	name string,
	description string,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE roles
		SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		name,
		description,
		roleID,
	)
	if err != nil {
		return mapAccessWriteError(err)
	}
	return requireOneRow(result, "update access role")
}

// DeleteRole xóa role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) DeleteRole(ctx context.Context, roleID uint64) error {
	result, err := executor(ctx, s.db).ExecContext(
		ctx,
		`DELETE FROM roles WHERE id = ?`,
		roleID,
	)
	if err != nil {
		return fmt.Errorf("delete access role: %w", err)
	}
	return requireOneRow(result, "delete access role")
}

// LockUserRoleIDs khóa người dùng role ID tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) LockUserRoleIDs(ctx context.Context, userID uint64) ([]uint64, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("user-role lock requires a MySQL transaction")
	}
	roleIDs := []uint64{}
	if err := executor(ctx, s.db).SelectContext(ctx, &roleIDs, `
		SELECT role_id
		FROM user_roles
		WHERE user_id = ?
		ORDER BY role_id
		FOR UPDATE`,
		userID,
	); err != nil {
		return nil, fmt.Errorf("lock user-role assignments: %w", err)
	}
	return roleIDs, nil
}

// LockUserIDsByRole khóa người dùng ID theo role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) LockUserIDsByRole(ctx context.Context, roleID uint64) ([]uint64, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("role assignments lock requires a MySQL transaction")
	}
	userIDs := []uint64{}
	if err := executor(ctx, s.db).SelectContext(ctx, &userIDs, `
		SELECT user_id
		FROM user_roles
		WHERE role_id = ?
		ORDER BY user_id
		FOR UPDATE`,
		roleID,
	); err != nil {
		return nil, fmt.Errorf("lock role assignments: %w", err)
	}
	return userIDs, nil
}

// LockAccountStates khóa account state của các user bị tác động trước mutation RBAC.
func (s *AccessStore) LockAccountStates(
	ctx context.Context,
	userIDs []uint64,
) ([]LockedAccountState, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("account-state lock requires a MySQL transaction")
	}
	if len(userIDs) == 0 {
		return []LockedAccountState{}, nil
	}
	query, args, err := sqlx.In(`
		SELECT id, lifecycle_state, email_verified, administrative_locked_at,
			login_locked_until, failed_login_attempts,
			password_change_required, auth_version
		FROM users
		WHERE id IN (?)
		ORDER BY id
		FOR UPDATE`,
		userIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("build account-state lock query: %w", err)
	}
	accounts := []LockedAccountState{}
	if err := executor(ctx, s.db).SelectContext(
		ctx,
		&accounts,
		s.db.Rebind(query),
		args...,
	); err != nil {
		return nil, fmt.Errorf("lock account states: %w", err)
	}
	return accounts, nil
}

// CountRoleAssignments đếm số user đang giữ role để bảo vệ thao tác xóa.
func (s *AccessStore) CountRoleAssignments(ctx context.Context, roleID uint64) (int64, error) {
	var count int64
	if err := executor(ctx, s.db).GetContext(
		ctx,
		&count,
		`SELECT COUNT(*) FROM user_roles WHERE role_id = ?`,
		roleID,
	); err != nil {
		return 0, fmt.Errorf("count role assignments: %w", err)
	}
	return count, nil
}

// CountPermissionsByIDs xác nhận toàn bộ permission ID đầu vào tồn tại.
func (s *AccessStore) CountPermissionsByIDs(ctx context.Context, ids []uint64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	query, args, err := sqlx.In(`SELECT COUNT(*) FROM permissions WHERE id IN (?)`, ids)
	if err != nil {
		return 0, fmt.Errorf("build permission count query: %w", err)
	}
	var count int
	if err := executor(ctx, s.db).GetContext(
		ctx,
		&count,
		s.db.Rebind(query),
		args...,
	); err != nil {
		return 0, fmt.Errorf("count permissions: %w", err)
	}
	return count, nil
}

// ReplaceRolePermissions thay thế role permission tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) ReplaceRolePermissions(
	ctx context.Context,
	roleID uint64,
	permissionIDs []uint64,
) error {
	db := executor(ctx, s.db)
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM role_permissions WHERE role_id = ?`,
		roleID,
	); err != nil {
		return fmt.Errorf("clear role permissions: %w", err)
	}
	if len(permissionIDs) == 0 {
		return nil
	}
	var query strings.Builder
	query.WriteString(`INSERT INTO role_permissions (role_id, permission_id, assigned_at) VALUES `)
	args := make([]any, 0, len(permissionIDs)*2)
	for index, permissionID := range permissionIDs {
		if index > 0 {
			query.WriteString(", ")
		}
		query.WriteString("(?, ?, CURRENT_TIMESTAMP)")
		args = append(args, roleID, permissionID)
	}
	if _, err := db.ExecContext(ctx, query.String(), args...); err != nil {
		return mapAccessWriteError(err)
	}
	return nil
}

// AssignRole gán role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) AssignRole(ctx context.Context, userID, roleID uint64) error {
	_, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`,
		userID,
		roleID,
	)
	if err != nil {
		return mapAccessWriteError(err)
	}
	return nil
}

// RemoveRole gỡ role tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *AccessStore) RemoveRole(ctx context.Context, userID, roleID uint64) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		DELETE FROM user_roles
		WHERE user_id = ? AND role_id = ?`,
		userID,
		roleID,
	)
	if err != nil {
		return fmt.Errorf("remove user role: %w", err)
	}
	return requireOneRow(result, "remove user role")
}

// mapAccessWriteError chuyển lỗi constraint đã biết thành business error ổn định.
func mapAccessWriteError(err error) error {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return apperror.ErrConflict
	}
	return fmt.Errorf("write access data: %w", err)
}
