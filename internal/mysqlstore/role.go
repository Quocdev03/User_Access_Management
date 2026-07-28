package mysqlstore

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

type RoleStore struct {
	db *sqlx.DB
}

func NewRoleStore(db *sqlx.DB) *RoleStore {
	return &RoleStore{db: db}
}

func (s *RoleStore) AssignRoleByName(
	ctx context.Context,
	userID uint64,
	roleName string,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_at)
		SELECT ?, id, CURRENT_TIMESTAMP
		FROM roles
		WHERE name = ?
		LIMIT 1`,
		userID,
		roleName,
	)
	if err != nil {
		return fmt.Errorf("assign registration role: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read assigned registration-role rows: %w", err)
	}
	if rows != 1 {
		return apperror.ErrInternalServer
	}
	return nil
}

func (s *RoleStore) NamesByUserID(
	ctx context.Context,
	userID uint64,
) ([]string, error) {
	roles := []string{}
	if err := executor(ctx, s.db).SelectContext(ctx, &roles, `
		SELECT r.name
		FROM roles r
		INNER JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?
		ORDER BY r.id`,
		userID,
	); err != nil {
		return nil, fmt.Errorf("find account role names: %w", err)
	}
	return roles, nil
}
