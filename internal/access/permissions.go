package access

import (
	"context"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

const (
	RoleAdmin     = "admin"
	RoleModerator = "moderator"
	RoleUser      = "user"
)

type Authorizer struct {
	store *mysqlstore.AccessStore
}

func NewAuthorizer(store *mysqlstore.AccessStore) *Authorizer {
	return &Authorizer{store: store}
}

func (a *Authorizer) Allowed(
	ctx context.Context,
	userID uint64,
	permission string,
) (bool, error) {
	return a.store.HasPermission(ctx, userID, permission)
}

func isReservedRoleName(name string) bool {
	switch name {
	case RoleAdmin, RoleModerator, RoleUser:
		return true
	default:
		return false
	}
}
