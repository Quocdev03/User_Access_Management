package session

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

type Invalidator struct {
	txManager *mysqlstore.TxManager
	accounts  *mysqlstore.AuthInvalidator
}

func NewInvalidator(db *sqlx.DB) *Invalidator {
	return &Invalidator{
		txManager: mysqlstore.NewTxManager(db),
		accounts:  mysqlstore.NewAuthInvalidator(db),
	}
}

func (i *Invalidator) InvalidateAll(ctx context.Context, userID uint64) error {
	return i.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		return i.accounts.Invalidate(txCtx, userID)
	})
}
