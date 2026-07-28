package mysqlstore

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/database"
)

type Executor = database.DBExecutor
type TxManager = database.TxManager

func NewTxManager(db *sqlx.DB) *TxManager {
	return database.NewTxManager(db)
}

func executor(ctx context.Context, db *sqlx.DB) Executor {
	return database.GetDB(ctx, db)
}

func inTransaction(ctx context.Context) bool {
	return database.InTransaction(ctx)
}
