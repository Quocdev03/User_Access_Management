package mysqlstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/database"
)

// File này gắn transaction vào context và thực thi callback nguyên tử.

// Executor là alias cho database.DBExecutor thực thi câu lệnh SQL.
type Executor = database.DBExecutor

// TxManager là alias cho database.TxManager điều phối transaction của MySQL.
type TxManager = database.TxManager

// NewTxManager khởi tạo TxManager với các dependency được cung cấp.
func NewTxManager(db *sqlx.DB) *TxManager {
	return database.NewTxManager(db)
}

// executor chọn transaction trong context hoặc fallback về connection pool.
func executor(ctx context.Context, db *sqlx.DB) Executor {
	return database.GetDB(ctx, db)
}

// inTransaction báo context hiện đã thuộc một transaction để chặn nested transaction.
func inTransaction(ctx context.Context) bool {
	return database.InTransaction(ctx)
}

// parsePositiveInsertID kiểm tra an toàn kết quả LastInsertId để tránh tràn số integer khi ép kiểu sang uint64 (G115).
func parsePositiveInsertID(res sql.Result, action string) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: read last insert id: %w", action, err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("%s: invalid non-positive insert id %d", action, id)
	}
	return uint64(id), nil
}
