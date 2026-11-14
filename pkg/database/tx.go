package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// File này cung cấp transaction manager dùng chung cho application use case.

// DBExecutor định nghĩa giao diện trừu tượng hóa việc thực thi truy vấn SQL trên connection pool hoặc transaction.
type DBExecutor interface {
	// ExecContext thực thi command bằng connection hoặc transaction gắn với context.
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	// GetContext scan đúng một row vào destination.
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	// SelectContext scan toàn bộ result set vào destination.
	SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	// NamedExecContext thực thi command có named parameters.
	NamedExecContext(ctx context.Context, query string, arg interface{}) (sql.Result, error)
	// QueryRowContext trả row scanner và trì hoãn lỗi query đến bước Scan.
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// txKey là context key dùng để lưu trữ và truy xuất đối tượng sqlx.Tx từ context.
type txKey struct{}

// GetDB trả transaction gắn với context hoặc connection pool mặc định.
func GetDB(ctx context.Context, defaultDB *sqlx.DB) DBExecutor {
	if tx, ok := ctx.Value(txKey{}).(*sqlx.Tx); ok {
		return tx
	}
	return defaultDB
}

// InTransaction báo context hiện đã thuộc transaction do use case sở hữu.
func InTransaction(ctx context.Context) bool {
	_, ok := ctx.Value(txKey{}).(*sqlx.Tx)
	return ok
}

// TxManager quản lý vòng đời transaction của database và đảm bảo commit hoặc rollback an toàn.
type TxManager struct {
	db *sqlx.DB
}

// NewTxManager khởi tạo TxManager với các dependency được cung cấp.
func NewTxManager(db *sqlx.DB) *TxManager {
	return &TxManager{db: db}
}

// RunInTx thực thi callback trong một transaction và từ chối nested transaction để giữ một owner nguyên tử.
func (tm *TxManager) RunInTx(ctx context.Context, fn func(txCtx context.Context) error) error {
	if InTransaction(ctx) {
		return fmt.Errorf("nested MySQL transaction is not allowed")
	}

	tx, err := tm.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("không thể bắt đầu transaction: %w", err)
	}

	txCtx := context.WithValue(ctx, txKey{}, tx)

	if err := fn(txCtx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("lỗi transaction: %v, lỗi rollback: %v", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("lỗi khi commit transaction: %w", err)
	}

	return nil
}
