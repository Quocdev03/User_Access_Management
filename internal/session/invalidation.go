// Package session phát hành, luân chuyển và thu hồi phiên đăng nhập.
package session

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

// File này định nghĩa contract vô hiệu hóa auth state trong MySQL transaction.

// Invalidator điều phối việc vô hiệu hóa toàn bộ phiên của người dùng bằng cách tăng auth_version trong transaction.
type Invalidator struct {
	txManager *mysqlstore.TxManager
	accounts  *mysqlstore.AuthInvalidator
}

// NewInvalidator khởi tạo Invalidator với các dependency được cung cấp.
func NewInvalidator(db *sqlx.DB) *Invalidator {
	return &Invalidator{
		txManager: mysqlstore.NewTxManager(db),
		accounts:  mysqlstore.NewAuthInvalidator(db),
	}
}

// InvalidateAll tăng auth_version và xóa toàn bộ session trong transaction hiện tại.
func (i *Invalidator) InvalidateAll(ctx context.Context, userID uint64) error {
	return i.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		return i.accounts.Invalidate(txCtx, userID)
	})
}
