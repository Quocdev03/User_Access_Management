package access

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này tạo use case access với các dependency dùng chung.

// BootstrapAccount chứa thông tin khởi tạo tài khoản quản trị viên trong quá trình bootstrap.
type BootstrapAccount struct {
	ID           uint64
	Username     string
	Email        string
	PasswordHash string
	FullName     string
	Phone        string
	DateOfBirth  time.Time
}

// Bootstrap thực thi use case khởi tạo quản trị viên đầu tiên và cấu hình vai trò mặc định.
type Bootstrap struct {
	accounts  *mysqlstore.AccountStore
	profiles  *mysqlstore.ProfileStore
	access    *mysqlstore.AccessStore
	audits    *mysqlstore.AuditStore
	txManager *mysqlstore.TxManager
}

// NewBootstrap khởi tạo Bootstrap với các dependency được cung cấp.
func NewBootstrap(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	profiles *mysqlstore.ProfileStore,
	accessStore *mysqlstore.AccessStore,
	audits *mysqlstore.AuditStore,
) *Bootstrap {
	return &Bootstrap{
		accounts:  accounts,
		profiles:  profiles,
		access:    accessStore,
		audits:    audits,
		txManager: mysqlstore.NewTxManager(db),
	}
}

// Create khởi tạo tài khoản quản trị đầu tiên khi hệ thống chưa có admin.
func (b *Bootstrap) Create(ctx context.Context, account *BootstrapAccount) error {
	now := time.Now().UTC()
	return b.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		adminRole, err := b.access.LockAdminRole(txCtx)
		if err != nil {
			return err
		}
		if adminRole == nil {
			return errors.New("admin role is missing; apply database migrations first")
		}
		adminUserIDs, err := b.access.LockUserIDsByRole(txCtx, adminRole.ID)
		if err != nil {
			return err
		}
		if len(adminUserIDs) > 0 {
			return apperror.ErrConflict.WithMessage("Hệ thống đã có quản trị viên, không thể chạy bootstrap admin")
		}
		registration := &mysqlstore.RegistrationAccount{
			Username:     account.Username,
			Email:        account.Email,
			PasswordHash: account.PasswordHash,
		}
		if err := b.accounts.CreateRegistration(txCtx, registration, now); err != nil {
			return err
		}
		account.ID = registration.ID
		accountState := accountstate.State{
			Lifecycle:     accountstate.Active,
			EmailVerified: true,
		}
		if err := b.accounts.UpdateState(
			txCtx,
			registration.ID,
			accountState,
			now,
		); err != nil {
			return err
		}
		if err := b.profiles.Upsert(txCtx, &mysqlstore.Profile{
			UserID:      registration.ID,
			FullName:    account.FullName,
			Phone:       account.Phone,
			DateOfBirth: account.DateOfBirth,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return err
		}
		if err := b.access.AssignRole(txCtx, registration.ID, adminRole.ID); err != nil {
			return err
		}
		accountID := registration.ID
		if err := writeAudit(
			txCtx,
			b.audits,
			accountID,
			"BOOTSTRAP_ADMIN",
			"users",
			strconv.FormatUint(accountID, 10),
			Metadata{},
		); err != nil {
			return err
		}
		return nil
	})
}
