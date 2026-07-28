package access

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

type BootstrapAccount struct {
	ID           uint64
	Username     string
	Email        string
	PasswordHash string
	FullName     string
	Phone        string
	DateOfBirth  time.Time
}

type Bootstrap struct {
	accounts  *mysqlstore.AccountStore
	profiles  *mysqlstore.ProfileStore
	access    *mysqlstore.AccessStore
	audits    *mysqlstore.AuditStore
	txManager *mysqlstore.TxManager
}

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
