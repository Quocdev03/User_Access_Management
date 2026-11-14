package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	accessapp "github.com/quocdev03/user-access-management/internal/access"
	"github.com/quocdev03/user-access-management/internal/accountstate"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này tạo tài khoản mới cùng verification challenge và outbox event.

// RegisterCommand chứa thông tin đăng ký tài khoản mới của người dùng.
type RegisterCommand struct {
	Username    string
	Email       string
	Password    string
	FullName    string
	Phone       string
	DateOfBirth string
}

// RegisteredAccount chứa thông tin tóm tắt của tài khoản vừa được khởi tạo thành công.
type RegisteredAccount struct {
	ID       uint64
	Username string
	Email    string
	Status   string
}

// Registration thực thi use case đăng ký tài khoản người dùng và phát hành challenge xác minh email.
type Registration struct {
	accounts     *mysqlstore.AccountStore
	profiles     *mysqlstore.ProfileStore
	roles        *mysqlstore.RoleStore
	verification *EmailVerification
	txManager    *mysqlstore.TxManager
}

// NewRegistration khởi tạo Registration với các dependency được cung cấp.
func NewRegistration(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	profiles *mysqlstore.ProfileStore,
	roles *mysqlstore.RoleStore,
	verification *EmailVerification,
) *Registration {
	return &Registration{
		accounts:     accounts,
		profiles:     profiles,
		roles:        roles,
		verification: verification,
		txManager:    mysqlstore.NewTxManager(db),
	}
}

// Register tạo account pending, canonical profile, challenge và outbox event trong transaction.
func (r *Registration) Register(
	ctx context.Context,
	command RegisterCommand,
) (RegisteredAccount, error) {
	if err := hash.ValidateNewPassword(command.Password); err != nil {
		return RegisteredAccount{}, apperror.ErrValidationError.WithMessage(err.Error())
	}
	dateOfBirth, err := time.Parse("2006-01-02", command.DateOfBirth)
	if err != nil {
		return RegisteredAccount{}, apperror.ErrInvalidDateFormat
	}
	passwordHash, err := hash.HashPassword(command.Password)
	if err != nil {
		return RegisteredAccount{}, fmt.Errorf("hash registration password: %w", err)
	}

	now := time.Now().UTC()
	account := &mysqlstore.RegistrationAccount{
		Username:     command.Username,
		Email:        command.Email,
		PasswordHash: passwordHash,
	}
	if err := r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		if err := r.accounts.CreateRegistration(txCtx, account, now); err != nil {
			return err
		}
		if err := r.profiles.Upsert(txCtx, &mysqlstore.Profile{
			UserID:      account.ID,
			FullName:    command.FullName,
			Phone:       command.Phone,
			DateOfBirth: dateOfBirth,
		}); err != nil {
			return err
		}
		if err := r.roles.AssignRoleByName(txCtx, account.ID, accessapp.RoleUser); err != nil {
			return err
		}
		return r.verification.issueInTx(txCtx, account.ID, command.Email, now)
	}); err != nil {
		return RegisteredAccount{}, err
	}

	status := accountstate.Registration().EffectiveStatus(now)
	return RegisteredAccount{
		ID:       account.ID,
		Username: command.Username,
		Email:    command.Email,
		Status:   string(status),
	}, nil
}
