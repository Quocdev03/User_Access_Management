package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này điều phối quên, đặt lại và thay đổi mật khẩu.

// PasswordPolicy quy định thời hạn hiệu lực của reset token và chính sách khóa tài khoản.
type PasswordPolicy struct {
	ResetExpiry       time.Duration
	MaxFailedAttempts int
	LockDuration      time.Duration
}

// PasswordMetadata lưu trữ địa chỉ IP và User-Agent khi thực hiện thao tác liên quan đến mật khẩu.
type PasswordMetadata struct {
	IPAddress string
	UserAgent string
}

// ResetPasswordCommand chứa thông tin token và mật khẩu mới để đặt lại mật khẩu.
type ResetPasswordCommand struct {
	Token       string
	NewPassword string
	Metadata    PasswordMetadata
}

// ChangePasswordCommand chứa mật khẩu hiện tại và mật khẩu mới khi người dùng chủ động đổi mật khẩu.
type ChangePasswordCommand struct {
	CurrentPassword string
	NewPassword     string
	Metadata        PasswordMetadata
}

// ForceChangePasswordCommand chứa thông tin để người dùng đổi mật khẩu bắt buộc tại lần đăng nhập đầu tiên.
type ForceChangePasswordCommand struct {
	Email           string
	CurrentPassword string
	NewPassword     string
	Metadata        PasswordMetadata
}

// Password điều phối các use case quên mật khẩu, đặt lại mật khẩu và đổi mật khẩu an toàn.
type Password struct {
	accounts     *mysqlstore.AccountStore
	resets       *mysqlstore.PasswordResetStore
	outbox       *mysqlstore.OutboxStore
	audits       *mysqlstore.AuditStore
	invalidator  *mysqlstore.AuthInvalidator
	txManager    *mysqlstore.TxManager
	codec        *mail.SecretCodec
	emailChanges *mysqlstore.EmailChangeStore
	policy       PasswordPolicy
}

// NewPassword khởi tạo Password với các dependency được cung cấp.
func NewPassword(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	resets *mysqlstore.PasswordResetStore,
	outbox *mysqlstore.OutboxStore,
	audits *mysqlstore.AuditStore,
	invalidator *mysqlstore.AuthInvalidator,
	codec *mail.SecretCodec,
	emailChanges *mysqlstore.EmailChangeStore,
	policy PasswordPolicy,
) *Password {
	if policy.ResetExpiry <= 0 {
		policy.ResetExpiry = time.Hour
	}
	return &Password{
		accounts:     accounts,
		resets:       resets,
		outbox:       outbox,
		audits:       audits,
		invalidator:  invalidator,
		txManager:    mysqlstore.NewTxManager(db),
		codec:        codec,
		emailChanges: emailChanges,
		policy:       policy,
	}
}

// Forgot tạo reset challenge và outbox event nhưng không làm lộ email có tồn tại.
func (p *Password) Forgot(ctx context.Context, email string) error {
	token, err := hash.GenerateResetToken()
	if err != nil {
		return fmt.Errorf("generate password reset token: %w", err)
	}
	tokenHash := hash.SHA256(token)
	now := time.Now().UTC()

	return p.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := p.accounts.FindByEmailForUpdate(txCtx, email)
		if err != nil {
			return err
		}
		if account == nil {
			return nil
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		state.UnlockLoginIfExpired(now)
		if !state.EmailVerified || state.AuthenticationError(now) != nil {
			return nil
		}
		if err := p.outbox.CancelPendingPasswordReset(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.resets.InvalidateActiveByUser(txCtx, account.ID, now); err != nil {
			return err
		}
		tokenID, err := p.resets.Create(
			txCtx,
			account.ID,
			tokenHash,
			state.AuthVersion,
			now.Add(p.policy.ResetExpiry),
		)
		if err != nil {
			return err
		}
		payload, err := p.codec.Seal(mail.SecretMessage{
			To:     account.Email,
			Secret: token,
		})
		if err != nil {
			return err
		}
		return p.outbox.Enqueue(txCtx, &mysqlstore.OutboxEvent{
			EventType:      mail.PasswordResetRequested,
			AggregateType:  "password_reset_token",
			AggregateID:    strconv.FormatUint(tokenID, 10),
			Payload:        payload,
			IdempotencyKey: "password-reset:" + strconv.FormatUint(tokenID, 10),
			MaxAttempts:    10,
			AvailableAt:    now,
		})
	})
}

// Reset consume reset token, đổi credential và vô hiệu hóa session trong transaction.
func (p *Password) Reset(ctx context.Context, command ResetPasswordCommand) error {
	if err := hash.ValidateNewPassword(command.NewPassword); err != nil {
		return apperror.ErrValidationError.WithMessage(err.Error())
	}
	now := time.Now().UTC()
	tokenHash := hash.SHA256(command.Token)
	tokenSnapshot, err := p.resets.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		return err
	}
	if !activeResetToken(tokenSnapshot, now) {
		return apperror.ErrResetTokenInvalid
	}
	accountSnapshot, err := p.accounts.FindByID(ctx, tokenSnapshot.UserID)
	if err != nil {
		return err
	}
	if accountSnapshot == nil ||
		accountSnapshot.AuthVersion != tokenSnapshot.AuthVersion {
		return apperror.ErrResetTokenInvalid
	}
	snapshotState, err := accountSnapshot.State()
	if err != nil {
		return err
	}
	snapshotState.UnlockLoginIfExpired(now)
	if !snapshotState.EmailVerified {
		return apperror.ErrAccountInactive
	}
	if err := snapshotState.AuthenticationError(now); err != nil {
		return err
	}
	if hash.CheckPassword(command.NewPassword, accountSnapshot.PasswordHash) {
		return apperror.ErrSamePassword
	}
	passwordHash, err := hash.HashPassword(command.NewPassword)
	if err != nil {
		return fmt.Errorf("hash reset password: %w", err)
	}

	var businessError error
	err = p.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := p.accounts.FindByIDForUpdate(txCtx, tokenSnapshot.UserID)
		if err != nil {
			return err
		}
		if account == nil ||
			account.AuthVersion != tokenSnapshot.AuthVersion ||
			subtle.ConstantTimeCompare(
				[]byte(account.PasswordHash),
				[]byte(accountSnapshot.PasswordHash),
			) != 1 {
			businessError = apperror.ErrResetTokenInvalid
			return nil
		}
		token, err := p.resets.FindByIDForUpdate(txCtx, tokenSnapshot.ID)
		if err != nil {
			return err
		}
		if !activeResetToken(token, now) {
			businessError = apperror.ErrResetTokenUsed
			return nil
		}
		if token.UserID != account.ID ||
			token.AuthVersion != account.AuthVersion ||
			subtle.ConstantTimeCompare([]byte(token.TokenHash), []byte(tokenHash)) != 1 {
			businessError = apperror.ErrResetTokenInvalid
			return nil
		}

		state, err := account.State()
		if err != nil {
			return err
		}
		state.UnlockLoginIfExpired(now)
		if !state.EmailVerified {
			businessError = apperror.ErrAccountInactive
			return nil
		}
		if err := state.AuthenticationError(now); err != nil {
			businessError = err
			return nil
		}
		state.CompleteCredentialChange()
		if err := p.outbox.CancelPendingPasswordReset(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.resets.Consume(txCtx, token.ID, now); err != nil {
			businessError = apperror.ErrResetTokenUsed
			return nil
		}
		if err := p.resets.InvalidateActiveByUser(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.outbox.CancelPendingEmailChange(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.emailChanges.CancelActiveByUser(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.accounts.UpdateCredential(
			txCtx,
			account.ID,
			passwordHash,
			state,
			now,
		); err != nil {
			return err
		}
		if err := p.invalidator.DeleteSessions(txCtx, account.ID); err != nil {
			return err
		}
		return p.auditCredentialChange(
			txCtx,
			account.ID,
			"PASSWORD_RESET",
			command.Metadata,
		)
	})
	if err != nil {
		return err
	}
	if businessError != nil {
		return businessError
	}
	return nil
}

// Change xác minh password hiện tại rồi đổi credential và vô hiệu hóa session.
func (p *Password) Change(
	ctx context.Context,
	userID uint64,
	command ChangePasswordCommand,
) error {
	if err := hash.ValidateNewPassword(command.NewPassword); err != nil {
		return apperror.ErrValidationError.WithMessage(err.Error())
	}
	account, err := p.accounts.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if account == nil {
		return apperror.ErrNotFound
	}
	return p.changeWithCurrentCredential(
		ctx,
		account,
		command.CurrentPassword,
		command.NewPassword,
		false,
		true,
		"PASSWORD_CHANGE",
		command.Metadata,
	)
}

// ForceChange đổi credential của tài khoản bị bắt buộc, tăng auth_version và xóa session.
func (p *Password) ForceChange(
	ctx context.Context,
	command ForceChangePasswordCommand,
) error {
	if err := hash.ValidateNewPassword(command.NewPassword); err != nil {
		return apperror.ErrValidationError.WithMessage(err.Error())
	}
	account, err := p.accounts.FindByEmail(ctx, command.Email)
	if err != nil {
		return err
	}
	if account == nil {
		_ = hash.CheckPassword("dummy-password", hash.DummyPasswordHash)
		return apperror.ErrInvalidCredentials
	}
	return p.changeWithCurrentCredential(
		ctx,
		account,
		command.CurrentPassword,
		command.NewPassword,
		true,
		false,
		"PASSWORD_FORCE_CHANGE",
		command.Metadata,
	)
}

// changeWithCurrentCredential xác minh password hiện tại rồi đổi credential trong locked transaction.
func (p *Password) changeWithCurrentCredential(
	ctx context.Context,
	accountSnapshot *mysqlstore.Account,
	currentPassword string,
	newPassword string,
	requirePasswordChange bool,
	trackFailedAttempts bool,
	auditAction string,
	metadata PasswordMetadata,
) error {
	now := time.Now().UTC()
	snapshotState, err := accountSnapshot.State()
	if err != nil {
		return err
	}
	snapshotState.UnlockLoginIfExpired(now)
	if currentPassword == newPassword {
		return apperror.ErrSamePassword
	}
	passwordMatches := hash.CheckPassword(currentPassword, accountSnapshot.PasswordHash)
	if !passwordMatches {
		if !trackFailedAttempts {
			return apperror.ErrInvalidCredentials
		}
		if err := snapshotState.AuthenticationError(now); err != nil {
			return apperror.ErrInvalidCredentials
		}
	} else {
		if err := snapshotState.AuthenticationError(now); err != nil {
			return err
		}
		if requirePasswordChange && !snapshotState.PasswordChangeRequired {
			return apperror.ErrBadRequest.WithMessage(
				"Tài khoản không nằm trong diện bắt buộc đổi mật khẩu",
			)
		}
	}
	var passwordHash string
	if passwordMatches {
		passwordHash, err = hash.HashPassword(newPassword)
		if err != nil {
			return fmt.Errorf("hash changed password: %w", err)
		}
	}

	var businessError error
	err = p.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := p.accounts.FindByIDForUpdate(txCtx, accountSnapshot.ID)
		if err != nil {
			return err
		}
		if account == nil {
			businessError = apperror.ErrNotFound
			return nil
		}
		if subtle.ConstantTimeCompare(
			[]byte(account.PasswordHash),
			[]byte(accountSnapshot.PasswordHash),
		) != 1 {
			businessError = apperror.ErrInvalidCredentials
			return nil
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		state.UnlockLoginIfExpired(now)
		if !passwordMatches {
			if !trackFailedAttempts {
				businessError = apperror.ErrInvalidCredentials
				return nil
			}
			if err := state.AuthenticationError(now); err != nil {
				businessError = apperror.ErrInvalidCredentials
				return nil
			}
			state.RecordFailedLogin(
				now,
				p.policy.MaxFailedAttempts,
				p.policy.LockDuration,
			)
			if err := p.accounts.UpdateState(txCtx, account.ID, state, now); err != nil {
				return err
			}
			if state.LoginLockedUntil != nil {
				businessError = apperror.ErrAccountLocked.WithMessage(fmt.Sprintf(
					"Tài khoản bị khóa %d phút do nhập sai mật khẩu %d lần",
					int(p.policy.LockDuration.Minutes()),
					p.policy.MaxFailedAttempts,
				))
			} else {
				businessError = apperror.ErrInvalidCredentials
			}
			return nil
		}
		if err := state.AuthenticationError(now); err != nil {
			businessError = err
			return nil
		}
		if requirePasswordChange && !state.PasswordChangeRequired {
			businessError = apperror.ErrBadRequest.WithMessage(
				"Tài khoản không nằm trong diện bắt buộc đổi mật khẩu",
			)
			return nil
		}

		state.CompleteCredentialChange()
		if err := p.outbox.CancelPendingPasswordReset(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.resets.InvalidateActiveByUser(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.outbox.CancelPendingEmailChange(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.emailChanges.CancelActiveByUser(txCtx, account.ID, now); err != nil {
			return err
		}
		if err := p.accounts.UpdateCredential(
			txCtx,
			account.ID,
			passwordHash,
			state,
			now,
		); err != nil {
			return err
		}
		if err := p.invalidator.DeleteSessions(txCtx, account.ID); err != nil {
			return err
		}
		if err := p.auditCredentialChange(txCtx, account.ID, auditAction, metadata); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if businessError != nil {
		return businessError
	}
	return nil
}

// auditCredentialChange ghi password mutation theo best effort và cảnh báo khi store thất bại.
func (p *Password) auditCredentialChange(
	ctx context.Context,
	userID uint64,
	action string,
	metadata PasswordMetadata,
) error {
	resource := "account"
	resourceID := strconv.FormatUint(userID, 10)
	ipAddress := metadata.IPAddress
	userAgent := metadata.UserAgent
	return p.audits.Create(ctx, &mysqlstore.AuditLog{
		UserID:     &userID,
		Action:     action,
		Resource:   &resource,
		ResourceID: &resourceID,
		IPAddress:  &ipAddress,
		UserAgent:  &userAgent,
		Status:     "success",
	})
}

// activeResetToken tạo business error cho reset token đã hết hạn hoặc bị consume.
func activeResetToken(token *mysqlstore.PasswordResetToken, now time.Time) bool {
	return token != nil &&
		token.ConsumedAt == nil &&
		token.ExpiresAt.After(now)
}
