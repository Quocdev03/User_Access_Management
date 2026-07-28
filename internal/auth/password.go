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

type PasswordPolicy struct {
	ResetExpiry       time.Duration
	MaxFailedAttempts int
	LockDuration      time.Duration
}

type PasswordMetadata struct {
	IPAddress string
	UserAgent string
}

type ResetPasswordCommand struct {
	Token       string
	NewPassword string
	Metadata    PasswordMetadata
}

type ChangePasswordCommand struct {
	CurrentPassword string
	NewPassword     string
	Metadata        PasswordMetadata
}

type ForceChangePasswordCommand struct {
	Email           string
	CurrentPassword string
	NewPassword     string
	Metadata        PasswordMetadata
}

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
		"PASSWORD_CHANGE",
		command.Metadata,
	)
}

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
		"PASSWORD_FORCE_CHANGE",
		command.Metadata,
	)
}

func (p *Password) changeWithCurrentCredential(
	ctx context.Context,
	accountSnapshot *mysqlstore.Account,
	currentPassword string,
	newPassword string,
	requirePasswordChange bool,
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

func activeResetToken(token *mysqlstore.PasswordResetToken, now time.Time) bool {
	return token != nil &&
		token.ConsumedAt == nil &&
		token.ExpiresAt.After(now)
}
