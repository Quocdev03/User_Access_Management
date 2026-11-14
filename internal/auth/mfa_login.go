package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quocdev03/user-access-management/internal/redisstore"
	sessionapp "github.com/quocdev03/user-access-management/internal/session"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này hoàn tất đăng nhập sau khi MFA challenge được xác minh.

// MFALoginCommand chứa tham số xác minh thử thách MFA để hoàn tất đăng nhập.
type MFALoginCommand struct {
	Challenge string
	Code      string
	IPAddress string
	UserAgent string
}

// VerifyLogin xác minh đăng nhập trong auth use case.
func (m *MFA) VerifyLogin(
	ctx context.Context,
	command MFALoginCommand,
) (LoginResult, error) {
	claim, claimed, err := m.challenges.Claim(
		ctx,
		command.Challenge,
		m.policy.MaxAttempts,
	)
	if err != nil {
		return LoginResult{}, err
	}
	if !claimed {
		return LoginResult{}, apperror.ErrMFAInvalid
	}

	now := time.Now().UTC()
	factor, err := m.prepareEnabledFactor(
		ctx,
		claim.Challenge.UserID,
		command.Code,
		now,
	)
	if err != nil {
		if errors.Is(err, apperror.ErrMFAInvalid) ||
			errors.Is(err, apperror.ErrMFANotEnabled) {
			return LoginResult{}, m.rejectLoginClaim(ctx, command, claim)
		}
		return LoginResult{}, m.releaseLoginClaim(ctx, command, claim, err)
	}

	ipAddress, userAgent := sessionapp.NormalizeRequestMeta(
		command.IPAddress,
		command.UserAgent,
	)
	var (
		result        LoginResult
		kickedJTIs    []string
		businessError error
	)
	err = m.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := m.accounts.FindByIDForUpdate(
			txCtx,
			claim.Challenge.UserID,
		)
		if err != nil {
			return err
		}
		if account == nil {
			businessError = apperror.ErrMFAInvalid
			return nil
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		state.UnlockLoginIfExpired(now)
		if state.AuthVersion != claim.Challenge.AuthVersion {
			businessError = apperror.ErrMFAInvalid
			return nil
		}
		if err := state.AuthenticationError(now); err != nil {
			businessError = err
			return nil
		}
		if state.PasswordChangeRequired {
			businessError = apperror.ErrMustChangePassword
			return nil
		}

		lockedMFA, err := m.store.FindByUserIDForUpdate(txCtx, account.ID)
		if err != nil {
			return err
		}
		if !sameMFASnapshot(lockedMFA, factor.record) ||
			lockedMFA.EnabledAt == nil {
			businessError = apperror.ErrMFAInvalid
			return nil
		}
		if err := m.consumeFactor(txCtx, account.ID, factor, now); err != nil {
			if errors.Is(err, apperror.ErrMFAInvalid) {
				businessError = err
				return nil
			}
			return err
		}

		profile, err := m.profiles.FindByUserID(txCtx, account.ID)
		if err != nil {
			return err
		}
		if profile == nil {
			return fmt.Errorf(
				"account %d canonical profile is not backfilled",
				account.ID,
			)
		}
		roles, err := m.roles.NamesByUserID(txCtx, account.ID)
		if err != nil {
			return err
		}
		if roles == nil {
			roles = []string{}
		}
		accessToken, refreshToken, accessJTI, err := generateTokenPair(
			account.ID,
			state.AuthVersion,
			roles,
			m.policy.TokenPolicy,
		)
		if err != nil {
			return err
		}
		state.CompleteAuthentication()
		if err := m.accounts.UpdateLoginState(
			txCtx,
			account.ID,
			state,
			&now,
			now,
		); err != nil {
			return err
		}
		kickedJTIs, err = m.issuer.IssueInTx(txCtx, sessionapp.IssueInput{
			UserID:       account.ID,
			RefreshToken: refreshToken,
			AccessJTI:    accessJTI,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
		})
		if err != nil {
			return err
		}
		if err := m.auditMutation(
			txCtx,
			account.ID,
			"LOGIN_MFA",
			PasswordMetadata{
				IPAddress: ipAddress,
				UserAgent: userAgent,
			},
		); err != nil {
			return err
		}
		result = LoginResult{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			UserID:       account.ID,
			Username:     account.Username,
			Email:        account.Email,
			FullName:     profile.FullName,
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, m.releaseLoginClaim(ctx, command, claim, err)
	}
	if businessError != nil {
		if errors.Is(businessError, apperror.ErrMFAInvalid) {
			return LoginResult{}, m.rejectLoginClaim(ctx, command, claim)
		}
		if _, finishErr := m.challenges.Finish(
			ctx,
			command.Challenge,
			claim.ClaimToken,
			true,
			m.policy.MaxAttempts,
		); finishErr != nil {
			return LoginResult{}, fmt.Errorf(
				"consume invalidated MFA challenge: %w",
				finishErr,
			)
		}
		return LoginResult{}, businessError
	}
	if err := m.issuer.FinalizeEvictions(
		ctx,
		claim.Challenge.UserID,
		kickedJTIs,
	); err != nil {
		_, finishErr := m.challenges.Finish(
			ctx,
			command.Challenge,
			claim.ClaimToken,
			true,
			m.policy.MaxAttempts,
		)
		return LoginResult{}, errors.Join(err, finishErr)
	}
	if _, err := m.challenges.Finish(
		ctx,
		command.Challenge,
		claim.ClaimToken,
		true,
		m.policy.MaxAttempts,
	); err != nil {
		invalidateErr := m.txManager.RunInTx(ctx, func(txCtx context.Context) error {
			return m.authInvalidator.Invalidate(txCtx, claim.Challenge.UserID)
		})
		return LoginResult{}, errors.Join(
			fmt.Errorf("consume MFA challenge after session issue: %w", err),
			invalidateErr,
		)
	}
	return result, nil
}

// rejectLoginClaim tăng failed-attempt state hoặc consume challenge theo nguyên nhân xác minh.
func (m *MFA) rejectLoginClaim(
	ctx context.Context,
	command MFALoginCommand,
	claim redisstore.MFAChallengeClaim,
) error {
	if _, err := m.challenges.Finish(
		ctx,
		command.Challenge,
		claim.ClaimToken,
		false,
		m.policy.MaxAttempts,
	); err != nil {
		return err
	}
	return apperror.ErrMFAInvalid
}

// releaseLoginClaim trả challenge về trạng thái retryable khi login transaction thất bại.
func (m *MFA) releaseLoginClaim(
	ctx context.Context,
	command MFALoginCommand,
	claim redisstore.MFAChallengeClaim,
	cause error,
) error {
	if err := m.challenges.Release(
		ctx,
		command.Challenge,
		claim.ClaimToken,
	); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}
