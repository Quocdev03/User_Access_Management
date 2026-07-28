package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	mailmessage "github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

const emailVerificationPurpose = "email_verification"

type EmailVerification struct {
	accounts    *mysqlstore.AccountStore
	challenges  *mysqlstore.VerificationChallengeStore
	outbox      *mysqlstore.OutboxStore
	invalidator *mysqlstore.AuthInvalidator
	txManager   *mysqlstore.TxManager
	codec       *mailmessage.SecretCodec
	pepper      string
	expiry      time.Duration
	maxAttempts int
}

func NewEmailVerification(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	challenges *mysqlstore.VerificationChallengeStore,
	outbox *mysqlstore.OutboxStore,
	invalidator *mysqlstore.AuthInvalidator,
	codec *mailmessage.SecretCodec,
	pepper string,
	expiry time.Duration,
	maxAttempts int,
) *EmailVerification {
	return &EmailVerification{
		accounts:    accounts,
		challenges:  challenges,
		outbox:      outbox,
		invalidator: invalidator,
		txManager:   mysqlstore.NewTxManager(db),
		codec:       codec,
		pepper:      pepper,
		expiry:      expiry,
		maxAttempts: maxAttempts,
	}
}

func (v *EmailVerification) Verify(ctx context.Context, email, otp string) error {
	now := time.Now().UTC()
	var businessError error
	err := v.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := v.accounts.FindByEmailForUpdate(txCtx, email)
		if err != nil {
			return err
		}
		if account == nil {
			dummy := hash.HashOTP("000000", v.pepper)
			input := hash.HashOTP(otp, v.pepper)
			_ = subtle.ConstantTimeCompare([]byte(dummy), []byte(input))
			businessError = apperror.ErrOTPInvalid
			return nil
		}

		state, err := account.State()
		if err != nil {
			return err
		}
		if state.EmailVerified {
			dummy := hash.HashOTP("000000", v.pepper)
			input := hash.HashOTP(otp, v.pepper)
			_ = subtle.ConstantTimeCompare([]byte(dummy), []byte(input))
			businessError = apperror.ErrOTPInvalid
			return nil
		}

		challenge, err := v.challenges.FindLatestActiveForUpdate(
			txCtx,
			account.ID,
			emailVerificationPurpose,
			now,
		)
		if err != nil {
			return err
		}
		if challenge == nil || challenge.Subject != account.Email {
			businessError = apperror.ErrOTPExpired
			return nil
		}
		if challenge.Attempts >= v.maxAttempts {
			businessError = apperror.ErrOTPMaxAttempts
			return nil
		}

		inputHash := hash.HashOTP(otp, v.pepper)
		if subtle.ConstantTimeCompare(
			[]byte(challenge.SecretHash),
			[]byte(inputHash),
		) != 1 {
			attempts, err := v.challenges.IncrementAttempts(txCtx, challenge.ID)
			if err != nil {
				return err
			}
			if attempts >= v.maxAttempts {
				businessError = apperror.ErrOTPMaxAttempts
			} else {
				businessError = apperror.ErrOTPInvalid
			}
			return nil
		}

		if err := v.outbox.CancelPendingVerification(
			txCtx,
			account.ID,
			emailVerificationPurpose,
			now,
		); err != nil {
			return err
		}
		if err := v.challenges.Consume(txCtx, challenge.ID, now); err != nil {
			return err
		}
		if err := state.VerifyEmail(); err != nil {
			businessError = err
			return nil
		}
		if err := v.accounts.UpdateState(txCtx, account.ID, state, now); err != nil {
			return err
		}
		return v.invalidator.DeleteSessions(txCtx, account.ID)
	})
	if err != nil {
		return err
	}
	return businessError
}

func (v *EmailVerification) Resend(ctx context.Context, email string) error {
	now := time.Now().UTC()
	var businessError error
	err := v.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := v.accounts.FindByEmailForUpdate(txCtx, email)
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
		if state.EmailVerified {
			return nil
		}
		return v.issueInTx(txCtx, account.ID, account.Email, now)
	})
	if err != nil {
		return err
	}
	return businessError
}

func (v *EmailVerification) issueInTx(
	ctx context.Context,
	userID uint64,
	email string,
	now time.Time,
) error {
	otp, err := generateOTP()
	if err != nil {
		return err
	}
	requestID := uuid.NewString()
	if err := v.outbox.CancelPendingVerification(
		ctx,
		userID,
		emailVerificationPurpose,
		now,
	); err != nil {
		return err
	}
	if err := v.challenges.InvalidateActive(
		ctx,
		userID,
		emailVerificationPurpose,
		now,
	); err != nil {
		return err
	}
	if err := v.challenges.Create(ctx, &mysqlstore.VerificationChallenge{
		RequestID:  requestID,
		UserID:     userID,
		Purpose:    emailVerificationPurpose,
		Subject:    email,
		SecretHash: hash.HashOTP(otp, v.pepper),
		ExpiresAt:  now.Add(v.expiry),
		CreatedAt:  now,
	}); err != nil {
		return err
	}
	payload, err := v.codec.Seal(mailmessage.SecretMessage{
		To:     email,
		Secret: otp,
	})
	if err != nil {
		return err
	}
	return v.outbox.Enqueue(ctx, &mysqlstore.OutboxEvent{
		EventType:      mailmessage.VerificationRequested,
		AggregateType:  "verification_challenge",
		AggregateID:    requestID,
		Payload:        payload,
		IdempotencyKey: "verification-email:" + requestID,
		MaxAttempts:    10,
		AvailableAt:    now,
	})
}

func generateOTP() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("generate verification OTP: %w", err)
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}
