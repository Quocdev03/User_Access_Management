package account

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"github.com/quocdev03/user-access-management/pkg/hash"
)

// File này điều phối yêu cầu và xác minh đổi email bằng durable outbox.

const (
	emailChangeOldPurpose = "change_email_old"
	emailChangeNewPurpose = "change_email_new"
)

// EmailPolicy định nghĩa chính sách thời gian hết hạn và số lần thử tối đa khi xác thực OTP đổi email.
type EmailPolicy struct {
	Expiry      time.Duration
	MaxAttempts int
}

// EmailMetadata chứa thông tin địa chỉ IP và User-Agent khi thực hiện yêu cầu đổi email.
type EmailMetadata struct {
	IPAddress string
	UserAgent string
}

// RequestEmailChangeCommand chứa thông tin tham số để khởi tạo yêu cầu thay đổi email của người dùng.
type RequestEmailChangeCommand struct {
	CurrentPassword string
	NewEmail        string
	Metadata        EmailMetadata
}

// VerifyEmailChangeCommand chứa các mã OTP xác minh gửi đến cả email cũ và email mới để hoàn tất đổi email.
type VerifyEmailChangeCommand struct {
	OldOTP   string
	NewOTP   string
	Metadata EmailMetadata
}

// Email quản lý toàn bộ quy trình yêu cầu, xác minh OTP kép và cập nhật email người dùng.
type Email struct {
	accounts    *mysqlstore.AccountStore
	requests    *mysqlstore.EmailChangeStore
	challenges  *mysqlstore.VerificationChallengeStore
	resets      *mysqlstore.PasswordResetStore
	outbox      *mysqlstore.OutboxStore
	audits      *mysqlstore.AuditStore
	invalidator *mysqlstore.AuthInvalidator
	txManager   *mysqlstore.TxManager
	codec       *mail.SecretCodec
	pepper      string
	policy      EmailPolicy
}

// NewEmail khởi tạo Email với các dependency được cung cấp.
func NewEmail(
	db *sqlx.DB,
	accounts *mysqlstore.AccountStore,
	requests *mysqlstore.EmailChangeStore,
	challenges *mysqlstore.VerificationChallengeStore,
	resets *mysqlstore.PasswordResetStore,
	outbox *mysqlstore.OutboxStore,
	audits *mysqlstore.AuditStore,
	invalidator *mysqlstore.AuthInvalidator,
	codec *mail.SecretCodec,
	pepper string,
	policy EmailPolicy,
) *Email {
	if policy.Expiry <= 0 {
		policy.Expiry = 15 * time.Minute
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = 5
	}
	return &Email{
		accounts:    accounts,
		requests:    requests,
		challenges:  challenges,
		resets:      resets,
		outbox:      outbox,
		audits:      audits,
		invalidator: invalidator,
		txManager:   mysqlstore.NewTxManager(db),
		codec:       codec,
		pepper:      pepper,
		policy:      policy,
	}
}

// Request tạo email-change challenge và durable verification email trong transaction.
func (e *Email) Request(
	ctx context.Context,
	userID uint64,
	command RequestEmailChangeCommand,
) error {
	accountSnapshot, err := e.accounts.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if accountSnapshot == nil {
		return apperror.ErrNotFound
	}
	if !hash.CheckPassword(command.CurrentPassword, accountSnapshot.PasswordHash) {
		return apperror.ErrInvalidCredentials
	}
	existing, err := e.accounts.FindByEmail(ctx, command.NewEmail)
	if err != nil {
		return err
	}
	if existing != nil {
		return apperror.ErrConflict
	}
	oldOTP, newOTP, err := generateEmailChangeOTPs()
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	return e.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := e.accounts.FindByIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if account == nil {
			return apperror.ErrNotFound
		}
		if subtle.ConstantTimeCompare(
			[]byte(account.PasswordHash),
			[]byte(accountSnapshot.PasswordHash),
		) != 1 {
			return apperror.ErrInvalidCredentials
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		if err := state.AuthenticationError(now); err != nil {
			return err
		}
		if account.Email != accountSnapshot.Email ||
			account.AuthVersion != accountSnapshot.AuthVersion {
			return apperror.ErrInvalidCredentials
		}
		existing, err := e.accounts.FindByEmail(txCtx, command.NewEmail)
		if err != nil {
			return err
		}
		if existing != nil {
			return apperror.ErrConflict
		}
		if err := e.issueInTx(
			txCtx,
			account.ID,
			account.Email,
			command.NewEmail,
			state.AuthVersion,
			oldOTP,
			newOTP,
			now,
		); err != nil {
			return err
		}
		return e.audit(
			txCtx,
			account.ID,
			"REQUEST_EMAIL_CHANGE",
			command.Metadata,
		)
	})
}

// Resend thay challenge cũ bằng OTP mới và durable outbox event.
func (e *Email) Resend(ctx context.Context, userID uint64) error {
	oldOTP, newOTP, err := generateEmailChangeOTPs()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var businessError error
	err = e.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := e.accounts.FindByIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if account == nil {
			businessError = apperror.ErrNotFound
			return nil
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		if err := state.AuthenticationError(now); err != nil {
			businessError = err
			return nil
		}
		request, err := e.requests.FindPendingForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if request == nil {
			businessError = noPendingEmailChange()
			return nil
		}
		if err := state.AuthenticationError(now); err != nil {
			if cancelErr := e.cancelInTx(txCtx, userID, now); cancelErr != nil {
				return cancelErr
			}
			businessError = err
			return nil
		}
		if !request.ExpiresAt.After(now) ||
			request.OldEmail != account.Email ||
			request.AuthVersionSnapshot != state.AuthVersion {
			if err := e.outbox.CancelPendingEmailChange(txCtx, userID, now); err != nil {
				return err
			}
			if err := e.requests.CancelActiveByUser(txCtx, userID, now); err != nil {
				return err
			}
			businessError = staleEmailChange()
			return nil
		}
		return e.issueInTx(
			txCtx,
			account.ID,
			request.OldEmail,
			request.NewEmail,
			state.AuthVersion,
			oldOTP,
			newOTP,
			now,
		)
	})
	if err != nil {
		return err
	}
	return businessError
}

// Verify consume challenge, đổi email và vô hiệu hóa auth state trong cùng transaction.
func (e *Email) Verify(
	ctx context.Context,
	userID uint64,
	command VerifyEmailChangeCommand,
) error {
	now := time.Now().UTC()
	var businessError error
	err := e.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		account, err := e.accounts.FindByIDForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if account == nil {
			businessError = apperror.ErrNotFound
			return nil
		}
		state, err := account.State()
		if err != nil {
			return err
		}
		request, err := e.requests.FindPendingForUpdate(txCtx, userID)
		if err != nil {
			return err
		}
		if request == nil {
			businessError = noPendingEmailChange()
			return nil
		}
		if !request.ExpiresAt.After(now) ||
			request.OldEmail != account.Email ||
			request.AuthVersionSnapshot != state.AuthVersion {
			if err := e.cancelInTx(txCtx, userID, now); err != nil {
				return err
			}
			businessError = staleEmailChange()
			return nil
		}

		oldChallenge, err := e.challenges.FindEmailChangeForUpdate(
			txCtx,
			request.ID,
			emailChangeOldPurpose,
		)
		if err != nil {
			return err
		}
		newChallenge, err := e.challenges.FindEmailChangeForUpdate(
			txCtx,
			request.ID,
			emailChangeNewPurpose,
		)
		if err != nil {
			return err
		}
		if oldChallenge == nil ||
			newChallenge == nil ||
			oldChallenge.Subject != request.OldEmail ||
			newChallenge.Subject != request.NewEmail ||
			!oldChallenge.ExpiresAt.After(now) ||
			!newChallenge.ExpiresAt.After(now) {
			if err := e.cancelInTx(txCtx, userID, now); err != nil {
				return err
			}
			businessError = apperror.ErrOTPExpired
			return nil
		}
		if oldChallenge.Attempts >= e.policy.MaxAttempts ||
			newChallenge.Attempts >= e.policy.MaxAttempts {
			businessError = apperror.ErrOTPMaxAttempts
			return nil
		}
		if subtle.ConstantTimeCompare(
			[]byte(oldChallenge.SecretHash),
			[]byte(hash.HashOTP(command.OldOTP, e.pepper)),
		) != 1 {
			res, err := e.recordFailedOTP(txCtx, oldChallenge.ID)
			if err != nil {
				return err
			}
			businessError = res.BusinessError
			return nil
		}
		if subtle.ConstantTimeCompare(
			[]byte(newChallenge.SecretHash),
			[]byte(hash.HashOTP(command.NewOTP, e.pepper)),
		) != 1 {
			res, err := e.recordFailedOTP(txCtx, newChallenge.ID)
			if err != nil {
				return err
			}
			businessError = res.BusinessError
			return nil
		}
		existing, err := e.accounts.FindByEmail(txCtx, request.NewEmail)
		if err != nil {
			return err
		}
		if existing != nil && existing.ID != userID {
			if err := e.cancelInTx(txCtx, userID, now); err != nil {
				return err
			}
			businessError = apperror.ErrConflict.WithMessage(
				"Email đã được sử dụng bởi người dùng khác",
			)
			return nil
		}

		state.InvalidateAuth()
		if err := e.accounts.UpdateEmail(
			txCtx,
			userID,
			request.NewEmail,
			state,
			now,
		); err != nil {
			if err == apperror.ErrConflict {
				if cancelErr := e.cancelInTx(txCtx, userID, now); cancelErr != nil {
					return cancelErr
				}
				businessError = apperror.ErrConflict.WithMessage(
					"Email đã được sử dụng bởi người dùng khác",
				)
				return nil
			}
			return err
		}
		if err := e.outbox.CancelPendingEmailChange(txCtx, userID, now); err != nil {
			return err
		}
		if err := e.outbox.CancelPendingPasswordReset(txCtx, userID, now); err != nil {
			return err
		}
		if err := e.resets.InvalidateActiveByUser(txCtx, userID, now); err != nil {
			return err
		}
		if err := e.challenges.Consume(txCtx, oldChallenge.ID, now); err != nil {
			return err
		}
		if err := e.challenges.Consume(txCtx, newChallenge.ID, now); err != nil {
			return err
		}
		if err := e.requests.Complete(txCtx, request.ID, now); err != nil {
			return err
		}
		if err := e.invalidator.DeleteSessions(txCtx, userID); err != nil {
			return err
		}
		if err := e.audit(
			txCtx,
			userID,
			"VERIFY_EMAIL_CHANGE",
			command.Metadata,
		); err != nil {
			return err
		}
		payload, err := e.codec.SealEmailChangeNotification(mail.EmailChangeNotification{
			OldEmail: request.OldEmail,
			NewEmail: request.NewEmail,
		})
		if err != nil {
			return err
		}
		return e.outbox.Enqueue(txCtx, &mysqlstore.OutboxEvent{
			EventType:      mail.EmailChangeCompleted,
			AggregateType:  "email_change_request",
			AggregateID:    request.ID,
			Payload:        payload,
			IdempotencyKey: "email-change-completed:" + request.ID,
			MaxAttempts:    10,
			AvailableAt:    now,
		})
	})
	if err != nil {
		return err
	}
	return businessError
}

// issueInTx tạo challenge và outbox event trong transaction do caller sở hữu.
func (e *Email) issueInTx(
	ctx context.Context,
	userID uint64,
	oldEmail string,
	newEmail string,
	authVersion uint64,
	oldOTP string,
	newOTP string,
	now time.Time,
) error {
	if err := e.outbox.CancelPendingEmailChange(ctx, userID, now); err != nil {
		return err
	}
	if err := e.requests.CancelActiveByUser(ctx, userID, now); err != nil {
		return err
	}
	requestID := uuid.NewString()
	if err := e.requests.Create(ctx, &mysqlstore.EmailChangeRequest{
		ID:                  requestID,
		UserID:              userID,
		OldEmail:            oldEmail,
		NewEmail:            newEmail,
		AuthVersionSnapshot: authVersion,
		State:               mysqlstore.EmailChangePending,
		ExpiresAt:           now.Add(e.policy.Expiry),
		CreatedAt:           now,
	}); err != nil {
		return err
	}
	if err := e.createChallengeAndDelivery(
		ctx,
		requestID,
		userID,
		emailChangeOldPurpose,
		oldEmail,
		oldOTP,
		now,
	); err != nil {
		return err
	}
	return e.createChallengeAndDelivery(
		ctx,
		requestID,
		userID,
		emailChangeNewPurpose,
		newEmail,
		newOTP,
		now,
	)
}

// createChallengeAndDelivery hủy yêu cầu cũ rồi ghi challenge cùng durable email mới.
func (e *Email) createChallengeAndDelivery(
	ctx context.Context,
	emailChangeRequestID string,
	userID uint64,
	purpose string,
	recipient string,
	otp string,
	now time.Time,
) error {
	challengeRequestID := uuid.NewString()
	if err := e.challenges.Create(ctx, &mysqlstore.VerificationChallenge{
		RequestID:            challengeRequestID,
		UserID:               userID,
		EmailChangeRequestID: &emailChangeRequestID,
		Purpose:              purpose,
		Subject:              recipient,
		SecretHash:           hash.HashOTP(otp, e.pepper),
		ExpiresAt:            now.Add(e.policy.Expiry),
		CreatedAt:            now,
	}); err != nil {
		return err
	}
	payload, err := e.codec.Seal(mail.SecretMessage{
		To:     recipient,
		Secret: otp,
	})
	if err != nil {
		return err
	}
	return e.outbox.Enqueue(ctx, &mysqlstore.OutboxEvent{
		EventType:      mail.EmailChangeVerificationRequested,
		AggregateType:  "verification_challenge",
		AggregateID:    challengeRequestID,
		Payload:        payload,
		IdempotencyKey: "email-change-verification:" + challengeRequestID,
		MaxAttempts:    10,
		AvailableAt:    now,
	})
}

// cancelInTx hủy challenge và outbox event đang pending trong transaction hiện tại.
func (e *Email) cancelInTx(
	ctx context.Context,
	userID uint64,
	now time.Time,
) error {
	if err := e.outbox.CancelPendingEmailChange(ctx, userID, now); err != nil {
		return err
	}
	return e.requests.CancelActiveByUser(ctx, userID, now)
}

// OTPAttemptResult chứa kết quả phân tích số lần nhập OTP thất bại.
type OTPAttemptResult struct {
	ExceededMaxAttempts bool
	BusinessError       error
}

// recordFailedOTP tăng số lần sai và trả về kết quả kiểm tra ngưỡng thất bại của challenge.
func (e *Email) recordFailedOTP(ctx context.Context, challengeID uint64) (OTPAttemptResult, error) {
	attempts, err := e.challenges.IncrementAttempts(ctx, challengeID)
	if err != nil {
		return OTPAttemptResult{}, err
	}
	if attempts >= e.policy.MaxAttempts {
		return OTPAttemptResult{
			ExceededMaxAttempts: true,
			BusinessError:       apperror.ErrOTPMaxAttempts,
		}, nil
	}
	return OTPAttemptResult{
		ExceededMaxAttempts: false,
		BusinessError:       apperror.ErrOTPInvalid,
	}, nil
}

// audit ghi email-change event theo best effort và cảnh báo khi store thất bại.
func (e *Email) audit(
	ctx context.Context,
	userID uint64,
	action string,
	metadata EmailMetadata,
) error {
	resource := "account"
	resourceID := strconv.FormatUint(userID, 10)
	ipAddress := metadata.IPAddress
	userAgent := metadata.UserAgent
	return e.audits.Create(ctx, &mysqlstore.AuditLog{
		UserID:     &userID,
		Action:     action,
		Resource:   &resource,
		ResourceID: &resourceID,
		IPAddress:  &ipAddress,
		UserAgent:  &userAgent,
		Status:     "success",
	})
}

// generateEmailChangeOTPs tạo email thay đổi OTP trong account use case.
func generateEmailChangeOTPs() (string, string, error) {
	oldOTP, err := generateEmailChangeOTP()
	if err != nil {
		return "", "", err
	}
	newOTP, err := generateEmailChangeOTP()
	if err != nil {
		return "", "", err
	}
	return oldOTP, newOTP, nil
}

// generateEmailChangeOTP tạo email thay đổi OTP trong account use case.
func generateEmailChangeOTP() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("generate email-change OTP: %w", err)
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

// noPendingEmailChange tạo business error khi tài khoản không có yêu cầu đổi email.
func noPendingEmailChange() error {
	return apperror.ErrBadRequest.WithMessage(
		"Không có yêu cầu đổi email nào đang chờ xử lý hoặc đã hết hạn",
	)
}

// staleEmailChange tạo conflict khi account state đã đổi sau lúc challenge được phát hành.
func staleEmailChange() error {
	return apperror.ErrBadRequest.WithMessage(
		"Yêu cầu đổi email không còn hợp lệ vì trạng thái tài khoản đã thay đổi. Vui lòng tạo yêu cầu mới",
	)
}
