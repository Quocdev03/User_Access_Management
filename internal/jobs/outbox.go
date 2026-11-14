package jobs

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/config"
	mailmessage "github.com/quocdev03/user-access-management/internal/mail"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"go.uber.org/zap"
)

// File này claim, giải mã và giao outbox event bằng bounded worker.

// MailSender định nghĩa hợp đồng gửi email được outbox worker sử dụng để phân phối các loại thông báo.
type MailSender interface {
	// SendVerificationEmail giao OTP xác minh đăng ký đến địa chỉ nhận.
	SendVerificationEmail(ctx context.Context, to, otp string) error
	// SendPasswordResetEmail giao đường dẫn đặt lại mật khẩu có token.
	SendPasswordResetEmail(ctx context.Context, to, token string) error
	// SendEmailChangeVerification giao OTP xác minh đến địa chỉ email mới.
	SendEmailChangeVerification(ctx context.Context, to, otp string) error
	// SendEmailChangeNotification cảnh báo cả địa chỉ cũ và mới sau khi đổi email.
	SendEmailChangeNotification(ctx context.Context, oldEmail, newEmail string) error
	// SendAdminNotification giao nội dung thông báo do quản trị viên tạo.
	SendAdminNotification(ctx context.Context, to, subject, message string) error
}

// OutboxWorker xử lý việc claim, giải mã và gửi các sự kiện email từ outbox table.
type OutboxWorker struct {
	store     *mysqlstore.OutboxStore
	txManager *mysqlstore.TxManager
	codec     *mailmessage.SecretCodec
	sender    MailSender
	cfg       config.OutboxConfig
	workerID  string
	logger    *zap.Logger
}

// NewOutboxWorker khởi tạo OutboxWorker với các dependency được cung cấp.
func NewOutboxWorker(
	db *sqlx.DB,
	store *mysqlstore.OutboxStore,
	codec *mailmessage.SecretCodec,
	sender MailSender,
	cfg config.OutboxConfig,
	logger *zap.Logger,
) *OutboxWorker {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "uam"
	}
	return &OutboxWorker{
		store:     store,
		txManager: mysqlstore.NewTxManager(db),
		codec:     codec,
		sender:    sender,
		cfg:       cfg,
		workerID:  hostname + ":" + uuid.NewString(),
		logger:    logger,
	}
}

// Start chạy bounded outbox workers cho đến khi context bị hủy.
func (w *OutboxWorker) Start(ctx context.Context) {
	w.logger.Info(
		"Outbox worker started",
		zap.Int("batch_size", w.cfg.BatchSize),
		zap.Int("max_concurrent", w.cfg.MaxConcurrent),
	)
	w.runOnce(ctx)
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Outbox worker stopped")
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

// runOnce claim một batch event và giao từng event ngoài MySQL transaction.
func (w *OutboxWorker) runOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now().UTC()
	var events []mysqlstore.OutboxEvent
	err := w.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		var err error
		events, err = w.store.ClaimAvailable(
			txCtx,
			w.workerID,
			now,
			now.Add(-w.cfg.ClaimTTL),
			w.cfg.BatchSize,
		)
		return err
	})
	if err != nil {
		w.logger.Error("Outbox claim failed", zap.Error(err))
		return
	}

	limit := w.cfg.MaxConcurrent
	if limit < 1 {
		limit = 1
	}
	semaphore := make(chan struct{}, limit)
	var wait sync.WaitGroup
	for _, event := range events {
		if ctx.Err() != nil {
			break
		}
		event := event
		semaphore <- struct{}{}
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer func() { <-semaphore }()
			w.deliver(ctx, event)
		}()
	}
	wait.Wait()
}

// deliver giải mã đúng payload type và gọi mail sender tương ứng.
func (w *OutboxWorker) deliver(ctx context.Context, event mysqlstore.OutboxEvent) {
	deliveryCtx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()

	var err error
	switch event.EventType {
	case mailmessage.VerificationRequested:
		var message mailmessage.SecretMessage
		message, err = w.codec.Open(event.Payload)
		if err == nil {
			err = w.sender.SendVerificationEmail(deliveryCtx, message.To, message.Secret)
		}
	case mailmessage.PasswordResetRequested:
		var message mailmessage.SecretMessage
		message, err = w.codec.Open(event.Payload)
		if err == nil {
			err = w.sender.SendPasswordResetEmail(deliveryCtx, message.To, message.Secret)
		}
	case mailmessage.EmailChangeVerificationRequested:
		var message mailmessage.SecretMessage
		message, err = w.codec.Open(event.Payload)
		if err == nil {
			err = w.sender.SendEmailChangeVerification(deliveryCtx, message.To, message.Secret)
		}
	case mailmessage.EmailChangeCompleted:
		var notification mailmessage.EmailChangeNotification
		notification, err = w.codec.OpenEmailChangeNotification(event.Payload)
		if err == nil {
			err = w.sender.SendEmailChangeNotification(deliveryCtx, notification.OldEmail, notification.NewEmail)
		}
	case mailmessage.AdminNotificationRequested:
		var message mailmessage.AdminNotification
		message, err = w.codec.OpenAdminNotification(event.Payload)
		if err == nil {
			err = w.sender.SendAdminNotification(
				deliveryCtx,
				message.To,
				message.Subject,
				message.Message,
			)
		}
	default:
		err = fmt.Errorf("unsupported outbox event type %q", event.EventType)
	}
	if err == nil {
		if deliveryCtx.Err() != nil {
			err = deliveryCtx.Err()
		} else if markErr := w.store.MarkDelivered(
			deliveryCtx,
			event.ID,
			w.workerID,
			time.Now().UTC(),
		); markErr != nil {
			w.logger.Error(
				"Outbox delivery could not be acknowledged",
				zap.Uint64("event_id", event.ID),
				zap.String("event_type", event.EventType),
				zap.Error(markErr),
			)
			return
		} else {
			return
		}
	}

	nextAttempt := time.Now().UTC().Add(outboxBackoff(event.Attempts))
	markCtx, markCancel := context.WithTimeout(context.WithoutCancel(ctx), w.cfg.Timeout)
	defer markCancel()
	if markErr := w.store.MarkFailed(
		markCtx,
		event,
		w.workerID,
		nextAttempt,
		err,
	); markErr != nil {
		w.logger.Error(
			"Outbox failure could not be recorded",
			zap.Uint64("event_id", event.ID),
			zap.String("event_type", event.EventType),
			zap.Error(markErr),
		)
		return
	}
	w.logger.Warn(
		"Outbox delivery failed",
		zap.Uint64("event_id", event.ID),
		zap.String("event_type", event.EventType),
		zap.Int("attempt", event.Attempts),
	)
}

// outboxBackoff tính exponential retry delay có giới hạn cho event thất bại.
func outboxBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return time.Duration(1<<attempt) * time.Second
}
