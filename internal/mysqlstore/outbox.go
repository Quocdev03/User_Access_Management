package mysqlstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

type OutboxEvent struct {
	ID             uint64    `db:"id"`
	EventType      string    `db:"event_type"`
	AggregateType  string    `db:"aggregate_type"`
	AggregateID    string    `db:"aggregate_id"`
	Payload        []byte    `db:"payload"`
	IdempotencyKey string    `db:"idempotency_key"`
	Attempts       int       `db:"attempts"`
	MaxAttempts    int       `db:"max_attempts"`
	AvailableAt    time.Time `db:"available_at"`
}

type OutboxStore struct {
	db *sqlx.DB
}

func NewOutboxStore(db *sqlx.DB) *OutboxStore {
	return &OutboxStore{db: db}
}

func (s *OutboxStore) Enqueue(ctx context.Context, event *OutboxEvent) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO outbox_events (
			event_type, aggregate_type, aggregate_id, payload,
			idempotency_key, max_attempts, available_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE id = id`,
		event.EventType,
		event.AggregateType,
		event.AggregateID,
		event.Payload,
		event.IdempotencyKey,
		event.MaxAttempts,
		event.AvailableAt.UTC(),
	); err != nil {
		return fmt.Errorf("enqueue outbox event: %w", err)
	}
	return nil
}

func (s *OutboxStore) CancelPendingVerification(
	ctx context.Context,
	userID uint64,
	purpose string,
	now time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE outbox_events
		SET dead_lettered_at = ?,
			payload = JSON_OBJECT('redacted', TRUE),
			claimed_at = NULL,
			claimed_by = NULL,
			last_error = 'superseded',
			updated_at = ?
		WHERE event_type = 'mail.verification_requested'
		  AND delivered_at IS NULL
		  AND dead_lettered_at IS NULL
		  AND aggregate_id IN (
			SELECT request_id
			FROM verification_challenges
			WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL
		  )`,
		now.UTC(),
		now.UTC(),
		userID,
		purpose,
	); err != nil {
		return fmt.Errorf("cancel pending verification delivery: %w", err)
	}
	return nil
}

func (s *OutboxStore) CancelPendingPasswordReset(
	ctx context.Context,
	userID uint64,
	now time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE outbox_events
		SET dead_lettered_at = ?,
			payload = JSON_OBJECT('redacted', TRUE),
			claimed_at = NULL,
			claimed_by = NULL,
			last_error = 'superseded',
			updated_at = ?
		WHERE event_type = 'mail.password_reset_requested'
		  AND delivered_at IS NULL
		  AND dead_lettered_at IS NULL
		  AND CAST(aggregate_id AS UNSIGNED) IN (
			SELECT id
			FROM password_reset_tokens
			WHERE user_id = ?
		  )`,
		now.UTC(),
		now.UTC(),
		userID,
	); err != nil {
		return fmt.Errorf("cancel pending password reset delivery: %w", err)
	}
	return nil
}

func (s *OutboxStore) CancelPendingEmailChange(
	ctx context.Context,
	userID uint64,
	now time.Time,
) error {
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE outbox_events
		SET dead_lettered_at = ?,
			payload = JSON_OBJECT('redacted', TRUE),
			claimed_at = NULL,
			claimed_by = NULL,
			last_error = 'superseded',
			updated_at = ?
		WHERE event_type IN (
				'mail.email_change_verification_requested',
				'mail.email_change_completed'
			)
		  AND delivered_at IS NULL
		  AND dead_lettered_at IS NULL
		  AND (
			aggregate_id IN (
				SELECT request_id
				FROM verification_challenges
				WHERE user_id = ? AND email_change_request_id IS NOT NULL
			)
			OR aggregate_id IN (
				SELECT id FROM email_change_requests WHERE user_id = ?
			)
		  )`,
		now.UTC(),
		now.UTC(),
		userID,
		userID,
	); err != nil {
		return fmt.Errorf("cancel pending email-change delivery: %w", err)
	}
	return nil
}

func (s *OutboxStore) ClaimAvailable(
	ctx context.Context,
	workerID string,
	now time.Time,
	staleBefore time.Time,
	limit int,
) ([]OutboxEvent, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("outbox claim requires a MySQL transaction")
	}
	if limit < 1 {
		return nil, nil
	}
	events := []OutboxEvent{}
	if err := executor(ctx, s.db).SelectContext(ctx, &events, `
		SELECT id, event_type, aggregate_type, aggregate_id, payload,
			idempotency_key, attempts, max_attempts, available_at
		FROM outbox_events
		WHERE delivered_at IS NULL
		  AND dead_lettered_at IS NULL
		  AND available_at <= ?
		  AND attempts < max_attempts
		  AND (claimed_at IS NULL OR claimed_at < ?)
		ORDER BY available_at, id
		LIMIT ?
		FOR UPDATE SKIP LOCKED`,
		now.UTC(),
		staleBefore.UTC(),
		limit,
	); err != nil {
		return nil, fmt.Errorf("lock available outbox events: %w", err)
	}
	if len(events) == 0 {
		return events, nil
	}

	ids := make([]uint64, 0, len(events))
	for index := range events {
		ids = append(ids, events[index].ID)
		events[index].Attempts++
	}
	query, args, err := sqlx.In(`
		UPDATE outbox_events
		SET claimed_at = ?, claimed_by = ?, attempts = attempts + 1,
			updated_at = ?
		WHERE id IN (?)`,
		now.UTC(),
		workerID,
		now.UTC(),
		ids,
	)
	if err != nil {
		return nil, fmt.Errorf("build outbox claim: %w", err)
	}
	if _, err := executor(ctx, s.db).ExecContext(
		ctx,
		s.db.Rebind(query),
		args...,
	); err != nil {
		return nil, fmt.Errorf("claim outbox events: %w", err)
	}
	return events, nil
}

func (s *OutboxStore) MarkDelivered(
	ctx context.Context,
	id uint64,
	workerID string,
	now time.Time,
) error {
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE outbox_events
		SET delivered_at = ?,
			payload = JSON_OBJECT('redacted', TRUE),
			claimed_at = NULL,
			claimed_by = NULL,
			last_error = NULL,
			updated_at = ?
		WHERE id = ? AND claimed_by = ? AND delivered_at IS NULL`,
		now.UTC(),
		now.UTC(),
		id,
		workerID,
	)
	if err != nil {
		return fmt.Errorf("mark outbox delivered: %w", err)
	}
	return requireOneRow(result, "mark outbox delivered")
}

func (s *OutboxStore) MarkFailed(
	ctx context.Context,
	event OutboxEvent,
	workerID string,
	nextAttempt time.Time,
	cause error,
) error {
	message := cause.Error()
	if len(message) > 1000 {
		message = message[:1000]
	}
	deadLetter := event.Attempts >= event.MaxAttempts
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE outbox_events
		SET available_at = ?,
			claimed_at = NULL,
			claimed_by = NULL,
			dead_lettered_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END,
			last_error = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND claimed_by = ? AND delivered_at IS NULL`,
		nextAttempt.UTC(),
		deadLetter,
		strings.TrimSpace(message),
		event.ID,
		workerID,
	)
	if err != nil {
		return fmt.Errorf("mark outbox failed: %w", err)
	}
	return requireOneRow(result, "mark outbox failed")
}

func (s *OutboxStore) DeleteCompletedBatch(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	if limit < 1 {
		return 0, nil
	}
	result, err := executor(ctx, s.db).ExecContext(ctx, `
		DELETE FROM outbox_events
		WHERE (delivered_at IS NOT NULL OR dead_lettered_at IS NOT NULL)
		  AND updated_at < ?
		ORDER BY updated_at, id
		LIMIT ?`,
		before.UTC(),
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("delete completed outbox events: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted outbox rows: %w", err)
	}
	return rows, nil
}

func requireOneRow(result interface {
	RowsAffected() (int64, error)
}, operation string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows: %w", operation, err)
	}
	if rows != 1 {
		return apperror.ErrNotFound
	}
	return nil
}
