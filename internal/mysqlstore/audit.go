package mysqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

type AuditLog struct {
	ID         uint64    `db:"id" json:"id"`
	UserID     *uint64   `db:"user_id" json:"user_id"`
	Action     string    `db:"action" json:"action"`
	Resource   *string   `db:"resource" json:"resource,omitempty"`
	ResourceID *string   `db:"resource_id" json:"resource_id,omitempty"`
	IPAddress  *string   `db:"ip_address" json:"ip_address,omitempty"`
	UserAgent  *string   `db:"user_agent" json:"user_agent,omitempty"`
	OldValues  *string   `db:"old_values" json:"old_values,omitempty"`
	NewValues  *string   `db:"new_values" json:"new_values,omitempty"`
	Status     string    `db:"status" json:"status"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

type AuditStore struct {
	db *sqlx.DB
}

func NewAuditStore(db *sqlx.DB) *AuditStore {
	return &AuditStore{db: db}
}

func (s *AuditStore) Create(ctx context.Context, log *AuditLog) error {
	query := `
		INSERT INTO audit_logs (
			user_id, action, resource, resource_id, ip_address, user_agent, old_values, new_values, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
	`
	res, err := executor(ctx, s.db).ExecContext(ctx, query,
		log.UserID,
		log.Action,
		log.Resource,
		log.ResourceID,
		log.IPAddress,
		log.UserAgent,
		log.OldValues,
		log.NewValues,
		log.Status,
	)
	if err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		log.ID = uint64(id)
	}

	return nil
}

func (s *AuditStore) FindAllWithFilters(
	ctx context.Context,
	userID *uint64,
	action *string,
	start, end *string,
) ([]AuditLog, error) {
	query := `SELECT id, user_id, action, resource, resource_id, ip_address,
		user_agent, old_values, new_values, status, created_at
		FROM audit_logs WHERE 1=1`
	args := []interface{}{}

	if userID != nil {
		query += ` AND user_id = ?`
		args = append(args, *userID)
	}
	if action != nil && *action != "" {
		query += ` AND action = ?`
		args = append(args, *action)
	}
	if start != nil && *start != "" {
		query += ` AND created_at >= ?`
		args = append(args, *start)
	}
	if end != nil && *end != "" {
		// end là YYYY-MM-DD: dùng < end+1day để gồm cả ngày end (tránh <= midnight đầu ngày).
		query += ` AND created_at < DATE_ADD(?, INTERVAL 1 DAY)`
		args = append(args, *end)
	}

	query += ` ORDER BY created_at DESC LIMIT 10000`

	logs := []AuditLog{}
	if err := executor(ctx, s.db).SelectContext(ctx, &logs, query, args...); err != nil {
		return nil, fmt.Errorf("find audit logs: %w", err)
	}
	return logs, nil
}

// DeleteOlderThanBatch xóa audit cũ hơn before, tối đa limit rows (retention policy).
func (s *AuditStore) DeleteOlderThanBatch(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit < 1 {
		limit = 1000
	}
	query := `DELETE FROM audit_logs WHERE created_at < ? LIMIT ?`
	res, err := executor(ctx, s.db).ExecContext(ctx, query, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old audit logs: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted audit-log rows: %w", err)
	}
	return rows, nil
}
