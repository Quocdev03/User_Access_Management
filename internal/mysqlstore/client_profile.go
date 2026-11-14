package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// File này lưu observed client profile gắn với tài khoản.

// ClientProfile ánh xạ bản ghi thông tin thiết bị và trình duyệt đã quan sát được của người dùng.
type ClientProfile struct {
	ID           uint64     `db:"id"`
	UserID       uint64     `db:"user_id"`
	DeviceName   *string    `db:"device_name"`
	DeviceType   *string    `db:"device_type"`
	OS           *string    `db:"os"`
	Browser      *string    `db:"browser"`
	IPAddress    *string    `db:"ip_address"`
	LastActiveAt *time.Time `db:"last_active_at"`
	CreatedAt    time.Time  `db:"created_at"`
}

const clientProfileProjection = `id, user_id, device_name, device_type,
	os, browser, ip_address, last_active_at, created_at`

// ClientProfileStore quản lý việc lưu và truy vấn hồ sơ thiết bị client trong MySQL.
type ClientProfileStore struct {
	db *sqlx.DB
}

// NewClientProfileStore khởi tạo ClientProfileStore với các dependency được cung cấp.
func NewClientProfileStore(db *sqlx.DB) *ClientProfileStore {
	return &ClientProfileStore{db: db}
}

// Observe upsert observed client profile mà không biến dữ liệu này thành canonical identity.
func (s *ClientProfileStore) Observe(ctx context.Context, profile *ClientProfile) error {
	clampClientProfile(profile)
	db := executor(ctx, s.db)

	var existingID uint64
	err := db.GetContext(ctx, &existingID, `
		SELECT id
		FROM devices
		WHERE user_id = ?
		  AND device_name <=> ?
		  AND device_type <=> ?
		  AND os <=> ?
		  AND browser <=> ?
		ORDER BY last_active_at DESC, id DESC
		LIMIT 1 FOR UPDATE`,
		profile.UserID,
		profile.DeviceName,
		profile.DeviceType,
		profile.OS,
		profile.Browser,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("find observed client profile: %w", err)
	}
	if err == nil {
		if _, err := db.ExecContext(ctx, `
			UPDATE devices
			SET ip_address = ?, last_active_at = NOW()
			WHERE id = ?`,
			profile.IPAddress,
			existingID,
		); err != nil {
			return fmt.Errorf("update observed client profile: %w", err)
		}
		profile.ID = existingID
		return nil
	}

	result, err := db.ExecContext(ctx, `
		INSERT INTO devices (
			user_id, device_name, device_type, os, browser,
			ip_address, last_active_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())`,
		profile.UserID,
		profile.DeviceName,
		profile.DeviceType,
		profile.OS,
		profile.Browser,
		profile.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("create observed client profile: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read observed client profile id: %w", err)
	}
	profile.ID = uint64(id)
	return nil
}

// FindByUserID truy vấn theo người dùng ID tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *ClientProfileStore) FindByUserID(
	ctx context.Context,
	userID uint64,
) ([]ClientProfile, error) {
	profiles := []ClientProfile{}
	if err := executor(ctx, s.db).SelectContext(ctx, &profiles,
		`SELECT `+clientProfileProjection+`
		 FROM devices
		 WHERE user_id = ?
		 ORDER BY last_active_at DESC, id DESC`,
		userID,
	); err != nil {
		return nil, fmt.Errorf("list observed client profiles: %w", err)
	}
	return profiles, nil
}

// clampClientProfile giới hạn độ dài metadata theo schema trước khi ghi.
func clampClientProfile(profile *ClientProfile) {
	profile.DeviceName = clampOptionalRunes(profile.DeviceName, 255)
	profile.DeviceType = clampOptionalRunes(profile.DeviceType, 50)
	profile.OS = clampOptionalRunes(profile.OS, 50)
	profile.Browser = clampOptionalRunes(profile.Browser, 50)
	profile.IPAddress = clampOptionalRunes(profile.IPAddress, 45)
}

// clampOptionalRunes cắt chuỗi UTF-8 theo rune và giữ nil cho giá trị trống.
func clampOptionalRunes(value *string, maximum int) *string {
	if value == nil {
		return nil
	}
	runes := []rune(*value)
	if len(runes) <= maximum {
		return value
	}
	clamped := string(runes[:maximum])
	return &clamped
}
