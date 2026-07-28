package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

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

type ClientProfileStore struct {
	db *sqlx.DB
}

func NewClientProfileStore(db *sqlx.DB) *ClientProfileStore {
	return &ClientProfileStore{db: db}
}

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

func clampClientProfile(profile *ClientProfile) {
	profile.DeviceName = clampOptionalRunes(profile.DeviceName, 255)
	profile.DeviceType = clampOptionalRunes(profile.DeviceType, 50)
	profile.OS = clampOptionalRunes(profile.OS, 50)
	profile.Browser = clampOptionalRunes(profile.Browser, 50)
	profile.IPAddress = clampOptionalRunes(profile.IPAddress, 45)
}

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
