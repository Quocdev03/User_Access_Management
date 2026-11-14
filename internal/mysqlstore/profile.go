package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/pkg/apperror"
)

// File này đọc và cập nhật canonical account profile trong MySQL.

// Profile ánh xạ bản ghi thông tin hồ sơ người dùng từ bảng profiles trong MySQL.
type Profile struct {
	UserID          uint64    `db:"user_id"`
	FullName        string    `db:"full_name"`
	Phone           string    `db:"phone"`
	DateOfBirth     time.Time `db:"date_of_birth"`
	AvatarObjectKey *string   `db:"avatar_object_key"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// ProfileStore quản lý các thao tác đọc và cập nhật thông tin hồ sơ tài khoản trong MySQL.
type ProfileStore struct {
	db *sqlx.DB
}

// AvatarMigrationCandidate đại diện cho bản ghi tài khoản cần di chuyển ảnh đại diện từ local sang S3.
type AvatarMigrationCandidate struct {
	UserID    uint64 `db:"user_id"`
	ObjectKey string `db:"avatar_object_key"`
}

// NewProfileStore khởi tạo ProfileStore với các dependency được cung cấp.
func NewProfileStore(db *sqlx.DB) *ProfileStore {
	return &ProfileStore{db: db}
}

// ListAvatarMigrationCandidates đọc batch profile còn tham chiếu local avatar URL.
func (s *ProfileStore) ListAvatarMigrationCandidates(
	ctx context.Context,
	afterUserID uint64,
	limit int,
) ([]AvatarMigrationCandidate, error) {
	if limit < 1 {
		return nil, nil
	}
	candidates := []AvatarMigrationCandidate{}
	if err := executor(ctx, s.db).SelectContext(ctx, &candidates, `
		SELECT user_id, avatar_object_key
		FROM user_profiles
		WHERE user_id > ?
		  AND avatar_object_key IS NOT NULL
		  AND avatar_object_key <> ''
		ORDER BY user_id
		LIMIT ?`,
		afterUserID,
		limit,
	); err != nil {
		return nil, fmt.Errorf("list avatar migration candidates: %w", err)
	}
	return candidates, nil
}

// CommitAvatarMigration đổi avatar reference sang object key khi source URL vẫn khớp snapshot.
func (s *ProfileStore) CommitAvatarMigration(
	ctx context.Context,
	userID uint64,
	expectedKey string,
	canonicalKey string,
) error {
	if !inTransaction(ctx) {
		return fmt.Errorf("avatar migration commit requires a MySQL transaction")
	}
	var current sql.NullString
	if err := executor(ctx, s.db).GetContext(ctx, &current, `
		SELECT avatar_object_key
		FROM user_profiles
		WHERE user_id = ?
		FOR UPDATE`,
		userID,
	); err != nil {
		return fmt.Errorf("lock avatar migration profile: %w", err)
	}
	if !current.Valid || current.String != expectedKey {
		return apperror.ErrConflict
	}
	if _, err := executor(ctx, s.db).ExecContext(ctx, `
		UPDATE user_profiles
		SET avatar_object_key = ?, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ?`,
		canonicalKey,
		userID,
	); err != nil {
		return fmt.Errorf("update canonical avatar key: %w", err)
	}
	return nil
}

// FindByUserID truy vấn theo người dùng ID tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *ProfileStore) FindByUserID(ctx context.Context, userID uint64) (*Profile, error) {
	var profile Profile
	err := executor(ctx, s.db).GetContext(ctx, &profile, `
		SELECT user_id, full_name, phone, date_of_birth, avatar_object_key,
			created_at, updated_at
		FROM user_profiles
		WHERE user_id = ?
		LIMIT 1`,
		userID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find profile by user id: %w", err)
	}
	return &profile, nil
}

// Upsert tạo hoặc cập nhật canonical profile trong transaction hiện tại.
func (s *ProfileStore) Upsert(ctx context.Context, profile *Profile) error {
	_, err := executor(ctx, s.db).ExecContext(ctx, `
		INSERT INTO user_profiles (
			user_id, full_name, phone, date_of_birth, avatar_object_key
		) VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			full_name = VALUES(full_name),
			phone = VALUES(phone),
			date_of_birth = VALUES(date_of_birth),
			avatar_object_key = VALUES(avatar_object_key)`,
		profile.UserID,
		profile.FullName,
		profile.Phone,
		profile.DateOfBirth,
		profile.AvatarObjectKey,
	)
	if err != nil {
		return fmt.Errorf("upsert profile: %w", err)
	}
	return nil
}

// UpdateMutable cập nhật mutable tại MySQL adapter và giữ mapping persistence khỏi domain.
func (s *ProfileStore) UpdateMutable(
	ctx context.Context,
	userID uint64,
	fullName *string,
	phone *string,
	dateOfBirth *time.Time,
) error {
	if !inTransaction(ctx) {
		return fmt.Errorf("profile update requires a MySQL transaction")
	}
	db := executor(ctx, s.db)

	var exists int
	if err := db.GetContext(ctx, &exists, `
		SELECT 1
		FROM user_profiles
		WHERE user_id = ?
		LIMIT 1`,
		userID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apperror.ErrNotFound
		}
		return fmt.Errorf("check mutable profile: %w", err)
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE user_profiles
		SET full_name = COALESCE(?, full_name),
			phone = COALESCE(?, phone),
			date_of_birth = COALESCE(?, date_of_birth),
			updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ?`,
		fullName,
		phone,
		dateOfBirth,
		userID,
	); err != nil {
		return fmt.Errorf("update canonical mutable profile: %w", err)
	}
	return nil
}

// SwapAvatar thay avatar URL và trả reference cũ để caller cleanup ngoài transaction.
func (s *ProfileStore) SwapAvatar(
	ctx context.Context,
	userID uint64,
	objectKey *string,
) (*string, error) {
	if !inTransaction(ctx) {
		return nil, fmt.Errorf("avatar swap requires a MySQL transaction")
	}
	db := executor(ctx, s.db)

	var oldKey sql.NullString
	if err := db.GetContext(ctx, &oldKey, `
		SELECT avatar_object_key
		FROM user_profiles
		WHERE user_id = ?
		FOR UPDATE`,
		userID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperror.ErrNotFound
		}
		return nil, fmt.Errorf("lock avatar profile: %w", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE user_profiles
		SET avatar_object_key = ?, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ?`,
		objectKey,
		userID,
	); err != nil {
		return nil, fmt.Errorf("update avatar object key: %w", err)
	}
	if !oldKey.Valid || oldKey.String == "" {
		return nil, nil
	}
	return &oldKey.String, nil
}
