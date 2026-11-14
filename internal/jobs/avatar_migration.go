// Package jobs chạy outbox delivery, cleanup và các tác vụ bảo trì có lease.
package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"go.uber.org/zap"
)

// File này di chuyển blob avatar theo batch dưới distributed lease.

// AvatarMigrationResult chứa kết quả số lượng ảnh đại diện đã được copy và bỏ qua trong quá trình di chuyển.
type AvatarMigrationResult struct {
	Copied  int
	Skipped int
}

// AvatarMigrator thực hiện việc di chuyển dữ liệu ảnh đại diện từ local filesystem sang object store S3.
type AvatarMigrator struct {
	profiles *mysqlstore.ProfileStore
	tx       *mysqlstore.TxManager
	source   *blob.LocalStore
	target   blob.VerifiedStore
	logger   *zap.Logger
}

// NewAvatarMigrator khởi tạo AvatarMigrator với các dependency được cung cấp.
func NewAvatarMigrator(
	db *sqlx.DB,
	source *blob.LocalStore,
	target blob.VerifiedStore,
	logger *zap.Logger,
) *AvatarMigrator {
	return &AvatarMigrator{
		profiles: mysqlstore.NewProfileStore(db),
		tx:       mysqlstore.NewTxManager(db),
		source:   source,
		target:   target,
		logger:   logger,
	}
}

// Run di chuyển avatar theo batch dưới distributed lease và trả báo cáo tổng hợp.
func (m *AvatarMigrator) Run(
	ctx context.Context,
	batchSize int,
) (AvatarMigrationResult, error) {
	if batchSize < 1 {
		batchSize = 100
	}
	var result AvatarMigrationResult
	var cursor uint64
	for {
		candidates, err := m.profiles.ListAvatarMigrationCandidates(
			ctx,
			cursor,
			batchSize,
		)
		if err != nil {
			return result, err
		}
		if len(candidates) == 0 {
			return result, nil
		}
		for _, candidate := range candidates {
			cursor = candidate.UserID
			if strings.HasPrefix(candidate.ObjectKey, "http://") ||
				strings.HasPrefix(candidate.ObjectKey, "https://") {
				result.Skipped++
				m.logger.Info(
					"Avatar migration skipped external URL",
					zap.Uint64("user_id", candidate.UserID),
				)
				continue
			}
			if err := m.copyOne(ctx, candidate); err != nil {
				return result, fmt.Errorf(
					"migrate avatar for user %d: %w",
					candidate.UserID,
					err,
				)
			}
			result.Copied++
		}
	}
}

// copyOne đọc local blob, ghi object mới và xác minh checksum trước khi commit reference.
func (m *AvatarMigrator) copyOne(
	ctx context.Context,
	candidate mysqlstore.AvatarMigrationCandidate,
) error {
	key, err := blob.CanonicalAvatarKey(candidate.ObjectKey)
	if err != nil {
		return err
	}
	file, err := m.source.Open(ctx, candidate.ObjectKey)
	if err != nil {
		return err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		_ = file.Close()
		return fmt.Errorf("hash local avatar: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return fmt.Errorf("rewind local avatar: %w", err)
	}
	if err := m.target.Put(ctx, key, file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close local avatar: %w", err)
	}
	expectedChecksum := hex.EncodeToString(digest.Sum(nil))
	if err := m.target.VerifySHA256(ctx, key, expectedChecksum); err != nil {
		m.deleteCopied(ctx, key)
		return err
	}
	err = m.tx.RunInTx(ctx, func(txCtx context.Context) error {
		return m.profiles.CommitAvatarMigration(
			txCtx,
			candidate.UserID,
			candidate.ObjectKey,
			key,
		)
	})
	if err != nil {
		m.deleteCopied(ctx, key)
		return err
	}
	return nil
}

// deleteCopied dọn object vừa copy khi database compare-and-swap không thành công.
func (m *AvatarMigrator) deleteCopied(ctx context.Context, key string) {
	deleteCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		10*time.Second,
	)
	defer cancel()
	if err := m.target.Delete(deleteCtx, key); err != nil {
		m.logger.Warn(
			"Failed to remove uncommitted migrated avatar",
			zap.String("key", key),
			zap.Error(err),
		)
	}
}
