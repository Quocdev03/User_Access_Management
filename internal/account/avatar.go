// Package account triển khai các use case hồ sơ, email và ảnh đại diện.
package account

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"go.uber.org/zap"
)

// File này điều phối upload, thay thế và xóa ảnh đại diện ngoài MySQL transaction.

const MaxAvatarBytes int64 = 2 << 20

// AvatarMetadata chứa thông tin IP và User-Agent khi thực hiện thao tác với ảnh đại diện.
type AvatarMetadata struct {
	IPAddress string
	UserAgent string
}

// Avatar điều phối các use case tải lên, cập nhật và xóa ảnh đại diện người dùng.
type Avatar struct {
	profiles  *mysqlstore.ProfileStore
	audits    *mysqlstore.AuditStore
	blobs     blob.Store
	txManager *mysqlstore.TxManager
	logger    *zap.Logger
}

// NewAvatar khởi tạo Avatar với các dependency được cung cấp.
func NewAvatar(
	db *sqlx.DB,
	profiles *mysqlstore.ProfileStore,
	audits *mysqlstore.AuditStore,
	blobs blob.Store,
	logger *zap.Logger,
) *Avatar {
	return &Avatar{
		profiles:  profiles,
		audits:    audits,
		blobs:     blobs,
		txManager: mysqlstore.NewTxManager(db),
		logger:    logger,
	}
}

// Upload kiểm tra ảnh, ghi blob mới rồi compare-and-swap profile reference trong transaction.
func (a *Avatar) Upload(
	ctx context.Context,
	userID uint64,
	content io.Reader,
	originalFileName string,
	declaredSize int64,
	metadata AvatarMetadata,
) (string, error) {
	if declaredSize > MaxAvatarBytes {
		return "", apperror.ErrBadRequest.WithMessage(
			"Kích thước ảnh đại diện không được vượt quá 2MB",
		)
	}
	extension := strings.ToLower(filepath.Ext(originalFileName))
	expectedContentType := ""
	switch extension {
	case ".jpg", ".jpeg":
		extension = ".jpg"
		expectedContentType = "image/jpeg"
	case ".png":
		expectedContentType = "image/png"
	case ".webp":
		expectedContentType = "image/webp"
	default:
		return "", apperror.ErrBadRequest.WithMessage(
			"Định dạng tệp không được hỗ trợ. Chỉ cho phép JPEG, PNG, WebP",
		)
	}

	data, err := io.ReadAll(io.LimitReader(content, MaxAvatarBytes+1))
	if err != nil {
		return "", fmt.Errorf("read avatar upload: %w", err)
	}
	if int64(len(data)) > MaxAvatarBytes {
		return "", apperror.ErrBadRequest.WithMessage(
			"Kích thước ảnh đại diện không được vượt quá 2MB",
		)
	}
	if len(data) == 0 ||
		http.DetectContentType(data) != expectedContentType {
		return "", apperror.ErrBadRequest.WithMessage(
			"Tệp tải lên không phải là định dạng hình ảnh hợp lệ",
		)
	}

	key := "avatars/" + uuid.NewString() + extension
	if err := a.blobs.Put(ctx, key, bytes.NewReader(data)); err != nil {
		return "", fmt.Errorf("store avatar blob: %w", err)
	}
	publicURL := a.blobs.URL(key)
	var oldKey *string
	err = a.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		var err error
		oldKey, err = a.profiles.SwapAvatar(
			txCtx,
			userID,
			&key,
		)
		if err != nil {
			return err
		}
		return a.audit(txCtx, userID, "UPLOAD_AVATAR", metadata)
	})
	if err != nil {
		a.deleteBestEffort(ctx, key, "new avatar after database failure")
		return "", err
	}
	if oldKey != nil && *oldKey != key {
		a.deleteBestEffort(ctx, *oldKey, "replaced avatar")
	}
	return publicURL, nil
}

// Delete gỡ avatar khỏi hồ sơ trong transaction rồi xóa blob theo best effort.
func (a *Avatar) Delete(
	ctx context.Context,
	userID uint64,
	metadata AvatarMetadata,
) error {
	var oldKey *string
	err := a.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		var err error
		oldKey, err = a.profiles.SwapAvatar(txCtx, userID, nil)
		if err != nil {
			return err
		}
		return a.audit(txCtx, userID, "DELETE_AVATAR", metadata)
	})
	if err != nil {
		return err
	}
	if oldKey != nil {
		a.deleteBestEffort(ctx, *oldKey, "deleted avatar")
	}
	return nil
}

// audit ghi avatar mutation theo best effort và không làm hỏng kết quả chính.
func (a *Avatar) audit(
	ctx context.Context,
	userID uint64,
	action string,
	metadata AvatarMetadata,
) error {
	resource := "profile"
	resourceID := strconv.FormatUint(userID, 10)
	ipAddress := metadata.IPAddress
	userAgent := metadata.UserAgent
	return a.audits.Create(ctx, &mysqlstore.AuditLog{
		UserID:     &userID,
		Action:     action,
		Resource:   &resource,
		ResourceID: &resourceID,
		IPAddress:  &ipAddress,
		UserAgent:  &userAgent,
		Status:     "success",
	})
}

// deleteBestEffort xóa blob cũ và chỉ cảnh báo khi cleanup ngoài transaction thất bại.
func (a *Avatar) deleteBestEffort(ctx context.Context, key, reason string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := a.blobs.Delete(cleanupCtx, key); err != nil {
		a.logger.Warn(
			"Avatar blob cleanup failed",
			zap.String("object_key", key),
			zap.String("reason", reason),
			zap.Error(err),
		)
	}
}
