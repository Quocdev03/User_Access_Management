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

const MaxAvatarBytes int64 = 2 << 20

type AvatarMetadata struct {
	IPAddress string
	UserAgent string
}

type Avatar struct {
	profiles  *mysqlstore.ProfileStore
	audits    *mysqlstore.AuditStore
	blobs     blob.Store
	txManager *mysqlstore.TxManager
	logger    *zap.Logger
}

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
