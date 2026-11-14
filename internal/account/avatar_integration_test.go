//go:build integration

package account_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"
	accountapp "github.com/quocdev03/user-access-management/internal/account"
	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/quocdev03/user-access-management/pkg/apperror"
	"go.uber.org/zap"
)

// File này kiểm chứng tích hợp avatar integration với các dependency runtime liên quan.

// fakeBlobStore là in-memory blob store giả lập phục vụ integration test cho avatar.
type fakeBlobStore struct {
	mu         sync.Mutex
	objects    map[string][]byte
	failDelete map[string]bool
	deleted    []string
}

// newFakeBlobStore tạo in-memory blob store để quan sát side effect của avatar use case.
func newFakeBlobStore() *fakeBlobStore {
	return &fakeBlobStore{
		objects:    make(map[string][]byte),
		failDelete: make(map[string]bool),
	}
}

// Put ghi put trong account use case.
func (s *fakeBlobStore) Put(
	_ context.Context,
	key string,
	content io.Reader,
) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = data
	return nil
}

// Delete ghi nhận blob key bị xóa trong fake avatar store.
func (s *fakeBlobStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, key)
	if s.failDelete[key] {
		return errors.New("blob delete unavailable")
	}
	delete(s.objects, key)
	return nil
}

// URL tạo fake public URL ổn định cho blob key đã ghi.
func (s *fakeBlobStore) URL(key string) string {
	return "/blob/" + key
}

// TestAvatarUploadAndDeleteSwapCanonicalObjectKey kiểm chứng kịch bản AvatarUploadAndDeleteSwapCanonicalObjectKey.
func TestAvatarUploadAndDeleteSwapCanonicalObjectKey(t *testing.T) {
	db := openAccountIntegrationDB(t)
	_, userID := profileFixture(t, db, "avatar_swap")
	oldKey := "avatars/old.png"
	if _, err := db.Exec(
		"UPDATE user_profiles SET avatar_object_key = ? WHERE user_id = ?",
		oldKey,
		userID,
	); err != nil {
		t.Fatalf("seed canonical avatar: %v", err)
	}
	blobs := newFakeBlobStore()
	blobs.objects[oldKey] = pngBytes()
	avatar := avatarFixture(db, blobs)

	publicURL, err := avatar.Upload(
		context.Background(),
		userID,
		bytes.NewReader(pngBytes()),
		"client-name.png",
		int64(len(pngBytes())),
		accountapp.AvatarMetadata{
			IPAddress: "127.0.0.51",
			UserAgent: "avatar-integration-upload",
		},
	)
	if err != nil {
		t.Fatalf("Upload(): %v", err)
	}
	if !strings.HasPrefix(publicURL, "/blob/avatars/") ||
		!strings.HasSuffix(publicURL, ".png") {
		t.Fatalf("public URL = %q", publicURL)
	}
	var stored struct {
		ObjectKey string `db:"avatar_object_key"`
	}
	if err := db.Get(&stored, `
		SELECT avatar_object_key
		FROM user_profiles
		WHERE user_id = ?`,
		userID,
	); err != nil {
		t.Fatalf("load avatar state: %v", err)
	}
	if publicURL != blobs.URL(stored.ObjectKey) ||
		stored.ObjectKey == oldKey {
		t.Fatalf("stored avatar = %+v, public=%q", stored, publicURL)
	}
	if _, exists := blobs.objects[oldKey]; exists {
		t.Fatal("replaced avatar blob was not removed")
	}
	if _, exists := blobs.objects[stored.ObjectKey]; !exists {
		t.Fatal("new avatar blob is missing")
	}
	profile := accountapp.NewProfile(
		db,
		mysqlstore.NewAccountStore(db),
		mysqlstore.NewProfileStore(db),
		mysqlstore.NewRoleStore(db),
		mysqlstore.NewAuditStore(db),
		blobs,
	)
	view, err := profile.Get(context.Background(), userID)
	if err != nil {
		t.Fatalf("Profile.Get(): %v", err)
	}
	if view.AvatarURL == nil || *view.AvatarURL != publicURL {
		t.Fatalf("profile avatar URL = %v, want %q", view.AvatarURL, publicURL)
	}

	if err := avatar.Delete(
		context.Background(),
		userID,
		accountapp.AvatarMetadata{UserAgent: "avatar-integration-delete"},
	); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*)
		FROM user_profiles
		WHERE user_id = ?
		  AND avatar_object_key IS NULL`,
		userID,
		1,
	)
	if _, exists := blobs.objects[stored.ObjectKey]; exists {
		t.Fatal("deleted avatar blob still exists")
	}
	assertAccountScalar(t, db, `
		SELECT COUNT(*) FROM audit_logs
		WHERE user_id = ? AND action IN ('UPLOAD_AVATAR', 'DELETE_AVATAR')`,
		userID,
		2,
	)
}

// TestAvatarUploadDatabaseFailureRemovesNewBlob kiểm chứng kịch bản AvatarUploadDatabaseFailureRemovesNewBlob.
func TestAvatarUploadDatabaseFailureRemovesNewBlob(t *testing.T) {
	db := openAccountIntegrationDB(t)
	blobs := newFakeBlobStore()
	avatar := avatarFixture(db, blobs)
	_, err := avatar.Upload(
		context.Background(),
		^uint64(0),
		bytes.NewReader(pngBytes()),
		"avatar.png",
		int64(len(pngBytes())),
		accountapp.AvatarMetadata{},
	)
	if !errors.Is(err, apperror.ErrNotFound) {
		t.Fatalf("Upload() error = %v, want not found", err)
	}
	if len(blobs.objects) != 0 || len(blobs.deleted) != 1 {
		t.Fatalf("compensation state: objects=%d deleted=%v", len(blobs.objects), blobs.deleted)
	}
}

// TestAvatarOldBlobCleanupFailureDoesNotRollbackNewAvatar kiểm chứng kịch bản AvatarOldBlobCleanupFailureDoesNotRollbackNewAvatar.
func TestAvatarOldBlobCleanupFailureDoesNotRollbackNewAvatar(t *testing.T) {
	db := openAccountIntegrationDB(t)
	_, userID := profileFixture(t, db, "avatar_cleanup_failure")
	oldKey := "avatars/cleanup-failure-old.png"
	if _, err := db.Exec(
		"UPDATE user_profiles SET avatar_object_key = ? WHERE user_id = ?",
		oldKey,
		userID,
	); err != nil {
		t.Fatalf("seed cleanup avatar: %v", err)
	}
	blobs := newFakeBlobStore()
	blobs.objects[oldKey] = pngBytes()
	blobs.failDelete[oldKey] = true
	avatar := avatarFixture(db, blobs)

	if _, err := avatar.Upload(
		context.Background(),
		userID,
		bytes.NewReader(pngBytes()),
		"avatar.png",
		int64(len(pngBytes())),
		accountapp.AvatarMetadata{},
	); err != nil {
		t.Fatalf("Upload(): %v", err)
	}
	var key string
	if err := db.Get(
		&key,
		"SELECT avatar_object_key FROM user_profiles WHERE user_id = ?",
		userID,
	); err != nil {
		t.Fatalf("load replacement avatar: %v", err)
	}
	if key == oldKey {
		t.Fatal("database rolled back after best-effort old blob cleanup failure")
	}
	if _, exists := blobs.objects[key]; !exists {
		t.Fatal("new avatar blob is missing")
	}
}

// TestAvatarRejectsExtensionContentMismatchBeforeBlobWrite kiểm chứng kịch bản AvatarRejectsExtensionContentMismatchBeforeBlobWrite.
func TestAvatarRejectsExtensionContentMismatchBeforeBlobWrite(t *testing.T) {
	db := openAccountIntegrationDB(t)
	blobs := newFakeBlobStore()
	avatar := avatarFixture(db, blobs)
	_, err := avatar.Upload(
		context.Background(),
		1,
		bytes.NewReader(pngBytes()),
		"avatar.jpg",
		int64(len(pngBytes())),
		accountapp.AvatarMetadata{},
	)
	if err == nil {
		t.Fatal("Upload() accepted mismatched extension and content")
	}
	if len(blobs.objects) != 0 {
		t.Fatal("invalid avatar reached blob storage")
	}
}

// avatarFixture tạo account và profile tối thiểu cho avatar integration test.
func avatarFixture(db *sqlx.DB, blobs *fakeBlobStore) *accountapp.Avatar {
	return accountapp.NewAvatar(
		db,
		mysqlstore.NewProfileStore(db),
		mysqlstore.NewAuditStore(db),
		blobs,
		zap.NewNop(),
	)
}

// pngBytes tạo ảnh PNG nhỏ hợp lệ dùng làm upload fixture.
func pngBytes() []byte {
	return append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
}
