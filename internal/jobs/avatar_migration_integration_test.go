//go:build integration

package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/pkg/hash"
	"go.uber.org/zap"
)

// File này kiểm chứng tích hợp avatar migration integration với các dependency runtime liên quan.

// TestAvatarMigratorCommitsOnlyAfterChecksumVerification kiểm chứng kịch bản AvatarMigratorCommitsOnlyAfterChecksumVerification.
func TestAvatarMigratorCommitsOnlyAfterChecksumVerification(t *testing.T) {
	db := openJobsIntegrationDB(t)
	userID, oldKey := seedAvatarMigrationCandidate(t, db, "verified")
	source, err := blob.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore(): %v", err)
	}
	if err := source.Put(
		context.Background(),
		oldKey,
		bytes.NewReader([]byte("verified-avatar")),
	); err != nil {
		t.Fatalf("seed local avatar: %v", err)
	}
	target := newFakeVerifiedStore(false)

	result, err := NewAvatarMigrator(
		db,
		source,
		target,
		zap.NewNop(),
	).Run(context.Background(), 10)
	if err != nil {
		t.Fatalf("Run(): %v", err)
	}
	if result.Copied != 1 {
		t.Fatalf("copied = %d, want 1", result.Copied)
	}
	var stored struct {
		Key string `db:"avatar_object_key"`
	}
	if err := db.Get(&stored, `
		SELECT avatar_object_key
		FROM user_profiles
		WHERE user_id = ?`,
		userID,
	); err != nil {
		t.Fatalf("load migrated avatar state: %v", err)
	}
	if stored.Key != "avatars/verified.png" {
		t.Fatalf("migrated state = %+v", stored)
	}
}

// TestAvatarMigratorChecksumFailurePreservesDatabase kiểm chứng kịch bản AvatarMigratorChecksumFailurePreservesDatabase.
func TestAvatarMigratorChecksumFailurePreservesDatabase(t *testing.T) {
	db := openJobsIntegrationDB(t)
	userID, oldKey := seedAvatarMigrationCandidate(t, db, "checksum_failure")
	source, err := blob.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore(): %v", err)
	}
	if err := source.Put(
		context.Background(),
		oldKey,
		bytes.NewReader([]byte("local-avatar")),
	); err != nil {
		t.Fatalf("seed local avatar: %v", err)
	}
	target := newFakeVerifiedStore(true)

	if _, err := NewAvatarMigrator(
		db,
		source,
		target,
		zap.NewNop(),
	).Run(context.Background(), 10); err == nil {
		t.Fatal("Run accepted checksum mismatch")
	}
	var storedKey string
	if err := db.Get(
		&storedKey,
		"SELECT avatar_object_key FROM user_profiles WHERE user_id = ?",
		userID,
	); err != nil {
		t.Fatalf("load preserved avatar key: %v", err)
	}
	if storedKey != oldKey {
		t.Fatalf("avatar key = %q, want %q", storedKey, oldKey)
	}
}

// seedAvatarMigrationCandidate tạo profile còn dùng local avatar URL để migration xử lý.
func seedAvatarMigrationCandidate(
	t *testing.T,
	db *sqlx.DB,
	suffix string,
) (uint64, string) {
	t.Helper()
	unique := strconv.FormatInt(time.Now().UnixNano(), 10)
	username := "avatar_" + suffix + "_" + unique
	result, err := db.Exec(`
		INSERT INTO users (
			username, email, password_hash, lifecycle_state, email_verified,
			administrative_locked_at, login_locked_until,
			failed_login_attempts, password_change_required, auth_version
		) VALUES (?, ?, ?, 'active', TRUE, NULL, NULL, 0, FALSE, 1)`,
		username,
		username+"@example.test",
		hash.DummyPasswordHash,
	)
	if err != nil {
		t.Fatalf("create avatar migration user: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read avatar migration user ID: %v", err)
	}
	userID := uint64(id)
	key := "/uploads/avatars/" + suffix + ".png"
	if _, err := db.Exec(`
		INSERT INTO user_profiles (
			user_id, full_name, phone, date_of_birth, avatar_object_key
		) VALUES (?, ?, ?, ?, ?)`,
		userID,
		"Avatar Migration",
		"0909000000",
		"1991-09-01",
		key,
	); err != nil {
		t.Fatalf("create avatar migration profile: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM users WHERE id = ?", userID)
	})
	return userID, key
}

// fakeVerifiedStore là test double triển khai VerifiedStore để kiểm thử checksum và di chuyển avatar.
type fakeVerifiedStore struct {
	mu         sync.Mutex
	objects    map[string][]byte
	failVerify bool
}

// newFakeVerifiedStore tạo blob test double có thể đối chiếu checksum.
func newFakeVerifiedStore(failVerify bool) *fakeVerifiedStore {
	return &fakeVerifiedStore{
		objects:    make(map[string][]byte),
		failVerify: failVerify,
	}
}

// Put ghi put trong bounded worker.
func (s *fakeVerifiedStore) Put(
	_ context.Context,
	key string,
	content io.Reader,
) error {
	body, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = body
	return nil
}

// Delete mô phỏng xóa object cho integration fixture của avatar migration.
func (s *fakeVerifiedStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, key)
	return nil
}

// URL tạo fake public URL cho object đã migrate.
func (s *fakeVerifiedStore) URL(key string) string {
	return "https://blob.example/" + key
}

// VerifySHA256 xác minh SHA-256 trong bounded worker.
func (s *fakeVerifiedStore) VerifySHA256(
	_ context.Context,
	key string,
	expected string,
) error {
	if s.failVerify {
		return errors.New("checksum mismatch")
	}
	s.mu.Lock()
	body := s.objects[key]
	s.mu.Unlock()
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("checksum mismatch")
	}
	return nil
}
