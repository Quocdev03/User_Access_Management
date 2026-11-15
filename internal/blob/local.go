package blob

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// File này lưu và đọc blob trên filesystem cho môi trường ngoài production.

// LocalStore triển khai Store lưu trữ tệp tin trên filesystem cục bộ.
type LocalStore struct {
	root string
}

// NewLocalStore khởi tạo LocalStore với các dependency được cung cấp.
func NewLocalStore(root string) (*LocalStore, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve local blob root: %w", err)
	}
	if err := os.MkdirAll(absoluteRoot, 0o750); err != nil {
		return nil, fmt.Errorf("create local blob root: %w", err)
	}
	return &LocalStore{root: absoluteRoot}, nil
}

// Put ghi atomically qua temporary file để tránh blob dở dang.
func (s *LocalStore) Put(
	ctx context.Context,
	key string,
	content io.Reader,
) error {
	target, owned, err := s.resolve(key)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(s.root, target)
	if err != nil ||
		!owned ||
		!strings.HasPrefix(filepath.ToSlash(relative), "avatars/") {
		return fmt.Errorf("invalid local blob key")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return fmt.Errorf("create local blob directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".upload-*")
	if err != nil {
		return fmt.Errorf("create temporary local blob: %w", err)
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o640); err != nil {
		return fmt.Errorf("set local blob permissions: %w", err)
	}
	if _, err := io.Copy(temp, content); err != nil {
		return fmt.Errorf("write local blob: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync local blob: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close local blob: %w", err)
	}
	if err := os.Rename(tempName, target); err != nil {
		return fmt.Errorf("commit local blob: %w", err)
	}
	return nil
}

// Delete xóa blob local nhưng không coi key không tồn tại là lỗi.
func (s *LocalStore) Delete(ctx context.Context, key string) error {
	target, owned, err := s.resolve(key)
	if err != nil {
		return err
	}
	if !owned {
		return nil
	}
	relative, err := filepath.Rel(s.root, target)
	if err != nil ||
		!strings.HasPrefix(filepath.ToSlash(relative), "avatars/") {
		return fmt.Errorf("invalid local blob key")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete local blob: %w", err)
	}
	return nil
}

// Open mở blob local sau khi xác minh đường dẫn không thoát storage root.
func (s *LocalStore) Open(ctx context.Context, key string) (*os.File, error) {
	target, owned, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, fmt.Errorf("local blob key is not owned")
	}
	relative, err := filepath.Rel(s.root, target)
	if err != nil ||
		!strings.HasPrefix(filepath.ToSlash(relative), "avatars/") {
		return nil, fmt.Errorf("invalid local blob key")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanTarget := filepath.Clean(target)
	file, err := os.Open(cleanTarget) // #nosec G304 -- target is verified within root and avatars/ prefix above
	if err != nil {
		return nil, fmt.Errorf("open local blob: %w", err)
	}
	return file, nil
}

// URL trả về đường dẫn public tương ứng với blob key trong local store.
func (s *LocalStore) URL(key string) string {
	switch {
	case key == "":
		return ""
	case strings.HasPrefix(key, "http://"), strings.HasPrefix(key, "https://"):
		return key
	}
	target, owned, err := s.resolve(key)
	if err != nil || !owned {
		return ""
	}
	relative, err := filepath.Rel(s.root, target)
	if err != nil ||
		!strings.HasPrefix(filepath.ToSlash(relative), "avatars/") {
		return ""
	}
	normalized := strings.TrimPrefix(filepath.ToSlash(key), "/uploads/")
	clean := path.Clean(normalized)
	parts := strings.Split(clean, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return "/uploads/" + path.Join(parts...)
}

// resolve làm sạch blob key và từ chối path thoát khỏi local storage root.
func (s *LocalStore) resolve(key string) (string, bool, error) {
	normalized := filepath.ToSlash(strings.TrimSpace(key))
	switch {
	case normalized == "":
		return "", false, nil
	case strings.HasPrefix(normalized, "http://"),
		strings.HasPrefix(normalized, "https://"):
		return "", false, nil
	case strings.HasPrefix(normalized, "/uploads/"):
		normalized = strings.TrimPrefix(normalized, "/uploads/")
	case strings.HasPrefix(normalized, "/"):
		return "", false, nil
	}
	clean := path.Clean(normalized)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, fmt.Errorf("blob key escapes local root")
	}
	localKey := filepath.FromSlash(clean)
	if filepath.IsAbs(localKey) || filepath.VolumeName(localKey) != "" {
		return "", false, fmt.Errorf("blob key must be relative")
	}
	target := filepath.Join(s.root, localKey)
	relative, err := filepath.Rel(s.root, target)
	if err != nil {
		return "", false, fmt.Errorf("resolve local blob key: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false, fmt.Errorf("blob key escapes local root")
	}
	return target, true, nil
}
