// Package blob cung cấp boundary lưu trữ ảnh đại diện trên local hoặc S3.
package blob

import (
	"context"
	"io"

	"github.com/quocdev03/user-access-management/internal/config"
)

// File này định nghĩa contract lưu trữ blob được account use case sử dụng.

// Store định nghĩa giao diện lưu trữ blob phục vụ lưu trữ ảnh đại diện và tệp tin hệ thống.
type Store interface {
	// Put định nghĩa contract ghi nội dung vào một blob key.
	Put(ctx context.Context, key string, content io.Reader) error
	// Delete định nghĩa contract xóa blob; implementation phải xử lý key không tồn tại an toàn.
	Delete(ctx context.Context, key string) error
	// URL định nghĩa contract tạo URL đọc blob mà caller có thể lưu trong hồ sơ.
	URL(key string) string
}

// VerifiedStore mở rộng Store với khả năng kiểm chứng tính toàn vẹn của blob qua mã băm SHA256.
type VerifiedStore interface {
	Store
	// VerifySHA256 định nghĩa contract đối chiếu checksum của blob đã ghi.
	VerifySHA256(ctx context.Context, key string, expectedHex string) error
}

// NewStore chọn blob adapter từ cấu hình và từ chối provider không thể khởi tạo.
func NewStore(ctx context.Context, cfg config.BlobConfig) (Store, error) {
	if cfg.Provider == "s3" {
		return NewS3Store(ctx, cfg)
	}
	return NewLocalStore(cfg.LocalRoot)
}
